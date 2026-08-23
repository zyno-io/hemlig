import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import * as k8s from "@kubernetes/client-node";
import {
  ClavisClient,
  ClavisError,
  NodeHttpsTransport,
  type Grant,
  type SecretMetadata,
  type SecretPayload,
} from "@clavis/client";

const group = "clavis.io";
const version = "v1alpha1";
const importPlural = "clavissecretimports";
const exportPlural = "clavissecretexports";

export interface ObjectMeta {
  readonly name?: string;
  readonly namespace?: string;
  readonly generation?: number;
  readonly resourceVersion?: string;
  readonly labels?: Readonly<Record<string, string>>;
  readonly annotations?: Readonly<Record<string, string>>;
}

interface ReconciliationStatus {
  readonly controlVersionId?: string;
  readonly payloadVersionId?: string;
  readonly sourceChecksum?: string;
  readonly observedGeneration?: number;
  readonly conditions?: readonly {
    readonly type?: string;
    readonly status?: string;
  }[];
}

export interface ClavisSecretImport {
  readonly apiVersion: "clavis.io/v1alpha1";
  readonly kind: "ClavisSecretImport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly secretId: string;
    readonly target?: { readonly name?: string; readonly type?: string };
  };
  readonly status?: ReconciliationStatus;
}

export interface ClavisSecretExport {
  readonly apiVersion: "clavis.io/v1alpha1";
  readonly kind: "ClavisSecretExport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly secretId: string;
    readonly environment: string;
    readonly source: { readonly name: string };
    readonly metadata: SecretMetadata;
    readonly acl: readonly Grant[];
  };
  readonly status?: ReconciliationStatus;
}

interface CoreApi {
  readNamespacedSecret(input: { readonly name: string; readonly namespace: string }): Promise<unknown>;
  createNamespacedSecret(input: { readonly namespace: string; readonly body: unknown }): Promise<unknown>;
  replaceNamespacedSecret(input: { readonly name: string; readonly namespace: string; readonly body: unknown }): Promise<unknown>;
}

interface CustomApi {
  listCustomObjectForAllNamespaces(input: { readonly group: string; readonly version: string; readonly plural: string }): Promise<unknown>;
  patchNamespacedCustomObjectStatus(input: {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
    readonly body: unknown;
  }): Promise<unknown>;
}

export interface ControllerConfig {
  readonly clusterUrl: string;
  readonly clusterTlsSecretName: string;
  readonly adminUrl: string;
  readonly adminToken: () => Promise<string>;
  readonly intervalMilliseconds: number;
}

/**
 * A polling reconciler deliberately uses only Kubernetes APIs: it needs no
 * queue service and is safe to run with multiple replicas because each apply
 * is resource-version aware. Watch-based triggering can be added later without
 * changing either CRD's reconciliation semantics.
 */
export class ClavisKubernetesController {
  public constructor(
    private readonly core: CoreApi,
    private readonly custom: CustomApi,
    private readonly config: ControllerConfig,
  ) {}

  public static fromDefaultConfig(config: ControllerConfig): ClavisKubernetesController {
    const kubeConfig = new k8s.KubeConfig();
    kubeConfig.loadFromDefault();
    return new ClavisKubernetesController(
      kubeConfig.makeApiClient(k8s.CoreV1Api) as unknown as CoreApi,
      kubeConfig.makeApiClient(k8s.CustomObjectsApi) as unknown as CustomApi,
      config,
    );
  }

  public async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      await this.reconcileAll();
      await wait(this.config.intervalMilliseconds, signal);
    }
  }

  public async reconcileAll(): Promise<void> {
    const [imports, exports] = await Promise.all([
      this.list<ClavisSecretImport>(importPlural),
      this.list<ClavisSecretExport>(exportPlural),
    ]);
    for (const resource of imports) {
      await this.reconcileImport(resource);
    }
    for (const resource of exports) {
      await this.reconcileExport(resource);
    }
  }

  public async reconcileImport(resource: ClavisSecretImport): Promise<void> {
    const namespace = required(resource.metadata.namespace, "import namespace");
    const name = required(resource.metadata.name, "import name");
    try {
      const client = await this.clusterClient(namespace);
      const targetName = resource.spec.target?.name ?? name;
      const importOwner = `${namespace}/${name}`;
      const currentControlVersionId = await this.currentImportedControlVersion(
        namespace,
        targetName,
        importOwner,
        resource.status,
      );
      const remote = await client.getClusterSecret(resource.spec.secretId, currentControlVersionId);
      if (remote === undefined) {
        return;
      }
      const data = payloadToKubernetesData(remote.payload);
      const body = {
        apiVersion: "v1",
        kind: "Secret",
        metadata: {
          name: targetName,
          namespace,
          labels: { "clavis.io/managed-by": "import" },
          annotations: {
            "clavis.io/import-owner": importOwner,
            "clavis.io/secret-id": remote.secretId,
            "clavis.io/control-version-id": remote.controlVersionId,
            "clavis.io/payload-version-id": remote.payloadVersionId,
            "clavis.io/data-checksum": stringMapChecksum(data),
          },
        },
        type: resource.spec.target?.type ?? "Opaque",
        data,
      };
      const materialized = await this.applyImportedSecret(namespace, targetName, importOwner, body);
      if (!materialized && statusIsReadyAtVersion(
        resource.status,
        resource.metadata.generation,
        remote.controlVersionId,
        remote.payloadVersionId,
      )) {
        return;
      }
      await this.setStatus(namespace, importPlural, name, {
        observedGeneration: resource.metadata.generation,
        controlVersionId: remote.controlVersionId,
        payloadVersionId: remote.payloadVersionId,
        conditions: [readyCondition("Imported", "Secret materialized from Clavis.")],
      });
    } catch (error) {
      await this.setFailure(namespace, importPlural, name, resource.metadata.generation, error);
    }
  }

  public async reconcileExport(resource: ClavisSecretExport): Promise<void> {
    const namespace = required(resource.metadata.namespace, "export namespace");
    const name = required(resource.metadata.name, "export name");
    try {
      const source = unwrapKubernetesResponse(
        await this.core.readNamespacedSecret({ name: resource.spec.source.name, namespace }),
      ) as { data?: Record<string, string>; binaryData?: Record<string, string>; metadata?: ObjectMeta };
      if (source.metadata?.labels?.["clavis.io/managed-by"] === "import") {
        throw new Error("An export cannot source a Secret managed by Clavis import.");
      }
      const payload = kubernetesDataToPayload({ ...source.data, ...source.binaryData });
      const sourceChecksum = payloadChecksum(payload);
      const token = await this.config.adminToken();
      const client = new ClavisClient(new URL(this.config.adminUrl), new NodeHttpsTransport());
      let current;
      try {
        current = await client.getAdminSecret(token, resource.spec.secretId);
      } catch (error) {
        if (!(error instanceof ClavisError) || error.status !== 404) {
          throw error;
        }
        current = await client.createAdminSecret(token, {
          secretId: resource.spec.secretId,
          environment: resource.spec.environment,
          metadata: resource.spec.metadata,
          acl: resource.spec.acl,
        });
      }
      if (current.environment !== resource.spec.environment) {
        throw new Error("The existing Clavis secret belongs to a different environment.");
      }
      const metadataChanged = JSON.stringify(current.metadata) !== JSON.stringify(resource.spec.metadata);
      const aclChanged = JSON.stringify(current.acl ?? []) !== JSON.stringify(resource.spec.acl);
      if (metadataChanged || aclChanged) {
        current = await client.updateAdminSecret(
          token,
          resource.spec.secretId,
          current.controlVersionId,
          { metadata: resource.spec.metadata, acl: resource.spec.acl },
        );
      }
      if (statusIsReadyAtVersion(
        resource.status,
        resource.metadata.generation,
        current.controlVersionId,
        current.payloadVersionId,
        sourceChecksum,
      )) {
        return;
      }
      const written = await client.putAdminPayload(
        token,
        resource.spec.secretId,
        current.controlVersionId,
        payload,
      );
      await this.setStatus(namespace, exportPlural, name, {
        observedGeneration: resource.metadata.generation,
        controlVersionId: written.controlVersionId,
        payloadVersionId: written.payloadVersionId,
        sourceChecksum,
        conditions: [readyCondition("Exported", "Secret payload written to Clavis.")],
      });
    } catch (error) {
      await this.setFailure(namespace, exportPlural, name, resource.metadata.generation, error);
    }
  }

  private async clusterClient(namespace: string): Promise<ClavisClient> {
    const identity = unwrapKubernetesResponse(
      await this.core.readNamespacedSecret({
        name: this.config.clusterTlsSecretName,
        namespace,
      }),
    ) as { data?: Record<string, string> };
    const certificate = identity.data?.["tls.crt"];
    const privateKey = identity.data?.["tls.key"];
    if (certificate === undefined || privateKey === undefined) {
      throw new Error("The configured Clavis mTLS Secret must contain tls.crt and tls.key.");
    }
    return new ClavisClient(
      new URL(this.config.clusterUrl),
      new NodeHttpsTransport({
        cert: Buffer.from(certificate, "base64"),
        key: Buffer.from(privateKey, "base64"),
      }),
    );
  }

  private async applyImportedSecret(
    namespace: string,
    name: string,
    importOwner: string,
    body: unknown,
  ): Promise<boolean> {
    try {
      const existing = unwrapKubernetesResponse(
        await this.core.readNamespacedSecret({ name, namespace }),
      ) as { metadata?: ObjectMeta; data?: Readonly<Record<string, string>>; type?: string };
      if (!isOwnedByImport(existing.metadata, importOwner)) {
        throw new Error(
          "The import target exists but is not owned by this ClavisSecretImport.",
        );
      }
      const desired = body as {
        readonly data: Readonly<Record<string, string>>;
        readonly metadata: { readonly annotations: Readonly<Record<string, string>> };
        readonly type: string;
      };
      if (
        existing.metadata?.annotations?.["clavis.io/control-version-id"] ===
          desired.metadata.annotations["clavis.io/control-version-id"] &&
        existing.metadata?.annotations?.["clavis.io/payload-version-id"] ===
          desired.metadata.annotations["clavis.io/payload-version-id"] &&
        existing.type === desired.type &&
        stringMapsEqual(existing.data, desired.data)
      ) {
        return false;
      }
      await this.core.replaceNamespacedSecret({
        name,
        namespace,
        body: {
          ...(body as Record<string, unknown>),
          metadata: {
            ...desired.metadata,
            resourceVersion: existing.metadata?.resourceVersion,
          },
        },
      });
      return true;
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
      await this.core.createNamespacedSecret({ namespace, body });
      return true;
    }
  }

  /**
   * Uses the cluster API's conditional read only when the local Secret still
   * reflects the last ready status. A missing, foreign, or tampered target
   * forces a full read so reconciliation can repair it.
   */
  private async currentImportedControlVersion(
    namespace: string,
    name: string,
    importOwner: string,
    status: ReconciliationStatus | undefined,
  ): Promise<string | undefined> {
    if (
      status?.controlVersionId === undefined ||
      status.payloadVersionId === undefined ||
      !isReady(status)
    ) {
      return undefined;
    }
    try {
      const existing = unwrapKubernetesResponse(
        await this.core.readNamespacedSecret({ name, namespace }),
      ) as { metadata?: ObjectMeta; data?: Readonly<Record<string, string>> };
      const annotations = existing.metadata?.annotations;
      if (
        !isOwnedByImport(existing.metadata, importOwner) ||
        annotations?.["clavis.io/control-version-id"] !== status.controlVersionId ||
        annotations?.["clavis.io/payload-version-id"] !== status.payloadVersionId ||
        annotations?.["clavis.io/data-checksum"] !== stringMapChecksum(existing.data ?? {})
      ) {
        return undefined;
      }
      return status.controlVersionId;
    } catch (error) {
      if (isNotFound(error)) {
        return undefined;
      }
      throw error;
    }
  }

  private async list<T>(plural: string): Promise<T[]> {
    const response = unwrapKubernetesResponse(
      await this.custom.listCustomObjectForAllNamespaces({ group, version, plural }),
    ) as { items?: T[] };
    return response.items ?? [];
  }

  private async setFailure(
    namespace: string,
    plural: string,
    name: string,
    generation: number | undefined,
    error: unknown,
  ): Promise<void> {
    await this.setStatus(namespace, plural, name, {
      observedGeneration: generation,
      conditions: [{
        type: "Ready",
        status: "False",
        reason: "ReconcileFailed",
        message: error instanceof Error ? error.message : "Unknown reconciliation failure.",
        lastTransitionTime: new Date().toISOString(),
      }],
    });
  }

  private async setStatus(
    namespace: string,
    plural: string,
    name: string,
    status: unknown,
  ): Promise<void> {
    await this.custom.patchNamespacedCustomObjectStatus({
      group,
      version,
      namespace,
      plural,
      name,
      body: { status },
    });
  }
}

export const controllerConfigFromEnvironment = (): ControllerConfig => ({
  clusterUrl: required(process.env.CLAVIS_CLUSTER_URL, "CLAVIS_CLUSTER_URL"),
  clusterTlsSecretName: process.env.CLAVIS_CLUSTER_TLS_SECRET ?? "clavis-client-tls",
  adminUrl: required(process.env.CLAVIS_ADMIN_URL, "CLAVIS_ADMIN_URL"),
  adminToken: async () => {
    const inline = process.env.CLAVIS_ADMIN_TOKEN;
    if (inline !== undefined && inline.trim().length > 0) {
      return inline.trim();
    }
    const file = required(process.env.CLAVIS_ADMIN_TOKEN_FILE, "CLAVIS_ADMIN_TOKEN_FILE");
    return (await readFile(file, "utf8")).trim();
  },
  intervalMilliseconds: Number.parseInt(process.env.CLAVIS_RECONCILE_INTERVAL_MS ?? "30000", 10),
});

export const payloadToKubernetesData = (payload: SecretPayload): Record<string, string> =>
  Object.fromEntries(
    Object.entries(payload).map(([key, entry]) => [
      key,
      entry.encoding === "base64" ? entry.value : Buffer.from(entry.value, "utf8").toString("base64"),
    ]),
  );

export const kubernetesDataToPayload = (
  data: Readonly<Record<string, string | undefined>>,
): SecretPayload =>
  Object.fromEntries(
    Object.entries(data)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([key, value]) => [key, { encoding: "base64", value }]),
  );

/** Stable content identity for an exported Kubernetes Secret's material. */
export const payloadChecksum = (payload: SecretPayload): string =>
  createHash("sha256")
    .update(JSON.stringify(Object.entries(payload).sort(([left], [right]) => left.localeCompare(right))))
    .digest("hex");

export const isOwnedByImport = (metadata: ObjectMeta | undefined, importOwner: string): boolean =>
  metadata?.labels?.["clavis.io/managed-by"] === "import" &&
  metadata.annotations?.["clavis.io/import-owner"] === importOwner;

const unwrapKubernetesResponse = (value: unknown): unknown =>
  typeof value === "object" && value !== null && "body" in value
    ? (value as { body: unknown }).body
    : value;

const required = (value: string | undefined, name: string): string => {
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value.trim();
};

const isNotFound = (error: unknown): boolean =>
  typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === 404;

const stringMapsEqual = (
  left: Readonly<Record<string, string>> | undefined,
  right: Readonly<Record<string, string>>,
): boolean => {
  const leftEntries = Object.entries(left ?? {}).sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));
  const rightEntries = Object.entries(right).sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
};

const stringMapChecksum = (data: Readonly<Record<string, string>>): string =>
  createHash("sha256")
    .update(JSON.stringify(Object.entries(data).sort(([left], [right]) => left.localeCompare(right))))
    .digest("hex");

const statusIsReadyAtVersion = (
  status: ReconciliationStatus | undefined,
  generation: number | undefined,
  controlVersionId: string,
  payloadVersionId: string | undefined,
  sourceChecksum?: string,
): boolean =>
  status !== undefined &&
  status.observedGeneration === generation &&
  status.controlVersionId === controlVersionId &&
  status.payloadVersionId === payloadVersionId &&
  status.sourceChecksum === sourceChecksum &&
  status.conditions?.some((condition) => condition.type === "Ready" && condition.status === "True") === true;

const isReady = (status: ReconciliationStatus): boolean =>
  status.conditions?.some((condition) => condition.type === "Ready" && condition.status === "True") === true;

const readyCondition = (reason: string, message: string) => ({
  type: "Ready",
  status: "True",
  reason,
  message,
  lastTransitionTime: new Date().toISOString(),
});

const wait = async (milliseconds: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => {
      clearTimeout(timeout);
      resolve();
    }, { once: true });
  });
