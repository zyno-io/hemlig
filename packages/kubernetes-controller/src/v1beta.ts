import { createHash, randomUUID } from "node:crypto";
import * as k8s from "@kubernetes/client-node";
import mqtt, { type MqttClient } from "mqtt";
import forge from "node-forge";
import {
  HemligClient,
  HemligError,
  type AgentConfig,
  type AgentControl,
  type ControlRevision,
  type SecretMetadata,
  type SecretPayload,
} from "@hemlig/client";
import { NodeHttpsTransport } from "@hemlig/client/node";
import {
  isOwnedByImport,
  kubernetesDataToPayload,
  payloadChecksum,
  payloadToKubernetesData,
} from "./index";

const group = "hemlig.io";
const version = "v1beta1";
const providerPlural = "hemligproviders";
const consumerPlural = "hemligconsumers";
const importPlural = "hemligsecretimports";
const exportPlural = "hemligsecretexports";
const controllerLabel = "hemlig.io/managed-by";
const consumerOwnerAnnotation = "hemlig.io/consumer-owner";
const identityCsrDataKey = "hemlig.io.csr";

export interface ObjectMeta {
  readonly name?: string;
  readonly namespace?: string;
  readonly uid?: string;
  readonly generation?: number;
  readonly resourceVersion?: string;
  readonly labels?: Readonly<Record<string, string>>;
  readonly annotations?: Readonly<Record<string, string>>;
}

interface Condition {
  readonly type: string;
  readonly status: "True" | "False";
  readonly reason: string;
  readonly message: string;
  readonly lastTransitionTime: string;
}

interface ReconciliationStatus {
  readonly observedGeneration?: number;
  readonly controlVersionId?: string;
  readonly payloadVersionId?: string;
  readonly sourceChecksum?: string;
  readonly consumerId?: string;
  readonly environment?: string;
  readonly grantId?: string;
  readonly conditions?: readonly Condition[];
}

export interface HemligProvider {
  readonly apiVersion: "hemlig.io/v1beta1";
  readonly kind: "HemligProvider";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly bootstrapUrl: string;
    readonly apiUrl: string;
    readonly allowedNamespaces: { readonly matchLabels: Readonly<Record<string, string>> };
  };
}

export interface HemligConsumer {
  readonly apiVersion: "hemlig.io/v1beta1";
  readonly kind: "HemligConsumer";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly providerRef: string;
    readonly bootstrapTokenRef: { readonly name: string; readonly key: string };
    readonly identity: { readonly secretName: string; readonly rotateBefore?: string };
  };
  readonly status?: ReconciliationStatus;
}

export interface HemligSecretImport {
  readonly apiVersion: "hemlig.io/v1beta1";
  readonly kind: "HemligSecretImport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: string;
    readonly secretId: string;
    readonly target?: { readonly name?: string; readonly type?: string };
    readonly deletionPolicy?: "Retain" | "Delete";
  };
  readonly status?: ReconciliationStatus;
}

export interface HemligSecretExport {
  readonly apiVersion: "hemlig.io/v1beta1";
  readonly kind: "HemligSecretExport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: string;
    readonly secretId: string;
    readonly source: { readonly name: string };
    readonly metadata: SecretMetadata;
  };
  readonly status?: ReconciliationStatus;
}

interface CoreApi {
  readNamespacedSecret(input: { readonly name: string; readonly namespace: string }): Promise<unknown>;
  createNamespacedSecret(input: { readonly namespace: string; readonly body: unknown }): Promise<unknown>;
  replaceNamespacedSecret(input: { readonly name: string; readonly namespace: string; readonly body: unknown }): Promise<unknown>;
  deleteNamespacedSecret(input: { readonly name: string; readonly namespace: string }): Promise<unknown>;
  readNamespace(input: { readonly name: string }): Promise<unknown>;
}

interface CustomApi {
  listClusterCustomObject(input: { readonly group: string; readonly version: string; readonly plural: string }): Promise<unknown>;
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

interface ReadyConsumer {
  readonly resource: HemligConsumer;
  readonly provider: HemligProvider;
  readonly client: HemligClient;
  readonly config: AgentConfig;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
}

interface IdentitySecret {
  readonly metadata?: ObjectMeta;
  readonly data?: Readonly<Record<string, string>>;
  readonly binaryData?: Readonly<Record<string, string>>;
  readonly type?: string;
}

export interface V1BetaControllerConfig {
  readonly intervalMilliseconds: number;
  readonly sourceDebounceMilliseconds: number;
}

/**
 * v1beta reconciler. It never reads an administrator token: automatic
 * enrollment is constrained by the pre-created AgentGrant encoded in the
 * single-use bootstrap capability, and all subsequent calls use agent mTLS.
 */
export class HemligV1BetaController {
  private readonly mqtt = new MqttHintManager(() => this.scheduleReconcile());
  private reconcileTimer: NodeJS.Timeout | undefined;
  private reconciling = false;
  private watch: k8s.Watch | undefined;

  public constructor(
    private readonly core: CoreApi,
    private readonly custom: CustomApi,
    private readonly config: V1BetaControllerConfig,
  ) {}

  public static fromDefaultConfig(config: V1BetaControllerConfig): HemligV1BetaController {
    const kubeConfig = new k8s.KubeConfig();
    kubeConfig.loadFromDefault();
    const controller = new HemligV1BetaController(
      kubeConfig.makeApiClient(k8s.CoreV1Api) as unknown as CoreApi,
      kubeConfig.makeApiClient(k8s.CustomObjectsApi) as unknown as CustomApi,
      config,
    );
    controller.watch = new k8s.Watch(kubeConfig);
    return controller;
  }

  public async run(signal: AbortSignal): Promise<void> {
    await this.reconcileAll();
    this.startWatches(signal);
    while (!signal.aborted) {
      await wait(this.config.intervalMilliseconds, signal);
      if (!signal.aborted) {
        await this.reconcileAll();
      }
    }
    this.mqtt.stop();
  }

  public async reconcileAll(): Promise<void> {
    if (this.reconciling) {
      return;
    }
    this.reconciling = true;
    try {
      const [providers, consumers, imports, exports] = await Promise.all([
        this.listCluster<HemligProvider>(providerPlural),
        this.listNamespaced<HemligConsumer>(consumerPlural),
        this.listNamespaced<HemligSecretImport>(importPlural),
        this.listNamespaced<HemligSecretExport>(exportPlural),
      ]);
      const providersByName = new Map(
        providers.flatMap((provider) => provider.metadata.name === undefined ? [] : [[provider.metadata.name, provider] as const]),
      );
      const readyConsumers = new Map<string, ReadyConsumer>();
      for (const consumer of consumers) {
        const ready = await this.reconcileConsumer(consumer, providersByName);
        if (ready !== undefined) {
          readyConsumers.set(resourceKey(consumer.metadata), ready);
        }
      }
      for (const resource of imports) {
        const consumer = readyConsumers.get(`${required(resource.metadata.namespace, "import namespace")}/${resource.spec.consumerRef}`);
        await this.reconcileImport(resource, consumer);
      }
      for (const resource of exports) {
        const consumer = readyConsumers.get(`${required(resource.metadata.namespace, "export namespace")}/${resource.spec.consumerRef}`);
        await this.reconcileExport(resource, consumer);
      }
    } finally {
      this.reconciling = false;
    }
  }

  private async reconcileConsumer(
    resource: HemligConsumer,
    providers: ReadonlyMap<string, HemligProvider>,
  ): Promise<ReadyConsumer | undefined> {
    const namespace = required(resource.metadata.namespace, "consumer namespace");
    const name = required(resource.metadata.name, "consumer name");
    try {
      const provider = providers.get(resource.spec.providerRef);
      if (provider === undefined) {
        throw new ReconcileError("ProviderNotFound", "The referenced HemligProvider was not found.");
      }
      await this.assertNamespaceAllowed(namespace, provider);
      const identity = await this.loadOrBootstrapIdentity(resource, provider);
      const client = agentClient(provider.spec.apiUrl, identity.certificate, identity.privateKey);
      const agentConfig = await client.getAgentConfig();
      this.mqtt.ensure({
        key: resourceKey(resource.metadata),
        ...agentConfig.mqtt,
        certificate: identity.certificate,
        privateKey: identity.privateKey,
      });
      await this.setStatus(namespace, consumerPlural, name, {
        observedGeneration: resource.metadata.generation,
        consumerId: agentConfig.consumerId,
        environment: agentConfig.environment,
        grantId: agentConfig.grant.grantId,
        conditions: [readyCondition("IdentityReady", "Bootstrap identity is active and scoped by Hemlig.")],
      }, resource.status);
      return { resource, provider, client, config: agentConfig, ...identity };
    } catch (error) {
      await this.setFailure(namespace, consumerPlural, name, resource.metadata.generation, resource.status, error);
      return undefined;
    }
  }

  private async loadOrBootstrapIdentity(
    resource: HemligConsumer,
    provider: HemligProvider,
  ): Promise<{ readonly certificate: Buffer; readonly privateKey: Buffer }> {
    const namespace = required(resource.metadata.namespace, "consumer namespace");
    const owner = resourceKey(resource.metadata);
    const identityName = resource.spec.identity.secretName;
    let identity: IdentitySecret | undefined;
    try {
      identity = asSecret(await this.core.readNamespacedSecret({ name: identityName, namespace }));
      this.assertIdentityOwnership(identity, owner);
      const certificate = valueData(identity, "tls.crt");
      const privateKey = valueData(identity, "tls.key");
      if (certificate !== undefined && privateKey !== undefined) {
        return { certificate: Buffer.from(certificate, "base64"), privateKey: Buffer.from(privateKey, "base64") };
      }
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
    }
    const pending = identity === undefined
      ? await this.createPendingIdentity(resource, provider, owner)
      : identity;
    const privateKey = requiredData(pending, "tls.key");
    const csr = requiredData(pending, identityCsrDataKey);
    const token = await this.bootstrapToken(resource, namespace);
    const bootstrap = new HemligClient(
      new URL(provider.spec.bootstrapUrl),
      new NodeHttpsTransport(),
    );
    const enrolled = await bootstrap.redeemBootstrap(token, Buffer.from(csr, "base64").toString("utf8"));
    const body = {
      apiVersion: "v1",
      kind: "Secret",
      metadata: {
        name: identityName,
        namespace,
        resourceVersion: pending.metadata?.resourceVersion,
        labels: { [controllerLabel]: "consumer" },
        annotations: {
          [consumerOwnerAnnotation]: owner,
          "hemlig.io/provider": provider.metadata.name,
          "hemlig.io/grant-id": enrolled.grant.grantId,
          "hemlig.io/api-fingerprint": enrolled.apiFingerprint,
        },
      },
      // Kubernetes treats Secret.type as immutable. The pending identity is
      // deliberately created as Opaque so it can also carry the CSR; retain
      // that type when replacing it with the enrolled certificate.
      type: pending.type ?? "Opaque",
      data: {
        "tls.crt": Buffer.from(enrolled.apiCertificatePem, "utf8").toString("base64"),
        "tls.key": privateKey,
      },
    };
    await this.core.replaceNamespacedSecret({ name: identityName, namespace, body });
    return {
      certificate: Buffer.from(enrolled.apiCertificatePem, "utf8"),
      privateKey: Buffer.from(privateKey, "base64"),
    };
  }

  private async createPendingIdentity(
    resource: HemligConsumer,
    provider: HemligProvider,
    owner: string,
  ): Promise<IdentitySecret> {
    const namespace = required(resource.metadata.namespace, "consumer namespace");
    const generated = generateCsr();
    const body = {
      apiVersion: "v1",
      kind: "Secret",
      metadata: {
        name: resource.spec.identity.secretName,
        namespace,
        labels: { [controllerLabel]: "consumer" },
        annotations: {
          [consumerOwnerAnnotation]: owner,
          "hemlig.io/provider": provider.metadata.name,
          "hemlig.io/identity-state": "pending-bootstrap",
        },
      },
      type: "Opaque",
      data: {
        "tls.key": Buffer.from(generated.privateKeyPem, "utf8").toString("base64"),
        [identityCsrDataKey]: Buffer.from(generated.csrPem, "utf8").toString("base64"),
      },
    };
    try {
      const created = await this.core.createNamespacedSecret({ namespace, body });
      return asSecret(created);
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
      const current = asSecret(await this.core.readNamespacedSecret({
        name: resource.spec.identity.secretName,
        namespace,
      }));
      this.assertIdentityOwnership(current, owner);
      return current;
    }
  }

  private async bootstrapToken(resource: HemligConsumer, namespace: string): Promise<string> {
    const secret = asSecret(await this.core.readNamespacedSecret({
      name: resource.spec.bootstrapTokenRef.name,
      namespace,
    }));
    const value = valueData(secret, resource.spec.bootstrapTokenRef.key);
    if (value === undefined) {
      throw new ReconcileError("BootstrapTokenUnavailable", "The referenced bootstrap token key is absent.");
    }
    return Buffer.from(value, "base64").toString("utf8");
  }

  private async reconcileImport(
    resource: HemligSecretImport,
    consumer: ReadyConsumer | undefined,
  ): Promise<void> {
    const namespace = required(resource.metadata.namespace, "import namespace");
    const name = required(resource.metadata.name, "import name");
    if (consumer === undefined) {
      await this.setFailure(namespace, importPlural, name, resource.metadata.generation, resource.status,
        new ReconcileError("ConsumerNotReady", "The referenced HemligConsumer is not ready."));
      return;
    }
    try {
      const targetName = resource.spec.target?.name ?? name;
      const owner = resourceKey(resource.metadata);
      const ifNoneMatch = await this.currentImportVersion(namespace, targetName, owner, resource.status);
      const remote = await consumer.client.getAgentSecret(resource.spec.secretId, ifNoneMatch);
      if (remote === undefined) {
        return;
      }
      const data = payloadToKubernetesData(remote.payload);
      const desired = {
        apiVersion: "v1",
        kind: "Secret",
        metadata: {
          name: targetName,
          namespace,
          labels: { [controllerLabel]: "import" },
          annotations: {
            "hemlig.io/import-owner": owner,
            "hemlig.io/secret-id": remote.secretId,
            "hemlig.io/control-version-id": remote.controlVersionId,
            "hemlig.io/payload-version-id": remote.payloadVersionId,
            "hemlig.io/data-checksum": stringMapChecksum(data),
          },
        },
        type: resource.spec.target?.type ?? "Opaque",
        data,
      };
      await this.applyImport(namespace, targetName, owner, desired);
      await this.setStatus(namespace, importPlural, name, {
        observedGeneration: resource.metadata.generation,
        controlVersionId: remote.controlVersionId,
        payloadVersionId: remote.payloadVersionId,
        conditions: [readyCondition("TargetReady", "Secret materialized from Hemlig.")],
      }, resource.status);
    } catch (error) {
      if (error instanceof HemligError && (error.status === 403 || error.status === 404)) {
        await this.removeOwnedImport(resource);
        await this.setStatus(namespace, importPlural, name, {
          observedGeneration: resource.metadata.generation,
          conditions: [falseCondition("AccessRevoked", "Hemlig no longer grants this import.")],
        }, resource.status);
        return;
      }
      await this.setFailure(namespace, importPlural, name, resource.metadata.generation, resource.status, error);
    }
  }

  private async reconcileExport(
    resource: HemligSecretExport,
    consumer: ReadyConsumer | undefined,
  ): Promise<void> {
    const namespace = required(resource.metadata.namespace, "export namespace");
    const name = required(resource.metadata.name, "export name");
    if (consumer === undefined) {
      await this.setFailure(namespace, exportPlural, name, resource.metadata.generation, resource.status,
        new ReconcileError("ConsumerNotReady", "The referenced HemligConsumer is not ready."));
      return;
    }
    try {
      const source = asSecret(await this.core.readNamespacedSecret({
        name: resource.spec.source.name,
        namespace,
      }));
      if (source.metadata?.labels?.[controllerLabel] === "import") {
        throw new ReconcileError("SourceIsImportManaged", "An export cannot source a Hemlig-managed import.");
      }
      const payload = kubernetesDataToPayload({
        ...source.data,
        ...source.binaryData,
      });
      const checksum = payloadChecksum(payload);
      let control: AgentControl | ControlRevision;
      try {
        control = await consumer.client.getAgentControl(resource.spec.secretId);
      } catch (error) {
        if (!(error instanceof HemligError) || error.status !== 404) {
          throw error;
        }
        control = await consumer.client.createAgentSecret({
          secretId: resource.spec.secretId,
          metadata: resource.spec.metadata,
        }, operationKey(resource.metadata, "create"));
      }
      if (!metadataEqual(control.metadata, resource.spec.metadata)) {
        control = await consumer.client.updateAgentSecret(
          resource.spec.secretId,
          control.controlVersionId,
          resource.spec.metadata,
          operationKey(resource.metadata, `metadata:${control.controlVersionId}`),
        );
      }
      const priorStatus = resource.status;
      if (
        priorStatus !== undefined &&
        priorStatus.observedGeneration === resource.metadata.generation &&
        priorStatus.sourceChecksum === checksum &&
        priorStatus.controlVersionId === control.controlVersionId &&
        priorStatus.payloadVersionId === control.payloadVersionId
      ) {
        return;
      }
      const written = await consumer.client.putAgentPayload(
        resource.spec.secretId,
        control.controlVersionId,
        payload,
        operationKey(resource.metadata, `payload:${checksum}:${control.controlVersionId}`),
      );
      await this.setStatus(namespace, exportPlural, name, {
        observedGeneration: resource.metadata.generation,
        controlVersionId: written.controlVersionId,
        payloadVersionId: written.payloadVersionId,
        sourceChecksum: checksum,
        conditions: [readyCondition("RemoteReady", "Source Secret was written through the scoped agent API.")],
      }, resource.status);
    } catch (error) {
      await this.setFailure(namespace, exportPlural, name, resource.metadata.generation, resource.status, error);
    }
  }

  private async assertNamespaceAllowed(namespace: string, provider: HemligProvider): Promise<void> {
    const namespaceRecord = unwrap(await this.core.readNamespace({ name: namespace })) as { metadata?: ObjectMeta };
    const requiredLabels = provider.spec.allowedNamespaces.matchLabels;
    const allowed = Object.entries(requiredLabels).every(
      ([key, value]) => namespaceRecord.metadata?.labels?.[key] === value,
    );
    if (!allowed) {
      throw new ReconcileError("ProviderNotPermitted", "This namespace does not match the provider selector.");
    }
  }

  private assertIdentityOwnership(secret: IdentitySecret, owner: string): void {
    if (
      secret.metadata?.labels?.[controllerLabel] !== "consumer" ||
      secret.metadata.annotations?.[consumerOwnerAnnotation] !== owner
    ) {
      throw new ReconcileError("IdentityOwnershipConflict", "The identity Secret is not owned by this HemligConsumer.");
    }
  }

  private async applyImport(
    namespace: string,
    name: string,
    owner: string,
    desired: Record<string, unknown>,
  ): Promise<void> {
    try {
      const current = asSecret(await this.core.readNamespacedSecret({ name, namespace }));
      if (!isOwnedByImport(current.metadata, owner)) {
        throw new ReconcileError("TargetOwnershipConflict", "The import target is owned by another resource.");
      }
      await this.core.replaceNamespacedSecret({
        name,
        namespace,
        body: {
          ...desired,
          metadata: {
            ...(desired.metadata as Record<string, unknown>),
            resourceVersion: current.metadata?.resourceVersion,
          },
        },
      });
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
      await this.core.createNamespacedSecret({ namespace, body: desired });
    }
  }

  private async removeOwnedImport(resource: HemligSecretImport): Promise<void> {
    const namespace = required(resource.metadata.namespace, "import namespace");
    const name = required(resource.metadata.name, "import name");
    const targetName = resource.spec.target?.name ?? name;
    try {
      const current = asSecret(await this.core.readNamespacedSecret({ name: targetName, namespace }));
      if (isOwnedByImport(current.metadata, resourceKey(resource.metadata))) {
        await this.core.deleteNamespacedSecret({ name: targetName, namespace });
      }
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
    }
  }

  private async currentImportVersion(
    namespace: string,
    name: string,
    owner: string,
    status: ReconciliationStatus | undefined,
  ): Promise<string | undefined> {
    if (status?.controlVersionId === undefined || status.payloadVersionId === undefined) {
      return undefined;
    }
    try {
      const current = asSecret(await this.core.readNamespacedSecret({ name, namespace }));
      const annotations = current.metadata?.annotations;
      if (
        !isOwnedByImport(current.metadata, owner) ||
        annotations?.["hemlig.io/control-version-id"] !== status.controlVersionId ||
        annotations?.["hemlig.io/payload-version-id"] !== status.payloadVersionId ||
        annotations?.["hemlig.io/data-checksum"] !== stringMapChecksum(current.data ?? {})
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

  private async listCluster<T>(plural: string): Promise<T[]> {
    const response = unwrap(await this.custom.listClusterCustomObject({ group, version, plural })) as { items?: T[] };
    return response.items ?? [];
  }

  private async listNamespaced<T>(plural: string): Promise<T[]> {
    const response = unwrap(await this.custom.listCustomObjectForAllNamespaces({ group, version, plural })) as { items?: T[] };
    return response.items ?? [];
  }

  private async setFailure(
    namespace: string,
    plural: string,
    name: string,
    generation: number | undefined,
    currentStatus: ReconciliationStatus | undefined,
    error: unknown,
  ): Promise<void> {
    const reason = error instanceof ReconcileError ? error.reason : "ReconcileFailed";
    const message = error instanceof ReconcileError
      ? error.message
      : error instanceof HemligError
        ? `Hemlig returned ${error.status}.`
        : "The reconciliation attempt failed.";
    await this.setStatus(namespace, plural, name, {
      observedGeneration: generation,
      conditions: [falseCondition(reason, message)],
    }, currentStatus);
  }

  private async setStatus(
    namespace: string,
    plural: string,
    name: string,
    status: ReconciliationStatus,
    currentStatus: ReconciliationStatus | undefined,
  ): Promise<void> {
    if (reconciliationStatusEqual(currentStatus, status)) {
      return;
    }
    await this.custom.patchNamespacedCustomObjectStatus({
      group,
      version,
      namespace,
      plural,
      name,
      // CustomObjectsApi prefers JSON Patch. `add` creates status on a new
      // object and replaces the status member on later reconciliations.
      body: [{ op: "add", path: "/status", value: status }],
    });
  }

  private scheduleReconcile(): void {
    if (this.reconcileTimer !== undefined) {
      return;
    }
    this.reconcileTimer = setTimeout(() => {
      this.reconcileTimer = undefined;
      void this.reconcileAll();
    }, this.config.sourceDebounceMilliseconds);
  }

  private startWatches(signal: AbortSignal): void {
    if (this.watch === undefined) {
      return;
    }
    for (const path of [
      `/apis/${group}/${version}/${providerPlural}`,
      `/apis/${group}/${version}/${consumerPlural}`,
      `/apis/${group}/${version}/${importPlural}`,
      `/apis/${group}/${version}/${exportPlural}`,
      "/api/v1/secrets",
      "/api/v1/namespaces",
    ]) {
      void this.watchPath(path, signal);
    }
  }

  private async watchPath(path: string, signal: AbortSignal): Promise<void> {
    if (this.watch === undefined || signal.aborted) {
      return;
    }
    try {
      await this.watch.watch(path, {}, () => this.scheduleReconcile(), () => {
        if (!signal.aborted) {
          setTimeout(() => { void this.watchPath(path, signal); }, 1_000);
        }
      });
    } catch {
      if (!signal.aborted) {
        setTimeout(() => { void this.watchPath(path, signal); }, 1_000);
      }
    }
  }
}

export const v1BetaControllerConfigFromEnvironment = (): V1BetaControllerConfig => ({
  intervalMilliseconds: positiveMilliseconds(process.env.HEMLIG_RECONCILE_INTERVAL_MS, 600_000),
  sourceDebounceMilliseconds: positiveMilliseconds(process.env.HEMLIG_SOURCE_DEBOUNCE_MS, 250),
});

class MqttHintManager {
  private readonly clients = new Map<string, { readonly fingerprint: string; readonly client: MqttClient }>();

  public constructor(private readonly onHint: () => void) {}

  public ensure(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly clientId: string;
    readonly topic: string;
    readonly certificate: Buffer;
    readonly privateKey: Buffer;
  }): void {
    const fingerprint = createHash("sha256")
      .update(input.endpoint)
      .update(input.clientId)
      .update(input.topic)
      .update(input.certificate)
      .digest("hex");
    const current = this.clients.get(input.key);
    if (current?.fingerprint === fingerprint) {
      return;
    }
    current?.client.end(true);
    const client = mqtt.connect(`mqtts://${input.endpoint}:8883`, {
      clientId: input.clientId,
      cert: input.certificate,
      key: input.privateKey,
      clean: true,
      reconnectPeriod: 1_000,
      connectTimeout: 10_000,
      rejectUnauthorized: true,
    });
    client.on("connect", () => {
      client.subscribe(input.topic, { qos: 1 });
      this.onHint();
    });
    client.on("message", () => this.onHint());
    this.clients.set(input.key, { fingerprint, client });
  }

  public stop(): void {
    for (const entry of this.clients.values()) {
      entry.client.end(true);
    }
    this.clients.clear();
  }
}

class ReconcileError extends Error {
  public constructor(readonly reason: string, message: string) {
    super(message);
  }
}

const agentClient = (url: string, certificate: Buffer, privateKey: Buffer): HemligClient =>
  new HemligClient(new URL(url), new NodeHttpsTransport({ cert: certificate, key: privateKey }));

const generateCsr = (): { readonly privateKeyPem: string; readonly csrPem: string } => {
  const pair = forge.pki.rsa.generateKeyPair({ bits: 3072, e: 0x10001 });
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = pair.publicKey;
  csr.setSubject([{ name: "commonName", value: "Hemlig Kubernetes agent" }]);
  csr.sign(pair.privateKey, forge.md.sha256.create());
  return {
    privateKeyPem: forge.pki.privateKeyToPem(pair.privateKey),
    csrPem: forge.pki.certificationRequestToPem(csr),
  };
};

const metadataEqual = (left: SecretMetadata, right: SecretMetadata): boolean =>
  stableJson(left) === stableJson(right);

const reconciliationStatusEqual = (
  current: ReconciliationStatus | undefined,
  desired: ReconciliationStatus,
): boolean =>
  current !== undefined &&
  stableJson(normalizeReconciliationStatus(current)) === stableJson(normalizeReconciliationStatus(desired));

const normalizeReconciliationStatus = (status: ReconciliationStatus): Omit<ReconciliationStatus, "conditions"> & {
  readonly conditions?: readonly Omit<Condition, "lastTransitionTime">[];
} => ({
  ...status,
  conditions: status.conditions?.map((condition) => ({
    type: condition.type,
    status: condition.status,
    reason: condition.reason,
    message: condition.message,
  })),
});

const stableJson = (value: unknown): string => JSON.stringify(sortValue(value));

const sortValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, sortValue(nested)]));
  }
  return value;
};

const operationKey = (metadata: ObjectMeta, operation: string): string =>
  createHash("sha256").update(`${metadata.uid ?? resourceKey(metadata)}:${metadata.generation ?? 0}:${operation}`).digest("hex");

const resourceKey = (metadata: ObjectMeta): string =>
  `${required(metadata.namespace, "resource namespace")}/${required(metadata.name, "resource name")}`;

const asSecret = (value: unknown): IdentitySecret => unwrap(value) as IdentitySecret;

const unwrap = (value: unknown): unknown =>
  typeof value === "object" && value !== null && "body" in value
    ? (value as { body: unknown }).body
    : value;

const valueData = (secret: IdentitySecret, key: string): string | undefined => secret.data?.[key];

const requiredData = (secret: IdentitySecret, key: string): string => {
  const value = valueData(secret, key);
  if (value === undefined) {
    throw new ReconcileError("IdentityOwnershipConflict", `The managed identity Secret is missing ${key}.`);
  }
  return value;
};

const required = (value: string | undefined, field: string): string => {
  if (value === undefined || value.length === 0) {
    throw new Error(`${field} is required.`);
  }
  return value;
};

const isNotFound = (error: unknown): boolean =>
  typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === 404;

const isAlreadyExists = (error: unknown): boolean =>
  typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === 409;

const stringMapChecksum = (data: Readonly<Record<string, string>>): string =>
  createHash("sha256")
    .update(JSON.stringify(Object.entries(data).sort(([left], [right]) => left.localeCompare(right))))
    .digest("hex");

const readyCondition = (reason: string, message: string): Condition => ({
  type: "Ready",
  status: "True",
  reason,
  message,
  lastTransitionTime: new Date().toISOString(),
});

const falseCondition = (reason: string, message: string): Condition => ({
  type: "Ready",
  status: "False",
  reason,
  message,
  lastTransitionTime: new Date().toISOString(),
});

const positiveMilliseconds = (value: string | undefined, fallback: number): number => {
  const parsed = Number.parseInt(value ?? String(fallback), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 3_600_000) {
    throw new Error("Controller interval values must be between 1 and 3600000 milliseconds.");
  }
  return parsed;
};

const wait = async (milliseconds: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => {
      clearTimeout(timeout);
      resolve();
    }, { once: true });
  });
