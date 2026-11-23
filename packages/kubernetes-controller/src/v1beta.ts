import {
  X509Certificate,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  randomUUID,
} from "node:crypto";
import { promisify } from "node:util";
import * as k8s from "@kubernetes/client-node";
import mqtt, { type MqttClient } from "mqtt";
import forge from "node-forge";
import {
  HemligClient,
  HemligError,
  type AgentConfig,
  type AgentControl,
  type AgentSyncEntry,
  type ControlRevision,
  type SecretMetadata,
  type SecretPayload,
} from "@zyno-io/hemlig-client";
import { NodeHttpsTransport } from "@zyno-io/hemlig-client/node";
import {
  allowsConsumerReference,
  consumerReferenceKey,
  namespaceMatches,
} from "./references";
import { PkiModule } from "./pki/module";
import { pkiConfigFromEnvironment } from "./pki/types";
import {
  isOwnedByImport,
  kubernetesDataToPayload,
  payloadChecksum,
  payloadToKubernetesData,
} from "./index";

const group = "hemlig.zyno.io";
const version = "v1beta1";
const providerPlural = "hemligproviders";
const consumerPlural = "hemligconsumers";
const importPlural = "hemligsecretimports";
const exportPlural = "hemligsecretexports";
const controllerLabel = "hemlig.zyno.io/managed-by";
const consumerOwnerAnnotation = "hemlig.zyno.io/consumer-owner";
const identityCsrDataKey = "hemlig.zyno.io.csr";
const rotateIdentityAnnotation = "hemlig.zyno.io/rotate-identity";
const rotationRequestAnnotation = "hemlig.zyno.io/rotation-request";
const rotatedAtAnnotation = "hemlig.zyno.io/rotated-at";
const apiFingerprintAnnotation = "hemlig.zyno.io/api-fingerprint";
const nextKeyDataKey = "hemlig.zyno.io.next-tls.key";
const nextCsrDataKey = "hemlig.zyno.io.next-csr";
const nextCertificateDataKey = "hemlig.zyno.io.next-tls.crt";
const previousCertificateDataKey = "hemlig.zyno.io.previous-tls.crt";
const previousKeyDataKey = "hemlig.zyno.io.previous-tls.key";
/** Binds staged next-* material to the certificate that requested it. */
const nextPredecessorAnnotation = "hemlig.zyno.io/next-predecessor-sha256";
const defaultRotateBeforeMilliseconds = 720 * 3_600_000;

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

interface IdentityStatus {
  readonly apiFingerprint: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly rotateAfter?: string;
  readonly lastRotationTime?: string;
  readonly rotationRequest?: string;
  readonly lastRotationError?: string;
}

interface ReconciliationStatus {
  readonly identity?: IdentityStatus;
  readonly secretUid?: string;
  readonly syncCursor?: string;
  readonly syncIdentity?: string;
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
  readonly apiVersion: "hemlig.zyno.io/v1beta1";
  readonly kind: "HemligProvider";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly bootstrapUrl: string;
    readonly apiUrl: string;
    readonly allowedNamespaces: {
      readonly matchLabels: Readonly<Record<string, string>>;
    };
  };
}

export interface HemligConsumer {
  readonly apiVersion: "hemlig.zyno.io/v1beta1";
  readonly kind: "HemligConsumer";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly providerRef: string;
    readonly bootstrapTokenRef: { readonly name: string; readonly key: string };
    readonly identity: {
      readonly secretName: string;
      readonly rotateBefore?: string;
    };
    /** Explicitly permits another namespace to reference this cluster consumer. */
    readonly allowCrossNamespaceReferences?: boolean;
    /** Lets HemligClusterIssuers use this consumer from any namespace; separate from allowCrossNamespaceReferences. */
    readonly allowClusterIssuers?: boolean;
  };
  readonly status?: ReconciliationStatus;
}

export interface HemligSecretImport {
  readonly apiVersion: "hemlig.zyno.io/v1beta1";
  readonly kind: "HemligSecretImport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: string;
    /** Defaults to this Import's namespace; cross-namespace use requires consumer opt-in. */
    readonly consumerNamespace?: string;
    readonly secretId: string;
    readonly target?: { readonly name?: string; readonly type?: string };
    readonly deletionPolicy?: "Retain" | "Delete";
  };
  readonly status?: ReconciliationStatus;
}

export interface HemligSecretExport {
  readonly apiVersion: "hemlig.zyno.io/v1beta1";
  readonly kind: "HemligSecretExport";
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: string;
    /** Defaults to this Export's namespace; cross-namespace use requires consumer opt-in. */
    readonly consumerNamespace?: string;
    readonly secretId: string;
    readonly source: { readonly name: string };
    readonly metadata: SecretMetadata;
  };
  readonly status?: ReconciliationStatus;
}

export interface CoreApi {
  readNamespacedSecret(input: {
    readonly name: string;
    readonly namespace: string;
  }): Promise<unknown>;
  createNamespacedSecret(input: {
    readonly namespace: string;
    readonly body: unknown;
  }): Promise<unknown>;
  replaceNamespacedSecret(input: {
    readonly name: string;
    readonly namespace: string;
    readonly body: unknown;
  }): Promise<unknown>;
  deleteNamespacedSecret(input: {
    readonly name: string;
    readonly namespace: string;
  }): Promise<unknown>;
  readNamespace(input: { readonly name: string }): Promise<unknown>;
  readNamespacedConfigMap(input: {
    readonly name: string;
    readonly namespace: string;
  }): Promise<unknown>;
  createNamespacedConfigMap(input: {
    readonly namespace: string;
    readonly body: unknown;
  }): Promise<unknown>;
  replaceNamespacedConfigMap(input: {
    readonly name: string;
    readonly namespace: string;
    readonly body: unknown;
  }): Promise<unknown>;
  deleteNamespacedConfigMap(input: {
    readonly name: string;
    readonly namespace: string;
    readonly body?: unknown;
  }): Promise<unknown>;
}

export interface CustomApi {
  listClusterCustomObject(input: {
    readonly group: string;
    readonly version: string;
    readonly plural: string;
    readonly limit?: number;
    readonly _continue?: string;
  }): Promise<unknown>;
  listCustomObjectForAllNamespaces(input: {
    readonly group: string;
    readonly version: string;
    readonly plural: string;
    readonly limit?: number;
    readonly _continue?: string;
  }): Promise<unknown>;
  getNamespacedCustomObject(input: {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
  }): Promise<unknown>;
  getClusterCustomObject(input: {
    readonly group: string;
    readonly version: string;
    readonly plural: string;
    readonly name: string;
  }): Promise<unknown>;
  replaceNamespacedCustomObjectStatus(input: {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
    readonly body: unknown;
  }): Promise<unknown>;
  patchClusterCustomObjectStatus(input: {
    readonly group: string;
    readonly version: string;
    readonly plural: string;
    readonly name: string;
    readonly body: unknown;
  }): Promise<unknown>;
  patchNamespacedCustomObjectStatus(input: {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
    readonly body: unknown;
  }): Promise<unknown>;
}

export interface RegisteredConsumer {
  readonly key: string;
  readonly uid: string | undefined;
  readonly generation: number | undefined;
  readonly resource: HemligConsumer;
  readonly provider: HemligProvider;
  readonly client: HemligClient;
  readonly consumerId: string;
  readonly environment: string;
  /** sha256 hex of the current identity certificate. */
  readonly identityFingerprint: string;
}

/** Read-only view of the Ready consumers published by the last full pass. */
export interface ConsumerRegistry {
  get(key: string): RegisteredConsumer | undefined;
  onChange(listener: (changed: ReadonlySet<string>) => void): () => void;
}

const registrySignature = (entry: RegisteredConsumer): string =>
  [
    entry.uid,
    entry.generation,
    entry.consumerId,
    entry.environment,
    entry.identityFingerprint,
    entry.provider.metadata.generation,
    entry.provider.spec.apiUrl,
    JSON.stringify(
      Object.entries(entry.provider.spec.allowedNamespaces.matchLabels).sort(
        ([left], [right]) => (left < right ? -1 : left > right ? 1 : 0),
      ),
    ),
  ].join("|");

class MutableConsumerRegistry implements ConsumerRegistry {
  private entries: ReadonlyMap<string, RegisteredConsumer> = new Map();
  private readonly listeners = new Set<
    (changed: ReadonlySet<string>) => void
  >();

  public get(key: string): RegisteredConsumer | undefined {
    return this.entries.get(key);
  }

  public onChange(listener: (changed: ReadonlySet<string>) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Replaces the whole map atomically, then reports the keys that changed. */
  public publish(next: ReadonlyMap<string, RegisteredConsumer>): void {
    const previous = this.entries;
    this.entries = new Map(next);
    const changed = new Set<string>();
    for (const [key, entry] of next) {
      const before = previous.get(key);
      // resourceVersion is excluded on purpose: consumer status changes every pass.
      if (
        before === undefined ||
        registrySignature(before) !== registrySignature(entry)
      ) {
        changed.add(key);
      }
    }
    for (const key of previous.keys()) {
      if (!next.has(key)) changed.add(key);
    }
    if (changed.size === 0) return;
    for (const listener of [...this.listeners]) {
      try {
        listener(changed);
      } catch {
        // A listener must not break the reconcile pass.
      }
    }
  }
}

interface ReadyConsumer {
  readonly resource: HemligConsumer;
  readonly provider: HemligProvider;
  readonly client: HemligClient;
  readonly config: AgentConfig;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
  readonly syncEntries: ReadonlyMap<string, AgentSyncEntry>;
  readonly syncSnapshot: boolean;
  readonly syncCheckpoint: string;
  readonly syncIdentity: string;
  readonly readyStatus: ReconciliationStatus;
  syncFailed: boolean;
  /** One authoritative grant read shared by every import that needs it. */
  revocationCheck?: Promise<AgentConfig>;
}

interface IdentitySecret {
  readonly metadata?: ObjectMeta;
  readonly data?: Readonly<Record<string, string>>;
  readonly binaryData?: Readonly<Record<string, string>>;
  readonly type?: string;
}

export { consumerReferenceKey, allowsConsumerReference } from "./references";

export interface V1BetaControllerConfig {
  readonly intervalMilliseconds: number;
  readonly sourceDebounceMilliseconds: number;
  /** Retry after a transient Kubernetes API failure without restarting the Pod. */
  readonly reconcileRetryMilliseconds?: number;
  /** Upper bound for the exponential retry backoff. */
  readonly reconcileRetryMaxMilliseconds?: number;
  /** Base backoff after a failed identity rotation attempt (default 60 s). */
  readonly identityRotationRetryMilliseconds?: number;
  /** Upper bound for the identity rotation backoff (default 6 h). */
  readonly identityRotationRetryMaxMilliseconds?: number;
  /** RSA modulus for rotated identity keys (default 3072; lowered only by tests). */
  readonly identityKeyBits?: number;
}

/**
 * v1beta reconciler. It never reads an administrator token: automatic
 * enrollment is constrained by the pre-created AgentGrant encoded in the
 * single-use bootstrap capability, and all subsequent calls use agent mTLS.
 */
export class HemligV1BetaController {
  private readonly mqtt = new MqttHintManager(() => this.scheduleReconcile());
  private reconcileTimer: NodeJS.Timeout | undefined;
  private reconcileDueAt = 0;
  private reconciling = false;
  /** A reconcile was requested while a pass was running; run another after it. */
  private rerunRequested = false;
  /** The latest transient resource failure in the current pass, if any. */
  private passRetryError: { readonly error: unknown } | undefined;
  /** Consecutive failed passes, used for exponential backoff. */
  private retryAttempt = 0;
  private watch: k8s.Watch | undefined;
  public readonly consumerRegistry = new MutableConsumerRegistry();
  private pki: PkiModule | undefined;
  private readonly watchResourceVersions = new Map<string, string>();
  private secretDependencies = new Set<string>();
  private namespaceDependencies = new Set<string>();
  /**
   * In-memory rotation backoff per consumer. A failed rotation never uses the
   * pass-level retry (it must not look like a consumer outage); it schedules
   * its own reconcile for when the backoff elapses, and the periodic sweep is
   * the safety net. A restart simply retries immediately.
   */
  private readonly rotationBackoff = new Map<
    string,
    {
      attempts: number;
      until: number;
      token: string | undefined;
      reason: string;
      message: string;
    }
  >();

  public constructor(
    private readonly core: CoreApi,
    private readonly custom: CustomApi,
    private readonly config: V1BetaControllerConfig,
  ) {}

  public static fromDefaultConfig(
    config: V1BetaControllerConfig,
  ): HemligV1BetaController {
    const kubeConfig = new k8s.KubeConfig();
    kubeConfig.loadFromDefault();
    const core = kubeConfig.makeApiClient(
      k8s.CoreV1Api,
    ) as unknown as CoreApi;
    const custom = kubeConfig.makeApiClient(
      k8s.CustomObjectsApi,
    ) as unknown as CustomApi;
    const controller = new HemligV1BetaController(core, custom, config);
    controller.watch = new k8s.Watch(kubeConfig);
    controller.pki = new PkiModule({
      core,
      custom,
      watch: controller.watch,
      registry: controller.consumerRegistry,
      config: pkiConfigFromEnvironment(),
    });
    return controller;
  }

  public async run(signal: AbortSignal): Promise<void> {
    let watchesStarted = false;
    while (!signal.aborted) {
      try {
        await this.reconcileAll();
        if (!watchesStarted) {
          this.startWatches(signal);
          watchesStarted = true;
        }
        await wait(this.config.intervalMilliseconds, signal);
      } catch (error) {
        this.reportReconcileFailure(error);
        await wait(this.nextRetryDelay(error), signal);
      }
    }
    this.pki?.stop();
    this.mqtt.stop();
  }

  public async reconcileAll(): Promise<void> {
    if (this.reconciling) {
      // Dropping this request would lose a watch event or a transient-failure
      // retry until the next periodic sweep.
      this.rerunRequested = true;
      return;
    }
    this.reconciling = true;
    this.rerunRequested = false;
    this.passRetryError = undefined;
    try {
      const [providers, consumers, imports, secretExports] = await Promise.all([
        this.listCluster<HemligProvider>(providerPlural),
        this.listNamespaced<HemligConsumer>(consumerPlural),
        this.listNamespaced<HemligSecretImport>(importPlural),
        this.listNamespaced<HemligSecretExport>(exportPlural),
      ]);
      this.secretDependencies = new Set([
        ...consumers.flatMap((resource) =>
          [
            resource.spec.identity.secretName,
            resource.spec.bootstrapTokenRef.name,
          ].map((name) => `${resource.metadata.namespace}/${name}`),
        ),
        ...imports.map(
          (resource) =>
            `${resource.metadata.namespace}/${resource.spec.target?.name ?? resource.metadata.name}`,
        ),
        ...secretExports.map(
          (resource) =>
            `${resource.metadata.namespace}/${resource.spec.source.name}`,
        ),
      ]);
      this.namespaceDependencies = new Set(
        [...consumers, ...imports, ...secretExports].flatMap((resource) =>
          resource.metadata.namespace === undefined
            ? []
            : [resource.metadata.namespace],
        ),
      );
      const providersByName = new Map(
        providers.flatMap((provider) =>
          provider.metadata.name === undefined
            ? []
            : [[provider.metadata.name, provider] as const],
        ),
      );
      const readyConsumers = new Map<string, ReadyConsumer>();
      for (const consumer of consumers) {
        const ready = await this.reconcileConsumer(consumer, providersByName);
        if (ready !== undefined) {
          readyConsumers.set(resourceKey(consumer.metadata), ready);
        }
      }
      this.consumerRegistry.publish(
        new Map(
          [...readyConsumers].map(([key, ready]) => [
            key,
            {
              key,
              uid: ready.resource.metadata.uid,
              generation: ready.resource.metadata.generation,
              resource: ready.resource,
              provider: ready.provider,
              client: ready.client,
              consumerId: ready.config.consumerId,
              environment: ready.config.environment,
              identityFingerprint: createHash("sha256")
                .update(ready.certificate)
                .digest("hex"),
            } satisfies RegisteredConsumer,
          ]),
        ),
      );
      for (const resource of imports) {
        const namespace = required(
          resource.metadata.namespace,
          "import namespace",
        );
        const consumer = readyConsumers.get(
          consumerReferenceKey(
            namespace,
            resource.spec.consumerRef,
            resource.spec.consumerNamespace,
          ),
        );
        const usableConsumer = allowsConsumerReference(
          namespace,
          resource.spec.consumerNamespace,
          consumer?.resource,
        )
          ? consumer
          : undefined;
        if (consumer !== undefined && usableConsumer === undefined) {
          // An explicit cross-namespace policy removal is a revocation, unlike
          // a temporarily unavailable consumer. Never leave its owned copy.
          await this.removeOwnedImport(resource);
        }
        await this.reconcileImport(resource, usableConsumer);
      }
      for (const resource of secretExports) {
        const namespace = required(
          resource.metadata.namespace,
          "export namespace",
        );
        const consumer = readyConsumers.get(
          consumerReferenceKey(
            namespace,
            resource.spec.consumerRef,
            resource.spec.consumerNamespace,
          ),
        );
        const usableConsumer = allowsConsumerReference(
          namespace,
          resource.spec.consumerNamespace,
          consumer?.resource,
        )
          ? consumer
          : undefined;
        await this.reconcileExport(resource, usableConsumer);
      }
      for (const consumer of readyConsumers.values()) {
        if (consumer.syncFailed) continue;
        await this.setStatus(
          required(consumer.resource.metadata.namespace, "consumer namespace"),
          consumerPlural,
          required(consumer.resource.metadata.name, "consumer name"),
          {
            ...consumer.readyStatus,
            syncCursor: consumer.syncCheckpoint,
            syncIdentity: consumer.syncIdentity,
          },
          consumer.readyStatus,
        );
      }
    } finally {
      this.reconciling = false;
    }
    // Schedule after the pass so a retry cannot fire into the running pass and
    // be discarded by the guard above.
    const retry = this.takePassRetry();
    if (retry === undefined) {
      this.retryAttempt = 0;
    } else {
      this.scheduleReconcile(this.nextRetryDelay(retry.error));
    }
    if (this.rerunRequested) {
      // A change observed during this pass must not wait behind the backoff.
      this.rerunRequested = false;
      this.scheduleReconcile();
    }
  }

  private async reconcileConsumer(
    resource: HemligConsumer,
    providers: ReadonlyMap<string, HemligProvider>,
  ): Promise<ReadyConsumer | undefined> {
    const namespace = required(
      resource.metadata.namespace,
      "consumer namespace",
    );
    const name = required(resource.metadata.name, "consumer name");
    let loadedCertificate: Buffer | undefined;
    try {
      const provider = providers.get(resource.spec.providerRef);
      if (provider === undefined) {
        throw new ReconcileError(
          "ProviderNotFound",
          "The referenced HemligProvider was not found.",
        );
      }
      await this.assertNamespaceAllowed(namespace, provider);
      let loaded = await this.loadOrBootstrapIdentity(resource, provider);
      loadedCertificate = loaded.certificate;
      let oldClient = agentClient(
        provider.spec.apiUrl,
        loaded.certificate,
        loaded.privateKey,
      );
      const syncWith = () =>
        this.synchronize(
          oldClient,
          resource.status?.syncIdentity ===
            syncIdentityFor(provider.spec.apiUrl, loaded.certificate)
            ? resource.status.syncCursor
            : undefined,
        );
      const authenticationFailed = () => {
        this.mqtt.remove(resourceKey(resource.metadata));
        return new ReconcileError(
          "AuthenticationFailed",
          "Hemlig rejected this consumer's client certificate (expired, revoked, or untrusted); see status.identity and the identity recovery runbook.",
        );
      };
      let sync: Awaited<ReturnType<HemligV1BetaController["synchronize"]>>;
      try {
        sync = await syncWith();
      } catch (error) {
        if (!isIdentityAuthenticationFailure(error)) throw error;
        const recovered = await this.recoverIssuedSuccessor(
          resource,
          provider,
          loaded,
        );
        if (recovered === undefined) throw authenticationFailed();
        loaded = recovered;
        loadedCertificate = recovered.certificate;
        oldClient = recovered.client;
        try {
          sync = await syncWith();
        } catch (retryError) {
          throw isIdentityAuthenticationFailure(retryError)
            ? authenticationFailed()
            : retryError;
        }
      }
      const agentConfig = sync.config;
      const rotation = await this.reconcileIdentityRotation(
        resource,
        provider,
        loaded,
        oldClient,
        agentConfig,
      );
      const identity = {
        certificate: rotation.certificate,
        privateKey: rotation.privateKey,
      };
      const syncIdentity = syncIdentityFor(
        provider.spec.apiUrl,
        identity.certificate,
      );
      this.mqtt.ensure({
        key: resourceKey(resource.metadata),
        ...agentConfig.mqtt,
        certificate: identity.certificate,
        privateKey: identity.privateKey,
      });
      const { identity: _staleIdentity, ...retainedStatus } =
        resource.status ?? {};
      const readyStatus: ReconciliationStatus = {
        ...retainedStatus,
        observedGeneration: resource.metadata.generation,
        consumerId: agentConfig.consumerId,
        environment: agentConfig.environment,
        grantId: agentConfig.grant.grantId,
        ...(rotation.status === undefined ? {} : { identity: rotation.status }),
        conditions: [
          readyCondition(
            "IdentityReady",
            "Bootstrap identity is active and scoped by Hemlig.",
          ),
          ...(rotation.condition === undefined ? [] : [rotation.condition]),
        ],
      };
      await this.setStatus(
        namespace,
        consumerPlural,
        name,
        readyStatus,
        resource.status,
      );
      return {
        resource,
        provider,
        client: rotation.client,
        config: agentConfig,
        ...identity,
        readyStatus,
        syncIdentity,
        syncCheckpoint: sync.checkpoint,
        syncEntries: sync.entries,
        syncSnapshot: sync.snapshot,
        syncFailed: false,
      };
    } catch (error) {
      const described =
        loadedCertificate === undefined
          ? undefined
          : describeIdentity(loadedCertificate);
      await this.setFailure(
        namespace,
        consumerPlural,
        name,
        resource.metadata.generation,
        resource.status,
        error,
        described === undefined
          ? {}
          : {
              identity: {
                ...resource.status?.identity,
                apiFingerprint: described.apiFingerprint,
                notBefore: described.notBefore,
                notAfter: described.notAfter,
              },
            },
      );
      this.scheduleTransientResourceRetry(error);
      return undefined;
    }
  }

  /**
   * Self-rotates the agent's mTLS identity. The old identity stays in use
   * until the new one has authenticated; any failure returns the old identity
   * and reports through the IdentityRotation condition only (never Ready).
   */
  private async reconcileIdentityRotation(
    resource: HemligConsumer,
    provider: HemligProvider,
    loaded: { readonly certificate: Buffer; readonly privateKey: Buffer },
    oldClient: HemligClient,
    agentConfig: AgentConfig,
  ): Promise<{
    readonly certificate: Buffer;
    readonly privateKey: Buffer;
    readonly client: HemligClient;
    readonly status: IdentityStatus | undefined;
    readonly condition: Condition | undefined;
  }> {
    const unchanged = (
      status: IdentityStatus | undefined,
      condition: Condition | undefined,
    ) => ({ ...loaded, client: oldClient, status, condition });
    const info = describeIdentity(loaded.certificate);
    if (info === undefined) return unchanged(undefined, undefined);
    const namespace = required(
      resource.metadata.namespace,
      "consumer namespace",
    );
    const key = resourceKey(resource.metadata);
    const secretName = resource.spec.identity.secretName;
    let secret: IdentitySecret;
    try {
      secret = asSecret(
        await this.core.readNamespacedSecret({ name: secretName, namespace }),
      );
    } catch {
      return unchanged(identityStatusFor(info, undefined, {}), undefined);
    }
    const annotations = secret.metadata?.annotations ?? {};
    const window = rotationWindow(resource.spec.identity.rotateBefore, info);
    const statusFor = (
      cert: typeof info,
      secretAnnotations: Readonly<Record<string, string>>,
      error?: string,
    ) =>
      identityStatusFor(
        cert,
        rotationWindow(resource.spec.identity.rotateBefore, cert),
        secretAnnotations,
        error,
      );
    let pending = valueData(secret, nextKeyDataKey) !== undefined;
    if (
      pending &&
      annotations[nextPredecessorAnnotation] !==
        certificateBinding(loaded.certificate)
    ) {
      // Staged for a different certificate (for example an operator rolled
      // back tls.* mid-rotation). Never promote it over the current pair.
      await this.discardPendingIdentity(namespace, secretName, loaded.certificate);
      pending = false;
    }
    const token = resource.metadata.annotations?.[rotateIdentityAnnotation];
    const manual = token !== undefined && token !== annotations[rotationRequestAnnotation];
    const automatic =
      window !== undefined && Date.now() >= Date.parse(info.notAfter) - window;
    if (!pending && !manual && !automatic) {
      this.rotationBackoff.delete(key);
      return unchanged(
        statusFor(info, annotations),
        window === undefined
          ? condition(
              "IdentityRotation",
              "True",
              "AutomaticRotationDisabled",
              "Automatic rotation is disabled; annotate the HemligConsumer with hemlig.zyno.io/rotate-identity to rotate manually.",
            )
          : condition(
              "IdentityRotation",
              "True",
              "NotDue",
              `Automatic rotation after ${new Date(Date.parse(info.notAfter) - window).toISOString()}.`,
            ),
      );
    }
    const backoff = this.rotationBackoff.get(key);
    if (backoff !== undefined && !(manual && token !== backoff.token)) {
      const remaining = backoff.until - Date.now();
      if (remaining > 0) {
        this.scheduleReconcile(remaining);
        return unchanged(
          statusFor(info, annotations, `${backoff.reason}: ${backoff.message}`),
          condition(
            "IdentityRotation",
            "False",
            backoff.reason,
            backoff.message,
          ),
        );
      }
    }
    try {
      const rotated = await this.rotateIdentity(
        resource,
        provider,
        loaded.certificate,
        oldClient,
        agentConfig,
        manual ? token : undefined,
      );
      this.rotationBackoff.delete(key);
      const rotatedInfo = describeIdentity(rotated.certificate) ?? info;
      return {
        ...rotated,
        status: statusFor(rotatedInfo, rotated.annotations),
        condition: condition(
          "IdentityRotation",
          "True",
          "NotDue",
          "Identity was rotated and verified.",
        ),
      };
    } catch (error) {
      const failure = classifyRotationFailure(error);
      if (failure.discardPending) {
        await this.discardPendingIdentity(namespace, secretName);
      }
      const attempts = (backoff?.attempts ?? 0) + 1;
      const base = this.config.identityRotationRetryMilliseconds ?? 60_000;
      const max = this.config.identityRotationRetryMaxMilliseconds ?? 21_600_000;
      const ceiling = Math.min(max, base * 2 ** Math.min(attempts - 1, 30));
      const delay = Math.round(ceiling / 2 + Math.random() * (ceiling / 2));
      this.rotationBackoff.set(key, {
        attempts,
        until: Date.now() + delay,
        token,
        reason: failure.reason,
        message: failure.message,
      });
      this.scheduleReconcile(delay);
      process.stderr.write(
        `Hemlig identity rotation for ${key} failed (${failure.reason}); retrying in ${delay} ms.\n`,
      );
      return unchanged(
        statusFor(info, annotations, `${failure.reason}: ${failure.message}`),
        condition("IdentityRotation", "False", failure.reason, failure.message),
      );
    }
  }

  private async rotateIdentity(
    resource: HemligConsumer,
    provider: HemligProvider,
    currentCertificate: Buffer,
    oldClient: HemligClient,
    agentConfig: AgentConfig,
    manualToken: string | undefined,
  ): Promise<{
    readonly certificate: Buffer;
    readonly privateKey: Buffer;
    readonly client: HemligClient;
    readonly annotations: Readonly<Record<string, string>>;
  }> {
    const namespace = required(
      resource.metadata.namespace,
      "consumer namespace",
    );
    const name = resource.spec.identity.secretName;
    const owner = resourceKey(resource.metadata);
    const update = (
      mutate: (
        data: Record<string, string>,
        annotations: Record<string, string>,
      ) => void,
    ) => this.updateIdentitySecret(namespace, name, owner, mutate);
    const fresh = asSecret(
      await this.core.readNamespacedSecret({ name, namespace }),
    );
    this.assertIdentityOwnership(fresh, owner);
    const storedCertificate = valueData(fresh, "tls.crt");
    if (
      storedCertificate === undefined ||
      !Buffer.from(storedCertificate, "base64").equals(currentCertificate)
    ) {
      throw new RotationError(
        "RotationFailed",
        "The identity Secret changed during reconciliation; retrying.",
        false,
      );
    }
    let secret = fresh;
    if (
      valueData(secret, nextKeyDataKey) === undefined ||
      valueData(secret, nextCsrDataKey) === undefined
    ) {
      const generated = await generateRotationCsr(
        this.config.identityKeyBits ?? 3072,
      );
      secret = await update((data, annotations) => {
        if (!storedCertificateMatches(data, currentCertificate))
          throw identitySecretChanged();
        data[nextKeyDataKey] = b64(generated.privateKeyPem);
        data[nextCsrDataKey] = b64(generated.csrPem);
        delete data[nextCertificateDataKey];
        annotations[nextPredecessorAnnotation] =
          certificateBinding(currentCertificate);
      });
    }
    const nextKey = Buffer.from(requiredData(secret, nextKeyDataKey), "base64");
    if (valueData(secret, nextCertificateDataKey) === undefined) {
      const csrPem = Buffer.from(
        requiredData(secret, nextCsrDataKey),
        "base64",
      ).toString("utf8");
      const issued = await oldClient.rotateAgentIdentity(
        csrPem,
        createHash("sha256").update(csrPem).digest("hex"),
      );
      if (
        issued.consumerId !== agentConfig.consumerId ||
        !publicKeysMatch(issued.apiCertificatePem, nextKey)
      ) {
        throw new RotationError(
          "RotationRejected",
          "Hemlig returned an identity that does not match the pending key; it was discarded.",
          true,
        );
      }
      const pendingKey = requiredData(secret, nextKeyDataKey);
      const pendingCsr = requiredData(secret, nextCsrDataKey);
      secret = await update((data) => {
        if (
          !storedCertificateMatches(data, currentCertificate) ||
          data[nextKeyDataKey] !== pendingKey ||
          data[nextCsrDataKey] !== pendingCsr ||
          data[nextCertificateDataKey] !== undefined
        )
          throw identitySecretChanged();
        data[nextCertificateDataKey] = b64(issued.apiCertificatePem);
      });
    }
    const nextCertificate = Buffer.from(
      requiredData(secret, nextCertificateDataKey),
      "base64",
    );
    const nextClient = agentClient(
      provider.spec.apiUrl,
      nextCertificate,
      nextKey,
    );
    try {
      const verified = await nextClient.getAgentConfig();
      if (
        verified.consumerId !== agentConfig.consumerId ||
        verified.environment !== agentConfig.environment
      ) {
        throw new RotationError(
          "VerificationFailed",
          "The new identity authenticated as a different consumer; it was discarded.",
          true,
        );
      }
    } catch (error) {
      if (error instanceof RotationError) throw error;
      throw new RotationError(
        "VerificationFailed",
        "The new identity could not be verified; keeping the current identity.",
        error instanceof HemligError &&
          error.status === 403 &&
          error.code === "identity_not_active",
      );
    }
    const finalAnnotations = await this.swapIdentity(
      resource,
      currentCertificate,
      requiredData(secret, nextCertificateDataKey),
      requiredData(secret, nextKeyDataKey),
      manualToken,
    );
    return {
      certificate: nextCertificate,
      privateKey: nextKey,
      client: nextClient,
      annotations: finalAnnotations,
    };
  }

  private async updateIdentitySecret(
    namespace: string,
    name: string,
    owner: string,
    mutate: (
      data: Record<string, string>,
      annotations: Record<string, string>,
    ) => void,
  ): Promise<IdentitySecret> {
    const current = asSecret(
      await this.core.readNamespacedSecret({ name, namespace }),
    );
    this.assertIdentityOwnership(current, owner);
    const data = { ...current.data };
    const annotations = { ...current.metadata?.annotations };
    mutate(data, annotations);
    const body = {
      apiVersion: "v1",
      kind: "Secret",
      metadata: { ...current.metadata, annotations },
      type: current.type ?? "Opaque",
      data,
    };
    await this.core.replaceNamespacedSecret({ name, namespace, body });
    return body;
  }

  /**
   * Promotes a verified pending identity. The write only applies when the
   * Secret still holds the certificate this pass started with and the exact
   * pending values that were verified, so an operator's concurrent rollback or
   * replacement is never clobbered.
   */
  private async swapIdentity(
    resource: HemligConsumer,
    currentCertificate: Buffer,
    nextCertificate: string,
    nextKey: string,
    manualToken: string | undefined,
  ): Promise<Record<string, string>> {
    const newInfo = describeIdentity(Buffer.from(nextCertificate, "base64"));
    let finalAnnotations: Record<string, string> = {};
    await this.updateIdentitySecret(
      required(resource.metadata.namespace, "consumer namespace"),
      resource.spec.identity.secretName,
      resourceKey(resource.metadata),
      (data, annotations) => {
        if (
          !storedCertificateMatches(data, currentCertificate) ||
          data[nextKeyDataKey] !== nextKey ||
          data[nextCertificateDataKey] !== nextCertificate
        )
          throw identitySecretChanged();
        const oldCertificate = data["tls.crt"];
        const oldKey = data["tls.key"];
        if (oldCertificate !== undefined)
          data[previousCertificateDataKey] = oldCertificate;
        if (oldKey !== undefined) data[previousKeyDataKey] = oldKey;
        data["tls.crt"] = nextCertificate;
        data["tls.key"] = nextKey;
        delete data[nextKeyDataKey];
        delete data[nextCsrDataKey];
        delete data[nextCertificateDataKey];
        delete annotations[nextPredecessorAnnotation];
        if (newInfo !== undefined)
          annotations[apiFingerprintAnnotation] = newInfo.apiFingerprint;
        annotations[rotatedAtAnnotation] = new Date().toISOString();
        if (manualToken !== undefined)
          annotations[rotationRequestAnnotation] = manualToken;
        finalAnnotations = annotations;
      },
    );
    return finalAnnotations;
  }

  /**
   * Recovery for an issued-but-unswapped successor when the current
   * certificate can no longer authenticate: if the persisted successor is
   * valid, matches its key and authenticates as this consumer, promote it.
   * Never discards pending material; any doubt returns undefined.
   */
  private async recoverIssuedSuccessor(
    resource: HemligConsumer,
    provider: HemligProvider,
    current: { readonly certificate: Buffer },
  ): Promise<
    | {
        readonly certificate: Buffer;
        readonly privateKey: Buffer;
        readonly client: HemligClient;
      }
    | undefined
  > {
    try {
      const namespace = required(
        resource.metadata.namespace,
        "consumer namespace",
      );
      const secret = asSecret(
        await this.core.readNamespacedSecret({
          name: resource.spec.identity.secretName,
          namespace,
        }),
      );
      const nextCertificate = valueData(secret, nextCertificateDataKey);
      const nextKey = valueData(secret, nextKeyDataKey);
      if (nextCertificate === undefined || nextKey === undefined)
        return undefined;
      const certificate = Buffer.from(nextCertificate, "base64");
      const privateKey = Buffer.from(nextKey, "base64");
      const info = describeIdentity(certificate);
      const now = Date.now();
      if (
        info === undefined ||
        now < Date.parse(info.notBefore) ||
        now >= Date.parse(info.notAfter) ||
        !publicKeysMatch(certificate.toString("utf8"), privateKey)
      )
        return undefined;
      const client = agentClient(provider.spec.apiUrl, certificate, privateKey);
      const verified = await client.getAgentConfig();
      const known = resource.status;
      if (
        !certificateNamesConsumer(current.certificate, verified.consumerId) ||
        (known?.consumerId !== undefined &&
          verified.consumerId !== known.consumerId) ||
        (known?.environment !== undefined &&
          verified.environment !== known.environment)
      )
        return undefined;
      await this.swapIdentity(
        resource,
        current.certificate,
        nextCertificate,
        nextKey,
        undefined,
      );
      return { certificate, privateKey, client };
    } catch (error) {
      // Only definitive outcomes end recovery here (a changed Secret or a
      // successor that cannot authenticate). Transient failures go through
      // the pass backoff instead of becoming a non-retryable auth failure.
      if (
        !(error instanceof RotationError) &&
        !isIdentityAuthenticationFailure(error) &&
        isTransientResourceError(error)
      )
        throw error;
      return undefined;
    }
  }

  private async discardPendingIdentity(
    namespace: string,
    name: string,
    onlyIfStaleFor?: Buffer,
  ): Promise<void> {
    try {
      const current = asSecret(
        await this.core.readNamespacedSecret({ name, namespace }),
      );
      const annotations = { ...current.metadata?.annotations };
      if (
        onlyIfStaleFor !== undefined &&
        annotations[nextPredecessorAnnotation] ===
          certificateBinding(onlyIfStaleFor)
      )
        return;
      const data = { ...current.data };
      delete data[nextKeyDataKey];
      delete data[nextCsrDataKey];
      delete data[nextCertificateDataKey];
      delete annotations[nextPredecessorAnnotation];
      await this.core.replaceNamespacedSecret({
        name,
        namespace,
        body: {
          apiVersion: "v1",
          kind: "Secret",
          metadata: { ...current.metadata, annotations },
          type: current.type ?? "Opaque",
          data,
        },
      });
    } catch {
      // Best effort: a stale pending key is replaced or reused next attempt.
    }
  }

  private async synchronize(
    client: HemligClient,
    syncCursor: string | undefined,
  ): Promise<{
    readonly config: AgentConfig;
    readonly entries: ReadonlyMap<string, AgentSyncEntry>;
    readonly snapshot: boolean;
    readonly checkpoint: string;
  }> {
    // Restart an expired/scope-changed cycle once. A continuously changing
    // grant must back off rather than spin indefinitely through snapshots.
    for (let reset = 0; reset < 2; reset += 1) {
      const entries = new Map<string, AgentSyncEntry>();
      let cursor: string | undefined;
      let config: AgentConfig | undefined;
      let snapshot = false;
      try {
        for (let pageNumber = 0; pageNumber < 1_000; pageNumber += 1) {
          const page = await client.syncAgent(
            cursor === undefined ? { syncCursor } : { cursor },
          );
          config = page.config;
          snapshot = page.snapshot;
          for (const entry of page.changes) entries.set(entry.secretUid, entry);
          if (page.nextCursor === undefined) {
            if (page.syncCursor === undefined)
              throw new Error(
                "Hemlig sync did not return a completed checkpoint.",
              );
            return { config, entries, snapshot, checkpoint: page.syncCursor };
          }
          cursor = page.nextCursor;
        }
        throw new Error("Hemlig sync exceeded its page limit.");
      } catch (error) {
        if (
          !(error instanceof HemligError) ||
          error.status !== 410 ||
          reset !== 0
        )
          throw error;
        syncCursor = undefined;
      }
    }
    throw new Error("Hemlig sync did not complete.");
  }

  private async loadOrBootstrapIdentity(
    resource: HemligConsumer,
    provider: HemligProvider,
  ): Promise<{ readonly certificate: Buffer; readonly privateKey: Buffer }> {
    const namespace = required(
      resource.metadata.namespace,
      "consumer namespace",
    );
    const owner = resourceKey(resource.metadata);
    const identityName = resource.spec.identity.secretName;
    let identity: IdentitySecret | undefined;
    try {
      identity = asSecret(
        await this.core.readNamespacedSecret({ name: identityName, namespace }),
      );
      this.assertIdentityOwnership(identity, owner);
      const certificate = valueData(identity, "tls.crt");
      const privateKey = valueData(identity, "tls.key");
      if (certificate !== undefined && privateKey !== undefined) {
        return {
          certificate: Buffer.from(certificate, "base64"),
          privateKey: Buffer.from(privateKey, "base64"),
        };
      }
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
    }
    const pending =
      identity === undefined
        ? await this.createPendingIdentity(resource, provider, owner)
        : identity;
    const privateKey = requiredData(pending, "tls.key");
    const csr = requiredData(pending, identityCsrDataKey);
    const token = await this.bootstrapToken(resource, namespace);
    const bootstrap = new HemligClient(
      new URL(provider.spec.bootstrapUrl),
      new NodeHttpsTransport(),
    );
    const enrolled = await bootstrap.redeemBootstrap(
      token,
      Buffer.from(csr, "base64").toString("utf8"),
    );
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
          "hemlig.zyno.io/provider": provider.metadata.name,
          "hemlig.zyno.io/grant-id": enrolled.grant.grantId,
          "hemlig.zyno.io/api-fingerprint": enrolled.apiFingerprint,
        },
      },
      // Kubernetes treats Secret.type as immutable. The pending identity is
      // deliberately created as Opaque so it can also carry the CSR; retain
      // that type when replacing it with the enrolled certificate.
      type: pending.type ?? "Opaque",
      data: {
        "tls.crt": Buffer.from(enrolled.apiCertificatePem, "utf8").toString(
          "base64",
        ),
        "tls.key": privateKey,
      },
    };
    await this.core.replaceNamespacedSecret({
      name: identityName,
      namespace,
      body,
    });
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
    const namespace = required(
      resource.metadata.namespace,
      "consumer namespace",
    );
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
          "hemlig.zyno.io/provider": provider.metadata.name,
          "hemlig.zyno.io/identity-state": "pending-bootstrap",
        },
      },
      type: "Opaque",
      data: {
        "tls.key": Buffer.from(generated.privateKeyPem, "utf8").toString(
          "base64",
        ),
        [identityCsrDataKey]: Buffer.from(generated.csrPem, "utf8").toString(
          "base64",
        ),
      },
    };
    try {
      const created = await this.core.createNamespacedSecret({
        namespace,
        body,
      });
      return asSecret(created);
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
      const current = asSecret(
        await this.core.readNamespacedSecret({
          name: resource.spec.identity.secretName,
          namespace,
        }),
      );
      this.assertIdentityOwnership(current, owner);
      return current;
    }
  }

  private async bootstrapToken(
    resource: HemligConsumer,
    namespace: string,
  ): Promise<string> {
    const secret = asSecret(
      await this.core.readNamespacedSecret({
        name: resource.spec.bootstrapTokenRef.name,
        namespace,
      }),
    );
    const value = valueData(secret, resource.spec.bootstrapTokenRef.key);
    if (value === undefined) {
      throw new ReconcileError(
        "BootstrapTokenUnavailable",
        "The referenced bootstrap token key is absent.",
      );
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
      await this.setFailure(
        namespace,
        importPlural,
        name,
        resource.metadata.generation,
        resource.status,
        new ReconcileError(
          "ConsumerNotReady",
          "The referenced HemligConsumer is not ready.",
        ),
      );
      return;
    }
    try {
      const targetName = resource.spec.target?.name ?? name;
      const owner = resourceKey(resource.metadata);
      const selected = consumer.config.grant.secretGrants.find(
        (grant) => grant.secretId === resource.spec.secretId,
      );
      if (
        !consumer.config.grant.capabilities.includes("read") ||
        !selected?.permissions.includes("read")
      )
        throw new ImportRevokedError("Import scope was revoked.");
      const indexed = consumer.syncEntries.get(selected.secretUid);
      if (indexed !== undefined && !indexed.permissions.includes("read"))
        throw new ImportRevokedError("Import access was revoked.");
      const awaiting = () =>
        this.setStatus(
          namespace,
          importPlural,
          name,
          {
            observedGeneration: resource.metadata.generation,
            secretUid: selected.secretUid,
            conditions: [
              falseCondition(
                "AwaitingValue",
                "The remote secret has no value yet.",
              ),
            ],
          },
          resource.status,
        );
      if (indexed?.state === "PENDING_VALUE") {
        await awaiting();
        return;
      }
      if (
        indexed === undefined &&
        !consumer.syncSnapshot &&
        resource.status?.observedGeneration === resource.metadata.generation &&
        resource.status?.secretUid === selected.secretUid &&
        resource.status?.conditions?.some(
          (entry) =>
            entry.type === "Ready" && entry.reason === "AwaitingValue",
        )
      )
        return;
      const localVersion = await this.currentImportVersion(
        namespace,
        targetName,
        owner,
        resource.status,
        selected.secretUid,
        resource.spec.target?.type ?? "Opaque",
      );
      const currentGeneration =
        resource.status?.observedGeneration === resource.metadata.generation;
      if (
        localVersion !== undefined &&
        currentGeneration &&
        (indexed?.controlVersionId === localVersion ||
          (indexed === undefined && !consumer.syncSnapshot))
      )
        return;
      const ifNoneMatch = currentGeneration ? localVersion : undefined;
      let remote: Awaited<ReturnType<HemligClient["getAgentSecret"]>>;
      try {
        remote = await consumer.client.getAgentSecret(
          resource.spec.secretId,
          ifNoneMatch,
        );
      } catch (error) {
        if (
          error instanceof HemligError &&
          (error.status === 403 || error.status === 404)
        )
          await this.confirmImportRevocation(consumer, resource.spec.secretId);
        throw error;
      }
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
            "hemlig.zyno.io/import-owner": owner,
            "hemlig.zyno.io/secret-id": remote.secretId,
            "hemlig.zyno.io/secret-uid": selected.secretUid,
            "hemlig.zyno.io/control-version-id": remote.controlVersionId,
            "hemlig.zyno.io/payload-version-id": remote.payloadVersionId,
            "hemlig.zyno.io/data-checksum": stringMapChecksum(data),
          },
        },
        type: resource.spec.target?.type ?? "Opaque",
        data,
      };
      await this.applyImport(namespace, targetName, owner, desired);
      await this.setStatus(
        namespace,
        importPlural,
        name,
        {
          observedGeneration: resource.metadata.generation,
          secretUid: selected.secretUid,
          controlVersionId: remote.controlVersionId,
          payloadVersionId: remote.payloadVersionId,
          conditions: [
            readyCondition("TargetReady", "Secret materialized from Hemlig."),
          ],
        },
        resource.status,
      );
    } catch (error) {
      if (error instanceof ImportRevokedError) {
        await this.removeOwnedImport(resource);
        await this.setStatus(
          namespace,
          importPlural,
          name,
          {
            observedGeneration: resource.metadata.generation,
            conditions: [
              falseCondition(
                "AccessRevoked",
                "Hemlig no longer grants this import.",
              ),
            ],
          },
          resource.status,
        );
        return;
      }
      await this.setFailure(
        namespace,
        importPlural,
        name,
        resource.metadata.generation,
        resource.status,
        error,
      );
      if (!(error instanceof ReconcileError && error.reason === "RemoteAccessDenied"))
        consumer.syncFailed = true;
      this.scheduleTransientResourceRetry(error);
    }
  }

  /**
   * A remote 403/404 is not proof of revocation: it can follow an expired
   * client certificate or a secret that has no value yet. Only a successful
   * fresh configuration read that no longer grants read authorizes deletion.
   */
  private async confirmImportRevocation(
    consumer: ReadyConsumer,
    secretId: string,
  ): Promise<never> {
    let config: AgentConfig;
    try {
      config = await (consumer.revocationCheck ??=
        consumer.client.getAgentConfig());
    } catch (error) {
      if (isIdentityAuthenticationFailure(error)) {
        throw new ReconcileError(
          "AuthenticationFailed",
          "Hemlig rejected this consumer's client certificate; imports are retained until access is confirmed.",
          true,
        );
      }
      throw new ReconcileError(
        "RevocationUnconfirmed",
        "Hemlig denied the read and the grant could not be re-checked; imports are retained.",
        true,
      );
    }
    const grant = config.grant.secretGrants.find(
      (entry) => entry.secretId === secretId,
    );
    if (
      !config.grant.capabilities.includes("read") ||
      !grant?.permissions.includes("read")
    )
      throw new ImportRevokedError("Hemlig no longer grants this import.");
    throw new ReconcileError(
      "RemoteAccessDenied",
      "Hemlig denied reading this secret although the grant still allows it; the import is retained.",
    );
  }

  private async reconcileExport(
    resource: HemligSecretExport,
    consumer: ReadyConsumer | undefined,
  ): Promise<void> {
    const namespace = required(resource.metadata.namespace, "export namespace");
    const name = required(resource.metadata.name, "export name");
    if (consumer === undefined) {
      await this.setFailure(
        namespace,
        exportPlural,
        name,
        resource.metadata.generation,
        resource.status,
        new ReconcileError(
          "ConsumerNotReady",
          "The referenced HemligConsumer is not ready.",
        ),
      );
      return;
    }
    try {
      const selected = consumer.config.grant.secretGrants.find(
        (grant) => grant.secretId === resource.spec.secretId,
      );
      if (
        !consumer.config.grant.capabilities.includes("write") ||
        !selected?.permissions.includes("write")
      )
        throw new HemligError(403, "Export scope was revoked.");
      const indexed = consumer.syncEntries.get(selected.secretUid);
      if (indexed !== undefined && !indexed.permissions.includes("write"))
        throw new HemligError(403, "Export access was revoked.");
      const source = asSecret(
        await this.core.readNamespacedSecret({
          name: resource.spec.source.name,
          namespace,
        }),
      );
      if (source.metadata?.labels?.[controllerLabel] === "import") {
        throw new ReconcileError(
          "SourceIsImportManaged",
          "An export cannot source a Hemlig-managed import.",
        );
      }
      const payload = kubernetesDataToPayload({
        ...source.data,
        ...source.binaryData,
      });
      const checksum = payloadChecksum(payload);
      const priorStatus = resource.status;
      if (
        indexed === undefined &&
        !consumer.syncSnapshot &&
        priorStatus?.secretUid === selected.secretUid &&
        priorStatus.observedGeneration === resource.metadata.generation &&
        priorStatus.sourceChecksum === checksum &&
        priorStatus.conditions?.some(
          (condition) =>
            condition.type === "Ready" && condition.status === "True",
        )
      )
        return;
      let control: AgentControl | ControlRevision;
      try {
        control =
          indexed?.metadata === undefined
            ? await consumer.client.getAgentControl(resource.spec.secretId)
            : {
                secretId: indexed.secretId,
                environment: consumer.config.environment,
                controlVersionId: indexed.controlVersionId,
                payloadVersionId: indexed.payloadVersionId,
                metadata: indexed.metadata,
                state: indexed.state,
              };
      } catch (error) {
        if (!(error instanceof HemligError) || error.status !== 404) {
          throw error;
        }
        throw new ReconcileError(
          "RemoteSecretNotFound",
          "An administrator must create this secret and add it to the AgentGrant before export.",
        );
      }
      if (!metadataEqual(control.metadata, resource.spec.metadata)) {
        control = await consumer.client.updateAgentSecret(
          resource.spec.secretId,
          control.controlVersionId,
          resource.spec.metadata,
          operationKey(
            resource.metadata,
            `metadata:${control.controlVersionId}`,
          ),
        );
      }
      const payloadMatches =
        priorStatus !== undefined &&
        priorStatus.secretUid === selected.secretUid &&
        priorStatus.sourceChecksum === checksum &&
        priorStatus.payloadVersionId === control.payloadVersionId;
      const written = payloadMatches
        ? control
        : await consumer.client.putAgentPayload(
            resource.spec.secretId,
            control.controlVersionId,
            payload,
            operationKey(
              resource.metadata,
              `payload:${checksum}:${control.controlVersionId}`,
            ),
          );
      await this.setStatus(
        namespace,
        exportPlural,
        name,
        {
          observedGeneration: resource.metadata.generation,
          secretUid: selected.secretUid,
          controlVersionId: written.controlVersionId,
          payloadVersionId: written.payloadVersionId,
          sourceChecksum: checksum,
          conditions: [
            readyCondition(
              "RemoteReady",
              "Source Secret was written through the scoped agent API.",
            ),
          ],
        },
        resource.status,
      );
    } catch (error) {
      await this.setFailure(
        namespace,
        exportPlural,
        name,
        resource.metadata.generation,
        resource.status,
        error,
      );
      if (!(
        error instanceof HemligError &&
        (error.status === 403 || error.status === 404)
      ))
        consumer.syncFailed = true;
      this.scheduleTransientResourceRetry(error);
    }
  }

  private async assertNamespaceAllowed(
    namespace: string,
    provider: HemligProvider,
  ): Promise<void> {
    const namespaceRecord = unwrap(
      await this.core.readNamespace({ name: namespace }),
    ) as { metadata?: ObjectMeta };
    const requiredLabels = provider.spec.allowedNamespaces.matchLabels;
    const allowed = namespaceMatches(
      namespaceRecord.metadata?.labels,
      requiredLabels,
    );
    if (!allowed) {
      throw new ReconcileError(
        "ProviderNotPermitted",
        "This namespace does not match the provider selector.",
      );
    }
  }

  private assertIdentityOwnership(secret: IdentitySecret, owner: string): void {
    if (
      secret.metadata?.labels?.[controllerLabel] !== "consumer" ||
      secret.metadata.annotations?.[consumerOwnerAnnotation] !== owner
    ) {
      throw new ReconcileError(
        "IdentityOwnershipConflict",
        "The identity Secret is not owned by this HemligConsumer.",
      );
    }
  }

  private async applyImport(
    namespace: string,
    name: string,
    owner: string,
    desired: Record<string, unknown>,
  ): Promise<void> {
    try {
      const current = asSecret(
        await this.core.readNamespacedSecret({ name, namespace }),
      );
      if (!isOwnedByImport(current.metadata, owner)) {
        throw new ReconcileError(
          "TargetOwnershipConflict",
          "The import target is owned by another resource.",
        );
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
      const current = asSecret(
        await this.core.readNamespacedSecret({ name: targetName, namespace }),
      );
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
    secretUid: string,
    type: string,
  ): Promise<string | undefined> {
    if (
      status?.secretUid !== secretUid ||
      status.controlVersionId === undefined ||
      status.payloadVersionId === undefined
    ) {
      return undefined;
    }
    try {
      const current = asSecret(
        await this.core.readNamespacedSecret({ name, namespace }),
      );
      const annotations = current.metadata?.annotations;
      if (
        !isOwnedByImport(current.metadata, owner) ||
        current.type !== type ||
        annotations?.["hemlig.zyno.io/secret-uid"] !== secretUid ||
        annotations?.["hemlig.zyno.io/control-version-id"] !==
          status.controlVersionId ||
        annotations?.["hemlig.zyno.io/payload-version-id"] !==
          status.payloadVersionId ||
        annotations?.["hemlig.zyno.io/data-checksum"] !==
          stringMapChecksum(current.data ?? {})
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
    const response = unwrap(
      await this.custom.listClusterCustomObject({ group, version, plural }),
    ) as { items?: T[] };
    return response.items ?? [];
  }

  private async listNamespaced<T>(plural: string): Promise<T[]> {
    const response = unwrap(
      await this.custom.listCustomObjectForAllNamespaces({
        group,
        version,
        plural,
      }),
    ) as { items?: T[] };
    return response.items ?? [];
  }

  private async setFailure(
    namespace: string,
    plural: string,
    name: string,
    generation: number | undefined,
    currentStatus: ReconciliationStatus | undefined,
    error: unknown,
    retained: Pick<ReconciliationStatus, "identity"> = {},
  ): Promise<void> {
    const reason =
      error instanceof ReconcileError ? error.reason : "ReconcileFailed";
    const message =
      error instanceof ReconcileError
        ? error.message
        : error instanceof HemligError
          ? `Hemlig returned ${error.status}.`
          : "The reconciliation attempt failed.";
    await this.setStatus(
      namespace,
      plural,
      name,
      {
        ...retained,
        observedGeneration: generation,
        conditions: [falseCondition(reason, message)],
      },
      currentStatus,
    );
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

  private scheduleReconcile(delayMilliseconds = this.eventDelay()): void {
    const dueAt = performance.now() + delayMilliseconds;
    if (this.reconcileTimer !== undefined) {
      // Keep the earlier pass: an event must not wait behind a long backoff,
      // and a retry is covered by a sooner pass.
      if (this.reconcileDueAt <= dueAt) {
        return;
      }
      clearTimeout(this.reconcileTimer);
    }
    this.reconcileDueAt = dueAt;
    this.reconcileTimer = setTimeout(() => {
      this.reconcileTimer = undefined;
      void this.reconcileAll().catch((error: unknown) => {
        this.reportReconcileFailure(error);
        this.scheduleReconcile(this.nextRetryDelay(error));
      });
    }, delayMilliseconds);
  }

  /**
   * A resource-level reconciliation failure is deliberately contained so one
   * bad Import does not prevent the remainder of the cluster from converging.
   * Containment must not turn a transient remote failure into a ten-minute
   * outage, though: the periodic sweep is only the missed-event safety net.
   */
  /** While failing, events preempt the backoff at most once per base delay. */
  private eventDelay(): number {
    const debounce = this.config.sourceDebounceMilliseconds;
    return this.retryAttempt === 0
      ? debounce
      : Math.max(debounce, this.config.reconcileRetryMilliseconds ?? 1_000);
  }

  private takePassRetry(): { readonly error: unknown } | undefined {
    const retry = this.passRetryError;
    this.passRetryError = undefined;
    return retry;
  }

  private scheduleTransientResourceRetry(error: unknown): void {
    if (!isTransientResourceError(error)) {
      return;
    }
    // reconcileAll schedules one retry for the whole pass once it finishes.
    this.passRetryError = { error };
  }

  /**
   * Capped exponential backoff with jitter, reset by a clean pass. A retry that
   * fires every second against a persistent failure would load the shared
   * Hemlig service (and its audit log) from every cluster at once.
   */
  private nextRetryDelay(error: unknown): number {
    const base = this.config.reconcileRetryMilliseconds ?? 1_000;
    const max = this.config.reconcileRetryMaxMilliseconds ?? 300_000;
    const ceiling = Math.min(max, base * 2 ** Math.min(this.retryAttempt, 30));
    this.retryAttempt += 1;
    const jittered = ceiling / 2 + Math.random() * (ceiling / 2);
    return Math.max(retryAfterMilliseconds(error) ?? 0, Math.round(jittered));
  }

  private reportReconcileFailure(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      `Hemlig reconciliation failed; retrying: ${message}\n`,
    );
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
    this.pki?.start(signal);
  }

  private async watchPath(path: string, signal: AbortSignal): Promise<void> {
    if (this.watch === undefined || signal.aborted) {
      return;
    }
    try {
      const resourceVersion = this.watchResourceVersions.get(path);
      await this.watch.watch(
        path,
        {
          allowWatchBookmarks: true,
          ...(resourceVersion === undefined ? {} : { resourceVersion }),
        },
        (phase: string, object: unknown) => {
          if (phase === "ERROR") {
            if (isExpiredWatch(object)) {
              this.watchResourceVersions.delete(path);
              this.scheduleReconcile();
            }
            return;
          }
          const metadata = (object as { readonly metadata?: ObjectMeta } | null)
            ?.metadata;
          if (typeof metadata?.resourceVersion === "string") {
            this.watchResourceVersions.set(path, metadata.resourceVersion);
          }
          // A fresh watch can replay the existing collection. Reconnect from
          // its last event/bookmark instead of turning that replay into full
          // cluster reconciliations; bookmarks themselves contain no change.
          if (
            (phase === "ADDED" ||
              phase === "MODIFIED" ||
              phase === "DELETED") &&
            !isOwnStatusUpdate(phase, object) &&
            this.isRelevantWatchEvent(path, metadata)
          ) {
            this.scheduleReconcile();
          }
        },
        (error: unknown) => {
          if (isExpiredWatch(error)) {
            this.watchResourceVersions.delete(path);
            this.scheduleReconcile();
          }
          if (!signal.aborted) {
            setTimeout(() => {
              void this.watchPath(path, signal);
            }, 1_000);
          }
        },
      );
    } catch (error) {
      if (isExpiredWatch(error)) {
        this.watchResourceVersions.delete(path);
        this.scheduleReconcile();
      }
      if (!signal.aborted) {
        setTimeout(() => {
          void this.watchPath(path, signal);
        }, 1_000);
      }
    }
  }

  private isRelevantWatchEvent(
    path: string,
    metadata: ObjectMeta | undefined,
  ): boolean {
    if (metadata?.name === undefined) return true;
    if (path === "/api/v1/namespaces")
      return this.namespaceDependencies.has(metadata.name);
    if (path === "/api/v1/secrets" && metadata.namespace !== undefined)
      return this.secretDependencies.has(
        `${metadata.namespace}/${metadata.name}`,
      );
    return true;
  }
}

export const v1BetaControllerConfigFromEnvironment =
  (): V1BetaControllerConfig => ({
    intervalMilliseconds: positiveMilliseconds(
      process.env.HEMLIG_RECONCILE_INTERVAL_MS,
      600_000,
    ),
    sourceDebounceMilliseconds: positiveMilliseconds(
      process.env.HEMLIG_SOURCE_DEBOUNCE_MS,
      250,
    ),
  });

class MqttHintManager {
  private readonly clients = new Map<
    string,
    { readonly fingerprint: string; readonly client: MqttClient }
  >();

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

  public remove(key: string): void {
    this.clients.get(key)?.client.end(true);
    this.clients.delete(key);
  }

  public stop(): void {
    for (const entry of this.clients.values()) {
      entry.client.end(true);
    }
    this.clients.clear();
  }
}

class ReconcileError extends Error {
  public constructor(
    readonly reason: string,
    message: string,
    /** Retry the whole pass with backoff (transient, self-healing causes). */
    readonly retryable = false,
  ) {
    super(message);
  }
}

/** The only condition under which an imported Secret is deleted. */
class ImportRevokedError extends Error {}

const storedCertificateMatches = (
  data: Readonly<Record<string, string>>,
  certificate: Buffer,
): boolean =>
  data["tls.crt"] !== undefined &&
  Buffer.from(data["tls.crt"], "base64").equals(certificate);

const certificateBinding = (certificate: Buffer): string =>
  createHash("sha256").update(certificate).digest("hex");

/** Hemlig leaves carry spiffe://hemlig/consumer/<consumerId> as a URI SAN. */
const certificateNamesConsumer = (
  certificate: Buffer,
  consumerId: string,
): boolean => {
  try {
    const subjectAltName = new X509Certificate(certificate).subjectAltName ?? "";
    return subjectAltName
      .split(/,\s*/)
      .includes(`URI:spiffe://hemlig/consumer/${consumerId}`);
  } catch {
    return false;
  }
};

const identitySecretChanged = (): RotationError =>
  new RotationError(
    "RotationFailed",
    "The identity Secret changed during rotation; retrying.",
    false,
  );

class RotationError extends Error {
  public constructor(
    readonly reason: string,
    message: string,
    readonly discardPending: boolean,
  ) {
    super(message);
  }
}

const classifyRotationFailure = (
  error: unknown,
): {
  readonly reason: string;
  readonly message: string;
  readonly discardPending: boolean;
} => {
  if (error instanceof RotationError) {
    return {
      reason: error.reason,
      message: error.message,
      discardPending: error.discardPending,
    };
  }
  const failure = (reason: string, message: string, discardPending = false) => ({
    reason,
    message,
    discardPending,
  });
  if (error instanceof HemligError) {
    const { status, code } = error;
    if (status === 400 && code === "invalid_csr")
      return failure(
        "RotationRejected",
        "Hemlig rejected the certificate request; a new key will be generated.",
        true,
      );
    if (status === 400 || status === 404 || status === 405)
      return failure(
        "RotationUnsupported",
        "This Hemlig server does not support identity self-rotation; upgrade it or rotate manually.",
      );
    if (status === 403 && isIdentityAuthenticationFailure(error))
      return failure(
        "AuthenticationFailed",
        "Hemlig rejected the current client certificate; rotation cannot proceed.",
      );
    if (status === 403)
      return failure(
        "RotationForbidden",
        "The agent grant does not permit identity rotation.",
      );
    if (status === 409 && code === "identity_limit_reached")
      return failure(
        "IdentityLimitReached",
        "The consumer has too many active identities; an administrator must revoke unused ones.",
      );
    if (status === 409 && code === "identity_rotation_conflict")
      return failure(
        "RotationConflict",
        "Another identity rotation for this consumer committed concurrently; retrying with the staged key.",
      );
    if (status === 409 && code === "identity_already_rotated")
      return failure(
        "IdentityAlreadyRotated",
        "This identity was already rotated to a successor that is still active.",
      );
    if (status === 409)
      return failure(
        "RotationRejected",
        "Hemlig could not replay or accept this rotation; a new key will be generated.",
        true,
      );
  }
  return failure("RotationFailed", "Identity rotation failed; will retry.");
};

const isIdentityAuthenticationFailure = (error: unknown): boolean =>
  error instanceof HemligError &&
  error.status === 403 &&
  (error.code === undefined || error.code === "identity_not_active");

const condition = (
  type: string,
  status: "True" | "False",
  reason: string,
  message: string,
): Condition => ({
  type,
  status,
  reason,
  message,
  lastTransitionTime: new Date().toISOString(),
});

const syncIdentityFor = (apiUrl: string, certificate: Buffer): string =>
  createHash("sha256").update(apiUrl).update(certificate).digest("hex");

const b64 = (value: string): string =>
  Buffer.from(value, "utf8").toString("base64");

const parseDuration = (value: string | undefined): number => {
  const match = /^([0-9]+)([smhd])$/.exec(value ?? "");
  if (match === null) return defaultRotateBeforeMilliseconds;
  const unit = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[
    match[2] as "s" | "m" | "h" | "d"
  ];
  return Number.parseInt(match[1]!, 10) * unit;
};

const describeIdentity = (
  certificate: Buffer,
):
  | {
      readonly apiFingerprint: string;
      readonly notBefore: string;
      readonly notAfter: string;
    }
  | undefined => {
  try {
    const parsed = new X509Certificate(certificate);
    return {
      apiFingerprint: createHash("sha256").update(parsed.raw).digest("hex"),
      notBefore: new Date(parsed.validFrom).toISOString(),
      notAfter: new Date(parsed.validTo).toISOString(),
    };
  } catch {
    return undefined;
  }
};

/** Rotation lead time, clamped to half the certificate lifetime; undefined = disabled. */
const rotationWindow = (
  rotateBefore: string | undefined,
  identity: { readonly notBefore: string; readonly notAfter: string },
): number | undefined => {
  const value = parseDuration(rotateBefore);
  if (value === 0) return undefined;
  const lifetime = Date.parse(identity.notAfter) - Date.parse(identity.notBefore);
  return Math.min(value, lifetime / 2);
};

const identityStatusFor = (
  identity: {
    readonly apiFingerprint: string;
    readonly notBefore: string;
    readonly notAfter: string;
  },
  window: number | undefined,
  annotations: Readonly<Record<string, string>>,
  lastRotationError?: string,
): IdentityStatus => {
  const lastRotationTime = annotations[rotatedAtAnnotation];
  const rotationRequest = annotations[rotationRequestAnnotation];
  return {
    apiFingerprint: identity.apiFingerprint,
    notBefore: identity.notBefore,
    notAfter: identity.notAfter,
    ...(window === undefined
      ? {}
      : {
          rotateAfter: new Date(
            Date.parse(identity.notAfter) - window,
          ).toISOString(),
        }),
    ...(lastRotationTime === undefined ? {} : { lastRotationTime }),
    ...(rotationRequest === undefined ? {} : { rotationRequest }),
    ...(lastRotationError === undefined ? {} : { lastRotationError }),
  };
};

const publicKeysMatch = (certificatePem: string, privateKey: Buffer): boolean => {
  try {
    const fromCertificate = new X509Certificate(certificatePem).publicKey.export(
      { type: "spki", format: "der" },
    );
    const fromKey = createPublicKey(createPrivateKey(privateKey)).export({
      type: "spki",
      format: "der",
    });
    return fromCertificate.equals(fromKey);
  } catch {
    return false;
  }
};

const generateKeyPairAsync = promisify(generateKeyPair);

/** Key generation runs on the libuv pool so it cannot stall the event loop. */
const generateRotationCsr = async (
  bits: number,
): Promise<{ readonly privateKeyPem: string; readonly csrPem: string }> => {
  const pair = await generateKeyPairAsync("rsa", {
    modulusLength: bits,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  const privateKey = forge.pki.privateKeyFromPem(pair.privateKey);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e);
  csr.setSubject([{ name: "commonName", value: "Hemlig Kubernetes agent" }]);
  csr.sign(privateKey, forge.md.sha256.create());
  return {
    privateKeyPem: pair.privateKey,
    csrPem: forge.pki.certificationRequestToPem(csr),
  };
};

const agentClient = (
  url: string,
  certificate: Buffer,
  privateKey: Buffer,
): HemligClient =>
  new HemligClient(
    new URL(url),
    new NodeHttpsTransport({ cert: certificate, key: privateKey }),
  );

const generateCsr = (): {
  readonly privateKeyPem: string;
  readonly csrPem: string;
} => {
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
  stableJson(normalizeReconciliationStatus(current)) ===
    stableJson(normalizeReconciliationStatus(desired));

const normalizeReconciliationStatus = (
  status: ReconciliationStatus,
): Omit<ReconciliationStatus, "conditions"> & {
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
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, sortValue(nested)]),
    );
  }
  return value;
};

const operationKey = (metadata: ObjectMeta, operation: string): string =>
  createHash("sha256")
    .update(
      `${metadata.uid ?? resourceKey(metadata)}:${metadata.generation ?? 0}:${operation}`,
    )
    .digest("hex");

const resourceKey = (metadata: ObjectMeta): string =>
  `${required(metadata.namespace, "resource namespace")}/${required(metadata.name, "resource name")}`;

const asSecret = (value: unknown): IdentitySecret =>
  unwrap(value) as IdentitySecret;

const unwrap = (value: unknown): unknown =>
  typeof value === "object" && value !== null && "body" in value
    ? (value as { body: unknown }).body
    : value;

const valueData = (secret: IdentitySecret, key: string): string | undefined =>
  secret.data?.[key];

const requiredData = (secret: IdentitySecret, key: string): string => {
  const value = valueData(secret, key);
  if (value === undefined) {
    throw new ReconcileError(
      "IdentityOwnershipConflict",
      `The managed identity Secret is missing ${key}.`,
    );
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
  typeof error === "object" &&
  error !== null &&
  "code" in error &&
  (error as { code?: unknown }).code === 404;

const isAlreadyExists = (error: unknown): boolean =>
  typeof error === "object" &&
  error !== null &&
  "code" in error &&
  (error as { code?: unknown }).code === 409;

const retryAfterMilliseconds = (error: unknown): number | undefined => {
  if (typeof error !== "object" || error === null || !("headers" in error)) {
    return undefined;
  }
  const headers = (error as { readonly headers?: unknown }).headers;
  if (
    typeof headers !== "object" ||
    headers === null ||
    !("retry-after" in headers)
  ) {
    return undefined;
  }
  const retryAfter = (headers as { readonly "retry-after"?: unknown })[
    "retry-after"
  ];
  if (typeof retryAfter !== "string" || !/^\d+$/.test(retryAfter)) {
    return undefined;
  }
  const seconds = Number.parseInt(retryAfter, 10);
  return Number.isSafeInteger(seconds) && seconds >= 0
    ? seconds * 1_000
    : undefined;
};

export const isTransientResourceError = (error: unknown): boolean => {
  if (error instanceof ReconcileError) {
    return error.retryable;
  }
  if (!(error instanceof HemligError)) {
    // Kubernetes API failures carry a numeric status: a missing source Secret
    // (404), forbidden access (403), or an invalid object (422) will not heal by
    // retrying, and a watch event reconciles once it is fixed. Transport
    // failures have no status and are safe to retry because all controller
    // operations are idempotent.
    const status = kubernetesStatus(error);
    return status === undefined || isTransientStatus(status);
  }
  return isTransientStatus(error.status);
};

/**
 * A MODIFIED Hemlig CR whose status already records its current generation is
 * a status-only write (normally this controller's own); it has no new input.
 */
const isOwnStatusUpdate = (phase: string, object: unknown): boolean => {
  if (phase !== "MODIFIED" || typeof object !== "object" || object === null) {
    return false;
  }
  const resource = object as {
    readonly apiVersion?: string;
    readonly kind?: string;
    readonly metadata?: {
      readonly generation?: number;
      readonly annotations?: Readonly<Record<string, string>>;
    };
    readonly status?: {
      readonly observedGeneration?: number;
      readonly identity?: { readonly rotationRequest?: string };
    };
  };
  // A new manual rotation token is an input even though the generation is
  // unchanged (annotations do not bump it).
  const token = resource.metadata?.annotations?.[rotateIdentityAnnotation];
  if (
    resource.kind === "HemligConsumer" &&
    token !== undefined &&
    token !== resource.status?.identity?.rotationRequest
  )
    return false;
  return (
    resource.apiVersion === `${group}/${version}` &&
    resource.metadata?.generation !== undefined &&
    resource.status?.observedGeneration === resource.metadata.generation
  );
};

const isExpiredWatch = (error: unknown): boolean => {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const status = error as {
    readonly code?: unknown;
    readonly statusCode?: unknown;
  };
  return status.code === 410 || status.statusCode === 410;
};

const isTransientStatus = (status: number): boolean =>
  status === 408 ||
  status === 409 ||
  status === 412 ||
  status === 425 ||
  status === 429 ||
  status >= 500;

const kubernetesStatus = (error: unknown): number | undefined => {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "number" ? code : undefined;
};

const stringMapChecksum = (data: Readonly<Record<string, string>>): string =>
  createHash("sha256")
    .update(
      JSON.stringify(
        Object.entries(data).sort(([left], [right]) =>
          left.localeCompare(right),
        ),
      ),
    )
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

const positiveMilliseconds = (
  value: string | undefined,
  fallback: number,
): number => {
  const parsed = Number.parseInt(value ?? String(fallback), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 3_600_000) {
    throw new Error(
      "Controller interval values must be between 1 and 3600000 milliseconds.",
    );
  }
  return parsed;
};

const wait = async (milliseconds: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
