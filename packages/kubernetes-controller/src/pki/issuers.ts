import { isDeepStrictEqual } from "node:util";
import { HemligError } from "@zyno-io/hemlig-client";
import type {
  ConsumerRegistry,
  CoreApi,
  CustomApi,
  HemligConsumer,
  RegisteredConsumer,
} from "../v1beta";
import {
  allowsConsumerReference,
  consumerReferenceKey,
  namespaceMatches,
} from "../references";
import type { KeyedWorkQueue, Outcome, WorkContext } from "./queue";
import {
  CLUSTER_ISSUER_PLURAL,
  CONSUMER_PLURAL,
  CONSUMER_VERSION,
  HEMLIG_GROUP,
  ISSUER_PLURAL,
  ISSUER_REFRESH_MIN_MS,
  ISSUER_VERSION,
  REMOTE_TIMEOUT_MS,
  clusterIssuerKey,
  isNotFound,
  issuerKey,
  log,
  unwrap,
  withTimeout,
  type AnyIssuer,
  type HemligClusterIssuer,
  type IssuerCondition,
  type IssuerStatus,
  type Scheduler,
} from "./types";
import { k8sTime } from "./cert-manager";

export interface PkiDeps {
  readonly core: CoreApi;
  readonly custom: CustomApi;
  readonly registry: ConsumerRegistry;
  readonly scheduler: Scheduler;
}

export type ResolveResult =
  | {
      readonly ok: true;
      readonly consumerKey: string;
      readonly consumer: HemligConsumer;
      readonly registered: RegisteredConsumer;
    }
  | {
      readonly ok: false;
      readonly reason: string;
      readonly message: string;
      /** Set when the registry already knows the consumer. */
      readonly registered?: RegisteredConsumer;
    };

export const isClusterIssuer = (
  issuer: AnyIssuer,
): issuer is HemligClusterIssuer => typeof issuer.spec.consumerRef === "object";

/**
 * Fresh opt-ins and selector checks for an issuer's consumer. Reused by the
 * CertificateRequest path (and, later, trust bundles).
 */
export const resolveIssuerConsumer = async (
  deps: Pick<PkiDeps, "core" | "custom" | "registry">,
  issuer: AnyIssuer,
): Promise<ResolveResult> => {
  let consumerNamespace: string;
  let consumerName: string;
  let consumerKey: string;
  if (isClusterIssuer(issuer)) {
    consumerNamespace = issuer.spec.consumerRef.namespace;
    consumerName = issuer.spec.consumerRef.name;
    consumerKey = `${consumerNamespace}/${consumerName}`;
  } else {
    const issuerNamespace = issuer.metadata.namespace ?? "";
    consumerKey = consumerReferenceKey(
      issuerNamespace,
      issuer.spec.consumerRef,
      issuer.spec.consumerNamespace,
    );
    consumerNamespace = issuer.spec.consumerNamespace ?? issuerNamespace;
    consumerName = issuer.spec.consumerRef;
  }
  let consumer: HemligConsumer;
  try {
    consumer = unwrap(
      await deps.custom.getNamespacedCustomObject({
        group: HEMLIG_GROUP,
        version: CONSUMER_VERSION,
        namespace: consumerNamespace,
        plural: CONSUMER_PLURAL,
        name: consumerName,
      }),
    ) as HemligConsumer;
  } catch (error) {
    if (!isNotFound(error)) throw error;
    return {
      ok: false,
      reason: "ConsumerNotFound",
      message: `HemligConsumer ${consumerKey} not found`,
    };
  }
  const registered = deps.registry.get(consumerKey);
  if (isClusterIssuer(issuer)) {
    if (consumer.spec.allowClusterIssuers !== true) {
      return {
        ok: false,
        reason: "ClusterIssuerNotPermitted",
        message: `HemligConsumer ${consumerKey} does not set allowClusterIssuers`,
        ...(registered === undefined ? {} : { registered }),
      };
    }
  } else if (
    !allowsConsumerReference(
      issuer.metadata.namespace ?? "",
      issuer.spec.consumerNamespace,
      consumer,
    )
  ) {
    return {
      ok: false,
      reason: "ConsumerReferenceNotPermitted",
      message: `HemligConsumer ${consumerKey} does not allow references from namespace ${issuer.metadata.namespace ?? ""}`,
      ...(registered === undefined ? {} : { registered }),
    };
  }
  if (
    registered === undefined ||
    registered.uid !== consumer.metadata.uid ||
    registered.generation !== consumer.metadata.generation
  ) {
    return {
      ok: false,
      reason: "ConsumerNotReady",
      message: `HemligConsumer ${consumerKey} is not Ready`,
    };
  }
  // The provider selector applies to the namespace that uses the consumer.
  const selectorNamespace = isClusterIssuer(issuer)
    ? consumerNamespace
    : (issuer.metadata.namespace ?? "");
  const labels = await readNamespaceLabels(deps.core, selectorNamespace);
  if (
    !namespaceMatches(
      labels,
      registered.provider.spec.allowedNamespaces.matchLabels,
    )
  ) {
    return {
      ok: false,
      reason: "ProviderNotPermitted",
      message: `Namespace ${selectorNamespace} does not match the provider selector`,
      registered,
    };
  }
  return { ok: true, consumerKey, consumer, registered };
};

export const readNamespaceLabels = async (
  core: CoreApi,
  namespace: string,
): Promise<Readonly<Record<string, string>> | undefined> => {
  try {
    const record = unwrap(await core.readNamespace({ name: namespace })) as {
      metadata?: { labels?: Readonly<Record<string, string>> };
    };
    return record.metadata?.labels;
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

interface ReadyUpdate {
  readonly status: "True" | "False";
  readonly reason: string;
  readonly message: string;
}

export class IssuerReconciler {
  private readonly waiters = new Map<string, Set<string>>();
  private readonly waiting = new Map<string, string>();
  private readonly lastReconciledAt = new Map<string, number>();

  public constructor(
    private readonly deps: PkiDeps,
    private readonly queue: Pick<KeyedWorkQueue, "add">,
  ) {}

  /** The CR `crKey` is blocked on this issuer; wake it when the issuer is Ready. */
  public waitFor(issuer: string, crKey: string): void {
    const previous = this.waiting.get(crKey);
    if (previous !== undefined && previous !== issuer) {
      this.waiters.get(previous)?.delete(crKey);
    }
    this.waiting.set(crKey, issuer);
    const set = this.waiters.get(issuer) ?? new Set<string>();
    set.add(crKey);
    this.waiters.set(issuer, set);
  }

  public stopWaiting(crKey: string): void {
    const issuer = this.waiting.get(crKey);
    if (issuer === undefined) return;
    this.waiting.delete(crKey);
    const set = this.waiters.get(issuer);
    set?.delete(crKey);
    if (set?.size === 0) this.waiters.delete(issuer);
  }

  /** Rate-limited: one Hemlig GET per issuer per 30 s, not one per waiting CR. */
  public requestRefresh(issuer: string): void {
    const last = this.lastReconciledAt.get(issuer);
    if (
      last !== undefined &&
      this.deps.scheduler.now() - last < ISSUER_REFRESH_MIN_MS
    ) {
      return;
    }
    this.queue.add(issuer);
  }

  public onGone(issuer: string): void {
    this.lastReconciledAt.delete(issuer);
    for (const crKey of this.waiters.get(issuer) ?? []) {
      this.waiting.delete(crKey);
    }
    this.waiters.delete(issuer);
  }

  public reset(): void {
    this.waiters.clear();
    this.waiting.clear();
    this.lastReconciledAt.clear();
  }

  public async reconcile(key: string, context: WorkContext): Promise<Outcome> {
    const cluster = key.startsWith("clusterissuer/");
    const [namespace, name] = cluster
      ? [undefined, key.slice("clusterissuer/".length)]
      : (key.slice("issuer/".length).split("/") as [string, string]);
    let issuer: AnyIssuer;
    try {
      issuer = unwrap(
        cluster
          ? await this.deps.custom.getClusterCustomObject({
              group: HEMLIG_GROUP,
              version: ISSUER_VERSION,
              plural: CLUSTER_ISSUER_PLURAL,
              name: name as string,
            })
          : await this.deps.custom.getNamespacedCustomObject({
              group: HEMLIG_GROUP,
              version: ISSUER_VERSION,
              namespace: namespace as string,
              plural: ISSUER_PLURAL,
              name: name as string,
            }),
      ) as AnyIssuer;
    } catch (error) {
      if (isNotFound(error)) {
        this.onGone(key);
        return { kind: "done" };
      }
      throw error;
    }
    const resolved = await resolveIssuerConsumer(this.deps, issuer);
    if (!resolved.ok) {
      await this.write(key, issuer, resolved.registered, undefined, {
        status: "False",
        reason: resolved.reason,
        message: resolved.message,
      });
      return { kind: "done" };
    }
    const release = context.tryAcquire(resolved.consumerKey);
    if (release === undefined) {
      return { kind: "defer", group: resolved.consumerKey };
    }
    let grant;
    try {
      grant = await withTimeout(
        resolved.registered.client.getIssuanceGrant(issuer.spec.issuanceGrant),
        REMOTE_TIMEOUT_MS,
        this.deps.scheduler,
      );
    } catch (error) {
      return await this.remoteFailure(key, issuer, resolved.registered, error);
    } finally {
      release();
    }
    const inactive = grant.status !== "ACTIVE" || grant.expired;
    const update: ReadyUpdate = inactive
      ? {
          status: "False",
          reason: "IssuanceGrantInactive",
          message: "The issuance grant is disabled or expired",
        }
      : grant.ca.status !== "ACTIVE"
        ? {
            status: "False",
            reason: "CaNotActive",
            message: "The issuing CA is not active",
          }
        : {
            status: "True",
            reason: "Ready",
            message: "The issuance grant and its CA are active",
          };
    await this.write(key, issuer, resolved.registered, grant, update);
    return { kind: "done" };
  }

  private async remoteFailure(
    key: string,
    issuer: AnyIssuer,
    registered: RegisteredConsumer,
    error: unknown,
  ): Promise<Outcome> {
    if (error instanceof HemligError) {
      if (error.status === 404 && error.code === "issuance_grant_not_found") {
        await this.write(key, issuer, registered, undefined, {
          status: "False",
          reason: "IssuanceGrantNotFound",
          message: "The issuance grant was not found",
        });
        return { kind: "done" };
      }
      if (
        error.status === 403 &&
        (error.code === "identity_not_active" || error.code === undefined)
      ) {
        await this.write(key, issuer, registered, undefined, {
          status: "False",
          reason: "ConsumerNotReady",
          message: "Hemlig rejected the consumer identity",
        });
        return { kind: "done" };
      }
    }
    const transient =
      !(error instanceof HemligError) ||
      error.status === 429 ||
      error.status >= 500;
    if (transient) {
      const current = issuer.status;
      const keepReady =
        current?.conditions?.some(
          (condition) =>
            condition.type === "Ready" && condition.status === "True",
        ) === true && current.observedGeneration === issuer.metadata.generation;
      if (!keepReady) {
        await this.write(key, issuer, registered, undefined, {
          status: "False",
          reason: "RemoteError",
          message: "Hemlig is unavailable",
        });
      }
      return { kind: "retry", policy: "fast" };
    }
    const code =
      error instanceof HemligError
        ? `${error.status}${error.code === undefined ? "" : ` ${error.code}`}`
        : "unknown";
    await this.write(key, issuer, registered, undefined, {
      status: "False",
      reason: "RemoteError",
      message: `HemligError (${code})`.slice(0, 200),
    });
    return { kind: "retry", policy: "slow" };
  }

  private async write(
    key: string,
    issuer: AnyIssuer,
    registered: RegisteredConsumer | undefined,
    grant:
      | {
          readonly uid: string;
          readonly version: string;
          readonly ca: {
            readonly caId: string;
            readonly fingerprint?: string;
            readonly notAfter?: string;
          };
        }
      | undefined,
    ready: ReadyUpdate,
  ): Promise<void> {
    const old = issuer.status;
    const oldReady = old?.conditions?.find((c) => c.type === "Ready");
    const condition: IssuerCondition = {
      type: "Ready",
      status: ready.status,
      reason: ready.reason,
      message: ready.message,
      lastTransitionTime:
        oldReady?.status === ready.status &&
        oldReady.lastTransitionTime !== undefined
          ? oldReady.lastTransitionTime
          : k8sTime(this.deps.scheduler.now()),
    };
    const status: IssuerStatus = {
      ...(issuer.metadata.generation === undefined
        ? {}
        : { observedGeneration: issuer.metadata.generation }),
      ...(registered === undefined
        ? {}
        : {
            consumerId: registered.consumerId,
            environment: registered.environment,
          }),
      ...(grant === undefined
        ? {}
        : {
            caId: grant.ca.caId,
            ...(grant.ca.fingerprint === undefined
              ? {}
              : { caFingerprint: grant.ca.fingerprint }),
            ...(grant.ca.notAfter === undefined
              ? {}
              : { caNotAfter: grant.ca.notAfter }),
            issuanceGrantVersion: grant.version,
            grantUid: grant.uid,
          }),
      conditions: [condition],
    };
    this.lastReconciledAt.set(key, this.deps.scheduler.now());
    if (!isDeepStrictEqual(old, status)) {
      const body = [{ op: "add", path: "/status", value: status }];
      if (isClusterIssuer(issuer)) {
        await this.deps.custom.patchClusterCustomObjectStatus({
          group: HEMLIG_GROUP,
          version: ISSUER_VERSION,
          plural: CLUSTER_ISSUER_PLURAL,
          name: issuer.metadata.name as string,
          body,
        });
      } else {
        await this.deps.custom.patchNamespacedCustomObjectStatus({
          group: HEMLIG_GROUP,
          version: ISSUER_VERSION,
          namespace: issuer.metadata.namespace as string,
          plural: ISSUER_PLURAL,
          name: issuer.metadata.name as string,
          body,
        });
      }
      log(`${key} Ready=${ready.status} ${ready.reason}`);
    }
    if (ready.status === "True") {
      const set = this.waiters.get(key);
      this.waiters.delete(key);
      for (const crKey of set ?? []) {
        this.waiting.delete(crKey);
        this.queue.add(crKey, { resetBackoff: true });
      }
    }
  }
}

export const issuerKeyFor = (issuer: AnyIssuer): string =>
  isClusterIssuer(issuer)
    ? clusterIssuerKey(issuer.metadata.name as string)
    : issuerKey(
        issuer.metadata.namespace as string,
        issuer.metadata.name as string,
      );
