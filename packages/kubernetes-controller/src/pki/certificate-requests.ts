import { HemligError, type PkiIssuedCertificate } from "@zyno-io/hemlig-client";
import { namespaceMatches } from "../references";
import {
  buildIssueRequest,
  classifyIssueError,
  idempotencyKeyFor,
  isHemligRequest,
  isTerminal,
  isTrue,
  issuedStatusFields,
  k8sTime,
  readyUnchanged,
  safeText,
  withReady,
  type ReadyUpdate,
  type StatusExtra,
} from "./cert-manager";
import {
  IssuerReconciler,
  readNamespaceLabels,
  resolveIssuerConsumer,
  type PkiDeps,
} from "./issuers";
import type { KeyedWorkQueue, Outcome, WorkContext } from "./queue";
import {
  CLUSTER_ISSUER_KIND,
  CLUSTER_ISSUER_PLURAL,
  CM_GROUP,
  CM_VERSION,
  CR_PLURAL,
  HEMLIG_GROUP,
  ISSUER_PLURAL,
  ISSUER_VERSION,
  REMOTE_TIMEOUT_MS,
  STATUS_WRITE_ATTEMPTS,
  clusterIssuerKey,
  isConflict,
  isNotFound,
  issuerKey,
  log,
  unwrap,
  withTimeout,
  type AnyIssuer,
  type CertificateRequest,
  type CertificateRequestStatus,
  type HemligClusterIssuer,
} from "./types";
import type { CustomApi } from "../v1beta";

export type WriteResult =
  "written" | "unchanged" | "terminal" | "uidChanged" | "gone";

/**
 * Writes CertificateRequest status with PUT on the whole read object. The
 * mutation is re-applied to a fresh read on every conflict, so foreign
 * conditions (Approved, Denied, InvalidRequest, ...) are never rebuilt or
 * reordered. Never merge-patch conditions here.
 */
export const writeRequestStatus = async (
  custom: CustomApi,
  cr: CertificateRequest,
  mutate: (status: CertificateRequestStatus) => CertificateRequestStatus,
): Promise<WriteResult> => {
  const namespace = cr.metadata.namespace as string;
  const name = cr.metadata.name as string;
  const uid = cr.metadata.uid;
  let current = cr;
  for (let attempt = 0; attempt < STATUS_WRITE_ATTEMPTS; attempt += 1) {
    if (current.metadata.uid !== uid) return "uidChanged";
    if (isTerminal(current)) return "terminal";
    const next = mutate(current.status ?? {});
    if (readyUnchanged(current.status, next)) return "unchanged";
    try {
      await custom.replaceNamespacedCustomObjectStatus({
        group: CM_GROUP,
        version: CM_VERSION,
        namespace,
        plural: CR_PLURAL,
        name,
        body: { ...current, status: next },
      });
      return "written";
    } catch (error) {
      if (isNotFound(error)) return "gone";
      if (!isConflict(error)) throw error;
      try {
        current = unwrap(
          await custom.getNamespacedCustomObject({
            group: CM_GROUP,
            version: CM_VERSION,
            namespace,
            plural: CR_PLURAL,
            name,
          }),
        ) as CertificateRequest;
      } catch (readError) {
        if (isNotFound(readError)) return "gone";
        throw readError;
      }
    }
  }
  throw new Error("status write conflict");
};

const issuerNamePattern = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;
const caIdPattern = /^ca-[a-z0-9-]{3,80}$/;
const serialPattern = /^[0-9a-f]{2,40}$/;

const describeError = (error: unknown): string =>
  error instanceof HemligError
    ? `status=${error.status} code=${safeText(error.code, 80) ?? "none"} reason=${safeText(error.details?.reason, 80) ?? "none"}`
    : "non-hemlig error";

export class CertificateRequestReconciler {
  public constructor(
    private readonly deps: PkiDeps,
    private readonly issuers: IssuerReconciler,
    private readonly queue: Pick<KeyedWorkQueue, "add">,
    /** Hemlig-owned, non-terminal request keys; drives the 5-minute resync. */
    private readonly pending: Set<string>,
  ) {}

  public async reconcile(key: string, context: WorkContext): Promise<Outcome> {
    const state = { waited: false };
    try {
      return await this.process(key, context, state);
    } finally {
      // Keep the registration across the run on the paths that wait again, so
      // an issuer turning Ready mid-run still wakes this request.
      if (!state.waited) this.issuers.stopWaiting(key);
    }
  }

  private async process(
    key: string,
    context: WorkContext,
    state: { waited: boolean },
  ): Promise<Outcome> {
    const [namespace, name] = key.slice("cr/".length).split("/") as [
      string,
      string,
    ];
    let cr: CertificateRequest;
    try {
      cr = unwrap(
        await this.deps.custom.getNamespacedCustomObject({
          group: CM_GROUP,
          version: CM_VERSION,
          namespace,
          plural: CR_PLURAL,
          name,
        }),
      ) as CertificateRequest;
    } catch (error) {
      if (isNotFound(error)) return this.finished(key);
      throw error;
    }
    if (!isHemligRequest(cr) || isTerminal(cr)) return this.finished(key);
    this.pending.add(key);

    if (isTrue(cr, "Denied")) {
      return this.terminalWrite(
        key,
        cr,
        "Denied",
        "The CertificateRequest was denied.",
      );
    }
    if (isTrue(cr, "InvalidRequest")) {
      return this.terminalWrite(
        key,
        cr,
        "Failed",
        "The CertificateRequest is marked InvalidRequest.",
      );
    }
    if (!isTrue(cr, "Approved")) {
      // No timer: the watch, relist or resync re-enqueues it once approved.
      return this.settle(
        key,
        await this.write(cr, {
          status: "False",
          reason: "Pending",
          message: "Waiting for approval",
        }),
        { kind: "done" },
      );
    }
    const ref = cr.spec.issuerRef as NonNullable<
      CertificateRequest["spec"]["issuerRef"]
    >;
    const refName = ref.name;
    if (
      typeof refName !== "string" ||
      refName.length > 253 ||
      !issuerNamePattern.test(refName)
    ) {
      return this.terminalWrite(
        key,
        cr,
        "Failed",
        "UnsupportedRequest: invalid issuerRef.name",
      );
    }
    const kind = ref.kind as string;
    const cluster = kind === CLUSTER_ISSUER_KIND;
    const waitKey = cluster
      ? clusterIssuerKey(refName)
      : issuerKey(namespace, refName);

    let issuer: AnyIssuer;
    try {
      issuer = unwrap(
        cluster
          ? await this.deps.custom.getClusterCustomObject({
              group: HEMLIG_GROUP,
              version: ISSUER_VERSION,
              plural: CLUSTER_ISSUER_PLURAL,
              name: refName,
            })
          : await this.deps.custom.getNamespacedCustomObject({
              group: HEMLIG_GROUP,
              version: ISSUER_VERSION,
              namespace,
              plural: ISSUER_PLURAL,
              name: refName,
            }),
      ) as AnyIssuer;
    } catch (error) {
      if (!isNotFound(error)) throw error;
      state.waited = true;
      this.issuers.waitFor(waitKey, key);
      return this.settle(
        key,
        await this.write(cr, {
          status: "False",
          reason: "Pending",
          message: `IssuerNotFound: ${kind} ${refName} not found`,
        }),
        { kind: "retry", policy: "slow" },
      );
    }

    if (cluster) {
      const selector = (issuer as HemligClusterIssuer).spec.allowedNamespaces;
      if (selector !== undefined) {
        const labels = await readNamespaceLabels(this.deps.core, namespace);
        if (!namespaceMatches(labels, selector.matchLabels)) {
          return this.terminalWrite(
            key,
            cr,
            "Failed",
            `NamespaceNotPermitted: namespace ${namespace} is not selected by HemligClusterIssuer ${refName}`,
          );
        }
      }
    }

    const resolved = await resolveIssuerConsumer(this.deps, issuer);
    if (!resolved.ok) {
      state.waited = true;
      this.issuers.waitFor(waitKey, key);
      this.issuers.requestRefresh(waitKey);
      return this.settle(
        key,
        await this.write(cr, {
          status: "False",
          reason: "Pending",
          message: `${resolved.reason}: ${resolved.message}`,
        }),
        { kind: "retry", policy: "slow" },
      );
    }

    const ready = issuer.status?.conditions?.find(
      (condition) => condition.type === "Ready",
    );
    if (
      ready?.status !== "True" ||
      issuer.status?.observedGeneration !== issuer.metadata.generation ||
      issuer.status?.consumerId !== resolved.registered.consumerId
    ) {
      const why =
        ready?.status === "True" || ready?.reason === undefined
          ? "Stale"
          : (safeText(ready.reason, 64) ?? "Stale");
      state.waited = true;
      this.issuers.waitFor(waitKey, key);
      this.issuers.requestRefresh(waitKey);
      return this.settle(
        key,
        await this.write(cr, {
          status: "False",
          reason: "Pending",
          message: `IssuerNotReady: ${kind} ${refName} (${why})`,
        }),
        { kind: "retry", policy: "slow" },
      );
    }

    const built = buildIssueRequest(cr);
    if (!built.ok) {
      return this.terminalWrite(key, cr, "Failed", built.message);
    }

    const release = context.tryAcquire(resolved.consumerKey);
    if (release === undefined) {
      return { kind: "defer", group: resolved.consumerKey };
    }
    let issued: PkiIssuedCertificate;
    try {
      issued = await withTimeout(
        resolved.registered.client.issueCertificate(
          issuer.spec.issuanceGrant,
          built.body,
          idempotencyKeyFor(cr.metadata.uid as string),
        ),
        REMOTE_TIMEOUT_MS,
        this.deps.scheduler,
      );
    } catch (error) {
      return this.issueFailed(key, cr, waitKey, error);
    } finally {
      release();
    }
    const fields = issuedStatusFields(issued);
    if (fields === undefined) {
      return this.settle(
        key,
        await this.write(cr, {
          status: "False",
          reason: "Pending",
          message:
            "InvalidResponse: Hemlig returned an unexpected certificate response",
        }),
        { kind: "retry", policy: "fast" },
      );
    }
    const caId = caIdPattern.test(issued.caId) ? issued.caId : undefined;
    const serial = serialPattern.test(issued.serial)
      ? issued.serial
      : undefined;
    const message = `Issued${caId === undefined ? "" : ` by ${caId}`}${serial === undefined ? "" : `, serial ${serial}`}`;
    const result = await this.write(
      cr,
      { status: "True", reason: "Issued", message },
      fields,
    );
    log(
      `issued ${namespace}/${name} caId=${caId ?? "unknown"} serial=${serial ?? "unknown"}`,
    );
    return this.settle(key, result, { kind: "done" }, true);
  }

  private async issueFailed(
    key: string,
    cr: CertificateRequest,
    waitKey: string,
    error: unknown,
  ): Promise<Outcome> {
    const failure = classifyIssueError(error);
    log(`${key} issue ${failure.kind} ${describeError(error)}`);
    if (failure.kind === "failed") {
      return this.terminalWrite(key, cr, "Failed", failure.message);
    }
    const result = await this.write(cr, {
      status: "False",
      reason: "Pending",
      message: failure.message,
    });
    if (failure.kind === "slow") {
      if (failure.refreshIssuer) this.issuers.requestRefresh(waitKey);
      return this.settle(key, result, { kind: "retry", policy: "slow" });
    }
    if (failure.kind === "fast") {
      return this.settle(key, result, {
        kind: "retry",
        policy: "fast",
        ...(failure.minDelayMs === undefined
          ? {}
          : { minDelayMs: failure.minDelayMs }),
      });
    }
    return this.settle(key, result, {
      kind: "retryAfter",
      delayMs: failure.delayMs,
    });
  }

  private finished(key: string): Outcome {
    this.pending.delete(key);
    this.issuers.stopWaiting(key);
    return { kind: "done" };
  }

  private async write(
    cr: CertificateRequest,
    ready: ReadyUpdate,
    extra: StatusExtra = {},
  ): Promise<WriteResult> {
    const now = this.deps.scheduler.now();
    return writeRequestStatus(this.deps.custom, cr, (status) =>
      withReady(status, ready, now, extra),
    );
  }

  /** Failed or Denied: terminal, so the request leaves the pending set. */
  private async terminalWrite(
    key: string,
    cr: CertificateRequest,
    reason: "Failed" | "Denied",
    message: string,
  ): Promise<Outcome> {
    const result = await this.write(
      cr,
      { status: "False", reason, message },
      { failureTime: k8sTime(this.deps.scheduler.now()) },
    );
    return this.settle(key, result, { kind: "done" }, true);
  }

  private settle(
    key: string,
    result: WriteResult,
    outcome: Outcome,
    terminal = false,
  ): Outcome {
    if (result === "uidChanged") {
      // Marked dirty because this key is processing; the new object is read
      // from scratch on the re-run.
      this.queue.add(key);
      return { kind: "done" };
    }
    if (result === "terminal" || result === "gone" || terminal) {
      return this.finished(key);
    }
    return outcome;
  }
}
