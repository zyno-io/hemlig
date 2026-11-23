import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { HemligError, type PkiCaBundle } from "@zyno-io/hemlig-client";
import type { ObjectMeta, RegisteredConsumer } from "../v1beta";
import { k8sTime } from "./cert-manager";
import { resolveIssuerConsumer, type PkiDeps } from "./issuers";
import type { KeyedWorkQueue, Outcome, WorkContext } from "./queue";
import {
  CA_IDS_ANNOTATION,
  CONFIGMAP_MAX_BYTES,
  CRL_ISSUER_ANNOTATION,
  CRL_NEXT_UPDATE_ANNOTATION,
  CRL_NUMBER_ANNOTATION,
  CRL_SHA256_ANNOTATION,
  CRL_SOURCE_ANNOTATION,
  CRL_THIS_UPDATE_ANNOTATION,
  HEMLIG_GROUP,
  ISSUER_VERSION,
  MANAGED_BY_LABEL,
  MANAGED_BY_TRUST_BUNDLE,
  OWNER_ANNOTATION,
  REMOTE_TIMEOUT_MS,
  TRUST_BUNDLE_KIND,
  TRUST_BUNDLE_PLURAL,
  isNotFound,
  k8sStatus,
  log,
  unwrap,
  withTimeout,
  type HemligTrustBundle,
  type IssuerCondition,
  type TrustBundleCrlStatus,
  type TrustBundleStatus,
} from "./types";

// -- Pure helpers -------------------------------------------------------------

export type CrlFormat = "der" | "pem";
export type CrlState = TrustBundleCrlStatus["state"];

export interface CrlMeta {
  readonly number: string;
  readonly thisUpdate: string;
  readonly nextUpdate: string;
}

export const crlConfigMapName = (target: string, id: string): string =>
  `${target}-crl-${id}`;

export const derToPem = (der: Uint8Array): string => {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN X509 CRL-----\n${lines.join("\n")}\n-----END X509 CRL-----\n`;
};

/** The same pattern and normalisation as the server's `pemBlocks`. */
export const pemCertificateBlocks = (pem: string): string[] =>
  (
    pem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    ) ?? []
  ).map((block) => `${block.trim()}\n`);

export const derSha256OfPemBlock = (block: string): string => {
  const body = block
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return createHash("sha256").update(Buffer.from(body, "base64")).digest("hex");
};

type BundleView = Pick<
  PkiCaBundle,
  "caId" | "anchorPem" | "anchorTrusted" | "chainPem"
>;

/**
 * Distrust wins: an anchor that any CA reports as not trusted is omitted even
 * when another CA reports it as trusted.
 */
export const certificateData = (
  views: readonly BundleView[],
): { readonly "ca.crt": string; readonly "chain.crt": string } => {
  const sorted = [...views].sort((a, b) => (a.caId < b.caId ? -1 : 1));
  const distrusted = new Set<string>();
  for (const view of sorted) {
    if (view.anchorTrusted) continue;
    for (const block of pemCertificateBlocks(view.anchorPem)) {
      distrusted.add(derSha256OfPemBlock(block));
    }
  }
  const anchors = new Map<string, string>();
  const chain = new Map<string, string>();
  for (const view of sorted) {
    for (const block of pemCertificateBlocks(view.anchorPem)) {
      const hash = derSha256OfPemBlock(block);
      if (!distrusted.has(hash) && !anchors.has(hash)) anchors.set(hash, block);
    }
    for (const block of pemCertificateBlocks(view.chainPem)) {
      const hash = derSha256OfPemBlock(block);
      if (!chain.has(hash)) chain.set(hash, block);
    }
  }
  return {
    "ca.crt": [...anchors.values()].join(""),
    "chain.crt": [...chain.values()].join(""),
  };
};

interface ConfigMapLike {
  readonly metadata?: ObjectMeta & {
    readonly ownerReferences?: readonly {
      readonly apiVersion?: string;
      readonly kind?: string;
      readonly name?: string;
      readonly uid?: string;
      readonly controller?: boolean;
    }[];
  };
  readonly data?: Readonly<Record<string, string>>;
  readonly binaryData?: Readonly<Record<string, string>>;
}

/** The Kubernetes size rule: `data` UTF-8 bytes plus the decoded `binaryData` bytes. */
export const configMapPayloadBytes = (
  cm: Pick<ConfigMapLike, "data" | "binaryData">,
): number => {
  let total = 0;
  for (const value of Object.values(cm.data ?? {})) {
    total += Buffer.byteLength(value, "utf8");
  }
  for (const value of Object.values(cm.binaryData ?? {})) {
    total += Buffer.from(value, "base64").length;
  }
  return total;
};

export const isOwnedByTrustBundle = (
  meta: ObjectMeta | undefined,
  owner: string,
): boolean =>
  meta?.labels?.[MANAGED_BY_LABEL] === MANAGED_BY_TRUST_BUNDLE &&
  meta.annotations?.[OWNER_ANNOTATION] === owner;

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

export interface StoredCrl extends CrlMeta {
  readonly sha256: string;
  readonly der: Buffer;
}

/**
 * The mounted CRL, or undefined unless the annotations, the key for the
 * requested format and the bytes all agree.
 */
export const storedCrl = (
  cm: ConfigMapLike,
  id: string,
  format: CrlFormat,
): StoredCrl | undefined => {
  const annotations = cm.metadata?.annotations;
  const sha256 = annotations?.[CRL_SHA256_ANNOTATION];
  const number = annotations?.[CRL_NUMBER_ANNOTATION];
  const thisUpdate = annotations?.[CRL_THIS_UPDATE_ANNOTATION];
  const nextUpdate = annotations?.[CRL_NEXT_UPDATE_ANNOTATION];
  if (
    sha256 === undefined ||
    number === undefined ||
    thisUpdate === undefined ||
    nextUpdate === undefined ||
    annotations?.[CRL_ISSUER_ANNOTATION] !== id
  ) {
    return undefined;
  }
  let der: Buffer;
  if (format === "der") {
    const value = cm.binaryData?.["crl.der"];
    if (value === undefined || cm.data?.["crl.pem"] !== undefined) {
      return undefined;
    }
    der = Buffer.from(value, "base64");
  } else {
    const value = cm.data?.["crl.pem"];
    if (value === undefined || cm.binaryData?.["crl.der"] !== undefined) {
      return undefined;
    }
    const body = value
      .replace(/-----(BEGIN|END) X509 CRL-----/g, "")
      .replace(/\s+/g, "");
    der = Buffer.from(body, "base64");
    if (derToPem(der) !== value) return undefined;
  }
  if (sha256Hex(der) !== sha256) return undefined;
  return { sha256, number, thisUpdate, nextUpdate, der };
};

export const freshness = (
  nextUpdate: string,
  nowMs: number,
): "Current" | "Stale" => {
  const at = Date.parse(nextUpdate);
  return Number.isNaN(at) || nowMs >= at ? "Stale" : "Current";
};

export interface ReadyInput {
  readonly partial: boolean;
  /** The previous Ready condition, when it was True at this generation. */
  readonly keep: IssuerCondition | undefined;
  readonly target:
    "written" | "unchanged" | "conflict" | "rejected" | "skipped";
  readonly notFound: readonly string[];
  readonly notActive: readonly string[];
  readonly crls: readonly (TrustBundleCrlStatus & {
    readonly required: boolean;
  })[];
  readonly drained: boolean;
}

export interface ReadyResult {
  readonly status: "True" | "False";
  readonly reason: string;
  readonly message: string;
}

const listIds = (ids: readonly string[]): string => {
  const sorted = [...new Set(ids)].sort();
  const shown = sorted.slice(0, 5).join(", ");
  return sorted.length > 5 ? `${shown}, …` : shown;
};

const clip = (message: string): string => message.slice(0, 1024);

/** The Ready precedence from the CRD contract. Messages never echo remote errors. */
export const readyFor = (
  input: ReadyInput,
): ReadyResult | { readonly keep: IssuerCondition } => {
  const fail = (reason: string, message: string): ReadyResult => ({
    status: "False",
    reason,
    message: clip(message),
  });
  const withState = (state: CrlState, onlyRequired: boolean): string[] =>
    input.crls
      .filter((crl) => crl.state === state && (!onlyRequired || crl.required))
      .map((crl) => crl.id);
  const conflicts = withState("Conflict", false);
  if (input.target === "conflict" || conflicts.length > 0) {
    return fail(
      "ConfigMapConflict",
      `A ConfigMap is not owned by this trust bundle${conflicts.length > 0 ? `: ${listIds(conflicts)}` : ""}`,
    );
  }
  if (input.target === "rejected") {
    return fail(
      "ConfigMapRejected",
      "The target ConfigMap was rejected or is too large",
    );
  }
  if (input.notFound.length > 0) {
    return fail("CaNotFound", `CA not found: ${listIds(input.notFound)}`);
  }
  if (input.notActive.length > 0) {
    return fail("CaNotActive", `CA not active: ${listIds(input.notActive)}`);
  }
  const rejected = withState("Rejected", false);
  if (rejected.length > 0) {
    return fail(
      "CrlRejected",
      `A CRL ConfigMap was rejected or is too large: ${listIds(rejected)}`,
    );
  }
  const missing = withState("Missing", true);
  if (missing.length > 0) {
    return fail("CrlMissing", `CRL not available: ${listIds(missing)}`);
  }
  const stale = withState("Stale", true);
  if (stale.length > 0) {
    return fail("CrlStale", `CRL is past its next update: ${listIds(stale)}`);
  }
  if (input.partial) {
    return input.keep === undefined
      ? fail("RemoteError", "Hemlig is unavailable or returned an error")
      : { keep: input.keep };
  }
  return input.drained
    ? {
        status: "True",
        reason: "CaDrained",
        message: "An accepted CA is drained and can be removed from the bundle",
      }
    : {
        status: "True",
        reason: "Ready",
        message: "The trust bundle and its CRLs are current",
      };
};

// -- Reconciler ---------------------------------------------------------------

const CA_ID = /^ca-[a-z0-9-]{3,80}$/;
const CRL_ISSUER_ID = /^(ca-[a-z0-9-]{3,80}|ext-[0-9a-f]{40})$/;
const USABLE = new Set(["ACTIVE", "RETIRED", "REVOKED"]);
const CRL_NUMBER = /^[0-9a-f]+$/;

const validView = (id: string, value: unknown): PkiCaBundle | undefined => {
  if (typeof value !== "object" || value === null) return undefined;
  const view = value as Partial<PkiCaBundle>;
  if (
    view.caId !== id ||
    typeof view.status !== "string" ||
    typeof view.drained !== "boolean" ||
    typeof view.anchorTrusted !== "boolean" ||
    typeof view.anchorPem !== "string" ||
    typeof view.chainPem !== "string" ||
    !Array.isArray(view.crlIssuers)
  ) {
    return undefined;
  }
  if (pemCertificateBlocks(view.anchorPem).length !== 1) return undefined;
  // A Hemlig ROOT has no chain: its certificate is the anchor.
  if (pemCertificateBlocks(view.chainPem).length < 1 && view.chainPem !== "") {
    return undefined;
  }
  for (const issuer of view.crlIssuers as unknown[]) {
    const entry = issuer as { id?: unknown; source?: unknown } | null;
    if (
      typeof entry?.id !== "string" ||
      !CRL_ISSUER_ID.test(entry.id) ||
      (entry.source !== "GENERATED" && entry.source !== "UPLOADED")
    ) {
      return undefined;
    }
  }
  return view as PkiCaBundle;
};

const validMeta = (meta: CrlMeta | undefined): meta is CrlMeta =>
  meta !== undefined &&
  CRL_NUMBER.test(meta.number) &&
  !Number.isNaN(Date.parse(meta.thisUpdate)) &&
  !Number.isNaN(Date.parse(meta.nextUpdate));

type Fetched =
  | { readonly kind: "ok"; readonly view: PkiCaBundle }
  | { readonly kind: "notFound" }
  | { readonly kind: "notActive" }
  | { readonly kind: "abort" }
  | { readonly kind: "partial"; readonly slow: boolean };

const isRejection = (status: number | undefined): boolean =>
  status === 422 || status === 413 || status === 400;

const asHemlig = (error: unknown): HemligError | undefined =>
  error instanceof HemligError ? error : undefined;

const isTransient = (error: unknown): boolean => {
  const hemlig = asHemlig(error);
  return hemlig === undefined || hemlig.status === 429 || hemlig.status >= 500;
};

const isIdentityRejection = (error: unknown): boolean => {
  const hemlig = asHemlig(error);
  return (
    hemlig !== undefined &&
    hemlig.status === 403 &&
    (hemlig.code === "identity_not_active" || hemlig.code === undefined)
  );
};

const errorStatus = (error: unknown): string => {
  const hemlig = asHemlig(error);
  return hemlig === undefined
    ? String(k8sStatus(error) ?? "unknown")
    : `${hemlig.status}${hemlig.code === undefined ? "" : ` ${hemlig.code}`}`;
};

/** A fallback entry whose mounted copy may have expired since it was recorded. */
const refreshedEntry = (
  entry: TrustBundleCrlStatus,
  nowMs: number,
): TrustBundleCrlStatus =>
  (entry.state === "Current" || entry.state === "Stale") &&
  entry.nextUpdate !== undefined
    ? { ...entry, state: freshness(entry.nextUpdate, nowMs) }
    : entry;

const sortedUnique = (ids: Iterable<string>): string[] =>
  [...new Set(ids)].sort();

export class TrustBundleReconciler {
  public constructor(
    private readonly deps: PkiDeps,
    private readonly queue: Pick<KeyedWorkQueue, "add">,
  ) {}

  public async reconcile(key: string, context: WorkContext): Promise<Outcome> {
    const [namespace, name] = key.slice("bundle/".length).split("/") as [
      string,
      string,
    ];
    let bundle: HemligTrustBundle;
    try {
      bundle = unwrap(
        await this.deps.custom.getNamespacedCustomObject({
          group: HEMLIG_GROUP,
          version: ISSUER_VERSION,
          namespace,
          plural: TRUST_BUNDLE_PLURAL,
          name,
        }),
      ) as HemligTrustBundle;
    } catch (error) {
      if (isNotFound(error)) return { kind: "done" };
      throw error;
    }
    const resolved = await resolveIssuerConsumer(this.deps, bundle);
    if (!resolved.ok) {
      await this.writeStatus(key, bundle, {
        ...(bundle.status ?? {}),
        conditions: [
          this.condition(bundle, {
            status: "False",
            reason: resolved.reason,
            message: resolved.message,
          }),
        ],
      });
      return { kind: "done" };
    }
    const release = context.tryAcquire(resolved.consumerKey);
    if (release === undefined) {
      return { kind: "defer", group: resolved.consumerKey };
    }
    if (this.deps.registry.get(resolved.consumerKey) !== resolved.registered) {
      release();
      this.queue.add(key);
      return { kind: "done" };
    }
    try {
      return await this.pass(key, bundle, resolved.registered);
    } finally {
      release();
    }
  }

  private async remote<T>(promise: Promise<T>): Promise<T> {
    return withTimeout(promise, REMOTE_TIMEOUT_MS, this.deps.scheduler);
  }

  private condition(
    bundle: HemligTrustBundle,
    ready: ReadyResult,
  ): IssuerCondition {
    const old = bundle.status?.conditions?.find((c) => c.type === "Ready");
    return {
      type: "Ready",
      status: ready.status,
      reason: ready.reason,
      message: ready.message,
      lastTransitionTime:
        old?.status === ready.status && old.lastTransitionTime !== undefined
          ? old.lastTransitionTime
          : k8sTime(this.deps.scheduler.now()),
    };
  }

  private async readConfigMap(
    namespace: string,
    name: string,
  ): Promise<ConfigMapLike | undefined> {
    try {
      return unwrap(
        await this.deps.core.readNamespacedConfigMap({ name, namespace }),
      ) as ConfigMapLike;
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }

  private ownerReference(bundle: HemligTrustBundle) {
    return {
      apiVersion: `${HEMLIG_GROUP}/${ISSUER_VERSION}`,
      kind: TRUST_BUNDLE_KIND,
      name: bundle.metadata.name as string,
      uid: bundle.metadata.uid as string,
      controller: true,
    };
  }

  /** The managed ConfigMap: our labels and annotations win, foreign extras survive a replace. */
  private desiredConfigMap(
    bundle: HemligTrustBundle,
    name: string,
    existing: ConfigMapLike | undefined,
    annotations: Record<string, string>,
    content: {
      data?: Record<string, string>;
      binaryData?: Record<string, string>;
    },
  ) {
    return {
      apiVersion: "v1",
      kind: "ConfigMap",
      metadata: {
        name,
        namespace: bundle.metadata.namespace as string,
        ...(existing?.metadata?.resourceVersion === undefined
          ? {}
          : { resourceVersion: existing.metadata.resourceVersion }),
        labels: {
          ...(existing?.metadata?.labels ?? {}),
          [MANAGED_BY_LABEL]: MANAGED_BY_TRUST_BUNDLE,
        },
        annotations: {
          ...(existing?.metadata?.annotations ?? {}),
          ...annotations,
        },
        ownerReferences: [this.ownerReference(bundle)],
      },
      ...content,
    };
  }

  private upToDate(
    existing: ConfigMapLike,
    desired: ReturnType<TrustBundleReconciler["desiredConfigMap"]>,
    bundle: HemligTrustBundle,
  ): boolean {
    const owner = this.ownerReference(bundle);
    const refs = existing.metadata?.ownerReferences ?? [];
    return (
      isDeepStrictEqual(existing.data ?? {}, desired.data ?? {}) &&
      isDeepStrictEqual(existing.binaryData ?? {}, desired.binaryData ?? {}) &&
      isDeepStrictEqual(
        existing.metadata?.labels ?? {},
        desired.metadata.labels,
      ) &&
      isDeepStrictEqual(
        existing.metadata?.annotations ?? {},
        desired.metadata.annotations,
      ) &&
      refs.length === 1 &&
      refs[0]?.uid === owner.uid &&
      refs[0]?.controller === true &&
      refs[0]?.kind === owner.kind &&
      refs[0]?.name === owner.name
    );
  }

  /** Create or replace. Returns an HTTP-ish result without ever logging the error text. */
  private async put(
    key: string,
    namespace: string,
    name: string,
    existing: ConfigMapLike | undefined,
    body: unknown,
  ): Promise<"written" | "rejected" | "failed"> {
    try {
      await (existing === undefined
        ? this.deps.core.createNamespacedConfigMap({ namespace, body })
        : this.deps.core.replaceNamespacedConfigMap({ name, namespace, body }));
      log(`${key} configmap ${name} written`);
      return "written";
    } catch (error) {
      const status = k8sStatus(error);
      log(
        `${key} configmap ${name} ${existing === undefined ? "create" : "replace"} failed (${status ?? "unknown"})`,
      );
      return isRejection(status) ? "rejected" : "failed";
    }
  }

  private async fetchBundle(
    key: string,
    id: string,
    registered: RegisteredConsumer,
  ): Promise<Fetched> {
    try {
      const raw = await this.remote(registered.client.getCaBundle(id));
      const view = validView(id, raw);
      if (view === undefined) {
        log(`${key} ca ${id} bundle failed (invalid)`);
        return { kind: "partial", slow: true };
      }
      return { kind: "ok", view };
    } catch (error) {
      if (isIdentityRejection(error)) {
        log(`${key} ca ${id} bundle failed (${errorStatus(error)})`);
        return { kind: "abort" };
      }
      const hemlig = asHemlig(error);
      if (hemlig?.status === 404 && hemlig.details?.reason === "ca_not_found") {
        return { kind: "notFound" };
      }
      if (hemlig?.status === 409 && hemlig.code === "ca_not_active") {
        return { kind: "notActive" };
      }
      log(`${key} ca ${id} bundle failed (${errorStatus(error)})`);
      return { kind: "partial", slow: !isTransient(error) };
    }
  }

  private async pass(
    key: string,
    bundle: HemligTrustBundle,
    registered: RegisteredConsumer,
  ): Promise<Outcome> {
    const namespace = bundle.metadata.namespace as string;
    const owner = `${namespace}/${bundle.metadata.name as string}`;
    const target = bundle.spec.target.name;
    const format: CrlFormat = bundle.spec.crlFormat === "pem" ? "pem" : "der";
    const now = this.deps.scheduler.now();
    const old = bundle.status;
    let partial = false;
    let slow = false;
    const markPartial = (isSlow: boolean): void => {
      partial = true;
      if (isSlow) slow = true;
    };
    const abort = async (): Promise<Outcome> => {
      await this.writeStatus(key, bundle, {
        ...(old ?? {}),
        consumerId: registered.consumerId,
        environment: registered.environment,
        conditions: [
          this.condition(bundle, {
            status: "False",
            reason: "ConsumerNotReady",
            message: "Hemlig rejected the consumer identity",
          }),
        ],
      });
      return { kind: "done" };
    };

    // 4. The target as it stands.
    let targetCm: ConfigMapLike | undefined;
    let targetKnown = true;
    try {
      targetCm = await this.readConfigMap(namespace, target);
    } catch (error) {
      log(`${key} configmap ${target} read failed (${errorStatus(error)})`);
      targetKnown = false;
      markPartial(false);
    }
    const targetOwned =
      targetCm === undefined || isOwnedByTrustBundle(targetCm.metadata, owner);
    let prevAccepted: string[];
    if (!targetKnown) {
      prevAccepted = [...(old?.acceptedCaIds ?? [])];
    } else if (targetCm !== undefined && targetOwned) {
      const raw = targetCm.metadata?.annotations?.[CA_IDS_ANNOTATION] ?? "";
      prevAccepted = raw
        .split(",")
        .filter((id) => CA_ID.test(id))
        .sort();
    } else {
      prevAccepted = [];
    }

    // 5. Every CA the bundle names, plus the ones currently mounted.
    const specIds = sortedUnique(bundle.spec.caIds);
    const fetchIds = sortedUnique([...specIds, ...prevAccepted]);
    const views = new Map<string, PkiCaBundle>();
    const notFound: string[] = [];
    const notActive: string[] = [];
    for (const id of fetchIds) {
      const result = await this.fetchBundle(key, id, registered);
      if (result.kind === "abort") return abort();
      if (result.kind === "ok") views.set(id, result.view);
      else if (result.kind === "partial") {
        markPartial(result.slow);
        // A transient failure means Hemlig is struggling: do not hold the
        // consumer slot for the remaining CAs.
        if (!result.slow) break;
      } else if (specIds.includes(id)) {
        (result.kind === "notFound" ? notFound : notActive).push(id);
      }
    }

    // 6. Only usable CAs from the spec feed the target.
    const usable: string[] = [];
    for (const id of specIds) {
      const view = views.get(id);
      if (view === undefined) continue;
      if (USABLE.has(view.status)) usable.push(id);
      else notActive.push(id);
    }

    // A complete pass that would leave nothing usable never wipes the mounts.
    if (!partial && usable.length === 0 && prevAccepted.length > 0) {
      markPartial(true);
    }

    // 7. The target ConfigMap.
    let targetState: ReadyInput["target"];
    let accepted: string[];
    const bundleViews = (ids: readonly string[]): PkiCaBundle[] =>
      ids.map((id) => views.get(id) as PkiCaBundle);
    if (partial) {
      targetState = "skipped";
      accepted = prevAccepted;
    } else if (!targetOwned) {
      targetState = "conflict";
      accepted = [];
    } else {
      const content = certificateData(bundleViews(usable));
      const desired = this.desiredConfigMap(
        bundle,
        target,
        targetCm,
        { [OWNER_ANNOTATION]: owner, [CA_IDS_ANNOTATION]: usable.join(",") },
        { data: { ...content } },
      );
      if (configMapPayloadBytes(desired) > CONFIGMAP_MAX_BYTES) {
        targetState = "rejected";
        accepted = prevAccepted;
      } else if (
        targetCm !== undefined &&
        this.upToDate(targetCm, desired, bundle)
      ) {
        targetState = "unchanged";
        accepted = usable;
      } else {
        const result = await this.put(
          key,
          namespace,
          target,
          targetCm,
          desired,
        );
        if (result === "written") {
          targetState = "written";
          accepted = usable;
        } else if (result === "rejected") {
          targetState = "rejected";
          accepted = prevAccepted;
        } else {
          markPartial(false);
          targetState = "skipped";
          accepted = prevAccepted;
        }
      }
    }

    // 8. A complete pass is the only one that may drop anything.
    const complete =
      !partial && (targetState === "written" || targetState === "unchanged");
    const oldCrls = new Map(
      (old?.crls ?? []).map((entry) => [entry.id, entry]),
    );
    const sources = new Map<string, "GENERATED" | "UPLOADED">();
    const crlIds = new Set<string>();
    if (bundle.spec.includeCrl !== false) {
      for (const id of accepted) {
        for (const issuer of views.get(id)?.crlIssuers ?? []) {
          crlIds.add(issuer.id);
          if (!sources.has(issuer.id)) sources.set(issuer.id, issuer.source);
        }
      }
      if (!complete) for (const id of oldCrls.keys()) crlIds.add(id);
    }
    const sourceOf = (id: string): "GENERATED" | "UPLOADED" =>
      sources.get(id) ??
      oldCrls.get(id)?.source ??
      (id.startsWith("ca-") ? "GENERATED" : "UPLOADED");

    // 9. One CRL ConfigMap per issuer.
    const entries: TrustBundleCrlStatus[] = [];
    let skipCrlFetches = false;
    for (const id of sortedUnique(crlIds)) {
      const outcome = await this.refreshCrl({
        key,
        bundle,
        namespace,
        owner,
        target,
        format,
        now,
        registered,
        id,
        source: sourceOf(id),
        previous: oldCrls.get(id),
        skipFetch: skipCrlFetches,
      });
      if (outcome.abort) return abort();
      if (outcome.partial) markPartial(outcome.slow);
      // After one transient failure do not hold the consumer slot for the rest.
      if (outcome.transient) skipCrlFetches = true;
      entries.push(outcome.entry);
    }

    // 10. Entries whose issuer left the bundle.
    const carried: TrustBundleCrlStatus[] = [];
    for (const [id, entry] of oldCrls) {
      if (crlIds.has(id)) continue;
      // `partial` may have turned true during the CRL loop.
      if (!complete || partial) {
        carried.push(refreshedEntry(entry, now));
        continue;
      }
      if (!(await this.deleteOwned(key, namespace, entry.configMap, owner))) {
        carried.push(refreshedEntry(entry, now));
        markPartial(false);
      }
    }

    // 11. Status.
    const required = (entry: TrustBundleCrlStatus): boolean => {
      if (entry.source !== "GENERATED") return true;
      if (accepted.includes(entry.id)) {
        const view = views.get(entry.id);
        return !(
          view !== undefined &&
          (view.status === "REVOKED" || view.drained)
        );
      }
      // A Hemlig root slot named by listed children: needed while one of them can still validate.
      const dependents = accepted
        .map((id) => views.get(id))
        .filter(
          (v): v is PkiCaBundle =>
            v?.crlIssuers.some((i) => i.id === entry.id) === true,
        );
      return (
        dependents.length === 0 ||
        dependents.some((v) => v.anchorTrusted && !v.drained)
      );
    };
    const publishAt = this.deps.scheduler.now();
    const allEntries = [...entries, ...carried]
      .map((entry) => refreshedEntry(entry, publishAt))
      .sort((a, b) => (a.id < b.id ? -1 : 1));
    const oldReady = old?.conditions?.find((c) => c.type === "Ready");
    const keep =
      oldReady?.status === "True" &&
      old?.observedGeneration === bundle.metadata.generation
        ? oldReady
        : undefined;
    const ready = readyFor({
      partial,
      keep,
      target: targetState,
      notFound,
      notActive,
      crls: allEntries.map((entry) => ({
        ...entry,
        required: required(entry),
      })),
      drained: accepted.some((id) => views.get(id)?.drained === true),
    });
    const condition =
      "keep" in ready ? ready.keep : this.condition(bundle, ready);
    const written = await this.writeStatus(key, bundle, {
      ...(bundle.metadata.generation === undefined
        ? {}
        : { observedGeneration: bundle.metadata.generation }),
      consumerId: registered.consumerId,
      environment: registered.environment,
      acceptedCaIds: sortedUnique(accepted),
      crls: allEntries,
      conditions: [condition],
    });
    if (!written) return { kind: "done" };
    return slow
      ? { kind: "retry", policy: "slow" }
      : partial
        ? { kind: "retry", policy: "fast" }
        : { kind: "done" };
  }

  private async refreshCrl(input: {
    readonly key: string;
    readonly bundle: HemligTrustBundle;
    readonly namespace: string;
    readonly owner: string;
    readonly target: string;
    readonly format: CrlFormat;
    readonly now: number;
    readonly registered: RegisteredConsumer;
    readonly id: string;
    readonly source: "GENERATED" | "UPLOADED";
    readonly previous: TrustBundleCrlStatus | undefined;
    readonly skipFetch?: boolean;
  }): Promise<{
    entry: TrustBundleCrlStatus;
    partial: boolean;
    slow: boolean;
    abort: boolean;
    transient: boolean;
  }> {
    const { key, bundle, namespace, owner, target, format, now, id, source } =
      input;
    const name = crlConfigMapName(target, id);
    const make = (state: CrlState, meta?: CrlMeta): TrustBundleCrlStatus => ({
      id,
      source,
      configMap: name,
      state,
      ...(meta === undefined
        ? {}
        : {
            number: meta.number,
            thisUpdate: meta.thisUpdate,
            nextUpdate: meta.nextUpdate,
          }),
    });
    const result = (
      entry: TrustBundleCrlStatus,
      flags: {
        partial?: boolean;
        slow?: boolean;
        abort?: boolean;
        transient?: boolean;
      } = {},
    ) => ({
      transient: flags.transient === true,
      entry,
      partial: flags.partial === true,
      slow: flags.slow === true,
      abort: flags.abort === true,
    });
    const previous =
      input.previous === undefined
        ? make("Missing")
        : refreshedEntry(input.previous, now);
    let cm: ConfigMapLike | undefined;
    try {
      cm = await this.readConfigMap(namespace, name);
    } catch (error) {
      log(`${key} configmap ${name} read failed (${errorStatus(error)})`);
      return result(previous, { partial: true });
    }
    if (cm !== undefined && !isOwnedByTrustBundle(cm.metadata, owner)) {
      return result(make("Conflict"));
    }
    const stored = cm === undefined ? undefined : storedCrl(cm, id, format);
    // A confirmed-absent ConfigMap is Missing. A copy that does not verify in
    // the current format may still verify in the other one (a format switch).
    const fromStored = (): TrustBundleCrlStatus => {
      if (cm === undefined) return make("Missing");
      const copy =
        stored ?? storedCrl(cm, id, format === "der" ? "pem" : "der");
      return copy === undefined
        ? make("Missing")
        : make(freshness(copy.nextUpdate, now), copy);
    };
    if (input.skipFetch === true) {
      return result(fromStored(), { partial: true });
    }
    let response;
    try {
      response = await this.remote(
        input.registered.client.getCrl(id, stored?.sha256),
      );
    } catch (error) {
      const hemlig = asHemlig(error);
      if (
        hemlig?.status === 404 &&
        ["crl_missing", "ca_not_found", "external_ca_not_found"].includes(
          hemlig.details?.reason as string,
        )
      ) {
        return result(make("Missing", stored));
      }
      log(`${key} crl ${id} fetch failed (${errorStatus(error)})`);
      if (isIdentityRejection(error)) {
        return result(fromStored(), { abort: true });
      }
      const slow = !isTransient(error);
      return result(fromStored(), {
        partial: true,
        slow,
        transient: !slow,
      });
    }
    let der: Buffer;
    let meta: CrlMeta;
    if (response.status === 304) {
      const candidate = response.crl ?? stored;
      if (stored === undefined || !validMeta(candidate)) {
        return result(fromStored(), { partial: true, slow: true });
      }
      der = stored.der;
      meta = candidate;
    } else {
      der = Buffer.from(response.bytes);
      if (response.etag === undefined || sha256Hex(der) !== response.etag) {
        return result(fromStored(), { partial: true });
      }
      if (!validMeta(response.crl)) {
        return result(fromStored(), { partial: true, slow: true });
      }
      meta = response.crl;
    }
    const sha256 = sha256Hex(der);
    const desired = this.desiredConfigMap(
      bundle,
      name,
      cm,
      {
        [OWNER_ANNOTATION]: owner,
        [CRL_ISSUER_ANNOTATION]: id,
        [CRL_SOURCE_ANNOTATION]: source,
        [CRL_SHA256_ANNOTATION]: sha256,
        [CRL_NUMBER_ANNOTATION]: meta.number,
        [CRL_THIS_UPDATE_ANNOTATION]: meta.thisUpdate,
        [CRL_NEXT_UPDATE_ANNOTATION]: meta.nextUpdate,
      },
      format === "der"
        ? { binaryData: { "crl.der": der.toString("base64") } }
        : { data: { "crl.pem": derToPem(der) } },
    );
    if (configMapPayloadBytes(desired) > CONFIGMAP_MAX_BYTES) {
      return result(make("Rejected", stored));
    }
    if (cm !== undefined && this.upToDate(cm, desired, bundle)) {
      return result(make(freshness(meta.nextUpdate, now), meta));
    }
    const written = await this.put(key, namespace, name, cm, desired);
    if (written === "written") {
      log(`${key} crl ${id} number=${meta.number}`);
      return result(make(freshness(meta.nextUpdate, now), meta));
    }
    if (written === "rejected") {
      return result(make("Rejected", stored));
    }
    return result(fromStored(), { partial: true });
  }

  /** True when the ConfigMap is gone or was removed; false keeps the entry for another pass. */
  private async deleteOwned(
    key: string,
    namespace: string,
    name: string,
    owner: string,
  ): Promise<boolean> {
    let cm: ConfigMapLike | undefined;
    try {
      cm = await this.readConfigMap(namespace, name);
    } catch (error) {
      log(`${key} configmap ${name} read failed (${errorStatus(error)})`);
      return false;
    }
    if (cm === undefined) return true;
    if (!isOwnedByTrustBundle(cm.metadata, owner)) return true;
    try {
      await this.deps.core.deleteNamespacedConfigMap({
        name,
        namespace,
        body: {
          preconditions: {
            uid: cm.metadata?.uid,
            resourceVersion: cm.metadata?.resourceVersion,
          },
        },
      });
      log(`${key} configmap ${name} deleted`);
      return true;
    } catch (error) {
      const status = k8sStatus(error);
      if (status === 404) return true;
      log(`${key} configmap ${name} delete failed (${status ?? "unknown"})`);
      return false;
    }
  }

  private async writeStatus(
    key: string,
    bundle: HemligTrustBundle,
    status: TrustBundleStatus,
  ): Promise<boolean> {
    const nowMs = this.deps.scheduler.now();
    const next: TrustBundleStatus = {
      ...status,
      ...(status.crls === undefined
        ? {}
        : { crls: status.crls.map((entry) => refreshedEntry(entry, nowMs)) }),
      ...(bundle.metadata.generation === undefined
        ? {}
        : { observedGeneration: bundle.metadata.generation }),
    };
    if (isDeepStrictEqual(bundle.status, next)) return true;
    try {
      await this.deps.custom.patchNamespacedCustomObjectStatus({
        group: HEMLIG_GROUP,
        version: ISSUER_VERSION,
        namespace: bundle.metadata.namespace as string,
        plural: TRUST_BUNDLE_PLURAL,
        name: bundle.metadata.name as string,
        body: [
          { op: "test", path: "/metadata/uid", value: bundle.metadata.uid },
          { op: "add", path: "/status", value: next },
        ],
      });
    } catch (error) {
      if (isNotFound(error)) return true;
      const code = k8sStatus(error);
      if (code === 409 || code === 422) {
        // The bundle was recreated: the new object has its own events.
        log(`${key} status patch refused (${code})`);
        this.queue.add(key);
        return false;
      }
      throw error;
    }
    const ready = next.conditions?.find((c) => c.type === "Ready");
    const old = bundle.status?.conditions?.find((c) => c.type === "Ready");
    if (ready?.status !== old?.status || ready?.reason !== old?.reason) {
      log(`${key} Ready=${ready?.status} ${ready?.reason}`);
    }
    return true;
  }
}
