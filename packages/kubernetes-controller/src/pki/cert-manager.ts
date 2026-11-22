import { HemligError } from "@zyno-io/hemlig-client";
import type { PkiIssueCertificateRequest } from "@zyno-io/hemlig-client";
import {
  CERTIFICATE_NAME_ANNOTATION,
  CERTIFICATE_REVISION_ANNOTATION,
  CLUSTER_ISSUER_KIND,
  HEMLIG_GROUP,
  IDEMPOTENCY_PREFIX,
  ISSUER_KIND,
  type CertificateRequest,
  type CertificateRequestStatus,
  type CrCondition,
} from "./types";

// ---------------------------------------------------------------------------
// Ownership, conditions, terminal states
// ---------------------------------------------------------------------------

/**
 * An empty kind is cert-manager's Issuer and an empty group is cert-manager.io,
 * so only an explicit Hemlig group with a Hemlig kind is ours.
 */
export const isHemligRequest = (cr: CertificateRequest): boolean => {
  const ref = cr.spec?.issuerRef;
  return (
    ref?.group === HEMLIG_GROUP &&
    (ref.kind === ISSUER_KIND || ref.kind === CLUSTER_ISSUER_KIND)
  );
};

export const conditionOf = (
  cr: { readonly status?: CertificateRequestStatus },
  type: string,
): CrCondition | undefined =>
  cr.status?.conditions?.find((condition) => condition.type === type);

export const isTrue = (
  cr: { readonly status?: CertificateRequestStatus },
  type: string,
): boolean => conditionOf(cr, type)?.status === "True";

export const isTerminal = (cr: {
  readonly status?: CertificateRequestStatus;
}): boolean => {
  const ready = conditionOf(cr, "Ready");
  return (
    ready?.status === "True" ||
    (ready?.status === "False" &&
      (ready.reason === "Failed" || ready.reason === "Denied")) ||
    (typeof cr.status?.certificate === "string" &&
      cr.status.certificate.length > 0)
  );
};

// ---------------------------------------------------------------------------
// Input mapping
//
// FROZEN: the usage mapping and the duration flooring below feed the server's
// idempotency digest (sorted raw strings and durationSeconds). Changing either
// later would turn an in-flight request replay into a 409 conflict (Failed).
// ---------------------------------------------------------------------------

const usageMap = new Map<string, string>([
  ["digital signature", "digitalSignature"],
  ["signing", "digitalSignature"],
  ["key encipherment", "keyEncipherment"],
  ["server auth", "serverAuth"],
  ["client auth", "clientAuth"],
]);

export type UsageResult =
  | { readonly ok: true; readonly usages?: string[] }
  | { readonly ok: false; readonly usage: string };

export const mapUsages = (usages?: readonly string[]): UsageResult => {
  if (usages === undefined || usages.length === 0) return { ok: true };
  const mapped = new Set<string>();
  for (const usage of usages) {
    const target = typeof usage === "string" ? usageMap.get(usage) : undefined;
    if (target === undefined) return { ok: false, usage: String(usage) };
    mapped.add(target);
  }
  return { ok: true, usages: [...mapped].sort() };
};

const unitNanoseconds: Readonly<Record<string, bigint>> = {
  ns: 1n,
  us: 1_000n,
  µs: 1_000n,
  μs: 1_000n,
  ms: 1_000_000n,
  s: 1_000_000_000n,
  m: 60_000_000_000n,
  h: 3_600_000_000_000n,
};

const durationPattern =
  /^[+]?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:ns|us|µs|μs|ms|s|m|h))+$/;
const durationPart = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/g;

export type DurationResult =
  { readonly ok: true; readonly seconds?: number } | { readonly ok: false };

/** Go `time.Duration` grammar, floored to whole seconds (frozen; see above). */
export const parseDurationSeconds = (value?: string): DurationResult => {
  if (value === undefined) return { ok: true };
  if (typeof value !== "string" || !durationPattern.test(value)) {
    return { ok: false };
  }
  let nanoseconds = 0n;
  for (const match of value.matchAll(durationPart)) {
    const [, number = "", unit = ""] = match;
    const [whole = "", fraction = ""] = number.split(".");
    const scale = unitNanoseconds[unit];
    if (scale === undefined) return { ok: false };
    nanoseconds += BigInt(whole === "" ? "0" : whole) * scale;
    if (fraction !== "") {
      nanoseconds +=
        (BigInt(fraction) * scale) / 10n ** BigInt(fraction.length);
    }
  }
  const seconds = nanoseconds / 1_000_000_000n;
  if (seconds < 1n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) {
    return { ok: false };
  }
  return { ok: true, seconds: Number(seconds) };
};

const MAX_CSR_BYTES = 64 * 1024;
const BEGIN_CSR = "-----BEGIN CERTIFICATE REQUEST-----";
const END_CSR = "-----END CERTIFICATE REQUEST-----";

/** Shape check only; the server does the real validation. */
export const decodeCsr = (request?: string): string | undefined => {
  if (typeof request !== "string" || request.length === 0) return undefined;
  if (!/^[A-Za-z0-9+/=\s]+$/.test(request)) return undefined;
  const bytes = Buffer.from(request, "base64");
  if (bytes.length === 0 || bytes.length > MAX_CSR_BYTES) return undefined;
  const pem = bytes.toString("utf8");
  return pem.includes(BEGIN_CSR) && pem.includes(END_CSR) ? pem : undefined;
};

// Same patterns and bounds as the server (src/pki/issuance-model.ts).
const requesterPatterns = {
  namespace: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/,
  name: /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/,
  uid: /^[0-9A-Fa-f-]{1,64}$/,
  revision: /^\d{1,10}$/,
} as const;

const passes = (
  value: string | undefined,
  pattern: RegExp,
  max: number,
): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= max &&
  pattern.test(value);

/**
 * Never forwards spec.username or spec.groups: the server rejects unknown
 * fields. Optional fields that fail the server's regexes are dropped.
 */
export const requesterFor = (
  cr: CertificateRequest,
): PkiIssueCertificateRequest["requester"] => {
  const { namespace, name, uid } = cr.metadata;
  if (
    !passes(namespace, requesterPatterns.namespace, 63) ||
    !passes(name, requesterPatterns.name, 253) ||
    !passes(uid, requesterPatterns.uid, 64)
  ) {
    return undefined;
  }
  const certificateName =
    cr.metadata.annotations?.[CERTIFICATE_NAME_ANNOTATION];
  const revision = cr.metadata.annotations?.[CERTIFICATE_REVISION_ANNOTATION];
  return {
    kubernetes: {
      namespace,
      name,
      uid,
      ...(passes(certificateName, requesterPatterns.name, 253)
        ? { certificateName }
        : {}),
      ...(passes(revision, requesterPatterns.revision, 10) ? { revision } : {}),
    },
  };
};

export type BuildResult =
  | { readonly ok: true; readonly body: PkiIssueCertificateRequest }
  | { readonly ok: false; readonly message: string };

/** Printable ASCII only, and nothing that could be PEM. */
export const safeText = (value: unknown, max = 253): string | undefined => {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    return undefined;
  }
  if (!/^[\x20-\x7e]+$/.test(value) || value.includes("-----")) {
    return undefined;
  }
  return value;
};

/** The body has exactly the five fields the server accepts. */
export const buildIssueRequest = (cr: CertificateRequest): BuildResult => {
  if (cr.spec.isCA === true) {
    return {
      ok: false,
      message: "UnsupportedRequest: CA certificates are not issued by Hemlig",
    };
  }
  const usages = mapUsages(cr.spec.usages);
  if (!usages.ok) {
    return {
      ok: false,
      message: `UnsupportedRequest: usage "${safeText(usages.usage, 64) ?? "unknown"}" is not supported`,
    };
  }
  const duration = parseDurationSeconds(cr.spec.duration);
  if (!duration.ok) {
    return {
      ok: false,
      message: "UnsupportedRequest: spec.duration is invalid",
    };
  }
  const csr = decodeCsr(cr.spec.request);
  if (csr === undefined) {
    return {
      ok: false,
      message:
        "UnsupportedRequest: spec.request is not a PEM certificate request",
    };
  }
  const requester = requesterFor(cr);
  return {
    ok: true,
    body: {
      certificateSigningRequestPem: csr,
      ...(duration.seconds === undefined
        ? {}
        : { durationSeconds: duration.seconds }),
      ...(usages.usages === undefined ? {} : { usages: usages.usages }),
      isCA: false,
      ...(requester === undefined ? {} : { requester }),
    },
  };
};

export const idempotencyKeyFor = (uid: string): string =>
  `${IDEMPOTENCY_PREFIX}${uid}`;

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const BEGIN_CERT = "-----BEGIN CERTIFICATE-----";

export const issuedStatusFields = (r: {
  readonly certificatePem?: unknown;
  readonly chainPem?: unknown;
  readonly caPem?: unknown;
}): { certificate: string; ca: string } | undefined => {
  const { certificatePem, chainPem, caPem } = r;
  if (
    typeof certificatePem !== "string" ||
    typeof chainPem !== "string" ||
    typeof caPem !== "string" ||
    !certificatePem.startsWith(BEGIN_CERT) ||
    !chainPem.startsWith(BEGIN_CERT) ||
    !caPem.startsWith(BEGIN_CERT) ||
    !certificatePem.endsWith("\n")
  ) {
    return undefined;
  }
  return {
    certificate: Buffer.from(certificatePem + chainPem, "utf8").toString(
      "base64",
    ),
    ca: Buffer.from(caPem, "utf8").toString("base64"),
  };
};

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/** RFC 3339 at second precision, as cert-manager writes it. */
export const k8sTime = (ms: number): string =>
  new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

export interface ReadyUpdate {
  readonly status: "True" | "False";
  readonly reason: "Pending" | "Failed" | "Issued" | "Denied";
  readonly message: string;
}

export interface StatusExtra {
  readonly certificate?: string;
  readonly ca?: string;
  readonly failureTime?: string;
}

/**
 * Returns a new status. The existing Ready element is replaced in place (or
 * appended); every other condition is kept as the same object in the same
 * position, because cert-manager's webhook guards the approval conditions.
 */
export const withReady = (
  status: CertificateRequestStatus | undefined,
  ready: ReadyUpdate,
  now: number,
  extra: StatusExtra = {},
): CertificateRequestStatus => {
  const current = status ?? {};
  const conditions = [...(current.conditions ?? [])];
  const index = conditions.findIndex((condition) => condition.type === "Ready");
  const old = index === -1 ? undefined : conditions[index];
  const next: CrCondition = {
    type: "Ready",
    status: ready.status,
    reason: ready.reason,
    message: ready.message,
    lastTransitionTime:
      old?.status === ready.status && old.lastTransitionTime !== undefined
        ? old.lastTransitionTime
        : k8sTime(now),
  };
  if (index === -1) conditions.push(next);
  else conditions[index] = next;
  return {
    ...current,
    ...extra,
    conditions,
  };
};

export const readyUnchanged = (
  a: CertificateRequestStatus | undefined,
  b: CertificateRequestStatus | undefined,
): boolean => {
  const left = conditionOf({ status: a }, "Ready");
  const right = conditionOf({ status: b }, "Ready");
  return (
    left?.status === right?.status &&
    left?.reason === right?.reason &&
    left?.message === right?.message &&
    a?.certificate === b?.certificate &&
    a?.ca === b?.ca &&
    (a?.failureTime === undefined) === (b?.failureTime === undefined)
  );
};

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

export type IssueFailure =
  | { kind: "failed"; message: string }
  | { kind: "slow"; message: string; refreshIssuer: boolean }
  | { kind: "fast"; message: string; minDelayMs?: number }
  | { kind: "retryAfter"; delayMs: number; message: string };

const MAX_MESSAGE = 1024;
const RETRY_AFTER_CAP_SECONDS = 86_400;

const withReason = (error: HemligError): string => {
  const code = safeText(error.code, 80) ?? "unknown";
  const reason = safeText(error.details?.reason, 80);
  return reason === undefined ? code : `${code} (${reason})`;
};

export const classifyIssueError = (error: unknown): IssueFailure => {
  const result = classify(error);
  return { ...result, message: result.message.slice(0, MAX_MESSAGE) };
};

const classify = (error: unknown): IssueFailure => {
  if (!(error instanceof HemligError)) {
    return { kind: "fast", message: "HemligUnavailable: network error" };
  }
  const { status, code } = error;
  if (status === 400 && (code === "bad_request" || code === "invalid_csr")) {
    return { kind: "failed", message: withReason(error) };
  }
  if (status === 403 && code === "issuance_denied") {
    const type = safeText(error.details?.deniedNameType, 32);
    const name = safeText(error.details?.deniedName, 253);
    return {
      kind: "failed",
      message: `${withReason(error)}${type !== undefined && name !== undefined ? `: ${type} ${name}` : ""}`,
    };
  }
  if (
    status === 409 &&
    (code === "issuance_revoked" ||
      code === "issuance_expired" ||
      code === "conflict")
  ) {
    return { kind: "failed", message: withReason(error) };
  }
  if (
    (status === 404 && code === "issuance_grant_not_found") ||
    (status === 403 && code === "issuance_grant_inactive") ||
    (status === 409 && code === "ca_not_active")
  ) {
    return { kind: "slow", message: withReason(error), refreshIssuer: true };
  }
  if (
    status === 409 &&
    (code === "ca_capacity_exceeded" || code === "ca_key_unavailable")
  ) {
    return { kind: "slow", message: withReason(error), refreshIssuer: false };
  }
  if (
    status === 403 &&
    (code === "identity_not_active" || code === undefined)
  ) {
    return {
      kind: "slow",
      message: "identity_not_active: Hemlig rejected the consumer identity",
      refreshIssuer: false,
    };
  }
  if (status === 429) {
    const seconds = error.retryAfterSeconds ?? error.details?.retryAfterSeconds;
    if (
      code === "issuance_rate_limited" &&
      typeof seconds === "number" &&
      Number.isInteger(seconds) &&
      seconds >= 1
    ) {
      return {
        kind: "retryAfter",
        delayMs: Math.min(seconds, RETRY_AFTER_CAP_SECONDS) * 1000,
        message: withReason(error),
      };
    }
    return { kind: "fast", message: "HemligUnavailable (429)" };
  }
  if (status >= 500) {
    return {
      kind: "fast",
      message: `HemligUnavailable (${status})`,
      ...(error.retryAfterSeconds === undefined
        ? {}
        : {
            minDelayMs:
              Math.min(error.retryAfterSeconds, RETRY_AFTER_CAP_SECONDS) * 1000,
          }),
    };
  }
  const codeText = safeText(code, 80);
  return {
    kind: "slow",
    message: `HemligError (${status}${codeText === undefined ? "" : ` ${codeText}`})`,
    refreshIssuer: false,
  };
};
