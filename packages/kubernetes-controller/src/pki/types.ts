import type { ObjectMeta } from "../v1beta";

export const HEMLIG_GROUP = "hemlig.zyno.io";
export const ISSUER_VERSION = "v1alpha1";
export const CONSUMER_VERSION = "v1beta1";
export const CM_GROUP = "cert-manager.io";
export const CM_VERSION = "v1";

export const ISSUER_PLURAL = "hemligissuers";
export const CLUSTER_ISSUER_PLURAL = "hemligclusterissuers";
export const CONSUMER_PLURAL = "hemligconsumers";
export const CR_PLURAL = "certificaterequests";

export const ISSUER_KIND = "HemligIssuer";
export const CLUSTER_ISSUER_KIND = "HemligClusterIssuer";

export const CERTIFICATE_NAME_ANNOTATION = "cert-manager.io/certificate-name";
export const CERTIFICATE_REVISION_ANNOTATION =
  "cert-manager.io/certificate-revision";

export const IDEMPOTENCY_PREFIX = "hml-cr-";

export const RESYNC_MS = 300_000;
export const REMOTE_TIMEOUT_MS = 60_000;
export const GROUP_CONCURRENCY = 2;
export const SLOW = { base: 30_000, max: 300_000 } as const;
export const FAST = { base: 1_000, max: 300_000 } as const;
export const ISSUER_REFRESH_MIN_MS = 30_000;
export const RELIST_PAGE = 500;
export const STATUS_WRITE_ATTEMPTS = 5;

export const requestKey = (namespace: string, name: string): string =>
  `cr/${namespace}/${name}`;
export const issuerKey = (namespace: string, name: string): string =>
  `issuer/${namespace}/${name}`;
export const clusterIssuerKey = (name: string): string =>
  `clusterissuer/${name}`;
export const consumerGroup = (namespace: string, name: string): string =>
  `${namespace}/${name}`;

export interface CrCondition {
  readonly type: string;
  readonly status: string;
  readonly reason?: string;
  readonly message?: string;
  readonly lastTransitionTime?: string;
  readonly [key: string]: unknown;
}

export interface CertificateRequestStatus {
  readonly conditions?: readonly CrCondition[];
  readonly certificate?: string;
  readonly ca?: string;
  readonly failureTime?: string;
  readonly [key: string]: unknown;
}

export interface CertificateRequest {
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly request?: string;
    readonly issuerRef?: {
      readonly group?: string;
      readonly kind?: string;
      readonly name?: string;
    };
    readonly duration?: string;
    readonly usages?: readonly string[];
    readonly isCA?: boolean;
    readonly [key: string]: unknown;
  };
  readonly status?: CertificateRequestStatus;
}

export interface IssuerStatus {
  readonly observedGeneration?: number;
  readonly consumerId?: string;
  readonly environment?: string;
  readonly caId?: string;
  readonly caFingerprint?: string;
  readonly caNotAfter?: string;
  readonly issuanceGrantVersion?: string;
  readonly grantUid?: string;
  readonly conditions?: readonly IssuerCondition[];
}

export interface IssuerCondition {
  readonly type: string;
  readonly status: string;
  readonly reason?: string;
  readonly message?: string;
  readonly lastTransitionTime?: string;
}

export interface HemligIssuer {
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: string;
    readonly consumerNamespace?: string;
    readonly issuanceGrant: string;
  };
  readonly status?: IssuerStatus;
}

export interface HemligClusterIssuer {
  readonly metadata: ObjectMeta;
  readonly spec: {
    readonly consumerRef: { readonly name: string; readonly namespace: string };
    readonly issuanceGrant: string;
    readonly allowedNamespaces?: {
      readonly matchLabels: Readonly<Record<string, string>>;
    };
  };
  readonly status?: IssuerStatus;
}

export type AnyIssuer = HemligIssuer | HemligClusterIssuer;

export interface Scheduler {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  random(): number;
}

export const realScheduler: Scheduler = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => {
    const handle = setTimeout(fn, ms);
    handle.unref();
    return handle;
  },
  clearTimeout: (handle) => clearTimeout(handle as NodeJS.Timeout),
  random: () => Math.random(),
};

export interface WatchApi {
  watch(
    path: string,
    query: Record<string, unknown>,
    onEvent: (phase: string, object: unknown) => void,
    done: (error: unknown) => void,
  ): Promise<AbortController>;
}

export interface PkiConfig {
  readonly concurrency: number;
}

export const pkiConfigFromEnvironment = (
  env: Readonly<Record<string, string | undefined>> = process.env,
): PkiConfig => {
  const raw = env.HEMLIG_PKI_CONCURRENCY;
  if (raw === undefined || raw === "") return { concurrency: 4 };
  const parsed = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 64) {
    throw new Error("HEMLIG_PKI_CONCURRENCY must be an integer from 1 to 64.");
  }
  return { concurrency: parsed };
};

export const unwrap = (value: unknown): unknown =>
  typeof value === "object" && value !== null && "body" in value
    ? (value as { body: unknown }).body
    : value;

export const k8sStatus = (error: unknown): number | undefined => {
  if (typeof error !== "object" || error === null) return undefined;
  const { code, statusCode } = error as {
    code?: unknown;
    statusCode?: unknown;
  };
  if (typeof code === "number") return code;
  if (typeof statusCode === "number") return statusCode;
  return undefined;
};

export const isNotFound = (error: unknown): boolean => k8sStatus(error) === 404;
export const isConflict = (error: unknown): boolean => k8sStatus(error) === 409;
export const isGone = (error: unknown): boolean => k8sStatus(error) === 410;
export const isForbidden = (error: unknown): boolean =>
  k8sStatus(error) === 403;

/**
 * Callers pass only keys, reasons, HTTP statuses, Hemlig codes, caIds and
 * serials. Never pass an `ApiException` or `HemligError` message: both can
 * echo request or response bodies.
 */
export const log = (line: string): void => {
  process.stderr.write(`Hemlig PKI: ${line}\n`);
};

/**
 * Races a remote call against a timeout. Both promises are handled: a late
 * rejection from either side must never become an unhandled rejection.
 */
export const withTimeout = <T>(
  promise: Promise<T>,
  milliseconds: number,
  scheduler: Scheduler,
): Promise<T> => {
  let handle: unknown;
  const timeout = new Promise<never>((_, reject) => {
    handle = scheduler.setTimeout(
      () => reject(new Error("remote call timed out")),
      milliseconds,
    );
  });
  timeout.catch(() => {});
  promise.catch(() => {});
  return Promise.race([promise, timeout]).finally(() =>
    scheduler.clearTimeout(handle),
  );
};
