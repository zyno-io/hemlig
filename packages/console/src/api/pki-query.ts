import type { QueryClient } from "@tanstack/vue-query";
import type { PkiCertificateSummary } from "./pki-schemas";

/**
 * Every PKI `GET` and `evaluate` writes an Object Lock read event, so these
 * queries must not refetch on focus or reconnect the way the rest of the
 * console does (see `main.ts`). Spread `PKI_QUERY_OPTIONS` into every PKI
 * `useQuery`.
 */
export const PKI_QUERY_OPTIONS = {
  staleTime: 60_000,
  refetchOnWindowFocus: false,
  refetchOnReconnect: false,
} as const;

export interface PkiCertificateFilters {
  readonly status?: string;
  readonly expiringBefore?: string;
  readonly issuanceGrant?: string;
  readonly includeExpired?: boolean;
}

export const pkiKeys = {
  cas: (env: string) => ["pki", "cas", env] as const,
  ca: (caId: string) => ["pki", "ca", caId] as const,
  externalCas: () => ["pki", "external-cas"] as const,
  caGrants: (caId: string) => ["pki", "ca-grants", caId] as const,
  consumerGrants: (consumerId: string, includeDeleted: boolean) =>
    ["pki", "consumer-grants", consumerId, includeDeleted] as const,
  grant: (consumerId: string, name: string) =>
    ["pki", "grant", consumerId, name] as const,
  envCertificates: (env: string, filter: string) =>
    ["pki", "env-certificates", env, filter] as const,
  caCertificates: (caId: string, filters: PkiCertificateFilters = {}) =>
    ["pki", "ca-certificates", caId, filters] as const,
  certificate: (caId: string, serial: string) =>
    ["pki", "certificate", caId, serial] as const,
  consumerCertificates: (consumerId: string, filters: PkiCertificateFilters = {}) =>
    ["pki", "consumer-certificates", consumerId, filters] as const,
};

/**
 * Chases cursors for the bounded lists (at most 50 CAs per environment, and
 * the external CA list). Stops at `maxPages` rather than looping forever.
 */
export const fetchAllPages = async <TItem>(
  fetchPage: (
    cursor: string | undefined,
  ) => Promise<{ readonly items: readonly TItem[]; readonly nextCursor?: string }>,
  maxPages = 5,
): Promise<TItem[]> => {
  const all: TItem[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const result = await fetchPage(cursor);
    all.push(...result.items);
    if (result.nextCursor === undefined) {
      break;
    }
    cursor = result.nextCursor;
  }
  return all;
};

/** One CA's slice of the environment-wide certificate list. */
export interface EnvCertificateSlice {
  readonly caId: string;
  readonly certificates: readonly PkiCertificateSummary[];
  readonly nextCursor: string | undefined;
  /** The last list call for this CA failed; earlier pages (if any) are kept. */
  readonly error: unknown;
  /** The CA's cursor expired; later pages can only come from a Refresh. */
  readonly outdated: boolean;
}

const ENV_CERTS = ["pki", "env-certificates"] as const;
/** The filter id inside an `envCertificates` query key. */
const envFilterOf = (key: readonly unknown[]): unknown => key[3];

/**
 * A revoke result already says what the certificate is now, so patch the
 * cached environment-wide lists instead of reading again (reads are audited).
 * Active and Expired lists drop it, All shows its new state. The Revoked list
 * cannot be patched (the row is not in it), so it is marked stale and reloads
 * the next time the tab mounts.
 */
export const applyCertificateRevoked = (
  queryClient: QueryClient,
  certificate: PkiCertificateSummary,
): void => {
  const sameCert = (c: PkiCertificateSummary): boolean =>
    c.caId === certificate.caId && c.serial === certificate.serial;
  const patch = (filters: readonly string[], drop: boolean): void => {
    queryClient.setQueriesData<readonly EnvCertificateSlice[]>(
      {
        queryKey: ENV_CERTS,
        predicate: (query) => filters.includes(String(envFilterOf(query.queryKey))),
      },
      (old) =>
        old?.map((slice) =>
          slice.caId !== certificate.caId || !slice.certificates.some(sameCert)
            ? slice
            : {
                ...slice,
                certificates: slice.certificates.flatMap((c) =>
                  !sameCert(c) ? [c] : drop ? [] : [certificate],
                ),
              },
        ),
    );
  };
  patch(["active", "expired"], certificate.status !== "ISSUED");
  patch(["all"], false);
  // Patching marks a query fresh, so mark the Revoked list stale afterwards.
  void queryClient.invalidateQueries({
    queryKey: ENV_CERTS,
    predicate: (query) => envFilterOf(query.queryKey) === "revoked",
    refetchType: "none",
  });
};

/** For a change with no row data (a bulk revoke): reload on the next mount. */
export const markEnvCertificatesStale = (queryClient: QueryClient): void => {
  void queryClient.invalidateQueries({ queryKey: ENV_CERTS, refetchType: "none" });
};
