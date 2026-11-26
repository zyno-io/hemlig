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
