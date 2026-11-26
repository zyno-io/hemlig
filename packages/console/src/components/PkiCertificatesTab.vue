<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, nextTick, ref } from "vue";
import { ApiError } from "../api/errors";
import {
  certificateSans,
  daysUntil,
  effectiveCertificateStatus,
  isoDate,
  subjectCommonName,
} from "../api/pki-format";
import {
  PKI_QUERY_OPTIONS,
  pkiKeys,
  type EnvCertificateSlice as CaSlice,
} from "../api/pki-query";
import type { PkiCaSummary, PkiCertificateSummary } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import ErrorNotice from "./ErrorNotice.vue";
import StateBadge from "./StateBadge.vue";

type CertFilter = "active" | "expired" | "revoked" | "all";

const props = defineProps<{ env: string; cas: readonly PkiCaSummary[] }>();
const store = useAppStore();
const queryClient = useQueryClient();

const FILTERS: readonly { id: CertFilter; label: string; status?: string; empty: string }[] = [
  { id: "active", label: "Active", status: "ISSUED", empty: "No active certificates." },
  { id: "expired", label: "Expired", status: "EXPIRED", empty: "No expired certificates." },
  { id: "revoked", label: "Revoked", status: "REVOKED", empty: "No revoked certificates." },
  { id: "all", label: "All", empty: "No certificates in this environment." },
];
const filter = ref<CertFilter>("active");
const search = ref("");
const loadingKeys = ref<ReadonlySet<string>>(new Set());
const MAX_SANS_SHOWN = 1;

const activeFilter = computed(() => FILTERS.find((f) => f.id === filter.value) ?? FILTERS[0]!);

// A CA that never issued (FAILED, PENDING_CERTIFICATE) has nothing to list, and
// a revoked CA's certificates are not active, so skip those reads (all audited).
const listedCas = computed(() =>
  props.cas.filter(
    (ca) =>
      ca.status !== "FAILED" &&
      ca.status !== "PENDING_CERTIFICATE" &&
      !(filter.value === "active" && ca.status === "REVOKED"),
  ),
);
const caName = (caId: string): string => {
  const ca = props.cas.find((candidate) => candidate.caId === caId);
  return ca === undefined ? caId : (ca.displayName ?? ca.name);
};

/** A cursor the server no longer accepts (they last 15 minutes). */
const isCursorExpired = (error: unknown): boolean =>
  error instanceof ApiError && (error.status === 400 || error.status === 410 || error.code === "bad_request");

const fetchSlice = async (
  caId: string,
  status: string | undefined,
  previous: CaSlice | undefined,
): Promise<CaSlice> => {
  try {
    const page = await store.requireApi().listPkiCertificates(caId, {
      ...(status === undefined ? {} : { status }),
      ...(previous?.nextCursor === undefined ? {} : { cursor: previous.nextCursor }),
    });
    return {
      caId,
      certificates: [...(previous?.certificates ?? []), ...page.certificates],
      nextCursor: page.nextCursor,
      error: undefined,
      outdated: false,
    };
  } catch (error) {
    if (previous !== undefined && isCursorExpired(error)) {
      return { ...previous, nextCursor: undefined, error: undefined, outdated: true };
    }
    return {
      caId,
      certificates: previous?.certificates ?? [],
      nextCursor: previous?.nextCursor,
      error,
      outdated: false,
    };
  }
};

// Mounted only once the tab is opened, so nothing here reads before then. Never
// refetches by itself (PKI_QUERY_OPTIONS, and no refetch on remount unless a
// revoke marked it stale): reads are audited, so a re-read is the Refresh
// button or a filter change. The fetch reads its inputs from the key.
const queryKey = computed(
  () =>
    [
      ...pkiKeys.envCertificates(props.env, filter.value),
      listedCas.value.map((ca) => ca.caId),
    ] as const,
);
const signature = computed(() => JSON.stringify(queryKey.value));
const slices = useQuery({
  queryKey,
  queryFn: ({ queryKey: key }) => {
    const [, , , filterId, caIds] = key;
    const status = FILTERS.find((f) => f.id === filterId)?.status;
    return Promise.all(caIds.map((caId) => fetchSlice(caId, status, undefined)));
  },
  ...PKI_QUERY_OPTIONS,
  refetchOnMount: (query) => query.state.isInvalidated,
});

const failedSlices = computed(() => (slices.data.value ?? []).filter((s) => s.error !== undefined));
const outdatedSlices = computed(() => (slices.data.value ?? []).filter((s) => s.outdated));
const hasMore = computed(() => (slices.data.value ?? []).some((s) => s.nextCursor !== undefined));
const loadingMore = computed(() => loadingKeys.value.has(signature.value));

const loadMore = async (): Promise<void> => {
  const key = queryKey.value;
  const id = signature.value;
  // Raw cache value, to compare by identity when writing back.
  const current = queryClient.getQueryData<CaSlice[]>(key);
  if (current === undefined || loadingKeys.value.has(id)) {
    return;
  }
  const status = activeFilter.value.status;
  loadingKeys.value = new Set(loadingKeys.value).add(id);
  try {
    // Only CAs with a cursor are read again; the rest are left as they are.
    const next = await Promise.all(
      current.map((slice) =>
        slice.nextCursor === undefined ? slice : fetchSlice(slice.caId, status, slice),
      ),
    );
    // A Refresh that landed meanwhile replaced the value: drop these pages.
    queryClient.setQueryData<CaSlice[]>(key, (old) => (old === current ? next : old));
  } finally {
    const rest = new Set(loadingKeys.value);
    rest.delete(id);
    loadingKeys.value = rest;
  }
};

/**
 * Re-reads after the CA list was refetched. When the CA set changed the new key
 * fetches by itself, so only a refetch of an unchanged key is needed here.
 */
const refresh = async (signatureBefore?: string): Promise<void> => {
  await nextTick();
  if (signatureBefore !== undefined && signatureBefore !== signature.value) {
    return;
  }
  await slices.refetch();
};
defineExpose({ refresh, signature });

const time = (iso: string): number => new Date(iso).getTime();

// The server lists each CA in ascending notAfter order, so order by expiry
// everywhere: Load more then only appends. Rows past the earliest point any
// unfinished CA has reached are held back, because that CA's next page can
// still contain earlier ones.
const cutoff = computed(() => {
  let bound = Infinity;
  for (const slice of slices.data.value ?? []) {
    if ((slice.nextCursor !== undefined || slice.outdated) && slice.certificates.length > 0) {
      bound = Math.min(bound, Math.max(...slice.certificates.map((c) => time(c.notAfter))));
    }
  }
  return bound;
});

const visible = computed(() =>
  (slices.data.value ?? [])
    .flatMap((slice) => slice.certificates)
    .filter((certificate) => time(certificate.notAfter) <= cutoff.value)
    .sort((a, b) => time(a.notAfter) - time(b.notAfter)),
);
const rows = computed(() => {
  const needle = search.value.trim().toLowerCase();
  return needle === ""
    ? visible.value
    : visible.value.filter((certificate) =>
        [certificate.subject, certificate.serial, ...certificateSans(certificate)].some((text) =>
          text.toLowerCase().includes(needle),
        ),
      );
});
const totalLoaded = computed(() =>
  (slices.data.value ?? []).reduce((sum, slice) => sum + slice.certificates.length, 0),
);
const heldBack = computed(() => totalLoaded.value - visible.value.length);

const linkText = (certificate: PkiCertificateSummary): string =>
  subjectCommonName(certificate.subject) || certificateSans(certificate)[0] || certificate.serial;

const expiresSoon = (certificate: PkiCertificateSummary): boolean =>
  effectiveCertificateStatus(certificate) === "ISSUED" && daysUntil(certificate.notAfter) < 30;
</script>

<template>
  <section class="card" data-testid="certificates-tab">
    <div class="card-header">
      <h2 class="section-title">Certificates</h2>
      <div class="flex flex-wrap items-center gap-2">
        <div class="flex gap-1" role="group" aria-label="Certificate status">
          <button
            v-for="option in FILTERS"
            :key="option.id"
            type="button"
            class="btn btn-sm"
            :class="filter === option.id ? 'bg-surface-3! text-ink!' : ''"
            :aria-pressed="filter === option.id"
            :data-testid="`cert-filter-${option.id}`"
            @click="filter = option.id"
          >{{ option.label }}</button>
        </div>
        <input
          v-model="search"
          type="search"
          class="input"
          placeholder="Filter loaded: name, SAN, serial"
          aria-label="Filter loaded certificates"
        />
      </div>
    </div>

    <ErrorNotice
      v-for="slice in failedSlices"
      :key="slice.caId"
      class="m-4"
      :error="slice.error"
      :context="`the certificates of ${caName(slice.caId)}`"
    />

    <p
      v-for="slice in outdatedSlices"
      :key="slice.caId"
      class="card-body meta"
      data-testid="cert-outdated"
    >
      The list for {{ caName(slice.caId) }} is out of date. Refresh to continue.
    </p>

    <p v-if="slices.isPending.value || slices.isFetching.value && !slices.data.value" class="card-body meta">
      Loading…
    </p>
    <ErrorNotice v-else-if="slices.error.value" class="m-4" :error="slices.error.value" context="certificates" />
    <p v-else-if="listedCas.length === 0" class="card-body meta">
      No certificate authorities in this environment yet.
    </p>
    <p v-else-if="rows.length === 0 && totalLoaded === 0 && failedSlices.length === 0" class="card-body meta">
      {{ activeFilter.empty }}
    </p>
    <p v-else-if="rows.length === 0" class="card-body meta">
      No loaded certificates match<template v-if="search.trim() !== ''"> "{{ search.trim() }}"</template>.
    </p>
    <div v-else class="overflow-x-auto">
      <table class="data-table">
        <thead>
          <tr>
            <th>Certificate</th>
            <th>CA</th>
            <th>Status</th>
            <th>Serial</th>
            <th>Expires</th>
            <th>Requester</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="certificate in rows" :key="`${certificate.caId}/${certificate.serial}`">
            <td class="align-middle text-[13px]">
              <RouterLink
                class="link font-medium"
                :to="{
                  name: 'pki-certificate',
                  params: { env, caId: certificate.caId, serial: certificate.serial },
                }"
              >{{ linkText(certificate) }}</RouterLink>
              <p v-if="certificateSans(certificate).length > 0" class="meta mono">
                {{ certificateSans(certificate)[0] }}
                <span v-if="certificateSans(certificate).length > MAX_SANS_SHOWN">
                  +{{ certificateSans(certificate).length - MAX_SANS_SHOWN }}
                </span>
              </p>
            </td>
            <td class="align-middle text-[13px]">
              <RouterLink
                class="link"
                :to="{ name: 'pki-ca', params: { env, caId: certificate.caId } }"
              >{{ caName(certificate.caId) }}</RouterLink>
            </td>
            <td class="align-middle">
              <StateBadge :state="effectiveCertificateStatus(certificate)" />
            </td>
            <td class="align-middle text-[13px]">
              <span class="mono inline-block max-w-32 truncate align-middle" :title="certificate.serial">{{
                certificate.serial
              }}</span>
            </td>
            <td class="align-middle text-[13px] whitespace-nowrap">
              <span :title="certificate.notAfter">{{ isoDate(certificate.notAfter) }}</span>
              <span v-if="expiresSoon(certificate)" class="tag tag-warning ml-1">&lt;30 days</span>
            </td>
            <td class="align-middle text-[13px]">
              <span v-if="certificate.requester.issuanceGrant?.name" class="mono">{{
                certificate.requester.issuanceGrant.name
              }}</span>
              <span v-else class="meta">{{
                certificate.requester.type === "human" ? "administrator" : "consumer"
              }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="hasMore" class="card-body flex flex-wrap items-center gap-3">
      <button class="btn" data-testid="cert-load-more" :disabled="loadingMore" @click="loadMore">
        {{ loadingMore ? "Loading…" : "Load more" }}
      </button>
      <span class="meta" data-testid="cert-partial">
        Partial list, ordered by expiry: {{ visible.length }} shown<template v-if="heldBack > 0">
        ({{ heldBack }} more loaded, held back to keep the order)</template>, and some CAs have
        more. Filtering covers loaded rows only.
      </span>
    </div>
  </section>
</template>
