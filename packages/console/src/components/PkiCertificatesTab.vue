<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, ref } from "vue";
import {
  certificateSans,
  daysUntil,
  effectiveCertificateStatus,
  isoDate,
  subjectCommonName,
} from "../api/pki-format";
import { PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
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
const loadingMore = ref(false);
const MAX_SANS_SHOWN = 1;

const activeFilter = computed(() => FILTERS.find((f) => f.id === filter.value) ?? FILTERS[0]!);

/** One CA's slice of the merged list. */
interface CaSlice {
  readonly caId: string;
  readonly certificates: readonly PkiCertificateSummary[];
  readonly nextCursor: string | undefined;
  /** The last list call for this CA failed; the earlier pages (if any) are kept. */
  readonly error: unknown;
}

// A failed FAILED-status CA never issued anything; skip it rather than audit a pointless read.
const listedCas = computed(() => props.cas.filter((ca) => ca.status !== "FAILED"));
const caName = (caId: string): string => {
  const ca = props.cas.find((candidate) => candidate.caId === caId);
  return ca === undefined ? caId : (ca.displayName ?? ca.name);
};

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
    };
  } catch (error) {
    return {
      caId,
      certificates: previous?.certificates ?? [],
      nextCursor: previous?.nextCursor,
      error,
    };
  }
};

// Mounted only once the tab is opened, so nothing here reads before then. Never
// refetches by itself (PKI_QUERY_OPTIONS, and no refetch on remount): reads are
// audited, so a re-read is the Refresh button or a filter change.
const queryKey = computed(
  () =>
    [
      ...pkiKeys.envCertificates(props.env, activeFilter.value.id),
      listedCas.value.map((ca) => ca.caId),
    ] as const,
);
const slices = useQuery({
  queryKey,
  queryFn: () =>
    Promise.all(
      listedCas.value.map((ca) => fetchSlice(ca.caId, activeFilter.value.status, undefined)),
    ),
  ...PKI_QUERY_OPTIONS,
  refetchOnMount: false,
});

const failedSlices = computed(() => (slices.data.value ?? []).filter((s) => s.error !== undefined));
const hasMore = computed(() => (slices.data.value ?? []).some((s) => s.nextCursor !== undefined));

const loadMore = async (): Promise<void> => {
  const current = slices.data.value;
  if (current === undefined || loadingMore.value) {
    return;
  }
  const key = queryKey.value;
  const status = activeFilter.value.status;
  loadingMore.value = true;
  try {
    // Only CAs with a cursor are read again; the rest are left as they are.
    const next = await Promise.all(
      current.map((slice) =>
        slice.nextCursor === undefined ? slice : fetchSlice(slice.caId, status, slice),
      ),
    );
    queryClient.setQueryData(key, next);
  } finally {
    loadingMore.value = false;
  }
};

const refresh = async (): Promise<void> => {
  await slices.refetch();
};
defineExpose({ refresh });

const sortKey = (certificate: PkiCertificateSummary): number =>
  new Date(activeFilter.value.id === "active" ? certificate.notAfter : certificate.issuedAt).getTime();

const rows = computed(() => {
  const needle = search.value.trim().toLowerCase();
  const merged = (slices.data.value ?? []).flatMap((slice) => slice.certificates);
  const matching =
    needle === ""
      ? merged
      : merged.filter((certificate) =>
          [certificate.subject, certificate.serial, ...certificateSans(certificate)].some((text) =>
            text.toLowerCase().includes(needle),
          ),
        );
  // Active: soonest expiry first. Otherwise newest first.
  const direction = activeFilter.value.id === "active" ? 1 : -1;
  return [...matching].sort((a, b) => direction * (sortKey(a) - sortKey(b)));
});
const totalLoaded = computed(() =>
  (slices.data.value ?? []).reduce((sum, slice) => sum + slice.certificates.length, 0),
);

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
              >{{ subjectCommonName(certificate.subject) }}</RouterLink>
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
        Partial list: {{ totalLoaded }} loaded so far, and some CAs have more. Filtering
        covers loaded rows only.
      </span>
    </div>
  </section>
</template>
