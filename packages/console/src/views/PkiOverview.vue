<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, ref } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import RootCrlUploadDialog from "../components/RootCrlUploadDialog.vue";
import StateBadge from "../components/StateBadge.vue";
import { CA_KIND_SHORT_LABEL, daysUntil, isoDate, keyAlgorithmLabel } from "../api/pki-format";
import { fetchAllPages, PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type { PkiCaSummary, PkiExternalCaSummary } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string }>();
const store = useAppStore();
const queryClient = useQueryClient();

// Every PKI read is audited: these two list queries are the whole page. The
// overview never reads a CA detail (see PKI_QUERY_OPTIONS).
const cas = useQuery({
  queryKey: computed(() => pkiKeys.cas(props.env)),
  queryFn: () =>
    fetchAllPages<PkiCaSummary>(async (cursor) => {
      const page = await store
        .requireApi()
        .listPkiCas({ environment: props.env, cursor });
      return { items: page.cas, nextCursor: page.nextCursor };
    }),
  ...PKI_QUERY_OPTIONS,
});
const externalCas = useQuery({
  queryKey: pkiKeys.externalCas(),
  queryFn: () =>
    fetchAllPages<PkiExternalCaSummary>(async (cursor) => {
      const page = await store.requireApi().listExternalCas({ cursor });
      return { items: page.externalCas, nextCursor: page.nextCursor };
    }),
  ...PKI_QUERY_OPTIONS,
});

const hideFailed = ref(true);
const uploadTarget = ref<PkiExternalCaSummary | undefined>();

const rows = computed(() =>
  (cas.data.value ?? []).filter((ca) => !hideFailed.value || ca.status !== "FAILED"),
);
const failedCount = computed(
  () => (cas.data.value ?? []).filter((ca) => ca.status === "FAILED").length,
);
const roots = computed(() =>
  (externalCas.data.value ?? []).filter((ext) => ext.environments.includes(props.env)),
);

const rootFor = (ca: PkiCaSummary): PkiExternalCaSummary | undefined =>
  (externalCas.data.value ?? []).find((ext) => ext.dependents.includes(ca.caId));

const expiresSoon = (ca: PkiCaSummary): boolean =>
  ca.notAfter !== undefined && ca.status !== "REVOKED" && daysUntil(ca.notAfter) < 30;

const refresh = async (): Promise<void> => {
  await Promise.all([cas.refetch(), externalCas.refetch()]);
};

const onUploaded = async (): Promise<void> => {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: pkiKeys.externalCas() }),
    queryClient.invalidateQueries({ queryKey: pkiKeys.cas(props.env) }),
  ]);
};
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">PKI in {{ env }}</h1>
        <p class="page-subtitle">
          Certificate authorities and the offline roots they chain to. Reads here are
          audited, so this page refreshes only when you ask.
        </p>
      </div>
      <div class="page-actions">
        <button class="btn" @click="refresh">Refresh</button>
        <RouterLink class="btn btn-primary" :to="{ name: 'pki-ca-new', params: { env } }">
          New CA
        </RouterLink>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="cas.error.value" :error="cas.error.value" context="the CA list" />

      <section class="card">
        <div class="card-header">
          <h2 class="section-title">Certificate authorities</h2>
          <label v-if="failedCount > 0" class="flex items-center gap-2 text-[13px]">
            <input v-model="hideFailed" type="checkbox" data-testid="hide-failed" />
            Hide failed ({{ failedCount }})
          </label>
        </div>
        <p v-if="cas.isPending.value" class="card-body meta">Loading…</p>
        <p v-else-if="rows.length === 0 && !cas.error.value" class="card-body meta">
          No certificate authorities in this environment yet.
        </p>
        <div v-else-if="rows.length > 0" class="overflow-x-auto">
          <table class="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Key</th>
                <th>Expires</th>
                <th>Root CRL</th>
                <th><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ca in rows" :key="ca.caId">
                <td class="align-middle">
                  <RouterLink
                    class="link font-medium"
                    :to="{ name: 'pki-ca', params: { env, caId: ca.caId } }"
                  >{{ ca.displayName ?? ca.name }}</RouterLink>
                  <p v-if="ca.displayName" class="meta mono">{{ ca.name }}</p>
                </td>
                <td class="align-middle text-[13px] whitespace-nowrap">
                  {{ CA_KIND_SHORT_LABEL[ca.kind] ?? ca.kind }}
                </td>
                <td class="align-middle"><StateBadge :state="ca.status" /></td>
                <td class="align-middle text-[13px] whitespace-nowrap">
                  {{ keyAlgorithmLabel(ca.keyAlgorithm) }}
                  <!-- The key's own state only matters when it differs from a working key. -->
                  <StateBadge v-if="ca.keyState !== 'ACTIVE'" class="ml-1" :state="ca.keyState" />
                </td>
                <td class="align-middle text-[13px] whitespace-nowrap">
                  <template v-if="ca.notAfter">
                    <span :title="ca.notAfter">{{ isoDate(ca.notAfter) }}</span>
                    <span v-if="expiresSoon(ca)" class="tag tag-warning ml-1">&lt;30 days</span>
                  </template>
                  <span v-else class="meta">not issued</span>
                </td>
                <td class="align-middle text-[13px] whitespace-nowrap">
                  <template v-if="ca.kind === 'EXTERNAL_INTERMEDIATE'">
                    <template v-if="rootFor(ca)">
                      <StateBadge :state="rootFor(ca)!.crlState" />
                      <span
                        v-if="rootFor(ca)!.crl?.nextUpdate"
                        class="meta ml-2"
                        :title="rootFor(ca)!.crl?.nextUpdate"
                      >next {{ isoDate(rootFor(ca)!.crl?.nextUpdate ?? "") }}</span>
                    </template>
                    <span v-else class="meta">none yet</span>
                  </template>
                  <span v-else class="meta">generated, see detail</span>
                </td>
                <td class="align-middle text-right">
                  <RouterLink
                    class="btn btn-sm"
                    :to="{
                      name: 'pki-ca-new',
                      params: { env },
                      query: { rolloverFrom: ca.caId },
                    }"
                  >Roll over</RouterLink>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card" data-testid="offline-roots">
        <div class="card-header">
          <h2 class="section-title">Offline roots</h2>
        </div>
        <ErrorNotice
          v-if="externalCas.error.value"
          class="m-4"
          :error="externalCas.error.value"
          context="the offline roots"
        />
        <p v-else-if="externalCas.isPending.value" class="card-body meta">Loading…</p>
        <p v-else-if="roots.length === 0" class="card-body meta">
          No offline roots are in use in this environment.
        </p>
        <div v-else class="overflow-x-auto">
          <table class="data-table">
            <thead>
              <tr>
                <th>Root</th>
                <th>CRL</th>
                <th>Next update</th>
                <th>CAs</th>
                <th><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ext in roots" :key="ext.extId">
                <td class="align-middle text-[13px] break-all">{{ ext.subjectDn }}</td>
                <td class="align-middle"><StateBadge :state="ext.crlState" /></td>
                <td class="align-middle text-[13px] whitespace-nowrap">
                  <span v-if="ext.crl?.nextUpdate" :title="ext.crl.nextUpdate">{{
                    isoDate(ext.crl.nextUpdate)
                  }}</span>
                  <span v-else class="meta">-</span>
                </td>
                <td class="align-middle text-[13px]">{{ ext.dependents.length }}</td>
                <td class="align-middle text-right">
                  <button
                    class="btn btn-sm"
                    :data-testid="`upload-crl-${ext.extId}`"
                    @click="uploadTarget = ext"
                  >
                    Upload CRL
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <RootCrlUploadDialog
      v-if="uploadTarget"
      :ext-id="uploadTarget.extId"
      :subject-dn="uploadTarget.subjectDn"
      :current-number-hex="uploadTarget.crl?.numberHex"
      @uploaded="onUploaded"
      @close="uploadTarget = undefined"
    />
  </div>
</template>
