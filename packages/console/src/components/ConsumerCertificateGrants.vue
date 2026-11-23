<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, ref, watch } from "vue";
import BulkRevokeDialog from "./BulkRevokeDialog.vue";
import CertificateSummaryTable from "./CertificateSummaryTable.vue";
import ErrorNotice from "./ErrorNotice.vue";
import StateBadge from "./StateBadge.vue";
import { fetchAllPages, PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type { PkiCertificateSummary, PkiIssuanceGrant } from "../api/pki-schemas";
import { useCursorPages } from "../composables/useCursorPages";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; consumerId: string }>();
const store = useAppStore();

const includeDeleted = ref(false);
const includeExpired = ref(false);
const grantFilter = ref("");

const grants = useQuery({
  ...PKI_QUERY_OPTIONS,
  queryKey: computed(() => pkiKeys.consumerGrants(props.consumerId, includeDeleted.value)),
  queryFn: () =>
    fetchAllPages(async (cursor) => {
      const page = await store.requireApi().listAdminIssuanceGrants(props.consumerId, {
        includeDeleted: includeDeleted.value,
        cursor,
      });
      return { items: page.grants, nextCursor: page.nextCursor };
    }),
});

const certificates = useCursorPages<PkiCertificateSummary>(async (cursor) => {
  const page = await store.requireApi().listConsumerPkiCertificates(props.consumerId, {
    ...(grantFilter.value === "" ? {} : { issuanceGrant: grantFilter.value }),
    includeExpired: includeExpired.value,
    cursor,
  });
  return { items: page.certificates, nextCursor: page.nextCursor };
});

const reloadCertificates = (): void => {
  certificates.reset();
  void certificates.loadMore();
};
// Filters are explicit operator choices, so refetching on change is one read
// per choice, not a background poll.
watch([grantFilter, includeExpired, () => props.consumerId], reloadCertificates, {
  immediate: true,
});

const revoking = ref(false);
const preset = ref<{ issuanceGrant: string; issuanceGrantUid?: string } | undefined>();

const openRevoke = (grant?: PkiIssuanceGrant): void => {
  preset.value =
    grant === undefined
      ? undefined
      : { issuanceGrant: grant.name, issuanceGrantUid: grant.uid };
  revoking.value = true;
};

const onRevokeDone = (): void => {
  revoking.value = false;
  reloadCertificates();
};
</script>

<template>
  <div class="space-y-4">
    <section class="card">
      <div class="card-header">
        <div>
          <h2 class="section-title">Issuance grants</h2>
          <p class="meta">What this consumer may request from each CA.</p>
        </div>
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-1 text-xs">
            <input v-model="includeDeleted" type="checkbox" data-testid="include-deleted" />
            Show deleted
          </label>
          <RouterLink
            class="btn btn-primary"
            :to="{ name: 'consumer-pki-grant-new', params: { env, consumerId } }"
          >New grant</RouterLink>
        </div>
      </div>
      <div v-if="grants.error.value" class="card-body">
        <ErrorNotice :error="grants.error.value" />
      </div>
      <div v-else-if="(grants.data.value ?? []).length > 0" class="overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr><th>Name</th><th>CA</th><th>Status</th><th>Expires</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="grant in grants.data.value" :key="`${grant.name}:${grant.uid}`">
              <td>
                <RouterLink
                  v-if="grant.status !== 'DELETED'"
                  class="link mono"
                  :to="{
                    name: 'consumer-pki-grant',
                    params: { env, consumerId, name: grant.name },
                  }"
                >{{ grant.name }}</RouterLink>
                <span v-else class="mono">{{ grant.name }}</span>
                <div v-if="grant.displayName" class="meta">{{ grant.displayName }}</div>
              </td>
              <td class="mono text-xs">{{ grant.caId }}</td>
              <td>
                <StateBadge :state="grant.status" />
                <span v-if="grant.expired" class="tag tag-warning ml-1">expired</span>
              </td>
              <td class="mono text-xs">{{ grant.expiresAt ?? "never" }}</td>
              <td class="text-right">
                <button
                  class="btn btn-sm btn-danger"
                  :aria-label="`Revoke certificates for ${grant.name}`"
                  @click="openRevoke(grant)"
                >
                  Revoke certificates…
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else-if="grants.data.value" class="card-body text-center text-[13px] text-ink-3">
        This consumer has no issuance grants.
      </p>
    </section>

    <section class="card">
      <div class="card-header">
        <div>
          <h2 class="section-title">Certificates</h2>
          <p class="meta">Issued to this consumer through its grants.</p>
        </div>
        <button class="btn btn-danger" data-testid="bulk-open" @click="openRevoke()">
          Revoke certificates…
        </button>
      </div>
      <div class="card-body flex flex-wrap items-center gap-3 border-b border-line">
        <label class="flex items-center gap-2 text-xs">
          Grant
          <select v-model="grantFilter" class="input w-auto" data-testid="cert-grant-filter">
            <option value="">All</option>
            <option v-for="grant in grants.data.value ?? []" :key="`${grant.name}:${grant.uid}`" :value="grant.name">
              {{ grant.name }}
            </option>
          </select>
        </label>
        <label class="flex items-center gap-1 text-xs">
          <input v-model="includeExpired" type="checkbox" data-testid="include-expired" />
          Include expired
        </label>
      </div>
      <div v-if="certificates.error.value" class="card-body">
        <ErrorNotice :error="certificates.error.value" />
      </div>
      <div v-else-if="certificates.items.value.length > 0" class="overflow-x-auto">
        <CertificateSummaryTable :env="env" :certificates="certificates.items.value" show-ca />
      </div>
      <p
        v-else-if="certificates.exhausted.value && !certificates.loading.value"
        class="card-body text-center text-[13px] text-ink-3"
      >
        No certificates match.
      </p>
      <div v-if="!certificates.exhausted.value && certificates.items.value.length > 0" class="card-body border-t border-line">
        <button class="btn" :disabled="certificates.loading.value" @click="certificates.loadMore()">
          {{ certificates.loading.value ? "Loading…" : "Load more" }}
        </button>
      </div>
    </section>

    <BulkRevokeDialog
      v-if="revoking"
      :consumer-id="consumerId"
      :grants="grants.data.value ?? []"
      :preset="preset"
      @done="onRevokeDone"
      @close="revoking = false"
    />
  </div>
</template>
