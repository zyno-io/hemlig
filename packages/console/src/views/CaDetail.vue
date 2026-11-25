<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import CaActivationPanel from "../components/CaActivationPanel.vue";
import CaRetireDialog from "../components/CaRetireDialog.vue";
import CertificateSummaryTable from "../components/CertificateSummaryTable.vue";
import CopyField from "../components/CopyField.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import RootCrlUploadDialog from "../components/RootCrlUploadDialog.vue";
import StateBadge from "../components/StateBadge.vue";
import TypedConfirmDialog from "../components/TypedConfirmDialog.vue";
import { formatDuration, localInputToIso } from "../api/pki-format";
import { PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type {
  PkiCaDetail,
  PkiCertificateSummary,
  PkiCrlPublishResponse,
  PkiIssuanceGrant,
} from "../api/pki-schemas";
import { useCursorPages } from "../composables/useCursorPages";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

type CaTab = "overview" | "certificates" | "grants";

const props = defineProps<{ env: string; caId: string; tab?: CaTab | undefined }>();
const store = useAppStore();
const router = useRouter();
const queryClient = useQueryClient();

const TABS: readonly { id: CaTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "certificates", label: "Certificates" },
  { id: "grants", label: "Certificate grants" },
];
const CERT_STATUSES = ["ISSUED", "REVOKED", "EXPIRED"] as const;

// PKI reads are audited: no refetch on focus, and a mutation writes its result
// into the cache rather than reading the CA again.
const ca = useQuery({
  queryKey: computed(() => pkiKeys.ca(props.caId)),
  queryFn: () => store.requireApi().getPkiCa(props.caId),
  ...PKI_QUERY_OPTIONS,
});
const detail = computed(() => ca.data.value);

const cacheCa = (next: PkiCaDetail): void => {
  queryClient.setQueryData(pkiKeys.ca(props.caId), next);
  void queryClient.invalidateQueries({ queryKey: pkiKeys.cas(props.env), refetchType: "none" });
};

// ---------------------------------------------------------------- Tabs

const activeTab = ref<CaTab>(props.tab ?? "overview");
watch(
  () => props.tab,
  (tab) => {
    activeTab.value = tab ?? "overview";
  },
);
const selectTab = (tab: CaTab): void => {
  activeTab.value = tab;
  void router.replace({ query: { tab } });
};

const certFilter = reactive({ status: "", expiringBefore: "" });
const certificates = useCursorPages<PkiCertificateSummary>(async (cursor) => {
  const expiringBefore = localInputToIso(certFilter.expiringBefore);
  const page = await store.requireApi().listPkiCertificates(props.caId, {
    ...(certFilter.status === "" ? {} : { status: certFilter.status }),
    ...(expiringBefore === undefined ? {} : { expiringBefore }),
    ...(cursor === undefined ? {} : { cursor }),
  });
  return { items: page.certificates, nextCursor: page.nextCursor };
});
const grants = useCursorPages<PkiIssuanceGrant>(async (cursor) => {
  const page = await store
    .requireApi()
    .listCaIssuanceGrants(props.caId, cursor === undefined ? {} : { cursor });
  return { items: page.grants, nextCursor: page.nextCursor };
});
const loadedTabs = new Set<CaTab>();
watch(
  activeTab,
  (tab) => {
    if (loadedTabs.has(tab)) {
      return;
    }
    loadedTabs.add(tab);
    if (tab === "certificates") {
      void certificates.loadMore();
    } else if (tab === "grants") {
      void grants.loadMore();
    }
  },
  { immediate: true },
);
const applyCertFilter = (): void => {
  certificates.reset();
  void certificates.loadMore();
};

// ------------------------------------------------------------- Actions

const canPublishCrl = computed(
  () =>
    detail.value !== undefined &&
    detail.value.key.state === "ACTIVE" &&
    (detail.value.status === "ACTIVE" ||
      (detail.value.status === "RETIRED" && !detail.value.drained)),
);
const canRetire = computed(() => detail.value?.status === "ACTIVE");
const canAbandon = computed(() => detail.value?.status === "PENDING_CERTIFICATE");
const canDestroyKey = computed(() => detail.value?.key.state === "DISABLED");
const awaitingDrain = computed(
  () =>
    detail.value !== undefined &&
    detail.value.key.state === "ACTIVE" &&
    detail.value.drainAt !== undefined &&
    detail.value.status !== "ACTIVE" &&
    detail.value.status !== "PENDING_CERTIFICATE",
);

const showRetire = ref(false);
const showAbandon = ref(false);
const showDestroy = ref(false);
const showUpload = ref(false);

const publish = useGuardedMutation<undefined, PkiCrlPublishResponse>({
  family: "pki",
  mutate: (_input, key) => store.requireApi().publishPkiCrl(props.caId, key),
});
const publishCrl = async (): Promise<void> => {
  const result = await (publish.canRetry.value ? publish.retry() : publish.submit(undefined));
  if (result !== undefined && detail.value !== undefined) {
    cacheCa({ ...detail.value, crl: result.crl });
  }
};

const destroy = useGuardedMutation<undefined, PkiCaDetail>({
  family: "pki",
  mutate: (_input, key) => store.requireApi().destroyPkiCaKey(props.caId, key),
});
const confirmDestroy = async (): Promise<void> => {
  const result = await (destroy.canRetry.value ? destroy.retry() : destroy.submit(undefined));
  if (result !== undefined) {
    cacheCa(result);
    showDestroy.value = false;
  }
};

const abandon = useGuardedMutation<string, PkiCaDetail>({
  family: "pki",
  mutate: (version, key) => store.requireApi().deletePkiCa(props.caId, version, key),
});
const confirmAbandon = async (): Promise<void> => {
  if (detail.value === undefined) {
    return;
  }
  const result = await abandon.submit(detail.value.version);
  if (result !== undefined) {
    cacheCa(result);
    showAbandon.value = false;
  }
};

const closeDialog = (which: "destroy" | "abandon"): void => {
  if (which === "destroy") {
    showDestroy.value = false;
    destroy.reset();
  } else {
    showAbandon.value = false;
    abandon.reset();
  }
};

// ----------------------------------------------------------- Downloads

const downloadError = ref<unknown>();
const saveBytes = (bytes: Uint8Array, filename: string): void => {
  const blob = new Blob([bytes as BlobPart], { type: "application/pkix-crl" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
};
const downloadCrl = async (issuerId: string, filename: string): Promise<void> => {
  downloadError.value = undefined;
  try {
    const { bytes } = await store.requireApi().getAdminCrl(issuerId);
    saveBytes(bytes, filename);
  } catch (caught) {
    downloadError.value = caught;
  }
};
const downloadCaCrl = (): Promise<void> =>
  downloadCrl(
    props.caId,
    `${detail.value?.name ?? props.caId}-crl-${detail.value?.crl?.number ?? 0}.crl`,
  );
const downloadRootCrl = (): Promise<void> => {
  const root = detail.value?.rootCrl;
  return root === undefined
    ? Promise.resolve()
    : downloadCrl(root.extId, `${detail.value?.name ?? props.caId}-root-crl-${root.numberHex ?? "0"}.crl`);
};

const onRootCrlUploaded = (): void => {
  void queryClient.invalidateQueries({ queryKey: pkiKeys.ca(props.caId) });
  void queryClient.invalidateQueries({ queryKey: pkiKeys.externalCas() });
};

// -------------------------------------------------------------- Display

const capacityPercent = computed(() => {
  const capacity = detail.value?.capacity;
  if (capacity?.count === undefined || capacity.capacity <= 0) {
    return undefined;
  }
  return Math.min(100, Math.round((capacity.count / capacity.capacity) * 100));
});

const SUBTREE_KEYS = ["dns", "ip", "uri"] as const;
const constraintRows = computed(() => {
  const nc = detail.value?.requestedConstraints.nameConstraints;
  return (["permitted", "excluded"] as const).flatMap((group) =>
    SUBTREE_KEYS.flatMap((key) => {
      const values = nc?.[group]?.[key];
      return values === undefined || values.length === 0
        ? []
        : [{ group, key, values }];
    }),
  );
});
const effectiveJson = computed(() =>
  detail.value?.effectiveConstraints === undefined
    ? undefined
    : JSON.stringify(detail.value.effectiveConstraints, null, 2),
);
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink class="link text-xs" :to="{ name: 'pki', params: { env } }">← PKI</RouterLink>
        <h1 class="page-title">
          <span class="mono">{{ detail?.name ?? caId }}</span>
          <StateBadge v-if="detail" class="ml-2" :state="detail.status" />
        </h1>
        <p v-if="detail" class="page-subtitle">
          <span class="mono">{{ detail.kind }}</span>
          <template v-if="detail.displayName"> · {{ detail.displayName }}</template>
        </p>
      </div>
      <div v-if="detail" class="page-actions">
        <RouterLink
          class="btn"
          :to="{ name: 'pki-ca-new', params: { env }, query: { rolloverFrom: caId } }"
        >Roll over</RouterLink>
        <button
          v-if="canPublishCrl"
          class="btn"
          data-testid="publish-crl"
          :disabled="publish.phase.value.kind === 'submitting'"
          @click="publishCrl"
        >Publish CRL</button>
        <button v-if="canRetire" class="btn btn-danger" data-testid="retire" @click="showRetire = true">
          Retire
        </button>
        <button v-if="canAbandon" class="btn btn-danger" data-testid="abandon" @click="showAbandon = true">
          Abandon
        </button>
        <button v-if="canDestroyKey" class="btn btn-danger" data-testid="destroy-key" @click="showDestroy = true">
          Destroy key
        </button>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="ca.error.value" :error="ca.error.value" context="this CA" />
      <p v-else-if="ca.isPending.value" class="meta">Loading…</p>

      <template v-if="detail">
        <MutationState
          :phase="publish.phase.value"
          :can-retry="publish.canRetry.value"
          family="pki"
          intent="publish the CRL"
          @retry="publish.retry()"
          @reload="publish.reset()"
        />
        <p v-if="publish.result.value" class="notice notice-success" role="status">
          CRL {{ publish.result.value.crl.number }} published.
        </p>
        <ErrorNotice v-if="downloadError" :error="downloadError" context="the CRL download" />

        <div v-if="awaitingDrain" class="notice notice-warning" data-testid="drain-notice">
          The key can be destroyed once it is disabled: available after drain at
          <span class="mono">{{ detail.drainAt }}</span>.
        </div>

        <CaActivationPanel
          v-if="detail.status === 'PENDING_CERTIFICATE' && detail.kind === 'EXTERNAL_INTERMEDIATE'"
          :ca="detail"
          @activated="cacheCa"
          @refresh="() => void ca.refetch()"
        />

        <div class="flex gap-1" role="tablist">
          <button
            v-for="tab in TABS"
            :key="tab.id"
            type="button"
            role="tab"
            class="btn btn-sm"
            :class="activeTab === tab.id ? 'bg-surface-3! text-ink!' : ''"
            :aria-selected="activeTab === tab.id"
            :data-testid="`tab-${tab.id}`"
            @click="selectTab(tab.id)"
          >{{ tab.label }}</button>
        </div>

        <template v-if="activeTab === 'overview'">
          <section class="card card-body">
            <dl class="facts">
              <dt>Subject</dt>
              <dd class="mono break-all">{{ detail.subjectDn }}</dd>
              <dt>Key</dt>
              <dd class="mono">
                {{ detail.key.algorithm }} · {{ detail.key.custody }}
                <StateBadge class="ml-1" :state="detail.key.state" />
              </dd>
              <template v-if="detail.fingerprint">
                <dt>Fingerprint</dt>
                <dd class="mono break-all">{{ detail.fingerprint }}</dd>
              </template>
              <template v-if="detail.serial">
                <dt>Serial</dt>
                <dd class="mono break-all">{{ detail.serial }}</dd>
              </template>
              <template v-if="detail.notBefore">
                <dt>Valid</dt>
                <dd class="mono">{{ detail.notBefore }} to {{ detail.notAfter }}</dd>
              </template>
              <template v-if="detail.parent">
                <dt>Parent</dt>
                <dd class="mono">{{ detail.parent.type }} {{ detail.parent.id }}</dd>
              </template>
              <dt>CRL issuers</dt>
              <dd class="mono">
                <span v-for="issuer in detail.crlIssuers" :key="issuer.id" class="mr-2">
                  {{ issuer.type }} {{ issuer.id }}
                </span>
                <span v-if="detail.crlIssuers.length === 0" class="meta">none</span>
              </dd>
              <dt>Created</dt>
              <dd class="mono">{{ detail.createdAt }}</dd>
              <template v-if="detail.activatedAt">
                <dt>Activated</dt>
                <dd class="mono">{{ detail.activatedAt }}</dd>
              </template>
              <template v-if="detail.retiredAt">
                <dt>Retired</dt>
                <dd class="mono">{{ detail.retiredAt }}</dd>
              </template>
              <template v-if="detail.revokedAt">
                <dt>Revoked</dt>
                <dd class="mono">
                  {{ detail.revokedAt }}
                  <template v-if="detail.revocationReason"> ({{ detail.revocationReason }})</template>
                  <template v-if="detail.revocationSource"> by {{ detail.revocationSource }}</template>
                </dd>
              </template>
              <template v-if="detail.revocationEvidence">
                <dt>Evidence</dt>
                <dd class="break-all">{{ detail.revocationEvidence }}</dd>
              </template>
              <dt>Drained</dt>
              <dd>{{ detail.drained ? "yes" : "no" }}</dd>
            </dl>
          </section>

          <section v-if="detail.certificatePem" class="card card-body space-y-3">
            <CopyField
              label="Certificate"
              :value="detail.certificatePem"
              multiline
              :filename="`${detail.name}.crt.pem`"
            />
            <CopyField
              v-if="detail.chainPem"
              label="Chain"
              :value="detail.chainPem"
              multiline
              :filename="`${detail.name}-chain.pem`"
            />
          </section>

          <section class="card">
            <div class="card-header"><h2 class="section-title">Constraints</h2></div>
            <div class="card-body space-y-3">
              <table v-if="constraintRows.length > 0" class="data-table">
                <thead>
                  <tr><th>Requested</th><th>Type</th><th>Values</th></tr>
                </thead>
                <tbody>
                  <tr v-for="row in constraintRows" :key="`${row.group}-${row.key}`">
                    <td>{{ row.group }}</td>
                    <td class="mono">{{ row.key }}</td>
                    <td class="mono text-xs">{{ row.values.join(", ") }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-if="detail.requestedConstraints.extendedKeyUsages" class="text-[13px]">
                Requested EKUs:
                <span class="mono">{{ detail.requestedConstraints.extendedKeyUsages.join(", ") }}</span>
              </p>
              <p v-if="constraintRows.length === 0 && !detail.requestedConstraints.extendedKeyUsages" class="meta">
                No name constraints or EKUs were requested.
              </p>
              <div v-if="effectiveJson">
                <p class="field-label">Effective constraints</p>
                <pre class="code-block mono">{{ effectiveJson }}</pre>
              </div>
            </div>
          </section>

          <section class="card">
            <div class="card-header"><h2 class="section-title">Policy</h2></div>
            <dl class="facts card-body">
              <dt>Issues leaves</dt>
              <dd>{{ detail.policy.issueLeaves ? "yes" : "no" }}</dd>
              <dt>Issues subordinates</dt>
              <dd>{{ detail.policy.issueSubordinates ? "yes" : "no" }}</dd>
              <dt>Max leaf lifetime</dt>
              <dd class="mono">{{ formatDuration(detail.policy.maxLeafLifetimeSeconds) }}</dd>
              <dt>Leaf algorithms</dt>
              <dd class="mono">{{ detail.policy.leafKeyAlgorithms.join(", ") }}</dd>
              <dt>Capacity</dt>
              <dd class="mono">{{ detail.policy.capacity }}</dd>
              <dt>Issuance per hour</dt>
              <dd class="mono">{{ detail.policy.issuancePerHour }}</dd>
              <dt>CRL validity</dt>
              <dd class="mono">{{ formatDuration(detail.policy.crlValiditySeconds) }}</dd>
            </dl>
          </section>

          <section v-if="detail.crl" class="card" data-testid="crl-card">
            <div class="card-header">
              <h2 class="section-title">CRL</h2>
              <button class="btn btn-sm" data-testid="download-crl" @click="downloadCaCrl">
                Download CRL
              </button>
            </div>
            <dl class="facts card-body">
              <dt>Number</dt>
              <dd class="mono">{{ detail.crl.number }}</dd>
              <dt>State</dt>
              <dd><StateBadge :state="detail.crl.state" /></dd>
              <dt>This update</dt>
              <dd class="mono">{{ detail.crl.thisUpdate }}</dd>
              <dt>Next update</dt>
              <dd class="mono">{{ detail.crl.nextUpdate }}</dd>
              <dt>Entries</dt>
              <dd class="mono">{{ detail.crl.entryCount }}</dd>
              <dt>Pending revocations</dt>
              <dd class="mono">{{ detail.crl.pendingRevocations }}</dd>
            </dl>
          </section>

          <section v-if="detail.capacity" class="card card-body" data-testid="capacity-card">
            <h2 class="section-title">Capacity</h2>
            <p class="meta mt-1">
              <template v-if="detail.capacity.count !== undefined">
                {{ detail.capacity.count }} of {{ detail.capacity.capacity }} certificates
              </template>
              <template v-else>Capacity {{ detail.capacity.capacity }}; count unavailable</template>
              · {{ detail.capacity.issuancePerHour }} per hour
            </p>
            <div
              v-if="capacityPercent !== undefined"
              class="mt-2 h-2 w-full overflow-hidden rounded bg-surface-3"
              role="progressbar"
              :aria-valuenow="capacityPercent"
              aria-valuemin="0"
              aria-valuemax="100"
            >
              <div
                class="h-full"
                :class="capacityPercent >= 80 ? 'bg-warning' : 'bg-accent'"
                :style="{ width: `${capacityPercent}%` }"
              />
            </div>
            <p v-if="capacityPercent !== undefined && capacityPercent >= 80" class="notice notice-warning mt-2">
              This CA is at {{ capacityPercent }}% of its capacity. Plan a rollover.
            </p>
          </section>

          <section v-if="detail.kind === 'EXTERNAL_INTERMEDIATE' && detail.rootCrl" class="card" data-testid="root-crl-card">
            <div class="card-header">
              <h2 class="section-title">Root CRL</h2>
              <span class="flex gap-2">
                <button class="btn btn-sm" data-testid="upload-root-crl" @click="showUpload = true">
                  Upload root CRL
                </button>
                <button class="btn btn-sm" data-testid="download-root-crl" @click="downloadRootCrl">
                  Download root CRL
                </button>
              </span>
            </div>
            <dl class="facts card-body">
              <dt>State</dt>
              <dd><StateBadge :state="detail.rootCrl.state" /></dd>
              <dt>Number</dt>
              <dd class="mono">{{ detail.rootCrl.numberHex ?? "-" }}</dd>
              <dt>Next update</dt>
              <dd class="mono">{{ detail.rootCrl.nextUpdate ?? "-" }}</dd>
            </dl>
          </section>
        </template>

        <section v-else-if="activeTab === 'certificates'" class="card" data-testid="certificates-tab">
          <div class="card-header">
            <h2 class="section-title">Certificates</h2>
            <form class="flex flex-wrap items-end gap-2" @submit.prevent="applyCertFilter">
              <label class="block">
                <span class="field-hint">Status</span>
                <select v-model="certFilter.status" class="input" aria-label="Status filter">
                  <option value="">Any</option>
                  <option v-for="status in CERT_STATUSES" :key="status" :value="status">{{ status }}</option>
                </select>
              </label>
              <label class="block">
                <span class="field-hint">Expiring before</span>
                <input v-model="certFilter.expiringBefore" type="datetime-local" class="input" aria-label="Expiring before" />
              </label>
              <button type="submit" class="btn btn-sm">Apply</button>
            </form>
          </div>
          <ErrorNotice v-if="certificates.error.value" :error="certificates.error.value" context="certificates" />
          <div class="overflow-x-auto">
            <CertificateSummaryTable :env="env" :certificates="certificates.items.value" />
          </div>
          <p v-if="certificates.exhausted.value && certificates.items.value.length === 0" class="card-body meta">
            No certificates match.
          </p>
          <div v-if="!certificates.exhausted.value" class="card-body">
            <button class="btn" :disabled="certificates.loading.value" @click="certificates.loadMore()">
              {{ certificates.loading.value ? "Loading…" : "Load more" }}
            </button>
          </div>
        </section>

        <section v-else class="card" data-testid="grants-tab">
          <div class="card-header">
            <h2 class="section-title">Certificate grants</h2>
            <span class="meta">Eventually consistent; a new grant can take a moment to appear.</span>
          </div>
          <ErrorNotice v-if="grants.error.value" :error="grants.error.value" context="grants" />
          <table v-if="grants.items.value.length > 0" class="data-table">
            <thead>
              <tr><th>Grant</th><th>Consumer</th><th>Status</th><th>Expires</th></tr>
            </thead>
            <tbody>
              <tr v-for="grant in grants.items.value" :key="grant.uid">
                <td>
                  <RouterLink
                    class="link mono"
                    :to="{
                      name: 'consumer-pki-grant',
                      params: { env, consumerId: grant.consumerId, name: grant.name },
                    }"
                  >{{ grant.name }}</RouterLink>
                </td>
                <td class="mono">{{ grant.consumerId }}</td>
                <td>
                  <StateBadge :state="grant.status" />
                  <span v-if="grant.expired" class="tag tag-warning ml-1">expired</span>
                </td>
                <td class="text-xs">{{ grant.expiresAt ?? "-" }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else-if="grants.exhausted.value" class="card-body meta">No grants use this CA.</p>
          <div v-if="!grants.exhausted.value" class="card-body">
            <button class="btn" :disabled="grants.loading.value" @click="grants.loadMore()">
              {{ grants.loading.value ? "Loading…" : "Load more" }}
            </button>
          </div>
        </section>
      </template>
    </div>

    <CaRetireDialog v-if="showRetire && detail" :ca="detail" @retired="cacheCa" @close="showRetire = false" />

    <TypedConfirmDialog
      v-if="showAbandon && detail"
      title="Abandon this CA?"
      :expected="detail.name"
      confirm-label="Abandon CA"
      :busy="abandon.phase.value.kind === 'submitting'"
      @confirm="confirmAbandon"
      @cancel="closeDialog('abandon')"
    >
      <p class="text-[13px] text-ink-2">
        {{ detail.name }} was never activated. Abandoning it marks it FAILED and it can no
        longer be activated. The name and subject stay claimed.
      </p>
      <MutationState
        :phase="abandon.phase.value"
        :can-retry="abandon.canRetry.value"
        family="pki"
        intent="abandon this CA"
        @retry="abandon.retry()"
        @reload="abandon.reset(); void ca.refetch()"
      />
    </TypedConfirmDialog>

    <TypedConfirmDialog
      v-if="showDestroy && detail"
      title="Destroy this CA key?"
      :expected="detail.name"
      confirm-label="Destroy key"
      :busy="destroy.phase.value.kind === 'submitting'"
      @confirm="confirmDestroy"
      @cancel="closeDialog('destroy')"
    >
      <p class="text-[13px] text-ink-2">
        This permanently destroys the signing key of {{ detail.name }}. It cannot be undone.
        The CA record and its certificates remain.
      </p>
      <MutationState
        :phase="destroy.phase.value"
        :can-retry="destroy.canRetry.value"
        family="pki"
        intent="destroy this CA key"
        @retry="destroy.retry()"
        @reload="destroy.reset()"
      />
    </TypedConfirmDialog>

    <RootCrlUploadDialog
      v-if="showUpload && detail?.rootCrl"
      :ext-id="detail.rootCrl.extId"
      :current-number-hex="detail.rootCrl.numberHex"
      @uploaded="onRootCrlUploaded"
      @close="showUpload = false"
    />
  </div>
</template>
