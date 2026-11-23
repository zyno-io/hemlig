<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed } from "vue";
import type { PkiCaDetail } from "../api/pki-schemas";
import { PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";
import MutationState from "./MutationState.vue";
import TypedConfirmDialog from "./TypedConfirmDialog.vue";

const props = defineProps<{ ca: PkiCaDetail }>();
const emit = defineEmits<{ retired: [ca: PkiCaDetail]; close: [] }>();

const store = useAppStore();

// The grant index is eventually consistent, so this is an approximate count.
const grants = useQuery({
  queryKey: computed(() => pkiKeys.caGrants(props.ca.caId)),
  queryFn: () => store.requireApi().listCaIssuanceGrants(props.ca.caId),
  ...PKI_QUERY_OPTIONS,
});

const liveGrants = computed(() =>
  (grants.data.value?.grants ?? []).filter((grant) => grant.status !== "DELETED"),
);
const hasMore = computed(() => grants.data.value?.nextCursor !== undefined);
const loadFailed = computed(() => grants.isError.value);
const loading = computed(() => grants.isPending.value);
const needsTyped = computed(
  () => loadFailed.value || liveGrants.value.length > 0 || hasMore.value,
);

const retirement = useGuardedMutation<undefined, PkiCaDetail>({
  family: "pki",
  mutate: (_input, key) => store.requireApi().retirePkiCa(props.ca.caId, key),
});

const submitting = computed(() => retirement.phase.value.kind === "submitting");

const confirm = async (): Promise<void> => {
  if (submitting.value || retirement.result.value !== undefined) {
    return;
  }
  const result = await retirement.submit(undefined);
  if (result !== undefined) {
    emit("retired", result);
  }
};
const retry = async (): Promise<void> => {
  const result = await retirement.retry();
  if (result !== undefined) {
    emit("retired", result);
  }
};
</script>

<template>
  <div
    v-if="retirement.result.value"
    class="modal-scrim"
    role="dialog"
    aria-modal="true"
    aria-labelledby="retire-done-title"
    @keydown.esc="emit('close')"
  >
    <div class="modal-panel max-w-lg">
      <h2 id="retire-done-title" class="text-[17px] font-semibold">CA retired</h2>
      <p class="mt-2 text-[13px] text-ink-2">
        {{ ca.name }} no longer issues. Its key stays active until it drains.
      </p>
      <ul v-if="(retirement.result.value.warnings ?? []).length > 0" class="mt-3 space-y-2">
        <li
          v-for="warning in retirement.result.value.warnings"
          :key="warning.code"
          class="notice notice-warning"
          data-testid="retire-warning"
        >
          {{ warning.message }}
        </li>
      </ul>
      <div class="mt-4 flex justify-end">
        <button type="button" class="btn btn-primary" @click="emit('close')">Close</button>
      </div>
    </div>
  </div>

  <TypedConfirmDialog
    v-else-if="needsTyped"
    title="Retire this CA?"
    :expected="ca.name"
    confirm-label="Retire CA"
    :busy="submitting"
    @confirm="confirm"
    @cancel="emit('close')"
  >
    <p class="text-[13px] text-ink-2">
      Retiring stops this CA from issuing. Existing certificates stay valid, and the
      CRL stays published.
    </p>
    <p v-if="loadFailed" class="notice notice-warning">
      The grants that reference this CA could not be loaded, so they cannot be counted.
    </p>
    <p v-else class="notice notice-warning" data-testid="retire-grant-count">
      About {{ liveGrants.length }}{{ hasMore ? "+" : "" }} issuance grant{{
        liveGrants.length === 1 && !hasMore ? "" : "s"
      }} still reference this CA and will stop issuing. The count is approximate.
    </p>
    <MutationState
      :phase="retirement.phase.value"
      :can-retry="retirement.canRetry.value"
      family="pki"
      intent="retire this CA"
      @retry="retry"
      @reload="retirement.reset()"
    />
  </TypedConfirmDialog>

  <div
    v-else
    class="modal-scrim"
    role="dialog"
    aria-modal="true"
    aria-labelledby="retire-title"
    @keydown.esc="emit('close')"
  >
    <div class="modal-panel max-w-lg">
      <h2 id="retire-title" class="text-[17px] font-semibold">Retire this CA?</h2>
      <p class="mt-2 text-[13px] text-ink-2">
        Retiring stops {{ ca.name }} from issuing. Existing certificates stay valid, and
        the CRL stays published. No issuance grants reference it.
      </p>
      <div class="mt-3">
        <MutationState
          :phase="retirement.phase.value"
          :can-retry="retirement.canRetry.value"
          family="pki"
          intent="retire this CA"
          @retry="retry"
          @reload="retirement.reset()"
        />
      </div>
      <div class="mt-5 flex justify-end gap-2">
        <button type="button" class="btn" @click="emit('close')">Cancel</button>
        <button
          type="button"
          class="btn btn-danger"
          data-testid="retire-confirm"
          :disabled="loading || submitting"
          @click="confirm"
        >
          Retire CA
        </button>
      </div>
    </div>
  </div>
</template>
