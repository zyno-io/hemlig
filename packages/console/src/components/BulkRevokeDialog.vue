<script setup lang="ts">
import { computed, ref } from "vue";
import MutationState from "./MutationState.vue";
import TypedConfirmDialog from "./TypedConfirmDialog.vue";
import { LEAF_REVOCATION_REASONS, localInputToIso } from "../api/pki-format";
import type {
  PkiBulkRevokeInput,
  PkiIssuanceGrant,
  PkiLeafRevocationReason,
} from "../api/pki-schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{
  consumerId: string;
  grants: readonly PkiIssuanceGrant[];
  preset?: { issuanceGrant: string; issuanceGrantUid?: string };
}>();
const emit = defineEmits<{ done: []; close: [] }>();

/** CLI parity (`cli/src/pki.ts`): the server revokes in batches. */
const MAX_ATTEMPTS = 20;

const store = useAppStore();

const scope = ref(props.preset?.issuanceGrant ?? "");
const thisGeneration = ref(props.preset?.issuanceGrantUid !== undefined);
const reason = ref<PkiLeafRevocationReason>("unspecified");
const invalidityDate = ref("");

// One key per intent. A continuation after an incomplete run must reuse it so
// the server resumes rather than starting a second revocation; any other new
// submit is a new intent and gets a fresh key.
let intentKey = crypto.randomUUID();

const totals = ref({ revoked: 0, alreadyRevoked: 0, attempts: 0 });
const complete = ref<boolean | undefined>();

const generationUid = computed(() => {
  if (scope.value === "") {
    return undefined;
  }
  if (props.preset?.issuanceGrant === scope.value && props.preset.issuanceGrantUid !== undefined) {
    return props.preset.issuanceGrantUid;
  }
  return props.grants.find((grant) => grant.name === scope.value)?.uid;
});

const invalidityIso = computed(() =>
  reason.value === "keyCompromise" ? localInputToIso(invalidityDate.value) : undefined,
);
const invalidityProblem = computed(() => {
  if (reason.value !== "keyCompromise" || invalidityDate.value === "") {
    return undefined;
  }
  const iso = invalidityIso.value;
  if (iso === undefined) {
    return "That is not a valid date.";
  }
  return new Date(iso).getTime() > Date.now() ? "The invalidity date cannot be in the future." : undefined;
});

const buildInput = (): PkiBulkRevokeInput => ({
  reason: reason.value,
  ...(invalidityIso.value === undefined ? {} : { invalidityDate: invalidityIso.value }),
  ...(scope.value === "" ? {} : { issuanceGrant: scope.value }),
  ...(scope.value !== "" && thisGeneration.value && generationUid.value !== undefined
    ? { issuanceGrantUid: generationUid.value }
    : {}),
});

const mutation = useGuardedMutation<PkiBulkRevokeInput, { complete: boolean }>({
  family: "pki",
  newKey: () => {
    if (complete.value !== false) {
      intentKey = crypto.randomUUID();
    }
    return intentKey;
  },
  mutate: async (input, key) => {
    let last = false;
    for (let attempt = 0; attempt < MAX_ATTEMPTS && !last; attempt += 1) {
      const response = await store
        .requireApi()
        .revokeConsumerPkiCertificates(props.consumerId, input, key);
      // An incomplete run leaves no replay record, so a rerun starts over and
      // reports earlier revocations as already revoked: take the last response,
      // minus what earlier attempts revoked.
      totals.value = {
        revoked: totals.value.revoked + response.revoked,
        alreadyRevoked: Math.max(0, response.alreadyRevoked - totals.value.revoked),
        attempts: totals.value.attempts + 1,
      };
      last = response.complete;
    }
    complete.value = last;
    return { complete: last };
  },
});

const running = computed(() => mutation.phase.value.kind === "submitting");
const started = computed(() => totals.value.attempts > 0 || mutation.phase.value.kind !== "idle");
const incomplete = computed(() => complete.value === false);
const finished = computed(() => complete.value === true);

const confirm = async (): Promise<void> => {
  if (running.value || invalidityProblem.value !== undefined) {
    return;
  }
  if (complete.value !== false) {
    totals.value = { revoked: 0, alreadyRevoked: 0, attempts: 0 };
  }
  // Continuing an incomplete run keeps its key (see `newKey`).
  await mutation.submit(buildInput());
};

const lockedInput = computed(() => running.value || incomplete.value);
</script>

<template>
  <div v-if="finished" class="modal-scrim" role="dialog" aria-modal="true" aria-labelledby="bulk-done-title">
    <div class="modal-panel max-w-md" data-testid="bulk-result">
      <h2 id="bulk-done-title" class="text-[17px] font-semibold">Certificates revoked</h2>
      <p class="mt-2 text-[13px]">
        Revoked {{ totals.revoked }}; {{ totals.alreadyRevoked }} were already revoked.
      </p>
      <p class="field-hint">CRLs are republished within 15 minutes.</p>
      <div class="mt-5 flex justify-end">
        <button type="button" class="btn btn-primary" @click="emit('done')">Close</button>
      </div>
    </div>
  </div>

  <TypedConfirmDialog
    v-else
    title="Revoke certificates"
    :expected="consumerId"
    :confirm-label="incomplete ? 'Run again' : 'Revoke certificates'"
    :busy="running || invalidityProblem !== undefined"
    @confirm="confirm"
    @cancel="started && incomplete ? emit('done') : emit('close')"
  >
    <p class="text-[13px] text-ink-2">
      Revokes issued certificates for this consumer. Revocation is permanent and cannot be undone.
    </p>

    <label class="block">
      <span class="field-label">Scope</span>
      <select v-model="scope" class="input" :disabled="lockedInput" data-testid="bulk-scope">
        <option value="">All certificates of {{ consumerId }}</option>
        <option v-for="grant in grants" :key="`${grant.name}:${grant.uid}`" :value="grant.name">
          Grant {{ grant.name }}<template v-if="grant.status === 'DELETED'"> (deleted)</template>
        </option>
        <option
          v-if="preset && !grants.some((grant) => grant.name === preset?.issuanceGrant)"
          :value="preset.issuanceGrant"
        >
          Grant {{ preset.issuanceGrant }}
        </option>
      </select>
    </label>
    <label v-if="scope !== ''" class="flex items-center gap-2 text-[13px]">
      <input
        v-model="thisGeneration"
        type="checkbox"
        :disabled="lockedInput || generationUid === undefined"
        data-testid="bulk-generation"
      />
      Only this generation of the grant (a recreated grant of the same name is left alone)
    </label>

    <label class="block">
      <span class="field-label">Reason</span>
      <select v-model="reason" class="input" :disabled="lockedInput" data-testid="bulk-reason">
        <option v-for="option in LEAF_REVOCATION_REASONS" :key="option" :value="option">{{ option }}</option>
      </select>
    </label>
    <label v-if="reason === 'keyCompromise'" class="block">
      <span class="field-label">Invalidity date (optional)</span>
      <input v-model="invalidityDate" type="datetime-local" class="input" :disabled="lockedInput" />
      <p v-if="invalidityProblem" class="field-error" role="alert">{{ invalidityProblem }}</p>
    </label>

    <p v-if="totals.attempts > 0" class="notice notice-info" role="status" data-testid="bulk-progress">
      Batch {{ totals.attempts }}: revoked {{ totals.revoked }}, already revoked
      {{ totals.alreadyRevoked }}<template v-if="incomplete">. More certificates remain; run
      again to continue with the same request.</template>
    </p>

    <MutationState
      :phase="mutation.phase.value"
      :can-retry="mutation.canRetry.value"
      family="pki"
      intent="revoke these certificates"
      @retry="mutation.retry()"
      @reload="emit('close')"
    />
  </TypedConfirmDialog>
</template>
