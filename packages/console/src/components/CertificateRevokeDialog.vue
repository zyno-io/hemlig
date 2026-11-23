<script setup lang="ts">
import { computed, ref } from "vue";
import MutationState from "./MutationState.vue";
import { LEAF_REVOCATION_REASONS, localInputToIso } from "../api/pki-format";
import type {
  PkiCertificateDetail,
  PkiLeafRevocationReason,
  PkiRevokeCertificateResponse,
} from "../api/pki-schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ certificate: PkiCertificateDetail }>();
const emit = defineEmits<{ revoked: [result: PkiRevokeCertificateResponse]; close: [] }>();

const store = useAppStore();

// Fixed at open: once the revoke lands, the certificate prop flips to REVOKED
// and the dialog must keep describing what it just did.
const upgrade = props.certificate.storedStatus === "REVOKED";
const reasons: readonly PkiLeafRevocationReason[] = upgrade
  ? ["keyCompromise"]
  : LEAF_REVOCATION_REASONS;

const reason = ref<PkiLeafRevocationReason>(upgrade ? "keyCompromise" : "unspecified");
const invalidityDate = ref("");

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

interface RevokeInput {
  readonly reason: PkiLeafRevocationReason;
  readonly invalidityDate?: string;
}

const mutation = useGuardedMutation<RevokeInput, PkiRevokeCertificateResponse>({
  family: "pki",
  mutate: (input, key) =>
    store
      .requireApi()
      .revokePkiCertificate(props.certificate.caId, props.certificate.serial, input, key),
});

const submitting = computed(() => mutation.phase.value.kind === "submitting");
const done = computed(() => mutation.phase.value.kind === "succeeded");

const submit = async (): Promise<void> => {
  // A second click while the first is in flight must not start another intent.
  if (submitting.value || done.value || invalidityProblem.value !== undefined) {
    return;
  }
  const result = await mutation.submit({
    reason: reason.value,
    ...(invalidityIso.value === undefined ? {} : { invalidityDate: invalidityIso.value }),
  });
  if (result !== undefined) {
    emit("revoked", result);
  }
};
</script>

<template>
  <div class="modal-scrim" role="dialog" aria-modal="true" aria-labelledby="cert-revoke-title" @keydown.esc="emit('close')">
    <form class="modal-panel max-w-lg" @submit.prevent="submit">
      <h2 id="cert-revoke-title" class="text-[17px] font-semibold">
        {{ upgrade ? "Upgrade revocation to keyCompromise" : "Revoke this certificate?" }}
      </h2>
      <p class="mono mt-2 break-all text-xs">{{ certificate.caId }} / {{ certificate.serial }}</p>
      <p v-if="upgrade" class="mt-2 text-[13px] text-ink-2">
        This certificate is already revoked (reason {{ certificate.revocation?.reason }}). The only
        change still possible is raising the reason to keyCompromise.
      </p>
      <p v-else class="mt-2 text-[13px] text-ink-2">
        Revocation is permanent. The certificate is added to the CA's next CRL.
      </p>

      <template v-if="!done">
        <label class="mt-4 block">
          <span class="field-label">Reason</span>
          <select v-model="reason" class="input" :disabled="upgrade || submitting" data-testid="revoke-reason">
            <option v-for="option in reasons" :key="option" :value="option">{{ option }}</option>
          </select>
        </label>
        <label v-if="reason === 'keyCompromise'" class="mt-3 block">
          <span class="field-label">Invalidity date (optional)</span>
          <input
            v-model="invalidityDate"
            type="datetime-local"
            class="input"
            :disabled="submitting"
            data-testid="revoke-invalidity"
          />
          <p class="field-hint">When the key was first believed compromised. Not in the future.</p>
          <p v-if="invalidityProblem" class="field-error" role="alert">{{ invalidityProblem }}</p>
        </label>
        <div class="mt-3">
          <MutationState
            :phase="mutation.phase.value"
            :can-retry="mutation.canRetry.value"
            family="pki"
            intent="revoke this certificate"
            @retry="mutation.retry()"
            @reload="emit('close')"
          />
        </div>
      </template>

      <div v-else class="mt-4 space-y-2" data-testid="revoke-result">
        <p class="notice notice-success" role="status">
          <template v-if="mutation.result.value?.changed === false">
            Nothing changed: the certificate was already revoked with that reason.
          </template>
          <template v-else>The certificate is revoked.</template>
        </p>
        <p v-if="mutation.result.value?.crlEntry === false" class="notice notice-info" data-testid="no-crl-entry">
          No CRL entry was written: the certificate has already expired, or its CA is revoked,
          so relying parties no longer trust it anyway.
        </p>
        <p v-else-if="mutation.result.value?.crlPublished === false" class="notice notice-info" data-testid="not-published">
          The CRL has not been republished yet. Maintenance publishes it within 15 minutes.
        </p>
        <p v-else class="text-[13px] text-ink-2">
          Published in CRL number {{ mutation.result.value?.crlNumber }}.
        </p>
      </div>

      <div class="mt-5 flex justify-end gap-2">
        <button type="button" class="btn" data-testid="revoke-close" @click="emit('close')">
          {{ done ? "Close" : "Cancel" }}
        </button>
        <button
          v-if="!done"
          type="submit"
          class="btn btn-danger"
          data-testid="revoke-submit"
          :disabled="submitting || invalidityProblem !== undefined"
        >
          {{ submitting ? "Revoking…" : upgrade ? "Upgrade" : "Revoke" }}
        </button>
      </div>
    </form>
  </div>
</template>
