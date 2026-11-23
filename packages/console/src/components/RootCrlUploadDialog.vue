<script setup lang="ts">
import { computed, ref } from "vue";
import type { PkiUploadCrlResponse } from "../api/pki-schemas";
import { inspectPem } from "../api/pki-format";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";
import MutationState from "./MutationState.vue";
import PemField from "./PemField.vue";

const props = defineProps<{
  extId: string;
  subjectDn?: string;
  currentNumberHex?: string;
}>();
const emit = defineEmits<{ uploaded: [result: PkiUploadCrlResponse]; close: [] }>();

const store = useAppStore();
const crl = ref("");

const upload = useGuardedMutation<string, PkiUploadCrlResponse>({
  family: "pki",
  mutate: (value, key) => store.requireApi().uploadExternalCaCrl(props.extId, value, key),
});

const inspection = computed(() => inspectPem(crl.value, "crl"));
const canSubmit = computed(
  () =>
    crl.value.trim() !== "" &&
    !inspection.value.privateKey &&
    inspection.value.problems.length === 0 &&
    upload.phase.value.kind !== "submitting" &&
    upload.phase.value.kind !== "succeeded",
);

const submit = async (): Promise<void> => {
  if (!canSubmit.value) {
    return;
  }
  const result = await upload.submit(crl.value);
  if (result !== undefined) {
    emit("uploaded", result);
  }
};
const retry = async (): Promise<void> => {
  const result = await upload.retry();
  if (result !== undefined) {
    emit("uploaded", result);
  }
};
</script>

<template>
  <div
    class="modal-scrim"
    role="dialog"
    aria-modal="true"
    aria-labelledby="root-crl-title"
    @keydown.esc="emit('close')"
  >
    <form class="modal-panel max-w-xl" @submit.prevent="submit">
      <h2 id="root-crl-title" class="text-[17px] font-semibold">Upload root CRL</h2>
      <p v-if="subjectDn" class="mono mt-2 break-all text-xs">{{ subjectDn }}</p>
      <p v-if="currentNumberHex" class="meta mt-1">
        Current CRL number <span class="mono">{{ currentNumberHex }}</span>
      </p>
      <p class="notice notice-warning mt-3">
        A CRL that lists a Hemlig intermediate revokes it here immediately and
        permanently, certificateHold included.
      </p>

      <div class="mt-3">
        <PemField v-model="crl" label="Root CRL" kind="crl" :rows="6" />
      </div>

      <div class="mt-3">
        <MutationState
          :phase="upload.phase.value"
          :can-retry="upload.canRetry.value"
          family="pki"
          intent="upload this CRL"
          @retry="retry"
          @reload="upload.reset()"
        />
      </div>

      <div v-if="upload.result.value" class="mt-3 space-y-2" data-testid="crl-result">
        <p v-if="!upload.result.value.changed" class="notice notice-success" role="status">
          This CRL is already current. Nothing changed.
        </p>
        <p v-else class="notice notice-success" role="status">The CRL was stored.</p>
        <div
          v-if="upload.result.value.revokedCaIds.length > 0"
          class="notice notice-danger"
          role="alert"
        >
          <p class="notice-title">These Hemlig CAs were revoked by this CRL:</p>
          <ul class="mt-1 list-disc pl-5">
            <li v-for="caId in upload.result.value.revokedCaIds" :key="caId" class="mono">
              {{ caId }}
            </li>
          </ul>
        </div>
      </div>

      <div class="mt-4 flex justify-end gap-2">
        <button type="button" class="btn" data-testid="crl-close" @click="emit('close')">
          {{ upload.result.value ? "Close" : "Cancel" }}
        </button>
        <button
          v-if="!upload.result.value"
          type="submit"
          class="btn btn-primary"
          data-testid="crl-upload"
          :disabled="!canSubmit"
        >
          {{ upload.phase.value.kind === "submitting" ? "Uploading…" : "Upload CRL" }}
        </button>
      </div>
    </form>
  </div>
</template>
