<script setup lang="ts">
import { computed, ref } from "vue";
import type { PkiUploadCrlResponse } from "../api/pki-schemas";
import { inspectPem } from "../api/pki-format";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useStoredTab } from "../composables/useStoredTab";
import { ezRenewCrlCommands } from "../api/ez-commands";
import { useAppStore } from "../stores/app";
import CopyField from "./CopyField.vue";
import EzManualTabs from "./EzManualTabs.vue";
import MutationState from "./MutationState.vue";
import PemField from "./PemField.vue";

const OFFLINE_ROOT_DOCS = "https://zyno-io.github.io/hemlig/operations/pki-offline-root.html";

const props = defineProps<{
  extId: string;
  subjectDn?: string;
  currentNumberHex?: string;
}>();
const emit = defineEmits<{ uploaded: [result: PkiUploadCrlResponse]; close: [] }>();

const TAB_OPTIONS = [
  { id: "ez", label: "EZ" },
  { id: "manual", label: "Manual" },
] as const;
type CrlTab = (typeof TAB_OPTIONS)[number]["id"];
const [tab, selectTab] = useStoredTab<CrlTab>("hemlig.pki.crl-tab", ["ez", "manual"], "ez");
const commands = computed(() => ezRenewCrlCommands(props.extId));
const activeTab = computed<CrlTab>(() => (commands.value ? tab.value : "manual"));

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

      <div v-if="commands" class="mt-3">
        <EzManualTabs
          id-prefix="crl"
          label="Upload method"
          :tabs="TAB_OPTIONS"
          :model-value="activeTab"
          @update:model-value="selectTab"
        />
      </div>

      <div
        v-if="commands && activeTab === 'ez'"
        id="crl-panel-ez"
        class="mt-3 space-y-2"
        role="tabpanel"
        aria-labelledby="crl-tab-ez"
        data-testid="crl-ez"
      >
        <p class="field-hint">
          The CLI renews the root CRL when it is due and uploads it. Run it on the
          machine that holds the root, signed in with
          <span class="mono">hemlig login</span>. See the
          <a class="link" :href="OFFLINE_ROOT_DOCS" target="_blank" rel="noopener noreferrer">offline root guide</a>.
        </p>
        <CopyField label="Renew if due and upload" :value="commands.renew" copy-only multiline />
        <CopyField label="Upload the current CRL" :value="commands.upload" copy-only multiline />
        <p class="field-hint">Air-gapped root: sign the CRL there, then upload it from an online machine.</p>
        <CopyField label="Sign offline" :value="commands.offlineRenew" copy-only multiline />
        <CopyField label="Upload the file" :value="commands.offlineUpload" copy-only multiline />
      </div>

      <div
        v-else
        id="crl-panel-manual"
        class="mt-3"
        role="tabpanel"
        aria-labelledby="crl-tab-manual"
        data-testid="crl-manual"
      >
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
          v-if="!upload.result.value && activeTab === 'manual'"
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
