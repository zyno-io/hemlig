<script setup lang="ts">
import { computed, ref } from "vue";
import { ApiError } from "../api/errors";
import type { PkiActivateCaInput, PkiCaDetail } from "../api/pki-schemas";
import { inspectPem } from "../api/pki-format";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";
import CopyField from "./CopyField.vue";
import MutationState from "./MutationState.vue";
import PemField from "./PemField.vue";

const props = defineProps<{ ca: PkiCaDetail }>();
const emit = defineEmits<{ activated: [ca: PkiCaDetail] }>();

const OFFLINE_ROOT_DOCS = "https://zyno-io.github.io/hemlig/operations/pki-offline-root.html";

const store = useAppStore();
const certificatePem = ref("");
const chainPem = ref("");
const rootCrl = ref("");
const acceptBroader = ref(false);
// Surfaced once the server says the signed certificate is broader than requested.
const showBroader = ref(false);

const activation = useGuardedMutation<PkiActivateCaInput, PkiCaDetail>({
  family: "pki",
  mutate: (input, key) => store.requireApi().activatePkiCa(props.ca.caId, input, key),
});

const problems = computed(() => [
  ...inspectPem(certificatePem.value, "certificate").problems,
  ...inspectPem(chainPem.value, "chain").problems,
  ...(rootCrl.value.trim() === "" ? [] : inspectPem(rootCrl.value, "crl").problems),
]);
const canSubmit = computed(
  () =>
    certificatePem.value.trim() !== "" &&
    chainPem.value.trim() !== "" &&
    problems.value.length === 0 &&
    activation.phase.value.kind !== "submitting",
);

const buildInput = (): PkiActivateCaInput => ({
  certificatePem: certificatePem.value,
  chainPem: chainPem.value,
  ...(rootCrl.value.trim() === "" ? {} : { rootCrl: rootCrl.value }),
  ...(showBroader.value && acceptBroader.value
    ? { acceptBroaderConstraints: true }
    : {}),
});

const finish = (result: PkiCaDetail | undefined): void => {
  const phase = activation.phase.value;
  if (
    phase.kind === "failed" &&
    phase.error instanceof ApiError &&
    phase.error.code === "chain_invalid" &&
    phase.error.reason === "constraints_broader"
  ) {
    showBroader.value = true;
  }
  if (result !== undefined) {
    emit("activated", result);
  }
};

const submit = async (): Promise<void> => {
  if (!canSubmit.value) {
    return;
  }
  finish(await activation.submit(buildInput()));
};
const retry = async (): Promise<void> => {
  finish(await activation.retry());
};
</script>

<template>
  <section class="card" data-testid="activation-panel">
    <div class="card-header">
      <h2 class="section-title">Activate this CA</h2>
    </div>
    <form class="card-body space-y-5" @submit.prevent="submit">
      <div>
        <h3 class="text-[13px] font-semibold">1. Download the CSR</h3>
        <p class="field-hint">Hemlig generated the key. Only the request leaves it.</p>
        <div v-if="ca.csrPem" class="mt-2">
          <CopyField
            label="Certificate request"
            :value="ca.csrPem"
            multiline
            :filename="`${ca.name}.csr.pem`"
          />
        </div>
      </div>

      <div>
        <h3 class="text-[13px] font-semibold">2. Sign it offline</h3>
        <p class="field-hint">
          Sign the request with your offline root, then issue the root's CRL. See the
          <a
            class="link"
            :href="OFFLINE_ROOT_DOCS"
            target="_blank"
            rel="noopener noreferrer"
          >offline root recipe</a>.
        </p>
      </div>

      <div class="space-y-3">
        <h3 class="text-[13px] font-semibold">3. Activate</h3>
        <PemField v-model="certificatePem" label="Signed certificate" kind="certificate" required />
        <PemField v-model="chainPem" label="Chain (the root)" kind="chain" required />
        <div>
          <PemField v-model="rootCrl" label="Root CRL (optional)" kind="crl" :rows="3" />
          <p class="field-hint">Only for a root Hemlig has not seen.</p>
        </div>

        <label v-if="showBroader" class="block notice notice-warning">
          <span class="flex items-start gap-2">
            <input v-model="acceptBroader" type="checkbox" data-testid="accept-broader" />
            <span>
              Accept broader constraints. The signed certificate's constraints are
              broader than the ones requested for this CA. Tick this only if that is
              intended.
            </span>
          </span>
        </label>

        <MutationState
          :phase="activation.phase.value"
          :can-retry="activation.canRetry.value"
          family="pki"
          intent="activate this CA"
          @retry="retry"
          @reload="activation.reset()"
        />

        <button
          type="submit"
          class="btn btn-primary"
          data-testid="activate-submit"
          :disabled="!canSubmit"
        >
          {{ activation.phase.value.kind === "submitting" ? "Activating…" : "Activate CA" }}
        </button>
      </div>
    </form>
  </section>
</template>
