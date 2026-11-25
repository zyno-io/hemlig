<script setup lang="ts">
import { computed, ref } from "vue";
import { ApiError } from "../api/errors";
import type { PkiActivateCaInput, PkiCaDetail } from "../api/pki-schemas";
import { inspectPem } from "../api/pki-format";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useStoredTab } from "../composables/useStoredTab";
import { ezActivationCommands } from "../api/ez-commands";
import { useAppStore } from "../stores/app";
import CopyField from "./CopyField.vue";
import EzManualTabs from "./EzManualTabs.vue";
import MutationState from "./MutationState.vue";
import PemField from "./PemField.vue";

const props = defineProps<{ ca: PkiCaDetail }>();
const emit = defineEmits<{ activated: [ca: PkiCaDetail]; refresh: [] }>();

const OFFLINE_ROOT_DOCS = "https://zyno-io.github.io/hemlig/operations/pki-offline-root.html";

const TAB_OPTIONS = [
  { id: "ez", label: "EZ" },
  { id: "manual", label: "Manual" },
] as const;
type ActivationTab = (typeof TAB_OPTIONS)[number]["id"];
const [tab, selectTab] = useStoredTab<ActivationTab>(
  "hemlig.pki.activation-tab",
  ["ez", "manual"],
  "ez",
);
const commands = computed(() =>
  ezActivationCommands(
    {
      caId: props.ca.caId,
      environment: props.ca.environment,
      name: props.ca.name,
      spkiSha256: props.ca.key.spkiSha256,
    },
    window.location.origin,
  ),
);
// Without usable identifiers there are no EZ commands; show Manual only.
const activeTab = computed<ActivationTab>(() => (commands.value ? tab.value : "manual"));

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
    <div class="card-body pb-0">
      <EzManualTabs
        v-if="commands"
        id-prefix="activation"
        label="Activation method"
        :tabs="TAB_OPTIONS"
        :model-value="activeTab"
        @update:model-value="selectTab"
      />
    </div>

    <div
      v-if="commands && activeTab === 'ez'"
      id="activation-panel-ez"
      class="card-body space-y-5"
      role="tabpanel"
      aria-labelledby="activation-tab-ez"
      data-testid="activation-ez"
    >
      <p class="field-hint">
        Hemlig holds this intermediate's key. You sign its request with your offline
        root, using the Hemlig CLI. The CLI checks the request, signs it, keeps the
        root CRL current and activates the CA. See the
        <a class="link" :href="OFFLINE_ROOT_DOCS" target="_blank" rel="noopener noreferrer">offline root guide</a>.
      </p>

      <div class="space-y-2">
        <h3 class="text-[13px] font-semibold">On the machine that holds the root</h3>
        <CopyField label="Sign in" :value="commands.login" copy-only multiline />
        <CopyField label="Sign and activate" :value="commands.sign" copy-only multiline />
      </div>

      <div class="space-y-2">
        <h3 class="text-[13px] font-semibold">Air-gapped machine</h3>
        <p class="field-hint">
          Copy the request to the root machine. The SPKI SHA-256 pins the file to this CA.
        </p>
        <CopyField
          v-if="ca.csrPem"
          label="Certificate request"
          :value="ca.csrPem"
          multiline
          :filename="commands.csrFile"
        />
        <CopyField label="Sign offline" :value="commands.offlineSign" copy-only multiline />
        <p class="field-hint">
          Carry <span class="mono">{{ commands.csrFile.replace(".csr.pem", ".pem") }}</span>,
          <span class="mono">root.pem</span> and <span class="mono">root.crl.pem</span> to a
          machine that is online and signed in:
        </p>
        <CopyField label="Activate" :value="commands.activate" copy-only multiline />
      </div>

      <button type="button" class="btn btn-sm" data-testid="activation-refresh" @click="emit('refresh')">
        Refresh
      </button>
    </div>

    <form
      v-else
      id="activation-panel-manual"
      class="card-body space-y-5"
      role="tabpanel"
      aria-labelledby="activation-tab-manual"
      data-testid="activation-manual"
      @submit.prevent="submit"
    >
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
