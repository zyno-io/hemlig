<script setup lang="ts">
import { computed, ref } from "vue";
import CopyField from "../components/CopyField.vue";
import MutationState from "../components/MutationState.vue";
import { inspectCsr } from "../api/csr";
import { identifier } from "../api/payload";
import type { EnrollmentResult } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string }>();
const store = useAppStore();

const consumerId = ref("");
const csr = ref("");
const csrProblem = ref<string | undefined>();

const idError = computed(() =>
  consumerId.value.length > 0 && !identifier.test(consumerId.value)
    ? "3–64 characters: lowercase letters, digits, or hyphens, starting with a letter."
    : undefined,
);

interface EnrollInput {
  readonly consumerId: string;
  readonly environment: string;
  readonly apiCertificateSigningRequestPem: string;
}

const enrollment = useGuardedMutation<EnrollInput, EnrollmentResult>({
  family: "consumer",
  mutate: (input, key) => store.requireApi().enrollConsumer(input, key),
});

// Terminal failure is its own code precisely so it is never retried. The
// truststore bundle is built from issuer roots, not from this request, so a
// different CSR cannot repair it.
const terminal = computed(() => {
  const phase = enrollment.phase.value;
  return phase.kind === "failed" && phase.error.code === "enrollment_failed"
    ? phase.error
    : undefined;
});

const readFile = async (event: Event): Promise<void> => {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (file !== undefined) {
    csr.value = await file.text();
  }
};

const submit = async (): Promise<void> => {
  const problem = await inspectCsr(csr.value);
  csrProblem.value = problem?.message;
  if (problem !== undefined) {
    return;
  }
  await enrollment.submit({
    consumerId: consumerId.value,
    environment: props.env,
    apiCertificateSigningRequestPem: csr.value.trim(),
  });
};

const result = computed(() => enrollment.result.value);
</script>

<template>
  <div class="max-w-2xl space-y-4 text-sm">
    <div>
      <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'consumers', params: { env } }">
        ← Consumers
      </RouterLink>
      <h1 class="text-lg font-semibold">Enroll a consumer in {{ env }}</h1>
    </div>

    <div v-if="result" class="space-y-4">
      <div class="rounded border border-ok/50 bg-ok/5 p-4">
        <p class="font-medium text-ok">{{ result.consumerId }} is enrolled and active.</p>
        <p class="mt-1 text-xs">
          This certificate is shown once. Hemlig never received a private key — pair this
          with the key the operator already holds and present both for mTLS.
        </p>
      </div>
      <div class="space-y-3 rounded border border-line bg-surface-raised p-4">
        <CopyField label="Leaf fingerprint" :value="result.apiFingerprint" />
        <CopyField label="Root fingerprint" :value="result.rootFingerprint" />
        <CopyField label="Client certificate" :value="result.apiCertificatePem" multiline />
      </div>
      <RouterLink
        class="inline-block rounded bg-accent px-3 py-1 text-white"
        :to="{ name: 'consumer', params: { env, consumerId: result.consumerId } }"
      >
        Open consumer
      </RouterLink>
    </div>

    <template v-else>
      <div v-if="terminal" class="rounded border border-danger/50 bg-danger/5 p-4">
        <p class="font-medium text-danger">The enrollment failed terminally.</p>
        <p class="mt-1">{{ terminal.message }}</p>
        <p class="mt-2 text-xs text-ink-muted">
          Do not resubmit. The rejected truststore bundle is assembled from issuer roots,
          not from this certificate request, so a new CSR cannot repair it. An operator
          must inspect the issuer and truststore configuration.
        </p>
        <p v-if="terminal.correlationId" class="mono mt-2 text-xs">{{ terminal.correlationId }}</p>
      </div>
      <MutationState
        v-else
        :phase="enrollment.phase.value"
        :can-retry="enrollment.canRetry.value"
        intent="enroll this consumer"
        @retry="enrollment.retry()"
        @reload="enrollment.reset()"
      />

      <form class="space-y-4 rounded border border-line bg-surface-raised p-4" @submit.prevent="submit">
        <label class="block">
          <span class="text-xs text-ink-muted">Consumer ID</span>
          <input
            v-model="consumerId"
            required
            placeholder="prod-east"
            class="mono mt-1 w-full rounded border border-line bg-surface px-2 py-1"
          />
          <span v-if="idError" class="text-xs text-danger">{{ idError }}</span>
        </label>

        <div>
          <span class="text-xs text-ink-muted">Certificate signing request (PEM)</span>
          <textarea
            v-model="csr"
            rows="8"
            spellcheck="false"
            placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            class="mono mt-1 w-full rounded border border-line bg-surface px-2 py-1 text-xs"
          />
          <input type="file" accept=".pem,.csr,.txt" class="mt-2 text-xs" @change="readFile" />
          <p v-if="csrProblem" class="mt-1 text-xs text-danger">{{ csrProblem }}</p>
          <p class="mt-1 text-xs text-ink-muted">
            The operator generates the key pair and keeps the private key. Hemlig signs
            the public key as a client-auth leaf with a SPIFFE URI naming this consumer;
            the subject and extensions in your request do not control that identity.
          </p>
        </div>

        <button
          class="rounded bg-accent px-4 py-1.5 text-white disabled:opacity-50"
          :disabled="!identifier.test(consumerId) || enrollment.phase.value.kind === 'submitting'"
          type="submit"
        >
          {{ enrollment.phase.value.kind === "submitting" ? "Enrolling…" : "Enroll consumer" }}
        </button>
        <p class="text-xs text-ink-muted">
          Enrollment publishes the truststore and waits for API Gateway to confirm it, so
          this can take a few seconds.
        </p>
      </form>
    </template>
  </div>
</template>
