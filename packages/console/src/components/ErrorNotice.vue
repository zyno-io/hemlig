<script setup lang="ts">
import { computed } from "vue";
import { ApiError } from "../api/errors";

const props = defineProps<{ error: unknown; context?: string }>();

const api = computed(() => (props.error instanceof ApiError ? props.error : undefined));

const headline = computed(() => {
  const error = api.value;
  if (error === undefined) {
    return "Something went wrong.";
  }
  switch (error.code) {
    case "unauthorized":
      // API Gateway rejected the token before Hemlig ran. Re-authenticating helps.
      return "Your session was rejected. Sign in again.";
    case "forbidden":
      // Hemlig accepted a token the gateway had already validated, then refused
      // it. That is a deployment configuration mismatch, not a stale session —
      // signing in again would loop.
      return "This deployment rejected a token the gateway accepted.";
    case "not_found":
      return "Not found.";
    case "conflict":
      return "That idempotency key was already used.";
    case "enrollment_failed":
      return "The enrollment failed terminally.";
    case "precondition_failed":
      return "This changed while you were editing it.";
    case "service_unavailable":
      return "Hemlig is temporarily unavailable.";
    case "network":
      return "The request did not reach Hemlig.";
    default:
      return "The request failed.";
  }
});

const guidance = computed(() => {
  const error = api.value;
  if (error?.code === "forbidden") {
    return "The API Gateway authorizer and the Hemlig handler disagree about the issuer, audience, or required scope. An operator must reconcile the deployment configuration; signing in again will not help.";
  }
  if (error?.code === "enrollment_failed") {
    return "The truststore bundle is built from issuer roots, not from the submitted request, so resubmitting a different CSR will not repair it. An operator must inspect the issuer and truststore.";
  }
  return undefined;
});

const rawDetail = computed(() => api.value?.message ?? String(props.error));
// Several codes have a headline that already says exactly what the message
// says; repeating it reads like a rendering bug.
const detail = computed(() =>
  rawDetail.value === headline.value ? undefined : rawDetail.value,
);
const correlationId = computed(() => api.value?.correlationId);
const transport = computed(() => api.value?.transportDetail);

const copyCorrelation = async (): Promise<void> => {
  if (correlationId.value !== undefined) {
    await navigator.clipboard.writeText(correlationId.value);
  }
};
</script>

<template>
  <div class="rounded border border-danger/40 bg-danger/5 p-4 text-sm">
    <p class="font-medium text-danger">{{ headline }}</p>
    <p v-if="context" class="mt-1 text-ink-muted">{{ context }}</p>
    <p v-if="detail" class="mt-1">{{ detail }}</p>
    <p v-if="transport" class="mono mt-1 text-xs text-ink-muted">{{ transport }}</p>
    <p v-if="guidance" class="mt-2 text-ink-muted">{{ guidance }}</p>
    <p v-if="correlationId" class="mt-3 flex items-center gap-2 text-xs text-ink-muted">
      <span class="mono">{{ correlationId }}</span>
      <button class="rounded border border-line px-2 py-0.5" @click="copyCorrelation">
        Copy correlation ID
      </button>
    </p>
  </div>
</template>
