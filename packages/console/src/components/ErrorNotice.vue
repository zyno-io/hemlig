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
  <div class="notice notice-danger" role="alert">
    <p class="flex items-start gap-2">
      <svg class="mt-0.5 shrink-0 text-danger" viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
        <path d="M8 1.5 15 14H1z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
        <path d="M8 6v3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        <circle cx="8" cy="11.6" r="0.9" fill="currentColor" />
      </svg>
      <span class="notice-title">{{ headline }}</span>
    </p>
    <div class="mt-1 space-y-1 pl-[21px]">
      <p v-if="context">{{ context }}</p>
      <p v-if="detail">{{ detail }}</p>
      <p v-if="transport" class="mono text-xs">{{ transport }}</p>
      <p v-if="guidance">{{ guidance }}</p>
      <p v-if="correlationId" class="flex flex-wrap items-center gap-2 pt-1 text-xs">
        <span class="mono text-ink">{{ correlationId }}</span>
        <button type="button" class="btn btn-sm" @click="copyCorrelation">
          Copy correlation ID
        </button>
      </p>
    </div>
  </div>
</template>
