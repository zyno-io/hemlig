<script setup lang="ts">
import { computed } from "vue";
import { ApiError } from "../api/errors";

const props = defineProps<{ error: unknown; context?: string }>();

const api = computed(() => (props.error instanceof ApiError ? props.error : undefined));

const reasonSuffix = (reason: string | undefined): string =>
  reason === undefined ? "" : ` (${reason})`;

const pkiRoleRequired = computed(
  () => api.value?.code === "forbidden" && api.value.reason === "pki_role_required",
);

const headline = computed(() => {
  const error = api.value;
  if (error === undefined) {
    return "Something went wrong.";
  }
  if (pkiRoleRequired.value) {
    return `Your account lacks the PKI ${String(error.details?.role ?? "required")} role.`;
  }
  switch (error.code) {
    case "ca_not_active":
      return `The CA is not active${reasonSuffix(error.reason)}.`;
    case "ca_subject_in_use":
      return "That subject name is already claimed. Subject names are never reused.";
    case "chain_invalid":
      return `The certificate or chain was refused${reasonSuffix(error.reason)}.`;
    case "crl_invalid":
      return `The CRL was refused${reasonSuffix(error.reason)}.`;
    case "crl_not_newer":
      return "That CRL is not newer than the stored one.";
    case "ca_issuance_budget_exceeded":
      return "capacity + 2 × issuance per hour must not exceed 12,000.";
    case "ca_key_unavailable":
      return "The CA key is temporarily unavailable.";
    case "ca_capacity_exceeded":
      return "The CA is at its certificate capacity.";
    case "issuance_rate_limited":
      return "Issuance is rate limited.";
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
      switch (error.reason) {
        case undefined:
        case "idempotency_key_reused":
          return "That idempotency key was already used.";
        case "name_in_use":
          return "That CA name is already taken. CA names are never reused.";
        case "grant_exists":
          return "A grant with that name already exists for this consumer.";
        case "key_not_disabled":
          return "The CA key must be disabled before it can be destroyed.";
        default:
          return "That conflicts with the current state.";
      }
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
  if (error?.code === "forbidden" && !pkiRoleRequired.value) {
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
const reason = computed(() => api.value?.reason);
// Only these two detail keys are rendered besides the reason: details can carry
// request echo that must not reach the screen.
const detailString = (key: string): string | undefined => {
  const value = api.value?.details?.[key];
  return typeof value === "string" ? value : undefined;
};
const detailPath = computed(() => detailString("path"));
const deniedName = computed(() => detailString("deniedName"));
const retryAfterSeconds = computed(() => api.value?.retryAfterSeconds);
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
      <p v-if="retryAfterSeconds !== undefined">
        Retry after {{ retryAfterSeconds }} {{ retryAfterSeconds === 1 ? "second" : "seconds" }}.
      </p>
      <p v-if="reason" class="text-xs">
        Reason: <span class="mono text-ink">{{ reason }}</span>
      </p>
      <p v-if="detailPath" class="text-xs">
        Path: <span class="mono text-ink">{{ detailPath }}</span>
      </p>
      <p v-if="deniedName" class="text-xs">
        Denied name: <span class="mono text-ink">{{ deniedName }}</span>
      </p>
      <p v-if="correlationId" class="flex flex-wrap items-center gap-2 pt-1 text-xs">
        <span class="mono text-ink">{{ correlationId }}</span>
        <button type="button" class="btn btn-sm" @click="copyCorrelation">
          Copy correlation ID
        </button>
      </p>
    </div>
  </div>
</template>
