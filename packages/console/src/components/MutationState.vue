<script setup lang="ts">
import ErrorNotice from "./ErrorNotice.vue";
import type { MutationPhase } from "../composables/useGuardedMutation";

defineProps<{
  phase: MutationPhase;
  canRetry?: boolean;
  /** What the caller was trying to do, for the ambiguous-outcome copy. */
  intent: string;
}>();
defineEmits<{ retry: []; reload: [] }>();
</script>

<template>
  <div v-if="phase.kind === 'stale'" class="notice notice-warning" role="status">
    <p class="notice-title">This changed while you were editing.</p>
    <p class="mt-1">
      Someone else created a newer control revision, so your update was refused rather
      than silently overwriting theirs. Your draft is intact.
    </p>
    <p class="mt-1">
      Reload the current revision, re-apply your change, and submit again.
    </p>
    <button type="button" class="btn mt-3" @click="$emit('reload')">
      Reload current revision
    </button>
  </div>

  <div v-else-if="phase.kind === 'unknown'" class="notice notice-warning" role="status">
    <p class="notice-title">The outcome is unknown.</p>
    <p class="mt-1">
      The request to {{ intent }} may or may not have been applied.
      <template v-if="phase.reconciling"> Checking what actually happened…</template>
    </p>
    <p v-if="!phase.reconciling && canRetry" class="mt-1">
      This operation replays safely, so retrying with the same key is correct.
    </p>
    <p v-else-if="!phase.reconciling" class="mt-1">
      Reload the secret and compare its revision before trying again — resubmitting could
      write it twice.
    </p>
    <div class="mt-3 flex gap-2">
      <button v-if="canRetry" type="button" class="btn" @click="$emit('retry')">
        Retry with the same key
      </button>
      <button type="button" class="btn" @click="$emit('reload')">
        Reload
      </button>
    </div>
  </div>

  <div v-else-if="phase.kind === 'reconciled-applied'" class="notice notice-success" role="status">
    <p class="notice-title">It was applied after all.</p>
    <p class="mt-1">
      The connection failed but the change had already been committed. Nothing further is
      needed.
    </p>
  </div>

  <div v-else-if="phase.kind === 'reconciled-absent'" class="notice notice-danger" role="status">
    <p class="notice-title">It was not applied.</p>
    <p class="mt-1">
      The request failed and the secret is unchanged. Submitting again is safe; a fresh
      key will be used.
    </p>
  </div>

  <ErrorNotice v-else-if="phase.kind === 'failed'" :error="phase.error" />
</template>
