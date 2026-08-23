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
  <div v-if="phase.kind === 'stale'" class="rounded border border-warn/50 bg-warn/5 p-4 text-sm">
    <p class="font-medium text-warn">This changed while you were editing.</p>
    <p class="mt-1">
      Someone else created a newer control revision, so your update was refused rather
      than silently overwriting theirs. Your draft is intact.
    </p>
    <p class="mt-1 text-ink-muted">
      Reload the current revision, re-apply your change, and submit again.
    </p>
    <button class="mt-3 rounded border border-line px-3 py-1" @click="$emit('reload')">
      Reload current revision
    </button>
  </div>

  <div v-else-if="phase.kind === 'unknown'" class="rounded border border-warn/50 bg-warn/5 p-4 text-sm">
    <p class="font-medium text-warn">The outcome is unknown.</p>
    <p class="mt-1">
      The request to {{ intent }} may or may not have been applied.
      <template v-if="phase.reconciling"> Checking what actually happened…</template>
    </p>
    <p v-if="!phase.reconciling && canRetry" class="mt-1 text-ink-muted">
      This operation replays safely, so retrying with the same key is correct.
    </p>
    <p v-else-if="!phase.reconciling" class="mt-1 text-ink-muted">
      Reload the secret and compare its revision before trying again — resubmitting could
      write it twice.
    </p>
    <div class="mt-3 flex gap-2">
      <button v-if="canRetry" class="rounded border border-line px-3 py-1" @click="$emit('retry')">
        Retry with the same key
      </button>
      <button class="rounded border border-line px-3 py-1" @click="$emit('reload')">
        Reload
      </button>
    </div>
  </div>

  <div v-else-if="phase.kind === 'reconciled-applied'" class="rounded border border-ok/50 bg-ok/5 p-4 text-sm">
    <p class="font-medium text-ok">It was applied after all.</p>
    <p class="mt-1">
      The connection failed but the change had already been committed. Nothing further is
      needed.
    </p>
  </div>

  <div v-else-if="phase.kind === 'reconciled-absent'" class="rounded border border-danger/50 bg-danger/5 p-4 text-sm">
    <p class="font-medium text-danger">It was not applied.</p>
    <p class="mt-1">
      The request failed and the secret is unchanged. Submitting again is safe; a fresh
      key will be used.
    </p>
  </div>

  <ErrorNotice v-else-if="phase.kind === 'failed'" :error="phase.error" />
</template>
