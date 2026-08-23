<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, onUnmounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import {
  MAX_PAYLOAD_BYTES,
  inspectPayload,
  parseDotEnv,
  toPayload,
  type PayloadRow,
} from "../api/payload";
import type { ControlRevision } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();
const router = useRouter();

const { data, error, refetch } = useQuery({
  queryKey: computed(() => ["secret", props.secretId]),
  queryFn: () => store.requireApi().getSecret(props.secretId),
});

/**
 * Payload values live only here, for the lifetime of this component. They are
 * never written to the store, the query cache, the URL, or browser storage,
 * and they are cleared on unmount.
 */
const rows = ref<PayloadRow[]>([]);
const revealed = ref<Set<string>>(new Set());
const confirming = ref(false);
const importText = ref("");
const showImport = ref(false);
const loadedVersion = ref<string | undefined>();

watch(
  data,
  (revision) => {
    loadedVersion.value = revision?.controlVersionId;
  },
  { immediate: true },
);

onUnmounted(() => {
  rows.value = [];
  importText.value = "";
});

const addRow = (): void => {
  rows.value.push({ id: crypto.randomUUID(), key: "", value: "", encoding: "utf8" });
};
if (rows.value.length === 0) {
  addRow();
}

const problems = computed(() => inspectPayload(rows.value));
const percentUsed = computed(() =>
  Math.min(100, Math.round((problems.value.bytes / MAX_PAYLOAD_BYTES) * 100)),
);

const currentCount = computed(() => data.value?.payloadKeyCount);
const destroyed = computed(() => {
  const existing = currentCount.value;
  if (existing === undefined) {
    return undefined;
  }
  return Math.max(0, existing - rows.value.filter((row) => row.key.length > 0).length);
});

const toggleReveal = (id: string): void => {
  const next = new Set(revealed.value);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  revealed.value = next;
};

const applyImport = (): void => {
  const parsed = parseDotEnv(importText.value, () => crypto.randomUUID());
  if (parsed.length > 0) {
    rows.value = parsed;
  }
  importText.value = "";
  showImport.value = false;
};

const mutation = useGuardedMutation<{ controlVersionId: string; rows: PayloadRow[] }, ControlRevision>({
  family: "secret",
  mutate: (input, key) =>
    store
      .requireApi()
      .putPayload(props.secretId, input.controlVersionId, toPayload(input.rows), key),
  reconcile: async (input) => {
    const current = await store.requireApi().getSecret(props.secretId);
    return current.controlVersionId === input.controlVersionId ? undefined : current;
  },
});

const submit = async (): Promise<void> => {
  confirming.value = false;
  if (loadedVersion.value === undefined) {
    return;
  }
  const result = await mutation.submit({
    controlVersionId: loadedVersion.value,
    rows: rows.value,
  });
  if (result !== undefined) {
    rows.value = [];
    await router.push({ name: "secret", params: { env: props.env, secretId: props.secretId } });
  }
};

const reload = async (): Promise<void> => {
  mutation.reset();
  await refetch();
};
</script>

<template>
  <div class="max-w-3xl space-y-4 text-sm">
    <div>
      <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'secret', params: { env, secretId } }">
        ← {{ secretId }}
      </RouterLink>
      <h1 class="text-lg font-semibold">Replace payload</h1>
    </div>

    <div class="rounded border border-warn/50 bg-warn/5 p-3 text-xs text-warn">
      <p class="font-medium">This replaces the entire payload.</p>
      <p class="mt-1">
        Every entry must be supplied here. Anything not listed below is destroyed. The
        administrator API never returns payload values, so existing values cannot be
        pre-filled — only re-entered.
      </p>
    </div>

    <ErrorNotice v-if="error" :error="error" />
    <MutationState
      :phase="mutation.phase.value"
      intent="replace this payload"
      @reload="reload"
    />

    <div class="rounded border border-line bg-surface-raised p-4">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <span class="text-xs text-ink-muted">
          {{ rows.length }} entr{{ rows.length === 1 ? "y" : "ies" }}
          <template v-if="currentCount !== undefined">
            · currently stored: {{ currentCount }}
          </template>
        </span>
        <button type="button" class="rounded border border-line px-2 py-1 text-xs" @click="showImport = !showImport">
          Paste .env
        </button>
      </div>

      <div v-if="showImport" class="mb-3">
        <textarea
          v-model="importText"
          rows="5"
          spellcheck="false"
          autocomplete="off"
          placeholder="DATABASE_URL=postgres://…"
          class="mono w-full rounded border border-line bg-surface px-2 py-1 text-xs"
        />
        <p class="mt-1 text-xs text-ink-muted">
          Replaces all rows. Values are imported as utf8; nothing is guessed as base64,
          because guessing wrong silently corrupts a delivered secret.
        </p>
        <button type="button" class="mt-2 rounded border border-line px-2 py-1 text-xs" @click="applyImport">
          Replace rows with this
        </button>
      </div>

      <div v-for="row in rows" :key="row.id" class="mb-2 flex items-start gap-2">
        <input
          v-model="row.key"
          placeholder="username"
          spellcheck="false"
          autocomplete="off"
          class="mono w-52 rounded border border-line bg-surface px-2 py-1"
        />
        <select v-model="row.encoding" class="rounded border border-line bg-surface px-2 py-1 text-xs">
          <option value="utf8">utf8</option>
          <option value="base64">base64</option>
        </select>
        <div class="flex-1">
          <input
            v-model="row.value"
            :type="revealed.has(row.id) ? 'text' : 'password'"
            spellcheck="false"
            autocomplete="off"
            class="mono w-full rounded border border-line bg-surface px-2 py-1"
          />
          <span v-if="problems.rows.get(row.id)" class="text-xs text-danger">
            {{ problems.rows.get(row.id) }}
          </span>
        </div>
        <button type="button" class="rounded border border-line px-2 py-1 text-xs" @click="toggleReveal(row.id)">
          {{ revealed.has(row.id) ? "Hide" : "Show" }}
        </button>
        <button
          type="button"
          class="rounded border border-line px-2 py-1 text-xs"
          @click="rows = rows.filter((r) => r.id !== row.id)"
        >
          Remove
        </button>
      </div>

      <button type="button" class="mt-1 rounded border border-line px-2 py-1 text-xs" @click="addRow">
        Add entry
      </button>

      <p v-if="problems.duplicates.length > 0" class="mt-2 text-xs text-danger">
        Duplicate keys: {{ problems.duplicates.join(", ") }}
      </p>

      <div class="mt-4">
        <div class="flex justify-between text-xs" :class="problems.oversize ? 'text-danger' : 'text-ink-muted'">
          <span>{{ problems.bytes.toLocaleString() }} of {{ MAX_PAYLOAD_BYTES.toLocaleString() }} bytes</span>
          <span>{{ percentUsed }}%</span>
        </div>
        <div class="mt-1 h-1.5 overflow-hidden rounded bg-line">
          <div
            class="h-full"
            :class="problems.oversize ? 'bg-danger' : 'bg-accent'"
            :style="{ width: `${percentUsed}%` }"
          />
        </div>
      </div>

      <button
        class="mt-4 rounded bg-accent px-4 py-1.5 text-white disabled:opacity-50"
        :disabled="!problems.valid || mutation.phase.value.kind === 'submitting'"
        @click="confirming = true"
      >
        {{ mutation.phase.value.kind === "submitting" ? "Encrypting…" : "Replace payload" }}
      </button>
    </div>

    <div
      v-if="confirming"
      class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div class="w-full max-w-md rounded border border-line bg-surface-raised p-5">
        <h2 class="font-semibold">Replace the payload of {{ secretId }}?</h2>
        <p class="mt-2 text-sm">
          You are submitting {{ rows.filter((r) => r.key.length > 0).length }}
          entr{{ rows.filter((r) => r.key.length > 0).length === 1 ? "y" : "ies" }}.
        </p>
        <p v-if="destroyed !== undefined && destroyed > 0" class="mt-2 rounded bg-danger/10 p-2 text-sm text-danger">
          The stored payload has {{ currentCount }} entries, so this destroys
          {{ destroyed }} of them permanently. The API cannot tell you which — only how
          many.
        </p>
        <p v-else-if="destroyed === undefined" class="mt-2 rounded bg-warn/10 p-2 text-sm text-warn">
          This revision predates entry counting, so how many entries exist is unknown.
          Anything not listed will be destroyed.
        </p>
        <p class="mt-2 text-xs text-ink-muted">
          Every grant-holding consumer receives the new payload on its next
          reconciliation.
        </p>
        <div class="mt-4 flex justify-end gap-2">
          <button class="rounded border border-line px-3 py-1" @click="confirming = false">Cancel</button>
          <button class="rounded bg-danger px-3 py-1 text-white" @click="submit">Replace payload</button>
        </div>
      </div>
    </div>
  </div>
</template>
