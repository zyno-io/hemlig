<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import {
  MAX_PAYLOAD_BYTES,
  inspectPayload,
  parseDotEnv,
  parseJsonPayload,
  toDotEnv,
  toJsonText,
  toPayload,
  type Encoding,
  type PayloadRow,
} from "../api/payload";
import type { ControlRevision } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();
const router = useRouter();
const route = useRoute();
const queryClient = useQueryClient();

const { data, error, refetch } = useQuery({
  queryKey: computed(() => ["secret", props.env, props.secretId]),
  queryFn: () => store.requireApi().getSecret(props.env, props.secretId),
});

/**
 * Payload values live only here, for the lifetime of this component. They are
 * never written to the store, the query cache, the URL, or browser storage,
 * and they are cleared on unmount. The JSON and .env tabs are just other
 * views onto this same array, so that guarantee covers `jsonText` and
 * `envText` too -- they hold the payload in cleartext exactly as much as
 * `rows` does.
 */
const rows = ref<PayloadRow[]>([]);
const revealed = ref<Set<string>>(new Set());
const confirming = ref(false);
const loadedVersion = ref<string | undefined>();
const payloadError = ref<unknown>();
const payloadLoading = ref(false);
const payloadLoaded = ref(false);

/**
 * Encodings as last loaded from storage, keyed by entry key. Used only to
 * detect a base64→utf8 downgrade before submit; edits within a session that
 * never loaded the current payload have nothing to compare against, which is
 * correct -- the operator typed those values themselves and cannot be
 * surprised by them.
 */
const baselineEncodings = ref<ReadonlyMap<string, Encoding> | undefined>();

type Tab = "form" | "json" | "env";
const activeTab = ref<Tab>("form");
const jsonText = ref("");
const jsonError = ref<string | undefined>();
const envText = ref("");

watch(
  data,
  (revision) => {
    // Once plaintext is loaded, retain the version it was read with. A later
    // metadata refresh must cause a stale write to fail with 412, not let old
    // credentials overwrite a newer payload.
    if (!payloadLoaded.value) {
      loadedVersion.value = revision?.controlVersionId;
    }
  },
  { immediate: true },
);

onUnmounted(() => {
  rows.value = [];
  revealed.value = new Set();
  jsonText.value = "";
  envText.value = "";
  payloadError.value = undefined;
  baselineEncodings.value = undefined;
});

const addRow = (): void => {
  rows.value.push({
    id: crypto.randomUUID(),
    key: "",
    value: "",
    encoding: "utf8",
  });
};
if (rows.value.length === 0) {
  addRow();
}

const problems = computed(() => inspectPayload(rows.value));
const percentUsed = computed(() =>
  Math.min(100, Math.round((problems.value.bytes / MAX_PAYLOAD_BYTES) * 100)),
);

/** Entries in the base64 encoding right now -- the .env tab's own warning. */
const base64Keys = computed(() => toDotEnv(rows.value).lossyKeys);

/**
 * Entries that were base64 in the last-loaded stored payload but are utf8 now
 * -- the pre-submit warning. This is a separate signal from `base64Keys`
 * above: that one warns *before* a lossy edit happens (values are still
 * base64, the operator is about to open the .env tab); this one warns
 * *after* one already has (values have already become utf8), which is
 * exactly the case an operator must not discover only after submitting.
 */
const encodingDowngrades = computed(() => {
  const baseline = baselineEncodings.value;
  if (baseline === undefined) {
    return [];
  }
  return rows.value
    .filter(
      (row) =>
        row.key.length > 0 &&
        baseline.get(row.key) === "base64" &&
        row.encoding === "utf8",
    )
    .map((row) => row.key);
});

const currentCount = computed(() => data.value?.payloadKeyCount);
const isFirstPayload = computed(
  () => data.value?.payloadVersionId === undefined,
);
const destroyed = computed(() => {
  const existing = currentCount.value;
  if (existing === undefined) {
    return undefined;
  }
  return Math.max(
    0,
    existing - rows.value.filter((row) => row.key.length > 0).length,
  );
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

/**
 * Regenerates the text shown by whichever tab is now active from the
 * canonical `rows`. This only ever reads `rows` and writes tab text -- never
 * the reverse -- so switching tabs (or reloading the payload while a
 * non-Form tab is open) can never itself mutate an entry's encoding. Only a
 * genuine edit inside a textarea (see `onJsonInput` / `onEnvInput`) does
 * that.
 */
const refreshActiveTabText = (): void => {
  if (activeTab.value === "json") {
    jsonText.value = toJsonText(rows.value);
    jsonError.value = undefined;
  } else if (activeTab.value === "env") {
    envText.value = toDotEnv(rows.value).text;
  }
};

const selectTab = (tab: Tab): void => {
  if (tab === activeTab.value) {
    return;
  }
  if (activeTab.value === "json" && jsonError.value !== undefined) {
    // The JSON tab's text does not parse (or violates the payload rules), so
    // `rows` was never updated to match it. Switching away now would keep
    // showing the stale `rows` model elsewhere while silently discarding
    // what the operator typed here.
    return;
  }
  activeTab.value = tab;
  refreshActiveTabText();
};

const onJsonInput = (): void => {
  const result = parseJsonPayload(jsonText.value, () => crypto.randomUUID());
  if (result.ok) {
    rows.value = result.rows;
    jsonError.value = undefined;
  } else {
    // Keep the text exactly as typed; it is momentarily unparseable, not
    // wrong forever, and the operator's keystrokes are not disposable.
    jsonError.value = result.error;
  }
};

const onEnvInput = (): void => {
  // A real edit, not a programmatic refresh (see refreshActiveTabText):
  // setting a ref's value does not dispatch a DOM `input` event, so this only
  // runs from the operator's own keystrokes or paste. This is the one place
  // an entry's encoding may flip to utf8 as a side effect -- .env cannot
  // represent base64, so any edit here commits to losing it.
  rows.value = parseDotEnv(envText.value, () => crypto.randomUUID());
};

/**
 * Do not use a query here: plaintext must remain component-local and must not
 * enter the shared query cache. Payload reads are an explicit, audited action.
 */
const loadPayload = async (): Promise<void> => {
  payloadLoading.value = true;
  payloadError.value = undefined;
  try {
    const current = await store
      .requireApi()
      .getSecretPayload(props.env, props.secretId);
    rows.value = Object.entries(current.payload).map(([key, entry]) => ({
      id: crypto.randomUUID(),
      key,
      value: entry.value,
      encoding: entry.encoding,
    }));
    baselineEncodings.value = new Map(
      Object.entries(current.payload).map(([key, entry]) => [
        key,
        entry.encoding,
      ]),
    );
    revealed.value = new Set();
    refreshActiveTabText();
    loadedVersion.value = current.controlVersionId;
    payloadLoaded.value = true;
  } catch (error) {
    payloadError.value = error;
  } finally {
    payloadLoading.value = false;
  }
};

const mutation = useGuardedMutation<
  { controlVersionId: string; rows: PayloadRow[] },
  ControlRevision
>({
  family: "secret",
  mutate: (input, key) =>
    store
      .requireApi()
      .putPayload(
        props.env,
        props.secretId,
        input.controlVersionId,
        toPayload(input.rows),
        key,
      ),
  reconcile: async (input) => {
    const current = await store
      .requireApi()
      .getSecret(props.env, props.secretId);
    return current.controlVersionId === input.controlVersionId
      ? undefined
      : current;
  },
});

const canSubmit = computed(
  () => problems.value.valid && jsonError.value === undefined,
);

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
    // The successful PUT already returned the authoritative replacement
    // control revision, so update the cache before returning to the detail
    // page instead of rendering the old pending revision.
    queryClient.setQueryData<ControlRevision>(
      ["secret", props.env, props.secretId],
      result,
    );
    rows.value = [];
    await router.push({
      name: "secret",
      params: { env: props.env, secretId: props.secretId },
      query: route.query,
    });
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
      <RouterLink
        class="text-xs text-accent hover:underline"
        :to="{ name: 'secret', params: { env, secretId }, query: route.query }"
      >
        ← {{ secretId }}
      </RouterLink>
      <h1 class="text-lg font-semibold">Replace payload</h1>
    </div>

    <div class="rounded border border-warn/50 bg-warn/5 p-3 text-xs text-warn">
      <p class="font-medium">This replaces the entire payload.</p>
      <p class="mt-1">
        Loading the current payload is explicit and audited. Values remain only
        in this editor; anything not listed when you save is destroyed.
      </p>
    </div>

    <ErrorNotice v-if="error" :error="error" />
    <ErrorNotice
      v-if="payloadError"
      :error="payloadError"
      context="Could not load the current payload."
    />
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
        <div class="flex gap-1" role="tablist">
          <button
            v-for="tab in ['form', 'json', 'env'] as const"
            :key="tab"
            type="button"
            role="tab"
            :aria-selected="activeTab === tab"
            :disabled="
              activeTab === 'json' && jsonError !== undefined && tab !== 'json'
            "
            class="rounded border px-2 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-50"
            :class="
              activeTab === tab
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-line'
            "
            @click="selectTab(tab)"
          >
            {{ tab === "form" ? "Form" : tab === "json" ? "JSON" : ".env" }}
          </button>
        </div>
        <button
          type="button"
          class="rounded border border-line px-2 py-1 text-xs"
          :disabled="payloadLoading || data?.payloadVersionId === undefined"
          @click="loadPayload"
        >
          {{
            payloadLoading
              ? "Loading…"
              : payloadLoaded
                ? "Reload current payload"
                : "Load current payload"
          }}
        </button>
      </div>

      <div v-if="activeTab === 'form'">
        <div
          v-for="row in rows"
          :key="row.id"
          class="mb-2 flex items-start gap-2"
        >
          <input
            v-model="row.key"
            spellcheck="false"
            autocomplete="off"
            class="mono w-52 rounded border border-line bg-surface px-2 py-1"
          />
          <select
            v-model="row.encoding"
            class="rounded border border-line bg-surface px-2 py-1 text-xs"
          >
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
          <button
            type="button"
            class="rounded border border-line px-2 py-1 text-xs"
            @click="toggleReveal(row.id)"
          >
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

        <button
          type="button"
          class="mt-1 rounded border border-line px-2 py-1 text-xs"
          @click="addRow"
        >
          Add key
        </button>
      </div>

      <div v-else-if="activeTab === 'json'">
        <p class="mb-2 text-xs text-ink-muted">
          Wire format: each entry carries its own encoding, so this is
          <code class="mono">{{ "{ key: { encoding, value } }" }}</code
          >, not a flat key/value map.
        </p>
        <textarea
          v-model="jsonText"
          rows="10"
          spellcheck="false"
          autocomplete="off"
          class="mono w-full rounded border border-line bg-surface px-2 py-1 text-xs"
          :class="jsonError ? 'border-danger' : ''"
          @input="onJsonInput"
        />
        <p v-if="jsonError" class="mt-1 text-xs text-danger">{{ jsonError }}</p>
      </div>

      <div v-else>
        <p
          v-if="base64Keys.length > 0"
          class="mb-2 rounded bg-warn/10 p-2 text-xs text-warn"
        >
          <span class="font-medium">
            {{ base64Keys.length }} entr{{
              base64Keys.length === 1 ? "y" : "ies"
            }}
            ({{ base64Keys.join(", ") }})
            {{ base64Keys.length === 1 ? "is" : "are" }} base64-encoded.
          </span>
          .env cannot express an encoding. Editing here and submitting marks
          every entry utf8, including these -- that changes what gets delivered.
        </p>
        <textarea
          v-model="envText"
          rows="10"
          spellcheck="false"
          autocomplete="off"
          placeholder="DATABASE_URL=postgres://…"
          class="mono w-full rounded border border-line bg-surface px-2 py-1 text-xs"
          @input="onEnvInput"
        />
      </div>

      <p v-if="problems.duplicates.length > 0" class="mt-2 text-xs text-danger">
        Duplicate keys: {{ problems.duplicates.join(", ") }}
      </p>

      <div class="mt-4">
        <div
          class="flex justify-between text-xs"
          :class="problems.oversize ? 'text-danger' : 'text-ink-muted'"
        >
          <span
            >{{ problems.bytes.toLocaleString() }} of
            {{ MAX_PAYLOAD_BYTES.toLocaleString() }} bytes</span
          >
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
        :disabled="!canSubmit || mutation.phase.value.kind === 'submitting'"
        @click="confirming = true"
      >
        {{
          mutation.phase.value.kind === "submitting"
            ? "Encrypting…"
            : "Replace payload"
        }}
      </button>
    </div>

    <div
      v-if="confirming"
      class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div
        class="w-full max-w-md rounded border border-line bg-surface-raised p-5"
      >
        <h2 class="font-semibold">Replace the payload of {{ secretId }}?</h2>
        <p class="mt-2 text-sm">
          You are submitting
          {{ rows.filter((r) => r.key.length > 0).length }} entr{{
            rows.filter((r) => r.key.length > 0).length === 1 ? "y" : "ies"
          }}.
        </p>
        <p
          v-if="isFirstPayload"
          class="mt-2 rounded bg-accent/10 p-2 text-sm text-accent"
        >
          This is the first payload. Saving it activates the secret; no stored
          entries will be destroyed.
        </p>
        <p
          v-else-if="destroyed !== undefined && destroyed > 0"
          class="mt-2 rounded bg-danger/10 p-2 text-sm text-danger"
        >
          The stored payload has {{ currentCount }} entries, so this destroys
          {{ destroyed }} of them permanently. The API cannot tell you which —
          only how many.
        </p>
        <p
          v-else-if="destroyed === undefined"
          class="mt-2 rounded bg-warn/10 p-2 text-sm text-warn"
        >
          This revision predates entry counting, so how many entries exist is
          unknown. Anything not listed will be destroyed.
        </p>
        <p
          v-if="encodingDowngrades.length > 0"
          class="mt-2 rounded bg-danger/10 p-2 text-sm text-danger"
        >
          {{ encodingDowngrades.length }} entr{{
            encodingDowngrades.length === 1 ? "y" : "ies"
          }}
          ({{ encodingDowngrades.join(", ") }}) will change from base64 to utf8.
          The original bytes cannot be recovered from stored ciphertext once
          this is submitted.
        </p>
        <p class="mt-2 text-xs text-ink-muted">
          Every grant-holding consumer receives the new payload on its next
          reconciliation.
        </p>
        <div class="mt-4 flex justify-end gap-2">
          <button
            class="rounded border border-line px-3 py-1"
            @click="confirming = false"
          >
            Cancel
          </button>
          <button
            class="rounded bg-danger px-3 py-1 text-white"
            @click="submit"
          >
            Replace payload
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
