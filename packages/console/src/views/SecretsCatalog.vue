<script setup lang="ts">
import { ref, watch } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { useCursorPages } from "../composables/useCursorPages";
import type { CatalogEntry } from "../api/schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string }>();
const store = useAppStore();

const pathPrefix = ref("");
const tags = ref("");
const applied = ref({ pathPrefix: "", tags: "" });

const pages = useCursorPages<CatalogEntry>(async (cursor) => {
  const page = await store.requireApi().listSecrets({
    environment: props.env,
    pathPrefix: applied.value.pathPrefix || undefined,
    tags: applied.value.tags || undefined,
    cursor,
  });
  return { items: page.secrets, nextCursor: page.nextCursor };
});

const reload = (): void => {
  pages.reset();
  void pages.loadMore();
};

// The cursor is bound to the actor and a hash of the filters, so any filter
// change invalidates it. Resetting is not an optimisation; sending the old
// cursor would be rejected.
watch(() => props.env, reload, { immediate: true });

const applyFilters = (): void => {
  applied.value = { pathPrefix: pathPrefix.value.trim(), tags: tags.value.trim() };
  reload();
};

const clearFilters = (): void => {
  pathPrefix.value = "";
  tags.value = "";
  applyFilters();
};
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-lg font-semibold">Secrets in {{ env }}</h1>
      <div class="flex gap-2">
        <button class="rounded border border-line px-3 py-1" :disabled="pages.loading.value" @click="reload">
          {{ pages.loading.value ? "Loading…" : "Refresh" }}
        </button>
        <RouterLink
          class="rounded bg-accent px-3 py-1 text-white"
          :to="{ name: 'secret-new', params: { env } }"
        >
          New secret
        </RouterLink>
      </div>
    </div>

    <form class="flex flex-wrap items-end gap-3 rounded border border-line bg-surface-raised p-3" @submit.prevent="applyFilters">
      <label class="flex flex-col gap-1">
        <span class="text-xs text-ink-muted">Path prefix</span>
        <input v-model="pathPrefix" class="w-64 rounded border border-line bg-surface px-2 py-1" placeholder="payments/stripe" />
      </label>
      <label class="flex flex-col gap-1">
        <span class="text-xs text-ink-muted">Tags (key:value, comma separated)</span>
        <input v-model="tags" class="w-80 rounded border border-line bg-surface px-2 py-1" placeholder="owner:payments,system:billing" />
      </label>
      <button class="rounded border border-line px-3 py-1" type="submit">Apply</button>
      <button class="rounded px-3 py-1 text-ink-muted" type="button" @click="clearFilters">Clear</button>
    </form>

    <ErrorNotice v-if="pages.error.value" :error="pages.error.value" />

    <table v-if="pages.items.value.length > 0" class="w-full border-collapse text-left">
      <thead class="text-xs uppercase tracking-wide text-ink-muted">
        <tr class="border-b border-line">
          <th class="py-2 pr-3 font-medium">Secret</th>
          <th class="py-2 pr-3 font-medium">Path</th>
          <th class="py-2 pr-3 font-medium">Tags</th>
          <th class="py-2 pr-3 font-medium">State</th>
          <th class="py-2 pr-3 font-medium">Entries</th>
          <th class="py-2 font-medium">Updated</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="secret in pages.items.value" :key="secret.secretId" class="border-b border-line/60">
          <td class="py-2 pr-3">
            <RouterLink
              class="text-accent hover:underline"
              :to="{ name: 'secret', params: { env, secretId: secret.secretId } }"
            >
              {{ secret.metadata.name }}
            </RouterLink>
            <div class="mono text-xs text-ink-muted">{{ secret.secretId }}</div>
          </td>
          <td class="mono py-2 pr-3 text-xs">{{ secret.metadata.path ?? "—" }}</td>
          <td class="py-2 pr-3 text-xs">
            <span
              v-for="(value, key) in secret.metadata.tags ?? {}"
              :key="key"
              class="mr-1 inline-block rounded bg-line/40 px-1.5 py-0.5"
            >{{ key }}:{{ value }}</span>
          </td>
          <td class="py-2 pr-3"><StateBadge :state="secret.state" /></td>
          <td class="py-2 pr-3 text-xs">{{ secret.payloadKeyCount ?? "—" }}</td>
          <td class="mono py-2 text-xs text-ink-muted">{{ secret.updatedAt ?? "—" }}</td>
        </tr>
      </tbody>
    </table>

    <!--
      A page is filtered after a bounded read, so an empty result with a cursor
      still outstanding does not mean there is nothing to find. "No secrets" is
      only truthful once the listing is exhausted.
    -->
    <p
      v-else-if="pages.exhausted.value && !pages.loading.value && !pages.error.value"
      class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
    >
      No secrets match in {{ env }}.
    </p>
    <p
      v-else-if="!pages.error.value"
      class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
    >
      Searching…
    </p>

    <div
      v-if="!pages.exhausted.value && pages.items.value.length > 0 && !pages.error.value"
      class="flex items-center gap-3"
    >
      <button class="rounded border border-line px-3 py-1" :disabled="pages.loading.value" @click="pages.loadMore()">
        {{ pages.loading.value ? "Loading…" : "Load more" }}
      </button>
      <span class="text-xs text-ink-muted">{{ pages.pagesFetched.value }} pages read</span>
    </div>
    <p
      v-else-if="!pages.exhausted.value && !pages.loading.value && !pages.error.value"
      class="text-xs text-ink-muted"
    >
      More pages remain but none matched yet.
      <button class="text-accent underline" @click="pages.loadMore()">Keep searching</button>
    </p>
  </div>
</template>
