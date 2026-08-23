<script setup lang="ts">
import { watch } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { useCursorPages } from "../composables/useCursorPages";
import type { ConsumerSummary } from "../api/schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string }>();
const store = useAppStore();

const pages = useCursorPages<ConsumerSummary>(async (cursor) => {
  const page = await store.requireApi().listConsumers({ environment: props.env, cursor });
  return { items: page.consumers, nextCursor: page.nextCursor };
});

const reload = (): void => {
  pages.reset();
  void pages.loadMore();
};
watch(() => props.env, reload, { immediate: true });
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold">Consumers in {{ env }}</h1>
      <div class="flex gap-2">
        <button class="rounded border border-line px-3 py-1" :disabled="pages.loading.value" @click="reload">
          {{ pages.loading.value ? "Loading…" : "Refresh" }}
        </button>
        <RouterLink class="rounded bg-accent px-3 py-1 text-white" :to="{ name: 'consumer-new', params: { env } }">
          Enroll consumer
        </RouterLink>
      </div>
    </div>

    <ErrorNotice v-if="pages.error.value" :error="pages.error.value" />

    <table v-if="pages.items.value.length > 0" class="w-full border-collapse text-left">
      <thead class="text-xs uppercase tracking-wide text-ink-muted">
        <tr class="border-b border-line">
          <th class="py-2 pr-3 font-medium">Consumer</th>
          <th class="py-2 pr-3 font-medium">Status</th>
          <th class="py-2 pr-3 font-medium">Active leaves</th>
          <th class="py-2 font-medium">Enrolled</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="consumer in pages.items.value" :key="consumer.consumerId" class="border-b border-line/60">
          <td class="py-2 pr-3">
            <RouterLink
              class="mono text-accent hover:underline"
              :to="{ name: 'consumer', params: { env, consumerId: consumer.consumerId } }"
            >{{ consumer.consumerId }}</RouterLink>
            <div class="mono text-xs text-ink-muted">{{ consumer.subjectUri }}</div>
          </td>
          <td class="py-2 pr-3"><StateBadge :state="consumer.status" /></td>
          <td class="py-2 pr-3 text-xs">{{ consumer.activeApiIdentityCount ?? "—" }}</td>
          <td class="mono py-2 text-xs text-ink-muted">{{ consumer.createdAt }}</td>
        </tr>
      </tbody>
    </table>

    <p v-else-if="pages.exhausted.value && !pages.loading.value && !pages.error.value" class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted">
      No consumers are enrolled in {{ env }}.
    </p>

    <button
      v-if="!pages.exhausted.value && pages.items.value.length > 0 && !pages.error.value"
      class="rounded border border-line px-3 py-1"
      :disabled="pages.loading.value"
      @click="pages.loadMore()"
    >
      Load more
    </button>
  </div>
</template>
