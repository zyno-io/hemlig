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
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">Consumers in {{ env }}</h1>
      </div>
      <div class="page-actions">
        <button class="btn" :disabled="pages.loading.value" @click="reload">
          {{ pages.loading.value ? "Loading…" : "Refresh" }}
        </button>
        <RouterLink class="btn btn-primary" :to="{ name: 'consumer-new', params: { env } }">
          Enroll consumer
        </RouterLink>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="pages.error.value" :error="pages.error.value" />

      <div v-if="pages.items.value.length > 0" class="card overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Consumer</th>
              <th>Status</th>
              <th>Active leaves</th>
              <th>Enrolled</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="consumer in pages.items.value" :key="consumer.consumerId">
              <td>
                <RouterLink
                  class="mono link"
                  :to="{ name: 'consumer', params: { env, consumerId: consumer.consumerId } }"
                >{{ consumer.consumerId }}</RouterLink>
                <div class="mono text-xs text-ink-3">{{ consumer.subjectUri }}</div>
              </td>
              <td><StateBadge :state="consumer.status" /></td>
              <td class="text-xs">{{ consumer.activeApiIdentityCount ?? "—" }}</td>
              <td class="mono text-xs text-ink-3">{{ consumer.createdAt }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="pages.exhausted.value && !pages.loading.value && !pages.error.value" class="card">
        <div class="empty-state">
          <p class="empty-state-title">No consumers are enrolled in {{ env }}.</p>
        </div>
      </div>

      <button
        v-if="!pages.exhausted.value && pages.items.value.length > 0 && !pages.error.value"
        class="btn"
        :disabled="pages.loading.value"
        @click="pages.loadMore()"
      >
        Load more
      </button>
    </div>
  </div>
</template>
