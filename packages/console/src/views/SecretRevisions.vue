<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed } from "vue";
import { useRoute } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();
const route = useRoute();

const { data, error, isFetching, refetch } = useQuery({
  queryKey: computed(() => ["revisions", props.env, props.secretId]),
  queryFn: () => store.requireApi().listRevisions(props.env, props.secretId),
});
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink
          class="link text-xs"
          :to="{
            name: 'secret',
            params: { env, secretId },
            query: route.query,
          }"
        >
          ← {{ secretId }}
        </RouterLink>
        <h1 class="page-title">Revision history</h1>
      </div>
      <div class="page-actions">
        <button class="btn" :disabled="isFetching" @click="refetch()">
          {{ isFetching ? "Refreshing…" : "Refresh" }}
        </button>
      </div>
    </div>

    <ErrorNotice v-if="error" :error="error" />

    <div v-else-if="data" class="space-y-4">
      <p v-if="data.truncated" class="notice notice-warning">
        This secret has more revisions than the response returns. Only the
        newest are shown.
      </p>
      <div class="card overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Control version</th>
              <th>Payload version</th>
              <th>Entries</th>
              <th>By</th>
              <th>Object</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="revision in data.revisions"
              :key="revision.controlVersionId"
            >
              <td class="mono text-xs">{{ revision.createdAt }}</td>
              <td class="mono text-xs break-all">
                {{ revision.controlVersionId }}
                <span v-if="revision.isCurrent" class="tag tag-success ml-1">current</span>
              </td>
              <td class="mono text-xs break-all">
                {{ revision.payloadVersionId ?? "—" }}
              </td>
              <td class="text-xs">
                {{ revision.payloadKeyCount ?? "—" }}
              </td>
              <td class="mono text-xs break-all">
                {{ revision.createdBy.id }}
              </td>
              <td class="text-xs">
                <span v-if="revision.objectAvailable" class="text-ink-3">retained</span>
                <span
                  v-else
                  class="text-ink-3"
                  title="Retention removed the immutable object after its Object Lock window"
                >
                  expired
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="meta">
        History is control-plane state, not audit evidence. Revisions whose
        object has expired remain listed because the record survives retention
        even though the stored body does not.
      </p>
    </div>
  </div>
</template>
