<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();

const { data, error, isFetching, refetch } = useQuery({
  queryKey: computed(() => ["revisions", props.secretId]),
  queryFn: () => store.requireApi().listRevisions(props.secretId),
});
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex items-center justify-between">
      <div>
        <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'secret', params: { env, secretId } }">
          ← {{ secretId }}
        </RouterLink>
        <h1 class="text-lg font-semibold">Revision history</h1>
      </div>
      <button class="rounded border border-line px-3 py-1" :disabled="isFetching" @click="refetch()">
        {{ isFetching ? "Refreshing…" : "Refresh" }}
      </button>
    </div>

    <ErrorNotice v-if="error" :error="error" />

    <div v-else-if="data">
      <p v-if="data.truncated" class="mb-3 rounded bg-warn/10 p-2 text-xs text-warn">
        This secret has more revisions than the response returns. Only the newest are
        shown.
      </p>
      <table class="w-full border-collapse text-left">
        <thead class="text-xs uppercase tracking-wide text-ink-muted">
          <tr class="border-b border-line">
            <th class="py-2 pr-3 font-medium">Created</th>
            <th class="py-2 pr-3 font-medium">Control version</th>
            <th class="py-2 pr-3 font-medium">Payload version</th>
            <th class="py-2 pr-3 font-medium">Entries</th>
            <th class="py-2 pr-3 font-medium">By</th>
            <th class="py-2 font-medium">Object</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="revision in data.revisions" :key="revision.controlVersionId" class="border-b border-line/60">
            <td class="mono py-2 pr-3 text-xs">{{ revision.createdAt }}</td>
            <td class="mono py-2 pr-3 text-xs break-all">
              {{ revision.controlVersionId }}
              <span v-if="revision.isCurrent" class="ml-1 rounded bg-ok/15 px-1.5 py-0.5 text-ok">current</span>
            </td>
            <td class="mono py-2 pr-3 text-xs break-all">{{ revision.payloadVersionId ?? "—" }}</td>
            <td class="py-2 pr-3 text-xs">{{ revision.payloadKeyCount ?? "—" }}</td>
            <td class="mono py-2 pr-3 text-xs break-all">{{ revision.createdBy.id }}</td>
            <td class="py-2 text-xs">
              <span v-if="revision.objectAvailable" class="text-ink-muted">retained</span>
              <span v-else class="text-ink-muted" title="Retention removed the immutable object after its Object Lock window">
                expired
              </span>
            </td>
          </tr>
        </tbody>
      </table>
      <p class="mt-3 text-xs text-ink-muted">
        History is control-plane state, not audit evidence. Revisions whose object has
        expired remain listed because the record survives retention even though the
        stored body does not.
      </p>
    </div>
  </div>
</template>
