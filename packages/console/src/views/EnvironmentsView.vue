<script setup lang="ts">
import CreateEnvironmentForm from "../components/CreateEnvironmentForm.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useEnvironmentsQuery } from "../composables/useEnvironments";

// Outside the `/e/:env/...` tree deliberately: this view is not scoped to
// one environment, it defines them.
const environments = useEnvironmentsQuery();
</script>

<template>
  <div class="space-y-6 text-sm">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h1 class="text-lg font-semibold">Environments</h1>
        <p class="mt-1 max-w-2xl text-ink-muted">
          Administrator-defined records, bounded to 100. Every secret and every consumer
          belongs to exactly one.
        </p>
      </div>
      <button
        class="shrink-0 rounded border border-line px-3 py-1"
        :disabled="environments.isFetching.value"
        @click="environments.refetch()"
      >
        {{ environments.isFetching.value ? "Refreshing…" : "Refresh" }}
      </button>
    </div>

    <ErrorNotice v-if="environments.error.value" :error="environments.error.value" />

    <table
      v-else-if="environments.data.value && environments.data.value.environments.length > 0"
      class="w-full border-collapse text-left"
    >
      <thead class="text-xs uppercase tracking-wide text-ink-muted">
        <tr class="border-b border-line">
          <th class="py-2 pr-3 font-medium">Name</th>
          <th class="py-2 pr-3 font-medium">Created</th>
          <th class="py-2 font-medium">Created by</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="environment in environments.data.value.environments"
          :key="environment.name"
          class="border-b border-line/60"
        >
          <td class="py-2 pr-3">
            <RouterLink
              class="mono text-accent hover:underline"
              :to="{ name: 'secrets', params: { env: environment.name } }"
            >
              {{ environment.name }}
            </RouterLink>
          </td>
          <td class="mono py-2 pr-3 text-xs text-ink-muted">{{ environment.createdAt }}</td>
          <td class="mono py-2 text-xs text-ink-muted">{{ environment.createdBy.id }}</td>
        </tr>
      </tbody>
    </table>

    <p
      v-else-if="environments.data.value"
      class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
    >
      No environments are defined yet.
    </p>
    <p v-else class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted">
      Loading…
    </p>

    <section class="max-w-md rounded border border-line bg-surface-raised p-4">
      <h2 class="font-medium">Define a new environment</h2>
      <p class="mt-1 text-xs text-ink-muted">
        Creating one does not change what you are viewing here.
      </p>
      <CreateEnvironmentForm class="mt-3" :navigate-on-create="false" />
    </section>
  </div>
</template>
