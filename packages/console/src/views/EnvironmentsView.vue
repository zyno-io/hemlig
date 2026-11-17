<script setup lang="ts">
import CreateEnvironmentForm from "../components/CreateEnvironmentForm.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useEnvironmentsQuery } from "../composables/useEnvironments";

// Outside the `/e/:env/...` tree deliberately: this view is not scoped to
// one environment, it defines them.
const environments = useEnvironmentsQuery();
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">Environments</h1>
        <p class="page-subtitle">
          Administrator-defined records, bounded to 100. Every secret and every consumer
          belongs to exactly one.
        </p>
      </div>
      <div class="page-actions">
        <button
          class="btn"
          :disabled="environments.isFetching.value"
          @click="environments.refetch()"
        >
          {{ environments.isFetching.value ? "Refreshing…" : "Refresh" }}
        </button>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="environments.error.value" :error="environments.error.value" />

      <div
        v-else-if="environments.data.value && environments.data.value.environments.length > 0"
        class="card overflow-x-auto"
      >
        <table class="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Created by</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="environment in environments.data.value.environments"
              :key="environment.name"
            >
              <td>
                <RouterLink
                  class="mono link"
                  :to="{ name: 'secrets', params: { env: environment.name } }"
                >
                  {{ environment.name }}
                </RouterLink>
              </td>
              <td class="mono text-xs text-ink-3">{{ environment.createdAt }}</td>
              <td class="mono text-xs text-ink-3">{{ environment.createdBy.id }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="environments.data.value" class="card">
        <div class="empty-state">
          <p class="empty-state-title">No environments are defined yet.</p>
        </div>
      </div>
      <div v-else class="card">
        <div class="empty-state">
          <p class="empty-state-title">Loading…</p>
        </div>
      </div>

      <section class="card card-body max-w-md">
        <h2 class="section-title">Define a new environment</h2>
        <p class="field-hint">
          Creating one does not change what you are viewing here.
        </p>
        <CreateEnvironmentForm class="mt-3" :navigate-on-create="false" />
      </section>
    </div>
  </div>
</template>
