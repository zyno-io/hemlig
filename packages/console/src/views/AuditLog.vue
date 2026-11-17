<script setup lang="ts">
import { ref, watch } from "vue";
import { useRoute } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { useCursorPages } from "../composables/useCursorPages";
import type { AuditEvent } from "../api/schemas";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const route = useRoute();
const selectedDate = ref(new Date().toISOString().slice(0, 10));
const routeSecretId =
  typeof route.query.secretId === "string" ? route.query.secretId : "";
const routeEnvironment =
  typeof route.query.environment === "string" ? route.query.environment : "";
const secretId = ref(routeSecretId);
const environment = ref(routeEnvironment);
const appliedSecretId = ref(routeSecretId);
const appliedEnvironment = ref(routeEnvironment);
const pages = useCursorPages<AuditEvent>(async (cursor) => {
  const page = await store.requireApi().listAudit({
    date: selectedDate.value,
    ...(appliedSecretId.value.length === 0
      ? {}
      : { secretId: appliedSecretId.value }),
    ...(appliedEnvironment.value.length === 0
      ? {}
      : { environment: appliedEnvironment.value }),
    cursor,
  });
  return { items: page.events, nextCursor: page.nextCursor };
});

const reload = (): void => {
  pages.reset();
  void pages.loadMore();
};

const applyFilter = (): void => {
  appliedSecretId.value = secretId.value.trim();
  appliedEnvironment.value = environment.value.trim();
  reload();
};

const actorType = (event: AuditEvent): string =>
  event.actor.type === "human"
    ? "Admin"
    : event.actor.type.charAt(0).toUpperCase() + event.actor.type.slice(1);

const target = (event: AuditEvent): string =>
  event.target === undefined
    ? "—"
    : Object.entries(event.target)
        .map(([key, value]) => `${key}: ${value}`)
        .join(", ");

watch(selectedDate, reload, { immediate: true });
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">Audit log</h1>
        <p class="page-subtitle">
          Immutable application evidence for one UTC day. Viewing this page is
          itself audited.
        </p>
      </div>
    </div>

    <div class="space-y-4">
      <form
        class="card card-body flex flex-wrap items-end gap-3"
        @submit.prevent="applyFilter"
      >
        <label class="block">
          <span class="field-label">Date (UTC)</span>
          <input v-model="selectedDate" type="date" class="input date-input mono w-auto" />
        </label>
        <label class="block">
          <span class="field-label">Secret ID</span>
          <input
            v-model="secretId"
            type="text"
            autocomplete="off"
            placeholder="All secrets"
            class="input mono w-44"
          />
        </label>
        <label class="block">
          <span class="field-label">Environment</span>
          <input
            v-model="environment"
            type="text"
            autocomplete="off"
            placeholder="All environments"
            class="input mono w-36"
          />
        </label>
        <button type="submit" class="btn" :disabled="pages.loading.value">
          Apply
        </button>
        <button type="button" class="btn" :disabled="pages.loading.value" @click="reload">
          {{ pages.loading.value ? "Loading…" : "Refresh" }}
        </button>
      </form>

      <ErrorNotice v-if="pages.error.value" :error="pages.error.value" />

      <div v-else-if="pages.items.value.length > 0" class="card overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Outcome</th>
              <th>Actor</th>
              <th>Operation</th>
              <th>Target</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="event in pages.items.value" :key="event.eventId">
              <td class="mono whitespace-nowrap text-xs text-ink-3">
                {{ event.at }}
              </td>
              <td>
                <StateBadge :state="event.outcome" />
                <div v-if="event.reasonCode" class="mt-1 text-xs text-ink-3">
                  {{ event.reasonCode }}
                </div>
              </td>
              <td>
                <span class="mono break-all text-xs">{{
                  event.actor.email ?? event.actor.id
                }}</span>
                <div class="text-xs text-ink-3">
                  {{ actorType(event) }}
                  <span v-if="event.actor.email">
                    · subject: <span class="mono">{{ event.actor.id }}</span></span
                  >
                </div>
              </td>
              <td class="mono break-all text-xs">
                {{ event.operation }}
              </td>
              <td class="mono break-all text-xs text-ink-3">
                {{ target(event) }}
              </td>
              <td class="mono whitespace-nowrap text-xs text-ink-3">
                {{ event.sourceIp ?? "—" }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="pages.exhausted.value && !pages.loading.value" class="card">
        <div class="empty-state">
          <p class="empty-state-title">
            No audit events were recorded on {{ selectedDate }} UTC<span
              v-if="appliedSecretId"
            >
              for {{ appliedSecretId }} </span
            >.
          </p>
        </div>
      </div>

      <div
        v-else-if="!pages.loading.value && pages.pagesFetched.value > 0"
        class="card"
      >
        <div class="empty-state">
          <p class="empty-state-title">
            No matching events appeared in the archive pages checked so far. More
            pages may still contain a match.
          </p>
        </div>
      </div>

      <button
        v-if="
          !pages.exhausted.value &&
          pages.pagesFetched.value > 0 &&
          !pages.error.value
        "
        class="btn"
        :disabled="pages.loading.value"
        @click="pages.loadMore()"
      >
        Load more
      </button>
    </div>
  </div>
</template>
