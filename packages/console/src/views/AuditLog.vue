<script setup lang="ts">
import { ref, watch } from "vue";
import { useRoute } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useCursorPages } from "../composables/useCursorPages";
import type { AuditEvent } from "../api/schemas";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const route = useRoute();
const selectedDate = ref(new Date().toISOString().slice(0, 10));
const routeSecretId =
  typeof route.query.secretId === "string" ? route.query.secretId : "";
const secretId = ref(routeSecretId);
const appliedSecretId = ref(routeSecretId);
const pages = useCursorPages<AuditEvent>(async (cursor) => {
  const page = await store.requireApi().listAudit({
    date: selectedDate.value,
    ...(appliedSecretId.value.length === 0
      ? {}
      : { secretId: appliedSecretId.value }),
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
  <div class="space-y-4 text-sm">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold">Audit log</h1>
        <p class="mt-1 text-ink-muted">
          Immutable application evidence for one UTC day. Viewing this page is
          itself audited.
        </p>
      </div>
      <form
        class="flex flex-wrap items-end gap-2"
        @submit.prevent="applyFilter"
      >
        <label class="grid gap-1 text-xs text-ink-muted">
          Date (UTC)
          <input
            v-model="selectedDate"
            type="date"
            class="date-input rounded border border-line bg-surface px-2 py-1 text-sm text-ink"
          />
        </label>
        <label class="grid gap-1 text-xs text-ink-muted">
          Secret ID
          <input
            v-model="secretId"
            type="text"
            autocomplete="off"
            placeholder="All secrets"
            class="w-44 rounded border border-line bg-surface px-2 py-1 text-sm text-ink"
          />
        </label>
        <button
          type="submit"
          class="rounded border border-line px-3 py-1"
          :disabled="pages.loading.value"
        >
          Apply
        </button>
        <button
          type="button"
          class="rounded border border-line px-3 py-1"
          :disabled="pages.loading.value"
          @click="reload"
        >
          {{ pages.loading.value ? "Loading…" : "Refresh" }}
        </button>
      </form>
    </div>

    <ErrorNotice v-if="pages.error.value" :error="pages.error.value" />

    <div
      v-else-if="pages.items.value.length > 0"
      class="overflow-x-auto rounded border border-line"
    >
      <table class="w-full border-collapse text-left">
        <thead
          class="bg-surface-raised text-xs uppercase tracking-wide text-ink-muted"
        >
          <tr>
            <th class="px-3 py-2 font-medium">Time</th>
            <th class="px-3 py-2 font-medium">Outcome</th>
            <th class="px-3 py-2 font-medium">Actor</th>
            <th class="px-3 py-2 font-medium">Operation</th>
            <th class="px-3 py-2 font-medium">Target</th>
            <th class="px-3 py-2 font-medium">Source</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="event in pages.items.value"
            :key="event.eventId"
            class="border-t border-line/60 align-top"
          >
            <td class="mono whitespace-nowrap px-3 py-2 text-xs text-ink-muted">
              {{ event.at }}
            </td>
            <td class="px-3 py-2">
              <span class="rounded bg-surface-raised px-2 py-0.5 text-xs">{{
                event.outcome
              }}</span>
              <div v-if="event.reasonCode" class="mt-1 text-xs text-ink-muted">
                {{ event.reasonCode }}
              </div>
            </td>
            <td class="px-3 py-2">
              <span class="mono break-all text-xs">{{
                event.actor.email ?? event.actor.id
              }}</span>
              <div class="text-xs text-ink-muted">
                {{ actorType(event) }}
                <span v-if="event.actor.email">
                  · subject: {{ event.actor.id }}</span
                >
              </div>
            </td>
            <td class="mono break-all px-3 py-2 text-xs">
              {{ event.operation }}
            </td>
            <td class="break-all px-3 py-2 text-xs text-ink-muted">
              {{ target(event) }}
            </td>
            <td class="mono whitespace-nowrap px-3 py-2 text-xs text-ink-muted">
              {{ event.sourceIp ?? "—" }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <p
      v-else-if="pages.exhausted.value && !pages.loading.value"
      class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
    >
      No audit events were recorded on {{ selectedDate }} UTC<span
        v-if="appliedSecretId"
      >
        for {{ appliedSecretId }} </span
      >.
    </p>

    <p
      v-else-if="!pages.loading.value && pages.pagesFetched.value > 0"
      class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
    >
      No matching events appeared in the archive pages checked so far. More
      pages may still contain a match.
    </p>

    <button
      v-if="
        !pages.exhausted.value &&
        pages.pagesFetched.value > 0 &&
        !pages.error.value
      "
      class="rounded border border-line px-3 py-1"
      :disabled="pages.loading.value"
      @click="pages.loadMore()"
    >
      Load more
    </button>
  </div>
</template>
