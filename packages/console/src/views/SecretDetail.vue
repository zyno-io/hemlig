<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();

const { data, error, isFetching, refetch } = useQuery({
  queryKey: computed(() => ["secret", props.secretId]),
  queryFn: () => store.requireApi().getSecret(props.secretId),
});
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'secrets', params: { env } }">
          ← Secrets
        </RouterLink>
        <h1 class="text-lg font-semibold">{{ data?.metadata.name ?? secretId }}</h1>
        <p class="mono text-xs text-ink-muted">{{ secretId }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button class="rounded border border-line px-3 py-1" :disabled="isFetching" @click="refetch()">
          {{ isFetching ? "Refreshing…" : "Refresh" }}
        </button>
        <RouterLink class="rounded border border-line px-3 py-1" :to="{ name: 'secret-revisions', params: { env, secretId } }">
          History
        </RouterLink>
        <RouterLink class="rounded border border-line px-3 py-1" :to="{ name: 'secret-metadata', params: { env, secretId } }">
          Edit metadata &amp; ACL
        </RouterLink>
        <RouterLink class="rounded bg-accent px-3 py-1 text-white" :to="{ name: 'secret-payload', params: { env, secretId } }">
          Replace payload
        </RouterLink>
      </div>
    </div>

    <ErrorNotice v-if="error" :error="error" />

    <div v-else-if="data" class="grid gap-4 md:grid-cols-2">
      <section class="rounded border border-line bg-surface-raised p-4">
        <h2 class="font-medium">Control revision</h2>
        <dl class="mt-3 grid grid-cols-[10rem_1fr] gap-y-1 text-xs">
          <dt class="text-ink-muted">State</dt>
          <dd><StateBadge :state="data.state" /></dd>
          <dt class="text-ink-muted">Environment</dt>
          <dd class="mono">{{ data.environment }}</dd>
          <dt class="text-ink-muted">Control version</dt>
          <dd class="mono break-all">{{ data.controlVersionId }}</dd>
          <dt class="text-ink-muted">Payload version</dt>
          <dd class="mono break-all">{{ data.payloadVersionId ?? "—" }}</dd>
          <dt class="text-ink-muted">Payload entries</dt>
          <dd class="mono">{{ data.payloadKeyCount ?? "unknown" }}</dd>
          <dt class="text-ink-muted">Created</dt>
          <dd class="mono">{{ data.createdAt }}</dd>
          <dt class="text-ink-muted">Created by</dt>
          <dd class="mono break-all">{{ data.createdBy.id }}</dd>
        </dl>
        <p v-if="data.state === 'PENDING_VALUE'" class="mt-3 rounded bg-warn/10 p-2 text-xs text-warn">
          This secret has no payload yet, so no consumer can read it. Set a payload to
          activate it.
        </p>
      </section>

      <section class="rounded border border-line bg-surface-raised p-4">
        <h2 class="font-medium">Metadata</h2>
        <dl class="mt-3 grid grid-cols-[10rem_1fr] gap-y-1 text-xs">
          <dt class="text-ink-muted">Name</dt>
          <dd>{{ data.metadata.name }}</dd>
          <dt class="text-ink-muted">Description</dt>
          <dd>{{ data.metadata.description ?? "—" }}</dd>
          <dt class="text-ink-muted">Path</dt>
          <dd class="mono">{{ data.metadata.path ?? "—" }}</dd>
        </dl>
        <div class="mt-2 text-xs">
          <span class="text-ink-muted">Tags</span>
          <div class="mt-1">
            <span
              v-for="(value, key) in data.metadata.tags ?? {}"
              :key="key"
              class="mr-1 inline-block rounded bg-line/40 px-1.5 py-0.5"
            >{{ key }}:{{ value }}</span>
            <span v-if="!data.metadata.tags" class="text-ink-muted">—</span>
          </div>
        </div>
        <p class="mt-3 text-xs text-ink-muted">
          Paths and tags are organisational only. They never select a delivery target or
          grant access.
        </p>
      </section>

      <section class="rounded border border-line bg-surface-raised p-4 md:col-span-2">
        <h2 class="font-medium">Access ({{ data.acl.length }} of 10)</h2>
        <ul v-if="data.acl.length > 0" class="mt-2 space-y-1">
          <li v-for="entry in data.acl" :key="entry.consumerId" class="flex items-center gap-2 text-xs">
            <RouterLink
              class="mono text-accent hover:underline"
              :to="{ name: 'consumer', params: { env, consumerId: entry.consumerId } }"
            >{{ entry.consumerId }}</RouterLink>
            <span class="rounded bg-line/40 px-1.5 py-0.5">{{ entry.permissions.join(", ") }}</span>
          </li>
        </ul>
        <p v-else class="mt-2 text-xs text-ink-muted">No consumer can read this secret.</p>
      </section>

      <section class="rounded border border-line bg-surface-raised p-4 md:col-span-2">
        <h2 class="font-medium">Payload</h2>
        <p class="mt-1 text-xs text-ink-muted">
          Payload values are never readable through the administrator API, by design.
          This console shows only how many entries exist
          <template v-if="data.payloadKeyCount !== undefined">
            (currently {{ data.payloadKeyCount }})</template>. Replacing a payload
          replaces every entry at once.
        </p>
      </section>
    </div>
  </div>
</template>
