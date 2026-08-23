<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, onUnmounted, ref, watch } from "vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import type { SecretReadResponse } from "../api/schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();

const { data, error, isFetching, refetch } = useQuery({
  queryKey: computed(() => ["secret", props.secretId]),
  queryFn: () => store.requireApi().getSecret(props.secretId),
});

/**
 * Plaintext is deliberately component-local: it never enters vue-query, the
 * application store, a URL, or browser storage. Fetching it is an explicit
 * audited request, and leaving this detail view clears it.
 */
const payload = ref<SecretReadResponse | undefined>();
const payloadError = ref<unknown>();
const payloadLoading = ref(false);

const revealPayload = async (): Promise<void> => {
  payloadLoading.value = true;
  payloadError.value = undefined;
  try {
    payload.value = await store.requireApi().getSecretPayload(props.secretId);
  } catch (requestError) {
    payloadError.value = requestError;
  } finally {
    payloadLoading.value = false;
  }
};

const hidePayload = (): void => {
  payload.value = undefined;
  payloadError.value = undefined;
};

onUnmounted(hidePayload);
watch(
  () => props.secretId,
  () => hidePayload(),
);

// Links the path to where it actually lives in the tree — the folder view
// this secret would show up under — rather than leaving it as inert text
// with no route out of this screen.
const pathTo = computed(() => {
  const path = data.value?.metadata.path;
  return path !== undefined && path.length > 0
    ? { name: "secrets-browse", params: { env: props.env, path: path.split("/") } }
    : { name: "secrets", params: { env: props.env } };
});
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'secrets', params: { env } }">
          ← Secrets
        </RouterLink>
        <h1 class="mono text-lg font-semibold">{{ secretId }}</h1>
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
          <dt class="text-ink-muted">Description</dt>
          <dd>{{ data.metadata.description ?? "—" }}</dd>
          <dt class="text-ink-muted">Path</dt>
          <dd class="flex items-center gap-2">
            <RouterLink class="mono text-accent hover:underline" :to="pathTo">
              {{ data.metadata.path ?? "Root" }}
            </RouterLink>
            <RouterLink
              class="text-accent hover:underline"
              :to="{ name: 'secret-metadata', params: { env, secretId } }"
            >
              Move
            </RouterLink>
          </dd>
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
        <h2 class="font-medium">Access ({{ data.acl.length }} of 40)</h2>
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
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h2 class="font-medium">Payload</h2>
          <button
            v-if="payload !== undefined"
            type="button"
            class="rounded border border-line px-2 py-1 text-xs"
            @click="hidePayload"
          >
            Hide
          </button>
          <button
            v-else
            type="button"
            class="rounded border border-line px-2 py-1 text-xs"
            :disabled="payloadLoading || data.payloadVersionId === undefined"
            @click="revealPayload"
          >
            {{ payloadLoading ? "Revealing…" : "Reveal" }}
          </button>
        </div>
        <p class="mt-1 text-xs text-ink-muted">
          <template v-if="data.payloadKeyCount !== undefined">
            {{ data.payloadKeyCount }}
            {{ data.payloadKeyCount === 1 ? "entry" : "entries" }}.
          </template>
          Revealing values is a deliberate, separately audited action. Values
          remain only in this page until you hide them or leave it; replacing a
          payload still replaces every entry at once.
        </p>
        <ErrorNotice
          v-if="payloadError"
          class="mt-3"
          :error="payloadError"
          context="Could not reveal the current payload."
        />
        <div v-if="payload !== undefined" class="mt-3 overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="text-ink-muted">
              <tr>
                <th class="pb-1 pr-3 font-medium">Key</th>
                <th class="pb-1 pr-3 font-medium">Encoding</th>
                <th class="pb-1 font-medium">Value</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(entry, key) in payload.payload" :key="key" class="border-t border-line">
                <td class="mono py-2 pr-3 align-top">{{ key }}</td>
                <td class="mono py-2 pr-3 align-top">{{ entry.encoding }}</td>
                <td class="mono whitespace-pre-wrap break-all py-2">{{ entry.value }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
