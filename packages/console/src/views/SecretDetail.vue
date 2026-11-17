<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import type { SecretReadResponse } from "../api/schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{
  env: string;
  secretId: string;
  archivedSecretUid?: string;
}>();
const store = useAppStore();
const route = useRoute();
const router = useRouter();
const queryClient = useQueryClient();
const isArchivedView = computed(() => props.archivedSecretUid !== undefined);

const { data, error, isFetching, refetch } = useQuery({
  queryKey: computed(() => [
    "secret",
    props.env,
    props.secretId,
    props.archivedSecretUid,
  ]),
  queryFn: () => {
    if (props.archivedSecretUid !== undefined) {
      return store
        .requireApi()
        .getArchivedSecret(props.env, props.archivedSecretUid);
    }
    return store.requireApi().getSecret(props.env, props.secretId);
  },
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
    payload.value = await store
      .requireApi()
      .getSecretPayload(props.env, props.secretId);
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
  () => [props.env, props.secretId],
  () => hidePayload(),
);

const queryValue = (name: string): string | undefined => {
  const value = route.query[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

const catalogReturnQuery = computed(() => ({
  ...(queryValue("catalogFilter") === undefined
    ? {}
    : { catalogFilter: queryValue("catalogFilter") }),
  ...(isArchivedView.value ? { archived: "true" } : {}),
}));

const catalogBackTo = computed(() => {
  const path = queryValue("catalogPath");
  return path === undefined
    ? {
        name: "secrets",
        params: { env: props.env },
        query: catalogReturnQuery.value,
      }
    : {
        name: "secrets-browse",
        params: { env: props.env, path: path.split("/") },
        query: catalogReturnQuery.value,
      };
});

const secretSubpageTo = (
  name: "secret-metadata" | "secret-payload" | "secret-revisions",
) => ({
  name,
  params: { env: props.env, secretId: props.secretId },
  query: route.query,
});

const archiving = ref(false);
const archiveError = ref<unknown>();

const archiveSecret = async (): Promise<void> => {
  if (data.value === undefined || isArchivedView.value || archiving.value) {
    return;
  }
  if (
    !window.confirm(
      `Archive ${data.value.secretId}? It will disappear from active searches and its ID can be reused.`,
    )
  ) {
    return;
  }
  archiving.value = true;
  archiveError.value = undefined;
  try {
    await store
      .requireApi()
      .archiveSecret(
        props.env,
        props.secretId,
        data.value.controlVersionId,
        crypto.randomUUID(),
      );
    queryClient.removeQueries({ queryKey: ["secrets-tree", props.env] });
    queryClient.removeQueries({ queryKey: ["secrets-search", props.env] });
    await router.push(catalogBackTo.value);
  } catch (requestError) {
    archiveError.value = requestError;
  } finally {
    archiving.value = false;
  }
};

const folderPath = (secretId: string): string | undefined => {
  const separator = secretId.lastIndexOf("/");
  return separator === -1 ? undefined : secretId.slice(0, separator);
};

const displayedSecretId = computed(() =>
  isArchivedView.value
    ? (data.value?.secretId ?? props.secretId)
    : props.secretId,
);

// A secret's prefix is its folder. It is identity, not editable metadata.
const pathTo = computed(() => {
  const path = folderPath(displayedSecretId.value);
  return path !== undefined && path.length > 0
    ? {
        name: "secrets-browse",
        params: { env: props.env, path: path.split("/") },
        query: isArchivedView.value ? { archived: "true" } : {},
      }
    : {
        name: "secrets",
        params: { env: props.env },
        query: isArchivedView.value ? { archived: "true" } : {},
      };
});
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink class="link text-xs" :to="catalogBackTo">
          ← Secrets
        </RouterLink>
        <h1 class="page-title mono">{{ displayedSecretId }}</h1>
      </div>
      <div class="page-actions">
        <button class="btn" :disabled="isFetching" @click="refetch()">
          {{ isFetching ? "Refreshing…" : "Refresh" }}
        </button>
        <RouterLink
          v-if="!isArchivedView"
          class="btn"
          :to="secretSubpageTo('secret-revisions')"
        >
          History
        </RouterLink>
        <RouterLink
          v-if="!isArchivedView"
          class="btn"
          :to="{ name: 'audit', query: { environment: env, secretId } }"
        >
          Audit log
        </RouterLink>
        <RouterLink
          v-if="!isArchivedView"
          class="btn"
          :to="secretSubpageTo('secret-metadata')"
        >
          Edit metadata &amp; ACL
        </RouterLink>
        <RouterLink
          v-if="!isArchivedView"
          class="btn btn-primary"
          :to="secretSubpageTo('secret-payload')"
        >
          Replace payload
        </RouterLink>
        <button
          v-if="!isArchivedView"
          class="btn btn-danger"
          :disabled="archiving || !data"
          @click="archiveSecret"
        >
          {{ archiving ? "Archiving…" : "Archive secret" }}
        </button>
      </div>
    </div>

    <ErrorNotice v-if="error" :error="error" />
    <ErrorNotice v-else-if="archiveError" :error="archiveError" />

    <div v-else-if="data" class="grid gap-4 md:grid-cols-2">
      <section class="card card-body">
        <h2 class="section-title">Control revision</h2>
        <dl class="facts mt-3">
          <dt>State</dt>
          <dd><StateBadge :state="data.state" /></dd>
          <dt>Environment</dt>
          <dd class="mono">{{ data.environment }}</dd>
          <dt>Control version</dt>
          <dd class="mono break-all">{{ data.controlVersionId }}</dd>
          <dt>Payload version</dt>
          <dd class="mono break-all">{{ data.payloadVersionId ?? "—" }}</dd>
          <dt>Payload entries</dt>
          <dd class="mono">{{ data.payloadKeyCount ?? "unknown" }}</dd>
          <dt>Created</dt>
          <dd class="mono">{{ data.createdAt }}</dd>
          <dt>Created by</dt>
          <dd class="mono break-all">{{ data.createdBy.id }}</dd>
        </dl>
        <p v-if="data.state === 'PENDING_VALUE'" class="notice notice-warning mt-3">
          This secret has no payload yet, so no consumer can read it. Set a
          payload to activate it.
        </p>
        <p v-else-if="data.state === 'ARCHIVED'" class="notice mt-3">
          This immutable record is archived. Its former secret ID may now be
          used by a new active secret.
        </p>
      </section>

      <section class="card card-body">
        <h2 class="section-title">Metadata</h2>
        <dl class="facts mt-3">
          <dt>Description</dt>
          <dd>{{ data.metadata.description ?? "—" }}</dd>
          <dt>Folder</dt>
          <dd>
            <RouterLink class="mono link" :to="pathTo">
              {{ folderPath(displayedSecretId) ?? "Root" }}
            </RouterLink>
          </dd>
        </dl>
        <div class="mt-3 text-[13px]">
          <span class="text-ink-3">Tags</span>
          <div class="mt-1 flex flex-wrap gap-1">
            <span
              v-for="(value, key) in data.metadata.tags ?? {}"
              :key="key"
              class="tag mono"
              >{{ key }}:{{ value }}</span
            >
            <span v-if="!data.metadata.tags" class="text-ink-3">—</span>
          </div>
        </div>
        <p class="meta mt-3">
          Folders are derived from the secret ID. Tags are organisational only
          and never select a delivery target or grant access.
        </p>
      </section>

      <section class="card md:col-span-2">
        <div class="card-header">
          <h2 class="section-title">Access ({{ data.acl.length }} of 40)</h2>
        </div>
        <ul v-if="data.acl.length > 0" class="card-rows">
          <li
            v-for="entry in data.acl"
            :key="entry.consumerId"
            class="row flex items-center gap-2 text-xs"
          >
            <RouterLink
              class="mono link"
              :to="{
                name: 'consumer',
                params: { env, consumerId: entry.consumerId },
              }"
              >{{ entry.consumerId }}</RouterLink
            >
            <span class="tag">{{ entry.permissions.join(", ") }}</span>
          </li>
        </ul>
        <p v-else class="card-body text-[13px] text-ink-3">
          No consumer can read this secret.
        </p>
      </section>

      <section v-if="!isArchivedView" class="card md:col-span-2">
        <div class="card-header">
          <h2 class="section-title">Payload</h2>
          <button
            v-if="payload !== undefined"
            type="button"
            class="btn btn-sm"
            @click="hidePayload"
          >
            Hide
          </button>
          <button
            v-else
            type="button"
            class="btn btn-sm"
            :disabled="payloadLoading || data.payloadVersionId === undefined"
            @click="revealPayload"
          >
            {{ payloadLoading ? "Revealing…" : "Reveal" }}
          </button>
        </div>
        <div class="card-body">
          <p class="meta">
            <template v-if="data.payloadKeyCount !== undefined">
              {{ data.payloadKeyCount }}
              {{ data.payloadKeyCount === 1 ? "entry" : "entries" }}.
            </template>
            Revealing values is a deliberate audited action. Values remain only in
            this page until you hide them or leave it.
          </p>
          <ErrorNotice
            v-if="payloadError"
            class="mt-3"
            :error="payloadError"
            context="Could not reveal the current payload."
          />
        </div>
        <div v-if="payload !== undefined" class="overflow-x-auto border-t border-line">
          <table class="data-table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Encoding</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(entry, key) in payload.payload" :key="key">
                <td class="mono text-xs">{{ key }}</td>
                <td class="mono text-xs">{{ entry.encoding }}</td>
                <td class="mono whitespace-pre-wrap break-all text-xs">
                  {{ entry.value }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
