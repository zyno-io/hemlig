<script setup lang="ts">
import { computed, watch } from "vue";
import { useRouter } from "vue-router";
import CreateEnvironmentForm from "../components/CreateEnvironmentForm.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import { useEnvironmentsQuery } from "../composables/useEnvironments";
import { recallEnvironment } from "../stores/app";

/**
 * `/` used to be a synchronous redirect straight into `/e/<env>/secrets`.
 * The environment list is administrator-defined API state.
 * App.vue mounts this route only after authentication, so the resolver can
 * safely fetch it and decide where to send the operator without guessing.
 */
const router = useRouter();

const environments = useEnvironmentsQuery();

const names = computed(() => environments.data.value?.environments.map((e) => e.name) ?? []);

// Fires once a non-empty list is available (including after a retry). A
// remembered name that is no longer in the list is a stale per-viewer hint,
// not something to send to the API — it is dropped in favour of the first
// defined environment rather than passed through.
watch(
  () => environments.data.value,
  (data) => {
    if (data === undefined || data.environments.length === 0) {
      return;
    }
    const remembered = recallEnvironment();
    const target =
      remembered !== undefined && names.value.includes(remembered) ? remembered : names.value[0]!;
    void router.replace({ name: "secrets", params: { env: target } });
  },
  { immediate: true },
);
</script>

<template>
  <div v-if="environments.error.value" class="mx-auto max-w-lg space-y-3 p-8 text-sm">
    <ErrorNotice :error="environments.error.value" context="loading environments" />
    <button
      class="rounded border border-line px-3 py-1"
      :disabled="environments.isFetching.value"
      @click="environments.refetch()"
    >
      {{ environments.isFetching.value ? "Retrying…" : "Retry" }}
    </button>
  </div>

  <div v-else-if="environments.data.value === undefined" class="p-8 text-center text-sm text-ink-muted">
    Loading environments…
  </div>

  <div v-else-if="names.length === 0" class="mx-auto max-w-xl px-6 py-10 text-sm">
    <section class="rounded border border-line bg-surface-raised p-6">
      <h1 class="text-lg font-semibold">Define your first environment</h1>
      <p class="mt-2 text-ink-muted">
        Hemlig has no built-in notion of dev, staging, or prod — environments are
        administrator-defined records, and this deployment does not have any yet. Every
        secret and every consumer belongs to exactly one, so there is nothing to browse
        until at least one exists.
      </p>
      <div class="mt-5 border-t border-line pt-5">
        <CreateEnvironmentForm />
      </div>
    </section>
  </div>

  <div v-else class="p-8 text-center text-sm text-ink-muted">Redirecting…</div>
</template>
