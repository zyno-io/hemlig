<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter, type RouteLocationRaw } from "vue-router";
import { useEnvironmentsQuery } from "../composables/useEnvironments";
import { rememberEnvironment, useAppStore } from "../stores/app";

const store = useAppStore();
const route = useRoute();
const router = useRouter();

// App.vue mounts the authenticated shell only after a session exists. The
// shell and root resolver share this query key, so only one fetch is made.
const environments = useEnvironmentsQuery();
const environmentNames = computed(
  () => environments.data.value?.environments.map((e) => e.name) ?? [],
);

const currentEnv = computed(() => {
  const fromRoute = route.params.env;
  return typeof fromRoute === "string" ? fromRoute : environmentNames.value[0];
});
const devMode = computed(() => store.config?.auth.mode === "dev-bridge");

// A neutral placeholder while there is nothing real to select from, rather
// than an empty (and misleadingly interactive-looking) dropdown.
const switcherPlaceholder = computed(() => {
  if (environments.error.value) {
    return "Unavailable";
  }
  return environments.data.value === undefined ? "Loading…" : "No environments yet";
});

const switchEnvironment = (event: Event): void => {
  const environment = (event.target as HTMLSelectElement).value;
  rememberEnvironment(environment);
  // Switching is a route change, which resets every cursor by construction.
  void router.push({ name: "secrets", params: { env: environment } });
};

const tabs = computed(() => {
  const items: { name: string; label: string; to: RouteLocationRaw }[] = [];
  // These two are meaningless without a known environment to scope into, and
  // there may genuinely be none yet on a fresh deployment.
  if (currentEnv.value !== undefined) {
    items.push(
      { name: "secrets", label: "Secrets", to: { name: "secrets", params: { env: currentEnv.value } } },
      { name: "consumers", label: "Consumers", to: { name: "consumers", params: { env: currentEnv.value } } },
    );
  }
  items.push(
    { name: "environments", label: "Environments", to: { name: "environments" } },
    { name: "trust", label: "Trust", to: { name: "trust" } },
    { name: "about", label: "About", to: { name: "about" } },
  );
  return items;
});

const active = (name: string): boolean => String(route.name ?? "").startsWith(name);
</script>

<template>
  <div class="min-h-screen">
    <header class="border-b border-line bg-surface-raised">
      <div class="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-6 py-3">
        <RouterLink :to="{ name: 'root' }" class="font-semibold tracking-tight">
          Hemlig
        </RouterLink>
        <label class="flex items-center gap-2 text-sm">
          <span class="text-ink-muted">Environment</span>
          <select
            class="rounded border border-line bg-surface px-2 py-1"
            :disabled="environmentNames.length === 0"
            :value="currentEnv"
            @change="switchEnvironment"
          >
            <option v-if="environmentNames.length === 0" value="">{{ switcherPlaceholder }}</option>
            <option v-for="environment in environmentNames" :key="environment" :value="environment">
              {{ environment }}
            </option>
          </select>
          <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'environments' }">
            Manage
          </RouterLink>
        </label>
        <div class="ml-auto flex items-center gap-3 text-sm">
          <span v-if="devMode" class="rounded bg-warn/15 px-2 py-0.5 text-xs text-warn">
            dev bridge — no identity provider
          </span>
          <span class="text-ink-muted">{{ store.session?.displayName ?? store.session?.subject }}</span>
          <button
            v-if="!devMode"
            class="rounded border border-line px-2 py-1 hover:bg-surface"
            @click="store.signOut()"
          >
            Sign out
          </button>
        </div>
      </div>
      <nav class="mx-auto flex max-w-6xl gap-1 px-6">
        <RouterLink
          v-for="tab in tabs"
          :key="tab.name"
          :to="tab.to"
          class="border-b-2 px-3 py-2 text-sm"
          :class="active(tab.name) ? 'border-accent text-ink' : 'border-transparent text-ink-muted hover:text-ink'"
        >
          {{ tab.label }}
        </RouterLink>
      </nav>
    </header>
    <main class="mx-auto max-w-6xl px-6 py-6">
      <slot />
    </main>
  </div>
</template>
