<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { rememberEnvironment, useAppStore } from "../stores/app";

const store = useAppStore();
const route = useRoute();
const router = useRouter();

const environments = computed(() => store.config?.environments ?? []);
const currentEnv = computed(() => String(route.params.env ?? environments.value[0] ?? ""));
const devMode = computed(() => store.config?.auth.mode === "dev-bridge");

const switchEnvironment = (event: Event): void => {
  const environment = (event.target as HTMLSelectElement).value;
  rememberEnvironment(environment);
  // Switching is a route change, which resets every cursor by construction.
  void router.push({ name: "secrets", params: { env: environment } });
};

const tabs = computed(() => [
  { name: "secrets", label: "Secrets", to: { name: "secrets", params: { env: currentEnv.value } } },
  { name: "consumers", label: "Consumers", to: { name: "consumers", params: { env: currentEnv.value } } },
  { name: "trust", label: "Trust", to: { name: "trust" } },
  { name: "about", label: "About", to: { name: "about" } },
]);

const active = (name: string): boolean => String(route.name ?? "").startsWith(name);
</script>

<template>
  <div class="min-h-screen">
    <header class="border-b border-line bg-surface-raised">
      <div class="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-6 py-3">
        <RouterLink :to="{ name: 'root' }" class="font-semibold tracking-tight">
          Hemlig
        </RouterLink>
        <span class="rounded border border-line px-2 py-0.5 text-xs text-ink-muted">
          {{ store.config?.deploymentName }}
        </span>
        <label class="flex items-center gap-2 text-sm">
          <span class="text-ink-muted">Environment</span>
          <select
            class="rounded border border-line bg-surface px-2 py-1"
            :value="currentEnv"
            @change="switchEnvironment"
          >
            <option v-for="environment in environments" :key="environment" :value="environment">
              {{ environment }}
            </option>
          </select>
        </label>
        <div class="ml-auto flex items-center gap-3 text-sm">
          <span v-if="devMode" class="rounded bg-warn/15 px-2 py-0.5 text-xs text-warn">
            dev bridge — no identity provider
          </span>
          <span class="text-ink-muted">{{ store.session?.displayName ?? store.session?.subject ?? "signed out" }}</span>
          <button
            v-if="!devMode && store.session"
            class="rounded border border-line px-2 py-1 hover:bg-surface"
            @click="store.signOut()"
          >
            Sign out
          </button>
          <button
            v-else-if="!devMode"
            class="rounded bg-accent px-2 py-1 text-white"
            @click="store.signIn()"
          >
            Sign in
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
