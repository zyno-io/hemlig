<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter, type RouteLocationRaw } from "vue-router";
import { useEnvironmentsQuery } from "../composables/useEnvironments";
import { rememberEnvironment, useAppStore } from "../stores/app";
import ThemeMenu from "./ThemeMenu.vue";

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
  return environments.data.value === undefined
    ? "Loading…"
    : "No environments yet";
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
      {
        name: "secrets",
        label: "Secrets",
        to: { name: "secrets", params: { env: currentEnv.value } },
      },
      {
        name: "consumers",
        label: "Consumers",
        to: { name: "consumers", params: { env: currentEnv.value } },
      },
    );
  }
  items.push(
    {
      name: "environments",
      label: "Environments",
      to: { name: "environments" },
    },
    { name: "audit", label: "Audit", to: { name: "audit" } },
    { name: "trust", label: "Trust", to: { name: "trust" } },
    { name: "about", label: "About", to: { name: "about" } },
  );
  return items;
});

// "secrets" also covers secret, secret-new, secret-metadata…; likewise consumers.
const active = (name: string): boolean =>
  String(route.name ?? "").startsWith(name.replace(/s$/, ""));
</script>

<template>
  <div class="min-h-screen">
    <a href="#main" class="skip-link">Skip to content</a>
    <header class="topbar">
      <div class="topbar-row">
        <RouterLink :to="{ name: 'root' }" class="brand" aria-label="Hemlig home">
          <span class="brand-mark" aria-hidden="true">
            <!-- A keyhole: hemlig is Swedish for secret. -->
            <svg viewBox="0 0 16 16" width="14" height="14">
              <circle cx="8" cy="6.25" r="2.6" fill="currentColor" />
              <path d="M6.6 7.6h2.8l.9 5.15H5.7z" fill="currentColor" />
            </svg>
          </span>
          <span class="brand-name">Hemlig</span>
        </RouterLink>

        <label class="env-switcher">
          <span class="sr-only">Environment</span>
          <select
            class="input env-select mono"
            :disabled="environmentNames.length === 0"
            :value="currentEnv"
            @change="switchEnvironment"
          >
            <option v-if="environmentNames.length === 0" value="">
              {{ switcherPlaceholder }}
            </option>
            <option
              v-for="environment in environmentNames"
              :key="environment"
              :value="environment"
            >
              {{ environment }}
            </option>
          </select>
        </label>

        <nav class="primary-nav" aria-label="Primary">
          <RouterLink
            v-for="tab in tabs"
            :key="tab.name"
            :to="tab.to"
            class="nav-link"
            :class="{ 'nav-link-active': active(tab.name) }"
            :aria-current="active(tab.name) ? 'page' : undefined"
          >
            {{ tab.label }}
          </RouterLink>
        </nav>

        <div class="topbar-end">
          <span v-if="devMode" class="tag tag-warning" title="Local dev bridge: no identity provider">
            Dev bridge
          </span>
          <span class="session-name meta">{{
            store.session?.displayName ?? store.session?.subject
          }}</span>
          <ThemeMenu />
          <button v-if="!devMode" type="button" class="btn btn-ghost" @click="store.signOut()">
            Sign out
          </button>
        </div>
      </div>
    </header>
    <main id="main" class="page" tabindex="-1">
      <slot />
    </main>
  </div>
</template>

<style scoped>
.skip-link {
  position: fixed;
  top: 8px;
  left: 8px;
  z-index: 100;
  padding: 8px 12px;
  border-radius: var(--r-md);
  background: var(--accent);
  color: var(--accent-text);
  font-size: 13px;
  font-weight: 500;
  transform: translateY(-200%);
  transition: transform 0.15s ease-out;
}

.skip-link:focus-visible {
  transform: none;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 40;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  backdrop-filter: saturate(1.4) blur(10px);
  -webkit-backdrop-filter: saturate(1.4) blur(10px);
}

.topbar-row {
  display: flex;
  min-height: var(--header-h);
  align-items: center;
  gap: 12px;
  padding: 0 16px;
}

.brand {
  display: inline-flex;
  flex-shrink: 0;
  align-items: center;
  gap: 8px;
  border-radius: var(--r-sm);
}

.brand-mark {
  display: inline-grid;
  width: 24px;
  height: 24px;
  place-items: center;
  border-radius: 6px;
  background: var(--text);
  color: var(--bg);
}

.brand-name {
  font-size: 14px;
  font-weight: 650;
  color: var(--text);
}

.env-switcher {
  flex-shrink: 0;
}

.env-select {
  width: auto;
  max-width: 180px;
  font-size: 12px;
}

.primary-nav {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 2px;
  overflow-x: auto;
  scrollbar-width: none;
}

.nav-link {
  flex-shrink: 0;
  padding: 6px 10px;
  border-radius: var(--r-sm);
  color: var(--text-2);
  font-size: 13px;
  font-weight: 500;
  line-height: 1;
  transition:
    background-color 0.12s,
    color 0.12s;
}

/* The scrolling nav clips outward rings; draw focus inside the link. */
.nav-link:focus-visible {
  outline-offset: -2px;
}

.nav-link:hover {
  background: var(--surface-2);
  color: var(--text);
}

.nav-link-active,
.nav-link-active:hover {
  background: var(--surface-3);
  color: var(--text);
}

.topbar-end {
  display: flex;
  flex-shrink: 0;
  align-items: center;
  gap: 8px;
  margin-left: auto;
}

.session-name {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

#main:focus {
  outline: none;
}

@media (max-width: 1100px) {
  .session-name {
    display: none;
  }
}

/* The nav moves to its own scrollable row rather than squeezing the bar. */
@media (max-width: 900px) {
  .topbar-row {
    flex-wrap: wrap;
    row-gap: 0;
  }

  .primary-nav {
    order: 3;
    width: 100%;
    margin: 0 -6px;
    padding: 0 0 8px;
  }
}

@media (max-width: 640px) {
  .brand-name {
    display: none;
  }
}

@media (max-width: 360px) {
  .topbar-row {
    gap: 8px;
    padding: 0 8px;
  }
}
</style>
