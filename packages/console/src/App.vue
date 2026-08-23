<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import AppShell from "./components/AppShell.vue";
import { useAppStore } from "./stores/app";

const store = useAppStore();
const route = useRoute();

// The auth routes render before a session exists and must not be wrapped.
const bare = computed(() => String(route.name ?? "").startsWith("auth-"));
</script>

<template>
  <div v-if="store.bootError" class="mx-auto max-w-2xl p-8">
    <h1 class="text-lg font-semibold text-danger">Hemlig Console cannot start</h1>
    <p class="mt-2 text-sm text-ink-muted">
      <code>/config.json</code> is missing or invalid. A partly configured console could
      target the wrong deployment, so it refuses to load.
    </p>
    <pre class="mt-4 overflow-x-auto rounded border border-line bg-surface-raised p-3 text-xs">{{ store.bootError }}</pre>
  </div>
  <RouterView v-else-if="bare" />
  <AppShell v-else>
    <RouterView />
  </AppShell>
</template>
