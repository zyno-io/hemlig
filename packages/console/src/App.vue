<script setup lang="ts">
import { computed, onMounted, watch } from "vue";
import { useRoute } from "vue-router";
import AppShell from "./components/AppShell.vue";
import AuthCallback from "./views/AuthCallback.vue";
import { useAppStore } from "./stores/app";

const store = useAppStore();
const route = useRoute();

const hasSession = computed(() => store.session !== undefined);
const isAuthCallback = computed(() => route.name === "auth-callback");
let redirectStarted = false;

/**
 * The console is deliberately authentication-first. It has no signed-out
 * application shell or routes: without a session, redirect to the identity
 * provider before mounting any route component that could expose partial UI
 * or make an unauthenticated API request.
 */
const redirectToSignIn = (): void => {
  if (redirectStarted || store.bootError !== undefined || isAuthCallback.value || hasSession.value) {
    return;
  }
  redirectStarted = true;
  void store.signIn().catch((error: unknown) => {
    store.bootError = error instanceof Error ? error.message : String(error);
  });
};

onMounted(redirectToSignIn);
watch([hasSession, isAuthCallback, () => store.bootError], redirectToSignIn);
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
  <AuthCallback v-else-if="isAuthCallback" />
  <AppShell v-else-if="hasSession">
    <RouterView />
  </AppShell>
</template>
