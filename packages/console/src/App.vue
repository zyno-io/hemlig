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
  if (
    redirectStarted ||
    store.bootError !== undefined ||
    store.signedOut ||
    isAuthCallback.value ||
    hasSession.value
  ) {
    return;
  }
  redirectStarted = true;
  void store.signIn(route.fullPath).catch((error: unknown) => {
    store.bootError = error instanceof Error ? error.message : String(error);
  });
};

onMounted(redirectToSignIn);
watch([hasSession, isAuthCallback, () => store.bootError, () => store.signedOut], redirectToSignIn);

const signInAgain = (): void => {
  redirectStarted = true;
  void store.signIn("/").catch((error: unknown) => {
    store.bootError = error instanceof Error ? error.message : String(error);
  });
};
</script>

<template>
  <div v-if="store.bootError" class="page max-w-2xl">
    <h1 class="page-title text-danger">Hemlig Console cannot start</h1>
    <p class="mt-2 text-ink-2">
      <code>/config.json</code> is missing or invalid. A partly configured console could
      target the wrong deployment, so it refuses to load.
    </p>
    <pre class="code-block mono mt-4">{{ store.bootError }}</pre>
  </div>
  <AuthCallback v-else-if="isAuthCallback" />
  <AppShell v-else-if="hasSession">
    <RouterView />
  </AppShell>
  <div v-else-if="store.signedOut" class="page max-w-2xl">
    <h1 class="page-title">You're signed out</h1>
    <p class="mt-2 text-ink-2">
      The console session has ended. Your identity provider may keep its own session open.
    </p>
    <button type="button" class="btn btn-primary mt-4" @click="signInAgain">Sign in</button>
  </div>
</template>
