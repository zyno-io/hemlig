import { VueQueryPlugin, type VueQueryPluginOptions } from "@tanstack/vue-query";
import { createPinia } from "pinia";
import { createApp } from "vue";
import App from "./App.vue";
import "./styles.css";
import { loadRuntimeConfig } from "./config";
import { createAppRouter } from "./router";
import { useAppStore } from "./stores/app";

/**
 * Metadata reads do not write audit evidence, so they may refresh normally.
 * Payload values are never queried through this cache: their reads remain
 * explicit, audited actions owned by the detail and payload components.
 */
const queryOptions: VueQueryPluginOptions = {
  queryClientConfig: {
    defaultOptions: {
      queries: {
        staleTime: 30 * 1000,
        gcTime: 15 * 60 * 1000,
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
        refetchOnMount: true,
        refetchInterval: false,
        retry: false,
      },
      mutations: { retry: false },
    },
  },
};

const bootstrap = async (): Promise<void> => {
  const app = createApp(App);
  const pinia = createPinia();
  app.use(pinia);
  app.use(VueQueryPlugin, queryOptions);

  const store = useAppStore(pinia);
  try {
    await store.initialize(await loadRuntimeConfig());
  } catch (error) {
    store.bootError = error instanceof Error ? error.message : String(error);
  }

  const router = createAppRouter();
  app.use(router);
  // Resolve `/auth/callback` before App.vue decides whether an unauthenticated
  // boot should start a new redirect. Otherwise a callback reload could race
  // the router and discard the authorization response.
  await router.isReady();
  app.mount("#app");
};

void bootstrap();
