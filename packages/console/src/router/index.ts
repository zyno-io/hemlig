import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";
import { recallEnvironment, useAppStore } from "../stores/app";

const routes: RouteRecordRaw[] = [
  { path: "/", name: "root", redirect: () => ({ name: "secrets", params: { env: defaultEnvironment() } }) },
  { path: "/auth/callback", name: "auth-callback", component: () => import("../views/AuthCallback.vue") },
  { path: "/e/:env/secrets", name: "secrets", component: () => import("../views/SecretsCatalog.vue"), props: true },
  { path: "/e/:env/secrets/new", name: "secret-new", component: () => import("../views/SecretCreate.vue"), props: true },
  { path: "/e/:env/secrets/:secretId", name: "secret", component: () => import("../views/SecretDetail.vue"), props: true },
  { path: "/e/:env/secrets/:secretId/metadata", name: "secret-metadata", component: () => import("../views/SecretMetadata.vue"), props: true },
  { path: "/e/:env/secrets/:secretId/payload", name: "secret-payload", component: () => import("../views/SecretPayload.vue"), props: true },
  { path: "/e/:env/secrets/:secretId/revisions", name: "secret-revisions", component: () => import("../views/SecretRevisions.vue"), props: true },
  { path: "/e/:env/consumers", name: "consumers", component: () => import("../views/ConsumersList.vue"), props: true },
  { path: "/e/:env/consumers/new", name: "consumer-new", component: () => import("../views/ConsumerEnroll.vue"), props: true },
  { path: "/e/:env/consumers/:consumerId", name: "consumer", component: () => import("../views/ConsumerDetail.vue"), props: true },
  { path: "/trust", name: "trust", component: () => import("../views/TrustStatus.vue") },
  { path: "/about", name: "about", component: () => import("../views/AboutView.vue") },
  { path: "/:pathMatch(.*)*", name: "not-found", component: () => import("../views/NotFound.vue") },
];

function defaultEnvironment(): string {
  const store = useAppStore();
  const environments = store.config?.environments ?? [];
  const remembered = recallEnvironment();
  return remembered !== undefined && environments.includes(remembered)
    ? remembered
    : (environments[0] ?? "dev");
}

export const createAppRouter = () =>
  createRouter({ history: createWebHistory(), routes });
