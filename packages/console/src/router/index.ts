import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
} from "vue-router";

const routes: RouteRecordRaw[] = [
  // `/` no longer redirects synchronously: the environment list is
  // administrator-defined API state that requires an authenticated call, and
  // in OIDC mode there is no session at boot. RootResolver.vue decides what
  // to show once that call can actually be made.
  {
    path: "/",
    name: "root",
    component: () => import("../views/RootResolver.vue"),
  },
  {
    path: "/auth/callback",
    name: "auth-callback",
    component: () => import("../views/AuthCallback.vue"),
  },
  // Not scoped to one environment — it defines them — so it lives outside
  // the `/e/:env/...` tree below.
  {
    path: "/environments",
    name: "environments",
    component: () => import("../views/EnvironmentsView.vue"),
  },
  {
    path: "/audit",
    name: "audit",
    component: () => import("../views/AuditLog.vue"),
  },
  {
    path: "/e/:env/secrets",
    name: "secrets",
    component: () => import("../views/SecretsCatalog.vue"),
    props: true,
  },
  // A distinct static "browse" segment, not a param on the secret-detail
  // route: vue-router ranks a static segment above a dynamic one regardless
  // of declaration order, so a secret literally named "browse" (a valid
  // secretId, same as the pre-existing "new" reservation below) can never be
  // reached through this route and a folder path can never be mistaken for a
  // secretId. `:path*` is repeatable, so `route.params.path` is a `string[]`
  // (or `undefined` on the plain `/secrets` route above, which is root).
  {
    path: "/e/:env/secrets/browse/:path*",
    name: "secrets-browse",
    component: () => import("../views/SecretsCatalog.vue"),
    props: true,
  },
  // `path` is a query param, not a route param: it is optional prefill data
  // (the folder the operator was browsing when they clicked "New secret"),
  // not part of this route's identity, so `props: true` (which only maps
  // params) is not enough to reach it.
  {
    path: "/e/:env/secrets/new",
    name: "secret-new",
    component: () => import("../views/SecretCreate.vue"),
    props: (route) => ({
      env: route.params.env,
      path: firstQueryValue(route.query.path),
    }),
  },
  {
    path: "/e/:env/secrets/:secretId",
    name: "secret",
    component: () => import("../views/SecretDetail.vue"),
    props: true,
  },
  {
    path: "/e/:env/secrets/:secretId/metadata",
    name: "secret-metadata",
    component: () => import("../views/SecretMetadata.vue"),
    props: true,
  },
  {
    path: "/e/:env/secrets/:secretId/payload",
    name: "secret-payload",
    component: () => import("../views/SecretPayload.vue"),
    props: true,
  },
  {
    path: "/e/:env/secrets/:secretId/revisions",
    name: "secret-revisions",
    component: () => import("../views/SecretRevisions.vue"),
    props: true,
  },
  {
    path: "/e/:env/consumers",
    name: "consumers",
    component: () => import("../views/ConsumersList.vue"),
    props: true,
  },
  {
    path: "/e/:env/consumers/new",
    name: "consumer-new",
    component: () => import("../views/ConsumerEnroll.vue"),
    props: true,
  },
  {
    path: "/e/:env/consumers/:consumerId",
    name: "consumer",
    component: () => import("../views/ConsumerDetail.vue"),
    props: true,
  },
  {
    path: "/trust",
    name: "trust",
    component: () => import("../views/TrustStatus.vue"),
  },
  {
    path: "/about",
    name: "about",
    component: () => import("../views/AboutView.vue"),
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("../views/NotFound.vue"),
  },
];

export const createAppRouter = () =>
  createRouter({ history: createWebHistory(), routes });

/** A repeated query param becomes an array and an absent one becomes null; only a single plain value is meaningful here. */
const firstQueryValue = (
  value: string | null | (string | null)[] | undefined,
): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;
