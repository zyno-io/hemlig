import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import { ApiError } from "../api/errors";
import type { EnvironmentListResponse } from "../api/schemas";
import { rememberEnvironment, useAppStore } from "../stores/app";
import RootResolver from "./RootResolver.vue";

interface FakeApi {
  listEnvironments: () => Promise<EnvironmentListResponse>;
}

const envList = (names: readonly string[]): EnvironmentListResponse => ({
  environments: names.map((name) => ({
    name,
    createdAt: "2026-08-23T00:00:00.000Z",
    createdBy: { type: "human", id: "admin" },
  })),
  generatedAt: "2026-08-23T00:00:00.000Z",
});

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "root", component: { template: "<div/>" } },
      { path: "/e/:env/secrets", name: "secrets", component: { template: "<div/>" } },
    ],
  });

const mountResolver = async (
  api: FakeApi,
): Promise<{ wrapper: ReturnType<typeof mount>; router: Router }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  // Bypasses HemligApi/fetch entirely, same as SecretsCatalog.test.ts.
  store.api = api as unknown as ReturnType<typeof store.requireApi>;
  store.adoptSession({ subject: "admin" });

  const router = buildRouter();
  await router.push({ name: "root" });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(RootResolver, {
    global: { plugins: [pinia, router, [VueQueryPlugin, { queryClient }]] },
  });
  await flushPromises();
  return { wrapper, router };
};

beforeEach(() => {
  window.localStorage.clear();
});

describe("RootResolver", () => {
  it("redirects to the remembered environment when it is still in the list", async () => {
    rememberEnvironment("staging");
    const { router } = await mountResolver({
      listEnvironments: async () => envList(["dev", "staging"]),
    });

    expect(router.currentRoute.value.name).toBe("secrets");
    expect(router.currentRoute.value.params.env).toBe("staging");
  });

  it("falls back to the first environment when the remembered one no longer exists", async () => {
    rememberEnvironment("decommissioned");
    const { router } = await mountResolver({
      listEnvironments: async () => envList(["dev", "staging"]),
    });

    expect(router.currentRoute.value.name).toBe("secrets");
    expect(router.currentRoute.value.params.env).toBe("dev");
  });

  it("renders a first-run panel and does not redirect when the list is empty", async () => {
    const { wrapper, router } = await mountResolver({ listEnvironments: async () => envList([]) });

    expect(wrapper.text()).toContain("Define your first environment");
    expect(wrapper.find("input").exists()).toBe(true);
    expect(router.currentRoute.value.name).toBe("root");
  });

  it("shows the error with its correlation ID and a retry, and does not guess an environment", async () => {
    const error = new ApiError(500, "internal_error", "boom", "corr-9");
    const { wrapper, router } = await mountResolver({
      listEnvironments: async () => {
        throw error;
      },
    });

    expect(wrapper.text()).toContain("corr-9");
    expect(wrapper.text()).toContain("Retry");
    expect(router.currentRoute.value.name).toBe("root");
  });
});
