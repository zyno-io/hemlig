import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import { ApiError } from "../api/errors";
import type { EnvironmentDefinition } from "../api/schemas";
import { environmentsQueryKey } from "../composables/useEnvironments";
import { recallEnvironment, useAppStore } from "../stores/app";
import CreateEnvironmentForm from "./CreateEnvironmentForm.vue";

interface FakeApi {
  createEnvironment: (name: string) => Promise<EnvironmentDefinition>;
}

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "root", component: { template: "<div/>" } },
      { path: "/e/:env/secrets", name: "secrets", component: { template: "<div/>" } },
      { path: "/environments", name: "environments", component: { template: "<div/>" } },
    ],
  });

const mountForm = async (
  api: FakeApi,
  props: { navigateOnCreate?: boolean } = {},
): Promise<{ wrapper: ReturnType<typeof mount>; router: Router; queryClient: QueryClient }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({ name: "root" });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(CreateEnvironmentForm, {
    props,
    global: { plugins: [pinia, router, [VueQueryPlugin, { queryClient }]] },
  });
  await flushPromises();
  return { wrapper, router, queryClient };
};

const environmentFixture: EnvironmentDefinition = {
  name: "staging",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
};

beforeEach(() => {
  window.localStorage.clear();
});

describe("CreateEnvironmentForm", () => {
  it("validates the name client-side with the same rule the service enforces", async () => {
    const { wrapper } = await mountForm({ createEnvironment: vi.fn() });

    await wrapper.find("input").setValue("Not Valid!");
    await flushPromises();

    expect(wrapper.text()).toContain("lowercase letters");
  });

  it("on success, invalidates the shared environments query and navigates into the new environment", async () => {
    const createEnvironment = vi.fn(async () => environmentFixture);
    const { wrapper, router, queryClient } = await mountForm({ createEnvironment });
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");

    await wrapper.find("input").setValue("staging");
    await wrapper.find("form").trigger("submit");
    await flushPromises();

    expect(createEnvironment).toHaveBeenCalledWith("staging");
    expect(invalidate).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: environmentsQueryKey }),
    );
    expect(router.currentRoute.value.name).toBe("secrets");
    expect(router.currentRoute.value.params.env).toBe("staging");
    expect(recallEnvironment()).toBe("staging");
  });

  it("does not navigate on success when navigateOnCreate is false", async () => {
    const { wrapper, router } = await mountForm(
      { createEnvironment: async () => environmentFixture },
      { navigateOnCreate: false },
    );

    await wrapper.find("input").setValue("staging");
    await wrapper.find("form").trigger("submit");
    await flushPromises();

    expect(router.currentRoute.value.name).toBe("root");
  });

  it("renders a duplicate name as an already-exists affordance to switch to, not a failure", async () => {
    const conflict = new ApiError(
      409,
      "conflict",
      "The environment already exists or the registry is full.",
    );
    const { wrapper, router } = await mountForm({
      createEnvironment: async () => {
        throw conflict;
      },
    });

    await wrapper.find("input").setValue("prod");
    await wrapper.find("form").trigger("submit");
    await flushPromises();

    expect(wrapper.text()).toContain("already exists");
    expect(wrapper.text()).not.toContain("request failed");

    await wrapper.find("button:not([type=submit])").trigger("click");
    await flushPromises();

    expect(router.currentRoute.value.name).toBe("secrets");
    expect(router.currentRoute.value.params.env).toBe("prod");
  });

  it("still reports a genuine failure that is not a naming conflict", async () => {
    const failure = new ApiError(500, "internal_error", "boom", "corr-1");
    const { wrapper } = await mountForm({
      createEnvironment: async () => {
        throw failure;
      },
    });

    await wrapper.find("input").setValue("prod");
    await wrapper.find("form").trigger("submit");
    await flushPromises();

    expect(wrapper.text()).toContain("corr-1");
  });
});
