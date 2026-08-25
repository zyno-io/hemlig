import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import { useAppStore } from "../stores/app";
import SecretCreate from "./SecretCreate.vue";

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/e/:env/secrets", name: "secrets", component: { template: "<div/>" } },
      { path: "/e/:env/secrets/new", name: "secret-new", component: { template: "<div/>" } },
      {
        path: "/e/:env/secrets/:secretId/payload",
        name: "secret-payload",
        component: { template: "<div/>" },
      },
    ],
  });

const mountView = async (
  props: { env: string; path?: string },
): Promise<{ wrapper: ReturnType<typeof mount> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  // This view's own submit flow is exercised elsewhere; the prefill does not
  // touch the API, so a store with no api at all is enough here.
  store.api = {} as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({ name: "secret-new", params: { env: props.env }, query: props.path ? { path: props.path } : {} });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretCreate, {
    props,
    global: { plugins: [pinia, router, [VueQueryPlugin, { queryClient }]] },
  });
  await flushPromises();
  return { wrapper };
};

const secretIdInput = (wrapper: Awaited<ReturnType<typeof mountView>>["wrapper"]) =>
  wrapper.find('input[placeholder="payments/stripe/api-key"]');

describe("SecretCreate folder prefix", () => {
  it("prefixes the secret ID with the folder being browsed", async () => {
    const { wrapper } = await mountView({ env: "dev", path: "payments/stripe" });

    expect((secretIdInput(wrapper).element as HTMLInputElement).value).toBe("payments/stripe/");
  });

  it("leaves the ID empty when creating from the root", async () => {
    const { wrapper } = await mountView({ env: "dev" });

    expect((secretIdInput(wrapper).element as HTMLInputElement).value).toBe("");
  });

  it("leaves the prefixed secret ID editable", async () => {
    const { wrapper } = await mountView({ env: "dev", path: "payments/stripe" });

    expect(secretIdInput(wrapper).attributes("disabled")).toBeUndefined();
    expect(secretIdInput(wrapper).attributes("readonly")).toBeUndefined();
  });
});
