import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import type { ConsumerListPage, ControlRevision } from "../api/schemas";
import { useAppStore } from "../stores/app";
import SecretMetadata from "./SecretMetadata.vue";

interface FakeApi {
  getSecret: (secretId: string) => Promise<ControlRevision>;
  listConsumers: (...args: unknown[]) => Promise<ConsumerListPage>;
}

const secretFixture = (overrides: Partial<ControlRevision> = {}): ControlRevision => ({
  schemaVersion: 1,
  secretId: "stripe-api-key",
  controlVersionId: "ctl-1",
  environment: "dev",
  state: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: { path: "payments/stripe" },
  acl: [],
  ...overrides,
});

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/e/:env/secrets/:secretId", name: "secret", component: { template: "<div/>" } },
      {
        path: "/e/:env/secrets/:secretId/metadata",
        name: "secret-metadata",
        component: { template: "<div/>" },
      },
    ],
  });

const defaultApi = (overrides: Partial<FakeApi> = {}): FakeApi => ({
  getSecret: async () => secretFixture(),
  listConsumers: async () => ({ consumers: [], generatedAt: "2026-08-23T00:00:00.000Z" }),
  ...overrides,
});

const mountView = async (api: FakeApi): Promise<{ wrapper: ReturnType<typeof mount> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({ name: "secret-metadata", params: { env: "dev", secretId: "stripe-api-key" } });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretMetadata, {
    props: { env: "dev", secretId: "stripe-api-key" },
    global: { plugins: [pinia, router, [VueQueryPlugin, { queryClient }]] },
  });
  await flushPromises();
  return { wrapper };
};

const folderInput = (wrapper: Awaited<ReturnType<typeof mountView>>["wrapper"]) =>
  wrapper.find('input[placeholder="payments/stripe/production"]');

describe("SecretMetadata move notice", () => {
  it("shows nothing when the folder is unchanged", async () => {
    const { wrapper } = await mountView(defaultApi());

    expect(wrapper.text()).not.toContain("Moving from");
  });

  it("shows the before/after once the folder differs from what was loaded", async () => {
    const { wrapper } = await mountView(defaultApi());

    await folderInput(wrapper).setValue("payments/adyen");
    await flushPromises();

    expect(wrapper.text()).toContain("Moving from");
    expect(wrapper.text()).toContain("payments/stripe");
    expect(wrapper.text()).toContain("payments/adyen");
  });

  it("renders the move-to-root wording when the folder is cleared", async () => {
    const { wrapper } = await mountView(defaultApi());

    await folderInput(wrapper).setValue("");
    await flushPromises();

    expect(wrapper.text()).toContain("Moving from");
    expect(wrapper.text()).toContain("the root");
  });
});
