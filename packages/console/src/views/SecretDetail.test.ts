import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import type { ControlRevision } from "../api/schemas";
import { useAppStore } from "../stores/app";
import SecretDetail from "./SecretDetail.vue";

interface FakeApi {
  getSecret: (
    environment: string,
    secretId: string,
  ) => Promise<ControlRevision>;
  getSecretPayload?: (
    environment: string,
    secretId: string,
  ) => Promise<{
    secretId: string;
    controlVersionId: string;
    payloadVersionId: string;
    payload: Record<string, { encoding: "utf8" | "base64"; value: string }>;
  }>;
}

const secretFixture = (
  overrides: Partial<ControlRevision> = {},
): ControlRevision => ({
  schemaVersion: 1,
  secretId: "stripe-api-key",
  controlVersionId: "ctl-1",
  environment: "dev",
  state: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: {},
  acl: [],
  ...overrides,
});

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/audit", name: "audit", component: { template: "<div/>" } },
      {
        path: "/e/:env/secrets",
        name: "secrets",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/browse/:path*",
        name: "secrets-browse",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId",
        name: "secret",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId/metadata",
        name: "secret-metadata",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId/revisions",
        name: "secret-revisions",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId/payload",
        name: "secret-payload",
        component: { template: "<div/>" },
      },
    ],
  });

const mountView = async (
  api: FakeApi,
  query: Record<string, string> = {},
): Promise<{ wrapper: ReturnType<typeof mount> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({
    name: "secret",
    params: { env: "dev", secretId: "stripe-api-key" },
    query,
  });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretDetail, {
    props: { env: "dev", secretId: "stripe-api-key" },
    // The global RouterLink stub (vitest.setup.ts) drops `to` entirely, which
    // hides it from the href-based assertions below; the real router already
    // provided as a plugin is enough to resolve real hrefs instead.
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: false },
    },
  });
  await flushPromises();
  return { wrapper };
};

describe("SecretDetail path", () => {
  it("returns to the folder that opened the secret", async () => {
    const { wrapper } = await mountView(
      { getSecret: async () => secretFixture() },
      { catalogPath: "payments/stripe" },
    );

    const back = wrapper
      .findAll("a")
      .find((link) => link.text().includes("Secrets"));
    expect(back?.attributes("href")).toBe(
      "/e/dev/secrets/browse/payments/stripe",
    );
  });

  it("returns to the applied catalog search", async () => {
    const { wrapper } = await mountView(
      { getSecret: async () => secretFixture() },
      { catalogFilter: "stripe owner:payments" },
    );

    const back = wrapper
      .findAll("a")
      .find((link) => link.text().includes("Secrets"));
    expect(back?.attributes("href")).toBe(
      "/e/dev/secrets?catalogFilter=stripe+owner:payments",
    );
  });

  it("links the path to its folder in the browse tree", async () => {
    const { wrapper } = await mountView({
      getSecret: async () =>
        secretFixture({ metadata: { path: "payments/stripe" } }),
    });

    const link = wrapper
      .findAll("a")
      .find((a) => a.text() === "payments/stripe");
    expect(link).toBeDefined();
    expect(link?.attributes("href")).toBe(
      "/e/dev/secrets/browse/payments/stripe",
    );
  });

  it("says a rootless secret is at the root rather than showing a dash with no route", async () => {
    const { wrapper } = await mountView({
      getSecret: async () => secretFixture({ metadata: {} }),
    });

    const link = wrapper.findAll("a").find((a) => a.text() === "Root");
    expect(link).toBeDefined();
    expect(link?.attributes("href")).toBe("/e/dev/secrets");
  });

  it("offers a Move affordance to the metadata editor", async () => {
    const { wrapper } = await mountView({
      getSecret: async () =>
        secretFixture({ metadata: { path: "payments/stripe" } }),
    });

    const move = wrapper.findAll("a").find((a) => a.text() === "Move");
    expect(move).toBeDefined();
    expect(move?.attributes("href")).toBe(
      "/e/dev/secrets/stripe-api-key/metadata",
    );
  });

  it("reveals the current payload only after the explicit audited action", async () => {
    const getSecretPayload = vi.fn(async () => ({
      secretId: "stripe-api-key",
      controlVersionId: "ctl-1",
      payloadVersionId: "pay-1",
      payload: {
        PASSWORD: { encoding: "utf8" as const, value: "correct-horse" },
      },
    }));
    const { wrapper } = await mountView({
      getSecret: async () =>
        secretFixture({ payloadVersionId: "pay-1", payloadKeyCount: 1 }),
      getSecretPayload,
    });

    expect(getSecretPayload).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("deliberate audited action");
    expect(wrapper.text()).not.toContain("correct-horse");

    const reveal = wrapper
      .findAll("button")
      .find((button) => button.text() === "Reveal");
    await reveal?.trigger("click");
    await flushPromises();

    expect(getSecretPayload).toHaveBeenCalledWith("dev", "stripe-api-key");
    expect(wrapper.text()).toContain("correct-horse");

    const hide = wrapper
      .findAll("button")
      .find((button) => button.text() === "Hide");
    await hide?.trigger("click");
    expect(wrapper.text()).not.toContain("correct-horse");
  });

  it("clears revealed plaintext when router reuse switches to another secret", async () => {
    const { wrapper } = await mountView({
      getSecret: async () => secretFixture({ payloadVersionId: "pay-1" }),
      getSecretPayload: async () => ({
        secretId: "stripe-api-key",
        controlVersionId: "ctl-1",
        payloadVersionId: "pay-1",
        payload: { PASSWORD: { encoding: "utf8", value: "correct-horse" } },
      }),
    });

    await wrapper
      .findAll("button")
      .find((button) => button.text() === "Reveal")
      ?.trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("correct-horse");

    await wrapper.setProps({ secretId: "other-secret" });
    expect(wrapper.text()).not.toContain("correct-horse");
  });
});
