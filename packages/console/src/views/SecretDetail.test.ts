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
  archiveSecret?: (
    environment: string,
    secretId: string,
    controlVersionId: string,
    idempotencyKey: string,
  ) => Promise<ControlRevision>;
  getArchivedSecret?: (
    environment: string,
    secretUid: string,
  ) => Promise<ControlRevision>;
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
        path: "/e/:env/secrets/archived/:secretUid",
        name: "archived-secret",
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
  archivedSecretUid?: string,
): Promise<{ wrapper: ReturnType<typeof mount> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push(
    archivedSecretUid === undefined
      ? {
          name: "secret",
          params: { env: "dev", secretId: "stripe-api-key" },
          query,
        }
      : {
          name: "archived-secret",
          params: { env: "dev", secretUid: archivedSecretUid },
          query,
        },
  );
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretDetail, {
    props: {
      env: "dev",
      secretId: "stripe-api-key",
      ...(archivedSecretUid === undefined ? {} : { archivedSecretUid }),
    },
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

  it("links the secret ID prefix to its folder in the browse tree", async () => {
    const { wrapper } = await mountView({
      getSecret: async () => secretFixture(),
    });
    await wrapper.setProps({ secretId: "payments/stripe/stripe-api-key" });
    await flushPromises();

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

  it("does not offer metadata as a way to move folders", async () => {
    const { wrapper } = await mountView({
      getSecret: async () => secretFixture(),
    });

    const move = wrapper.findAll("a").find((a) => a.text() === "Move");
    expect(move).toBeUndefined();
  });

  it("archives from the active detail after confirmation", async () => {
    const archiveSecret = vi.fn(async () =>
      secretFixture({ state: "ARCHIVED", acl: [] }),
    );
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { wrapper } = await mountView({
      getSecret: async () => secretFixture(),
      archiveSecret,
    });

    const archive = wrapper
      .findAll("button")
      .find((button) => button.text() === "Archive secret");
    await archive?.trigger("click");
    await flushPromises();

    expect(confirm).toHaveBeenCalled();
    expect(archiveSecret).toHaveBeenCalledWith(
      "dev",
      "stripe-api-key",
      "ctl-1",
      expect.any(String),
    );
    confirm.mockRestore();
  });

  it("uses the archived UID detail route and never offers its payload", async () => {
    const getArchivedSecret = vi.fn(async () =>
      secretFixture({ state: "ARCHIVED", acl: [] }),
    );
    const { wrapper } = await mountView(
      { getSecret: async () => secretFixture(), getArchivedSecret },
      { archived: "true" },
      "sec-archived-123",
    );

    expect(getArchivedSecret).toHaveBeenCalledWith("dev", "sec-archived-123");
    expect(wrapper.text()).toContain("This immutable record is archived.");
    expect(
      wrapper.findAll("button").map((button) => button.text()),
    ).not.toContain("Reveal");
    expect(wrapper.text()).not.toContain("Replace payload");
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
