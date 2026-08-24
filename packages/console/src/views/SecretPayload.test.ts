import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import type { ControlRevision } from "../api/schemas";
import { useAppStore } from "../stores/app";
import SecretPayload from "./SecretPayload.vue";

interface FakeApi {
  getSecret: (secretId: string) => Promise<ControlRevision>;
  putPayload?: (
    secretId: string,
    controlVersionId: string,
    payload: Record<string, { encoding: "utf8" | "base64"; value: string }>,
    idempotencyKey: string,
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
      {
        path: "/e/:env/secrets/:secretId",
        name: "secret",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId/payload",
        name: "secret-payload",
        component: { template: "<div/>" },
      },
    ],
  });

const defaultApi = (overrides: Partial<FakeApi> = {}): FakeApi => ({
  getSecret: async () => secretFixture(),
  ...overrides,
});

const mountViewWithQueryClient = async (
  api: FakeApi,
): Promise<{ wrapper: ReturnType<typeof mount>; queryClient: QueryClient }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({
    name: "secret-payload",
    params: { env: "dev", secretId: "stripe-api-key" },
  });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretPayload, {
    props: { env: "dev", secretId: "stripe-api-key" },
    global: { plugins: [pinia, router, [VueQueryPlugin, { queryClient }]] },
  });
  await flushPromises();
  return { wrapper, queryClient };
};

const mountView = async (api: FakeApi): Promise<ReturnType<typeof mount>> => {
  const mounted = await mountViewWithQueryClient(api);
  return mounted.wrapper;
};

const tab = (
  wrapper: ReturnType<typeof mount>,
  label: "Form" | "JSON" | ".env",
) => wrapper.findAll('[role="tab"]').find((btn) => btn.text() === label)!;

const submitButton = (wrapper: ReturnType<typeof mount>) =>
  wrapper.findAll("button").find((btn) => btn.text() === "Replace payload")!;

/** The Form tab always renders exactly [key input, value input] for one row. */
const formInputs = (wrapper: ReturnType<typeof mount>) => {
  const inputs = wrapper.findAll("input");
  return { key: inputs[0]!, value: inputs[1]! };
};

describe("SecretPayload tabs", () => {
  it("describes a first payload as activating the secret and returns its revision to the detail cache", async () => {
    const activated = secretFixture({
      controlVersionId: "ctl-2",
      payloadVersionId: "pay-1",
      payloadKeyCount: 1,
      state: "ACTIVE",
    });
    const putPayload = vi.fn(async () => activated);
    const { wrapper, queryClient } = await mountViewWithQueryClient({
      getSecret: async () => secretFixture({ state: "PENDING_VALUE" }),
      putPayload,
    });

    const inputs = formInputs(wrapper);
    await inputs.key.setValue("TOKEN");
    await inputs.value.setValue("first-secret-value");
    await submitButton(wrapper).trigger("click");

    expect(wrapper.text()).toContain("This is the first payload");
    expect(wrapper.text()).toContain("no stored entries will be destroyed");
    expect(wrapper.text()).not.toContain("predates entry counting");

    const replacementButtons = wrapper
      .findAll("button")
      .filter((button) => button.text() === "Replace payload");
    await replacementButtons[replacementButtons.length - 1]!.trigger("click");
    await flushPromises();

    expect(putPayload).toHaveBeenCalledWith(
      "dev",
      "stripe-api-key",
      "ctl-1",
      { TOKEN: { encoding: "utf8", value: "first-secret-value" } },
      expect.any(String),
    );
    expect(
      queryClient.getQueryData(["secret", "dev", "stripe-api-key"]),
    ).toEqual(activated);
  });

  it("defaults to the Form tab", async () => {
    const wrapper = await mountView(defaultApi());

    expect(tab(wrapper, "Form").attributes("aria-selected")).toBe("true");
    expect(tab(wrapper, "JSON").attributes("aria-selected")).toBe("false");
    expect(tab(wrapper, ".env").attributes("aria-selected")).toBe("false");
    expect(wrapper.find("input").exists()).toBe(true);
    expect(wrapper.find("textarea").exists()).toBe(false);
  });

  it("labels the row-adding button 'Add key', not 'Add entry'", async () => {
    const wrapper = await mountView(defaultApi());

    expect(wrapper.text()).toContain("Add key");
    expect(wrapper.text()).not.toContain("Add entry");
  });

  it("does not placeholder-hint the key input with an example username", async () => {
    const wrapper = await mountView(defaultApi());

    expect(formInputs(wrapper).key.attributes("placeholder")).toBeUndefined();
  });

  it("preserves content across Form -> JSON -> .env -> Form", async () => {
    const wrapper = await mountView(defaultApi());

    const inputs = formInputs(wrapper);
    await inputs.key.setValue("username");
    await inputs.value.setValue("service-account");
    await flushPromises();

    await tab(wrapper, "JSON").trigger("click");
    await flushPromises();
    let textarea = wrapper.find("textarea");
    expect(textarea.element.value).toContain('"username"');
    expect(textarea.element.value).toContain('"service-account"');

    await tab(wrapper, ".env").trigger("click");
    await flushPromises();
    textarea = wrapper.find("textarea");
    expect(textarea.element.value).toContain("username=service-account");

    await tab(wrapper, "Form").trigger("click");
    await flushPromises();
    const roundTripped = formInputs(wrapper);
    expect(roundTripped.key.element.value).toBe("username");
    expect(roundTripped.value.element.value).toBe("service-account");
  });

  it("blocks tab switching and submit while the JSON tab is unparseable, and keeps the typed text", async () => {
    const wrapper = await mountView(defaultApi());

    await tab(wrapper, "JSON").trigger("click");
    await flushPromises();

    const textarea = wrapper.find("textarea");
    await textarea.setValue("{ this is not json");
    await flushPromises();

    expect(wrapper.text()).toContain("Invalid JSON");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
    expect(tab(wrapper, "Form").attributes("disabled")).toBeDefined();
    expect(tab(wrapper, ".env").attributes("disabled")).toBeDefined();

    // The broken text must still be exactly what was typed -- not reverted,
    // not cleared.
    expect(wrapper.find("textarea").element.value).toBe("{ this is not json");
  });

  it("blocks submit for JSON that parses but violates the payload rules", async () => {
    const wrapper = await mountView(defaultApi());

    await tab(wrapper, "JSON").trigger("click");
    await flushPromises();

    await wrapper
      .find("textarea")
      .setValue(JSON.stringify({ a: { encoding: "base64", value: "abc" } }));
    await flushPromises();

    expect(wrapper.text()).toContain("canonical base64");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
  });

  it("shows the base64 warning on the .env tab only when base64 entries exist", async () => {
    const wrapper = await mountView(defaultApi());

    await tab(wrapper, ".env").trigger("click");
    await flushPromises();
    expect(wrapper.text()).not.toContain("base64-encoded");

    await tab(wrapper, "Form").trigger("click");
    await flushPromises();
    const inputs = formInputs(wrapper);
    await inputs.key.setValue("TOKEN");
    await wrapper.find("select").setValue("base64");
    await inputs.value.setValue("c2VjcmV0");
    await flushPromises();

    await tab(wrapper, ".env").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("base64-encoded");
    expect(wrapper.text()).toContain("TOKEN");
  });

  it("does not change a base64 entry's encoding merely by viewing the .env tab", async () => {
    const wrapper = await mountView(defaultApi());

    const inputs = formInputs(wrapper);
    await inputs.key.setValue("TOKEN");
    await wrapper.find("select").setValue("base64");
    await inputs.value.setValue("c2VjcmV0");
    await flushPromises();

    await tab(wrapper, ".env").trigger("click");
    await flushPromises();
    // Viewing must not touch the model: switch back to Form without typing
    // anything in the .env textarea, and the encoding must be unchanged.
    await tab(wrapper, "Form").trigger("click");
    await flushPromises();

    expect(wrapper.find("select").element.value).toBe("base64");
  });
});
