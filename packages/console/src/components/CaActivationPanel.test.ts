import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PkiCaDetail } from "../api/pki-schemas";
import CaActivationPanel from "./CaActivationPanel.vue";


// A Map-backed localStorage: Node's own experimental localStorage can shadow jsdom's.
const installStorage = (): void => {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
};

const SPKI = "ab".repeat(32);
const ca = {
  caId: "ca-0a1b",
  environment: "prod",
  name: "issuing-1",
  csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
  key: { custody: "KMS", algorithm: "ECDSA_P384", spkiSha256: SPKI, state: "ACTIVE" },
} as unknown as PkiCaDetail;

const mountPanel = () => {
  const pinia = createPinia();
  setActivePinia(pinia);
  return mount(CaActivationPanel, { props: { ca }, global: { plugins: [pinia] } });
};

describe("CaActivationPanel tabs", () => {
  beforeEach(installStorage);
  afterEach(() => vi.restoreAllMocks());

  it("defaults to EZ with this CA's commands", () => {
    const wrapper = mountPanel();
    expect(wrapper.find('[data-testid="activation-ez"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="activation-manual"]').exists()).toBe(false);
    const text = wrapper.text();
    expect(text).toContain("hemlig pki ez sign-cert ca-0a1b --environment prod");
    expect(text).toContain(`--expect-spki-sha256 ${SPKI}`);
    expect(text).toContain("hemlig pki ez activate ca-0a1b --environment prod");
    expect(wrapper.get('[role="tablist"]').findAll('[role="tab"]')).toHaveLength(2);
    expect(wrapper.get('[data-testid="activation-tab-ez"]').attributes("aria-selected")).toBe("true");
  });

  it("switches to the unchanged manual flow, remembers it, and supports arrow keys", async () => {
    const wrapper = mountPanel();
    await wrapper.get('[data-testid="activation-tab-manual"]').trigger("click");
    expect(wrapper.find('[data-testid="activation-ez"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="activation-manual"]').exists()).toBe(true);
    expect(wrapper.text()).toContain("Signed certificate");
    expect(wrapper.get('[data-testid="activate-submit"]').attributes("disabled")).toBeDefined();
    expect(window.localStorage.getItem("hemlig.pki.activation-tab")).toBe("manual");

    await wrapper.get('[data-testid="activation-tab-manual"]').trigger("keydown", { key: "ArrowLeft" });
    expect(wrapper.find('[data-testid="activation-ez"]').exists()).toBe(true);

    expect(mountPanel().find('[data-testid="activation-ez"]').exists()).toBe(true);
  });

  it("restores the stored tab", () => {
    window.localStorage.setItem("hemlig.pki.activation-tab", "manual");
    expect(mountPanel().find('[data-testid="activation-manual"]').exists()).toBe(true);
  });

  it("copies a command to the clipboard", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const wrapper = mountPanel();
    const copy = wrapper.findAll("button").find((b) => b.text() === "Copy")!;
    await copy.trigger("click");
    await flushPromises();
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("hemlig login --console-url"));
  });

  it("emits refresh", async () => {
    const wrapper = mountPanel();
    await wrapper.get('[data-testid="activation-refresh"]').trigger("click");
    expect(wrapper.emitted("refresh")).toHaveLength(1);
  });
});
