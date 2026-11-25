import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { useAppStore } from "../stores/app";
import RootCrlUploadDialog from "./RootCrlUploadDialog.vue";


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

const block = (label: string): string =>
  `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----\n`;

const mountDialog = (uploadExternalCaCrl: ReturnType<typeof vi.fn>) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  useAppStore().api = { uploadExternalCaCrl } as unknown as ReturnType<
    ReturnType<typeof useAppStore>["requireApi"]
  >;
  return mount(RootCrlUploadDialog, {
    props: { extId: "ext-1", subjectDn: "CN=Root", currentNumberHex: "0a" },
    global: { plugins: [pinia] },
  });
};

const upload = async (wrapper: ReturnType<typeof mountDialog>, text: string) => {
  await wrapper.get("textarea").setValue(text);
  await wrapper.get("form").trigger("submit");
  await flushPromises();
};

describe("RootCrlUploadDialog", () => {
  it("warns before submit", () => {
    const wrapper = mountDialog(vi.fn());
    expect(wrapper.text()).toContain(
      "A CRL that lists a Hemlig intermediate revokes it here immediately and permanently, certificateHold included.",
    );
  });

  it("never uploads a pasted private key", async () => {
    const uploadExternalCaCrl = vi.fn();
    const wrapper = mountDialog(uploadExternalCaCrl);
    await upload(wrapper, block("X509 CRL") + block("EC PRIVATE KEY"));
    expect(uploadExternalCaCrl).not.toHaveBeenCalled();
    expect(wrapper.get('[data-testid="crl-upload"]').attributes("disabled")).toBeDefined();
    expect(wrapper.text()).toContain("not sent");
  });

  it("uploads a CRL and emits uploaded", async () => {
    const uploadExternalCaCrl = vi.fn(async () => ({
      extId: "ext-1",
      changed: true,
      revokedCaIds: [],
    }));
    const wrapper = mountDialog(uploadExternalCaCrl);
    await upload(wrapper, block("X509 CRL"));
    expect(uploadExternalCaCrl).toHaveBeenCalledWith("ext-1", block("X509 CRL"), expect.any(String));
    expect(wrapper.emitted("uploaded")).toHaveLength(1);
  });

  it("shows a danger notice listing revoked CAs", async () => {
    const wrapper = mountDialog(
      vi.fn(async () => ({ extId: "ext-1", changed: true, revokedCaIds: ["ca-aa", "ca-bb"] })),
    );
    await upload(wrapper, block("X509 CRL"));
    const result = wrapper.get('[data-testid="crl-result"]');
    expect(result.find(".notice-danger").text()).toContain("ca-aa");
    expect(result.find(".notice-danger").text()).toContain("ca-bb");
  });

  it("says an unchanged CRL is already current", async () => {
    const wrapper = mountDialog(
      vi.fn(async () => ({ extId: "ext-1", changed: false, revokedCaIds: [] })),
    );
    await upload(wrapper, block("X509 CRL"));
    expect(wrapper.get('[data-testid="crl-result"]').text()).toContain("already current");
  });
});

describe("RootCrlUploadDialog EZ tab", () => {
  const ext = `ext-${"b".repeat(40)}`;
  const mountEz = () => {
    installStorage();
    const pinia = createPinia();
    setActivePinia(pinia);
    return mount(RootCrlUploadDialog, { props: { extId: ext }, global: { plugins: [pinia] } });
  };

  it("shows the renew and upload commands and hides the upload button", async () => {
    const wrapper = mountEz();
    expect(wrapper.find('[data-testid="crl-ez"]').exists()).toBe(true);
    expect(wrapper.text()).toContain(`hemlig pki ez renew-crl --if-due --expect-ext-id ${ext}`);
    expect(wrapper.text()).toContain(`hemlig pki ez upload-crl --expect-ext-id ${ext}`);
    expect(wrapper.find('[data-testid="crl-upload"]').exists()).toBe(false);
    await wrapper.get('[data-testid="crl-tab-manual"]').trigger("click");
    expect(wrapper.find('[data-testid="crl-manual"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="crl-upload"]').exists()).toBe(true);
  });

  it("falls back to Manual for a malformed ext ID", () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const wrapper = mount(RootCrlUploadDialog, { props: { extId: "ext-1" }, global: { plugins: [pinia] } });
    expect(wrapper.find('[role="tablist"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="crl-upload"]').exists()).toBe(true);
  });
});
