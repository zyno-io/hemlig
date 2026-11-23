import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import PemField from "./PemField.vue";

const block = (label: string, body = "AAAA"): string =>
  `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;

const mountField = (kind: "certificate" | "chain" | "csr" | "crl") =>
  mount(PemField, { props: { label: "Certificate", modelValue: "", kind } });

const lastEmit = (wrapper: ReturnType<typeof mountField>): unknown => {
  const events = wrapper.emitted("update:modelValue") ?? [];
  return events[events.length - 1]?.[0];
};

describe("PemField", () => {
  it.each([
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
  ])("clears a pasted %s and says it is not sent", async (label) => {
    const wrapper = mountField("chain");
    const textarea = wrapper.get("textarea");
    await textarea.setValue(block("CERTIFICATE") + block(label));

    expect(lastEmit(wrapper)).toBe("");
    expect((textarea.element as HTMLTextAreaElement).value).toBe("");
    expect(wrapper.text()).toContain("not sent");
  });

  it("emits a clean paste and shows no warning", async () => {
    const wrapper = mountField("certificate");
    await wrapper.get("textarea").setValue(block("CERTIFICATE"));
    expect(lastEmit(wrapper)).toBe(block("CERTIFICATE"));
    expect(wrapper.text()).not.toContain("not sent");
  });

  it("shows inspection problems on blur", async () => {
    const wrapper = mountField("certificate");
    await wrapper.setProps({ modelValue: block("CERTIFICATE") + block("CERTIFICATE") });
    await wrapper.get("textarea").trigger("blur");
    expect(wrapper.text()).toContain("exactly one CERTIFICATE");
  });

  it("accepts an EC CSR", async () => {
    const wrapper = mountField("csr");
    await wrapper.setProps({ modelValue: block("CERTIFICATE REQUEST", "ECEC") });
    await wrapper.get("textarea").trigger("blur");
    expect(wrapper.find("[role=alert]").exists()).toBe(false);
  });

  it("loads a DER certificate file as PEM", async () => {
    const wrapper = mountField("certificate");
    const input = wrapper.get('input[type="file"]');
    Object.defineProperty(input.element, "files", {
      configurable: true,
      value: [new File([new Uint8Array([0x30, 0x82, 0x01, 0xff])], "c.der")],
    });
    await input.trigger("change");
    await vi.waitFor(() => {
      expect(String(lastEmit(wrapper))).toContain("-----BEGIN CERTIFICATE-----");
    });
  });

  it("refuses a private key file", async () => {
    const wrapper = mountField("certificate");
    const input = wrapper.get('input[type="file"]');
    Object.defineProperty(input.element, "files", {
      configurable: true,
      value: [new File([block("EC PRIVATE KEY")], "k.pem")],
    });
    await input.trigger("change");
    await vi.waitFor(() => {
      expect(lastEmit(wrapper)).toBe("");
    });
    expect(wrapper.text()).toContain("not sent");
  });
});
