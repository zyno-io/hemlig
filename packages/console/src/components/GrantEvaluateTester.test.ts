import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import type { PkiEvaluateInput, PkiEvaluateResponse } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import GrantEvaluateTester from "./GrantEvaluateTester.vue";

const context = {
  grant: { status: "ACTIVE" as const, expired: false },
  ca: { status: "ACTIVE", keyState: "ACTIVE" },
  capacity: { count: 3, capacity: 10_000 },
  quotas: {
    grantHour: { count: 0, limit: 100 },
    grantDay: { count: 0, limit: 1000 },
    caHour: { count: 0, limit: 1000 },
  },
};

const allow = (): PkiEvaluateResponse => ({
  decision: "allow",
  trace: [
    { step: 1, name: "grant_state", outcome: "pass" },
    { step: 2, name: "names", outcome: "pass", detail: "web.example.com allowed" },
  ],
  plan: {
    keyAlgorithm: "ECDSA_P256",
    sans: { dns: ["web.example.com"] },
    subject: "CN=web.example.com",
    keyUsages: ["digitalSignature"],
    extendedKeyUsages: ["serverAuth"],
    certificatePolicies: [],
    notBefore: "2026-11-01T00:00:00Z",
    notAfter: "2026-11-01T01:00:00Z",
    lifetimeClamped: true,
    sanCritical: false,
  },
  context,
});

const deny = (): PkiEvaluateResponse => ({
  decision: "deny",
  denial: {
    reason: "name_not_permitted",
    detail: "not allowed by the grant",
    deniedNameType: "dns",
    deniedName: "evil.example.com",
  },
  trace: [{ step: 2, name: "names", outcome: "fail" }],
  context,
});

const mountTester = (
  evaluate: (c: string, n: string, input: PkiEvaluateInput) => Promise<PkiEvaluateResponse>,
  dirty = false,
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = { evaluateIssuanceGrant: evaluate } as unknown as ReturnType<typeof store.requireApi>;
  return mount(GrantEvaluateTester, {
    props: {
      consumerId: "payments",
      name: "web",
      savedVersion: "v4",
      dirty,
      keyAlgorithms: ["ECDSA_P256", "RSA_2048"],
    },
    global: { plugins: [pinia] },
  });
};

describe("GrantEvaluateTester", () => {
  it("does not call evaluate while typing", async () => {
    const evaluate = vi.fn(async () => allow());
    const wrapper = mountTester(evaluate);
    await wrapper.get('[data-testid="eval-dns"]').setValue("web.example.com");
    await wrapper.get('[data-testid="eval-cn"]').setValue("web.example.com");
    await flushPromises();
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("sends the names request and renders an allow with plan and trace", async () => {
    const evaluate = vi.fn(async () => allow());
    const wrapper = mountTester(evaluate);
    await wrapper.get('[data-testid="eval-dns"]').setValue("web.example.com");
    await wrapper.get('[data-testid="eval-cn"]').setValue("web.example.com");
    await wrapper.get('[data-testid="eval-duration"]').setValue("1h");
    await wrapper.get("form").trigger("submit");
    await flushPromises();

    expect(evaluate).toHaveBeenCalledWith("payments", "web", {
      keyAlgorithm: "ECDSA_P256",
      sans: { dns: ["web.example.com"] },
      commonName: "web.example.com",
      durationSeconds: 3600,
    });
    const result = wrapper.get('[data-testid="eval-result"]');
    expect(result.text()).toContain("allow");
    expect(result.text()).toContain("lifetime clamped");
    expect(result.text()).toContain("grant_state");
    expect(result.text()).toContain("web.example.com allowed");
  });

  it("renders a deny with the reason and denied name", async () => {
    const wrapper = mountTester(async () => deny());
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    const text = wrapper.get('[data-testid="eval-result"]').text();
    expect(text).toContain("name_not_permitted");
    expect(text).toContain("evil.example.com");
    expect(text).not.toContain("Plan");
  });

  it("sends only the CSR, accepts an EC CSR and rejects a private key", async () => {
    const evaluate = vi.fn(async () => allow());
    const wrapper = mountTester(evaluate);
    await wrapper.findAll('[role="tab"]')[1]?.trigger("click");
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBEC\n-----END CERTIFICATE REQUEST-----";
    const field = wrapper.get("textarea");
    await field.setValue(csr);
    await wrapper.get('[data-testid="eval-duration"]').setValue("30m");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledWith("payments", "web", {
      certificateSigningRequestPem: csr,
      durationSeconds: 1800,
    });

    await field.setValue("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----");
    await flushPromises();
    expect((field.element as HTMLTextAreaElement).value).toBe("");
    expect(wrapper.text()).toContain("not sent");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("shows the dirty banner only when the draft has changes", async () => {
    const clean = mountTester(async () => allow(), false);
    expect(clean.find('[data-testid="dirty-banner"]').exists()).toBe(false);
    const dirty = mountTester(async () => allow(), true);
    expect(dirty.get('[data-testid="dirty-banner"]').text()).toContain(
      "Tests the saved grant (version v4). Save to test your changes.",
    );
  });

  it("rerun repeats the last test exactly once and does nothing before a first test", async () => {
    const evaluate = vi.fn(
      async (_c: string, _n: string, _input: PkiEvaluateInput) => allow(),
    );
    const wrapper = mountTester(evaluate);
    const exposed = wrapper.vm as unknown as { rerun: () => Promise<void> };
    await exposed.rerun();
    expect(evaluate).not.toHaveBeenCalled();

    await wrapper.get('[data-testid="eval-dns"]').setValue("a.example.com");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    await wrapper.get('[data-testid="eval-dns"]').setValue("changed.example.com");
    await exposed.rerun();
    expect(evaluate).toHaveBeenCalledTimes(2);
    expect(evaluate.mock.calls[1]?.[2]).toEqual(evaluate.mock.calls[0]?.[2]);
  });
});
