import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import { ApiError } from "../api/errors";
import type {
  PkiCaDetail,
  PkiCaSummary,
  PkiGrantInput,
  PkiGrantValidationResult,
  PkiIssuanceGrant,
} from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import IssuanceGrantEditor from "./IssuanceGrantEditor.vue";

const actor = { type: "human" as const, id: "admin" };

const baseGrant = (overrides: Partial<PkiIssuanceGrant> = {}): PkiIssuanceGrant => ({
  consumerId: "payments",
  environment: "prod",
  name: "web",
  uid: "pkg-123",
  caId: "ca-1",
  status: "ACTIVE",
  expired: false,
  displayName: "web certs",
  policy: {
    names: {
      dns: { allow: ["*.payments.example.com"], deny: [] },
      commonName: { mode: "san", addToSans: true },
    },
    keyAlgorithms: ["ECDSA_P256"],
    keyUsages: ["digitalSignature"],
    extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
    lifetime: { defaultSeconds: 86_400, maxSeconds: 86_400, minSeconds: 3600 },
    quotas: { perHour: 100, perDay: 1000 },
  },
  policyDigest: "sha256:a",
  quotas: { perHour: 100, perDay: 1000 },
  version: "v1",
  createdAt: "2026-11-01T00:00:00Z",
  createdBy: actor,
  updatedAt: "2026-11-01T00:00:00Z",
  updatedBy: actor,
  ...overrides,
});

const caSummary: PkiCaSummary = {
  caId: "ca-1",
  environment: "prod",
  name: "issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "c1",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-10-01T00:00:00Z",
};

const caDetail = (): PkiCaDetail =>
  ({
    ...caSummary,
    policy: {
      issueLeaves: true,
      issueSubordinates: false,
      maxLeafLifetimeSeconds: 7_776_000,
      leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P384"],
      capacity: 10_000,
      issuancePerHour: 50,
      crlValiditySeconds: 86_400,
    },
  }) as unknown as PkiCaDetail;

interface Fake {
  getAdminIssuanceGrant: ReturnType<typeof vi.fn>;
  listPkiCas: ReturnType<typeof vi.fn>;
  getPkiCa: ReturnType<typeof vi.fn>;
  createIssuanceGrant: ReturnType<typeof vi.fn>;
  updateIssuanceGrant: ReturnType<typeof vi.fn>;
  validateIssuanceGrantCreate: ReturnType<typeof vi.fn>;
  validateIssuanceGrantUpdate: ReturnType<typeof vi.fn>;
  deleteIssuanceGrant: ReturnType<typeof vi.fn>;
  evaluateIssuanceGrant: ReturnType<typeof vi.fn>;
  revokeConsumerPkiCertificates: ReturnType<typeof vi.fn>;
}

const fake = (overrides: Partial<Fake> = {}): Fake => ({
  getAdminIssuanceGrant: vi.fn(async () => baseGrant()),
  listPkiCas: vi.fn(async () => ({ cas: [caSummary], generatedAt: "now" })),
  getPkiCa: vi.fn(async () => caDetail()),
  createIssuanceGrant: vi.fn(async () => baseGrant()),
  updateIssuanceGrant: vi.fn(async () => baseGrant({ version: "v2" })),
  validateIssuanceGrantCreate: vi.fn(),
  validateIssuanceGrantUpdate: vi.fn(),
  deleteIssuanceGrant: vi.fn(async () => baseGrant({ status: "DELETED" })),
  evaluateIssuanceGrant: vi.fn(),
  revokeConsumerPkiCertificates: vi.fn(),
  ...overrides,
});

const mountEditor = async (
  api: Fake,
  props: { name?: string; caId?: string } = { name: "web" },
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/c/:consumerId", name: "consumer", component: { template: "<div/>" } },
      { path: "/g/:consumerId/:name", name: "consumer-pki-grant", component: { template: "<div/>" } },
    ],
  });
  await router.push("/c/payments");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = mount(IssuanceGrantEditor, {
    props: { env: "prod", consumerId: "payments", ...props },
    attachTo: document.body,
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: { template: "<a><slot /></a>" } },
    },
  });
  await flushPromises();
  return { wrapper, router };
};

describe("IssuanceGrantEditor edit mode", () => {
  it("saves with If-Match equal to the loaded version, a key and the full body", async () => {
    const api = fake();
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-display-name"]').setValue("renamed");
    await wrapper.get("form").trigger("submit");
    await flushPromises();

    expect(api.updateIssuanceGrant).toHaveBeenCalledTimes(1);
    const [consumerId, name, version, body, key] = api.updateIssuanceGrant.mock.calls[0] as [
      string,
      string,
      string,
      PkiGrantInput,
      string,
    ];
    expect([consumerId, name, version]).toEqual(["payments", "web", "v1"]);
    expect(typeof key).toBe("string");
    expect(body).toEqual({
      caId: "ca-1",
      displayName: "renamed",
      status: "ACTIVE",
      names: {
        dns: { allow: ["*.payments.example.com"], deny: [] },
        commonName: { mode: "san", addToSans: true },
      },
      keyAlgorithms: ["ECDSA_P256"],
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
      lifetime: { defaultSeconds: 86_400, maxSeconds: 86_400, minSeconds: 3600 },
      quotas: { perHour: 100, perDay: 1000 },
    });
    wrapper.unmount();
  });

  it("shows the stale panel on 412, keeps the draft, and reload adopts only the version", async () => {
    const fresh = baseGrant({
      version: "v9",
      updatedAt: "2026-11-05T00:00:00Z",
      updatedBy: { type: "human", id: "alice", email: "alice@example.com" },
      displayName: "alice was here",
    });
    const api = fake({
      updateIssuanceGrant: vi.fn(async () => {
        throw new ApiError(412, "precondition_failed", "stale");
      }),
    });
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-display-name"]').setValue("my edit");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(api.updateIssuanceGrant).toHaveBeenCalledTimes(1);
    expect(wrapper.text()).toContain("Your draft is intact");

    api.getAdminIssuanceGrant.mockResolvedValue(fresh);
    const reload = wrapper.findAll("button").find((b) => b.text().includes("Reload current revision"));
    await reload?.trigger("click");
    await flushPromises();

    expect((wrapper.get('[data-testid="grant-display-name"]').element as HTMLInputElement).value).toBe("my edit");
    expect(wrapper.get('[data-testid="stale-note"]').text()).toContain("alice@example.com saved version v9");

    api.updateIssuanceGrant.mockResolvedValue(baseGrant({ version: "v10" }));
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(api.updateIssuanceGrant.mock.calls[1]?.[2]).toBe("v9");
    wrapper.unmount();
  });

  it("offers to discard the draft on a stale save", async () => {
    const api = fake({
      updateIssuanceGrant: vi.fn(async () => {
        throw new ApiError(412, "precondition_failed", "stale");
      }),
    });
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-display-name"]').setValue("my edit");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    api.getAdminIssuanceGrant.mockResolvedValue(baseGrant({ version: "v3", displayName: "theirs" }));
    await wrapper.get('[data-testid="discard-draft"]').trigger("click");
    await flushPromises();
    expect((wrapper.get('[data-testid="grant-display-name"]').element as HTMLInputElement).value).toBe("theirs");
    wrapper.unmount();
  });

  it("validates without a key and maps errors to lines", async () => {
    const result: PkiGrantValidationResult = {
      valid: false,
      errors: [{ code: "invalid_rule", path: "policy.names.dns.allow[0]", message: "bad rule" }],
      warnings: [],
    };
    const api = fake({ validateIssuanceGrantUpdate: vi.fn(async () => result) });
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-validate"]').trigger("click");
    await flushPromises();

    expect(api.validateIssuanceGrantUpdate).toHaveBeenCalledTimes(1);
    const call = api.validateIssuanceGrantUpdate.mock.calls[0] ?? [];
    expect(call.slice(0, 3)).toEqual(["payments", "web", "v1"]);
    expect(call).toHaveLength(4);
    expect(wrapper.text()).toContain("Line 1: bad rule");
    expect(api.updateIssuanceGrant).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("deletes with If-Match, says nothing is revoked, and never revokes", async () => {
    const api = fake();
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-delete-open"]').trigger("click");
    expect(wrapper.get('[role="dialog"]').text()).toContain("Deleting does not revoke certificates");
    await wrapper.get('[data-testid="grant-delete-confirm"]').trigger("click");
    await flushPromises();

    expect(api.deleteIssuanceGrant).toHaveBeenCalledTimes(1);
    const call = api.deleteIssuanceGrant.mock.calls[0] ?? [];
    expect(call.slice(0, 3)).toEqual(["payments", "web", "v1"]);
    expect(typeof call[3]).toBe("string");
    expect(api.revokeConsumerPkiCertificates).not.toHaveBeenCalled();

    // The follow-up bulk revoke is prefilled but only ever by an explicit action.
    await wrapper.get('[data-testid="revoke-after-delete"]').trigger("click");
    expect((wrapper.get('[data-testid="bulk-scope"]').element as HTMLSelectElement).value).toBe("web");
    expect(api.revokeConsumerPkiCertificates).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("reloads the current revision after a stale delete and confirms with the new version", async () => {
    const api = fake({
      deleteIssuanceGrant: vi
        .fn()
        .mockRejectedValueOnce(new ApiError(412, "precondition_failed", "stale"))
        .mockResolvedValue(baseGrant({ status: "DELETED" })),
    });
    const { wrapper } = await mountEditor(api);
    await wrapper.get('[data-testid="grant-delete-open"]').trigger("click");
    await wrapper.get('[data-testid="grant-delete-confirm"]').trigger("click");
    await flushPromises();
    expect(api.deleteIssuanceGrant.mock.calls[0]?.[2]).toBe("v1");

    api.getAdminIssuanceGrant.mockResolvedValue(baseGrant({ version: "v4" }));
    const reload = wrapper.findAll("button").find((b) => b.text().includes("Reload current revision"));
    await reload?.trigger("click");
    await flushPromises();

    await wrapper.get('[data-testid="grant-delete-open"]').trigger("click");
    await wrapper.get('[data-testid="grant-delete-confirm"]').trigger("click");
    await flushPromises();
    expect(api.deleteIssuanceGrant).toHaveBeenCalledTimes(2);
    expect(api.deleteIssuanceGrant.mock.calls[1]?.[2]).toBe("v4");
    wrapper.unmount();
  });

  it("is read-only when the policy has fields the form cannot represent", async () => {
    const api = fake({
      getAdminIssuanceGrant: vi.fn(async () =>
        baseGrant({ policy: { ...baseGrant().policy, futureField: { x: 1 } } }),
      ),
    });
    const { wrapper } = await mountEditor(api);
    expect(wrapper.get('[data-testid="readonly-notice"]').text()).toContain("use the CLI");
    expect(wrapper.find('[data-testid="grant-save"]').exists()).toBe(false);
    expect(wrapper.text()).toContain("futureField");
    expect(api.updateIssuanceGrant).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("does not refetch on window focus", async () => {
    const api = fake();
    const { wrapper } = await mountEditor(api);
    window.dispatchEvent(new Event("focus"));
    await flushPromises();
    expect(api.getAdminIssuanceGrant).toHaveBeenCalledTimes(1);
    expect(api.getPkiCa).toHaveBeenCalledTimes(1);
    wrapper.unmount();
  });

  it("re-runs the last test once after a save and shows the dirty banner meanwhile", async () => {
    const evaluate = vi.fn(async () => ({
      decision: "deny" as const,
      denial: { reason: "name_not_permitted", detail: "no" },
      trace: [],
      context: {
        grant: { status: "ACTIVE" as const, expired: false },
        ca: { status: "ACTIVE", keyState: "ACTIVE" },
        capacity: { capacity: 10 },
        quotas: {
          grantHour: { count: 0, limit: 1 },
          grantDay: { count: 0, limit: 1 },
          caHour: { count: 0, limit: 1 },
        },
      },
    }));
    const api = fake({ evaluateIssuanceGrant: evaluate });
    const { wrapper } = await mountEditor(api);
    expect(wrapper.find('[data-testid="dirty-banner"]').exists()).toBe(false);
    await wrapper.findAll("form")[1]?.trigger("submit");
    await flushPromises();
    expect(evaluate).toHaveBeenCalledTimes(1);

    await wrapper.get('[data-testid="grant-display-name"]').setValue("edited");
    expect(wrapper.get('[data-testid="dirty-banner"]').text()).toContain("version v1");
    await wrapper.findAll("form")[0]?.trigger("submit");
    await flushPromises();
    expect(api.updateIssuanceGrant).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledTimes(2);
    expect(wrapper.find('[data-testid="dirty-banner"]').exists()).toBe(false);
    wrapper.unmount();
  });
});

describe("IssuanceGrantEditor create mode", () => {
  it("posts the create request, disables the tester and keeps a name error", async () => {
    const api = fake({
      createIssuanceGrant: vi.fn(async () => {
        throw new ApiError(409, "conflict", "exists", "c1", undefined, { reason: "grant_exists" });
      }),
    });
    const { wrapper } = await mountEditor(api, { caId: "ca-1" });
    expect(wrapper.find('[data-testid="tester-disabled"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="eval-run"]').exists()).toBe(false);
    expect(api.getAdminIssuanceGrant).not.toHaveBeenCalled();

    await wrapper.get('[data-testid="grant-name"]').setValue("web");
    await wrapper.get("form").trigger("submit");
    await flushPromises();

    expect(api.createIssuanceGrant).toHaveBeenCalledTimes(1);
    const [consumerId, body, key] = api.createIssuanceGrant.mock.calls[0] as [string, PkiGrantInput & { name: string }, string];
    expect(consumerId).toBe("payments");
    expect(body.name).toBe("web");
    expect(body.caId).toBe("ca-1");
    expect(typeof key).toBe("string");
    expect(wrapper.text()).toContain("A grant with that name already exists.");
    wrapper.unmount();
  });

  it("makes no GET when reloading a stale state in create mode", async () => {
    const api = fake({
      createIssuanceGrant: vi.fn(async () => {
        throw new ApiError(412, "precondition_failed", "stale");
      }),
    });
    const { wrapper } = await mountEditor(api, { caId: "ca-1" });
    await wrapper.get('[data-testid="grant-name"]').setValue("web");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    const reload = wrapper.findAll("button").find((b) => b.text().includes("Reload current revision"));
    expect(reload).toBeDefined();
    await reload?.trigger("click");
    await flushPromises();
    expect(api.getAdminIssuanceGrant).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("blocks an invalid name locally and lists only active issuing CAs", async () => {
    const api = fake({
      listPkiCas: vi.fn(async () => ({
        cas: [
          caSummary,
          { ...caSummary, caId: "ca-root", kind: "ROOT" as const },
          { ...caSummary, caId: "ca-old", status: "RETIRED" as const },
        ],
        generatedAt: "now",
      })),
    });
    const { wrapper } = await mountEditor(api, {});
    const options = wrapper.get('[data-testid="grant-ca"]').findAll("option").map((o) => o.text());
    expect(options.join("|")).toContain("ca-1");
    expect(options.join("|")).not.toContain("ca-root");
    expect(options.join("|")).not.toContain("ca-old");

    await wrapper.get('[data-testid="grant-name"]').setValue("Bad Name");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(api.createIssuanceGrant).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("lowercase letters");
    wrapper.unmount();
  });

  it("warns for Ed25519 and for a quota above the CA rate", async () => {
    const { wrapper } = await mountEditor(fake(), { caId: "ca-1" });
    expect(wrapper.find('[data-testid="ed25519-warning"]').exists()).toBe(false);
    const ed = wrapper.findAll('input[type="checkbox"]').find((box) => (box.element as HTMLInputElement).value === "ED25519");
    expect((ed?.element as HTMLInputElement).disabled).toBe(true);
    await wrapper.get('[placeholder="default 100"]').setValue("500");
    expect(wrapper.get('[data-testid="quota-warning"]').text()).toContain("50 per hour");
    wrapper.unmount();
  });
});
