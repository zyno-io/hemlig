import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import type {
  PkiBulkRevokeInput,
  PkiBulkRevokeResponse,
  PkiCertificateSummary,
  PkiIssuanceGrant,
} from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import ConsumerCertificateGrants from "./ConsumerCertificateGrants.vue";

const actor = { type: "human" as const, id: "admin" };

const grant = (name: string, overrides: Partial<PkiIssuanceGrant> = {}): PkiIssuanceGrant => ({
  consumerId: "payments",
  environment: "prod",
  name,
  uid: `pkg-${name}`,
  caId: "ca-1",
  status: "ACTIVE",
  expired: false,
  policy: {},
  policyDigest: "d",
  quotas: { perHour: 100, perDay: 1000 },
  version: "v1",
  createdAt: "2026-11-01T00:00:00Z",
  createdBy: actor,
  updatedAt: "2026-11-01T00:00:00Z",
  updatedBy: actor,
  ...overrides,
});

const cert = (serial: string): PkiCertificateSummary => ({
  caId: "ca-1",
  serial,
  status: "ISSUED",
  storedStatus: "ISSUED",
  fingerprint: "ff",
  subject: "CN=x",
  sans: { dns: ["x.example.com"] },
  keyAlgorithm: "ECDSA_P256",
  notBefore: "2026-11-01T00:00:00Z",
  notAfter: "2027-11-01T00:00:00Z",
  issuedAt: "2026-11-01T00:00:00Z",
  requester: { type: "consumer", id: "payments", issuanceGrant: { name: "web" } },
});

const bulk = (complete: boolean, revoked = 5, already = 1): PkiBulkRevokeResponse => ({
  consumerId: "payments",
  complete,
  revoked,
  alreadyRevoked: already,
  caIds: ["ca-1"],
  crls: [],
});

interface Calls {
  listAdminIssuanceGrants: ReturnType<typeof vi.fn>;
  listConsumerPkiCertificates: ReturnType<typeof vi.fn>;
  revokeConsumerPkiCertificates: ReturnType<typeof vi.fn>;
}

const mountTab = async (overrides: Partial<Calls> = {}) => {
  const calls: Calls = {
    listAdminIssuanceGrants: vi.fn(
      async (_c: string, input: { includeDeleted?: boolean } = {}) => ({
        grants: input.includeDeleted
          ? [grant("web"), grant("old", { status: "DELETED", uid: "pkg-old-1" })]
          : [grant("web")],
        generatedAt: "now",
      }),
    ),
    listConsumerPkiCertificates: vi.fn(async () => ({
      certificates: [cert("0a")],
      generatedAt: "now",
    })),
    revokeConsumerPkiCertificates: vi.fn(async () => bulk(true)),
    ...overrides,
  };
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = calls as unknown as ReturnType<typeof store.requireApi>;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/:rest(.*)*", component: { template: "<div/>" } }],
  });
  await router.push("/");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = mount(ConsumerCertificateGrants, {
    props: { env: "prod", consumerId: "payments" },
    attachTo: document.body,
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: { template: "<a><slot /></a>" } },
    },
  });
  await flushPromises();
  return { wrapper, calls };
};

const typeConsumer = async (wrapper: Awaited<ReturnType<typeof mountTab>>["wrapper"]) => {
  await wrapper.get('[data-testid="typed-confirm-input"]').setValue("payments");
};
const confirm = (wrapper: Awaited<ReturnType<typeof mountTab>>["wrapper"]) =>
  wrapper.get('[data-testid="typed-confirm-confirm"]');

describe("ConsumerCertificateGrants", () => {
  it("lists grants and certificates and refetches grants when includeDeleted toggles", async () => {
    const { wrapper, calls } = await mountTab();
    expect(wrapper.text()).toContain("web");
    expect(wrapper.text()).not.toContain("old");
    expect(calls.listAdminIssuanceGrants).toHaveBeenCalledTimes(1);

    await wrapper.get('[data-testid="include-deleted"]').setValue(true);
    await flushPromises();
    expect(calls.listAdminIssuanceGrants).toHaveBeenCalledTimes(2);
    expect(calls.listAdminIssuanceGrants.mock.calls[1]?.[1]).toMatchObject({ includeDeleted: true });
    expect(wrapper.text()).toContain("old");
    expect(wrapper.text()).toContain("DELETED");
    wrapper.unmount();
  });

  it("filters certificates by grant", async () => {
    const { wrapper, calls } = await mountTab();
    expect(calls.listConsumerPkiCertificates).toHaveBeenCalledTimes(1);
    await wrapper.get('[data-testid="cert-grant-filter"]').setValue("web");
    await flushPromises();
    expect(calls.listConsumerPkiCertificates).toHaveBeenCalledTimes(2);
    expect(calls.listConsumerPkiCertificates.mock.calls[1]?.[1]).toMatchObject({
      issuanceGrant: "web",
    });
    wrapper.unmount();
  });

  it("requires the consumer id to be typed before any revoke", async () => {
    const { wrapper, calls } = await mountTab();
    await wrapper.get('[data-testid="bulk-open"]').trigger("click");
    expect(confirm(wrapper).attributes("disabled")).toBeDefined();
    await wrapper.get('[data-testid="typed-confirm-input"]').setValue("payment");
    expect(confirm(wrapper).attributes("disabled")).toBeDefined();
    expect(calls.revokeConsumerPkiCertificates).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("reuses one key while incomplete and sums the totals", async () => {
    const responses = [bulk(false, 100, 0), bulk(false, 100, 2), bulk(true, 30, 1)];
    const revoke = vi.fn(
      async (_c: string, _i: PkiBulkRevokeInput, _k: string) =>
        responses.shift() ?? bulk(true, 0, 0),
    );
    const { wrapper } = await mountTab({ revokeConsumerPkiCertificates: revoke });
    await wrapper.get('[data-testid="bulk-open"]').trigger("click");
    await typeConsumer(wrapper);
    await wrapper.get("form").trigger("submit");
    await flushPromises();

    expect(revoke).toHaveBeenCalledTimes(3);
    const keys = new Set(revoke.mock.calls.map((call) => call[2]));
    expect(keys.size).toBe(1);
    const result = wrapper.get('[data-testid="bulk-result"]').text();
    expect(result).toContain("Revoked 230");
    expect(result).toContain("3 were already revoked");
    wrapper.unmount();
  });

  it("stops at 20 attempts and runs again on the same key", async () => {
    let calls = 0;
    const revoke = vi.fn(async (_c: string, _i: PkiBulkRevokeInput, _k: string) => {
      calls += 1;
      return bulk(calls > 20 ? true : false, 1, 0);
    });
    const { wrapper } = await mountTab({ revokeConsumerPkiCertificates: revoke });
    await wrapper.get('[data-testid="bulk-open"]').trigger("click");
    await typeConsumer(wrapper);
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(revoke).toHaveBeenCalledTimes(20);
    expect(wrapper.get('[data-testid="bulk-progress"]').text()).toContain("run");
    expect(confirm(wrapper).text()).toBe("Run again");

    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(revoke).toHaveBeenCalledTimes(21);
    expect(new Set(revoke.mock.calls.map((call) => call[2])).size).toBe(1);
    expect(wrapper.get('[data-testid="bulk-result"]').text()).toContain("Revoked 21");
    wrapper.unmount();
  });

  it("scopes to a grant and adds the uid for this generation", async () => {
    const revoke = vi.fn(
      async (_c: string, _i: PkiBulkRevokeInput, _k: string) => bulk(true),
    );
    const { wrapper } = await mountTab({ revokeConsumerPkiCertificates: revoke });
    await wrapper.get('[aria-label="Revoke certificates for web"]').trigger("click");
    await typeConsumer(wrapper);
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(revoke.mock.calls[0]?.[1]).toEqual({ reason: "unspecified", issuanceGrant: "web", issuanceGrantUid: "pkg-web" });
    wrapper.unmount();

    const second = await mountTab({ revokeConsumerPkiCertificates: revoke });
    await second.wrapper.get('[data-testid="bulk-open"]').trigger("click");
    await second.wrapper.get('[data-testid="bulk-scope"]').setValue("web");
    await second.wrapper.get('[data-testid="bulk-generation"]').setValue(false);
    await typeConsumer(second.wrapper);
    await second.wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(revoke.mock.calls[1]?.[1]).toEqual({ reason: "unspecified", issuanceGrant: "web" });
    second.wrapper.unmount();
  });
});
