import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import type { PkiCaSummary, PkiCertificateSummary, PkiExternalCaSummary } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import PkiOverview from "./PkiOverview.vue";

const ca = (over: Partial<PkiCaSummary>): PkiCaSummary => ({
  caId: "ca-a",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "v1",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-11-01T00:00:00Z",
  ...over,
});

const ext = (over: Partial<PkiExternalCaSummary>): PkiExternalCaSummary => ({
  extId: "ext-1",
  fingerprint: "ff",
  spkiSha256: "ab",
  subjectDn: "CN=Offline Root",
  subjectKeyIdentifier: "01",
  notAfter: "2036-01-01T00:00:00Z",
  dependents: ["ca-a"],
  environments: ["prod"],
  version: "v1",
  createdAt: "2026-11-01T00:00:00Z",
  crlState: "CURRENT",
  crl: { numberHex: "0a", nextUpdate: "2026-12-01T00:00:00Z" },
  ...over,
});

const cert = (over: Partial<PkiCertificateSummary>): PkiCertificateSummary => ({
  caId: "ca-a",
  serial: "0a01",
  status: "ISSUED",
  storedStatus: "ISSUED",
  fingerprint: "ff",
  subject: "CN=svc.example.com,O=Acme",
  sans: { dns: ["svc.example.com", "alt.example.com"] },
  keyAlgorithm: "ECDSA_P256",
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: "2099-01-01T00:00:00Z",
  issuedAt: "2026-01-01T00:00:00Z",
  requester: { type: "consumer", id: "c1", issuanceGrant: { name: "web" } },
  ...over,
});

type ListCerts = (
  caId: string,
  input: { status?: string; cursor?: string },
) => Promise<{ certificates: PkiCertificateSummary[]; nextCursor?: string; generatedAt: string }>;

const mountView = async (
  cas: PkiCaSummary[],
  externals: PkiExternalCaSummary[],
  getPkiCa = vi.fn(),
  listPkiCertificates: ReturnType<typeof vi.fn<ListCerts>> = vi.fn<ListCerts>(async () => ({
    certificates: [],
    generatedAt: "2026-11-01T00:00:00Z",
  })),
  query: Record<string, string> = {},
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const listPkiCas = vi.fn(async () => ({ cas, generatedAt: "2026-11-01T00:00:00Z" }));
  const listExternalCas = vi.fn(async () => ({
    externalCas: externals,
    generatedAt: "2026-11-01T00:00:00Z",
  }));
  useAppStore().api = { listPkiCas, listExternalCas, getPkiCa, listPkiCertificates } as unknown as ReturnType<
    ReturnType<typeof useAppStore>["requireApi"]
  >;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/e/:env/pki", name: "pki", component: { template: "<div/>" } },
      { path: "/e/:env/pki/cas/new", name: "pki-ca-new", component: { template: "<div/>" } },
      { path: "/e/:env/pki/cas/:caId", name: "pki-ca", component: { template: "<div/>" } },
      {
        path: "/e/:env/pki/cas/:caId/certificates/:serial",
        name: "pki-certificate",
        component: { template: "<div/>" },
      },
    ],
  });
  await router.push({ name: "pki", params: { env: "prod" }, query });
  await router.isReady();
  const wrapper = mount(PkiOverview, {
    props: query.tab === undefined ? { env: "prod" } : { env: "prod", tab: query.tab as "certificates" },
    global: {
      plugins: [
        pinia,
        router,
        [
          VueQueryPlugin,
          { queryClient: new QueryClient({ defaultOptions: { queries: { retry: false } } }) },
        ],
      ],
      stubs: { RouterLink: false },
    },
  });
  await flushPromises();
  return { wrapper, getPkiCa, listPkiCas, listPkiCertificates, router };
};

describe("PkiOverview", () => {
  it("joins the root CRL state from dependents and warns on MISSING", async () => {
    const { wrapper } = await mountView(
      [ca({ caId: "ca-a" }), ca({ caId: "ca-b", name: "other", kind: "ROOT" })],
      [ext({ crlState: "MISSING", crl: undefined })],
    );
    const rows = wrapper.findAll("tbody tr");
    const first = rows[0];
    expect(first?.find(".tag-warning").text()).toBe("MISSING");
    expect(rows[1]?.text()).toContain("generated, see detail");
  });

  it("filters the roots card by environment", async () => {
    const { wrapper } = await mountView(
      [ca({})],
      [
        ext({ extId: "ext-1", subjectDn: "CN=Prod Root" }),
        ext({ extId: "ext-2", subjectDn: "CN=Staging Root", environments: ["staging"] }),
      ],
    );
    const card = wrapper.get('[data-testid="offline-roots"]');
    expect(card.text()).toContain("CN=Prod Root");
    expect(card.text()).not.toContain("CN=Staging Root");
  });

  it("never reads a CA detail and hides FAILED rows by default", async () => {
    const { wrapper, getPkiCa } = await mountView(
      [ca({ caId: "ca-a" }), ca({ caId: "ca-f", name: "broken-ca", status: "FAILED" })],
      [],
    );
    expect(getPkiCa).not.toHaveBeenCalled();
    expect(wrapper.text()).not.toContain("broken-ca");
    await wrapper.get('[data-testid="hide-failed"]').setValue(false);
    expect(wrapper.text()).toContain("broken-ca");
  });

  it("does not refetch on window focus", async () => {
    const { listPkiCas } = await mountView([ca({})], []);
    window.dispatchEvent(new Event("focus"));
    await flushPromises();
    expect(listPkiCas).toHaveBeenCalledTimes(1);
  });

  it("links roll over with rolloverFrom and opens the upload dialog", async () => {
    const { wrapper } = await mountView([ca({ caId: "ca-a" })], [ext({})]);
    const link = wrapper.findAll("a").find((a) => a.text() === "Roll over");
    expect(link?.attributes("href")).toContain("rolloverFrom=ca-a");
    await wrapper.get('[data-testid="upload-crl-ext-1"]').trigger("click");
    expect(wrapper.text()).toContain("Upload root CRL");
  });

  describe("Certificates tab", () => {
    const two = [ca({ caId: "ca-a", name: "issuer-a" }), ca({ caId: "ca-b", name: "issuer-b" })];
    const byCa = (map: Record<string, PkiCertificateSummary[]>, cursors: Record<string, string> = {}) =>
      vi.fn<ListCerts>(async (caId, input) => {
        const certificates = map[caId];
        if (certificates === undefined) {
          throw new Error("boom");
        }
        const next = cursors[caId];
        return {
          certificates: input.cursor === undefined ? certificates : [],
          ...(next !== undefined && input.cursor === undefined ? { nextCursor: next } : {}),
          generatedAt: "2026-11-01T00:00:00Z",
        };
      });

    it("switches tabs, updates the URL, and loads certificates only when opened", async () => {
      const list = byCa({ "ca-a": [cert({})], "ca-b": [] });
      const { wrapper, router, listPkiCertificates } = await mountView(two, [], vi.fn(), list);
      expect(listPkiCertificates).not.toHaveBeenCalled();
      expect(wrapper.find('[data-testid="certificates-tab"]').exists()).toBe(false);

      await wrapper.get('[data-testid="tab-certificates"]').trigger("click");
      await flushPromises();
      expect(router.currentRoute.value.query.tab).toBe("certificates");
      expect(wrapper.find('[data-testid="certificates-tab"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="offline-roots"]').exists()).toBe(false);
      expect(listPkiCertificates).toHaveBeenCalledTimes(2);

      await wrapper.get('[data-testid="tab-cas"]').trigger("click");
      await flushPromises();
      expect(router.currentRoute.value.query.tab).toBe("cas");
      expect(wrapper.find('[data-testid="offline-roots"]').exists()).toBe(true);
    });

    it("opens on the certificates tab from the tab prop", async () => {
      const { wrapper } = await mountView(two, [], vi.fn(), byCa({ "ca-a": [], "ca-b": [] }), {
        tab: "certificates",
      });
      expect(wrapper.find('[data-testid="certificates-tab"]').exists()).toBe(true);
    });

    it("fans out across CAs and merges rows, soonest expiry first", async () => {
      const list = byCa({
        "ca-a": [cert({ serial: "aa", notAfter: "2099-06-01T00:00:00Z" })],
        "ca-b": [cert({ caId: "ca-b", serial: "bb", notAfter: "2098-01-01T00:00:00Z" })],
      });
      const { wrapper } = await mountView(two, [], vi.fn(), list, { tab: "certificates" });
      expect(list).toHaveBeenCalledWith("ca-a", { status: "ISSUED" });
      expect(list).toHaveBeenCalledWith("ca-b", { status: "ISSUED" });
      const rows = wrapper.findAll("tbody tr");
      expect(rows).toHaveLength(2);
      expect(rows[0]?.text()).toContain("issuer-b");
      expect(rows[1]?.text()).toContain("issuer-a");
      expect(rows[0]?.text()).toContain("svc.example.com");
      expect(rows[0]?.text()).toContain("+1");
      expect(rows[0]?.find("a").attributes("href")).toBe("/e/prod/pki/cas/ca-b/certificates/bb");
    });

    it("maps each filter to the server status and re-queries", async () => {
      const list = byCa({ "ca-a": [], "ca-b": [] });
      const { wrapper } = await mountView(two, [], vi.fn(), list, { tab: "certificates" });
      for (const [id, status] of [
        ["expired", "EXPIRED"],
        ["revoked", "REVOKED"],
        ["all", undefined],
      ] as const) {
        await flushPromises();
        list.mockClear();
        await wrapper.get(`[data-testid="cert-filter-${id}"]`).trigger("click");
        await flushPromises();
        expect(list).toHaveBeenCalledTimes(2);
        expect(list).toHaveBeenCalledWith("ca-a", status === undefined ? {} : { status });
      }
      expect(wrapper.text()).toContain("No certificates in this environment.");
      // Back to a filter that is still fresh in the cache: no second audited read.
      list.mockClear();
      await wrapper.get('[data-testid="cert-filter-active"]').trigger("click");
      await flushPromises();
      expect(list).not.toHaveBeenCalled();
      expect(wrapper.text()).toContain("No active certificates.");
    });

    it("shows a certificate past notAfter as EXPIRED", async () => {
      const list = byCa({
        "ca-a": [cert({ notAfter: "2020-01-01T00:00:00Z" })],
        "ca-b": [],
      });
      const { wrapper } = await mountView(two, [], vi.fn(), list, { tab: "certificates" });
      const badge = wrapper.get("tbody .tag");
      expect(badge.text()).toBe("EXPIRED");
      expect(badge.classes()).toContain("tag-danger");
    });

    it("load more reads only CAs that have a cursor", async () => {
      const list = byCa({ "ca-a": [cert({ serial: "aa" })], "ca-b": [cert({ caId: "ca-b", serial: "bb" })] }, { "ca-a": "next-a" });
      const { wrapper } = await mountView(two, [], vi.fn(), list, { tab: "certificates" });
      expect(wrapper.get('[data-testid="cert-partial"]').text()).toContain("Partial list");
      list.mockClear();
      await wrapper.get('[data-testid="cert-load-more"]').trigger("click");
      await flushPromises();
      expect(list).toHaveBeenCalledTimes(1);
      expect(list).toHaveBeenCalledWith("ca-a", { status: "ISSUED", cursor: "next-a" });
      expect(wrapper.find('[data-testid="cert-load-more"]').exists()).toBe(false);
      expect(wrapper.findAll("tbody tr")).toHaveLength(2);
    });

    it("names a failing CA and still renders the others", async () => {
      const list = byCa({ "ca-a": [cert({})] });
      const { wrapper } = await mountView(two, [], vi.fn(), list, { tab: "certificates" });
      expect(wrapper.text()).toContain("issuer-b");
      expect(wrapper.findAll("tbody tr")).toHaveLength(1);
      expect(wrapper.text()).toContain("the certificates of issuer-b");
    });
  });
});
