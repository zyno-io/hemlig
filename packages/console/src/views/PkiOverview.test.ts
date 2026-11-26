import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import type { PkiCaSummary, PkiCertificateSummary, PkiExternalCaSummary } from "../api/pki-schemas";
import { ApiError } from "../api/errors";
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
  casFailure?: Error,
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const listPkiCas = vi.fn(async () => {
    if (casFailure) {
      throw casFailure;
    }
    return { cas, generatedAt: "2026-11-01T00:00:00Z" };
  });
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
  return { wrapper, getPkiCa, listPkiCas, listPkiCertificates, listExternalCas, router };
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

  describe("Certificates tab review fixes", () => {
    const certsTab = { tab: "certificates" };
    const refreshButton = (w: Awaited<ReturnType<typeof mountView>>["wrapper"]) =>
      w.findAll("button").find((b) => b.text() === "Refresh")!;
    const page = (certificates: PkiCertificateSummary[], nextCursor?: string) => ({
      certificates,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      generatedAt: "2026-11-01T00:00:00Z",
    });

    it("drops a load-more page that a Refresh overtook", async () => {
      let release: (() => void) | undefined;
      let firstReads = 0;
      const list = vi.fn<ListCerts>(async (caId, input) => {
        if (input.cursor !== undefined) {
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return page([cert({ serial: "page2" })]);
        }
        if (caId !== "ca-a") {
          return page([]);
        }
        firstReads += 1;
        return firstReads === 1 ? page([cert({ serial: "old" })], "c1") : page([cert({ serial: "fresh" })]);
      });
      const { wrapper } = await mountView(
        [ca({ caId: "ca-a" }), ca({ caId: "ca-b", name: "b" })], [], vi.fn(), list, certsTab,
      );
      await wrapper.get('[data-testid="cert-load-more"]').trigger("click");
      await flushPromises();
      await refreshButton(wrapper).trigger("click");
      await flushPromises();
      release?.();
      await flushPromises();
      expect(wrapper.find('[data-testid="cert-load-more"]').exists()).toBe(false);
      const serials = wrapper.findAll("tbody .mono[title]").map((e) => e.attributes("title"));
      expect(serials).toEqual(["fresh"]);
    });

    it("uses the first SAN, then the serial, when the subject has no CN", async () => {
      const list = vi.fn<ListCerts>(async (caId) =>
        page(caId === "ca-a" ? [cert({ serial: "s1", subject: "" }), cert({ serial: "s2", subject: "", sans: {}, notAfter: "2099-02-01T00:00:00Z" })] : []),
      );
      const { wrapper } = await mountView([ca({ caId: "ca-a" })], [], vi.fn(), list, certsTab);
      const links = wrapper.findAll("tbody tr").map((r) => r.find("a").text());
      expect(links).toEqual(["svc.example.com", "s2"]);
    });

    it("orders by expiry and holds back rows past an unfinished CA, so Load more only appends", async () => {
      const list = vi.fn<ListCerts>(async (caId, input) => {
        if (caId === "ca-a") {
          return input.cursor === undefined
            ? page([cert({ serial: "a1", notAfter: "2030-01-01T00:00:00Z" })], "n")
            : page([cert({ serial: "a2", notAfter: "2032-01-01T00:00:00Z" })]);
        }
        return page([cert({ caId: "ca-b", serial: "b1", notAfter: "2031-01-01T00:00:00Z" })]);
      });
      const { wrapper } = await mountView(
        [ca({ caId: "ca-a" }), ca({ caId: "ca-b", name: "b" })], [], vi.fn(), list, certsTab,
      );
      const serials = () => wrapper.findAll("tbody .mono[title]").map((e) => e.attributes("title"));
      expect(serials()).toEqual(["a1"]);
      expect(wrapper.get('[data-testid="cert-partial"]').text()).toContain("ordered by expiry");
      await wrapper.get('[data-testid="cert-load-more"]').trigger("click");
      await flushPromises();
      expect(serials()).toEqual(["a1", "b1", "a2"]);
    });

    it("does not fan out twice when Refresh finds the CA set changed", async () => {
      const cas = [ca({ caId: "ca-a" })];
      const list = vi.fn<ListCerts>(async () => page([]));
      const { wrapper } = await mountView(cas, [], vi.fn(), list, certsTab);
      expect(list).toHaveBeenCalledTimes(1);
      cas.push(ca({ caId: "ca-b", name: "b" }));
      await refreshButton(wrapper).trigger("click");
      await flushPromises();
      expect(list).toHaveBeenCalledTimes(3); // 1 + the new key's two CAs, once
      list.mockClear();
      await refreshButton(wrapper).trigger("click");
      await flushPromises();
      expect(list).toHaveBeenCalledTimes(2); // unchanged set: one refetch
    });

    it("reads no offline roots on the Certificates tab, and skips FAILED, pending and (for Active) revoked CAs", async () => {
      const cas = [
        ca({ caId: "ca-a" }),
        ca({ caId: "ca-p", status: "PENDING_CERTIFICATE" }),
        ca({ caId: "ca-f", status: "FAILED" }),
        ca({ caId: "ca-r", status: "REVOKED" }),
      ];
      const list = vi.fn<ListCerts>(async () => page([]));
      const { wrapper, listExternalCas } = await mountView(cas, [], vi.fn(), list, certsTab);
      expect(listExternalCas).not.toHaveBeenCalled();
      expect(list.mock.calls.map((c) => c[0])).toEqual(["ca-a"]);
      await refreshButton(wrapper).trigger("click");
      await flushPromises();
      expect(listExternalCas).not.toHaveBeenCalled();
      await wrapper.get('[data-testid="cert-filter-all"]').trigger("click");
      await flushPromises();
      expect(list.mock.calls.map((c) => c[0]).slice(-2)).toEqual(["ca-a", "ca-r"]);
    });

    it("turns an expired cursor into a Refresh prompt, not an error", async () => {
      const list = vi.fn<ListCerts>(async (_caId, input) => {
        if (input.cursor !== undefined) {
          throw new ApiError(400, "bad_request", "cursor expired");
        }
        return page([cert({})], "stale");
      });
      const { wrapper } = await mountView([ca({ caId: "ca-a" })], [], vi.fn(), list, certsTab);
      await wrapper.get('[data-testid="cert-load-more"]').trigger("click");
      await flushPromises();
      expect(wrapper.get('[data-testid="cert-outdated"]').text()).toContain("out of date");
      expect(wrapper.find('[data-testid="cert-load-more"]').exists()).toBe(false);
      expect(wrapper.text()).not.toContain("cursor expired");
      expect(wrapper.findAll("tbody tr")).toHaveLength(1);
    });
  });

  describe("Certificates tab follow-ups", () => {
    const page = (certificates: PkiCertificateSummary[], nextCursor?: string) => ({
      certificates,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      generatedAt: "2026-11-01T00:00:00Z",
    });
    const twoCas = [ca({ caId: "ca-a" }), ca({ caId: "ca-b", name: "b" })];
    // ca-a holds a cursor after one early row; ca-b has a later row that is held back.
    const heldBackList = (cursorFails = false) =>
      vi.fn<ListCerts>(async (caId, input) => {
        if (caId === "ca-a") {
          if (input.cursor !== undefined) {
            throw new ApiError(400, "bad_request", "cursor expired");
          }
          return page([cert({ serial: "a1", notAfter: "2030-01-01T00:00:00Z" })], cursorFails ? "n" : "n");
        }
        return page([cert({ caId: "ca-b", serial: "b1", notAfter: "2031-01-01T00:00:00Z" })]);
      });

    it("searches held-back rows too, ordered by expiry", async () => {
      const { wrapper } = await mountView(twoCas, [], vi.fn(), heldBackList(), { tab: "certificates" });
      const serials = () => wrapper.findAll("tbody .mono[title]").map((e) => e.attributes("title"));
      expect(serials()).toEqual(["a1"]);
      await wrapper.get('input[type="search"]').setValue("b1");
      expect(serials()).toEqual(["b1"]);
      await wrapper.get('input[type="search"]').setValue("svc");
      expect(serials()).toEqual(["a1", "b1"]);
    });

    it("replaces Load more with Refresh while a CA is outdated, and keeps the held-back count", async () => {
      const { wrapper } = await mountView(twoCas, [], vi.fn(), heldBackList(), { tab: "certificates" });
      await wrapper.get('[data-testid="cert-load-more"]').trigger("click");
      await flushPromises();
      expect(wrapper.find('[data-testid="cert-load-more"]').exists()).toBe(false);
      expect(wrapper.find('[data-testid="cert-refresh"]').exists()).toBe(true);
      expect(wrapper.get('[data-testid="cert-partial"]').text()).toContain("1 more loaded, held back");
    });

    it("does not stay on Loading when the first CA list load fails", async () => {
      const { wrapper } = await mountView([], [], vi.fn(), undefined, { tab: "certificates" }, new ApiError(500, "internal_error", "down"));
      expect(wrapper.text()).not.toContain("Loading…");
    });

    it("reads the offline roots once across tab switches, even after they go stale", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        const { wrapper, listExternalCas } = await mountView([ca({})], [ext({})]);
        expect(listExternalCas).toHaveBeenCalledTimes(1);
        await wrapper.get('[data-testid="tab-certificates"]').trigger("click");
        vi.setSystemTime(Date.now() + 5 * 60_000);
        await wrapper.get('[data-testid="tab-cas"]').trigger("click");
        await flushPromises();
        expect(listExternalCas).toHaveBeenCalledTimes(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
