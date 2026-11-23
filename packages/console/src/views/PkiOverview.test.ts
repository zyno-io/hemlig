import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import type { PkiCaSummary, PkiExternalCaSummary } from "../api/pki-schemas";
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

const mountView = async (
  cas: PkiCaSummary[],
  externals: PkiExternalCaSummary[],
  getPkiCa = vi.fn(),
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const listPkiCas = vi.fn(async () => ({ cas, generatedAt: "2026-11-01T00:00:00Z" }));
  const listExternalCas = vi.fn(async () => ({
    externalCas: externals,
    generatedAt: "2026-11-01T00:00:00Z",
  }));
  useAppStore().api = { listPkiCas, listExternalCas, getPkiCa } as unknown as ReturnType<
    ReturnType<typeof useAppStore>["requireApi"]
  >;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/e/:env/pki", name: "pki", component: { template: "<div/>" } },
      { path: "/e/:env/pki/cas/new", name: "pki-ca-new", component: { template: "<div/>" } },
      { path: "/e/:env/pki/cas/:caId", name: "pki-ca", component: { template: "<div/>" } },
    ],
  });
  await router.push({ name: "pki", params: { env: "prod" } });
  await router.isReady();
  const wrapper = mount(PkiOverview, {
    props: { env: "prod" },
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
  return { wrapper, getPkiCa, listPkiCas };
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
});
