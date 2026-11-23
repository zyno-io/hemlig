import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import { ApiError } from "../api/errors";
import type { PkiCaDetail } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import CaDetail from "./CaDetail.vue";

const actor = { type: "human" as const, id: "admin-1" };
const pem = (label: string, body = "AAAA"): string =>
  `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;

const ca = (over: Partial<PkiCaDetail> = {}): PkiCaDetail => ({
  caId: "ca-1",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "v7",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-11-01T00:00:00Z",
  key: { custody: "KMS", algorithm: "ECDSA_P256", spkiSha256: "ab", state: "ACTIVE" },
  subject: { commonName: "Prod Issuing CA 1" },
  subjectDn: "CN=Prod Issuing CA 1",
  requestedConstraints: {},
  crlIssuers: [],
  policy: {
    issueLeaves: true,
    issueSubordinates: false,
    maxLeafLifetimeSeconds: 7_776_000,
    leafKeyAlgorithms: ["ECDSA_P256"],
    capacity: 1_000,
    issuancePerHour: 100,
    crlValiditySeconds: 604_800,
  },
  maxIssueLifetimeEverSeconds: 0,
  createdBy: actor,
  drained: false,
  crl: {
    number: 12,
    thisUpdate: "2026-11-01T00:00:00Z",
    nextUpdate: "2026-11-08T00:00:00Z",
    entryCount: 1,
    sha256: "aa",
    revision: 1,
    pendingRevocations: 0,
    state: "CURRENT",
  },
  ...over,
});

const grantPage = (count: number) => ({
  grants: Array.from({ length: count }, (_, index) => ({
    consumerId: "payments",
    environment: "prod",
    name: `web-${index}`,
    uid: `g-${index}`,
    caId: "ca-1",
    status: "ACTIVE" as const,
    expired: false,
    policy: {},
    policyDigest: "d",
    quotas: { perHour: 1, perDay: 1 },
    version: "v1",
    createdAt: "2026-11-01T00:00:00Z",
    createdBy: actor,
    updatedAt: "2026-11-01T00:00:00Z",
    updatedBy: actor,
  })),
  generatedAt: "2026-11-01T00:00:00Z",
});

const certPage = { certificates: [], generatedAt: "2026-11-01T00:00:00Z" };

type Api = Record<string, ReturnType<typeof vi.fn>>;

const mountView = async (api: Api, props: { tab?: "overview" | "certificates" | "grants" } = {}) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  useAppStore().api = api as unknown as ReturnType<ReturnType<typeof useAppStore>["requireApi"]>;
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
      {
        path: "/e/:env/consumers/:consumerId/issuance-grants/:name",
        name: "consumer-pki-grant",
        component: { template: "<div/>" },
      },
    ],
  });
  await router.push({ name: "pki-ca", params: { env: "prod", caId: "ca-1" } });
  await router.isReady();
  const wrapper = mount(CaDetail, {
    props: { env: "prod", caId: "ca-1", ...props },
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
  return wrapper;
};
type W = Awaited<ReturnType<typeof mountView>>;

const click = async (wrapper: W, testId: string): Promise<void> => {
  await wrapper.get(`[data-testid="${testId}"]`).trigger("click");
  await flushPromises();
};
const typeName = async (wrapper: W, text: string): Promise<void> => {
  await wrapper.get('[data-testid="typed-confirm-input"]').setValue(text);
};
const confirmButton = (wrapper: W) => wrapper.get('[data-testid="typed-confirm-confirm"]');

beforeEach(() => {
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("CaDetail pending activation", () => {
  const pending = (): PkiCaDetail =>
    ca({
      status: "PENDING_CERTIFICATE",
      csrPem: pem("CERTIFICATE REQUEST"),
      crl: undefined,
    });

  it("activates with exact PEMs and reveals the broader-constraints box on refusal", async () => {
    const activatePkiCa = vi
      .fn()
      .mockRejectedValueOnce(
        new ApiError(400, "chain_invalid", "m", "c", undefined, { reason: "constraints_broader" }),
      )
      .mockResolvedValueOnce(ca());
    const wrapper = await mountView({ getPkiCa: vi.fn(async () => pending()), activatePkiCa });
    const cert = pem("CERTIFICATE", "CCCC");
    const chain = pem("CERTIFICATE", "RRRR");
    const [certArea, chainArea] = wrapper.findAll("textarea");
    await certArea?.setValue(cert);
    await chainArea?.setValue(chain);
    expect(wrapper.find('[data-testid="accept-broader"]').exists()).toBe(false);

    const form = wrapper.get('[data-testid="activation-panel"] form');
    await form.trigger("submit");
    await flushPromises();
    expect(activatePkiCa).toHaveBeenCalledWith(
      "ca-1",
      { certificatePem: cert, chainPem: chain },
      expect.any(String),
    );

    await wrapper.get('[data-testid="accept-broader"]').setValue(true);
    await form.trigger("submit");
    await flushPromises();
    expect(activatePkiCa).toHaveBeenCalledTimes(2);
    expect(activatePkiCa.mock.calls[1]?.[1]).toEqual({
      certificatePem: cert,
      chainPem: chain,
      acceptBroaderConstraints: true,
    });
    expect(activatePkiCa.mock.calls[1]?.[2]).not.toBe(activatePkiCa.mock.calls[0]?.[2]);
    expect(wrapper.find('[data-testid="activation-panel"]').exists()).toBe(false);
  });

  it("offers the CSR download and typed abandon", async () => {
    const deletePkiCa = vi.fn(async () => ca({ status: "FAILED" }));
    const wrapper = await mountView({ getPkiCa: vi.fn(async () => pending()), deletePkiCa });
    await click(wrapper, "abandon");
    await typeName(wrapper, "Prod-Issuing-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await typeName(wrapper, "prod-issuing-1");
    await wrapper.get('[role="dialog"] form').trigger("submit");
    await flushPromises();
    expect(deletePkiCa).toHaveBeenCalledTimes(1);
    expect(deletePkiCa).toHaveBeenCalledWith("ca-1", "v7", expect.any(String));
  });
});

describe("CaDetail abandon stale", () => {
  it("reloads the current revision after a 412 and confirms with the new version", async () => {
    const getPkiCa = vi
      .fn()
      .mockResolvedValueOnce(
        ca({ status: "PENDING_CERTIFICATE", csrPem: pem("CERTIFICATE REQUEST"), crl: undefined }),
      );
    getPkiCa.mockResolvedValue(
      ca({ status: "PENDING_CERTIFICATE", csrPem: pem("CERTIFICATE REQUEST"), crl: undefined, version: "v8" }),
    );
    const deletePkiCa = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(412, "precondition_failed", "stale"))
      .mockResolvedValue(ca({ status: "FAILED" }));
    const wrapper = await mountView({ getPkiCa, deletePkiCa });
    await click(wrapper, "abandon");
    await typeName(wrapper, "prod-issuing-1");
    await wrapper.get('[role="dialog"] form').trigger("submit");
    await flushPromises();
    expect(deletePkiCa.mock.calls[0]?.[1]).toBe("v7");

    const reload = wrapper.findAll("button").find((b) => b.text().includes("Reload current revision"));
    await reload?.trigger("click");
    await flushPromises();
    expect(getPkiCa).toHaveBeenCalledTimes(2);

    await wrapper.get('[role="dialog"] form').trigger("submit");
    await flushPromises();
    expect(deletePkiCa).toHaveBeenCalledTimes(2);
    expect(deletePkiCa.mock.calls[1]?.[1]).toBe("v8");
  });
});

describe("CaDetail certificates filter", () => {
  it("offers only the statuses the server accepts", async () => {
    const wrapper = await mountView(
      { getPkiCa: vi.fn(async () => ca()), listPkiCaCertificates: vi.fn(async () => ({ certificates: [] })) },
      { tab: "certificates" },
    );
    const options = wrapper.findAll('select[aria-label="Status filter"] option').map((o) => o.text());
    expect(options).toEqual(["Any", "ISSUED", "REVOKED", "EXPIRED"]);
  });
});

describe("CaDetail destroy key", () => {
  it("has no destroy button while the key is ACTIVE", async () => {
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () =>
        ca({ status: "RETIRED", drainAt: "2026-12-01T00:00:00Z" }),
      ),
    });
    expect(wrapper.find('[data-testid="destroy-key"]').exists()).toBe(false);
    expect(wrapper.get('[data-testid="drain-notice"]').text()).toContain("2026-12-01T00:00:00Z");
  });

  it("requires the exact name, destroys once, and cancel calls nothing", async () => {
    const destroyPkiCaKey = vi.fn(async () =>
      ca({ status: "RETIRED", key: { custody: "KMS", algorithm: "x", spkiSha256: "a", state: "DESTROYED" } }),
    );
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () =>
        ca({
          status: "RETIRED",
          keyState: "DISABLED",
          key: { custody: "KMS", algorithm: "x", spkiSha256: "a", state: "DISABLED" },
        }),
      ),
      destroyPkiCaKey,
    });

    await click(wrapper, "destroy-key");
    await typeName(wrapper, "PROD-ISSUING-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await wrapper.get('[data-testid="typed-confirm-cancel"]').trigger("click");
    expect(destroyPkiCaKey).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="typed-confirm-input"]').exists()).toBe(false);

    await click(wrapper, "destroy-key");
    await typeName(wrapper, "prod-issuing-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeUndefined();
    await wrapper.get('[role="dialog"] form').trigger("submit");
    await flushPromises();
    expect(destroyPkiCaKey).toHaveBeenCalledTimes(1);
    expect(destroyPkiCaKey).toHaveBeenCalledWith("ca-1", expect.any(String));
  });
});

describe("CaDetail retire", () => {
  const retired = (): PkiCaDetail =>
    ca({
      status: "RETIRED",
      warnings: [{ code: "issuance_grants_reference_ca", message: "Grants still reference this CA." }],
    });

  it("uses a typed dialog when grants are listed and shows the warning", async () => {
    const retirePkiCa = vi.fn(async () => retired());
    const destroyPkiCaKey = vi.fn();
    const deletePkiCa = vi.fn();
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () => ca()),
      listCaIssuanceGrants: vi.fn(async () => grantPage(2)),
      retirePkiCa,
      destroyPkiCaKey,
      deletePkiCa,
    });
    await click(wrapper, "retire");
    expect(wrapper.get('[data-testid="retire-grant-count"]').text()).toContain("2");
    await typeName(wrapper, "prod-issuing-1");
    await wrapper.get('[role="dialog"] form').trigger("submit");
    await flushPromises();

    expect(retirePkiCa).toHaveBeenCalledTimes(1);
    expect(wrapper.get('[data-testid="retire-warning"]').text()).toBe(
      "Grants still reference this CA.",
    );
    expect(destroyPkiCaKey).not.toHaveBeenCalled();
    expect(deletePkiCa).not.toHaveBeenCalled();
  });

  it("uses a plain confirm when no grants reference the CA", async () => {
    const retirePkiCa = vi.fn(async () => ca({ status: "RETIRED" }));
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () => ca()),
      listCaIssuanceGrants: vi.fn(async () => grantPage(0)),
      retirePkiCa,
    });
    await click(wrapper, "retire");
    expect(wrapper.find('[data-testid="typed-confirm-input"]').exists()).toBe(false);
    await click(wrapper, "retire-confirm");
    expect(retirePkiCa).toHaveBeenCalledTimes(1);
  });

  it("uses a typed dialog when the grants could not be loaded", async () => {
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () => ca()),
      listCaIssuanceGrants: vi.fn(async () => {
        throw new ApiError(500, "internal_error", "boom");
      }),
      retirePkiCa: vi.fn(),
    });
    await click(wrapper, "retire");
    expect(wrapper.find('[data-testid="typed-confirm-input"]').exists()).toBe(true);
  });
});

describe("CaDetail downloads, tabs and refetching", () => {
  it("downloads the CRL as a Blob of the exact bytes", async () => {
    const bytes = new Uint8Array([0x30, 0xff, 0x00]);
    const createObjectURL = vi.fn(() => "blob:crl");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const names: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      names.push(this.download);
    });
    const wrapper = await mountView({
      getPkiCa: vi.fn(async () => ca()),
      getAdminCrl: vi.fn(async () => ({ bytes })),
    });
    await click(wrapper, "download-crl");

    const blob = (createObjectURL.mock.calls[0] as unknown[])[0] as Blob;
    const read = await new Promise<number[]>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve([...new Uint8Array(reader.result as ArrayBuffer)]);
      reader.readAsArrayBuffer(blob);
    });
    expect(read).toEqual([0x30, 0xff, 0x00]);
    expect(names).toEqual(["prod-issuing-1-crl-12.crl"]);
    vi.unstubAllGlobals();
  });

  it("passes the status filter on the certificates tab", async () => {
    const listPkiCertificates = vi.fn(async () => certPage);
    const wrapper = await mountView({ getPkiCa: vi.fn(async () => ca()), listPkiCertificates });
    expect(listPkiCertificates).not.toHaveBeenCalled();
    await click(wrapper, "tab-certificates");
    expect(listPkiCertificates).toHaveBeenCalledTimes(1);
    await wrapper.get('select[aria-label="Status filter"]').setValue("REVOKED");
    await wrapper.get('[data-testid="certificates-tab"] form').trigger("submit");
    await flushPromises();
    expect(listPkiCertificates).toHaveBeenLastCalledWith("ca-1", { status: "REVOKED" });
  });

  it("loads grants only when the grants tab is selected", async () => {
    const listCaIssuanceGrants = vi.fn(async () => grantPage(1));
    const wrapper = await mountView({ getPkiCa: vi.fn(async () => ca()), listCaIssuanceGrants });
    expect(listCaIssuanceGrants).not.toHaveBeenCalled();
    await click(wrapper, "tab-grants");
    expect(listCaIssuanceGrants).toHaveBeenCalledTimes(1);
    const link = wrapper.findAll("a").find((a) => a.text() === "web-0");
    expect(link?.attributes("href")).toContain("/consumers/payments/issuance-grants/web-0");
  });

  it("does not refetch the CA on window focus", async () => {
    const getPkiCa = vi.fn(async () => ca());
    await mountView({ getPkiCa });
    window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    await flushPromises();
    expect(getPkiCa).toHaveBeenCalledTimes(1);
  });
});
