import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import { ApiError } from "../api/errors";
import type {
  PkiCertificateDetail,
  PkiLeafRevocationReason,
  PkiRevokeCertificateResponse,
} from "../api/pki-schemas";
import { useAppStore } from "../stores/app";
import CertificateDetail from "./CertificateDetail.vue";

const certificate = (overrides: Partial<PkiCertificateDetail> = {}): PkiCertificateDetail => ({
  caId: "ca-1",
  serial: "0a1b",
  status: "ISSUED",
  storedStatus: "ISSUED",
  fingerprint: "ff00",
  subject: "CN=web.example.com",
  sans: { dns: ["web.example.com"] },
  keyAlgorithm: "ECDSA_P256",
  notBefore: "2026-11-01T00:00:00Z",
  notAfter: "2027-11-01T00:00:00Z",
  issuedAt: "2026-11-01T00:00:00Z",
  requester: {
    type: "consumer",
    id: "payments",
    consumerId: "payments",
    issuanceGrant: { name: "web", uid: "pkg-1" },
    asserted: { kubernetes: { namespace: "pay", name: "web-0", uid: "u1" } },
  },
  certificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  spkiSha256: "ab12",
  keyUsages: ["digitalSignature"],
  extendedKeyUsages: ["serverAuth"],
  ...overrides,
});

const revoked = (reason: string): PkiCertificateDetail =>
  certificate({
    status: "REVOKED",
    storedStatus: "REVOKED",
    revocation: { at: "2026-11-02T00:00:00Z", reason },
  });

const response = (cert: PkiCertificateDetail, extra: Partial<PkiRevokeCertificateResponse> = {}): PkiRevokeCertificateResponse => ({
  certificate: cert,
  crlEntry: true,
  crlPublished: true,
  crlNumber: 7,
  changed: true,
  crl: { number: 7, pendingRevocations: 0 },
  ...extra,
});

interface Fake {
  getPkiCertificate: ReturnType<typeof vi.fn>;
  revokePkiCertificate: ReturnType<typeof vi.fn>;
}

const mountView = async (api: Fake, seed?: (queryClient: QueryClient) => void) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: ["pki-ca", "consumer-pki-grant"].map((name) => ({
      path: `/${name}/:a?/:b?/:c?`,
      name,
      component: { template: "<div/>" },
    })),
  });
  await router.push("/pki-ca");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  seed?.(queryClient);
  const wrapper = mount(CertificateDetail, {
    props: { env: "prod", caId: "ca-1", serial: "0a1b" },
    attachTo: document.body,
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: { template: "<a><slot /></a>" } },
    },
  });
  await flushPromises();
  return wrapper;
};

describe("CertificateDetail", () => {
  it("renders the facts with the caller-asserted label and a named PEM download", async () => {
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: vi.fn(),
    });
    const text = wrapper.text();
    expect(text).toContain("CN=web.example.com");
    expect(text).toContain("caller-asserted");
    expect(text).toContain("pay/web-0");
    expect(text).toContain("ISSUED");
    wrapper.unmount();
  });

  it("revokes once with a key and shows invalidityDate only for keyCompromise", async () => {
    const revoke = vi.fn(
      async (_ca: string, _serial: string, _input: unknown, _key: string) =>
        response(revoked("keyCompromise")),
    );
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: revoke,
    });
    await wrapper.get('[data-testid="revoke-open"]').trigger("click");
    expect(wrapper.find('[data-testid="revoke-invalidity"]').exists()).toBe(false);
    await wrapper.get('[data-testid="revoke-reason"]').setValue("keyCompromise");
    expect(wrapper.find('[data-testid="revoke-invalidity"]').exists()).toBe(true);
    await wrapper.get('[data-testid="revoke-invalidity"]').setValue("2026-11-01T10:00");

    await wrapper.get('[data-testid="revoke-submit"]').trigger("submit");
    await flushPromises();
    expect(revoke).toHaveBeenCalledTimes(1);
    const call = revoke.mock.calls[0] ?? [];
    expect(call[0]).toBe("ca-1");
    expect(call[1]).toBe("0a1b");
    expect(call[2]).toEqual({
      reason: "keyCompromise",
      invalidityDate: new Date("2026-11-01T10:00").toISOString(),
    });
    expect(typeof call[3]).toBe("string");
    wrapper.unmount();
  });

  it("patches the cached environment-wide certificate lists after a revoke", async () => {
    const key = ["pki", "env-certificates", "prod", "active", ["ca-1"]];
    let client: QueryClient | undefined;
    const wrapper = await mountView(
      {
        getPkiCertificate: vi.fn(async () => certificate()),
        revokePkiCertificate: vi.fn(async () => response(revoked("unspecified"))),
      },
      (qc) => {
        client = qc;
        qc.setQueryData(key, [
          { caId: "ca-1", certificates: [certificate()], nextCursor: undefined, error: undefined, outdated: false },
        ]);
      },
    );
    await wrapper.get('[data-testid="revoke-open"]').trigger("click");
    await wrapper.get('[data-testid="revoke-submit"]').trigger("submit");
    await flushPromises();
    const cached = client?.getQueryData<{ certificates: unknown[] }[]>(key);
    expect(cached?.[0]?.certificates).toEqual([]);
    wrapper.unmount();
  });

  it("does not start a second revoke on a second click while submitting", async () => {
    let release: (value: PkiRevokeCertificateResponse) => void = () => undefined;
    const revoke = vi.fn(
      () => new Promise<PkiRevokeCertificateResponse>((resolve) => { release = resolve; }),
    );
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: revoke,
    });
    await wrapper.get('[data-testid="revoke-open"]').trigger("click");
    const form = wrapper.get("form");
    await form.trigger("submit");
    await form.trigger("submit");
    await form.trigger("submit");
    expect(revoke).toHaveBeenCalledTimes(1);
    release(response(revoked("unspecified")));
    await flushPromises();
    wrapper.unmount();
  });

  it("offers only the keyCompromise upgrade for a certificate revoked for another reason", async () => {
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => revoked("superseded")),
      revokePkiCertificate: vi.fn(),
    });
    const open = wrapper.get('[data-testid="revoke-open"]');
    expect(open.text()).toBe("Upgrade to keyCompromise");
    await open.trigger("click");
    const options = wrapper.get('[data-testid="revoke-reason"]').findAll("option");
    expect(options.map((option) => option.text())).toEqual(["keyCompromise"]);
    wrapper.unmount();
  });

  it("offers no action once revoked for keyCompromise", async () => {
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => revoked("keyCompromise")),
      revokePkiCertificate: vi.fn(),
    });
    expect(wrapper.find('[data-testid="revoke-open"]').exists()).toBe(false);
    wrapper.unmount();
  });

  it("offers no revoke on a CA certificate and links to the child CA", async () => {
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => certificate({ childCaId: "ca-child", isCa: true })),
      revokePkiCertificate: vi.fn(),
    });
    expect(wrapper.find('[data-testid="revoke-open"]').exists()).toBe(false);
    expect(wrapper.text()).toContain("ca-child");
    wrapper.unmount();
  });

  it("explains crlEntry false and crlPublished false", async () => {
    const noEntry = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: vi.fn(async () =>
        response(revoked("unspecified"), { crlEntry: false, crlPublished: false }),
      ),
    });
    await noEntry.get('[data-testid="revoke-open"]').trigger("click");
    await noEntry.get('[data-testid="revoke-submit"]').trigger("submit");
    await flushPromises();
    expect(noEntry.get('[data-testid="no-crl-entry"]').text()).toContain("expired");
    noEntry.unmount();

    const unpublished = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: vi.fn(async () =>
        response(revoked("unspecified"), { crlPublished: false }),
      ),
    });
    await unpublished.get('[data-testid="revoke-open"]').trigger("click");
    await unpublished.get('[data-testid="revoke-submit"]').trigger("submit");
    await flushPromises();
    expect(unpublished.get('[data-testid="not-published"]').text()).toContain("15 minutes");
    unpublished.unmount();
  });

  it("retries an ambiguous failure with the same key", async () => {
    const keys: string[] = [];
    let attempts = 0;
    const revoke = vi.fn(async (_c: string, _s: string, _i: unknown, key: string) => {
      keys.push(key);
      attempts += 1;
      if (attempts === 1) {
        throw new ApiError(503, "service_unavailable", "down");
      }
      return response(revoked("unspecified" as PkiLeafRevocationReason));
    });
    const wrapper = await mountView({
      getPkiCertificate: vi.fn(async () => certificate()),
      revokePkiCertificate: revoke,
    });
    await wrapper.get('[data-testid="revoke-open"]').trigger("click");
    await wrapper.get('[data-testid="revoke-submit"]').trigger("submit");
    await flushPromises();
    expect(wrapper.text()).toContain("outcome is unknown");
    const retry = wrapper.findAll("button").find((b) => b.text().includes("Retry with the same key"));
    await retry?.trigger("click");
    await flushPromises();
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
    wrapper.unmount();
  });
});
