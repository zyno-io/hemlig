import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import { ApiError } from "../api/errors";
import { ED25519_WARNING, EXTERNAL_ROOT_RECOMMENDATION } from "../api/pki-format";
import type { PkiCaDetail, PkiCaSummary } from "../api/pki-schemas";
import CopyField from "../components/CopyField.vue";
import { useAppStore } from "../stores/app";
import CaCreate from "./CaCreate.vue";

const actor = { type: "human" as const, id: "admin-1" };

const detail = (over: Partial<PkiCaDetail> = {}): PkiCaDetail => ({
  caId: "ca-base",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "v1",
  keyAlgorithm: "ECDSA_P384",
  keyState: "ACTIVE",
  createdAt: "2026-11-01T00:00:00Z",
  key: { custody: "KMS", algorithm: "ECDSA_P384", spkiSha256: "ab", state: "ACTIVE" },
  subject: { commonName: "Prod Issuing CA 1", organization: "Example" },
  subjectDn: "CN=Prod Issuing CA 1,O=Example",
  requestedConstraints: {
    nameConstraints: { permitted: { dns: ["example.com"] } },
    extendedKeyUsages: ["serverAuth"],
  },
  crlIssuers: [],
  policy: {
    issueLeaves: true,
    issueSubordinates: false,
    maxLeafLifetimeSeconds: 7_776_000,
    leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P384"],
    capacity: 9_000,
    issuancePerHour: 1_000,
    crlValiditySeconds: 604_800,
  },
  maxIssueLifetimeEverSeconds: 0,
  createdBy: actor,
  drained: false,
  ...over,
});

const summary = (over: Partial<PkiCaSummary>): PkiCaSummary => ({
  caId: "ca-x",
  environment: "prod",
  name: "x",
  kind: "ROOT",
  status: "ACTIVE",
  version: "v1",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-11-01T00:00:00Z",
  ...over,
});

interface Api {
  listPkiCas?: ReturnType<typeof vi.fn>;
  getPkiCa?: ReturnType<typeof vi.fn>;
  createPkiCa: ReturnType<typeof vi.fn>;
}

const mountView = async (
  api: Api,
  props: { rolloverFrom?: string; kind?: "ROOT" | "INTERMEDIATE" | "EXTERNAL_INTERMEDIATE" } = {},
) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  useAppStore().api = api as unknown as ReturnType<ReturnType<typeof useAppStore>["requireApi"]>;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/e/:env/pki", name: "pki", component: { template: "<div/>" } },
      { path: "/e/:env/pki/cas/:caId", name: "pki-ca", component: { template: "<div/>" } },
    ],
  });
  await router.push({ name: "pki", params: { env: "prod" } });
  await router.isReady();
  const wrapper = mount(CaCreate, {
    props: { env: "prod", ...props },
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
const callArg = (fn: ReturnType<typeof vi.fn>, call: number, arg: number): unknown =>
  (fn.mock.calls as unknown[][])[call]?.[arg];
const input = (wrapper: W, id: string) => wrapper.get(`[data-testid="${id}"]`);
const submitButton = (wrapper: W) => input(wrapper, "create-submit");
const submitForm = async (wrapper: W): Promise<void> => {
  await wrapper.get("form").trigger("submit");
  await flushPromises();
};
const fill = async (wrapper: W, name: string, cn: string): Promise<void> => {
  await input(wrapper, "ca-name").setValue(name);
  await input(wrapper, "subject-commonName").setValue(cn);
};

describe("CaCreate", () => {
  it("lists the kinds by who signs them, recommended first, each with a hint", async () => {
    const wrapper = await mountView({ createPkiCa: vi.fn() });
    const labels = wrapper.findAll("[data-testid^=kind-]").map((label) => label.text());
    expect(labels).toEqual([
      expect.stringContaining("Intermediate signed by your offline root (recommended)"),
      expect.stringContaining("Intermediate signed by a Hemlig root"),
      expect.stringContaining("Root held by Hemlig (not recommended)"),
    ]);
    expect(labels[0]).toContain("You sign the CSR with your root and paste back the certificate.");
    expect(labels[1]).toContain("Hemlig signs it with a root it already holds.");
    expect(labels[2]).toContain("Prefer an offline root.");
    const values = wrapper
      .findAll<HTMLInputElement>('input[name="kind"]')
      .map((radio) => radio.element.value);
    expect(values).toEqual(["EXTERNAL_INTERMEDIATE", "INTERMEDIATE", "ROOT"]);
  });

  it("pre-fills a rollover and blocks a reused DN", async () => {
    const createPkiCa = vi.fn(async () => detail({ caId: "ca-new", name: "prod-issuing-2" }));
    const wrapper = await mountView(
      { getPkiCa: vi.fn(async () => detail()), createPkiCa },
      { rolloverFrom: "ca-base" },
    );

    expect((input(wrapper, "ca-name").element as HTMLInputElement).value).toBe("prod-issuing-2");
    expect((input(wrapper, "subject-commonName").element as HTMLInputElement).value).toBe(
      "Prod Issuing CA 2",
    );
    expect((input(wrapper, "ca-algorithm").element as HTMLSelectElement).value).toBe("ECDSA_P384");
    expect((wrapper.get('textarea[aria-label="Permitted dns"]').element as HTMLTextAreaElement).value).toBe(
      "example.com",
    );
    expect((input(wrapper, "policy-capacity").element as HTMLInputElement).value).toBe("9000");
    expect(submitButton(wrapper).attributes("disabled")).toBeUndefined();

    await input(wrapper, "subject-commonName").setValue("prod issuing ca 1");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
    expect(wrapper.text()).toContain("Subject names are never reused");
    await submitForm(wrapper);
    expect(createPkiCa).not.toHaveBeenCalled();

    await input(wrapper, "subject-commonName").setValue("Prod Issuing CA 2");
    await submitForm(wrapper);
    expect(createPkiCa).toHaveBeenCalledTimes(1);
    const body = callArg(createPkiCa, 0, 0) as Record<string, unknown>;
    expect(body).toMatchObject({
      environment: "prod",
      name: "prod-issuing-2",
      kind: "EXTERNAL_INTERMEDIATE",
      keyAlgorithm: "ECDSA_P384",
      subject: { commonName: "Prod Issuing CA 2", organization: "Example" },
      requestedConstraints: {
        nameConstraints: { permitted: { dns: ["example.com"] } },
        extendedKeyUsages: ["serverAuth"],
      },
      policy: {
        maxLeafLifetimeSeconds: 7_776_000,
        leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P384"],
        capacity: 9_000,
        issuancePerHour: 1_000,
        crlValiditySeconds: 604_800,
      },
    });
    expect(body).not.toHaveProperty("validitySeconds");
  });

  it("blocks a rollover that keeps the base name", async () => {
    const wrapper = await mountView(
      { getPkiCa: vi.fn(async () => detail()), createPkiCa: vi.fn() },
      { rolloverFrom: "ca-base" },
    );
    await input(wrapper, "ca-name").setValue("prod-issuing-1");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
  });

  it("shows the ROOT callout and gates submit on the acknowledgement", async () => {
    const createPkiCa = vi.fn();
    const wrapper = await mountView({ createPkiCa }, { kind: "ROOT" });
    expect(wrapper.get('[data-testid="root-callout"]').text()).toContain(
      EXTERNAL_ROOT_RECOMMENDATION,
    );
    expect(wrapper.find('[data-testid="policy-max-leaf"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="leaf-algorithms"]').exists()).toBe(false);

    await fill(wrapper, "lab-root", "Lab Root");
    await input(wrapper, "subject-country").setValue("US");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
    await input(wrapper, "root-ack").setValue(true);
    expect(submitButton(wrapper).attributes("disabled")).toBeUndefined();

    await input(wrapper, "subject-country").setValue("USA");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
  });

  it("warns about Ed25519 and shows server warnings on success", async () => {
    const createPkiCa = vi.fn(async () =>
      detail({
        caId: "ca-new",
        name: "edge-ca",
        status: "PENDING_CERTIFICATE",
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAA\n-----END CERTIFICATE REQUEST-----\n",
        warnings: [{ code: "ed25519_compatibility", message: "Server says Ed25519 is risky." }],
      }),
    );
    const wrapper = await mountView({ createPkiCa });
    expect(wrapper.find('[data-testid="ed25519-warning"]').exists()).toBe(false);
    await input(wrapper, "ca-algorithm").setValue("ED25519");
    expect(input(wrapper, "ed25519-warning").text()).toBe(ED25519_WARNING);
    await input(wrapper, "ca-algorithm").setValue("ECDSA_P256");
    expect(wrapper.find('[data-testid="ed25519-warning"]').exists()).toBe(false);

    await input(wrapper, "ca-algorithm").setValue("ED25519");
    await fill(wrapper, "edge-ca", "Edge CA");
    await submitForm(wrapper);

    expect(wrapper.get('[data-testid="create-warning"]').text()).toBe("Server says Ed25519 is risky.");
    expect(wrapper.findComponent(CopyField).props("filename")).toBe("edge-ca.csr.pem");
    expect(wrapper.text()).toContain("Continue to CA");
  });

  it("maps ca_subject_in_use to the subject and name_in_use to the name", async () => {
    const createPkiCa = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, "ca_subject_in_use", "m", "c"))
      .mockRejectedValueOnce(
        new ApiError(409, "conflict", "m", "c", undefined, { reason: "name_in_use" }),
      );
    const wrapper = await mountView({ createPkiCa });
    await fill(wrapper, "some-ca", "Some CA");

    await submitForm(wrapper);
    expect(
      wrapper.get("[data-testid=subject-commonName]").element.closest("section")?.textContent,
    ).toContain("That subject name is already claimed");

    await submitForm(wrapper);
    expect(wrapper.get("[data-testid=ca-name]").element.closest("label")?.textContent).toContain(
      "That CA name is already taken",
    );
  });

  it("lists only ACTIVE roots for an intermediate and sends parent and validity", async () => {
    const listPkiCas = vi.fn(async () => ({
      cas: [
        summary({ caId: "ca-root-a", name: "root-a" }),
        summary({ caId: "ca-root-old", name: "root-old", status: "RETIRED" }),
        summary({ caId: "ca-int", name: "int-x", kind: "INTERMEDIATE" }),
      ],
      generatedAt: "2026-11-01T00:00:00Z",
    }));
    const createPkiCa = vi.fn(async () => detail({ caId: "ca-new", name: "int-new" }));
    const wrapper = await mountView({ listPkiCas, createPkiCa }, { kind: "INTERMEDIATE" });

    const options = wrapper.get('[data-testid="ca-parent"]').findAll("option").map((o) => o.text());
    expect(options).toEqual(["Select an active root", "root-a"]);

    await fill(wrapper, "int-new", "Int New");
    await input(wrapper, "ca-parent").setValue("ca-root-a");
    await input(wrapper, "ca-validity").setValue("365d");
    await submitForm(wrapper);

    expect(callArg(createPkiCa, 0, 0)).toMatchObject({
      kind: "INTERMEDIATE",
      parentCaId: "ca-root-a",
      validitySeconds: 365 * 86_400,
    });
  });

  it("omits validitySeconds for an external create", async () => {
    const createPkiCa = vi.fn(async () => detail({ caId: "ca-new", name: "ext-new" }));
    const wrapper = await mountView({ createPkiCa });
    expect(wrapper.find('[data-testid="ca-validity"]').exists()).toBe(false);
    await fill(wrapper, "ext-new", "Ext New");
    await submitForm(wrapper);
    expect(callArg(createPkiCa, 0, 0)).not.toHaveProperty("validitySeconds");
    expect(callArg(createPkiCa, 0, 0)).not.toHaveProperty("policy");
  });

  it("blocks submit when the issuance budget is exceeded", async () => {
    const createPkiCa = vi.fn();
    const wrapper = await mountView({ createPkiCa });
    await fill(wrapper, "ext-new", "Ext New");
    await input(wrapper, "policy-capacity").setValue("10000");
    await input(wrapper, "policy-per-hour").setValue("2000");
    expect(input(wrapper, "budget-error").text()).toContain("12,000");
    expect(submitButton(wrapper).attributes("disabled")).toBeDefined();
    await submitForm(wrapper);
    expect(createPkiCa).not.toHaveBeenCalled();
  });

  it("retries a network failure with the same key", async () => {
    const createPkiCa = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(0, "network", "down"))
      .mockResolvedValueOnce(detail({ caId: "ca-new", name: "ext-new" }));
    const wrapper = await mountView({ createPkiCa });
    await fill(wrapper, "ext-new", "Ext New");
    await submitForm(wrapper);
    expect(wrapper.text()).toContain("The outcome is unknown");

    await wrapper
      .findAll("button")
      .find((b) => b.text() === "Retry with the same key")
      ?.trigger("click");
    await flushPromises();

    expect(createPkiCa).toHaveBeenCalledTimes(2);
    expect(callArg(createPkiCa, 0, 1)).toBe(callArg(createPkiCa, 1, 1));
    expect(wrapper.text()).toContain("Continue to CA");
  });
});
