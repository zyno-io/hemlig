import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import { parse } from "yaml";
import { caDrained } from "./ca-model";
import { anchorTrusted, caBundleView } from "./bundle-model";
import type { CaCrlState, CaRecord } from "./types";

const block = (label: string) =>
  `-----BEGIN CERTIFICATE-----\n${label}\n-----END CERTIFICATE-----`;
const root = block("ROOT");
const intermediate = block("INTERMEDIATE");
const leaf = block("ISSUING");

const bundleFixture = (overrides: Partial<CaRecord> = {}): CaRecord =>
  ({
    caId: "ca-0a1b",
    environment: "prod",
    name: "prod-issuing-1",
    status: "ACTIVE",
    key: { state: "ACTIVE" },
    crlIssuers: [
      { type: "ca", id: "ca-0a1b" },
      { type: "external", id: `ext-${"a".repeat(40)}` },
    ],
    certificatePem: `${leaf}\n`,
    chainPem: `${intermediate}\n${root}\n`,
    fingerprint: "ab".repeat(32),
    notAfter: "2028-01-01T00:00:00.000Z",
    ...overrides,
  }) as CaRecord;

describe("caBundleView", () => {
  it("splits the anchor from the chain and maps the CRL issuers", () => {
    const view = caBundleView(bundleFixture(), undefined);
    expect(Object.keys(view)).toEqual([
      "caId",
      "name",
      "status",
      "drained",
      "fingerprint",
      "notAfter",
      "anchorPem",
      "anchorTrusted",
      "chainPem",
      "crlIssuers",
    ]);
    expect(view).toMatchObject({
      caId: "ca-0a1b",
      status: "ACTIVE",
      drained: false,
      anchorPem: `${root}\n`,
      anchorTrusted: true,
      chainPem: `${leaf}\n${intermediate}\n`,
      crlIssuers: [
        { id: "ca-0a1b", source: "GENERATED" },
        { id: `ext-${"a".repeat(40)}`, source: "UPLOADED" },
      ],
    });
    expect(anchorTrusted(bundleFixture())).toBe(true);
  });

  it("reports a drained RETIRED CA", () => {
    const retired = bundleFixture({
      status: "RETIRED",
      retiredAt: "2026-01-01T00:00:00.000Z",
      key: { state: "DISABLED" } as CaRecord["key"],
    });
    const crl = {
      revision: 0,
      published: { thisUpdate: "2026-02-01T00:00:00.000Z", revision: 0 },
    } as CaCrlState;
    expect(caDrained(retired, crl)).toBe(true);
    expect(caBundleView(retired, crl)).toMatchObject({
      status: "RETIRED",
      drained: true,
    });
    expect(caDrained(retired, undefined)).toBe(false);
    expect(caDrained(bundleFixture(), crl)).toBe(false);
  });

  it.each(["certificatePem", "chainPem", "fingerprint", "notAfter"] as const)(
    "is a 503 when %s is missing",
    (field) => {
      expect(() =>
        caBundleView(bundleFixture({ [field]: undefined }), undefined),
      ).toThrow(expect.objectContaining({ statusCode: 503 }));
    },
  );
});

describe("Hemlig ROOT and INTERMEDIATE bundle views", () => {
  const rootFixture = (overrides: Partial<CaRecord> = {}): CaRecord =>
    bundleFixture({
      kind: "ROOT",
      caId: "ca-0a1b",
      certificatePem: `${root}\n`,
      chainPem: `${root}\n`,
      crlIssuers: [{ type: "ca", id: "ca-0a1b" }],
      ...overrides,
    });
  const childFixture = (overrides: Partial<CaRecord> = {}): CaRecord =>
    bundleFixture({
      kind: "INTERMEDIATE",
      parentCaId: "ca-root",
      certificatePem: `${intermediate}\n`,
      chainPem: `${root}\n`,
      crlIssuers: [
        { type: "ca", id: "ca-0a1b" },
        { type: "ca", id: "ca-root" },
      ],
      ...overrides,
    });

  it("gives a ROOT an empty chain and its own certificate as the anchor", () => {
    const view = caBundleView(rootFixture(), undefined);
    expect(view).toMatchObject({
      anchorPem: `${root}\n`,
      chainPem: "",
      anchorTrusted: true,
      crlIssuers: [{ id: "ca-0a1b", source: "GENERATED" }],
    });
    expect(Object.keys(view)).toHaveLength(10);
  });

  it.each([
    ["ACTIVE", true],
    ["RETIRED", true],
    ["REVOKED", false],
  ] as const)("trusts a %s ROOT: %s", (status, trusted) => {
    expect(anchorTrusted(rootFixture({ status }))).toBe(trusted);
    expect(caBundleView(rootFixture({ status }), undefined).anchorTrusted).toBe(
      trusted,
    );
  });

  it("is a 503 when a ROOT has no certificate", () => {
    expect(() =>
      caBundleView(rootFixture({ certificatePem: undefined }), undefined),
    ).toThrow(expect.objectContaining({ statusCode: 503 }));
  });

  it("splits an INTERMEDIATE into the root anchor and its own chain", () => {
    const view = caBundleView(childFixture(), undefined, { status: "ACTIVE" });
    expect(view).toMatchObject({
      anchorPem: `${root}\n`,
      chainPem: `${intermediate}\n`,
      anchorTrusted: true,
      crlIssuers: [
        { id: "ca-0a1b", source: "GENERATED" },
        { id: "ca-root", source: "GENERATED" },
      ],
    });
  });

  it.each([
    ["ACTIVE", true],
    ["RETIRED", true],
    ["REVOKED", false],
  ] as const)(
    "follows a %s parent for an INTERMEDIATE: %s",
    (status, trusted) => {
      expect(anchorTrusted(childFixture(), { status })).toBe(trusted);
    },
  );

  it("keeps a trusted anchor for a CA-revoked INTERMEDIATE", () => {
    const child = childFixture({ status: "REVOKED" });
    expect(anchorTrusted(child, { status: "ACTIVE" })).toBe(true);
    expect(
      caBundleView(child, undefined, { status: "ACTIVE" }).anchorTrusted,
    ).toBe(true);
  });

  it("is a 503 when the INTERMEDIATE's parent is missing", () => {
    expect(() => caBundleView(childFixture(), undefined)).toThrow(
      expect.objectContaining({ statusCode: 503 }),
    );
    expect(() => anchorTrusted(childFixture())).toThrow(
      expect.objectContaining({ statusCode: 503 }),
    );
  });

  it("leaves the EXTERNAL view always trusted", () => {
    expect(
      anchorTrusted(bundleFixture({ kind: "EXTERNAL_INTERMEDIATE" })),
    ).toBe(true);
  });

  it("validates a ROOT view against PkiCaBundle", () => {
    const document = parse(
      readFileSync(
        join(__dirname, "../../openapi/consumer-secrets.yaml"),
        "utf8",
      ),
    );
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    ajv.addSchema(document, "openapi.json");
    const validate = ajv.compile({
      $ref: "openapi.json#/components/schemas/PkiCaBundle",
    });
    const view = caBundleView(rootFixture(), undefined);
    expect(validate(view)).toBe(true);
  });
});
