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
