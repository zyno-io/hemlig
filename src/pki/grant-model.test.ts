import {
  grantCreateDigest,
  parseGrantRequest,
  resolvedQuotas,
} from "./grant-model";
import { caGrantContext } from "./ca-model";
import { samplePolicy } from "./__fixtures__/issuance-harness";
import type { CaRecord } from "./types";

const now = new Date("2026-06-01T00:00:00.000Z");
const base = { caId: "ca-test-one", ...samplePolicy() };

describe("parseGrantRequest", () => {
  it("splits the envelope from the policy fields", () => {
    const parsed = parseGrantRequest(
      {
        ...base,
        name: "web",
        displayName: "Web",
        status: "DISABLED",
        expiresAt: "2026-07-01T12:00:00+02:00",
      },
      "create",
      now,
    );
    expect(parsed.envelope).toEqual({
      name: "web",
      caId: "ca-test-one",
      displayName: "Web",
      status: "DISABLED",
      expiresAt: "2026-07-01T10:00:00.000Z",
    });
    expect(Object.keys(parsed.policyFields).sort()).toEqual(
      ["extendedKeyUsages", "keyUsages", "lifetime", "names"],
    );
  });

  it.each([
    ["expectedGrantUid", { expectedGrantUid: "pkg-x" }],
    ["an unknown key", { nonsense: 1 }],
  ])("rejects %s as unknown_field", (_label, extra) => {
    expect(() =>
      parseGrantRequest({ ...base, name: "web", ...extra }, "create", now),
    ).toThrow(expect.objectContaining({ statusCode: 400, safeReason: "unknown_field" }));
  });

  it("requires the path name on a PUT to match", () => {
    expect(() =>
      parseGrantRequest({ ...base, name: "other" }, "update", now, "web"),
    ).toThrow(expect.objectContaining({ safeReason: "name_mismatch" }));
    expect(
      parseGrantRequest({ ...base, name: "web" }, "update", now, "web").envelope.status,
    ).toBeUndefined();
  });

  it("refuses a DELETED status and a past or unparseable expiry", () => {
    expect(() =>
      parseGrantRequest({ ...base, name: "web", status: "DELETED" }, "create", now),
    ).toThrow(expect.objectContaining({ safeReason: "invalid_status" }));
    for (const expiresAt of ["2026-05-01T00:00:00Z", "soon", 5]) {
      expect(() =>
        parseGrantRequest({ ...base, name: "web", expiresAt }, "create", now),
      ).toThrow(expect.objectContaining({ safeReason: "invalid_expiry" }));
    }
  });

  it("hashes the body independently of key order", () => {
    expect(grantCreateDigest("c-one", { a: 1, b: { x: 1, y: 2 } })).toBe(
      grantCreateDigest("c-one", { b: { y: 2, x: 1 }, a: 1 }),
    );
  });

  it("resolves the default quotas", () => {
    expect(resolvedQuotas(samplePolicy())).toEqual({ perHour: 100, perDay: 1000 });
    expect(resolvedQuotas(samplePolicy({ quotas: { perHour: 5 } }))).toEqual({
      perHour: 5,
      perDay: 1000,
    });
  });
});

describe("caGrantContext", () => {
  const ca = (effective: CaRecord["effective"]): CaRecord =>
    ({
      policy: { leafKeyAlgorithms: ["ECDSA_P256"], maxLeafLifetimeSeconds: 100 },
      effective,
    }) as CaRecord;

  it("converts effective constraints", () => {
    const context = caGrantContext(
      ca({
        nameConstraints: {
          permitted: [
            { type: "dns", value: "example.com" },
            { type: "ip", value: "10.0.0.0/8" },
          ],
          excluded: [{ type: "dns", value: "bad.example.com" }],
        },
        extendedKeyUsages: [
          "1.3.6.1.5.5.7.3.1",
          "1.3.6.1.5.5.7.3.2",
          "2.5.29.37.0",
        ],
      }),
    );
    expect(context.nameConstraints).toEqual({
      permitted: { dns: ["example.com"], ip: ["10.0.0.0/8"] },
      excluded: { dns: ["bad.example.com"] },
    });
    expect(context.extendedKeyUsages).toEqual([
      "serverAuth",
      "clientAuth",
      "2.5.29.37.0",
    ]);
  });

  it("leaves absent constraints absent", () => {
    const context = caGrantContext(ca(undefined));
    expect("nameConstraints" in context).toBe(false);
    expect("extendedKeyUsages" in context).toBe(false);
  });
});
