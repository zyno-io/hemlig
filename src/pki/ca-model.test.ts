import {
  assertHumanReplay,
  assertRootPolicyUpdate,
  caDetail,
  caSummary,
  crlReasonName,
  externalCaDetail,
  parseActivateRequest,
  parseCaPolicy,
  parseCreateCaRequest,
  parseNameConstraints,
  parseUpdateCaRequest,
  parseUploadCrlRequest,
  requestDigest,
  resolvePolicy,
  DEFAULT_ROOT_POLICY,
  rootCrlState,
  subjectDn,
  toSubtreeMap,
} from "./ca-model";
import type { CaRecord, ExternalCaRecord } from "./types";

const base = {
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  keyAlgorithm: "ECDSA_P256",
  subject: { commonName: "Prod Issuing CA 1", organization: "Example Corp" },
};

const reason = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (error) {
    return (error as { details?: { reason?: string }; message: string }).details
      ?.reason;
  }
  return "no error";
};

describe("parseCreateCaRequest", () => {
  it("maps the subject and applies the policy defaults", () => {
    const parsed = parseCreateCaRequest(base);
    expect(parsed.subject).toEqual({
      CN: "Prod Issuing CA 1",
      O: "Example Corp",
    });
    expect(parsed.policy).toEqual({
      issueLeaves: true,
      issueSubordinates: false,
      maxLeafLifetimeSeconds: 90 * 86_400,
      leafKeyAlgorithms: expect.any(Array),
      capacity: 8000,
      issuancePerHour: 2000,
      crlValiditySeconds: 604_800,
    });
    expect(parsed.requested).toEqual({ pathLen: 0 });
  });

  it("accepts the CRL validity in the policy or in crl", () => {
    expect(
      parseCreateCaRequest({ ...base, policy: { crlValiditySeconds: 7200 } })
        .policy.crlValiditySeconds,
    ).toBe(7200);
    expect(
      parseCreateCaRequest({ ...base, crl: { validitySeconds: 3600 } }).policy
        .crlValiditySeconds,
    ).toBe(3600);
    expect(
      reason(() =>
        parseCreateCaRequest({
          ...base,
          crl: { validitySeconds: 3600 },
          policy: { crlValiditySeconds: 7200 },
        }),
      ),
    ).toBe("invalid_policy");
  });

  it("rejects unknown keys, other kinds and bad subjects", () => {
    expect(reason(() => parseCreateCaRequest({ ...base, extra: 1 }))).toBe(
      "unknown_field",
    );
    expect(
      reason(() =>
        parseCreateCaRequest({
          ...base,
          subject: { commonName: "x", cn: "y" },
        }),
      ),
    ).toBe("unknown_field");
    expect(reason(() => parseCreateCaRequest({ ...base, kind: "BOGUS" }))).toBe(
      "kind_not_supported",
    );
    expect(() =>
      parseCreateCaRequest({ ...base, subject: { commonName: "café" } }),
    ).toThrow();
    expect(() => parseCreateCaRequest({ ...base, name: "Bad Name" })).toThrow();
  });

  it("maps constraints and EKUs to the stored shapes", () => {
    const parsed = parseCreateCaRequest({
      ...base,
      requestedConstraints: {
        nameConstraints: {
          permitted: {
            dns: ["Example.com", ".sub.example.com", "example.com"],
            ip: ["10.0.0.0/8"],
          },
          excluded: { uri: ["bad.example.com"] },
        },
        extendedKeyUsages: ["serverAuth"],
      },
    });
    expect(parsed.requested.nameConstraints).toEqual({
      permitted: [
        { type: "dns", value: "example.com" },
        { type: "dns", value: ".sub.example.com" },
        { type: "ip", value: "10.0.0.0/8" },
      ],
      excluded: [{ type: "uri", value: "bad.example.com" }],
    });
    expect(parsed.requested.extendedKeyUsages).toEqual(["1.3.6.1.5.5.7.3.1"]);
    expect(toSubtreeMap(parsed.requested.nameConstraints!)).toEqual({
      permitted: {
        dns: ["example.com", ".sub.example.com"],
        ip: ["10.0.0.0/8"],
      },
      excluded: { uri: ["bad.example.com"] },
    });
  });
});

describe("name constraints", () => {
  it("rejects malformed bases", () => {
    expect(
      reason(() =>
        parseNameConstraints({ permitted: { dns: ["bad_name.com"] } }),
      ),
    ).toBe("invalid_name_constraint");
    expect(
      reason(() => parseNameConstraints({ permitted: { ip: ["10.0.0.1/8"] } })),
    ).toBe("invalid_name_constraint");
    expect(
      reason(() => parseNameConstraints({ permitted: { ip: ["not-a-cidr"] } })),
    ).toBe("invalid_name_constraint");
  });

  it("allows 50 subtrees and rejects 51", () => {
    const dns = (count: number) => ({
      permitted: {
        dns: Array.from({ length: count }, (_, i) => `h${i}.example.com`),
      },
    });
    expect(parseNameConstraints(dns(50))?.permitted).toHaveLength(50);
    expect(reason(() => parseNameConstraints(dns(51)))).toBe(
      "invalid_name_constraint",
    );
  });

  it("reserves the hemlig URI host and stores an empty set as absent", () => {
    expect(
      reason(() => parseNameConstraints({ permitted: { uri: ["hemlig"] } })),
    ).toBe("reserved_name");
    expect(
      reason(() => parseNameConstraints({ permitted: { uri: [".hemlig"] } })),
    ).toBe("reserved_name");
    expect(
      parseNameConstraints({ excluded: { uri: ["hemlig"] } }),
    ).toBeDefined();
    expect(parseNameConstraints({})).toBeUndefined();
  });
});

describe("policy", () => {
  it("enforces the bounds", () => {
    for (const bad of [
      { maxLeafLifetimeSeconds: 299 },
      { capacity: 0 },
      { capacity: 12001 },
      { issuancePerHour: 6001 },
      { crlValiditySeconds: 3599 },
      { leafKeyAlgorithms: [] },
      { leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P256"] },
      { leafKeyAlgorithms: ["DSA"] },
      { bogus: 1 },
    ]) {
      expect(() => parseCaPolicy(bad)).toThrow();
    }
  });

  it("refuses a budget over 12000 and accepts the boundary", () => {
    expect(() =>
      parseCaPolicy({ capacity: 8000, issuancePerHour: 2001 }),
    ).toThrow(expect.objectContaining({ code: "ca_issuance_budget_exceeded" }));
    expect(
      parseCaPolicy({ capacity: 8000, issuancePerHour: 2000 }).capacity,
    ).toBe(8000);
  });

  it("keeps the stored values for omitted fields on update", () => {
    const existing = parseCaPolicy({ capacity: 100, issuancePerHour: 10 });
    expect(parseCaPolicy({ capacity: 200 }, existing)).toMatchObject({
      capacity: 200,
      issuancePerHour: 10,
    });
    expect(parseUpdateCaRequest({ policy: { capacity: 5 } }).policy).toEqual({
      capacity: 5,
    });
    expect(() => parseUpdateCaRequest({})).toThrow();
    expect(parseUpdateCaRequest({ policy: {} })).not.toHaveProperty(
      "displayName",
    );
    expect(parseUpdateCaRequest({ policy: {}, displayName: null })).toEqual({
      policy: {},
      displayName: null,
    });
    expect(() =>
      parseUpdateCaRequest({ policy: {}, displayName: "" }),
    ).toThrow();
  });
});

describe("other parsers and digests", () => {
  it("are strict", () => {
    expect(
      reason(() =>
        parseActivateRequest({ certificatePem: "a", chainPem: "b", x: 1 }),
      ),
    ).toBe("unknown_field");
    expect(reason(() => parseUploadCrlRequest({ crl: "a", x: 1 }))).toBe(
      "unknown_field",
    );
    expect(
      parseActivateRequest({ certificatePem: "a", chainPem: "b" }),
    ).toEqual({
      certificatePem: "a",
      chainPem: "b",
      acceptBroaderConstraints: false,
    });
  });

  it("derives digests that ignore key order", () => {
    expect(requestDigest("x", { a: 1, b: { c: 2, d: 3 } })).toBe(
      requestDigest("x", { b: { d: 3, c: 2 }, a: 1 }),
    );
    expect(requestDigest("x", { a: 1 })).not.toBe(requestDigest("y", { a: 1 }));
  });

  it("rejects a replay of a different operation", () => {
    const stored = { operationType: "pki.ca.create", requestDigest: "d1" };
    expect(() =>
      assertHumanReplay(stored, "pki.ca.create", "d1"),
    ).not.toThrow();
    expect(() => assertHumanReplay(stored, "pki.ca.create", "d2")).toThrow(
      expect.objectContaining({ statusCode: 409 }),
    );
    expect(() => assertHumanReplay(stored, "pki.ca.retire", "d1")).toThrow();
  });

  it("maps CRL reason codes", () => {
    expect(crlReasonName()).toBe("unspecified");
    expect(crlReasonName(0)).toBe("unspecified");
    expect(crlReasonName(1)).toBe("keyCompromise");
    expect(crlReasonName(6)).toBe("certificateHold");
    expect(crlReasonName(9)).toBe("privilegeWithdrawn");
    expect(crlReasonName(10)).toBe("aACompromise");
    expect(crlReasonName(7)).toBe("code:7");
  });

  it("classifies the root CRL state", () => {
    const now = new Date("2026-11-22T00:00:00.000Z");
    expect(rootCrlState(undefined, now)).toBe("MISSING");
    expect(rootCrlState({ nextUpdate: "2026-11-22T00:00:00.000Z" }, now)).toBe(
      "STALE",
    );
    expect(rootCrlState({ nextUpdate: "2026-11-22T00:00:01.000Z" }, now)).toBe(
      "CURRENT",
    );
  });

  it("formats DNs in encoded order", () => {
    expect(
      subjectDn([
        { oid: "2.5.4.6", value: "US" },
        { oid: "0.9.2342.19200300.100.1.25", value: "example" },
        { oid: "1.2.3", value: "odd" },
        { oid: "2.5.4.3", value: "Root" },
      ]),
    ).toBe("C=US, DC=example, 1.2.3=odd, CN=Root");
  });
});

describe("response mappers", () => {
  const ca = {
    caId: "ca-one",
    environment: "prod",
    name: "prod-one",
    kind: "EXTERNAL_INTERMEDIATE",
    status: "ACTIVE",
    version: "pkv-1",
    crlIssuers: [],
    key: {
      custody: "WRAPPED",
      algorithm: "ECDSA_P256",
      spkiSha256: "a".repeat(64),
      state: "ACTIVE",
      wrapped: {
        algorithm: "AES-256-GCM",
        encryptedDataKey: "SECRET-EDK",
        iv: "iv",
        tag: "tag",
        ciphertext: "SECRET-CT",
      },
    },
    subject: { CN: "Prod One", O: "Example" },
    subjectKey: "k",
    requested: { pathLen: 0 },
    policy: parseCaPolicy({}),
    maxIssueLifetimeEverSeconds: 1,
    createdAt: "2026-11-01T00:00:00.000Z",
    createdBy: { type: "human", id: "a" },
    parent: { type: "external", id: "ext-1" },
  } as unknown as CaRecord;

  it("never emits wrapped key material", () => {
    const now = new Date("2026-11-22T00:00:00.000Z");
    const text = JSON.stringify([
      caSummary(ca),
      caDetail(ca, {
        now,
        external: { crl: undefined } as unknown as ExternalCaRecord,
      }),
    ]);
    for (const secret of [
      "wrapped",
      "encryptedDataKey",
      "ciphertext",
      "SECRET",
    ]) {
      expect(text).not.toContain(secret);
    }
    expect(caDetail(ca, { now })).toMatchObject({
      subjectDn: "O=Example, CN=Prod One",
      rootCrl: { extId: "ext-1", state: "MISSING" },
      drained: false,
    });
  });

  it("returns an integer pendingRevocations", () => {
    const view = caDetail(ca, {
      now: new Date("2026-11-22T00:00:00.000Z"),
      crl: {
        revision: 3,
        lastNumber: 2,
        published: {
          number: 2,
          objectKey: "k",
          sha256: "s",
          thisUpdate: "2026-11-21T00:00:00.000Z",
          nextUpdate: "2026-11-28T00:00:00.000Z",
          revision: 1,
          entryCount: 0,
        },
      },
    });
    expect(
      (view.crl as { pendingRevocations: number }).pendingRevocations,
    ).toBe(2);
  });

  it("maps an external CA with sorted sets", () => {
    const view = externalCaDetail(
      {
        extId: "ext-1",
        certificatePem: "pem",
        fingerprint: "f",
        spkiSha256: "s",
        subjectDer: "",
        subjectAttributes: [{ oid: "2.5.4.3", value: "Root" }],
        subjectKey: "k",
        subjectKeyIdentifier: "aa",
        notAfter: "2030-01-01T00:00:00.000Z",
        createdAt: "2026-01-01T00:00:00.000Z",
        dependents: new Set(["ca-b", "ca-a"]),
        environments: new Set(["prod"]),
        version: "v",
      },
      new Date("2026-11-22T00:00:00.000Z"),
    );
    expect(view).toMatchObject({
      dependents: ["ca-a", "ca-b"],
      subjectDn: "CN=Root",
      crlState: "MISSING",
    });
  });
});

describe("EXTERNAL create digest stability (T-A7)", () => {
  it("keeps the digest of an EXTERNAL_INTERMEDIATE create byte-identical", () => {
    // Computed on the Phase 6 code. Stored idempotency records hold this digest, so it must never change.
    const parsed = parseCreateCaRequest({
      environment: "prod",
      name: "prod-issuing-1",
      kind: "EXTERNAL_INTERMEDIATE",
      keyAlgorithm: "ECDSA_P256",
      subject: {
        commonName: "Prod Issuing CA 1",
        organization: "Example Corp",
      },
      requestedConstraints: {
        nameConstraints: { permitted: { dns: ["example.com"] } },
        extendedKeyUsages: ["serverAuth"],
      },
      policy: { capacity: 100 },
      displayName: "Prod",
    });
    expect(requestDigest("pki.ca.create", parsed)).toBe(
      "1306d773c2240662578d0b957368f36d013e1ff9bb4dff19b40e5275d974a5ad",
    );
  });
});

describe("ROOT and INTERMEDIATE creation", () => {
  const root = { ...base, kind: "ROOT" };
  const intermediate = {
    ...base,
    kind: "INTERMEDIATE",
    parentCaId: "ca-root-one",
  };

  it("defaults a ROOT to pathLen 1, no leaf issuance and 3,650 days", () => {
    const parsed = parseCreateCaRequest(root);
    expect(parsed).toMatchObject({
      kind: "ROOT",
      requested: { pathLen: 1 },
      validitySeconds: 315_360_000,
      policy: { issueLeaves: false, issueSubordinates: true },
    });
    expect("parentCaId" in parsed).toBe(false);
  });

  it("defaults an INTERMEDIATE to pathLen 0, leaf issuance and 365 days", () => {
    expect(parseCreateCaRequest(intermediate)).toMatchObject({
      kind: "INTERMEDIATE",
      parentCaId: "ca-root-one",
      requested: { pathLen: 0 },
      validitySeconds: 31_536_000,
      policy: { issueLeaves: true, issueSubordinates: false },
    });
  });

  it("applies the parentCaId rules", () => {
    expect(
      reason(() => parseCreateCaRequest({ ...base, kind: "INTERMEDIATE" })),
    ).toBe("parent_required");
    expect(
      reason(() =>
        parseCreateCaRequest({ ...root, parentCaId: "ca-root-one" }),
      ),
    ).toBe("parent_not_allowed");
    expect(
      reason(() =>
        parseCreateCaRequest({ ...base, parentCaId: "ca-root-one" }),
      ),
    ).toBe("parent_not_allowed");
    expect(() =>
      parseCreateCaRequest({ ...intermediate, parentCaId: "x" }),
    ).toThrow();
  });

  it("checks the validity bounds per kind and refuses it for the EXTERNAL kind", () => {
    const rootOf = (validitySeconds: number) => () =>
      parseCreateCaRequest({ ...root, validitySeconds });
    const childOf = (validitySeconds: number) => () =>
      parseCreateCaRequest({ ...intermediate, validitySeconds });
    expect(rootOf(7_776_000)().kind).toBe("ROOT");
    expect(reason(rootOf(7_775_999))).toBe("invalid_validity");
    expect(rootOf(630_720_000)().kind).toBe("ROOT");
    expect(reason(rootOf(630_720_001))).toBe("invalid_validity");
    expect(childOf(2_592_000)().kind).toBe("INTERMEDIATE");
    expect(reason(childOf(2_591_999))).toBe("invalid_validity");
    expect(reason(childOf(630_720_001))).toBe("invalid_validity");
    expect(
      reason(() => parseCreateCaRequest({ ...root, validitySeconds: 1.5 })),
    ).toBe("invalid_validity");
    expect(
      reason(() =>
        parseCreateCaRequest({ ...base, validitySeconds: 2_592_000 }),
      ),
    ).toBe("validity_not_allowed");
  });

  it("refuses leaf fields on a ROOT and accepts them on an INTERMEDIATE", () => {
    for (const policy of [
      { maxLeafLifetimeSeconds: 3600 },
      { leafKeyAlgorithms: ["ECDSA_P256"] },
    ]) {
      expect(reason(() => parseCreateCaRequest({ ...root, policy }))).toBe(
        "invalid_policy",
      );
    }
    expect(
      parseCreateCaRequest({ ...root, policy: { capacity: 100 } }).policy
        .capacity,
    ).toBe(100);
    expect(
      parseCreateCaRequest({
        ...intermediate,
        policy: { maxLeafLifetimeSeconds: 3600 },
      }).policy.maxLeafLifetimeSeconds,
    ).toBe(3600);
  });

  it("names the three kinds when refusing another", () => {
    try {
      parseCreateCaRequest({ ...base, kind: "BOGUS" });
    } catch (error) {
      expect((error as Error).message).toBe(
        "kind must be EXTERNAL_INTERMEDIATE, ROOT or INTERMEDIATE.",
      );
    }
  });
});

describe("resolvePolicy and root policy updates", () => {
  it("keeps the stored issue flags", () => {
    expect(resolvePolicy({ capacity: 5 }, DEFAULT_ROOT_POLICY)).toMatchObject({
      issueLeaves: false,
      issueSubordinates: true,
      capacity: 5,
    });
    expect(resolvePolicy({})).toMatchObject({
      issueLeaves: true,
      issueSubordinates: false,
    });
  });

  it("passes equal leaf fields and refuses different ones", () => {
    expect(() =>
      assertRootPolicyUpdate(
        {
          maxLeafLifetimeSeconds: DEFAULT_ROOT_POLICY.maxLeafLifetimeSeconds,
          leafKeyAlgorithms: [...DEFAULT_ROOT_POLICY.leafKeyAlgorithms],
          capacity: 7,
        },
        DEFAULT_ROOT_POLICY,
      ),
    ).not.toThrow();
    expect(() => assertRootPolicyUpdate({}, DEFAULT_ROOT_POLICY)).not.toThrow();
    expect(
      reason(() =>
        assertRootPolicyUpdate(
          { maxLeafLifetimeSeconds: 600 },
          DEFAULT_ROOT_POLICY,
        ),
      ),
    ).toBe("invalid_policy");
    expect(
      reason(() =>
        assertRootPolicyUpdate(
          { leafKeyAlgorithms: ["ECDSA_P256"] },
          DEFAULT_ROOT_POLICY,
        ),
      ),
    ).toBe("invalid_policy");
  });

  it("shows parentCaId in the detail", () => {
    const detail = caDetail(
      {
        caId: "ca-child",
        environment: "prod",
        name: "child",
        kind: "INTERMEDIATE",
        status: "ACTIVE",
        version: "v",
        parent: { type: "ca", id: "ca-root-one" },
        parentCaId: "ca-root-one",
        crlIssuers: [],
        key: {
          custody: "WRAPPED",
          algorithm: "ECDSA_P256",
          spkiSha256: "a",
          state: "ACTIVE",
        },
        subject: { CN: "Child" },
        subjectKey: "k",
        requested: { pathLen: 0 },
        policy: parseCaPolicy({}),
        maxIssueLifetimeEverSeconds: 1,
        createdAt: "2026-11-01T00:00:00.000Z",
        createdBy: { type: "human", id: "a" },
      } as unknown as CaRecord,
      { now: new Date("2026-11-22T00:00:00Z") },
    );
    expect(detail.parentCaId).toBe("ca-root-one");
  });
});
