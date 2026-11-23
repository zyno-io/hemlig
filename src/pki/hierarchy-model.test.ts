import {
  assembleCertificate,
  buildCaTbs,
  buildRootTbs,
  parseCertificate,
} from "./asn1/certificate";
import { DEFAULT_ROOT_POLICY } from "./ca-model";
import {
  assertBuiltCaCertificate,
  assertParentCanIssue,
  childValidity,
  deriveChildConstraints,
  hemligAncestors,
  parseRevokeCaRequest,
  rootValidity,
} from "./hierarchy-model";
import { newKey, subjectDer } from "./__fixtures__/testkit";
import type { CaRecord } from "./types";

const now = new Date("2026-11-22T12:00:00.000Z");
const day = 86_400_000;

const rootRecord = (overrides: Partial<CaRecord> = {}): CaRecord =>
  ({
    caId: "ca-root-one",
    environment: "prod",
    name: "hemlig-root",
    kind: "ROOT",
    status: "ACTIVE",
    version: "pkv-1",
    key: {
      custody: "WRAPPED",
      algorithm: "ECDSA_P384",
      spkiSha256: "00",
      state: "ACTIVE",
      wrapped: { algorithm: "AES-256-GCM" },
    },
    policy: { ...DEFAULT_ROOT_POLICY },
    certificatePem:
      "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
    subjectDer: "AA==",
    subjectKeyIdentifier: "aa",
    notBefore: new Date(now.getTime() - day).toISOString(),
    notAfter: new Date(now.getTime() + 3650 * day).toISOString(),
    ...overrides,
  }) as unknown as CaRecord;

const reasonOf = (work: () => unknown): { code?: string; reason?: string } => {
  try {
    work();
  } catch (error) {
    const e = error as {
      code?: string;
      details?: { reason?: string };
      safeReason?: string;
    };
    return { code: e.code, reason: e.details?.reason ?? e.safeReason };
  }
  throw new Error("expected an error");
};

describe("assertParentCanIssue", () => {
  it("returns an active ROOT in the environment", () => {
    const root = rootRecord();
    expect(assertParentCanIssue(root, "prod", now)).toBe(root);
  });

  it.each([
    ["missing", undefined, "prod", "not_found", "parent_not_found"],
    [
      "foreign environment",
      rootRecord(),
      "staging",
      "conflict",
      "parent_environment_mismatch",
    ],
    [
      "an INTERMEDIATE",
      rootRecord({ kind: "INTERMEDIATE" }),
      "prod",
      "ca_not_active",
      "subordinates_not_permitted",
    ],
    [
      "a ROOT that may not issue subordinates",
      rootRecord({
        policy: { ...DEFAULT_ROOT_POLICY, issueSubordinates: false },
      }),
      "prod",
      "ca_not_active",
      "subordinates_not_permitted",
    ],
    [
      "retired",
      rootRecord({ status: "RETIRED" }),
      "prod",
      "ca_not_active",
      "retired",
    ],
    [
      "revoked",
      rootRecord({ status: "REVOKED" }),
      "prod",
      "ca_not_active",
      "revoked",
    ],
    [
      "a disabled key",
      rootRecord({
        key: { ...rootRecord().key, state: "DISABLED" },
      }),
      "prod",
      "ca_key_unavailable",
      "ca_key_unavailable",
    ],
    [
      "not yet valid",
      rootRecord({ notBefore: new Date(now.getTime() + day).toISOString() }),
      "prod",
      "ca_not_active",
      "not_yet_valid",
    ],
    [
      "expired",
      rootRecord({ notAfter: now.toISOString() }),
      "prod",
      "ca_not_active",
      "expired",
    ],
    [
      "without a certificate",
      rootRecord({ certificatePem: undefined }),
      "prod",
      "service_unavailable",
      undefined,
    ],
  ])("refuses %s", (_label, parent, environment, code, reason) => {
    const got = reasonOf(() =>
      assertParentCanIssue(parent as CaRecord | undefined, environment, now),
    );
    expect(got.code).toBe(code);
    if (reason !== undefined) {
      expect(got.reason).toBe(reason);
    }
  });

  it("refuses a missing wrapped key", () => {
    const key = { ...rootRecord().key, wrapped: undefined };
    expect(
      reasonOf(() => assertParentCanIssue(rootRecord({ key }), "prod", now))
        .code,
    ).toBe("ca_key_unavailable");
  });
});

describe("deriveChildConstraints", () => {
  const nc = (...dns: string[]) => ({
    permitted: dns.map((value) => ({ type: "dns" as const, value })),
    excluded: [],
  });
  const requested = (overrides: Partial<CaRecord["requested"]> = {}) => ({
    pathLen: 0 as const,
    ...overrides,
  });

  it("inherits NameConstraints and EKU when the request has none", () => {
    expect(
      deriveChildConstraints(
        {
          nameConstraints: nc("example.com"),
          extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
        },
        requested(),
      ),
    ).toEqual({
      nameConstraints: nc("example.com"),
      extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
    });
  });

  it("accepts a permitted subset and an EKU subset", () => {
    expect(
      deriveChildConstraints(
        {
          nameConstraints: nc("example.com"),
          extendedKeyUsages: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
        },
        requested({
          nameConstraints: nc("api.example.com"),
          extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
        }),
      ),
    ).toEqual({
      nameConstraints: nc("api.example.com"),
      extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
    });
  });

  it("passes the child's own constraints through under an unconstrained parent", () => {
    expect(
      deriveChildConstraints(
        undefined,
        requested({ nameConstraints: nc("example.org") }),
      ),
    ).toEqual({ nameConstraints: nc("example.org") });
    expect(deriveChildConstraints({}, requested())).toEqual({});
  });

  it("refuses a permitted base outside the parent's", () => {
    expect(
      reasonOf(() =>
        deriveChildConstraints(
          { nameConstraints: nc("example.com") },
          requested({ nameConstraints: nc("example.org") }),
        ),
      ),
    ).toEqual({
      code: "bad_request",
      reason: "name_constraints_broader_than_parent",
    });
  });

  it("refuses a child that omits a parent exclusion", () => {
    expect(
      reasonOf(() =>
        deriveChildConstraints(
          {
            nameConstraints: {
              permitted: [{ type: "dns", value: "example.com" }],
              excluded: [{ type: "dns", value: "bad.example.com" }],
            },
          },
          requested({ nameConstraints: nc("example.com") }),
        ),
      ).reason,
    ).toBe("name_constraints_broader_than_parent");
  });

  it("refuses an EKU superset", () => {
    expect(
      reasonOf(() =>
        deriveChildConstraints(
          { extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"] },
          requested({
            extendedKeyUsages: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
          }),
        ),
      ).reason,
    ).toBe("extended_key_usage_broader_than_parent");
  });
});

describe("validity", () => {
  const parent = (notAfterDays: number) => ({
    notBefore: new Date(now.getTime() - day).toISOString(),
    notAfter: new Date(now.getTime() + notAfterDays * day).toISOString(),
  });

  it("backdates a minute and keeps the requested lifetime when it fits", () => {
    const v = childValidity(parent(3650), 365 * 86_400, now);
    expect(v.notBefore.toISOString()).toBe("2026-11-22T11:59:00.000Z");
    expect(v.notAfter.getTime() - v.notBefore.getTime()).toBe(365 * day);
    expect(v.clamped).toBe(false);
    expect(v.lifetimeSeconds).toBe(365 * 86_400);
  });

  it("starts no earlier than the parent and clamps to its notAfter", () => {
    const early = {
      notBefore: new Date(now.getTime() - 30_000).toISOString(),
      notAfter: new Date(now.getTime() + 100 * day).toISOString(),
    };
    const v = childValidity(early, 365 * 86_400, now);
    expect(v.notBefore.toISOString()).toBe(early.notBefore);
    expect(v.notAfter.toISOString()).toBe(early.notAfter);
    expect(v.clamped).toBe(true);
  });

  it("accepts exactly 30 days and refuses one second less", () => {
    const exact = {
      notBefore: new Date(now.getTime() - 60_000).toISOString(),
      notAfter: new Date(now.getTime() - 60_000 + 30 * day).toISOString(),
    };
    expect(childValidity(exact, 365 * 86_400, now).lifetimeSeconds).toBe(
      30 * 86_400,
    );
    const short = {
      ...exact,
      notAfter: new Date(
        now.getTime() - 60_000 + 30 * day - 1000,
      ).toISOString(),
    };
    expect(reasonOf(() => childValidity(short, 365 * 86_400, now))).toEqual({
      code: "conflict",
      reason: "parent_validity_insufficient",
    });
  });

  it("accepts the 30-day minimum request under a long-lived parent", () => {
    expect(childValidity(parent(3650), 2_592_000, now).lifetimeSeconds).toBe(
      2_592_000,
    );
  });

  it("builds a root window from a minute ago", () => {
    const v = rootValidity(7_776_000, now);
    expect(v.notBefore.toISOString()).toBe("2026-11-22T11:59:00.000Z");
    expect(v.notAfter.getTime() - v.notBefore.getTime()).toBe(90 * day);
  });
});

describe("parseRevokeCaRequest", () => {
  const future = new Date("2026-06-01T00:00:00Z");

  it("defaults to unspecified and accepts every CA reason", () => {
    expect(parseRevokeCaRequest({}, future)).toMatchObject({
      reason: "unspecified",
    });
    for (const reason of [
      "caCompromise",
      "affiliationChanged",
      "superseded",
      "cessationOfOperation",
      "privilegeWithdrawn",
    ]) {
      expect(parseRevokeCaRequest({ reason }, future).reason).toBe(reason);
    }
  });

  it("takes an invalidity date only with caCompromise and not from the future", () => {
    expect(
      parseRevokeCaRequest(
        { reason: "caCompromise", invalidityDate: "2026-05-01T00:00:00Z" },
        future,
      ).invalidityDate,
    ).toBe("2026-05-01T00:00:00.000Z");
    expect(
      reasonOf(() =>
        parseRevokeCaRequest(
          { reason: "superseded", invalidityDate: "2026-05-01T00:00:00Z" },
          future,
        ),
      ).reason,
    ).toBe("invalidity_date_requires_ca_compromise");
    expect(
      reasonOf(() =>
        parseRevokeCaRequest(
          { invalidityDate: "2026-05-01T00:00:00Z" },
          future,
        ),
      ).reason,
    ).toBe("invalidity_date_requires_ca_compromise");
    for (const invalidityDate of ["2027-01-01T00:00:00Z", "nope", 5]) {
      expect(
        reasonOf(() =>
          parseRevokeCaRequest(
            { reason: "caCompromise", invalidityDate },
            future,
          ),
        ).reason,
      ).toBe("invalid_invalidity_date");
    }
  });

  it("refuses keyCompromise, unknown reasons, unknown fields and non-objects", () => {
    expect(
      reasonOf(() => parseRevokeCaRequest({ reason: "keyCompromise" }, future)),
    ).toEqual({ code: "bad_request", reason: "invalid_reason" });
    expect(
      reasonOf(() => parseRevokeCaRequest({ reason: 1 }, future)).reason,
    ).toBe("invalid_reason");
    expect(
      reasonOf(() => parseRevokeCaRequest({ other: 1 }, future)).reason,
    ).toBe("unknown_field");
    expect(reasonOf(() => parseRevokeCaRequest([], future)).reason).toBe(
      "invalid_body",
    );
  });
});

describe("assertBuiltCaCertificate", () => {
  const build = async (pathLen = 1) => {
    const key = await newKey("ECDSA_P256");
    const built = buildRootTbs({
      algorithm: "ECDSA_P256",
      serial: Buffer.alloc(20, 1),
      notBefore: new Date("2026-11-22T00:00:00Z"),
      notAfter: new Date("2036-11-22T00:00:00Z"),
      subjectDer: subjectDer("Root"),
      spkiDer: key.spkiDer,
      pathLen,
    });
    const der = assembleCertificate(
      built.tbs,
      built.signatureAlgorithm,
      key.sign(built.tbs),
    );
    return { key, built, der };
  };

  it("returns the parsed certificate for a good one", async () => {
    const { key, built, der } = await build();
    const parsed = assertBuiltCaCertificate(der, built, {
      issuerSpkiDer: key.spkiDer,
      pathLen: 1,
    });
    expect(parsed.fingerprint).toBe(parseCertificate(der).fingerprint);
  });

  it("refuses a tampered signature, swapped TBS bytes and a wrong pathLen with a 503 and no DER in the log", async () => {
    const log = jest.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { key, built, der } = await build();
      const bad = Buffer.from(der);
      bad[bad.length - 2] = (bad[bad.length - 2] as number) ^ 0xff;
      const other = await build(0);
      for (const [certificate, tbs, pathLen] of [
        [bad, built, 1],
        [der, other.built, 1],
        [der, built, 0],
      ] as const) {
        expect(
          reasonOf(() =>
            assertBuiltCaCertificate(certificate, tbs, {
              issuerSpkiDer: key.spkiDer,
              pathLen,
            }),
          ).code,
        ).toBe("service_unavailable");
      }
      const logged = JSON.stringify(log.mock.calls);
      expect(logged).not.toContain(der.toString("base64"));
      expect(logged).not.toContain(der.toString("hex"));
      expect(log.mock.calls.map((call) => call[1])).toEqual([
        { field: "signature" },
        { field: "tbs" },
        { field: "basicConstraints" },
      ]);
    } finally {
      log.mockRestore();
    }
  });

  it("refuses an oversized certificate", async () => {
    const log = jest.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { key, built, der } = await build();
      const padded = Buffer.concat([der, Buffer.alloc(20_000)]);
      // The trailing bytes also break the parse; either way it is refused.
      expect(
        reasonOf(() =>
          assertBuiltCaCertificate(padded, built, {
            issuerSpkiDer: key.spkiDer,
            pathLen: 1,
          }),
        ).code,
      ).toBe("service_unavailable");
    } finally {
      log.mockRestore();
    }
  });

  it("verifies a child built by buildCaTbs under the root's key", async () => {
    const root = await build();
    const rootCert = parseCertificate(root.der);
    const child = await newKey("ECDSA_P256");
    const built = buildCaTbs({
      issuer: rootCert,
      serial: Buffer.alloc(20, 2),
      notBefore: new Date("2026-11-22T00:00:00Z"),
      notAfter: new Date("2027-11-22T00:00:00Z"),
      subjectDer: subjectDer("Child"),
      spkiDer: child.spkiDer,
      pathLen: 0,
    });
    const der = assembleCertificate(
      built.tbs,
      built.signatureAlgorithm,
      root.key.sign(built.tbs),
    );
    expect(
      assertBuiltCaCertificate(der, built, {
        issuerSpkiDer: rootCert.spkiDer,
        pathLen: 0,
      }).basicConstraints?.pathLen,
    ).toBe(0);
  });
});

describe("hemligAncestors", () => {
  it("is empty without a parent and the parent otherwise", () => {
    expect(hemligAncestors({})).toEqual([]);
    expect(hemligAncestors({ parentCaId: "ca-root-one" })).toEqual([
      "ca-root-one",
    ]);
  });
});
