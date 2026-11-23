import { sha256Hex } from "../util/encoding";
import { parseCrl } from "./asn1/crl";
import {
  buildSignedCrl,
  computeDropDueAt,
  CrlService,
  crlObjectKey,
  crlRefreshMarginSeconds,
  crlStaleThresholdSeconds,
  drainPoint,
  evaluateCrl,
  isDrained,
  publishInlineBestEffort,
  selectCrlEntries,
} from "./crl-service";
import { makeIntermediate, makeRoot, newKey } from "./__fixtures__/testkit";
import type { CaCrlState, CaRecord, RevocationEntryRecord } from "./types";

const hour = 3600;
const day = 86_400;

describe("refresh scheduling", () => {
  it.each([
    [hour, 1800, 600],
    [7 * day, 201_600, 67_200],
    [30 * day, 864_000, 172_800],
  ])(
    "validity %d gives margin %d and stale threshold %d",
    (validity, margin, threshold) => {
      expect(crlRefreshMarginSeconds(validity)).toBe(margin);
      expect(crlStaleThresholdSeconds(validity)).toBe(threshold);
    },
  );
});

const published = (
  overrides: Partial<NonNullable<CaCrlState["published"]>> = {},
) => ({
  number: 1,
  objectKey: "k",
  sha256: "s",
  thisUpdate: "2026-11-01T00:00:00.000Z",
  nextUpdate: "2026-11-08T00:00:00.000Z",
  revision: 0,
  entryCount: 0,
  ...overrides,
});
const ca = (overrides: Partial<CaRecord> = {}): CaRecord =>
  ({
    status: "ACTIVE",
    key: { state: "ACTIVE" },
    policy: { crlValiditySeconds: 7 * day },
    maxIssueLifetimeEverSeconds: 3600,
    notAfter: "2027-11-01T00:00:00.000Z",
    ...overrides,
  }) as CaRecord;
const at = (iso: string) => new Date(iso);

describe("evaluateCrl", () => {
  const state = (overrides: Partial<CaCrlState> = {}): CaCrlState => ({
    revision: 0,
    lastNumber: 1,
    published: published(),
    ...overrides,
  });

  it("is quiet while fresh", () => {
    const result = evaluateCrl(ca(), state(), at("2026-11-02T00:00:00.000Z"));
    expect(result.reasons).toEqual([]);
    expect(result.signable).toBe(true);
    expect(result.stale).toBe(false);
  });

  it("asks for a republish when dirty", () => {
    expect(
      evaluateCrl(ca(), state({ revision: 1 }), at("2026-11-02T00:00:00.000Z"))
        .reasons,
    ).toEqual(["dirty"]);
  });

  it("refreshes inside the margin and marks stale below the threshold", () => {
    // nextUpdate - margin(201600 s) = 2026-11-05T16:00
    expect(
      evaluateCrl(ca(), state(), at("2026-11-05T15:59:59.000Z")).reasons,
    ).toEqual([]);
    expect(
      evaluateCrl(ca(), state(), at("2026-11-05T16:00:00.000Z")).reasons,
    ).toEqual(["refresh"]);
    expect(
      evaluateCrl(ca(), state(), at("2026-11-07T12:00:00.000Z")).stale,
    ).toBe(true);
    expect(
      evaluateCrl(ca(), state(), at("2026-11-06T00:00:00.000Z")).stale,
    ).toBe(false);
  });

  it("drops after dropDueAt", () => {
    const withDrop = state({
      published: published({ dropDueAt: "2026-11-01T01:00:00.000Z" }),
    });
    expect(
      evaluateCrl(ca(), withDrop, at("2026-11-01T01:00:00.000Z")).reasons,
    ).toEqual([]);
    expect(
      evaluateCrl(ca(), withDrop, at("2026-11-01T01:00:01.000Z")).reasons,
    ).toEqual(["drop"]);
  });

  it("drains a retired CA after its drain point and then stops", () => {
    const retired = ca({
      status: "RETIRED",
      retiredAt: "2026-11-01T00:00:00.000Z",
    });
    expect(drainPoint(retired)).toBe("2026-11-01T01:00:00.000Z");
    const before = evaluateCrl(
      retired,
      state(),
      at("2026-11-01T01:00:01.000Z"),
    );
    expect(before.reasons).toContain("drain");
    expect(before.drained).toBe(false);
    const after = state({
      published: published({ thisUpdate: "2026-11-01T01:00:01.000Z" }),
    });
    expect(isDrained(retired, after)).toBe(true);
    const result = evaluateCrl(retired, after, at("2026-11-01T01:00:02.000Z"));
    expect(result.drained).toBe(true);
    expect(result.alarmable).toBe(false);
  });

  it("is not drained while a revocation is unpublished", () => {
    const retired = ca({
      status: "RETIRED",
      retiredAt: "2026-11-01T00:00:00.000Z",
    });
    expect(
      isDrained(
        retired,
        state({
          revision: 2,
          published: published({ thisUpdate: "2026-11-02T00:00:00.000Z" }),
        }),
      ),
    ).toBe(false);
  });

  it("never signs REVOKED or key-disabled CAs", () => {
    for (const candidate of [
      ca({ status: "REVOKED" }),
      ca({ key: { state: "DISABLED" } as CaRecord["key"] }),
      ca({ status: "PENDING_CERTIFICATE" }),
    ]) {
      const result = evaluateCrl(
        candidate,
        state({ revision: 5 }),
        at("2027-01-01T00:00:00.000Z"),
      );
      expect(result.signable).toBe(false);
      expect(result.reasons).toEqual([]);
    }
  });
});

describe("entry selection", () => {
  const entry = (notAfter: string): RevocationEntryRecord => ({
    caId: "ca-x",
    serial: "01",
    revokedAt: "2026-01-01T00:00:00.000Z",
    reason: "keyCompromise",
    notAfter,
  });

  it("keeps an entry through an outage until the first CRL after its expiry", () => {
    const e = entry("2026-11-01T01:00:00.000Z");
    // T0 = before expiry, then a long outage, then T1 after expiry, then T2.
    const t0 = "2026-11-01T00:00:00.000Z";
    const t1 = "2026-11-11T00:00:00.000Z";
    expect(selectCrlEntries([e], undefined)).toHaveLength(1);
    expect(selectCrlEntries([e], { thisUpdate: t0 })).toHaveLength(1);
    expect(selectCrlEntries([e], { thisUpdate: t1 })).toHaveLength(0);
  });

  it("computes the drop time from unexpired included entries", () => {
    expect(
      computeDropDueAt(
        [
          entry("2026-11-01T00:30:00.000Z"),
          entry("2026-11-01T05:00:00.000Z"),
          entry("2026-11-01T02:00:00.000Z"),
        ],
        "2026-11-01T01:00:00.000Z",
      ),
    ).toBe("2026-11-01T02:00:00.000Z");
    expect(
      computeDropDueAt(
        [entry("2026-10-01T00:00:00.000Z")],
        "2026-11-01T00:00:00.000Z",
      ),
    ).toBeUndefined();
  });

  it("formats object keys", () => {
    expect(crlObjectKey("ca-x", "7", "a".repeat(64))).toBe(
      `crl/ca-x/7-${"a".repeat(16)}.crl`,
    );
  });
});

describe("buildSignedCrl", () => {
  it("builds a CRL that parses and verifies under the CA", async () => {
    const root = await makeRoot();
    const caKey = await newKey("ECDSA_P256");
    const cert = await makeIntermediate(root, { key: caKey });
    const der = await buildSignedCrl(
      {
        subjectDer: cert.cert.subjectDer.toString("base64"),
        subjectKeyIdentifier: cert.cert.subjectKeyIdentifier!.toString("hex"),
        spkiDer: cert.cert.spkiDer,
      },
      { algorithm: "ECDSA_P256", sign: async (tbs) => caKey.sign(tbs) },
      {
        number: 7,
        thisUpdate: new Date("2026-11-01T00:00:00Z"),
        nextUpdate: new Date("2026-11-08T00:00:00Z"),
        entries: [
          {
            caId: "ca-x",
            serial: "0a0b",
            revokedAt: "2026-10-31T00:00:00.000Z",
            reason: "keyCompromise",
            invalidityDate: "2026-10-30T00:00:00.000Z",
            notAfter: "2027-01-01T00:00:00.000Z",
          },
        ],
      },
    );
    const parsed = parseCrl(der.der);
    expect(parsed.issuerDer.equals(cert.cert.subjectDer)).toBe(true);
    expect(
      parsed.authorityKeyIdentifier!.equals(cert.cert.subjectKeyIdentifier!),
    ).toBe(true);
    expect(parsed.crlNumber!.toString("hex")).toBe("07");
    expect(parsed.entries[0]).toMatchObject({ serialHex: "0a0b", reason: 1 });
  });

  it("reports signing failures through the callback and rethrows", async () => {
    const { ApiError } = await import("../domain/errors");
    const failure = new ApiError(
      503,
      "service_unavailable",
      "x",
      "kms_access_denied",
    );
    const seen = jest.fn();
    await expect(
      buildSignedCrl(
        {
          subjectDer: "AA==",
          subjectKeyIdentifier: "00",
          spkiDer: Buffer.alloc(1),
        },
        {
          algorithm: "ECDSA_P256",
          sign: async () => {
            throw failure;
          },
        },
        {
          number: 1,
          thisUpdate: new Date(),
          nextUpdate: new Date(Date.now() + 1000),
          entries: [],
        },
        seen,
      ),
    ).rejects.toBe(failure);
    expect(seen).toHaveBeenCalledWith(failure);
  });
});

describe("CrlService.publish", () => {
  const owner = expect.stringMatching(/^crl-/);
  const caRecord = {
    caId: "ca-test-one",
    status: "ACTIVE",
    key: { state: "ACTIVE" },
    policy: { crlValiditySeconds: 3600 },
    environment: "prod",
  } as unknown as CaRecord;

  const clock = { now: new Date("2026-11-01T00:00:00.500Z") };
  const setup = async (pkiOverrides: Record<string, unknown>) => {
    clock.now = new Date("2026-11-01T00:00:00.500Z");
    const root = await makeRoot();
    const caKey = await newKey("ECDSA_P256");
    const cert = await makeIntermediate(root, { key: caKey });
    const full = {
      ...caRecord,
      subjectDer: cert.cert.subjectDer.toString("base64"),
      subjectKeyIdentifier: cert.cert.subjectKeyIdentifier!.toString("hex"),
      certificatePem: cert.pem,
    } as CaRecord;
    const pki = {
      getCa: jest.fn(async () => full),
      acquireCrlLease: jest.fn(async () => "acquired"),
      allocateCrlNumber: jest.fn(async () => ({ number: 5, startRevision: 2 })),
      listRevocationsSince: jest.fn(async () => []),
      commitCrlPublication: jest.fn(async () => "committed"),
      expireCarriedRevocations: jest.fn(async () => 0),
      markCrlSwept: jest.fn(async () => undefined),
      releaseCrlLease: jest.fn(async () => undefined),
      getCaCrlState: jest.fn(),
      ...pkiOverrides,
    };
    const putImmutableOrGet = jest.fn(async () => ({}));
    const emit = jest.fn();
    const wait = jest.fn(async () => undefined);
    const service = new CrlService(
      {
        pki,
        objects: { putImmutableOrGet },
        signerFor: () => ({
          algorithm: "ECDSA_P256",
          sign: async (tbs: Uint8Array) => caKey.sign(tbs),
        }),
        config: { pkiBucketName: "pki", environmentName: "test" },
        now: () => clock.now,
        emit,
      } as never,
      wait,
    );
    return { service, pki, putImmutableOrGet, emit, wait, ca: full };
  };

  it("returns deadline before signing when an inline deadline has passed, and releases the lease", async () => {
    const { service, pki, putImmutableOrGet, ca } = await setup({});
    const result = await service.publish(ca, {
      trigger: "inline",
      deadline: new Date(clock.now.getTime() - 1),
    });
    expect(result).toEqual({ kind: "deadline" });
    expect(pki.releaseCrlLease).toHaveBeenCalledWith("ca-test-one", owner);
    expect(putImmutableOrGet).not.toHaveBeenCalled();
    expect(pki.commitCrlPublication).not.toHaveBeenCalled();
  });

  it("returns deadline before the commit when signing outlasts the deadline", async () => {
    const { service, pki, putImmutableOrGet, ca } = await setup({});
    putImmutableOrGet.mockImplementation(async () => {
      clock.now = new Date(clock.now.getTime() + 6_000);
      return {};
    });
    const result = await service.publish(ca, {
      trigger: "inline",
      deadline: new Date(clock.now.getTime() + 5_000),
    });
    expect(result).toEqual({ kind: "deadline" });
    expect(pki.releaseCrlLease).toHaveBeenCalledTimes(1);
    expect(pki.commitCrlPublication).not.toHaveBeenCalled();
  });

  it("ignores the deadline when none is given", async () => {
    const { service, ca } = await setup({});
    clock.now = new Date(clock.now.getTime() + 86_400_000);
    expect((await service.publish(ca, { trigger: "force" })).kind).toBe("published");
  });

  it("publishes: lease, number, object, pointer, sweep", async () => {
    const { service, pki, putImmutableOrGet, ca } = await setup({});
    const result = await service.publish(ca, { trigger: "force" });
    expect(result).toMatchObject({
      kind: "published",
      pointer: {
        number: 5,
        revision: 2,
        entryCount: 0,
        thisUpdate: "2026-11-01T00:00:00.000Z",
        nextUpdate: "2026-11-01T01:00:00.000Z",
      },
    });
    expect(putImmutableOrGet).toHaveBeenCalledWith(
      "pki",
      expect.stringMatching(/^crl\/ca-test-one\/5-[0-9a-f]{16}\.crl$/),
      expect.any(Buffer),
      "application/pkix-crl",
    );
    expect(pki.commitCrlPublication).toHaveBeenCalledWith(
      expect.objectContaining({ owner, clearDirty: true, startRevision: 2 }),
    );
    expect(pki.markCrlSwept).toHaveBeenCalledWith(
      "ca-test-one",
      "2026-11-01T00:00:00.000Z",
    );
  });

  it("falls back to keeping dirtySince when a revocation landed mid-generation", async () => {
    const commit = jest
      .fn()
      .mockResolvedValueOnce("conditionFailed")
      .mockResolvedValueOnce("committed");
    const { service, pki, ca } = await setup({
      commitCrlPublication: commit,
      getCaCrlState: jest.fn(async () => ({
        lease: { owner: "x" },
        published: { number: 4 },
      })),
    });
    const state = pki.getCaCrlState as jest.Mock;
    state.mockImplementation(async () => ({
      lease: { owner: (commit.mock.calls[0][0] as { owner: string }).owner },
      published: { number: 4 },
    }));
    const result = await service.publish(ca, { trigger: "force" });
    expect(result.kind).toBe("published");
    expect(commit.mock.calls.map((call) => call[0].clearDirty)).toEqual([
      true,
      false,
    ]);
  });

  it("is superseded when the lease changed owner or the number is not newer", async () => {
    for (const current of [
      { lease: { owner: "someone-else" }, published: { number: 4 } },
      { published: { number: 5 } },
    ]) {
      const { service, ca } = await setup({
        commitCrlPublication: jest.fn(async () => "conditionFailed"),
        getCaCrlState: jest.fn(async () => current),
      });
      expect((await service.publish(ca, { trigger: "force" })).kind).toBe(
        "superseded",
      );
    }
    const { service, ca } = await setup({
      allocateCrlNumber: jest.fn(async () => "lost"),
    });
    expect((await service.publish(ca, { trigger: "force" })).kind).toBe(
      "superseded",
    );
  });

  it("polls a busy lease every 500 ms until the wait runs out", async () => {
    const { service, pki, wait, ca } = await setup({
      acquireCrlLease: jest.fn(async () => "busy"),
    });
    expect(
      await service.publish(ca, { trigger: "force", waitForLeaseMs: 1500 }),
    ).toEqual({ kind: "busy" });
    expect(wait).toHaveBeenCalledTimes(3);
    expect(wait).toHaveBeenCalledWith(500);
    expect(pki.acquireCrlLease).toHaveBeenCalledTimes(4);
    expect(await service.publish(ca, { trigger: "maintenance" })).toEqual({
      kind: "busy",
    });
  });

  it("swallows a failed sweep", async () => {
    jest.spyOn(console, "error").mockImplementation(() => undefined);
    const { service, ca } = await setup({
      expireCarriedRevocations: jest.fn(async () => {
        throw new Error("boom");
      }),
    });
    expect((await service.publish(ca, { trigger: "force" })).kind).toBe(
      "published",
    );
  });

  it("emits metrics for key and KMS failures and rethrows", async () => {
    const { ApiError } = await import("../domain/errors");
    for (const [error, metric] of [
      [
        new ApiError(409, "ca_key_unavailable", "x", "ca_key_unavailable"),
        "CaKeyUnavailable",
      ],
      [
        new ApiError(503, "service_unavailable", "x", "kms_access_denied"),
        "KmsAccessDenied",
      ],
    ] as const) {
      const { ca, emit, pki, putImmutableOrGet, wait } = await setup({});
      const service = new CrlService(
        {
          pki,
          objects: { putImmutableOrGet },
          signerFor: () => ({
            algorithm: "ECDSA_P256",
            sign: async () => {
              throw error;
            },
          }),
          config: { pkiBucketName: "pki", environmentName: "test" },
          now: () => new Date(),
          emit,
        } as never,
        wait,
      );
      await expect(service.publish(ca, { trigger: "force" })).rejects.toBe(
        error,
      );
      expect(emit).toHaveBeenCalledWith("test", { [metric]: 1 });
    }
  });

  it("re-reads the CA under the lease and refuses a stale record", async () => {
    for (const changed of [
      { status: "REVOKED" },
      { key: { state: "DISABLED" } },
      undefined,
    ]) {
      const { service, pki, ca, putImmutableOrGet } = await setup({});
      (pki.getCa as jest.Mock).mockResolvedValue(
        changed === undefined ? undefined : { ...ca, ...changed },
      );
      const result = await service.publish(ca, { trigger: "maintenance" });
      expect(result.kind).toBe("superseded");
      expect(pki.allocateCrlNumber).not.toHaveBeenCalled();
      expect(putImmutableOrGet).not.toHaveBeenCalled();
    }
  });

  it("signs with the re-read record", async () => {
    const { service, pki, ca } = await setup({});
    const signerFor = jest.fn(() => ({
      algorithm: "ECDSA_P256" as const,
      sign: async () => {
        throw new Error("stop");
      },
    }));
    const fresh = { ...ca, version: "fresh" } as CaRecord;
    (pki.getCa as jest.Mock).mockResolvedValue(fresh);
    const custom = new CrlService(
      {
        pki,
        objects: { putImmutableOrGet: jest.fn() },
        signerFor,
        config: { pkiBucketName: "pki", environmentName: "test" },
        now: () => new Date(),
        emit: jest.fn(),
      } as never,
      async () => undefined,
    );
    await expect(custom.publish(ca, { trigger: "force" })).rejects.toThrow(
      "stop",
    );
    expect(signerFor).toHaveBeenCalledWith(fresh);
  });

  it("is superseded when the commit finds the CA inactive", async () => {
    const { service, ca } = await setup({
      commitCrlPublication: jest.fn(async () => "inactive"),
    });
    expect((await service.publish(ca, { trigger: "force" })).kind).toBe(
      "superseded",
    );
  });
});

describe("CrlService.download", () => {
  const der = Buffer.from("crl-bytes");
  const sha = sha256Hex(der);
  const pointer = {
    objectKey: "crl/x",
    sha256: sha,
    thisUpdate: "2026-11-01T00:00:00.000Z",
    nextUpdate: "2026-11-08T00:00:00.000Z",
  };
  const ext = {
    environments: new Set(["prod"]),
    crl: { ...pointer, numberHex: "0".repeat(39) + "7" },
  };
  const setup = (getBytes = jest.fn(async () => der)) => {
    const pki = {
      getCa: jest.fn(async (id: string) =>
        id === "ca-known" ? { environment: "prod" } : undefined,
      ),
      getCaCrlState: jest.fn(async () => ({
        published: { ...pointer, number: 4 },
      })),
      getExternalCa: jest.fn(async (id: string) =>
        id === "ext-known" ? ext : undefined,
      ),
    };
    const service = new CrlService({
      pki,
      objects: { getBytes },
      config: { pkiBucketName: "pki" },
    } as never);
    return { service, getBytes };
  };

  it("scopes a CA to the environment and returns its metadata", async () => {
    const { service } = setup();
    await expect(
      service.download("ca-known", [], { environment: "other" }),
    ).rejects.toMatchObject({ details: { reason: "ca_not_found" } });
    await expect(
      service.download("ca-unknown", [], { environment: "prod" }),
    ).rejects.toMatchObject({ details: { reason: "ca_not_found" } });
    await expect(
      service.download("ca-known", [], { environment: "prod" }),
    ).resolves.toEqual({
      kind: "bytes",
      der,
      sha256: sha,
      numberText: "4",
      thisUpdate: pointer.thisUpdate,
      nextUpdate: pointer.nextUpdate,
    });
  });

  it("scopes an external root to its environments", async () => {
    const { service } = setup();
    await expect(
      service.download("ext-known", [], { environment: "other" }),
    ).rejects.toMatchObject({ details: { reason: "external_ca_not_found" } });
    await expect(
      service.download("ext-known", [], { environment: "prod" }),
    ).resolves.toMatchObject({ kind: "bytes", numberText: "0".repeat(39) + "7" });
  });

  it("applies no scope for the admin", async () => {
    const { service } = setup();
    await expect(service.download("ca-known")).resolves.toMatchObject({
      kind: "bytes",
    });
    await expect(service.download("ext-known")).resolves.toMatchObject({
      kind: "bytes",
    });
  });

  it("returns the metadata on a 304 without reading the object", async () => {
    const { service, getBytes } = setup();
    await expect(
      service.download("ca-known", [sha], { environment: "prod" }),
    ).resolves.toEqual({
      kind: "notModified",
      sha256: sha,
      numberText: "4",
      thisUpdate: pointer.thisUpdate,
      nextUpdate: pointer.nextUpdate,
    });
    await service.download("ca-known", ["*"], { environment: "prod" });
    expect(getBytes).not.toHaveBeenCalled();
  });

  it("is a 503 on an integrity mismatch", async () => {
    const { service } = setup(jest.fn(async () => Buffer.from("tampered")));
    await expect(
      service.download("ca-known", [], { environment: "prod" }),
    ).rejects.toMatchObject({ statusCode: 503 });
  });
});

describe("publishInlineBestEffort", () => {
  const now = new Date("2026-11-22T12:00:00.000Z");
  const publish = (result: unknown) =>
    jest.fn(async () => {
      if (result instanceof Error) {
        throw result;
      }
      return result;
    });
  let log: jest.SpyInstance;
  beforeEach(() => {
    log = jest.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => log.mockRestore());

  it("reports the number of a published CRL and passes an inline deadline", async () => {
    const crls = { publish: publish({ kind: "published", pointer: { number: 7 } }) };
    expect(await publishInlineBestEffort(crls as never, ca(), now)).toEqual({
      crlPublished: true,
      crlNumber: 7,
    });
    expect(crls.publish).toHaveBeenCalledWith(expect.anything(), {
      trigger: "inline",
      waitForLeaseMs: 1000,
      deadline: new Date(now.getTime() + 5000),
    });
    await publishInlineBestEffort(crls as never, ca(), now, 1000);
    expect(
      (crls.publish.mock.calls[1] as unknown as [unknown, { deadline: Date }])[1]
        .deadline,
    ).toEqual(new Date(now.getTime() + 1000));
  });

  it("does not sign a CA that cannot sign", async () => {
    const crls = { publish: publish({ kind: "published", pointer: { number: 7 } }) };
    for (const target of [
      ca({ status: "REVOKED" }),
      ca({ key: { state: "DISABLED" } as CaRecord["key"] }),
    ]) {
      expect(await publishInlineBestEffort(crls as never, target, now)).toEqual({
        crlPublished: false,
      });
    }
    expect(crls.publish).not.toHaveBeenCalled();
  });

  it("logs a busy lease or a failure without failing", async () => {
    expect(
      await publishInlineBestEffort({ publish: publish({ kind: "busy" }) } as never, ca({ caId: "ca-a" }), now),
    ).toEqual({ crlPublished: false });
    expect(
      await publishInlineBestEffort({ publish: publish(new TypeError("x")) } as never, ca({ caId: "ca-a" }), now),
    ).toEqual({ crlPublished: false });
    expect(log.mock.calls.map((call) => JSON.parse(call[0] as string))).toEqual([
      { event: "pki_inline_crl_failed", caId: "ca-a", kind: "busy" },
      { event: "pki_inline_crl_failed", caId: "ca-a", kind: "error", error: "TypeError" },
    ]);
  });
});
