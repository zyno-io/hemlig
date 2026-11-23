import { CaService } from "./ca-service";
import { CrlService } from "./crl-service";
import { parseRawCsr } from "./asn1/csr";
import { fromPem } from "./asn1/pem";
import { verifySignature } from "./asn1/algorithms";
import { WrappedCaSigner } from "./signer";
import {
  crlPem,
  makeCrl,
  makeIntermediate,
  makeRoot,
  mockKms,
  type TestCert,
  type TestKey,
} from "./__fixtures__/testkit";
import type { CaRecord } from "./types";
import { buildCaSubject } from "./subject";

const actor = { type: "human" as const, id: "admin-1" };
const now = new Date();

const body = (extra: Record<string, unknown> = {}) => ({
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  keyAlgorithm: "ECDSA_P256",
  subject: { commonName: "Prod Issuing CA 1", organization: "Example Corp" },
  ...extra,
});

const errorOf = async (work: Promise<unknown>) => {
  try {
    await work;
  } catch (error) {
    return error as {
      statusCode: number;
      code: string;
      details?: { reason?: string };
    };
  }
  throw new Error("expected an error");
};

type Mocks = any;

const setup = (
  overrides: {
    pki?: Record<string, unknown>;
    repository?: Record<string, unknown>;
  } = {},
) => {
  const kms = mockKms();
  const store: { ca?: CaRecord } = {};
  const pki = {
    getCa: jest.fn(async () => store.ca),
    getCaCrlState: jest.fn(async () => undefined),
    getExternalCa: jest.fn(async () => undefined),
    getCaNameClaim: jest.fn(async () => undefined),
    getSubjectClaim: jest.fn(async () => undefined),
    queryDirectory: jest.fn(async () => []),
    hasGrantsForCa: jest.fn(async () => false),
    createCa: jest.fn(async (input: { ca: CaRecord }) => {
      store.ca = input.ca;
      return { kind: "created" };
    }),
    activateCa: jest.fn(async () => ({ kind: "activated" })),
    updateCaPolicy: jest.fn(async () => ({ kind: "committed" })),
    abandonCa: jest.fn(async () => ({ kind: "committed" })),
    retireCa: jest.fn(async () => ({ kind: "committed" })),
    destroyKey: jest.fn(async () => ({ kind: "committed" })),
    ...overrides.pki,
  };
  const repository = {
    getIdempotency: jest.fn(async () => undefined),
    getIssuer: jest.fn(async () => undefined),
    requireEnvironment: jest.fn(async () => ({})),
    ...overrides.repository,
  };
  const put = jest.fn(async () => ({}));
  const deps = {
    pki,
    repository,
    objects: { putImmutableOrGet: put, getBytes: jest.fn() },
    kms: kms.kms,
    cursors: { encode: jest.fn(), decode: jest.fn() },
    signerFor: (ca: CaRecord) =>
      new WrappedCaSigner({
        kms: kms.kms,
        kmsKeyId: "arn:key",
        caId: ca.caId,
        environment: ca.environment,
        algorithm: ca.key.algorithm,
        wrapped: ca.key.wrapped!,
      }),
    config: {
      pkiBucketName: "pki",
      payloadKmsKeyArn: "arn:key",
      environmentName: "test",
    },
    now: () => now,
    emit: jest.fn(),
  };
  const crls = new CrlService(deps as never);
  return {
    service: new CaService(deps as never, crls),
    pki: pki as unknown as Mocks,
    repository: repository as unknown as Mocks,
    store,
    kms,
    put,
    deps,
  };
};

describe("CaService.create", () => {
  it("builds a verifying CSR with the critical CA profile, wraps the key and commits the claims", async () => {
    const { service, pki, store, kms } = setup();
    const result = await service.create(
      actor,
      "idem-key-0001",
      body({
        requestedConstraints: {
          nameConstraints: { permitted: { dns: ["example.com"] } },
          extendedKeyUsages: ["serverAuth"],
        },
      }),
    );
    expect(result.status).toBe(201);
    expect(result.etag).toBe(store.ca!.version);
    const csr = parseRawCsr(
      fromPem(result.body.csrPem as string, "CERTIFICATE REQUEST"),
    );
    expect(
      verifySignature(
        csr.spkiDer,
        csr.signatureAlgorithm,
        csr.infoDer,
        csr.signature,
      ),
    ).toBe(true);
    const der = csr.infoDer.toString("hex");
    // critical BasicConstraints, KeyUsage, NameConstraints and the EKU are present
    expect(der).toContain("0603551d13" + "0101ff");
    expect(der).toContain("0603551d1e0101ff");
    expect(der).toContain("2b06010505070301");
    expect(JSON.stringify(result.body)).not.toMatch(
      /encryptedDataKey|ciphertext|wrapped/,
    );
    const created = pki.createCa.mock.calls[0]![0] as {
      ca: CaRecord;
      idempotency: { operationType: string; result: unknown };
    };
    expect(created.idempotency).toMatchObject({
      operationType: "pki.ca.create",
      result: { caId: created.ca.caId },
    });
    expect(created.ca).toMatchObject({
      status: "PENDING_CERTIFICATE",
      crlIssuers: [],
      subjectKey: buildCaSubject({ O: "Example Corp", CN: "Prod Issuing CA 1" })
        .key,
      maxIssueLifetimeEverSeconds: 90 * 86_400,
    });
    expect(created.ca.key.wrapped?.algorithm).toBe("AES-256-GCM");
    // the plaintext data key handed out by KMS was zeroed
    expect(
      kms.handedOut.every((buffer) => buffer.every((byte) => byte === 0)),
    ).toBe(true);
  });

  it("zeroes the plaintext private key", async () => {
    const wrapped =
      jest.requireActual<typeof import("./wrapped-keys")>("./wrapped-keys");
    const original = wrapped.generateCaKeyPair;
    const seen: Buffer[] = [];
    const spy = jest
      .spyOn(wrapped, "generateCaKeyPair")
      .mockImplementation(async (algorithm) => {
        const real = await original(algorithm);
        seen.push(real.privateKeyDer);
        return real;
      });
    try {
      const { service } = setup();
      await service.create(actor, "idem-key-0001", body());
      expect(seen).toHaveLength(1);
      expect(seen[0]!.every((byte) => byte === 0)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it("warns about Ed25519", async () => {
    const { service } = setup();
    const result = await service.create(
      actor,
      "idem-key-0001",
      body({ keyAlgorithm: "ED25519" }),
    );
    expect(result.body.warnings).toEqual([
      expect.objectContaining({ code: "ed25519_compatibility" }),
    ]);
  });

  it("refuses other kinds, the identity root subject, duplicates and the 51st CA", async () => {
    expect(
      await errorOf(
        setup().service.create(actor, "idem-key-0001", body({ kind: "BOGUS" })),
      ),
    ).toMatchObject({
      code: "bad_request",
      details: { reason: "kind_not_supported" },
    });
    expect(
      await errorOf(
        setup().service.create(
          actor,
          "idem-key-0001",
          body({ subject: { commonName: "Hemlig test Issuing Root" } }),
        ),
      ),
    ).toMatchObject({
      code: "ca_subject_in_use",
      details: { reason: "identity_root_reserved" },
    });
    expect(
      await errorOf(
        setup({
          pki: { getCaNameClaim: jest.fn(async () => ({})) },
        }).service.create(actor, "idem-key-0001", body()),
      ),
    ).toMatchObject({ code: "conflict", details: { reason: "name_in_use" } });
    expect(
      await errorOf(
        setup({
          pki: { getSubjectClaim: jest.fn(async () => ({})) },
        }).service.create(actor, "idem-key-0001", body()),
      ),
    ).toMatchObject({
      code: "ca_subject_in_use",
      details: { reason: "subject_claimed" },
    });
    const fifty = Array.from({ length: 50 }, () => ({ status: "ACTIVE" }));
    expect(
      await errorOf(
        setup({
          pki: { queryDirectory: jest.fn(async () => fifty) },
        }).service.create(actor, "idem-key-0001", body()),
      ),
    ).toMatchObject({
      code: "conflict",
      details: { reason: "ca_limit_reached" },
    });
    // FAILED CAs do not count
    const failed = Array.from({ length: 50 }, () => ({ status: "FAILED" }));
    expect(
      (
        await setup({
          pki: { queryDirectory: jest.fn(async () => failed) },
        }).service.create(actor, "idem-key-0001", body())
      ).status,
    ).toBe(201);
  });

  it("maps a slot cancellation to its error", async () => {
    for (const [kind, expected] of [
      ["nameInUse", { code: "conflict", reason: "name_in_use" }],
      [
        "subjectInUse",
        { code: "ca_subject_in_use", reason: "subject_claimed" },
      ],
    ] as const) {
      const error = await errorOf(
        setup({
          pki: { createCa: jest.fn(async () => ({ kind })) },
        }).service.create(actor, "idem-key-0001", body()),
      );
      expect(error).toMatchObject({
        code: expected.code,
        details: { reason: expected.reason },
      });
    }
  });

  it("replays instead of conflicting when the identical create committed after the first check", async () => {
    const first = setup();
    await first.service.create(actor, "idem-key-0001", body());
    const created = first.pki.createCa.mock.calls[0]![0] as {
      idempotency: { requestDigest: string };
    };
    const stored = {
      operationType: "pki.ca.create",
      requestDigest: created.idempotency.requestDigest,
      status: "COMMITTED",
      result: { caId: first.store.ca!.caId },
    };
    // The idempotency slot is empty at the start, then the winner commits: claims exist, the record now does too.
    const racing = setup({
      pki: { getCaNameClaim: jest.fn(async () => ({})) },
      repository: {
        getIdempotency: jest
          .fn()
          .mockResolvedValueOnce(undefined)
          .mockResolvedValue(stored),
      },
    });
    racing.store.ca = first.store.ca;
    const result = await racing.service.create(actor, "idem-key-0001", body());
    expect(result).toMatchObject({ status: 201 });
    expect(result.body.caId).toBe(first.store.ca!.caId);
    expect(racing.pki.createCa).not.toHaveBeenCalled();
  });

  it("replays a stored request and rejects a different body under the same key", async () => {
    const first = setup();
    await first.service.create(actor, "idem-key-0001", body());
    const created = first.pki.createCa.mock.calls[0]![0] as {
      idempotency: { requestDigest: string };
    };
    const stored = {
      operationType: "pki.ca.create",
      requestDigest: created.idempotency.requestDigest,
      status: "COMMITTED",
      result: { caId: first.store.ca!.caId },
    };
    const replay = setup({
      repository: { getIdempotency: jest.fn(async () => stored) },
    });
    replay.store.ca = first.store.ca;
    const again = await replay.service.create(actor, "idem-key-0001", body());
    expect(again).toMatchObject({
      status: 201,
      shouldWriteTerminalAudit: true,
    });
    expect(again.body.caId).toBe(first.store.ca!.caId);
    expect(replay.pki.createCa).not.toHaveBeenCalled();
    replay.repository.getIdempotency.mockResolvedValue({
      ...stored,
      status: "SUCCEEDED",
    });
    expect(
      (await replay.service.create(actor, "idem-key-0001", body()))
        .shouldWriteTerminalAudit,
    ).toBe(false);
    expect(
      await errorOf(
        replay.service.create(
          actor,
          "idem-key-0001",
          body({ name: "other-name" }),
        ),
      ),
    ).toMatchObject({ statusCode: 409 });
  });
});

describe("CaService activation", () => {
  let root: TestCert;
  beforeAll(async () => {
    root = await makeRoot({
      subject: { O: "Test Corp", CN: "Test Offline Root" },
    });
  });

  const pendingCa = async (harness: ReturnType<typeof setup>) => {
    await harness.service.create(actor, "idem-key-0001", body());
    const ca = harness.store.ca!;
    const spki = parseRawCsr(
      fromPem(ca.csrPem!, "CERTIFICATE REQUEST"),
    ).spkiDer;
    const cert = await makeIntermediate(root, {
      key: { spkiDer: spki } as unknown as TestKey,
      subject: ca.subject,
      notBefore: new Date(now.getTime() - 3_600_000),
      notAfter: new Date(now.getTime() + 365 * 86_400_000),
    });
    return { ca, cert };
  };
  const rootCrl = (entries: { serialHex: string }[] = [], number = 1n) =>
    crlPem(
      makeCrl({
        ca: root,
        number,
        thisUpdate: new Date(now.getTime() - 3_600_000),
        nextUpdate: new Date(now.getTime() + 30 * 86_400_000),
        entries,
      }),
    );

  it("commits the five-slot activation with an empty initial CRL and a new external record", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    const result = await harness.service.activate(
      actor,
      "idem-key-0002",
      ca.caId,
      {
        certificatePem: cert.pem,
        chainPem: root.pem,
        rootCrl: rootCrl(),
      },
    );
    expect(result.status).toBe(200);
    const input = harness.pki.activateCa.mock.calls[0]![0] as Record<
      string,
      any
    >;
    expect(input.caId).toBe(ca.caId);
    expect(input.loadedVersion).toBe(ca.version);
    expect(input.fields).toMatchObject({
      serial: cert.cert.serialHex,
      parent: {
        type: "external",
        id: `ext-${root.cert.spkiSha256.slice(0, 40)}`,
      },
      crlIssuers: [
        { type: "ca", id: ca.caId },
        { type: "external", id: expect.stringMatching(/^ext-/) },
      ],
    });
    expect(input.fields.acceptBroaderConstraints).toBeUndefined();
    expect(input.crl).toMatchObject({
      revision: 0,
      lastNumber: 1,
      published: { number: 1, entryCount: 0, revision: 0 },
    });
    expect(input.external.kind).toBe("create");
    expect(input.external.record.crl.numberHex).toMatch(/01$/);
    expect(input.external.record.dependents).toEqual(new Set([ca.caId]));
    expect(input.rootSubject.key).toBeDefined();
    // the initial CRL and the seeded root CRL are stored
    expect(harness.put).toHaveBeenCalledTimes(2);
  });

  it("joins an existing external record with an update and keeps its CRL", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    const first = await harness.service.activate(
      actor,
      "idem-key-0002",
      ca.caId,
      {
        certificatePem: cert.pem,
        chainPem: root.pem,
        rootCrl: rootCrl(),
      },
    );
    expect(first.status).toBe(200);
    const record = (harness.pki.activateCa.mock.calls[0]![0] as any).external
      .record;
    const crlDer = Buffer.from(
      rootCrl()
        .replace(/-----[A-Z0-9 ]+-----/g, "")
        .replace(/\s+/g, ""),
      "base64",
    );
    const second = setup({
      pki: {
        getExternalCa: jest.fn(async () => record),
      },
    });
    (second.deps.objects.getBytes as jest.Mock).mockResolvedValue(crlDer);
    record.crl.sha256 = require("node:crypto")
      .createHash("sha256")
      .update(crlDer)
      .digest("hex");
    const pending = await pendingCa(second);
    await second.service.activate(actor, "idem-key-0003", pending.ca.caId, {
      certificatePem: pending.cert.pem,
      chainPem: root.pem,
    });
    const input = second.pki.activateCa.mock.calls[0]![0] as any;
    expect(input.external).toMatchObject({
      kind: "update",
      loadedVersion: record.version,
    });
  });

  it("returns upload_first for a root CRL that differs from the stored one", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    await harness.service.activate(actor, "idem-key-0002", ca.caId, {
      certificatePem: cert.pem,
      chainPem: root.pem,
      rootCrl: rootCrl(),
    });
    const record = (harness.pki.activateCa.mock.calls[0]![0] as any).external
      .record;
    for (const stored of [record, { ...record, crl: undefined }]) {
      const second = setup({
        pki: { getExternalCa: jest.fn(async () => stored) },
      });
      const pending = await pendingCa(second);
      expect(
        await errorOf(
          second.service.activate(actor, "idem-key-0003", pending.ca.caId, {
            certificatePem: pending.cert.pem,
            chainPem: root.pem,
            rootCrl: rootCrl([], 2n),
          }),
        ),
      ).toMatchObject({
        code: "crl_invalid",
        details: { reason: "upload_first" },
      });
    }
  });

  it("rejects an external record whose subject or SKI differs", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    await harness.service.activate(actor, "idem-key-0002", ca.caId, {
      certificatePem: cert.pem,
      chainPem: root.pem,
    });
    const record = (harness.pki.activateCa.mock.calls[0]![0] as any).external
      .record;
    for (const changed of [
      { subjectKey: "other" },
      { subjectKeyIdentifier: "00" },
    ]) {
      const second = setup({
        pki: {
          getExternalCa: jest.fn(async () => ({ ...record, ...changed })),
        },
      });
      const pending = await pendingCa(second);
      expect(
        await errorOf(
          second.service.activate(actor, "idem-key-0003", pending.ca.caId, {
            certificatePem: pending.cert.pem,
            chainPem: root.pem,
          }),
        ),
      ).toMatchObject({
        code: "chain_invalid",
        details: { reason: "external_ca_mismatch" },
      });
    }
  });

  it("refuses a certificate the supplied root CRL revokes", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    expect(
      await errorOf(
        harness.service.activate(actor, "idem-key-0002", ca.caId, {
          certificatePem: cert.pem,
          chainPem: root.pem,
          rootCrl: rootCrl([{ serialHex: cert.cert.serialHex }]),
        }),
      ),
    ).toMatchObject({
      code: "ca_not_active",
      details: { reason: "revoked_by_parent" },
    });
    expect(harness.pki.activateCa).not.toHaveBeenCalled();
  });

  it("only activates a pending CA", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    harness.store.ca = { ...ca, status: "ACTIVE" };
    expect(
      await errorOf(
        harness.service.activate(actor, "idem-key-0002", ca.caId, {
          certificatePem: cert.pem,
          chainPem: root.pem,
        }),
      ),
    ).toMatchObject({
      code: "conflict",
      details: { reason: "ca_not_pending" },
    });
  });

  it("maps the cancellation outcomes and re-runs on an external change", async () => {
    const harness = setup();
    const { ca, cert } = await pendingCa(harness);
    const run = () =>
      harness.service.activate(actor, "idem-key-0002", ca.caId, {
        certificatePem: cert.pem,
        chainPem: root.pem,
      });
    harness.pki.activateCa.mockResolvedValueOnce({ kind: "rootSubjectInUse" });
    expect(await errorOf(run())).toMatchObject({
      code: "ca_subject_in_use",
      details: { reason: "root_subject_claimed" },
    });
    harness.pki.activateCa
      .mockResolvedValueOnce({ kind: "externalChanged" })
      .mockResolvedValueOnce({ kind: "activated" });
    expect((await run()).status).toBe(200);
    expect(harness.pki.activateCa).toHaveBeenCalledTimes(3);
    harness.pki.activateCa.mockResolvedValue({ kind: "externalChanged" });
    expect(await errorOf(run())).toMatchObject({ statusCode: 503 });
    harness.pki.activateCa.mockResolvedValue({ kind: "profileChanged" });
    expect(await errorOf(run())).toMatchObject({
      details: { reason: "ca_not_pending" },
    });
  });
});

describe("CaService update, abandon, retire, destroy-key", () => {
  const active = (extra: Partial<CaRecord> = {}): CaRecord =>
    ({
      caId: "ca-test-one",
      environment: "prod",
      name: "n",
      kind: "EXTERNAL_INTERMEDIATE",
      status: "ACTIVE",
      version: "pkv-1",
      key: {
        custody: "WRAPPED",
        algorithm: "ECDSA_P256",
        spkiSha256: "a",
        state: "ACTIVE",
      },
      subject: { CN: "x" },
      crlIssuers: [],
      policy: {
        issueLeaves: true,
        issueSubordinates: false,
        maxLeafLifetimeSeconds: 3600,
        leafKeyAlgorithms: ["ECDSA_P256"],
        capacity: 100,
        issuancePerHour: 10,
        crlValiditySeconds: 3600,
      },
      maxIssueLifetimeEverSeconds: 7200,
      createdAt: "2026-01-01T00:00:00.000Z",
      createdBy: actor,
      ...extra,
    }) as CaRecord;
  const harness = (ca: CaRecord, pki: Record<string, unknown> = {}) => {
    const h = setup({ pki });
    h.store.ca = ca;
    return h;
  };

  it("update replays first, then checks If-Match, then the state", async () => {
    const h = harness(active());
    expect(
      await errorOf(
        h.service.update(actor, "idem-key-0001", "ca-test-one", "stale", {
          policy: { capacity: 50 },
        }),
      ),
    ).toMatchObject({ statusCode: 412 });
    h.store.ca = active({ status: "RETIRED" });
    expect(
      await errorOf(
        h.service.update(actor, "idem-key-0001", "ca-test-one", "pkv-1", {
          policy: { capacity: 50 },
        }),
      ),
    ).toMatchObject({
      code: "ca_not_active",
      details: { reason: "retired" },
    });
  });

  it("update keeps maxIssueLifetimeEverSeconds monotone and merges the policy", async () => {
    const h = harness(active());
    await h.service.update(actor, "idem-key-0001", "ca-test-one", "pkv-1", {
      displayName: "New",
      policy: { maxLeafLifetimeSeconds: 600 },
    });
    const input = h.pki.updateCaPolicy.mock.calls[0]![0] as any;
    expect(input.maxIssueLifetimeEverSeconds).toBe(7200);
    expect(input.policy).toMatchObject({
      maxLeafLifetimeSeconds: 600,
      capacity: 100,
    });
    expect(input.displayName).toBe("New");
    await h.service.update(actor, "idem-key-0002", "ca-test-one", "pkv-1", {
      policy: { maxLeafLifetimeSeconds: 9000 },
    });
    expect(
      (h.pki.updateCaPolicy.mock.calls[1]![0] as any)
        .maxIssueLifetimeEverSeconds,
    ).toBe(9000);
  });

  it("update keeps the display name when omitted and clears it on null", async () => {
    const h = harness(active({ displayName: "Old" }));
    await h.service.update(actor, "idem-key-0001", "ca-test-one", "pkv-1", {
      policy: { capacity: 50 },
    });
    await h.service.update(actor, "idem-key-0002", "ca-test-one", "pkv-1", {
      displayName: null,
      policy: { capacity: 50 },
    });
    const [kept, cleared] = h.pki.updateCaPolicy.mock.calls.map(
      (call: any[]) => call[0],
    );
    expect(kept).not.toHaveProperty("displayName");
    expect(cleared.displayName).toBeNull();
    expect(kept.idempotency.requestDigest).not.toBe(
      cleared.idempotency.requestDigest,
    );
  });

  it("update digests differ for an omitted and a literal displayName", async () => {
    const h = harness(active());
    for (const [key, extra] of [
      ["idem-key-0001", {}],
      ["idem-key-0002", { displayName: "keep" }],
    ] as const) {
      await h.service.update(actor, key, "ca-test-one", "pkv-1", {
        policy: { capacity: 50 },
        ...extra,
      });
    }
    const digests = h.pki.updateCaPolicy.mock.calls.map(
      (call: any[]) => call[0].idempotency.requestDigest,
    );
    expect(digests[0]).not.toBe(digests[1]);
  });

  it("update refuses an over-budget policy and reports a lost race as 412", async () => {
    const h = harness(active());
    expect(
      await errorOf(
        h.service.update(actor, "idem-key-0001", "ca-test-one", "pkv-1", {
          policy: { capacity: 12000 },
        }),
      ),
    ).toMatchObject({
      code: "ca_issuance_budget_exceeded",
    });
    h.pki.updateCaPolicy.mockImplementation(async () => {
      h.store.ca = active({ version: "pkv-2" });
      return { kind: "conditionFailed" };
    });
    expect(
      await errorOf(
        h.service.update(actor, "idem-key-0001", "ca-test-one", "pkv-1", {
          policy: { capacity: 50 },
        }),
      ),
    ).toMatchObject({ statusCode: 412 });
  });

  it("abandons only a pending CA", async () => {
    const h = harness(active());
    expect(
      await errorOf(
        h.service.abandon(actor, "idem-key-0001", "ca-test-one", "pkv-1"),
      ),
    ).toMatchObject({ details: { reason: "ca_not_pending" } });
    h.store.ca = active({ status: "PENDING_CERTIFICATE" });
    await h.service.abandon(actor, "idem-key-0001", "ca-test-one", "pkv-1");
    expect(h.pki.abandonCa).toHaveBeenCalledWith(
      expect.objectContaining({ loadedVersion: "pkv-1" }),
    );
  });

  it("retires an ACTIVE CA with a warning for grants and re-runs once on a race", async () => {
    const h = harness(active(), { hasGrantsForCa: jest.fn(async () => true) });
    const result = await h.service.retire(
      actor,
      "idem-key-0001",
      "ca-test-one",
    );
    expect(result.body.warnings).toEqual([
      expect.objectContaining({ code: "issuance_grants_reference_ca" }),
    ]);
    expect(result.auditTarget.reason).toBe("manual");
    const racing = harness(active());
    racing.pki.retireCa
      .mockResolvedValueOnce({ kind: "conditionFailed" })
      .mockResolvedValueOnce({ kind: "committed" });
    await racing.service.retire(actor, "idem-key-0001", "ca-test-one");
    expect(racing.pki.retireCa).toHaveBeenCalledTimes(2);
    racing.store.ca = active({ status: "REVOKED" });
    expect(
      await errorOf(
        racing.service.retire(actor, "idem-key-0002", "ca-test-one"),
      ),
    ).toMatchObject({ details: { reason: "revoked" } });
  });

  it("destroys only a DISABLED key", async () => {
    const h = harness(active());
    expect(
      await errorOf(
        h.service.destroyKey(actor, "idem-key-0001", "ca-test-one"),
      ),
    ).toMatchObject({ details: { reason: "key_not_disabled" } });
    h.store.ca = active({ key: { ...active().key, state: "DESTROYED" } });
    expect(
      await errorOf(
        h.service.destroyKey(actor, "idem-key-0001", "ca-test-one"),
      ),
    ).toMatchObject({ details: { reason: "key_destroyed" } });
    h.store.ca = active({
      status: "RETIRED",
      key: { ...active().key, state: "DISABLED" },
    });
    await h.service.destroyKey(actor, "idem-key-0001", "ca-test-one");
    expect(h.pki.destroyKey).toHaveBeenCalled();
  });
});
