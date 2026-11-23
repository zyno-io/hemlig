import { CertificateService, certificateSummary } from "./certificate-service";
import { admin, issuanceHarness, errorOf, type Harness } from "./__fixtures__/issuance-harness";
import type { CaRecord, IssuedCertificateRecord, RevocationEntryRecord } from "./types";

const serialOf = (n: number): string => n.toString(16).padStart(40, "0").replace(/^0/, "1");

const certificate = (
  h: Harness,
  serial: string,
  overrides: Partial<IssuedCertificateRecord> = {},
  caId = "ca-test-one",
): IssuedCertificateRecord => ({
  caId,
  environment: "prod",
  serial,
  status: "ISSUED",
  certificatePem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
  fingerprint: "f".repeat(64),
  spkiSha256: "e".repeat(64),
  subject: "CN=a.example.com",
  sans: { dns: ["a.example.com"], ip: [], uri: [] },
  keyAlgorithm: "ECDSA_P256",
  keyUsages: ["digitalSignature"],
  extendedKeyUsages: ["serverAuth"],
  isCa: false,
  notBefore: new Date(h.clock.now.getTime() - 60_000).toISOString(),
  notAfter: new Date(h.clock.now.getTime() + 3_600_000).toISOString(),
  issuedAt: new Date(h.clock.now.getTime() - 60_000).toISOString(),
  requester: { type: "human", id: "admin-1" },
  ...overrides,
});

const setup = async () => {
  const h = await issuanceHarness();
  const publish = jest.fn(async () => ({
    kind: "published",
    pointer: { number: 7, entryCount: 1 },
  }));
  const pki = h.pki as unknown as Harness["pki"] & {
    getRevocationEntry: jest.Mock;
    revokeCertificate: jest.Mock;
    putHumanIdempotency: jest.Mock;
    revokeBatch: jest.Mock;
    listConsumerPointersPage: jest.Mock;
  };
  pki.getRevocationEntry = jest.fn(async () => undefined);
  pki.revokeCertificate = jest.fn(async () => ({ kind: "committed" }));
  pki.putHumanIdempotency = jest.fn(async () => "committed");
  pki.revokeBatch = jest.fn(async () => ({ kind: "committed" }));
  pki.listConsumerPointersPage = jest.fn(async () => ({ pointers: [] }));
  const service = new CertificateService(h.deps as never, { publish } as never);
  return { h, pki, publish, service };
};

const seed = (h: Harness, cert: IssuedCertificateRecord) => {
  h.state.certificates.set(cert.serial, cert);
  return cert;
};

describe("CertificateService.revoke", () => {
  it("revokes an unexpired certificate with an entry and publishes inline", async () => {
    const { h, pki, publish, service } = await setup();
    const cert = seed(h, certificate(h, "0a1b"));
    const result = await service.revoke(admin, "key-rev-00001", "ca-test-one", cert.serial, {
      reason: "keyCompromise",
      invalidityDate: "2026-01-01T00:00:00Z",
    });
    expect(pki.revokeCertificate).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: "entry",
        reason: "keyCompromise",
        invalidityDate: "2026-01-01T00:00:00.000Z",
        notAfter: cert.notAfter,
        by: admin,
        idempotency: expect.objectContaining({
          operationType: "pki.certificate.revoke",
          result: { caId: "ca-test-one", serial: "0a1b", crlEntry: true, changed: true, crlRevision: 1 },
        }),
      }),
    );
    expect(publish).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ trigger: "inline", waitForLeaseMs: 1000, deadline: expect.any(Date) }),
    );
    const deadline = (publish.mock.calls[0] as unknown as [unknown, { deadline: Date }])[1].deadline;
    expect(deadline.getTime() - h.clock.now.getTime()).toBe(5000);
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ crlEntry: true, crlPublished: true, crlNumber: 7, changed: true });
    expect(result.auditTarget).toMatchObject({
      caId: "ca-test-one",
      serial: "0a1b",
      reason: "keyCompromise",
      crlEntry: "true",
      crlPublished: "true",
      crlNumber: "7",
      changed: "true",
    });
  });

  it("keeps an expired certificate inventory-only: no entry, no publish", async () => {
    const { h, pki, publish, service } = await setup();
    seed(h, certificate(h, "0a1b", { notAfter: new Date(h.clock.now.getTime() - 1000).toISOString() }));
    const result = await service.revoke(admin, "key-rev-00002", "ca-test-one", "0a1b", {});
    expect(pki.revokeCertificate).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "inventory", expired: true }),
    );
    expect(publish).not.toHaveBeenCalled();
    expect(result.body).toMatchObject({ crlEntry: false, crlPublished: false });
  });

  it("keeps certificates under a REVOKED CA inventory-only", async () => {
    const { h, pki, publish, service } = await setup();
    h.state.ca = { ...h.ca, status: "REVOKED" };
    seed(h, certificate(h, "0a1b"));
    await service.revoke(admin, "key-rev-00003", "ca-test-one", "0a1b", {});
    expect(pki.revokeCertificate).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "inventory", expired: false }),
    );
    expect(publish).not.toHaveBeenCalled();
  });

  it("writes only the idempotency record for an already revoked certificate", async () => {
    const { h, pki, publish, service } = await setup();
    seed(
      h,
      certificate(h, "0a1b", {
        status: "REVOKED",
        revocation: { at: h.clock.now.toISOString(), reason: "superseded", by: admin },
      }),
    );
    const result = await service.revoke(admin, "key-rev-00004", "ca-test-one", "0a1b", {
      reason: "superseded",
    });
    expect(pki.putHumanIdempotency).toHaveBeenCalled();
    expect(pki.revokeCertificate).not.toHaveBeenCalled();
    expect(publish).not.toHaveBeenCalled();
    expect(result.body).toMatchObject({ changed: false });
  });

  it("upgrades to keyCompromise with a live entry, and without one when the entry has a TTL", async () => {
    const { h, pki, publish, service } = await setup();
    seed(
      h,
      certificate(h, "0a1b", {
        status: "REVOKED",
        revocation: { at: h.clock.now.toISOString(), reason: "superseded", by: admin },
      }),
    );
    const entry: RevocationEntryRecord = {
      caId: "ca-test-one",
      serial: "0a1b",
      revokedAt: h.clock.now.toISOString(),
      reason: "superseded",
      notAfter: h.clock.now.toISOString(),
    };
    pki.getRevocationEntry.mockResolvedValue(entry);
    await service.revoke(admin, "key-rev-00005", "ca-test-one", "0a1b", { reason: "keyCompromise" });
    expect(pki.revokeCertificate).toHaveBeenLastCalledWith(
      expect.objectContaining({ mode: "upgrade", entryLive: true }),
    );
    expect(publish).toHaveBeenCalledTimes(1);

    pki.getRevocationEntry.mockResolvedValue({ ...entry, ttl: 123 });
    await service.revoke(admin, "key-rev-00006", "ca-test-one", "0a1b", { reason: "keyCompromise" });
    expect(pki.revokeCertificate).toHaveBeenLastCalledWith(
      expect.objectContaining({ mode: "upgrade", entryLive: false }),
    );
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["caCompromise", { reason: "caCompromise" }, "invalid_reason"],
    ["a date without keyCompromise", { reason: "superseded", invalidityDate: "2026-01-01T00:00:00Z" }, "invalidity_date_requires_key_compromise"],
    ["a future date", { reason: "keyCompromise", invalidityDate: "2999-01-01T00:00:00Z" }, "invalid_invalidity_date"],
    ["an unknown field", { other: 1 }, "unknown_field"],
    ["a year before 1950", { reason: "keyCompromise", invalidityDate: "1949-12-31T23:59:59Z" }, "invalid_invalidity_date"],
    ["a negative year", { reason: "keyCompromise", invalidityDate: "-000001-01-01T00:00:00Z" }, "invalid_invalidity_date"],
  ])("rejects %s", async (_label, request, reason) => {
    const { h, service } = await setup();
    seed(h, certificate(h, "0a1b"));
    expect(
      await errorOf(service.revoke(admin, "key-rev-00007", "ca-test-one", "0a1b", request)),
    ).toMatchObject({ statusCode: 400, safeReason: reason });
  });

  it("is 404 for an unknown certificate and 409 for a CA certificate", async () => {
    const { h, service } = await setup();
    expect(
      await errorOf(service.revoke(admin, "key-rev-00008", "ca-test-one", "ff", {})),
    ).toMatchObject({ statusCode: 404, safeReason: "certificate_not_found" });
    seed(h, certificate(h, "0a1b", { childCaId: "ca-child-one" }));
    expect(
      await errorOf(service.revoke(admin, "key-rev-00009", "ca-test-one", "0a1b", {})),
    ).toMatchObject({ statusCode: 409, safeReason: "use_ca_revoke" });
  });

  it.each([
    ["busy", async () => ({ kind: "busy" })],
    ["deadline", async () => ({ kind: "deadline" })],
    [
      "a thrown error",
      async () => {
        throw new Error("kms");
      },
    ],
  ])("reports crlPublished false and still answers 200 when publication is %s", async (_label, outcome) => {
    const { h, publish, service } = await setup();
    publish.mockImplementation(outcome as never);
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      seed(h, certificate(h, "0a1b"));
      const result = await service.revoke(admin, "key-rev-00010", "ca-test-one", "0a1b", {});
      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({ crlEntry: true, crlPublished: false });
      expect(spy.mock.calls.join(" ")).toContain("pki_inline_crl_failed");
    } finally {
      spy.mockRestore();
    }
  });

  it("re-reads and redoes the table once when the certificate moved, then 503s", async () => {
    const { h, pki, service } = await setup();
    seed(h, certificate(h, "0a1b"));
    pki.revokeCertificate
      .mockResolvedValueOnce({ kind: "canceled", failed: ["certificate"] })
      .mockResolvedValue({ kind: "committed" });
    await service.revoke(admin, "key-rev-00011", "ca-test-one", "0a1b", {});
    expect(pki.revokeCertificate).toHaveBeenCalledTimes(2);
    pki.revokeCertificate.mockResolvedValue({ kind: "canceled", failed: ["crl"] });
    expect(
      await errorOf(service.revoke(admin, "key-rev-00012", "ca-test-one", "0a1b", {})),
    ).toMatchObject({ statusCode: 503 });
  });
});

describe("CertificateService.bulkRevoke", () => {
  const world = async (counts: Record<string, number>) => {
    const ctx = await setup();
    const { h, pki } = ctx;
    const cas = new Map<string, CaRecord>();
    const pointers: { caId: string; serial: string }[] = [];
    let n = 1;
    for (const [caId, count] of Object.entries(counts)) {
      cas.set(caId, { ...h.ca, caId });
      for (let i = 0; i < count; i += 1) {
        const serial = serialOf(n++);
        seed(h, certificate(h, serial, {}, caId));
        pointers.push({ caId, serial });
      }
    }
    pki.getCa.mockImplementation(async (id: string) => cas.get(id));
    pki.getCertificate.mockImplementation(async (caId: string, serial: string) => {
      const found = h.state.certificates.get(serial);
      return found?.caId === caId ? found : undefined;
    });
    pki.listConsumerPointersPage.mockResolvedValue({
      pointers: pointers.map((pointer) => ({ ...pointer, notAfter: "", issuedAt: "" })),
    });
    pki.revokeBatch.mockImplementation(async (batch: { items: { serial: string }[] }) => {
      for (const item of batch.items) {
        const current = h.state.certificates.get(item.serial)!;
        h.state.certificates.set(item.serial, { ...current, status: "REVOKED" });
      }
      return { kind: "committed" };
    });
    return ctx;
  };

  it("revokes 65 certificates over two CAs in batches of 30, 30, 5 and 1, with one publish per CA", async () => {
    const { pki, publish, service } = await world({ "ca-aaa-one": 60, "ca-bbb-two": 5 });
    const result = await service.bulkRevoke(admin, "key-bulk-00001", "consumer-one", { reason: "superseded" });
    expect(result.complete).toBe(true);
    expect(
      pki.revokeBatch.mock.calls.map(
        (call) => (call as unknown as [{ items: unknown[] }])[0].items.length,
      ),
    ).toEqual([30, 30, 5]);
    expect(publish).toHaveBeenCalledTimes(2);
    expect(result.body).toMatchObject({
      consumerId: "consumer-one",
      complete: true,
      revoked: 65,
      alreadyRevoked: 0,
      caIds: ["ca-aaa-one", "ca-bbb-two"],
    });
    expect(pki.putHumanIdempotency).toHaveBeenCalledTimes(1);
    expect(result.auditTarget).toMatchObject({ bulk: "true", count: "65", complete: "true" });
  });

  it("skips certificates a rerun finds already revoked", async () => {
    const { pki, service } = await world({ "ca-aaa-one": 3 });
    await service.bulkRevoke(admin, "key-bulk-00002", "consumer-one", {});
    pki.revokeBatch.mockClear();
    const again = await service.bulkRevoke(admin, "key-bulk-00002", "consumer-one", {});
    expect(pki.revokeBatch).not.toHaveBeenCalled();
    expect(again.body).toMatchObject({ revoked: 0, alreadyRevoked: 3 });
  });

  it("inventories certificates under a REVOKED CA without entries", async () => {
    const { h, pki, publish, service } = await world({ "ca-aaa-one": 2 });
    pki.getCa.mockImplementation(async (id: string) => ({ ...h.ca, caId: id, status: "REVOKED" }));
    await service.bulkRevoke(admin, "key-bulk-00003", "consumer-one", {});
    expect(pki.revokeBatch).toHaveBeenCalledWith(expect.objectContaining({ withEntries: false }));
    expect(publish).not.toHaveBeenCalled();
  });

  it("stops at the deadline: complete false, no idempotency record", async () => {
    const { h, pki, service } = await world({ "ca-aaa-one": 70 });
    pki.revokeBatch.mockImplementation(async () => {
      h.clock.now = new Date(h.clock.now.getTime() + 21_000);
      return { kind: "committed" };
    });
    const result = await service.bulkRevoke(admin, "key-bulk-00004", "consumer-one", {});
    expect(result.complete).toBe(false);
    expect(result.body).toMatchObject({ complete: false, revoked: 30 });
    expect(pki.putHumanIdempotency).not.toHaveBeenCalled();
    expect(result.auditTarget.complete).toBe("false");
  });

  it("re-reads the failed serials after a cancellation and retries the rest", async () => {
    const { h, pki, service } = await world({ "ca-aaa-one": 3 });
    const serials = [...h.state.certificates.keys()];
    h.state.certificates.set(serials[0]!, { ...h.state.certificates.get(serials[0]!)!, status: "REVOKED" });
    pki.revokeBatch
      .mockResolvedValueOnce({ kind: "canceled", failed: [`cert:${serials[0]}`] })
      .mockResolvedValue({ kind: "committed" });
    // The pointer read already saw the first one as ISSUED.
    const original = pki.getCertificate.getMockImplementation()!;
    let first = true;
    pki.getCertificate.mockImplementation(async (caId: string, serial: string) => {
      const found = await original(caId, serial);
      if (first && serial === serials[0]) {
        first = false;
        return { ...found, status: "ISSUED" } as IssuedCertificateRecord;
      }
      return found;
    });
    const result = await service.bulkRevoke(admin, "key-bulk-00005", "consumer-one", {});
    expect(result.body).toMatchObject({ revoked: 2, alreadyRevoked: 1 });
    expect(
      (pki.revokeBatch.mock.calls[1] as unknown as [{ items: unknown[] }])[0].items,
    ).toHaveLength(2);
  });

  it("makes progress when each page takes 7 seconds, and a rerun finishes", async () => {
    const { h, pki, service } = await world({ "ca-aaa-one": 3 });
    const all = (await pki.listConsumerPointersPage("c", {} as never)).pointers;
    const pages = all.map((pointer: unknown) => [pointer]);
    let calls = 0;
    pki.listConsumerPointersPage.mockImplementation(async () => {
      h.clock.now = new Date(h.clock.now.getTime() + 7_000);
      const index = calls++ % pages.length;
      return {
        pointers: pages[index],
        ...(index < pages.length - 1 ? { lastEvaluatedKey: { n: index } } : {}),
      };
    });
    const first = await service.bulkRevoke(admin, "key-bulk-00007", "consumer-one", {});
    expect(first.complete).toBe(false);
    expect(first.body.revoked).toBe(2);
    expect(pki.putHumanIdempotency).not.toHaveBeenCalled();
    calls = 0;
    calls = 0;
    const last = await service.bulkRevoke(admin, "key-bulk-00007", "consumer-one", {});
    expect(last.complete).toBe(true);
    expect([...h.state.certificates.values()].every((c) => c.status === "REVOKED")).toBe(true);
  });

  it("publishes every touched CA with an unpublished revision, and counts expired fallout", async () => {
    const { h, pki, publish, service } = await world({ "ca-aaa-one": 1, "ca-bbb-two": 1 });
    // The second CA's certificate is already revoked, but its CRL was never published.
    const [, second] = [...h.state.certificates.values()];
    h.state.certificates.set(second!.serial, { ...second!, status: "REVOKED" });
    (pki.getCaCrlState as jest.Mock).mockImplementation(async (id: string) =>
      id === "ca-bbb-two"
        ? { revision: 3, lastNumber: 1, published: { revision: 1, number: 1 } }
        : { revision: 1, lastNumber: 1, published: { revision: 1, number: 1 } },
    );
    const result = await service.bulkRevoke(admin, "key-bulk-00008", "consumer-one", {});
    const published = (publish.mock.calls as unknown as { caId: string }[][]).map(
      (call) => call[0]!.caId,
    );
    expect(published.sort()).toEqual(["ca-aaa-one", "ca-bbb-two"]);
    expect(result.body).toMatchObject({ revoked: 1, alreadyRevoked: 1 });
  });

  it("counts an expired certificate that falls out of a batch", async () => {
    const { h, pki, service } = await world({ "ca-aaa-one": 2 });
    const serials = [...h.state.certificates.keys()];
    pki.revokeBatch.mockResolvedValueOnce({ kind: "canceled", failed: [`cert:${serials[0]}`] });
    const original = pki.getCertificate.getMockImplementation()!;
    let calls = 0;
    pki.getCertificate.mockImplementation(async (caId: string, serial: string) => {
      const found = await original(caId, serial);
      // The batch cancellation re-read sees the first certificate expired.
      if (serial === serials[0] && (calls += 1) === 2) {
        return { ...found, notAfter: new Date(h.clock.now.getTime() - 1).toISOString() } as IssuedCertificateRecord;
      }
      return found;
    });
    const result = await service.bulkRevoke(admin, "key-bulk-00009", "consumer-one", {});
    expect(pki.revokeCertificate).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "inventory", expired: true }),
    );
    expect(result.body).toMatchObject({ revoked: 2 });
  });

  it.each([
    ["PEM text", "-----BEGIN PRIVATE KEY-----"],
    ["an uppercase name", "Web"],
    ["a long name", "a".repeat(80)],
  ])("rejects %s as the issuanceGrant filter and audits nothing of it", async (_label, value) => {
    const { service } = await setup();
    expect(
      await errorOf(service.bulkRevoke(admin, "key-bulk-00010", "consumer-one", { issuanceGrant: value })),
    ).toMatchObject({ statusCode: 400, safeReason: "invalid_filter" });
    expect(
      await errorOf(service.bulkRevoke(admin, "key-bulk-00011", "consumer-one", { issuanceGrantUid: value })),
    ).toMatchObject({ statusCode: 400, safeReason: "invalid_filter" });
  });

  it("replays a completed run from its record", async () => {
    const { h, service } = await world({ "ca-aaa-one": 1 });
    const stored = {
      operationType: "pki.certificate.revoke",
      requestDigest: "",
      status: "SUCCEEDED",
      result: { consumerId: "consumer-one", complete: true, revoked: 1, alreadyRevoked: 0, caIds: [], crls: [] },
    };
    const first = await service.bulkRevoke(admin, "key-bulk-00006", "consumer-one", {});
    void first;
    const call = h.deps.repository.getIdempotency as jest.Mock;
    call.mockImplementationOnce(async () => ({
      ...stored,
      requestDigest: (h.pki as unknown as { putHumanIdempotency: jest.Mock }).putHumanIdempotency.mock
        .calls[0][0].requestDigest,
    }));
    const replayed = await service.bulkRevoke(admin, "key-bulk-00006", "consumer-one", {});
    expect(replayed.body).toMatchObject({ complete: true, revoked: 1 });
    expect(replayed.shouldWriteTerminalAudit).toBe(false);
  });
});

describe("inventory", () => {
  it("lists with the effective status", async () => {
    const { h, pki, service } = await setup();
    const pkiList = pki as unknown as { queryCertificatesPage: jest.Mock };
    pkiList.queryCertificatesPage = jest.fn(async () => ({
      certificates: [
        certificate(h, "01"),
        certificate(h, "02", { notAfter: new Date(h.clock.now.getTime() - 1000).toISOString() }),
        certificate(h, "03", { status: "REVOKED" }),
      ],
    }));
    const page = await service.list(admin, "ca-test-one", { status: "ISSUED" });
    expect(
      (page.certificates as { status: string }[]).map((entry) => entry.status),
    ).toEqual(["ISSUED", "EXPIRED", "REVOKED"]);
    expect(pkiList.queryCertificatesPage).toHaveBeenCalledWith(
      "ca-test-one",
      expect.objectContaining({ after: h.clock.now.toISOString(), status: "ISSUED", limit: 100 }),
    );
  });

  it("reports CA_REVOKED and 404s a missing certificate", async () => {
    const { h, service } = await setup();
    seed(h, certificate(h, "01"));
    h.state.ca = { ...h.ca, status: "REVOKED" };
    expect(await service.get("ca-test-one", "01")).toMatchObject({ status: "CA_REVOKED" });
    expect(await errorOf(service.get("ca-test-one", "02"))).toMatchObject({ statusCode: 404 });
  });
});

describe("certificateSummary", () => {
  it("adds isCa and childCaId on a CA row only", async () => {
    const h = await issuanceHarness();
    const now = h.clock.now;
    const leaf = certificateSummary(certificate(h, "0a1b"), h.ca, now);
    expect(leaf).not.toHaveProperty("isCa");
    expect(leaf).not.toHaveProperty("childCaId");
    const row = certificateSummary(
      certificate(h, "0a1c", { isCa: true, childCaId: "ca-child-one" }),
      h.ca,
      now,
    );
    expect(row).toMatchObject({ isCa: true, childCaId: "ca-child-one", status: "ISSUED" });
  });
});

describe("CertificateService.revoke replay", () => {
  it("recomputes crlPublished against the floored second and the recorded revision", async () => {
    const { h, pki, service } = await setup();
    h.clock.now = new Date("2026-11-22T12:00:00.789Z");
    const cert = seed(h, certificate(h, "0a1b"));
    h.state.crl = { revision: 4, lastNumber: 6 };
    pki.revokeCertificate.mockImplementation(async (input: any) => {
      h.state.human.set(input.idempotency.idempotencyKey, {
        operationType: input.idempotency.operationType,
        requestDigest: input.idempotency.requestDigest,
        status: "COMMITTED",
        result: input.idempotency.result,
      });
      h.state.certificates.set(cert.serial, {
        ...cert,
        status: "REVOKED",
        revocation: { at: input.now, reason: input.reason, by: admin },
      });
      return { kind: "committed" };
    });
    await service.revoke(admin, "key-rev-replay1", "ca-test-one", cert.serial, {});
    expect(h.state.human.get("key-rev-replay1")!.result).toMatchObject({
      crlEntry: true,
      crlRevision: 5,
    });
    const published = (revision: number) => ({
      revision: 5,
      lastNumber: 7,
      published: {
        number: 7,
        objectKey: "k",
        sha256: "s",
        thisUpdate: "2026-11-22T12:00:00.000Z",
        nextUpdate: "2026-11-29T12:00:00.000Z",
        revision,
        entryCount: 1,
      },
    });
    // Published within the same second as the revoke, covering the bump.
    h.state.crl = published(5);
    const covered = await service.revoke(admin, "key-rev-replay1", "ca-test-one", cert.serial, {});
    expect(covered.body).toMatchObject({ crlEntry: true, crlPublished: true, crlNumber: 7 });
    // A CRL from the same second that predates the bump does not count.
    h.state.crl = published(4);
    const stale = await service.revoke(admin, "key-rev-replay1", "ca-test-one", cert.serial, {});
    expect(stale.body.crlPublished).toBe(false);
    expect(stale.body.crlNumber).toBeUndefined();
  });
});
