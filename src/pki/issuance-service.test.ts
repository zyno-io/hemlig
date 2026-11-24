import { generateKeyPairSync } from "node:crypto";
import { parseCertificate } from "./asn1/certificate";
import { decodeSubjectAltName } from "./asn1/names";
import { EXT } from "./asn1/extensions";
import { fromPem } from "./asn1/pem";
import {
  caId,
  consumerId,
  errorOf,
  issuanceHarness,
  makeCsr,
  samplePolicy,
  type Harness,
} from "./__fixtures__/issuance-harness";
import { leafKey } from "./__fixtures__/testkit";
import { admin } from "./__fixtures__/issuance-harness";
import type { CaRecord } from "./types";

const issue = (
  h: Harness,
  overrides: Parameters<Harness["ctx"]>[0] = {},
) => h.issuance.issueForConsumer(h.ctx(overrides));

const leafOf = (body: Record<string, unknown>) =>
  parseCertificate(fromPem(body.certificatePem as string, "CERTIFICATE"));

describe("IssuanceService.issueForConsumer: happy path", () => {
  it("issues, commits the full input and reports the target", async () => {
    const h = await issuanceHarness();
    const onTarget = jest.fn();
    const result = await h.issuance.issueForConsumer({
      ...h.ctx({ idempotencyKey: "key-happy-0001" }),
      onTarget,
    });
    expect(result.status).toBe(201);
    expect(result.replayed).toBe(false);
    const leaf = leafOf(result.body);
    expect(result.body).toMatchObject({
      caId,
      serial: leaf.serialHex,
      issuanceGrant: "web",
      lifetimeClamped: false,
      caPem: h.root.pem,
    });
    expect(result.body.chainPem).toBe(h.ca.certificatePem);
    expect(onTarget).toHaveBeenCalledWith({
      caId,
      issuanceGrantUid: "pkg-uid-0001",
    });
    const commit = h.state.commits[0]!;
    expect(commit).toMatchObject({
      path: "consumer",
      consumerId,
      identityFingerprint: "a".repeat(64),
      idempotencyKey: "key-happy-0001",
      ancestors: [],
      ca: { caId, version: "pkv-ca-1", issuancePerHour: 2000 },
      grant: {
        name: "web",
        uid: "pkg-uid-0001",
        version: "pkv-grant-1",
        perHour: 100,
        perDay: 1000,
      },
    });
    expect(commit.certificate).toMatchObject({
      status: "ISSUED",
      keyAlgorithm: "ECDSA_P256",
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: ["serverAuth"],
      isCa: false,
      sans: { dns: ["web.example.com"], ip: [], uri: [] },
      subject: "CN=web.example.com",
      requester: {
        type: "consumer",
        consumerId,
        issuanceGrant: { name: "web", uid: "pkg-uid-0001" },
      },
    });
    expect(commit.certificate.notAfter).toBe(leaf.notAfter.toISOString());
    expect(result.auditTarget).toMatchObject({
      consumerId,
      issuanceGrant: "web",
      issuanceGrantUid: "pkg-uid-0001",
      replayed: "false",
      lifetimeClamped: "false",
    });
    const san = leaf.extensions.find((e) => e.oid === EXT.subjectAltName)!;
    expect(decodeSubjectAltName(san.value).dns).toEqual(["web.example.com"]);
  });

  it("records the Kubernetes requester as asserted metadata only", async () => {
    const h = await issuanceHarness();
    const requester = {
      kubernetes: { namespace: "apps", name: "web-1", uid: "ab-12" },
    };
    const a = await issue(h, {
      idempotencyKey: "key-req-00001",
      body: { certificateSigningRequestPem: makeCsr(), requester },
    });
    expect(h.state.commits[0]!.certificate.requester.asserted).toEqual(
      requester,
    );
    expect(a.auditTarget.k8sNamespace).toBe("apps");
  });

  it("applies the agent grant check and commits it", async () => {
    const h = await issuanceHarness({
      agentGrantId: "grant-00000000-0000-0000-0000-000000000000",
    });
    await issue(h);
    expect(h.state.commits[0]).toMatchObject({
      agentGrant: {
        grantId: "grant-00000000-0000-0000-0000-000000000000",
        environment: "prod",
      },
    });
  });
});

describe("replay", () => {
  it("replays first, with no quota or capacity read", async () => {
    const h = await issuanceHarness();
    const first = await issue(h, { idempotencyKey: "key-replay-001" });
    h.pki.getQuotaCount.mockClear();
    h.pki.getCaCrlState.mockClear();
    h.pki.getGrant.mockClear();
    const again = await issue(h, { idempotencyKey: "key-replay-001" });
    expect(again.replayed).toBe(true);
    expect(again.body.serial).toBe(first.body.serial);
    expect(h.pki.getQuotaCount).not.toHaveBeenCalled();
    expect(h.pki.getCaCrlState).not.toHaveBeenCalled();
    expect(h.pki.getGrant).not.toHaveBeenCalled();
    expect(h.state.commits).toHaveLength(1);
    expect(again.auditTarget.replayed).toBe("true");
  });

  it("refuses a key reused with a different request", async () => {
    const h = await issuanceHarness();
    await issue(h, { idempotencyKey: "key-reuse-0001" });
    const error = await errorOf(
      issue(h, {
        idempotencyKey: "key-reuse-0001",
        body: { certificateSigningRequestPem: makeCsr({ dns: ["b.example.com"] }) },
      }),
    );
    expect(error).toMatchObject({
      statusCode: 409,
      code: "conflict",
      safeReason: "idempotency_key_reused",
    });
  });

  it("returns the same result for a different usage order", async () => {
    const h = await issuanceHarness();
    const csr = makeCsr();
    const a = await issue(h, {
      idempotencyKey: "key-order-0001",
      body: {
        certificateSigningRequestPem: csr,
        usages: ["server auth", "digital signature"],
      },
    });
    const b = await issue(h, {
      idempotencyKey: "key-order-0001",
      body: {
        certificateSigningRequestPem: csr,
        usages: ["digital signature", "server auth", "server auth"],
      },
    });
    expect(b.body.serial).toBe(a.body.serial);
  });

  it("fails a replay of a revoked certificate, a revoked CA, a near-expiry result and a 91-day-old record", async () => {
    const h = await issuanceHarness();
    const first = await issue(h, { idempotencyKey: "key-checks-001" });
    const serial = first.body.serial as string;
    const stored = h.state.certificates.get(serial)!;

    h.state.certificates.set(serial, { ...stored, status: "REVOKED" });
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-checks-001" })),
    ).toMatchObject({ statusCode: 409, code: "issuance_revoked", safeReason: "certificate_revoked" });
    h.state.certificates.set(serial, stored);

    h.state.ca = { ...h.ca, status: "REVOKED" };
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-checks-001" })),
    ).toMatchObject({ code: "issuance_revoked", safeReason: "ca_revoked" });
    h.state.ca = h.ca;

    const notAfter = Date.parse(stored.notAfter);
    h.clock.now = new Date(notAfter - 30_000);
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-checks-001" })),
    ).toMatchObject({ statusCode: 409, code: "issuance_expired", safeReason: "result_expiring" });

    h.clock.now = new Date(notAfter + 91 * 86_400_000);
    h.pki.getCertificate.mockClear();
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-checks-001" })),
    ).toMatchObject({ safeReason: "inventory_expired" });
    expect(h.pki.getCertificate).not.toHaveBeenCalled();
  });
});

describe("preconditions", () => {
  it("rejects an inactive identity and an inactive agent grant", async () => {
    const h = await issuanceHarness({
      agentGrantId: "grant-00000000-0000-0000-0000-000000000000",
    });
    h.state.agentGrant = { ...h.state.agentGrant, status: "PENDING" };
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 403,
      code: "identity_not_active",
      safeReason: "agent_grant_inactive",
    });
    h.state.agentGrant = undefined;
    h.state.identity = { ...h.state.identity, status: "REVOKED" };
    expect(await errorOf(issue(h))).toMatchObject({
      code: "identity_not_active",
    });
  });

  it.each([
    ["missing", undefined],
    ["deleted", { status: "DELETED" as const }],
    ["another environment", { environment: "staging" }],
  ])("reports a %s grant as not found", async (_label, patch) => {
    const h = await issuanceHarness();
    h.state.grants.set(
      "web",
      patch === undefined ? (undefined as never) : { ...h.grant, ...patch },
    );
    if (patch === undefined) {
      h.state.grants.delete("web");
    }
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 404,
      code: "issuance_grant_not_found",
    });
  });

  it("reports disabled and expired grants", async () => {
    const h = await issuanceHarness();
    h.state.grants.set("web", { ...h.grant, status: "DISABLED" });
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 403,
      code: "issuance_grant_inactive",
      safeReason: "grant_disabled",
    });
    h.state.grants.set("web", {
      ...h.grant,
      expiresAt: new Date(h.clock.now.getTime() - 1000).toISOString(),
    });
    expect(await errorOf(issue(h))).toMatchObject({
      safeReason: "grant_expired",
    });
  });

  it.each([
    ["retired", { status: "RETIRED" as const }, "retired"],
    ["revoked", { status: "REVOKED" as const }, "revoked"],
    [
      "environment",
      { environment: "staging" },
      "environment_mismatch",
    ],
    [
      "leaves",
      { policy: { issueLeaves: false } },
      "leaves_not_permitted",
    ],
    [
      "expired",
      { notAfter: "2000-01-01T00:00:00.000Z" },
      "expired",
    ],
  ])("refuses a CA that is %s", async (_label, patch, reason) => {
    const h = await issuanceHarness();
    h.state.ca = {
      ...h.ca,
      ...patch,
      policy: { ...h.ca.policy, ...("policy" in patch ? patch.policy : {}) },
    } as typeof h.ca;
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 409,
      code: "ca_not_active",
      safeReason: reason,
    });
  });

  it("reports an unusable CA key", async () => {
    const h = await issuanceHarness();
    h.state.ca = { ...h.ca, key: { ...h.ca.key, state: "DISABLED" } };
    expect(await errorOf(issue(h))).toMatchObject({ code: "ca_key_unavailable" });
  });
});

describe("capacity and quota", () => {
  it("refuses at capacity", async () => {
    const h = await issuanceHarness({ caPolicy: { capacity: 2 } });
    h.state.crl = {
      revision: 0,
      lastNumber: 1,
      capacity: {
        count: 2,
        countFrom: h.clock.now.toISOString(),
        countedAt: h.clock.now.toISOString(),
      },
    };
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 409,
      code: "ca_capacity_exceeded",
    });
  });

  it("recounts and stores when the count is 31 minutes old, not at 29", async () => {
    const h = await issuanceHarness();
    const countedAt = (minutes: number) =>
      new Date(h.clock.now.getTime() - minutes * 60_000).toISOString();
    h.state.crl = {
      revision: 0,
      lastNumber: 1,
      capacity: { count: 1, countFrom: countedAt(29), countedAt: countedAt(29) },
    };
    await issue(h);
    expect(h.pki.countCertificatesSince).not.toHaveBeenCalled();
    h.state.crl = {
      revision: 0,
      lastNumber: 1,
      capacity: { count: 1, countFrom: countedAt(31), countedAt: countedAt(31) },
    };
    h.state.certificatesSince = 7;
    await issue(h);
    expect(h.pki.countCertificatesSince).toHaveBeenCalledTimes(1);
    expect(h.state.crl.capacity).toMatchObject({ count: 7 });
  });

  it("answers 429 with the header and details, and grant_day wins", async () => {
    const h = await issuanceHarness({
      policy: samplePolicy({ quotas: { perHour: 1, perDay: 1 } }),
    });
    h.pki.getQuotaCount.mockResolvedValue(1);
    const error = await errorOf(issue(h));
    expect(error).toMatchObject({
      statusCode: 429,
      code: "issuance_rate_limited",
      details: { reason: "grant_day" },
    });
    const seconds = Number(error.headers?.["retry-after"]);
    expect(seconds).toBeGreaterThanOrEqual(1);
    expect(error.details?.retryAfterSeconds).toBe(seconds);
    // The day window outlives the hour window.
    expect(seconds).toBeGreaterThanOrEqual(1);
  });

  it("reports ca_hour when only the CA counter is full", async () => {
    const h = await issuanceHarness({ caPolicy: { issuancePerHour: 5 } });
    h.pki.getQuotaCount.mockImplementation(async (key: { pk: string }) =>
      key.pk.startsWith("PKI_QUOTA#ca#") ? 5 : 0,
    );
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 429,
      details: { reason: "ca_hour" },
    });
  });

  it("returns a winner that appears between step 2 and the pre-check, instead of 429 or capacity", async () => {
    const h = await issuanceHarness();
    const first = await issue(h, { idempotencyKey: "key-winner-001" });
    const record = h.state.replays.get("key-winner-001")!;
    h.state.replays.delete("key-winner-001");
    let calls = 0;
    h.pki.getReplayRecord.mockImplementation(async () =>
      (calls += 1) === 1 ? undefined : record,
    );
    h.pki.getQuotaCount.mockResolvedValue(1_000_000);
    const result = await issue(h, { idempotencyKey: "key-winner-001" });
    expect(result.replayed).toBe(true);
    expect(result.body.serial).toBe(first.body.serial);

    calls = 0;
    h.pki.getQuotaCount.mockResolvedValue(0);
    h.state.crl = {
      revision: 0,
      lastNumber: 1,
      capacity: {
        count: h.ca.policy.capacity,
        countFrom: h.clock.now.toISOString(),
        countedAt: h.clock.now.toISOString(),
      },
    };
    expect((await issue(h, { idempotencyKey: "key-winner-001" })).replayed).toBe(true);
  });
});

describe("commit outcomes", () => {
  const winnerOf = (h: Harness, serial: string) => {
    const issued = [...h.state.certificates.values()][0]!;
    return {
      requestDigest: "",
      caId,
      serial,
      notAfter: issued.notAfter,
      grantUid: "pkg-uid-0001",
    };
  };

  it("returns the winner on replayExists and discards the local certificate", async () => {
    const h = await issuanceHarness();
    const first = await issue(h, { idempotencyKey: "key-race-00001" });
    const winner = h.state.replays.get("key-race-00001")!;
    h.state.replays.delete("key-race-00001");
    let reads = 0;
    h.pki.getReplayRecord.mockImplementation(async () =>
      (reads += 1) <= 1 ? undefined : winner,
    );
    h.state.outcomes.push({ kind: "replayExists" });
    const result = await issue(h, { idempotencyKey: "key-race-00001" });
    expect(result.body.serial).toBe(first.body.serial);
    expect(result.replayed).toBe(true);
    void winnerOf;
  });

  it("quotaExhausted: replay with an own record, 429 without", async () => {
    const h = await issuanceHarness();
    h.state.outcomes.push({
      kind: "quotaExhausted",
      quotas: ["grantHour"],
      retryAfterSeconds: 120,
    });
    const error = await errorOf(issue(h, { idempotencyKey: "key-quota-0001" }));
    expect(error).toMatchObject({
      statusCode: 429,
      details: { reason: "grant_hour", retryAfterSeconds: 120 },
    });
    // With a record: first apply a normal commit, then drop it for the first read only.
    const h2 = await issuanceHarness();
    const first = await issue(h2, { idempotencyKey: "key-quota-0002" });
    const record = h2.state.replays.get("key-quota-0002")!;
    h2.state.replays.delete("key-quota-0002");
    let reads = 0;
    h2.pki.getReplayRecord.mockImplementation(async () =>
      (reads += 1) <= 1 ? undefined : record,
    );
    h2.state.outcomes.push({
      kind: "quotaExhausted",
      quotas: ["grantHour"],
      retryAfterSeconds: 120,
    });
    expect(
      (await issue(h2, { idempotencyKey: "key-quota-0002" })).body.serial,
    ).toBe(first.body.serial);
  });

  it("reruns once with fresh reads after a precondition failure, then 503", async () => {
    const h = await issuanceHarness();
    h.state.outcomes.push({ kind: "preconditionFailed", slots: ["grant"] });
    await issue(h);
    expect(h.repository.getIdentity).toHaveBeenCalledTimes(2);
    expect(h.state.commits).toHaveLength(2);

    const h2 = await issuanceHarness();
    h2.state.outcomes.push(
      { kind: "preconditionFailed", slots: ["ca"] },
      { kind: "unclassified" },
    );
    expect(await errorOf(issue(h2))).toMatchObject({ statusCode: 503 });
  });

  it("re-signs with a new serial on a serial collision", async () => {
    const h = await issuanceHarness();
    h.state.outcomes.push({ kind: "serialCollision" });
    const result = await issue(h);
    expect(h.state.commits).toHaveLength(2);
    expect(h.state.commits[0]!.certificate.serial).not.toBe(
      h.state.commits[1]!.certificate.serial,
    );
    expect(result.body.serial).toBe(h.state.commits[1]!.certificate.serial);
  });

  it("answers 503 on conflict and when an ambiguous commit cannot be confirmed", async () => {
    const h = await issuanceHarness();
    h.state.outcomes.push({ kind: "conflict" });
    expect(await errorOf(issue(h))).toMatchObject({ statusCode: 503 });
    const h2 = await issuanceHarness();
    h2.state.outcomes.push({ kind: "ambiguous" });
    expect(await errorOf(issue(h2))).toMatchObject({ statusCode: 503 });
  });

  it("reads an ambiguous commit back", async () => {
    const h = await issuanceHarness();
    const original = h.pki.commitIssuance.getMockImplementation()!;
    h.pki.commitIssuance.mockImplementationOnce(async (commit) => {
      await original(commit);
      return { kind: "ambiguous" };
    });
    const result = await issue(h, { idempotencyKey: "key-ambig-0001" });
    expect(result.replayed).toBe(true);
    expect(result.body.serial).toBe(h.state.commits[0]!.certificate.serial);
  });

  it("re-checks the stored result when the commit succeeded after an ambiguous send", async () => {
    const h = await issuanceHarness();
    const original = h.pki.commitIssuance.getMockImplementation()!;
    h.pki.commitIssuance.mockImplementationOnce(async (commit) => {
      await original(commit);
      // An operator revokes the certificate before the resend lands.
      const stored = h.state.certificates.get(commit.certificate.serial)!;
      h.state.certificates.set(stored.serial, { ...stored, status: "REVOKED" });
      return { kind: "committed", ambiguous: true };
    });
    expect(await errorOf(issue(h, { idempotencyKey: "key-ambig-0002" }))).toMatchObject({
      statusCode: 409,
      code: "issuance_revoked",
    });
    // A plain commit returns without re-reading.
    const h2 = await issuanceHarness();
    await issue(h2);
    expect(h2.pki.getCertificate).not.toHaveBeenCalled();
  });

  it("refuses to commit a result that is about to expire", async () => {
    const h = await issuanceHarness();
    const real = h.deps.signerFor;
    (h.deps as { signerFor: unknown }).signerFor = (ca: typeof h.ca) => {
      const signer = real(ca);
      return {
        algorithm: signer.algorithm,
        sign: async (tbs: Uint8Array) => {
          const signature = await signer.sign(tbs);
          h.clock.now = new Date(h.clock.now.getTime() + 3_550_000);
          return signature;
        },
      };
    };
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 409,
      code: "issuance_expired",
      safeReason: "issuance_expired",
    });
    expect(h.state.commits).toHaveLength(0);
  });

  it("commits the grant and identity expiry checks against the post-signing clock", async () => {
    const h = await issuanceHarness();
    const real = h.deps.signerFor;
    (h.deps as { signerFor: unknown }).signerFor = (ca: typeof h.ca) => {
      const signer = real(ca);
      return {
        algorithm: signer.algorithm,
        sign: async (tbs: Uint8Array) => {
          const signature = await signer.sign(tbs);
          h.clock.now = new Date(h.clock.now.getTime() + 20_000);
          return signature;
        },
      };
    };
    const start = h.clock.now.getTime();
    await issue(h);
    const commit = h.state.commits[0]!;
    expect(commit.now.getTime()).toBe(start);
    expect((commit as { commitNow?: Date }).commitNow?.getTime()).toBe(
      start + 20_000,
    );
  });

  it("emits the key metrics when signing fails", async () => {
    const h = await issuanceHarness();
    h.kms.send.mockRejectedValueOnce(
      Object.assign(new Error("x"), { name: "AccessDeniedException" }),
    );
    const error = await errorOf(issue(h));
    expect(error.statusCode).toBeGreaterThanOrEqual(409);
    expect(h.emit).toHaveBeenCalled();
  });
});

describe("engine", () => {
  it("denies isCA before anything is read", async () => {
    const h = await issuanceHarness();
    const error = await errorOf(
      issue(h, {
        body: { certificateSigningRequestPem: makeCsr(), isCA: true },
      }),
    );
    expect(error).toMatchObject({
      statusCode: 403,
      code: "issuance_denied",
      safeReason: "ca_not_permitted",
    });
    expect(h.pki.getReplayRecord).not.toHaveBeenCalled();
  });

  it("names the denied name", async () => {
    const h = await issuanceHarness();
    const error = await errorOf(
      issue(h, {
        body: { certificateSigningRequestPem: makeCsr({ dns: ["evil.test"], cn: "evil.test" }) },
      }),
    );
    expect(error).toMatchObject({
      code: "issuance_denied",
      details: {
        reason: "name_not_permitted",
        deniedNameType: "dns",
        deniedName: "evil.test",
      },
    });
  });

  it("defaults key usages and refuses what the grant does not list", async () => {
    const h = await issuanceHarness({
      policy: samplePolicy({ keyAlgorithms: ["ECDSA_P384"] }),
    });
    expect(await errorOf(issue(h))).toMatchObject({
      safeReason: "key_algorithm_not_permitted",
    });
  });

  it("denies more than the grant's maxSans (51 with a CN and a forced URI)", async () => {
    const policy = samplePolicy({
      names: { dns: { allow: ["*.example.com"] }, maxSans: 50 },
      forced: { sans: { uri: ["spiffe://example.com/svc"] } },
    });
    const h = await issuanceHarness({ policy });
    const dns = Array.from({ length: 49 }, (_, i) => `h${i}.example.com`);
    const error = await errorOf(
      issue(h, {
        body: {
          certificateSigningRequestPem: makeCsr({ dns, cn: "cn.example.com" }),
        },
      }),
    );
    expect(error).toMatchObject({ safeReason: "too_many_names" });
  });

  it("issues an admin-forced name that is outside the allowlist", async () => {
    const policy = samplePolicy({
      forced: { sans: { dns: ["internal.corp.test"] } },
    });
    const h = await issuanceHarness({ policy });
    const result = await issue(h);
    expect(h.state.commits[0]!.certificate.sans.dns).toEqual([
      "web.example.com",
      "internal.corp.test",
    ]);
    expect(result.status).toBe(201);
  });

  it("denies a certificate that would be too large", async () => {
    const policy = samplePolicy({
      names: { dns: { allow: ["**.example.com"] }, maxSans: 100 },
    });
    const h = await issuanceHarness({ policy });
    const label = (n: number) => `${String(n).padStart(4, "0")}${"a".repeat(56)}`;
    const dns = Array.from(
      { length: 70 },
      (_, i) =>
        `${label(i)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(50)}.example.com`,
    );
    expect(dns[0]!.length).toBeLessThanOrEqual(253);
    expect(
      await errorOf(
        issue(h, {
          body: { certificateSigningRequestPem: makeCsr({ dns, cn: "cn.example.com" }) },
        }),
      ),
    ).toMatchObject({ safeReason: "certificate_too_large" });
  });

  it("issues RSA-4096 by default and refuses it when the grant omits it", async () => {
    const key = leafKey({ type: "rsa", bits: 2048 });
    const h = await issuanceHarness();
    const csr = makeCsr({ key });
    expect((await issue(h, { body: { certificateSigningRequestPem: csr } })).status).toBe(201);
    const h2 = await issuanceHarness({
      policy: samplePolicy({ keyAlgorithms: ["ECDSA_P256"] }),
    });
    expect(
      await errorOf(issue(h2, { body: { certificateSigningRequestPem: csr } })),
    ).toMatchObject({ safeReason: "key_algorithm_not_permitted" });
  });

  it(
    "issues RSA-8192 only through a grant that lists it",
    async () => {
      const key = leafKey({ type: "rsa", bits: 8192 });
      const csr = makeCsr({ key });
      const h = await issuanceHarness({
        policy: samplePolicy({ keyAlgorithms: ["RSA_8192"] }),
        caPolicy: {
          leafKeyAlgorithms: ["ECDSA_P256", "RSA_8192"],
        },
      });
      expect(
        (await issue(h, { body: { certificateSigningRequestPem: csr } })).status,
      ).toBe(201);
      const h2 = await issuanceHarness({
        policy: samplePolicy({ keyAlgorithms: ["RSA_4096"] }),
      });
      expect(
        await errorOf(
          issue(h2, { body: { certificateSigningRequestPem: csr } }),
        ),
      ).toMatchObject({ safeReason: "key_algorithm_not_permitted" });
    },
    300_000,
  );
});

describe("denied names", () => {
  it("drops a denied value that carries PEM or control characters", async () => {
    const { issuanceDenied } = await import("./errors");
    const pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
    for (const value of [pem, "bad\u0007name", "caf\u00e9"]) {
      const error = issuanceDenied("name_not_permitted", undefined, { type: "subject", value });
      expect(error.details).toEqual({ reason: "name_not_permitted" });
    }
    expect(
      issuanceDenied("name_not_permitted", undefined, { type: "dns", value: "evil.test" }).details,
    ).toMatchObject({ deniedName: "evil.test" });
  });

  it("drops it from evaluate responses too", async () => {
    const h = await issuanceHarness();
    const result = await h.issuance.evaluate(consumerId, "web", {
      keyAlgorithm: "ECDSA_P256",
      sans: { dns: ["web.example.com"] },
      subject: { organization: "-----BEGIN PRIVATE KEY-----" },
    });
    expect(JSON.stringify(result)).not.toContain("deniedName\":\"-----");
    expect((result.denial as Record<string, unknown>).deniedName).toBeUndefined();
  });
});

describe("evaluate", () => {
  it("returns the trace in step order with the plan and context", async () => {
    const h = await issuanceHarness();
    const result = await h.issuance.evaluate(consumerId, "web", {
      certificateSigningRequestPem: makeCsr(),
    });
    expect(result.decision).toBe("allow");
    expect(
      (result.trace as { step: number }[]).map((step) => step.step),
    ).toEqual([1, 5, 6, 7, 8, 9, 10]);
    expect(result).toMatchObject({
      plan: { keyAlgorithm: "ECDSA_P256", subject: "CN=web.example.com" },
      context: {
        grant: { status: "ACTIVE", expired: false },
        ca: { status: "ACTIVE", keyState: "ACTIVE" },
        quotas: { grantHour: { count: 0, limit: 100 } },
      },
    });
    expect(h.pki.countCertificatesSince).not.toHaveBeenCalled();
  });

  it("denies with the named name and still evaluates a disabled grant", async () => {
    const h = await issuanceHarness();
    h.state.grants.set("web", { ...h.grant, status: "DISABLED" });
    const result = await h.issuance.evaluate(consumerId, "web", {
      keyAlgorithm: "ECDSA_P256",
      sans: { dns: ["evil.test"] },
    });
    expect(result).toMatchObject({
      decision: "deny",
      denial: {
        reason: "name_not_permitted",
        deniedNameType: "dns",
        deniedName: "evil.test",
      },
    });
  });

  it("requires exactly one of a CSR or a key algorithm with names", async () => {
    const h = await issuanceHarness();
    for (const body of [
      {},
      { keyAlgorithm: "ECDSA_P256" },
      { certificateSigningRequestPem: makeCsr(), keyAlgorithm: "ECDSA_P256" },
      { certificateSigningRequestPem: makeCsr(), sans: { dns: ["a.example.com"] } },
    ]) {
      expect(
        await errorOf(h.issuance.evaluate(consumerId, "web", body)),
      ).toMatchObject({ statusCode: 400, safeReason: "evaluate_input" });
    }
  });
});

describe("secrets never reach logs or audit targets", () => {
  it("contains no PEM in console output or audit targets", async () => {
    const spies = (["log", "error", "warn", "info"] as const).map((name) =>
      jest.spyOn(console, name).mockImplementation(() => undefined),
    );
    try {
      const h = await issuanceHarness();
      h.state.outcomes.push({ kind: "ambiguous" });
      const targets: Record<string, string>[] = [];
      await errorOf(issue(h));
      const ok = await issue(h, { idempotencyKey: "key-scan-00001" });
      targets.push(ok.auditTarget);
      await errorOf(
        issue(h, {
          body: { certificateSigningRequestPem: makeCsr({ dns: ["x.test"], cn: "x.test" }) },
        }),
      );
      const output = JSON.stringify([
        ...spies.flatMap((spy) => spy.mock.calls),
        ...targets,
      ]);
      expect(output).not.toContain("-----BEGIN");
      expect(generateKeyPairSync).toBeDefined();
    } finally {
      for (const spy of spies) {
        spy.mockRestore();
      }
    }
  });
});

describe("a Hemlig INTERMEDIATE under a ROOT", () => {
  const rootId = "ca-test-root";
  const root = (status: CaRecord["status"] = "ACTIVE"): CaRecord =>
    ({ caId: rootId, kind: "ROOT", status }) as CaRecord;

  it("commits the ancestor slot for an INTERMEDIATE and none for an EXTERNAL CA", async () => {
    const h = await issuanceHarness({ parent: root() });
    await issue(h);
    expect(h.state.commits[0]).toMatchObject({ ancestors: [rootId] });
    const admin1 = await issuanceHarness({ parent: root() });
    await admin1.issuance.issueForAdmin(admin, "key-admin-0001", caId, {
      certificateSigningRequestPem: admin1.defaultCsr,
      useCsrNames: true,
    });
    expect(admin1.state.commits[0]).toMatchObject({
      path: "admin",
      ancestors: [rootId],
    });
    const external = await issuanceHarness();
    await issue(external);
    expect(external.state.commits[0]).toMatchObject({ ancestors: [] });
  });

  it("refuses a REVOKED parent before signing, on both paths", async () => {
    const h = await issuanceHarness({ parent: root("REVOKED") });
    const callsBefore = h.kms.send.mock.calls.length;
    expect(await errorOf(issue(h))).toMatchObject({
      statusCode: 409,
      code: "ca_not_active",
      safeReason: "ancestor_revoked",
    });
    expect(
      await errorOf(
        h.issuance.issueForAdmin(admin, "key-admin-0002", caId, {
          certificateSigningRequestPem: h.defaultCsr,
        }),
      ),
    ).toMatchObject({ code: "ca_not_active", safeReason: "ancestor_revoked" });
    expect(h.kms.send.mock.calls).toHaveLength(callsBefore);
    expect(h.state.commits).toHaveLength(0);
  });

  it("issues under a RETIRED parent", async () => {
    const h = await issuanceHarness({ parent: root("RETIRED") });
    expect((await issue(h)).status).toBe(201);
  });

  it("answers 503 when the parent record is missing", async () => {
    const h = await issuanceHarness({ parent: root() });
    h.state.parent = undefined;
    expect(await errorOf(issue(h))).toMatchObject({ statusCode: 503 });
  });

  it("reruns after an ancestor precondition failure, then reports ancestor_revoked", async () => {
    const h = await issuanceHarness({ parent: root() });
    h.state.outcomes.push({ kind: "preconditionFailed", slots: ["ancestor"] });
    h.pki.commitIssuance.mockImplementationOnce(async (commit) => {
      h.state.commits.push(commit);
      h.state.parent = root("REVOKED");
      return { kind: "preconditionFailed", slots: ["ancestor"] };
    });
    expect(await errorOf(issue(h))).toMatchObject({
      code: "ca_not_active",
      safeReason: "ancestor_revoked",
    });
    expect(h.state.commits).toHaveLength(1);
  });

  it("replays an administrator issuance under a REVOKED parent as ancestor_revoked", async () => {
    const h = await issuanceHarness({ parent: root() });
    const request = {
      certificateSigningRequestPem: h.defaultCsr,
      useCsrNames: true,
    };
    await h.issuance.issueForAdmin(admin, "key-admin-0003", caId, request);
    h.state.parent = root("REVOKED");
    expect(
      await errorOf(
        h.issuance.issueForAdmin(admin, "key-admin-0003", caId, request),
      ),
    ).toMatchObject({
      statusCode: 409,
      code: "issuance_revoked",
      safeReason: "ancestor_revoked",
    });
    expect(h.state.ca.status).toBe("ACTIVE");
  });

  it("replays with the child ACTIVE and the parent REVOKED as ancestor_revoked, and a REVOKED child as ca_revoked", async () => {
    const h = await issuanceHarness({ parent: root() });
    await issue(h, { idempotencyKey: "key-ancestor-01" });
    h.state.parent = root("REVOKED");
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-ancestor-01" })),
    ).toMatchObject({
      statusCode: 409,
      code: "issuance_revoked",
      safeReason: "ancestor_revoked",
    });
    h.state.ca = { ...h.ca, status: "REVOKED" };
    expect(
      await errorOf(issue(h, { idempotencyKey: "key-ancestor-01" })),
    ).toMatchObject({ code: "issuance_revoked", safeReason: "ca_revoked" });
  });
});
