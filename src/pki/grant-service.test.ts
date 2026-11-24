import { issuanceHarness, samplePolicy, errorOf, consumerId, admin, type Harness } from "./__fixtures__/issuance-harness";
import type { IssuanceGrantRecord } from "./types";

const body = (extra: Record<string, unknown> = {}) => ({
  name: "api",
  caId: "ca-test-one",
  ...samplePolicy(),
  ...extra,
});

const setup = async (options: Parameters<typeof issuanceHarness>[0] = {}) => {
  const h = await issuanceHarness(options);
  const created: IssuanceGrantRecord[] = [];
  const pki = h.pki as unknown as Harness["pki"] & {
    countLiveGrants: jest.Mock;
    createGrant: jest.Mock;
    updateGrant: jest.Mock;
    deleteGrant: jest.Mock;
  };
  pki.countLiveGrants = jest.fn(async () => 1);
  pki.createGrant = jest.fn(async (input: { grant: IssuanceGrantRecord }) => {
    created.push(input.grant);
    h.state.grants.set(input.grant.name, input.grant);
    return { kind: "created" };
  });
  pki.updateGrant = jest.fn(async (input: { grant: IssuanceGrantRecord }) => {
    h.state.grants.set(input.grant.name, input.grant);
    return { kind: "updated" };
  });
  pki.deleteGrant = jest.fn(async (input: { name: string; newVersion: string; now: string }) => {
    const current = h.state.grants.get(input.name)!;
    h.state.grants.set(input.name, {
      ...current,
      status: "DELETED",
      version: input.newVersion,
      deletedAt: input.now,
    });
    return { kind: "deleted" };
  });
  return { h, created, pki };
};

const create = (h: Harness, extra: Record<string, unknown> = {}, key = "key-grant-0001") =>
  h.grants.create(admin, key, consumerId, body(extra));

describe("GrantService.create", () => {
  it("commits the record and answers 201 with an ETag and the audit target", async () => {
    const { h, created, pki } = await setup();
    const result = await create(h);
    expect(result.status).toBe(201);
    expect(result.etag).toBe(created[0]!.version);
    expect(created[0]).toMatchObject({
      uid: expect.stringMatching(/^pkg-/),
      consumerId,
      environment: "prod",
      name: "api",
      caId: "ca-test-one",
      status: "ACTIVE",
      version: expect.stringMatching(/^pkv-/),
      policyDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(pki.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        caVersion: "pkv-ca-1",
        idempotency: expect.objectContaining({
          operationType: "pki.grant.create",
          idempotencyKey: "key-grant-0001",
        }),
      }),
    );
    expect(result.auditTarget).toMatchObject({
      consumerId,
      environment: "prod",
      caId: "ca-test-one",
      issuanceGrant: "api",
      issuanceGrantUid: created[0]!.uid,
      status: "ACTIVE",
    });
  });

  it("replays by key and refuses a changed body", async () => {
    const { h, created, pki } = await setup();
    await create(h);
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.create",
      requestDigest: ((pki.createGrant.mock.calls[0] as unknown[])[0] as { idempotency: { requestDigest: string } }).idempotency.requestDigest,
      status: "SUCCEEDED",
      result: { consumerId, name: "api" },
    });
    const replayed = await create(h);
    expect(replayed.status).toBe(201);
    expect(replayed.shouldWriteTerminalAudit).toBe(false);
    expect(created).toHaveLength(1);
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.create",
      requestDigest: "other",
      status: "COMMITTED",
      result: {},
    });
    expect(await errorOf(create(h))).toMatchObject({ statusCode: 409 });
  });

  it("creates over a tombstone with a new uid", async () => {
    const { h, created } = await setup();
    await create(h);
    const first = created[0]!.uid;
    await h.grants.delete(admin, "key-grant-del01", consumerId, "api", created[0]!.version);
    await create(h, {}, "key-grant-0002");
    expect(created[1]!.uid).not.toBe(first);
  });

  it("maps exists to grant_exists and a lost CA race to a retry", async () => {
    const { h, pki } = await setup();
    pki.createGrant.mockResolvedValueOnce({ kind: "exists" });
    expect(await errorOf(create(h))).toMatchObject({ statusCode: 409, safeReason: "grant_exists" });
    pki.createGrant.mockResolvedValueOnce({ kind: "caChanged" });
    await create(h);
    expect(pki.createGrant).toHaveBeenCalledTimes(3);
    pki.createGrant.mockResolvedValue({ kind: "caChanged" });
    h.state.ca = { ...h.ca, status: "RETIRED" };
    expect(await errorOf(create(h, {}, "key-grant-0009"))).toMatchObject({
      code: "ca_not_active",
    });
  });

  it("refuses the 21st live grant", async () => {
    const { h, pki } = await setup();
    pki.countLiveGrants.mockResolvedValue(20);
    expect(await errorOf(create(h))).toMatchObject({
      statusCode: 409,
      safeReason: "grant_limit_reached",
    });
  });

  it("is a 404 for an unknown CA and 400 for another environment", async () => {
    const { h } = await setup();
    expect(await errorOf(create(h, { caId: "ca-unknown-one" }))).toMatchObject({
      statusCode: 404,
      safeReason: "ca_not_found",
    });
    h.state.ca = { ...h.ca, environment: "staging" };
    expect(await errorOf(create(h))).toMatchObject({
      statusCode: 400,
      safeReason: "environment_mismatch",
    });
  });
});

describe("replay after the requested expiry", () => {
  it("replays an identical create and update after expiresAt has passed", async () => {
    const { h, pki } = await setup();
    const expiresAt = new Date(h.clock.now.getTime() + 60_000).toISOString();
    await create(h, { expiresAt });
    const digestOf = (call: unknown) =>
      (call as { idempotency: { requestDigest: string } }).idempotency.requestDigest;
    const stored = (digest: string, operationType: string) => ({
      operationType,
      requestDigest: digest,
      status: "SUCCEEDED",
      result: { consumerId, name: "api" },
    });
    h.clock.now = new Date(h.clock.now.getTime() + 3_600_000);
    h.deps.repository.getIdempotency.mockResolvedValueOnce(
      stored(digestOf((pki.createGrant.mock.calls[0] as unknown[])[0]), "pki.grant.create"),
    );
    expect((await create(h, { expiresAt })).status).toBe(201);
    expect(pki.createGrant).toHaveBeenCalledTimes(1);
    // A new request with the past expiry is still refused.
    expect(await errorOf(create(h, { expiresAt }, "key-grant-0099"))).toMatchObject({
      safeReason: "invalid_expiry",
    });
    const { name: _name, ...update } = body({ expiresAt });
    const { grants } = h;
    const spy = jest.spyOn(grants as never, "prior" as never);
    h.deps.repository.getIdempotency.mockResolvedValueOnce(
      stored("x", "pki.grant.update"),
    );
    spy.mockResolvedValueOnce(stored("x", "pki.grant.update") as never);
    expect((await grants.update(admin, "key-upd-00077", consumerId, "api", "v", update)).status).toBe(200);
    expect(pki.updateGrant).not.toHaveBeenCalled();
  });
});

describe("consumers", () => {
  it("accepts a PENDING agent and refuses another environment or a mapping without its grant", async () => {
    const { h } = await setup();
    const repository = h.repository as unknown as {
      getAgentGrantIdForConsumer: jest.Mock;
      getAgentGrant: jest.Mock;
      getConsumer: jest.Mock;
    };
    repository.getAgentGrantIdForConsumer.mockResolvedValue("grant-1");
    repository.getAgentGrant.mockResolvedValue({ environment: "prod", status: "PENDING" });
    expect((await create(h)).status).toBe(201);
    repository.getAgentGrant.mockResolvedValue({ environment: "staging", status: "ACTIVE" });
    expect(await errorOf(create(h, {}, "key-grant-0002"))).toMatchObject({
      safeReason: "environment_mismatch",
    });
    repository.getAgentGrant.mockResolvedValue(undefined);
    expect(await errorOf(create(h, {}, "key-grant-0003"))).toMatchObject({
      statusCode: 503,
    });
  });

  it("requires an ACTIVE direct consumer", async () => {
    const { h } = await setup();
    const repository = h.repository as unknown as {
      getAgentGrantIdForConsumer: jest.Mock;
      getAgentGrant: jest.Mock;
      getConsumer: jest.Mock;
    };
    repository.getConsumer.mockResolvedValue({ environment: "prod", status: "PENDING" });
    expect(await errorOf(create(h))).toMatchObject({
      statusCode: 409,
      safeReason: "consumer_not_active",
    });
    repository.getConsumer.mockResolvedValue(undefined);
    expect(await errorOf(create(h))).toMatchObject({
      statusCode: 404,
      safeReason: "consumer_not_found",
    });
  });
});

describe("policy validation against the CA", () => {
  const constrained = (h: Harness) => {
    h.state.ca = {
      ...h.ca,
      effective: {
        nameConstraints: {
          permitted: [{ type: "dns", value: "example.org" }],
          excluded: [],
        },
      },
    };
  };

  it("errors on a rule entirely outside the CA constraints", async () => {
    const { h } = await setup();
    constrained(h);
    const error = await errorOf(create(h));
    expect(error).toMatchObject({
      statusCode: 400,
      safeReason: "invalid_grant_policy",
      details: { code: "rule_outside_ca_constraints" },
    });
    const result = await h.grants.validateCreate(consumerId, body());
    expect(result.valid).toBe(false);
  });

  it("errors on a forced SAN outside the constraints and warns on a partial overlap", async () => {
    const { h } = await setup();
    constrained(h);
    const forced = await h.grants.validateCreate(
      consumerId,
      body({
        names: { dns: { allow: ["*.example.org"] }, maxSans: 5 },
        forced: { sans: { dns: ["x.other.com"] } },
      }),
    );
    expect(forced.errors.map((e) => e.code)).toContain("forced_san_violates_ca_constraints");
    h.state.ca = {
      ...h.ca,
      effective: {
        nameConstraints: {
          permitted: [
            { type: "dns", value: "example.com" },
            { type: "dns", value: "svc.cluster.local" },
          ],
          excluded: [],
        },
      },
    };
    const partial = await h.grants.validateCreate(
      consumerId,
      body({ names: { dns: { allow: ["**.cluster.local"] }, maxSans: 5 } }),
    );
    expect(partial.valid).toBe(true);
    expect(partial.warnings.length).toBeGreaterThan(0);
  });

  it("refuses a policy over 32 KiB, a key algorithm and a lifetime outside the CA", async () => {
    const { h } = await setup({ caPolicy: { leafKeyAlgorithms: ["ECDSA_P256"], maxLeafLifetimeSeconds: 3600 } });
    expect(
      await errorOf(
        create(h, { displayName: "x", names: { dns: { allow: ["a".repeat(40_000) + ".example.com"] } } }),
      ),
    ).toMatchObject({ safeReason: "policy_too_large" });
    expect(
      (await h.grants.validateCreate(consumerId, body({ keyAlgorithms: ["RSA_2048"] }))).valid,
    ).toBe(false);
    expect(
      (
        await h.grants.validateCreate(
          consumerId,
          body({ lifetime: { defaultSeconds: 3600, maxSeconds: 86_400 } }),
        )
      ).valid,
    ).toBe(false);
  });

  it("warns when the grant's hourly quota exceeds the CA rate", async () => {
    const { h } = await setup({ caPolicy: { issuancePerHour: 10 } });
    const result = await h.grants.validateCreate(
      consumerId,
      body({ quotas: { perHour: 50 } }),
    );
    expect(result.valid).toBe(true);
    expect(result.warnings.map((w) => w.code)).toContain("quota_exceeds_ca_rate");
  });

  it("validateOnly writes nothing and needs no key", async () => {
    const { h, pki } = await setup();
    const result = await h.grants.validateCreate(consumerId, body());
    expect(result).toMatchObject({ valid: true, errors: [] });
    expect(result.policyDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(pki.createGrant).not.toHaveBeenCalled();
    expect(h.deps.repository.getIdempotency).not.toHaveBeenCalled();
  });
});

describe("update and delete", () => {
  it("updates under If-Match, keeping the uid and moving the CA", async () => {
    const { h, pki } = await setup();
    const existing = h.grant;
    const { name: _name, ...update } = body({ displayName: "Web" });
    const result = await h.grants.update(admin, "key-upd-00001", consumerId, "web", existing.version, update);
    expect(result.status).toBe(200);
    expect(pki.updateGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        ifMatch: "pkv-grant-1",
        caVersion: "pkv-ca-1",
        grant: expect.objectContaining({ uid: existing.uid, displayName: "Web" }),
      }),
    );
    expect(result.etag).not.toBe(existing.version);
  });

  it("replays an update as the generation it wrote, not a later change by someone else", async () => {
    const { h, pki } = await setup();
    const { name: _name, ...update } = body({ displayName: "Mine" });
    const first = await h.grants.update(admin, "key-upd-00010", consumerId, "web", "pkv-grant-1", update);
    const call = pki.updateGrant.mock.calls[0]![0] as {
      idempotency: { requestDigest: string; result: Record<string, unknown> };
    };
    // Another operator disables the grant (v3) before the retry arrives.
    h.state.grants.set("web", {
      ...(h.state.grants.get("web") as IssuanceGrantRecord),
      status: "DISABLED",
      version: "pkv-v3",
    });
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.update",
      requestDigest: call.idempotency.requestDigest,
      status: "SUCCEEDED",
      result: call.idempotency.result,
    });
    const replayed = await h.grants.update(admin, "key-upd-00010", consumerId, "web", "pkv-grant-1", update);
    expect(replayed.etag).toBe(first.etag);
    expect(replayed.body.version).toBe(first.etag);
    expect(replayed.body.status).toBe("ACTIVE");
    expect(pki.updateGrant).toHaveBeenCalledTimes(1);
  });

  it("replays a create as the generation it wrote, not a later update", async () => {
    const { h, created, pki } = await setup();
    const first = await create(h);
    const call = pki.createGrant.mock.calls[0]![0] as {
      idempotency: { requestDigest: string; result: Record<string, unknown> };
    };
    h.state.grants.set("api", { ...created[0]!, version: "pkv-later", status: "DISABLED" });
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.create",
      requestDigest: call.idempotency.requestDigest,
      status: "SUCCEEDED",
      result: call.idempotency.result,
    });
    const replayed = await create(h);
    expect(replayed.etag).toBe(first.etag);
    expect(replayed.body.status).toBe("ACTIVE");
  });

  it("refuses to confirm a delete from a receipt without a record when the grant is live", async () => {
    const { h, pki } = await setup();
    pki.deleteGrant.mockClear();
    // The digest is recomputed by the service, so capture it from a real delete first.
    await h.grants.delete(admin, "key-del-00020", consumerId, "web", "pkv-grant-1");
    const call = pki.deleteGrant.mock.calls[0]![0] as {
      idempotency: { requestDigest: string };
    };
    h.state.grants.set("web", {
      ...(h.state.grants.get("web") as IssuanceGrantRecord),
      status: "ACTIVE",
      uid: "pkg-other",
      version: "pkv-new",
    });
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.delete",
      requestDigest: call.idempotency.requestDigest,
      status: "SUCCEEDED",
      result: { consumerId, name: "web" },
    });
    expect(
      await errorOf(h.grants.delete(admin, "key-del-00020", consumerId, "web", "pkv-grant-1")),
    ).toMatchObject({ statusCode: 503 });
  });

  it("answers 412 before and after the commit", async () => {
    const { h, pki } = await setup();
    const { name: _name, ...update } = body();
    expect(
      await errorOf(h.grants.update(admin, "key-upd-00002", consumerId, "web", "stale", update)),
    ).toMatchObject({ statusCode: 412 });
    pki.updateGrant.mockImplementationOnce(async () => {
      h.state.grants.set("web", { ...h.grant, version: "pkv-newer" });
      return { kind: "stale" };
    });
    expect(
      await errorOf(h.grants.update(admin, "key-upd-00003", consumerId, "web", "pkv-grant-1", update)),
    ).toMatchObject({ statusCode: 412 });
  });

  it("moves the CA and reports previousCaId", async () => {
    const { h } = await setup();
    const { name: _name, ...update } = body();
    const result = await h.grants.update(admin, "key-upd-00004", consumerId, "web", "pkv-grant-1", update);
    expect(result.auditTarget.previousCaId).toBeUndefined();
    h.state.grants.set("web", { ...h.grant, caId: "ca-other-one", version: "pkv-moved" });
    const moved = await h.grants.update(admin, "key-upd-00005", consumerId, "web", "pkv-moved", update);
    expect(moved.auditTarget).toMatchObject({ previousCaId: "ca-other-one", caId: "ca-test-one" });
  });

  it("validateUpdate needs a matching If-Match and writes nothing", async () => {
    const { h, pki } = await setup();
    const { name: _name, ...update } = body();
    expect(await h.grants.validateUpdate(consumerId, "web", "pkv-grant-1", update)).toMatchObject({ valid: true });
    expect(await errorOf(h.grants.validateUpdate(consumerId, "web", "nope", update))).toMatchObject({ statusCode: 412 });
    expect(pki.updateGrant).not.toHaveBeenCalled();
  });

  it("deletes into a tombstone that get still returns", async () => {
    const { h, pki } = await setup();
    const result = await h.grants.delete(admin, "key-del-00001", consumerId, "web", "pkv-grant-1");
    expect(result.status).toBe(200);
    expect(result.body.status).toBe("DELETED");
    expect(pki.deleteGrant).toHaveBeenCalledWith(
      expect.objectContaining({ consumerId, name: "web", ifMatch: "pkv-grant-1" }),
    );
    expect((await h.grants.get(consumerId, "web")).body.status).toBe("DELETED");
    expect(
      await errorOf(h.grants.delete(admin, "key-del-00002", consumerId, "web", "x")),
    ).toMatchObject({ statusCode: 404, safeReason: "grant_not_found" });
    expect(await errorOf(h.grants.get(consumerId, "missing-one"))).toMatchObject({
      statusCode: 404,
    });
  });

  it("answers a delete with the deleted generation even if the name is recreated at once", async () => {
    const { h, pki } = await setup();
    const original = h.state.grants.get("web")!;
    const realDelete = pki.deleteGrant.getMockImplementation()!;
    pki.deleteGrant.mockImplementationOnce(async (input: never) => {
      const outcome = await realDelete(input);
      h.state.grants.set("web", {
        ...original,
        uid: "pkg-uid-replacement",
        version: "pkv-replacement",
        status: "ACTIVE",
      });
      return outcome;
    });
    const result = await h.grants.delete(admin, "key-del-00003", consumerId, "web", "pkv-grant-1");
    expect(result.body.uid).toBe(original.uid);
    expect(result.body.status).toBe("DELETED");
    expect(result.auditTarget.issuanceGrantUid).toBe(original.uid);
    const call = pki.deleteGrant.mock.calls[0]![0] as {
      idempotency: { result: { uid: string } };
    };
    expect(call.idempotency.result.uid).toBe(original.uid);
  });

  it("replays a delete with the deleted generation after the name is recreated", async () => {
    const { h, pki } = await setup();
    const original = h.state.grants.get("web")!;
    await h.grants.delete(admin, "key-del-00004", consumerId, "web", "pkv-grant-1");
    const recorded = (pki.deleteGrant.mock.calls[0]![0] as {
      idempotency: { requestDigest: string; result: Record<string, unknown> };
    }).idempotency;
    h.state.grants.set("web", {
      ...original,
      uid: "pkg-uid-replacement",
      version: "pkv-replacement",
    });
    h.deps.repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.grant.delete",
      requestDigest: recorded.requestDigest,
      status: "SUCCEEDED",
      result: recorded.result,
    });
    const replayed = await h.grants.delete(admin, "key-del-00004", consumerId, "web", "pkv-grant-1");
    expect(replayed.body.uid).toBe(original.uid);
    expect(replayed.body.status).toBe("DELETED");
    expect(replayed.shouldWriteTerminalAudit).toBe(false);
  });
});
