import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { IssuanceGrantRecord, IssuedCertificateRecord } from "../pki/types";
import {
  buildBulkRevokeBatch,
  buildCreateGrantTransaction,
  buildDeleteGrantTransaction,
  buildIssuanceCommit,
  buildRevokeTransaction,
  buildUpdateGrantTransaction,
  classifyIssuanceCancellation,
  quotaRetryAfterSeconds,
  PKI_DIRECTORY_ATTRIBUTES,
  pkiDirectory,
  pkiKeys,
  PkiIndexNotReadyError,
  PkiRepository,
  pkiTtl,
  quotaWindows,
  type AdminIssuanceCommit,
  type ConsumerIssuanceCommit,
  type IssuanceCommit,
} from "./pki";

const now = new Date("2026-11-22T10:30:00.000Z");
const notAfter = "2026-12-22T10:30:00.000Z";
const fingerprint = "f".repeat(64);
const serial = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567";

const certificate = (
  requester: IssuedCertificateRecord["requester"],
  overrides: Partial<IssuedCertificateRecord> = {},
): IssuedCertificateRecord => ({
  caId: "ca-prod-one",
  environment: "prod",
  serial,
  status: "ISSUED",
  certificatePem: "PEM",
  fingerprint: "a".repeat(64),
  spkiSha256: "b".repeat(64),
  subject: "CN=test",
  sans: { dns: [], ip: [], uri: [] },
  keyAlgorithm: "ECDSA_P256",
  keyUsages: [],
  extendedKeyUsages: [],
  isCa: false,
  notBefore: now.toISOString(),
  notAfter,
  issuedAt: now.toISOString(),
  requester,
  ...overrides,
});

const consumerCommit = (
  overrides: Partial<ConsumerIssuanceCommit> = {},
): ConsumerIssuanceCommit => ({
  path: "consumer",
  now,
  idempotencyKey: "idempotency-key-1",
  requestDigest: "d".repeat(64),
  certificate: certificate({
    type: "consumer",
    id: "payments-agent",
    consumerId: "payments-agent",
    issuanceGrant: { name: "web-tls", uid: "uid-1234", version: "v1" },
  }),
  ca: { caId: "ca-prod-one", version: "cv-1", issuancePerHour: 2000 },
  consumerId: "payments-agent",
  identityFingerprint: fingerprint,
  grant: {
    name: "web-tls",
    uid: "uid-1234",
    version: "v1",
    perHour: 100,
    perDay: 1000,
  },
  agentGrant: {
    grantId: "grant-12345678-1234-1234-1234-123456789012",
    environment: "prod",
  },
  ...overrides,
});

const adminCommit = (
  overrides: Partial<AdminIssuanceCommit> = {},
): AdminIssuanceCommit => ({
  path: "admin",
  now,
  idempotencyKey: "idempotency-key-2",
  requestDigest: "d".repeat(64),
  certificate: certificate({ type: "human", id: "admin-1" }),
  ca: { caId: "ca-prod-one", version: "cv-1", issuancePerHour: 2000 },
  actor: { type: "human", id: "admin-1" },
  adminPerHour: 100,
  ...overrides,
});

describe("key builders", () => {
  it("builds each key", () => {
    expect(pkiKeys.caProfile("ca-prod-one")).toEqual({
      pk: "PKI_CA#ca-prod-one",
      sk: "PROFILE",
    });
    expect(pkiKeys.caCrl("ca-prod-one")).toEqual({
      pk: "PKI_CA#ca-prod-one",
      sk: "CRL",
    });
    expect(pkiKeys.revocation("ca-prod-one", "0a")).toEqual({
      pk: "PKI_CA#ca-prod-one",
      sk: "REVOKED#0a",
    });
    expect(pkiKeys.caName("prod", "root-one")).toEqual({
      pk: "PKI_CA_NAME#prod#root-one",
      sk: "LOOKUP",
    });
    expect(pkiKeys.subject("a".repeat(64))).toEqual({
      pk: `PKI_SUBJECT#${"a".repeat(64)}`,
      sk: "LOOKUP",
    });
    expect(pkiKeys.externalCa(`ext-${"a".repeat(40)}`)).toEqual({
      pk: `PKI_EXTCA#ext-${"a".repeat(40)}`,
      sk: "PROFILE",
    });
    expect(pkiKeys.certificate("ca-prod-one", "0a")).toEqual({
      pk: "PKI_CERT#ca-prod-one#0a",
      sk: "PROFILE",
    });
    expect(
      pkiKeys.consumerCertificate(
        "payments-agent",
        notAfter,
        "ca-prod-one",
        "0a",
      ),
    ).toEqual({
      pk: "PKI_CONSUMER#payments-agent",
      sk: `CERT#${notAfter}#ca-prod-one#0a`,
    });
    expect(pkiKeys.grant("payments-agent", "web-tls")).toEqual({
      pk: "PKI_GRANT#payments-agent",
      sk: "NAME#web-tls",
    });
    expect(pkiKeys.grantQuota("uid-1", "HOUR#2026112210")).toEqual({
      pk: "PKI_QUOTA#uid-1",
      sk: "HOUR#2026112210",
    });
    expect(pkiKeys.adminQuota("ca-prod-one", "DAY#20261122")).toEqual({
      pk: "PKI_QUOTA#admin#ca-prod-one",
      sk: "DAY#20261122",
    });
    expect(pkiKeys.caQuota("ca-prod-one", "HOUR#2026112210")).toEqual({
      pk: "PKI_QUOTA#ca#ca-prod-one",
      sk: "HOUR#2026112210",
    });
    expect(pkiKeys.replay("payments-agent", "idempotency-key-1")).toEqual({
      pk: "PKI_IDEMPOTENCY#payments-agent",
      sk: "REQUEST#idempotency-key-1",
    });
    expect(pkiKeys.humanIdempotency("admin-1", "idempotency-key-1")).toEqual({
      pk: "IDEMPOTENCY#human#admin-1",
      sk: "REQUEST#idempotency-key-1",
    });
  });

  it("rejects malformed components", () => {
    expect(() => pkiKeys.caProfile("prod-one")).toThrow();
    expect(() => pkiKeys.certificate("ca-prod-one", "xyz")).toThrow();
    expect(() => pkiKeys.certificate("ca-prod-one", "a")).toThrow();
    expect(() => pkiKeys.grant("Payments", "web-tls")).toThrow();
    expect(() => pkiKeys.caName("Prod", "root-one")).toThrow();
    expect(() => pkiKeys.subject("abc")).toThrow();
    expect(() => pkiKeys.externalCa("ext-abc")).toThrow();
    expect(() => pkiKeys.grantQuota("admin#ca", "HOUR#x")).toThrow();
    expect(() => pkiKeys.replay("payments-agent", "short")).toThrow();
    expect(() => pkiKeys.replay("payments-agent", "k".repeat(129))).toThrow();
    expect(() =>
      pkiKeys.consumerCertificate(
        "payments-agent",
        "2026-11-22",
        "ca-prod-one",
        "0a",
      ),
    ).toThrow();
  });

  it("builds directory keys and exports the attribute names", () => {
    expect(pkiDirectory.ca("prod", "root-one")).toEqual({
      pkiDirectoryPk: "PKI_CAS",
      pkiDirectorySk: "prod#root-one",
    });
    expect(pkiDirectory.externalCa(`ext-${"b".repeat(40)}`)).toEqual({
      pkiDirectoryPk: "PKI_EXTCAS",
      pkiDirectorySk: `ext-${"b".repeat(40)}`,
    });
    expect(
      pkiDirectory.grant("ca-prod-one", "payments-agent", "web-tls"),
    ).toEqual({
      pkiDirectoryPk: "PKI_CA_GRANTS#ca-prod-one",
      pkiDirectorySk: "payments-agent#web-tls",
    });
    expect(pkiDirectory.certificate("ca-prod-one", notAfter, "0a")).toEqual({
      pkiDirectoryPk: "PKI_CERTS#ca-prod-one",
      pkiDirectorySk: `${notAfter}#0a`,
    });
    expect(PKI_DIRECTORY_ATTRIBUTES).toEqual([
      "pkiDirectoryPk",
      "pkiDirectorySk",
    ]);
  });

  it("computes TTLs in epoch seconds", () => {
    const seconds = Date.parse(notAfter) / 1000;
    expect(pkiTtl.certificate(notAfter)).toBe(seconds + 90 * 86400);
    expect(pkiTtl.consumerPointer(notAfter)).toBe(seconds + 90 * 86400);
    expect(pkiTtl.replay(notAfter)).toBe(seconds + 400 * 86400);
    const windows = quotaWindows(now);
    expect(pkiTtl.hourCounter(windows.hourStart)).toBe(
      windows.hourStart.getTime() / 1000 + 48 * 3600,
    );
    expect(pkiTtl.dayCounter(windows.dayStart)).toBe(
      windows.dayStart.getTime() / 1000 + 3 * 86400,
    );
  });

  it("computes quota windows at the end of a day", () => {
    const windows = quotaWindows(new Date("2026-12-31T23:59:59.999Z"));
    expect(windows.hourSk).toBe("HOUR#2026123123");
    expect(windows.daySk).toBe("DAY#20261231");
    expect(windows.hourEnd.toISOString()).toBe("2027-01-01T00:00:00.000Z");
    expect(windows.dayEnd.toISOString()).toBe("2027-01-01T00:00:00.000Z");
    expect(windows.hourStart.toISOString()).toBe("2026-12-31T23:00:00.000Z");
    expect(windows.dayStart.toISOString()).toBe("2026-12-31T00:00:00.000Z");
  });
});

describe("buildIssuanceCommit", () => {
  const tokens = (expression: string): string[] =>
    expression.match(/[#:]?[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
  const allowed =
    /^(#\w+|:\w+|pk|attribute_not_exists|attribute_exists|if_not_exists|SET|ADD|AND|OR|NOT)$/;

  const expressionsOf = (items: unknown[]): string[] =>
    items.flatMap((item) => {
      const [operation] = Object.values(item as Record<string, unknown>) as [
        Record<string, string | undefined>,
      ];
      return [operation.ConditionExpression, operation.UpdateExpression].filter(
        (value): value is string => value !== undefined,
      );
    });

  it("orders the agent path by slot", () => {
    const built = buildIssuanceCommit("control", consumerCommit());
    expect(built.slots).toEqual([
      "replay",
      "certificate",
      "consumerPointer",
      "grantHour",
      "grantDay",
      "caHour",
      "grant",
      "ca",
      "identity",
      "agentGrant",
    ]);
    const items = built.input.TransactItems as Record<string, any>[];
    expect(items).toHaveLength(10);
    const [replay, cert, pointer, gh, gd, ch, grant, ca, identity, agent] =
      items as [
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
        Record<string, any>,
      ];
    expect(replay.Put.Item).toEqual({
      pk: "PKI_IDEMPOTENCY#payments-agent",
      sk: "REQUEST#idempotency-key-1",
      requestDigest: "d".repeat(64),
      caId: "ca-prod-one",
      serial,
      notAfter,
      grantUid: "uid-1234",
      ttl: pkiTtl.replay(notAfter),
    });
    expect(replay.Put.ConditionExpression).toBe("attribute_not_exists(pk)");
    expect(cert.Put.Item).toMatchObject({
      pk: `PKI_CERT#ca-prod-one#${serial}`,
      sk: "PROFILE",
      pkiDirectoryPk: "PKI_CERTS#ca-prod-one",
      pkiDirectorySk: `${notAfter}#${serial}`,
      ttl: pkiTtl.certificate(notAfter),
      status: "ISSUED",
      serial,
    });
    expect(pointer.Put.Item).toEqual({
      pk: "PKI_CONSUMER#payments-agent",
      sk: `CERT#${now.toISOString()}#ca-prod-one#${serial}`,
      caId: "ca-prod-one",
      serial,
      environment: "prod",
      notAfter,
      issuedAt: now.toISOString(),
      issuanceGrant: "web-tls",
      issuanceGrantUid: "uid-1234",
      ttl: pkiTtl.consumerPointer(notAfter),
    });
    const windows = quotaWindows(now);
    const quota = (key: unknown, limit: number, ttl: number) => ({
      TableName: "control",
      Key: key,
      UpdateExpression: "SET #ttl = if_not_exists(#ttl, :ttl) ADD #count :one",
      ConditionExpression: "attribute_not_exists(#count) OR #count < :limit",
      ExpressionAttributeNames: { "#ttl": "ttl", "#count": "count" },
      ExpressionAttributeValues: { ":ttl": ttl, ":one": 1, ":limit": limit },
    });
    expect(gh.Update).toEqual(
      quota(
        pkiKeys.grantQuota("uid-1234", windows.hourSk),
        100,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    expect(gd.Update).toEqual(
      quota(
        pkiKeys.grantQuota("uid-1234", windows.daySk),
        1000,
        pkiTtl.dayCounter(windows.dayStart),
      ),
    );
    expect(ch.Update).toEqual(
      quota(
        pkiKeys.caQuota("ca-prod-one", windows.hourSk),
        2000,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    expect(grant.ConditionCheck).toEqual({
      TableName: "control",
      Key: { pk: "PKI_GRANT#payments-agent", sk: "NAME#web-tls" },
      ConditionExpression:
        "#uid = :uid AND #version = :version AND #status = :active AND (attribute_not_exists(#expiresAt) OR #expiresAt > :now)",
      ExpressionAttributeNames: {
        "#uid": "uid",
        "#version": "version",
        "#status": "status",
        "#expiresAt": "expiresAt",
      },
      ExpressionAttributeValues: {
        ":uid": "uid-1234",
        ":version": "v1",
        ":active": "ACTIVE",
        ":now": now.toISOString(),
      },
    });
    expect(ca.ConditionCheck).toMatchObject({
      Key: { pk: "PKI_CA#ca-prod-one", sk: "PROFILE" },
      ConditionExpression:
        "#status = :active AND #version = :version AND #key.#state = :active",
      ExpressionAttributeValues: { ":active": "ACTIVE", ":version": "cv-1" },
    });
    expect(identity.ConditionCheck).toMatchObject({
      Key: { pk: `IDENTITY#${fingerprint}`, sk: "PROFILE" },
      ConditionExpression:
        "#status = :active AND #kind = :api AND #notAfter > :now AND #consumerId = :consumerId",
      ExpressionAttributeValues: {
        ":active": "ACTIVE",
        ":api": "api",
        ":now": now.toISOString(),
        ":consumerId": "payments-agent",
      },
    });
    expect(agent.ConditionCheck).toMatchObject({
      Key: {
        pk: "AGENT_GRANT#grant-12345678-1234-1234-1234-123456789012",
        sk: "PROFILE",
      },
      ConditionExpression:
        "#status = :active AND #environment = :environment AND #consumerId = :consumerId",
    });
  });

  it("omits the agent grant on the direct path", () => {
    const built = buildIssuanceCommit(
      "control",
      consumerCommit({ agentGrant: undefined }),
    );
    expect(built.slots).toHaveLength(9);
    expect(built.slots).not.toContain("agentGrant");
  });

  it("orders the admin path and writes a human idempotency record", () => {
    const built = buildIssuanceCommit("control", adminCommit());
    expect(built.slots).toEqual([
      "replay",
      "certificate",
      "adminHour",
      "caHour",
      "ca",
    ]);
    const items = built.input.TransactItems as Record<string, any>[];
    expect(items[0]?.Put.Item).toEqual({
      pk: "IDEMPOTENCY#human#admin-1",
      sk: "REQUEST#idempotency-key-2",
      operationType: "pki.certificate.issue",
      requestDigest: "d".repeat(64),
      status: "COMMITTED",
      result: { caId: "ca-prod-one", serial, notAfter },
      createdAt: now.toISOString(),
    });
    expect(items[2]?.Update.Key).toEqual(
      pkiKeys.adminQuota("ca-prod-one", quotaWindows(now).hourSk),
    );
    expect(items[2]?.Update.ExpressionAttributeValues[":limit"]).toBe(100);
  });

  it("adds an ancestor check per Hemlig ancestor", () => {
    const built = buildIssuanceCommit(
      "control",
      adminCommit({ ancestors: ["ca-root-one"] }),
    );
    expect(built.slots.at(-1)).toBe("ancestor");
    const item = (built.input.TransactItems as Record<string, any>[]).at(-1);
    expect(item?.ConditionCheck).toMatchObject({
      Key: { pk: "PKI_CA#ca-root-one", sk: "PROFILE" },
      ConditionExpression: "#status <> :revoked",
    });
  });

  it("uses only placeholders, bare pk and DynamoDB functions in expressions", () => {
    for (const commit of [
      consumerCommit(),
      consumerCommit({ agentGrant: undefined }),
      adminCommit({ ancestors: ["ca-root-one"] }),
    ]) {
      const built = buildIssuanceCommit("control", commit);
      for (const expression of expressionsOf(
        built.input.TransactItems as unknown[],
      )) {
        for (const token of tokens(expression)) {
          expect(token).toMatch(allowed);
        }
      }
    }
  });

  it("derives a deterministic token of at most 36 characters per generation", () => {
    const token = (generation?: number): string =>
      buildIssuanceCommit("control", consumerCommit(), generation).input
        .ClientRequestToken as string;
    expect(token()).toHaveLength(36);
    expect(token()).toBe(token(0));
    expect(token(1)).not.toBe(token(0));
    expect(token(2)).not.toBe(token(1));
    expect(
      buildIssuanceCommit(
        "control",
        consumerCommit({ idempotencyKey: "idempotency-key-9" }),
      ).input.ClientRequestToken,
    ).not.toBe(token());
    // Generations change only the token.
    expect(
      buildIssuanceCommit("control", consumerCommit(), 3).input.TransactItems,
    ).toEqual(
      buildIssuanceCommit("control", consumerCommit(), 0).input.TransactItems,
    );
  });

  it("throws on invariant violations", () => {
    const build = (commit: IssuanceCommit) => () =>
      buildIssuanceCommit("control", commit);
    const base = consumerCommit();
    expect(build({ ...base, grant: { ...base.grant, perHour: 0 } })).toThrow();
    expect(build({ ...base, grant: { ...base.grant, perDay: 1.5 } })).toThrow();
    expect(
      build({ ...base, ca: { ...base.ca, issuancePerHour: 0 } }),
    ).toThrow();
    expect(build(adminCommit({ adminPerHour: 0 }))).toThrow();
    expect(
      build({ ...base, grant: { ...base.grant, uid: "uid#bad" } }),
    ).toThrow();
    expect(
      build({
        ...base,
        certificate: { ...base.certificate, status: "REVOKED" },
      }),
    ).toThrow();
    expect(
      build({
        ...base,
        certificate: { ...base.certificate, caId: "ca-other-one" },
      }),
    ).toThrow();
    expect(
      build({
        ...base,
        certificate: { ...base.certificate, notAfter: "2026-12-22" },
      }),
    ).toThrow();
    expect(
      build({ ...base, certificate: { ...base.certificate, serial: "zz" } }),
    ).toThrow();
    expect(build({ ...base, consumerId: "someone-else" })).toThrow();
    expect(
      build({
        ...base,
        agentGrant: {
          grantId: "grant-12345678-1234-1234-1234-123456789012",
          environment: "staging",
        },
      }),
    ).toThrow();
    expect(
      build(adminCommit({ actor: { type: "consumer", id: "admin-1" } })),
    ).toThrow();
    expect(
      build(adminCommit({ actor: { type: "human", id: "someone-else" } })),
    ).toThrow();
    expect(
      build(
        adminCommit({
          ancestors: Array.from({ length: 100 }, (_, i) => `ca-anc-${i + 100}`),
        }),
      ),
    ).toThrow();
  });
});

describe("classifyIssuanceCancellation", () => {
  const commit = consumerCommit();
  const built = buildIssuanceCommit("control", commit);
  const cancel = (failures: Record<string, string>, fill = "None") => ({
    name: "TransactionCanceledException",
    CancellationReasons: built.slots.map((slot) => ({
      Code: failures[slot] ?? fill,
    })),
  });
  const classify = (error: unknown) =>
    classifyIssuanceCancellation(built, commit, error);
  const ccf = "ConditionalCheckFailed";

  it("row 1: missing or mismatched reasons are unclassified", () => {
    expect(classify({ name: "TransactionCanceledException" })).toEqual({
      kind: "unclassified",
    });
    expect(classify({ CancellationReasons: [{ Code: "None" }] })).toEqual({
      kind: "unclassified",
    });
  });

  it("row 2: a replay failure is replayExists", () => {
    expect(classify(cancel({ replay: ccf }))).toEqual({ kind: "replayExists" });
  });

  it("row 3: precondition failures list their slots", () => {
    expect(classify(cancel({ grant: ccf, identity: ccf }))).toEqual({
      kind: "preconditionFailed",
      slots: ["grant", "identity"],
    });
  });

  it("row 4: quota failures carry a retry-after", () => {
    const hour = classify(cancel({ grantHour: ccf, caHour: ccf }));
    expect(hour).toEqual({
      kind: "quotaExhausted",
      quotas: ["grantHour", "caHour"],
      retryAfterSeconds: 1800,
    });
    const day = classify(cancel({ grantDay: ccf }));
    expect(day).toMatchObject({
      kind: "quotaExhausted",
      retryAfterSeconds: Math.ceil(
        (quotaWindows(now).dayEnd.getTime() - now.getTime()) / 1000,
      ),
    });
    const both = classify(cancel({ grantHour: ccf, grantDay: ccf }));
    expect(both).toMatchObject({
      retryAfterSeconds: Math.ceil(
        (quotaWindows(now).dayEnd.getTime() - now.getTime()) / 1000,
      ),
    });
  });

  it("clamps the retry-after to at least one second", () => {
    const edge = consumerCommit({ now: new Date("2026-11-22T10:59:59.999Z") });
    const builtEdge = buildIssuanceCommit("control", edge);
    const result = classifyIssuanceCancellation(builtEdge, edge, {
      CancellationReasons: builtEdge.slots.map((slot) => ({
        Code: slot === "grantHour" ? ccf : "None",
      })),
    });
    expect(result).toMatchObject({ retryAfterSeconds: 1 });
  });

  it("row 5: a certificate or pointer collision is serialCollision", () => {
    expect(classify(cancel({ certificate: ccf }))).toEqual({
      kind: "serialCollision",
    });
    expect(classify(cancel({ consumerPointer: ccf }))).toEqual({
      kind: "serialCollision",
    });
  });

  it("row 6: only transient codes retry", () => {
    for (const code of [
      "TransactionConflict",
      "ThrottlingError",
      "ProvisionedThroughputExceeded",
      "RequestLimitExceeded",
    ]) {
      expect(classify(cancel({ certificate: code }))).toEqual({
        kind: "retry",
      });
    }
  });

  it("row 7: any other code throws a 503 and logs codes only", () => {
    const log = jest.spyOn(console, "error").mockImplementation();
    expect(() => classify(cancel({ ca: "ValidationError" }))).toThrow(
      expect.objectContaining({ statusCode: 503 }),
    );
    expect(() =>
      classify(
        cancel({
          certificate: "TransactionConflict",
          ca: "ItemCollectionSizeLimitExceeded",
        }),
      ),
    ).toThrow(expect.objectContaining({ statusCode: 503 }));
    expect(JSON.stringify(log.mock.calls)).not.toContain("PEM");
    log.mockRestore();
  });

  it("applies the precedence between rows", () => {
    expect(
      classify(cancel({ replay: ccf, grant: ccf, grantHour: ccf })),
    ).toEqual({
      kind: "replayExists",
    });
    expect(classify(cancel({ grant: ccf, grantHour: ccf }))).toMatchObject({
      kind: "preconditionFailed",
    });
    expect(
      classify(cancel({ grantHour: ccf, certificate: ccf })),
    ).toMatchObject({
      kind: "quotaExhausted",
    });
    expect(
      classify(cancel({ certificate: ccf, caHour: "TransactionConflict" })),
    ).toEqual({ kind: "serialCollision" });
  });
});

describe("PkiRepository", () => {
  const named = (name: string, extra: Record<string, unknown> = {}) =>
    Object.assign(new Error(name), { name, ...extra });
  const canceled = (code: string) =>
    named("TransactionCanceledException", {
      CancellationReasons: buildIssuanceCommit(
        "control",
        consumerCommit(),
      ).slots.map((slot) => ({ Code: slot === "replay" ? code : "None" })),
    });
  const conflict = () => {
    const slots = buildIssuanceCommit("control", consumerCommit()).slots;
    return named("TransactionCanceledException", {
      CancellationReasons: slots.map((slot) => ({
        Code: slot === "certificate" ? "TransactionConflict" : "None",
      })),
    });
  };
  const setup = (send: jest.Mock) => {
    const sleep = jest.fn(async () => undefined);
    const repository = new PkiRepository(
      { send } as unknown as DynamoDBDocumentClient,
      {
        tableName: "control",
        directoryIndex: "pki-directory",
        sleep,
        random: () => 0,
      },
    );
    return { repository, sleep };
  };
  const tokenOf = (call: unknown[]): string =>
    (call[0] as { input: { ClientRequestToken: string } }).input
      .ClientRequestToken;
  const inputOf = (call: unknown[]) => (call[0] as { input: unknown }).input;

  it("commits on the first attempt", async () => {
    const send = jest.fn().mockResolvedValue({});
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "committed",
    });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("retries conflicts with a new generation token and nothing else changed", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(conflict())
      .mockRejectedValueOnce(conflict())
      .mockResolvedValueOnce({});
    const { repository, sleep } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "committed",
    });
    expect(send).toHaveBeenCalledTimes(3);
    const expected = [0, 1, 2].map(
      (generation) =>
        buildIssuanceCommit("control", consumerCommit(), generation).input,
    );
    send.mock.calls.forEach((call, index) => {
      expect(inputOf(call)).toEqual(expected[index]);
    });
    expect(new Set(send.mock.calls.map(tokenOf)).size).toBe(3);
    expect(sleep).toHaveBeenCalledTimes(2);
  });

  it("gives up after three conflict retries", async () => {
    const send = jest.fn().mockRejectedValue(conflict());
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "conflict",
    });
    expect(send).toHaveBeenCalledTimes(4);
  });

  it("resends an identical input with the same token after an ambiguous error", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(named("TimeoutError"))
      .mockResolvedValueOnce({});
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "committed",
      ambiguous: true,
    });
    expect(inputOf(send.mock.calls[1] as unknown[])).toBe(
      inputOf(send.mock.calls[0] as unknown[]),
    );
    expect(tokenOf(send.mock.calls[0] as unknown[])).toBe(
      tokenOf(send.mock.calls[1] as unknown[]),
    );
  });

  it("reports ambiguous after a second ambiguous error", async () => {
    const send = jest.fn().mockRejectedValue(named("TimeoutError"));
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "ambiguous",
    });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("treats TransactionInProgress as ambiguous and retries", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(named("TransactionInProgressException"))
      .mockResolvedValueOnce({});
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "committed",
      ambiguous: true,
    });
  });

  it("classifies a replay cancellation after an ambiguous attempt", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(named("TimeoutError"))
      .mockRejectedValueOnce(canceled("ConditionalCheckFailed"));
    const { repository } = setup(send);
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "replayExists",
    });
  });

  it.each([
    "AccessDeniedException",
    "IdempotentParameterMismatchException",
    "ValidationException",
    "ResourceNotFoundException",
    "UnrecognizedClientException",
  ])("%s is a 503", async (name) => {
    const log = jest.spyOn(console, "error").mockImplementation();
    const send = jest.fn().mockRejectedValue(named(name));
    const { repository } = setup(send);
    await expect(
      repository.commitIssuance(consumerCommit()),
    ).rejects.toMatchObject({
      statusCode: 503,
    });
    expect(send).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith("PKI issuance commit failed", { name });
    log.mockRestore();
  });

  it("queries the directory index for any CA, ignoring non-PKI items", async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        Items: [{ pk: "WORKFLOW#x" }],
        LastEvaluatedKey: { pk: "a" },
      })
      .mockResolvedValueOnce({ Items: [{ pk: "PKI_CA#ca-prod-one" }] })
      .mockResolvedValueOnce({ Items: [{ pk: "IDENTITY#x" }] });
    const { repository } = setup(send);
    await expect(repository.hasAnyCa()).resolves.toBe(true);
    await expect(repository.hasAnyCa()).resolves.toBe(false);
    expect(inputOf(send.mock.calls[0] as unknown[])).toEqual({
      TableName: "control",
      IndexName: "pki-directory",
      KeyConditionExpression: "#pk = :pk",
      ExpressionAttributeNames: { "#pk": "pkiDirectoryPk" },
      ExpressionAttributeValues: { ":pk": "PKI_CAS" },
      Limit: 1,
    });
    expect(inputOf(send.mock.calls[1] as unknown[])).toMatchObject({
      ExclusiveStartKey: { pk: "a" },
      Limit: 1,
    });
  });

  it("reports a backfilling index as not ready", async () => {
    const send = jest.fn().mockRejectedValue(
      named("ValidationException", {
        message: "Cannot read from backfilling global secondary index: pki-directory",
      }),
    );
    const { repository } = setup(send);
    await expect(repository.hasAnyCa()).rejects.toBeInstanceOf(
      PkiIndexNotReadyError,
    );
    send.mockRejectedValue(named("ValidationException", { message: "other" }));
    await expect(repository.hasAnyCa()).rejects.not.toBeInstanceOf(
      PkiIndexNotReadyError,
    );
  });

  it("reads the replay record strongly and rejects malformed data", async () => {
    const item = {
      requestDigest: "d",
      caId: "ca-prod-one",
      serial,
      notAfter,
      grantUid: "uid-1234",
      ttl: 1,
    };
    const send = jest
      .fn()
      .mockResolvedValueOnce({ Item: item })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Item: { requestDigest: 1 } });
    const { repository } = setup(send);
    await expect(
      repository.getReplayRecord("payments-agent", "idempotency-key-1"),
    ).resolves.toEqual({
      requestDigest: "d",
      caId: "ca-prod-one",
      serial,
      notAfter,
      grantUid: "uid-1234",
    });
    expect(inputOf(send.mock.calls[0] as unknown[])).toMatchObject({
      Key: pkiKeys.replay("payments-agent", "idempotency-key-1"),
      ConsistentRead: true,
    });
    await expect(
      repository.getReplayRecord("payments-agent", "idempotency-key-1"),
    ).resolves.toBeUndefined();
    await expect(
      repository.getReplayRecord("payments-agent", "idempotency-key-1"),
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it("reads quota counts strongly, defaulting to zero", async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Item: { count: 7 } })
      .mockResolvedValueOnce({ Item: { count: "x" } });
    const { repository } = setup(send);
    const key = pkiKeys.caQuota("ca-prod-one", "HOUR#2026112210");
    await expect(repository.getQuotaCount(key)).resolves.toBe(0);
    await expect(repository.getQuotaCount(key)).resolves.toBe(7);
    await expect(repository.getQuotaCount(key)).rejects.toMatchObject({
      statusCode: 503,
    });
    expect(inputOf(send.mock.calls[0] as unknown[])).toMatchObject({
      ConsistentRead: true,
    });
  });
});

// ---------------------------------------------------------------------------
// Phase 4 builders and reads
// ---------------------------------------------------------------------------

const actor = { type: "human" as const, id: "admin-1" };
const idempotency = {
  actor,
  idempotencyKey: "idempotency-key-3",
  operationType: "pki.grant.create",
  requestDigest: "d".repeat(64),
  result: { consumerId: "payments", name: "web" },
  now: now.toISOString(),
};
const grant = (overrides: Partial<IssuanceGrantRecord> = {}): IssuanceGrantRecord => ({
  uid: "pkg-1234",
  consumerId: "payments",
  environment: "prod",
  name: "web",
  caId: "ca-prod-one",
  status: "ACTIVE",
  policy: { names: {}, keyUsages: [], extendedKeyUsages: { allow: [], default: [] }, lifetime: { defaultSeconds: 1, maxSeconds: 2 } },
  policyDigest: "p".repeat(64),
  version: "pkv-1",
  createdAt: now.toISOString(),
  createdBy: actor,
  updatedAt: now.toISOString(),
  updatedBy: actor,
  ...overrides,
});

describe("grant transactions", () => {
  it("creates a grant over nothing or a tombstone, guarded by the CA version", () => {
    const items = buildCreateGrantTransaction("control", {
      idempotency,
      grant: grant({ displayName: "Web" }),
      caVersion: "cv-1",
    });
    expect(items.map((item) => item.slot)).toEqual(["idempotency", "grant", "ca"]);
    expect(items[1]!.item.Put).toMatchObject({
      Item: {
        pk: "PKI_GRANT#payments",
        sk: "NAME#web",
        pkiDirectoryPk: "PKI_CA_GRANTS#ca-prod-one",
        pkiDirectorySk: "payments#web",
        uid: "pkg-1234",
        displayName: "Web",
      },
      ConditionExpression: "attribute_not_exists(pk) OR #status = :deleted",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: { ":deleted": "DELETED" },
    });
    expect(items[2]!.item.ConditionCheck).toMatchObject({
      Key: pkiKeys.caProfile("ca-prod-one"),
      ConditionExpression: "#status = :active AND #version = :v",
      ExpressionAttributeValues: { ":active": "ACTIVE", ":v": "cv-1" },
    });
  });

  it("updates under If-Match with the uid and removes absent optionals", () => {
    const items = buildUpdateGrantTransaction("control", {
      idempotency,
      grant: grant({ version: "pkv-2" }),
      ifMatch: "pkv-1",
      caVersion: "cv-1",
    });
    const update = items[1]!.item.Update!;
    expect(update.UpdateExpression).toMatch(/^SET .*#caId = :caId.*#pkiDirectoryPk = :pkiDirectoryPk.* REMOVE #displayName, #expiresAt$/);
    expect(update.ConditionExpression).toBe(
      "#version = :ifMatch AND #uid = :uid AND #deletedStatus <> :deleted",
    );
    expect(update.ExpressionAttributeValues).toMatchObject({
      ":ifMatch": "pkv-1",
      ":uid": "pkg-1234",
      ":version": "pkv-2",
    });
    const withBoth = buildUpdateGrantTransaction("control", {
      idempotency,
      grant: grant({ displayName: "x", expiresAt: "2999-01-01T00:00:00.000Z" }),
      ifMatch: "pkv-1",
      caVersion: "cv-1",
    })[1]!.item.Update!;
    expect(withBoth.UpdateExpression).not.toContain("REMOVE");
    expect(withBoth.UpdateExpression).toContain("#displayName = :displayName");
  });

  it("tombstones a grant and removes its directory attributes", () => {
    const update = buildDeleteGrantTransaction("control", {
      idempotency,
      consumerId: "payments",
      name: "web",
      ifMatch: "pkv-1",
      newVersion: "pkv-3",
      now: now.toISOString(),
      actor,
    })[1]!.item.Update!;
    expect(update.UpdateExpression).toBe(
      "SET #status = :deleted, #version = :v, #deletedAt = :now, #deletedBy = :actor, #updatedAt = :now, #updatedBy = :actor REMOVE #pkiDirectoryPk, #pkiDirectorySk",
    );
    expect(update.ConditionExpression).toBe("#version = :ifMatch AND #status <> :deleted");
  });
});

/** DynamoDB rejects an expression attribute name or value that no expression references. */
const expectNoUnusedPlaceholders = (
  items: readonly { item: { [kind: string]: unknown } }[],
): void => {
  for (const { item } of items) {
    const op = (item.Update ?? item.Put ?? item.ConditionCheck ?? item.Delete) as Record<string, unknown>;
    const text = [op.UpdateExpression, op.ConditionExpression].filter(Boolean).join(" ");
    for (const name of Object.keys((op.ExpressionAttributeNames ?? {}) as object)) {
      expect({ name, used: new RegExp(`${name}(?![A-Za-z0-9_])`).test(text) }).toEqual({ name, used: true });
    }
    for (const value of Object.keys((op.ExpressionAttributeValues ?? {}) as object)) {
      expect({ value, used: new RegExp(`${value}(?![A-Za-z0-9_])`).test(text) }).toEqual({ value, used: true });
    }
  }
};

describe("unused expression placeholders", () => {
  const base = {
    idempotency,
    caId: "ca-prod-one",
    serial: "0a1b",
    notAfter,
    now: now.toISOString(),
    reason: "keyCompromise" as const,
    invalidityDate: "2026-11-01T00:00:00.000Z",
    by: actor,
  };

  it.each([
    ["entry", { mode: "entry" as const }],
    ["expired inventory", { mode: "inventory" as const, expired: true }],
    ["revoked-CA inventory", { mode: "inventory" as const, expired: false }],
    ["upgrade without an entry", { mode: "upgrade" as const, entryLive: false }],
    ["upgrade with an entry", { mode: "upgrade" as const, entryLive: true }],
  ])("revoke %s binds only what it uses", (_label, extra) => {
    expectNoUnusedPlaceholders(buildRevokeTransaction("control", { ...base, ...extra }));
  });

  it("bulk batches, with and without entries, and grant builders bind only what they use", () => {
    for (const withEntries of [true, false]) {
      expectNoUnusedPlaceholders(
        buildBulkRevokeBatch("control", {
          caId: "ca-prod-one",
          items: [{ serial: "0a1b", notAfter }],
          withEntries,
          now: now.toISOString(),
          actor,
          reason: "superseded",
        }),
      );
    }
    expectNoUnusedPlaceholders(buildCreateGrantTransaction("control", { idempotency, grant: grant(), caVersion: "cv" }));
    expectNoUnusedPlaceholders(
      buildUpdateGrantTransaction("control", { idempotency, grant: grant({ displayName: "x" }), ifMatch: "v", caVersion: "cv" }),
    );
    expectNoUnusedPlaceholders(
      buildDeleteGrantTransaction("control", {
        idempotency, consumerId: "payments", name: "web", ifMatch: "v", newVersion: "n", now: now.toISOString(), actor,
      }),
    );
  });

  it("the revoked-CA inventory update carries no #notAfter or :now", () => {
    const update = buildRevokeTransaction("control", { ...base, mode: "inventory", expired: false })[1]!.item.Update!;
    expect(update.ExpressionAttributeNames).not.toHaveProperty("#notAfter");
    expect(update.ExpressionAttributeValues).not.toHaveProperty(":now");
  });
});

describe("ambiguous issuance commits", () => {
  it("flags a commit that succeeded after an ambiguous send", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(Object.assign(new Error("timeout"), { name: "TimeoutError" }))
      .mockResolvedValueOnce({});
    const repository = new PkiRepository({ send } as unknown as DynamoDBDocumentClient, {
      tableName: "control",
      directoryIndex: "pki-directory",
      sleep: async () => undefined,
      random: () => 0,
    });
    await expect(repository.commitIssuance(consumerCommit())).resolves.toEqual({
      kind: "committed",
      ambiguous: true,
    });
  });
});

describe("revoke transactions", () => {
  const base = {
    idempotency: { ...idempotency, operationType: "pki.certificate.revoke" },
    caId: "ca-prod-one",
    serial: "0a1b",
    notAfter,
    now: now.toISOString(),
    reason: "keyCompromise" as const,
    invalidityDate: "2026-11-01T00:00:00.000Z",
    by: actor,
  };

  it("entry mode: certificate, entry and CRL revision in one transaction", () => {
    const items = buildRevokeTransaction("control", { ...base, mode: "entry" });
    expect(items.map((item) => item.slot)).toEqual(["idempotency", "certificate", "entry", "crl"]);
    expect(items[1]!.item.Update).toMatchObject({
      Key: pkiKeys.certificate("ca-prod-one", "0a1b"),
      UpdateExpression: "SET #status = :revoked, #revocation = :rev",
      ConditionExpression: "#status = :issued AND #notAfter > :now",
      ExpressionAttributeValues: {
        ":rev": { at: now.toISOString(), reason: "keyCompromise", invalidityDate: "2026-11-01T00:00:00.000Z", by: actor },
      },
    });
    // The entry has exactly Phase 3's RevocationEntryRecord keys, and no TTL.
    expect(Object.keys(items[2]!.item.Put!.Item!).sort()).toEqual(
      ["caId", "invalidityDate", "notAfter", "pk", "reason", "revokedAt", "serial", "sk"],
    );
    expect(items[2]!.item.Put).toMatchObject({
      Item: { pk: "PKI_CA#ca-prod-one", sk: "REVOKED#0a1b", revokedAt: now.toISOString() },
      ConditionExpression: "attribute_not_exists(pk)",
    });
    expect(items[3]!.item.Update).toMatchObject({
      Key: pkiKeys.caCrl("ca-prod-one"),
      UpdateExpression: "SET #revision = #revision + :one, #dirtySince = if_not_exists(#dirtySince, :now)",
      ConditionExpression: "attribute_exists(pk)",
    });
  });

  it("inventory mode touches only the certificate", () => {
    const expired = buildRevokeTransaction("control", { ...base, mode: "inventory", expired: true });
    expect(expired.map((item) => item.slot)).toEqual(["idempotency", "certificate"]);
    expect(expired[1]!.item.Update!.ConditionExpression).toBe("#status = :issued AND #notAfter <= :now");
    const revokedCa = buildRevokeTransaction("control", { ...base, mode: "inventory", expired: false });
    expect(revokedCa[1]!.item.Update!.ConditionExpression).toBe("#status = :issued");
  });

  it("upgrade mode edits the reason, and the entry and revision only when the entry is live", () => {
    const certificateOnly = buildRevokeTransaction("control", { ...base, mode: "upgrade", entryLive: false });
    expect(certificateOnly.map((item) => item.slot)).toEqual(["idempotency", "certificate"]);
    expect(certificateOnly[1]!.item.Update).toMatchObject({
      UpdateExpression:
        "SET #revocation.#reason = :kc, #revocation.#upgradedAt = :now, #revocation.#invalidityDate = :inv",
      ConditionExpression: "#status = :revoked AND #revocation.#reason <> :kc",
    });
    const live = buildRevokeTransaction("control", { ...base, mode: "upgrade", entryLive: true });
    expect(live.map((item) => item.slot)).toEqual(["idempotency", "certificate", "entry", "crl"]);
    expect(live[2]!.item.Update).toMatchObject({
      ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(#ttl)",
    });
  });

  it("builds a bulk batch of at most 30 certificates and no idempotency slot", () => {
    const items = Array.from({ length: 30 }, (_, i) => ({
      serial: (i + 1).toString(16).padStart(4, "0"),
      notAfter,
    }));
    const batch = buildBulkRevokeBatch("control", {
      caId: "ca-prod-one",
      items,
      withEntries: true,
      now: now.toISOString(),
      actor,
      reason: "superseded",
    });
    expect(batch).toHaveLength(61);
    expect(batch[0]!.slot).toBe("cert:0001");
    expect(batch[30]!.slot).toBe("entry:0001");
    expect(batch[60]!.slot).toBe("crl");
    expect(
      buildBulkRevokeBatch("control", {
        caId: "ca-prod-one",
        items: items.slice(0, 2),
        withEntries: false,
        now: now.toISOString(),
        actor,
        reason: "superseded",
      }).map((item) => item.slot),
    ).toEqual(["cert:0001", "cert:0002"]);
    expect(() =>
      buildBulkRevokeBatch("control", {
        caId: "ca-prod-one",
        items: [...items, { serial: "ffff", notAfter }],
        withEntries: true,
        now: now.toISOString(),
        actor,
        reason: "superseded",
      }),
    ).toThrow();
  });
});

describe("quotaRetryAfterSeconds", () => {
  it("uses the hour end for hour slots and the day end for the day slot", () => {
    expect(quotaRetryAfterSeconds(["grantHour"], now)).toBe(1800);
    expect(quotaRetryAfterSeconds(["grantHour", "grantDay"], now)).toBe(13.5 * 3600);
    expect(quotaRetryAfterSeconds(["caHour", "adminHour"], new Date("2026-11-22T10:59:59.999Z"))).toBe(1);
  });
});

describe("Phase 4 repository reads and writes", () => {
  const setupPhase4 = (send: jest.Mock) =>
    new PkiRepository({ send } as unknown as DynamoDBDocumentClient, {
      tableName: "control",
      directoryIndex: "pki-directory",
      sleep: async () => undefined,
      random: () => 0,
    });
  const inputs = (send: jest.Mock) =>
    send.mock.calls.map((call) => (call[0] as { input: Record<string, unknown> }).input);

  it("sums Count over every page for the certificate count", async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({ Count: 5, LastEvaluatedKey: { pk: "a" } })
      .mockResolvedValueOnce({ Count: 7 });
    await expect(
      setupPhase4(send).countCertificatesSince("ca-prod-one", "2026-11-22T00:00:00.000Z"),
    ).resolves.toBe(12);
    expect(inputs(send)[0]).toMatchObject({
      IndexName: "pki-directory",
      Select: "COUNT",
      KeyConditionExpression: "#pk = :pk AND #sk > :from",
      ExpressionAttributeValues: { ":pk": "PKI_CERTS#ca-prod-one", ":from": "2026-11-22T00:00:00.000Z" },
    });
    expect(inputs(send)[1]).toMatchObject({ ExclusiveStartKey: { pk: "a" } });
  });

  it("maps a backfilling index to PkiIndexNotReadyError on a count", async () => {
    const send = jest.fn().mockRejectedValue(
      Object.assign(new Error("index is backfilling"), { name: "ValidationException" }),
    );
    await expect(
      setupPhase4(send).countCertificatesSince("ca-prod-one", "2026-11-22T00:00:00.000Z"),
    ).rejects.toBeInstanceOf(PkiIndexNotReadyError);
  });

  it("reports a backfilling index as a 503 with the index_not_ready reason", () => {
    expect(new PkiIndexNotReadyError()).toMatchObject({
      statusCode: 503,
      code: "service_unavailable",
      safeReason: "index_not_ready",
    });
  });

  it("stores a capacity count monotonically and releases only an owned lease", async () => {
    const send = jest.fn().mockResolvedValue({});
    const repository = setupPhase4(send);
    await repository.storeCapacityCount("ca-prod-one", {
      count: 3,
      countFrom: "2026-11-22T10:00:00.000Z",
      countedAt: now.toISOString(),
    });
    await repository.releaseCrlLease("ca-prod-one", "crl-owner");
    expect(inputs(send)[0]).toMatchObject({
      Key: pkiKeys.caCrl("ca-prod-one"),
      UpdateExpression: "SET #capacity = :c",
      ConditionExpression:
        "attribute_exists(pk) AND (attribute_not_exists(#capacity) OR #capacity.#countedAt <= :at)",
    });
    expect(inputs(send)[1]).toMatchObject({
      UpdateExpression: "REMOVE #lease",
      ConditionExpression: "#lease.#owner = :owner",
      ExpressionAttributeValues: { ":owner": "crl-owner" },
    });
    send.mockRejectedValueOnce(Object.assign(new Error("x"), { name: "ConditionalCheckFailedException" }));
    await expect(repository.releaseCrlLease("ca-prod-one", "other")).resolves.toBeUndefined();
  });

  it("reads grants strongly and filters tombstones unless asked", async () => {
    const send = jest.fn().mockResolvedValue({ Items: [{ pk: "PKI_GRANT#payments", sk: "NAME#web", ...grant() }] });
    const repository = setupPhase4(send);
    await repository.listGrantsPage("payments", { includeDeleted: false, limit: 100 });
    await repository.listGrantsPage("payments", { includeDeleted: true, limit: 100 });
    expect(inputs(send)[0]).toMatchObject({
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      FilterExpression: "#status <> :deleted",
      ConsistentRead: true,
    });
    expect(inputs(send)[1]!.FilterExpression).toBeUndefined();
    send.mockResolvedValueOnce({ Item: { pk: "x", sk: "y", uid: "pkg-1" } });
    await expect(repository.getGrant("payments", "web")).rejects.toMatchObject({ statusCode: 503 });
  });

  it("queries certificates with range bounds and a status filter", async () => {
    const send = jest.fn().mockResolvedValue({ Items: [] });
    await setupPhase4(send).queryCertificatesPage("ca-prod-one", {
      after: "2026-11-22T00:00:00.000Z",
      before: "2026-12-22T00:00:00.000Z",
      status: "ISSUED",
      limit: 100,
    });
    expect(inputs(send)[0]).toMatchObject({
      IndexName: "pki-directory",
      KeyConditionExpression: "#pk = :pk AND #sk BETWEEN :after AND :before",
      FilterExpression: "#status = :s",
    });
  });

  it("lists consumer pointers newest first with its filters", async () => {
    const send = jest.fn().mockResolvedValue({ Items: [] });
    await setupPhase4(send).listConsumerPointersPage("payments", {
      notAfterAfter: "2026-11-22T00:00:00.000Z",
      grantName: "web",
      newestFirst: true,
      limit: 50,
    });
    expect(inputs(send)[0]).toMatchObject({
      ScanIndexForward: false,
      ConsistentRead: true,
      FilterExpression: "#notAfter > :notAfter AND #issuanceGrant = :grantName",
    });
  });

  it("keeps the consumer issuance commit's slots unchanged", () => {
    expect(buildIssuanceCommit("control", consumerCommit()).slots).toEqual([
      "replay",
      "certificate",
      "consumerPointer",
      "grantHour",
      "grantDay",
      "caHour",
      "grant",
      "ca",
      "identity",
      "agentGrant",
    ]);
    expect(buildIssuanceCommit("control", adminCommit()).slots).toEqual([
      "replay",
      "certificate",
      "adminHour",
      "caHour",
      "ca",
    ]);
  });
});
