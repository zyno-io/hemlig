import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type {
  CaCrlState,
  CaRecord,
  IssuanceGrantRecord,
  IssuedCertificateRecord,
} from "../pki/types";
import {
  buildBulkRevokeBatch,
  buildCreateCaTransaction,
  buildCreateGrantTransaction,
  buildCreateIntermediateTransaction,
  buildDistrustRootTransaction,
  buildRevokeForRevokedAncestorUpdate,
  buildRevokeIntermediateTransaction,
  buildUpdateCaPolicyTransaction,
  issuedCertificatePutItem,
  quotaIncrementItem,
  type CreateIntermediateTransaction,
  type NamedItem,
  type RevokeIntermediateTransaction,
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

  it("compares the grant and identity expiry to the post-signing clock", () => {
    const commitNow = new Date(now.getTime() + 5000);
    const built = buildIssuanceCommit(
      "control",
      consumerCommit({ commitNow }),
    );
    const checks = (
      built.input.TransactItems as {
        ConditionCheck?: {
          Key: { pk: string };
          ExpressionAttributeValues: Record<string, unknown>;
        };
      }[]
    ).filter((item) => item.ConditionCheck !== undefined);
    const withNow = checks.filter(
      (item) => item.ConditionCheck!.ExpressionAttributeValues[":now"] !== undefined,
    );
    expect(withNow).toHaveLength(2);
    for (const item of withNow) {
      expect(item.ConditionCheck!.ExpressionAttributeValues[":now"]).toBe(
        commitNow.toISOString(),
      );
    }
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

  it("returns an empty page without querying when before <= after", async () => {
    const send = jest.fn();
    await expect(
      setupPhase4(send).queryCertificatesPage("ca-prod-one", {
        after: "2026-11-22T00:00:00.000Z",
        before: "2026-11-21T00:00:00.000Z",
        status: "ISSUED",
        limit: 100,
      }),
    ).resolves.toEqual({ certificates: [] });
    expect(send).not.toHaveBeenCalled();
  });

  describe("filtered reads against a Limit-then-filter stand-in", () => {
    const pointer = (i: number, live: boolean) => {
      const serial = i.toString(16).padStart(8, "0");
      const issued = live ? "2026-11-22T00:00:00.000Z" : "2026-08-01T00:00:00.000Z";
      return {
        pk: "PKI_CONSUMER#payments-prod",
        sk: `CERT#${issued}#ca-aaa#${serial}${live ? "" : ""}`,
        caId: "ca-aaa",
        serial,
        notAfter: live ? "2026-12-22T00:00:00.000Z" : "2026-08-02T00:00:00.000Z",
        issuedAt: issued,
      };
    };
    // Applies Limit (when sent) before the filter, and caps a page at 1000 evaluated items to stand in for 1 MB.
    const standIn = (items: Record<string, unknown>[]) => {
      const calls: Record<string, any>[] = [];
      const client = {
        send: async (command: { input: Record<string, any> }) => {
          const input = command.input;
          calls.push(input);
          const start = input.ExclusiveStartKey === undefined ? 0 : items.findIndex((item) => item.sk === input.ExclusiveStartKey.sk) + 1;
          const evaluated = items.slice(start, start + Math.min(input.Limit ?? 1000, 1000));
          const after = input.ExpressionAttributeValues[":notAfter"] as string;
          const matched = evaluated.filter((item) => (item.notAfter as string) > after);
          const last = start + evaluated.length - 1;
          return {
            Items: matched,
            ...(last < items.length - 1 ? { LastEvaluatedKey: { pk: items[last]!.pk, sk: items[last]!.sk } } : {}),
          };
        },
      };
      return { calls, client };
    };
    const repo = (client: unknown) =>
      new PkiRepository(client as never, { tableName: "t", directoryIndex: "pki-directory" } as never);
    const now = "2026-11-23T00:00:00.000Z";

    it("reaches 10 live pointers behind 50,000 expired ones in a few round trips", async () => {
      const expired = Array.from({ length: 50_000 }, (_, i) => pointer(i + 16, false));
      const live = Array.from({ length: 10 }, (_, i) => pointer(0xff000000 + i, true));
      const fake = standIn([...expired, ...live]);
      const page = await repo(fake.client).listConsumerPointersPage("payments-prod", {
        notAfterAfter: now,
        newestFirst: false,
        limit: 100,
      });
      expect(page.pointers).toHaveLength(10);
      expect(fake.calls.length).toBeLessThanOrEqual(60);
      expect(fake.calls.every((call) => call.Limit === undefined)).toBe(true);
    });

    it("resumes a truncated page with no skips or duplicates", async () => {
      const items = Array.from({ length: 25 }, (_, i) => pointer(i + 16, true));
      const fake = standIn(items);
      const seen: string[] = [];
      let start: Record<string, unknown> | undefined;
      do {
        const page = await repo(fake.client).listConsumerPointersPage("payments-prod", {
          notAfterAfter: now,
          newestFirst: false,
          limit: 10,
          ...(start === undefined ? {} : { start }),
        });
        expect(page.pointers.length).toBeLessThanOrEqual(10);
        seen.push(...page.pointers.map((p) => p.serial));
        start = page.lastEvaluatedKey;
      } while (start !== undefined);
      expect(seen).toEqual(items.map((item) => item.serial));
    });

    it("includes the index keys in a truncated cursor on an index query", async () => {
      const rows = Array.from({ length: 5 }, (_, i) => ({
        pk: `PKI_CERT#ca-prod-one#0${i}`,
        sk: "PROFILE",
        pkiDirectoryPk: "PKI_CERTS#ca-prod-one",
        pkiDirectorySk: `2026-12-0${i + 1}T00:00:00.000Z#0${i}`,
        status: "ISSUED",
      }));
      const send = jest.fn().mockResolvedValue({ Items: rows });
      const page = await (
        setupPhase4(send) as unknown as {
          queryLoop: (o: unknown) => Promise<{ lastEvaluatedKey?: unknown }>;
        }
      ).queryLoop({
        index: "pki-directory",
        key: { expression: "#pk = :pk", names: { "#pk": "pkiDirectoryPk" }, values: { ":pk": "x" } },
        filter: { expression: "#status = :s", names: { "#status": "status" }, values: { ":s": "ISSUED" } },
        limit: 2,
      });
      expect(page.lastEvaluatedKey).toEqual({
        pk: rows[1]!.pk,
        sk: "PROFILE",
        pkiDirectoryPk: rows[1]!.pkiDirectoryPk,
        pkiDirectorySk: rows[1]!.pkiDirectorySk,
      });
      expect(inputs(send)[0]!.Limit).toBeUndefined();
    });

    it("stops before another round trip when shouldStop is true, returning the cursor", async () => {
      const expired = Array.from({ length: 5_000 }, (_, i) => pointer(i + 16, false));
      const fake = standIn(expired);
      let trips = 0;
      const page = await repo(fake.client).listConsumerPointersPage("payments-prod", {
        notAfterAfter: now,
        newestFirst: false,
        limit: 100,
        shouldStop: () => (trips += 1) > 2,
      });
      expect(fake.calls).toHaveLength(3);
      expect(page.pointers).toEqual([]);
      expect(page.lastEvaluatedKey).toBeDefined();
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

describe("Phase 7 hierarchy transactions", () => {
  const caRecord = (overrides: Record<string, unknown> = {}): CaRecord =>
    ({
      caId: "ca-child-one",
      environment: "prod",
      name: "child-one",
      kind: "INTERMEDIATE",
      status: "ACTIVE",
      version: "pkv-child",
      parent: { type: "ca", id: "ca-root-one" },
      parentCaId: "ca-root-one",
      crlIssuers: [],
      key: { custody: "WRAPPED", algorithm: "ECDSA_P256", spkiSha256: "c".repeat(64), state: "ACTIVE" },
      subject: { CN: "Child" },
      subjectKey: "d".repeat(64),
      requested: { pathLen: 0 },
      policy: {},
      maxIssueLifetimeEverSeconds: 1,
      serial: "0a0b",
      createdAt: now.toISOString(),
      createdBy: actor,
      ...overrides,
    }) as unknown as CaRecord;
  const crl: CaCrlState = { revision: 0, lastNumber: 1, sweptThrough: now.toISOString() };
  const childRow = (overrides: Partial<IssuedCertificateRecord> = {}) =>
    certificate(
      { type: "human", id: "admin-1" },
      { caId: "ca-root-one", isCa: true, childCaId: "ca-child-one", serial: "0a0b", ...overrides },
    );
  const createInput = (parent: Partial<CreateIntermediateTransaction["parent"]> = {}): CreateIntermediateTransaction => ({
    idempotency,
    ca: caRecord(),
    crl,
    certificate: childRow(),
    parent: {
      caId: "ca-root-one",
      version: "pkv-root",
      issuancePerHour: 2000,
      loadedMaxIssueLifetimeEverSeconds: 0,
      childLifetimeSeconds: 31_536_000,
      ...parent,
    },
    now,
    adminPerHour: 100,
  });

  it("refactors the shared issuance items without changing them", () => {
    const built = buildIssuanceCommit("control", adminCommit());
    const cert = adminCommit().certificate;
    expect(built.input.TransactItems![1]).toEqual(issuedCertificatePutItem("control", cert));
    expect(built.input.TransactItems![2]).toEqual(
      quotaIncrementItem(
        "control",
        pkiKeys.adminQuota("ca-prod-one", quotaWindows(now).hourSk),
        100,
        pkiTtl.hourCounter(quotaWindows(now).hourStart),
      ),
    );
    expect(issuedCertificatePutItem("control", cert).Put!.Item).toMatchObject({
      ...pkiKeys.certificate("ca-prod-one", serial),
      ...pkiDirectory.certificate("ca-prod-one", notAfter, serial),
      ttl: pkiTtl.certificate(notAfter),
    });
  });

  it("buildCreateCaTransaction appends the CRL state only when given", () => {
    const without = buildCreateCaTransaction("control", { idempotency, ca: caRecord() });
    expect(without.map((item) => item.slot)).toEqual(["idempotency", "name", "subject", "profile"]);
    const withCrl = buildCreateCaTransaction("control", { idempotency, ca: caRecord(), crl });
    expect(withCrl.map((item) => item.slot)).toEqual(["idempotency", "name", "subject", "profile", "crl"]);
    expect(withCrl[4]!.item.Put).toMatchObject({
      Item: { ...pkiKeys.caCrl("ca-child-one"), revision: 0, lastNumber: 1 },
      ConditionExpression: "attribute_not_exists(pk)",
    });
  });

  describe("buildCreateIntermediateTransaction", () => {
    const base =
      "#status = :active AND #version = :version AND #key.#state = :active AND #policy.#issueSubordinates = :true";

    it("orders the nine slots and writes the parent's inventory row and counters", () => {
      const items = buildCreateIntermediateTransaction("control", createInput());
      expect(items.map((item) => item.slot)).toEqual([
        "idempotency", "name", "subject", "profile", "crl", "certificate", "adminHour", "caHour", "parent",
      ]);
      const windows = quotaWindows(now);
      expect(items[5]!.item.Put!.Item).toMatchObject({
        ...pkiKeys.certificate("ca-root-one", "0a0b"),
        ...pkiDirectory.certificate("ca-root-one", notAfter, "0a0b"),
        ttl: pkiTtl.certificate(notAfter),
        isCa: true,
        childCaId: "ca-child-one",
      });
      expect(items[6]!.item.Update).toMatchObject({
        Key: pkiKeys.adminQuota("ca-root-one", windows.hourSk),
        ExpressionAttributeValues: { ":limit": 100, ":ttl": pkiTtl.hourCounter(windows.hourStart) },
      });
      expect(items[7]!.item.Update).toMatchObject({
        Key: pkiKeys.caQuota("ca-root-one", windows.hourSk),
        ExpressionAttributeValues: { ":limit": 2000 },
      });
      expectNoUnusedPlaceholders(items);
    });

    it("guards the parent with a ConditionCheck when the lifetime does not grow", () => {
      for (const loaded of [31_536_000, 40_000_000]) {
        const parent = buildCreateIntermediateTransaction(
          "control",
          createInput({ loadedMaxIssueLifetimeEverSeconds: loaded }),
        )[8]!.item;
        expect(parent.Update).toBeUndefined();
        expect(parent.ConditionCheck).toMatchObject({
          Key: pkiKeys.caProfile("ca-root-one"),
          ConditionExpression: base,
          ExpressionAttributeValues: { ":active": "ACTIVE", ":version": "pkv-root", ":true": true },
        });
      }
    });

    it("raises the parent's maximum in place, without a version bump, when the lifetime grows", () => {
      const items = buildCreateIntermediateTransaction("control", createInput());
      const update = items[8]!.item.Update!;
      expect(update).toMatchObject({
        Key: pkiKeys.caProfile("ca-root-one"),
        UpdateExpression: "SET #max = :lifetime",
        ConditionExpression: `${base} AND #max <= :lifetime`,
        ExpressionAttributeNames: { "#max": "maxIssueLifetimeEverSeconds" },
        ExpressionAttributeValues: { ":lifetime": 31_536_000, ":version": "pkv-root" },
      });
      expect(update.UpdateExpression).not.toContain("#version");
      expectNoUnusedPlaceholders(items);
    });

    it("refuses an inconsistent input and a zero limit", () => {
      expect(() =>
        buildCreateIntermediateTransaction("control", { ...createInput(), certificate: childRow({ isCa: false }) }),
      ).toThrow();
      expect(() =>
        buildCreateIntermediateTransaction("control", { ...createInput(), certificate: childRow({ childCaId: "ca-other" }) }),
      ).toThrow();
      expect(() =>
        buildCreateIntermediateTransaction("control", { ...createInput(), certificate: childRow({ caId: "ca-other" }) }),
      ).toThrow();
      expect(() =>
        buildCreateIntermediateTransaction("control", { ...createInput(), ca: caRecord({ parentCaId: "ca-other" }) }),
      ).toThrow();
      expect(() => buildCreateIntermediateTransaction("control", { ...createInput(), adminPerHour: 0 })).toThrow();
      expect(() =>
        buildCreateIntermediateTransaction("control", createInput({ issuancePerHour: 0 })),
      ).toThrow();
    });
  });

  describe("createIntermediateCa outcomes", () => {
    const slots = buildCreateIntermediateTransaction("control", createInput()).map((item) => item.slot);
    const cancelWith = (failed: string[], other = "None") =>
      Object.assign(new Error("canceled"), {
        name: "TransactionCanceledException",
        CancellationReasons: slots.map((slot) => ({
          Code: failed.includes(slot) ? "ConditionalCheckFailed" : other,
        })),
      });
    const run = (error: unknown) => {
      const send = jest.fn().mockRejectedValue(error);
      const repository = new PkiRepository({ send } as unknown as DynamoDBDocumentClient, {
        tableName: "control",
        directoryIndex: "pki-directory",
        sleep: async () => undefined,
        random: () => 0,
      });
      return repository.createIntermediateCa(createInput());
    };

    it("commits", async () => {
      const send = jest.fn().mockResolvedValue({});
      const repository = new PkiRepository({ send } as unknown as DynamoDBDocumentClient, {
        tableName: "control",
        directoryIndex: "pki-directory",
      });
      await expect(repository.createIntermediateCa(createInput())).resolves.toEqual({ kind: "created" });
    });

    it.each([
      [["idempotency", "name"], { kind: "replay" }],
      [["name"], { kind: "nameInUse" }],
      [["subject"], { kind: "subjectInUse" }],
      [["parent"], { kind: "parentChanged" }],
      [["certificate"], { kind: "serialCollision" }],
    ])("maps a failed %j", async (failed, expected) => {
      await expect(run(cancelWith(failed))).resolves.toEqual(expected);
    });

    it("lists the exhausted counters with a retry time", async () => {
      await expect(run(cancelWith(["caHour"]))).resolves.toEqual({
        kind: "quotaExhausted",
        quotas: ["caHour"],
        retryAfterSeconds: 1800,
      });
      await expect(run(cancelWith(["adminHour", "caHour"]))).resolves.toMatchObject({
        quotas: ["adminHour", "caHour"],
      });
    });

    it("answers 503 for a profile or CRL collision and for an unknown cancellation", async () => {
      await expect(run(cancelWith(["profile"]))).rejects.toMatchObject({ statusCode: 503 });
      await expect(run(cancelWith(["crl"]))).rejects.toMatchObject({ statusCode: 503 });
      await expect(
        run(Object.assign(new Error("canceled"), { name: "TransactionCanceledException" })),
      ).rejects.toMatchObject({ statusCode: 503 });
    });
  });

  describe("buildRevokeIntermediateTransaction", () => {
    const revoke = (
      row: RevokeIntermediateTransaction["row"],
      ca: Partial<CaRecord> = {},
    ): NamedItem[] =>
      buildRevokeIntermediateTransaction("control", {
        idempotency,
        ca: caRecord(ca),
        newVersion: "pkv-new",
        now: now.toISOString(),
        reason: "caCompromise",
        invalidityDate: "2026-11-01T00:00:00.000Z",
        by: actor,
        evidence: "parent:ca-root-one",
        ...(row === undefined ? {} : { row }),
      });

    it("entry mode has five items and bumps the root's CRL revision", () => {
      const items = revoke({ mode: "entry", notAfter });
      expect(items.map((item) => item.slot)).toEqual(["idempotency", "profile", "certificate", "entry", "crl"]);
      expect(items[1]!.item.Update).toMatchObject({
        Key: pkiKeys.caProfile("ca-child-one"),
        UpdateExpression:
          "SET #status = :revoked, #revokedAt = :now, #revocationReason = :reason, #revocationSource = :hemlig, #revocationEvidence = :evidence, #version = :v, #key.#state = :disabled",
        ConditionExpression:
          "(#status = :active OR #status = :retired) AND #version = :loaded AND #kind = :intermediate AND #parentCaId = :parent",
        ExpressionAttributeValues: {
          ":hemlig": "HEMLIG",
          ":evidence": "parent:ca-root-one",
          ":loaded": "pkv-child",
          ":parent": "ca-root-one",
          ":disabled": "DISABLED",
        },
      });
      expect(items[2]!.item.Update).toMatchObject({
        Key: pkiKeys.certificate("ca-root-one", "0a0b"),
        ConditionExpression: "#status = :issued AND #notAfter > :now",
      });
      expect(items[3]!.item.Put).toMatchObject({
        Item: { pk: "PKI_CA#ca-root-one", sk: "REVOKED#0a0b", reason: "caCompromise", notAfter },
      });
      expect(items[4]!.item.Update).toMatchObject({ Key: pkiKeys.caCrl("ca-root-one") });
      expectNoUnusedPlaceholders(items);
    });

    it("conditions the revision bump on the revision that was read", () => {
      const items = buildRevokeIntermediateTransaction("control", {
        idempotency,
        ca: caRecord(),
        newVersion: "pkv-new",
        now: now.toISOString(),
        reason: "caCompromise",
        by: actor,
        evidence: "parent:ca-root-one",
        expectCrlRevision: 4,
        row: { mode: "entry", notAfter },
      });
      expect(items[4]!.item.Update).toMatchObject({
        ConditionExpression: "attribute_exists(pk) AND #revision = :expect",
        ExpressionAttributeValues: { ":expect": 4 },
      });
      expectNoUnusedPlaceholders(items);
      const leaf = buildRevokeTransaction("control", {
        idempotency,
        caId: "ca-prod-one",
        serial: "0a1b",
        notAfter,
        now: now.toISOString(),
        reason: "superseded",
        by: actor,
        mode: "entry",
        expectCrlRevision: 0,
      });
      expect(leaf[3]!.item.Update!.ExpressionAttributeValues).toMatchObject({ ":expect": 0 });
      expectNoUnusedPlaceholders(leaf);
    });

    it("expired mode has three items and no entry or revision bump", () => {
      const items = revoke({ mode: "expired", notAfter });
      expect(items.map((item) => item.slot)).toEqual(["idempotency", "profile", "certificate"]);
      expect(items[2]!.item.Update!.ConditionExpression).toBe("#status = :issued AND #notAfter <= :now");
      expectNoUnusedPlaceholders(items);
    });

    it("inventory mode has three items with the bare condition", () => {
      const items = revoke({ mode: "inventory", notAfter });
      expect(items.map((item) => item.slot)).toEqual(["idempotency", "profile", "certificate"]);
      expect(items[2]!.item.Update!.ConditionExpression).toBe("#status = :issued");
      expect(items[2]!.item.Update!.ExpressionAttributeNames).not.toHaveProperty("#notAfter");
      expect(items[2]!.item.Update!.ExpressionAttributeValues).not.toHaveProperty(":now");
      expectNoUnusedPlaceholders(items);
    });

    it("without a row has two items", () => {
      const items = revoke(undefined);
      expect(items.map((item) => item.slot)).toEqual(["idempotency", "profile"]);
      expectNoUnusedPlaceholders(items);
    });

    it("sets the key state only when the loaded key is ACTIVE", () => {
      const disabled = revoke({ mode: "entry", notAfter }, {
        key: { custody: "WRAPPED", algorithm: "ECDSA_P256", spkiSha256: "c", state: "DISABLED" },
      } as Partial<CaRecord>);
      const update = disabled[1]!.item.Update!;
      expect(update.UpdateExpression).not.toContain("#key");
      expect(update.ExpressionAttributeNames).not.toHaveProperty("#key");
      expect(update.ExpressionAttributeValues).not.toHaveProperty(":disabled");
      expectNoUnusedPlaceholders(disabled);
    });

    it("refuses a CA that is not a Hemlig intermediate", () => {
      expect(() => revoke(undefined, { parentCaId: undefined })).toThrow();
    });
  });

  describe("distrust and the ancestor flip", () => {
    const input = {
      idempotency,
      ca: caRecord({ kind: "ROOT", parentCaId: undefined }),
      newVersion: "pkv-new",
      now: now.toISOString(),
      reason: "caCompromise" as const,
      evidence: "local-distrust",
    };

    it("distrusts a root with the key disabled in the same write", () => {
      const items = buildDistrustRootTransaction("control", input);
      expect(items.map((item) => item.slot)).toEqual(["idempotency", "profile"]);
      expect(items[1]!.item.Update).toMatchObject({
        ConditionExpression:
          "(#status = :active OR #status = :retired) AND #version = :loaded AND #kind = :root",
        ExpressionAttributeValues: { ":root": "ROOT", ":evidence": "local-distrust", ":disabled": "DISABLED" },
      });
      expect(items[1]!.item.Update!.UpdateExpression).toContain("#key.#state = :disabled");
      expectNoUnusedPlaceholders(items);
      const retired = buildDistrustRootTransaction("control", {
        ...input,
        ca: caRecord({
          kind: "ROOT",
          key: { custody: "WRAPPED", algorithm: "ECDSA_P256", spkiSha256: "c", state: "DISABLED" },
        }),
      });
      expectNoUnusedPlaceholders(retired);
      expect(retired[1]!.item.Update!.UpdateExpression).not.toContain("#key");
    });

    it("flips a child with ReturnValues and a key-state condition", () => {
      const update = buildRevokeForRevokedAncestorUpdate(
        "control",
        caRecord(),
        { revokedAt: now.toISOString(), reason: "caCompromise", evidence: "ancestor:ca-root-one" },
        "ca-root-one",
        "pkv-new",
      );
      expect(update).toMatchObject({
        Key: pkiKeys.caProfile("ca-child-one"),
        ConditionExpression:
          "(#status = :active OR #status = :retired) AND #parentCaId = :ancestor AND #key.#state = :loadedKeyState",
        ReturnValues: "ALL_NEW",
        ExpressionAttributeValues: { ":ancestor": "ca-root-one", ":loadedKeyState": "ACTIVE", ":disabled": "DISABLED" },
      });
      expectNoUnusedPlaceholders([{ item: { Update: update } }]);
      const disabled = buildRevokeForRevokedAncestorUpdate(
        "control",
        caRecord({ key: { custody: "WRAPPED", algorithm: "ECDSA_P256", spkiSha256: "c", state: "DISABLED" } }),
        { revokedAt: now.toISOString(), reason: "unspecified", evidence: "ancestor:ca-root-one" },
        "ca-root-one",
        "pkv-new",
      );
      expect(disabled.UpdateExpression).not.toContain("#key");
      expect(disabled.ExpressionAttributeValues).not.toHaveProperty(":disabled");
      expectNoUnusedPlaceholders([{ item: { Update: disabled } }]);
    });

    it("revokeForRevokedAncestor returns the new record or undefined", async () => {
      const send = jest
        .fn()
        .mockResolvedValueOnce({ Attributes: { ...caRecord(), pk: "PKI_CA#ca-child-one", sk: "PROFILE", status: "REVOKED" } })
        .mockRejectedValueOnce(Object.assign(new Error("c"), { name: "ConditionalCheckFailedException" }));
      const repository = new PkiRepository({ send } as unknown as DynamoDBDocumentClient, {
        tableName: "control",
        directoryIndex: "pki-directory",
      });
      const revocation = { revokedAt: now.toISOString(), reason: "unspecified", evidence: "ancestor:ca-root-one" };
      await expect(repository.revokeForRevokedAncestor(caRecord(), revocation, "ca-root-one")).resolves.toMatchObject({
        caId: "ca-child-one",
        status: "REVOKED",
      });
      await expect(repository.revokeForRevokedAncestor(caRecord(), revocation, "ca-root-one")).resolves.toBeUndefined();
    });
  });

  it("builds the policy update without the maximum when it is undefined", () => {
    const base = {
      idempotency,
      caId: "ca-root-one",
      loadedVersion: "pkv-1",
      newVersion: "pkv-2",
      now: now.toISOString(),
      policy: {} as CaRecord["policy"],
    };
    const without = buildUpdateCaPolicyTransaction("control", base);
    const update = without[1]!.item.Update!;
    expect(update.UpdateExpression).toBe("SET #policy = :policy, #version = :v");
    expect(update.ConditionExpression).toBe("#version = :ifMatch AND (#status = :pending OR #status = :active)");
    expect(update.ExpressionAttributeNames).not.toHaveProperty("#maxIssueLifetimeEverSeconds");
    expect(update.ExpressionAttributeValues).not.toHaveProperty(":max");
    expectNoUnusedPlaceholders(without);
    expectNoUnusedPlaceholders(buildUpdateCaPolicyTransaction("control", { ...base, displayName: null }));
    const withMax = buildUpdateCaPolicyTransaction("control", { ...base, maxIssueLifetimeEverSeconds: 5 });
    expect(withMax[1]!.item.Update!.UpdateExpression).toBe(
      "SET #policy = :policy, #maxIssueLifetimeEverSeconds = :max, #version = :v",
    );
    expect(withMax[1]!.item.Update!.ConditionExpression).toContain("#maxIssueLifetimeEverSeconds <= :max");
    expectNoUnusedPlaceholders(withMax);
  });
});
