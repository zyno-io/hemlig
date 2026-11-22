import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify,
} from "node:crypto";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { KMSClient } from "@aws-sdk/client-kms";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { PkiConfig } from "../aws/config";
import { ApiError } from "../domain/errors";
import { generateCaKeyPair, wrapCaKey } from "../pki/wrapped-keys";
import { WrappedCaSigner } from "../pki/signer";
import type { IssuedCertificateRecord } from "../pki/types";
import {
  buildIssuanceCommit,
  classifyIssuanceCancellation,
  pkiDirectory,
  pkiKeys,
  pkiTtl,
  PkiRepository,
  quotaWindows,
  type AdminIssuanceCommit,
  type ConsumerIssuanceCommit,
  type IssuanceCommitOutcome,
  type PkiKey,
} from "../repositories/pki";

/**
 * PKI transaction suite against MiniStack. It runs as part of `yarn ministack:verify`, not under jest. It exercises
 * the real commit transaction (every condition, each cancellation reason as classified), the first quota window, GSI
 * keys, TTL attributes and the WRAPPED CA key round trip through KMS.
 */
export interface PkiVerifyOptions {
  readonly dynamo: DynamoDBClient;
  readonly kms: KMSClient;
  readonly keyArn: string;
  readonly table: string;
  readonly config: PkiConfig;
}

const notice = (message: string): void => {
  process.stdout.write(
    process.env.GITHUB_ACTIONS === undefined
      ? `PKI notice: ${message}\n`
      : `::warning::${message}\n`,
  );
};

const check = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(`PKI verification failed: ${message}`);
  }
};

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const eventually = async <T>(
  produce: () => Promise<T | undefined>,
  label: string,
  timeoutMs = 2000,
): Promise<T> => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await produce();
    if (value !== undefined) {
      return value;
    }
    if (Date.now() > deadline) {
      throw new Error(`PKI verification failed: ${label} (timed out)`);
    }
    await sleep(100);
  }
};

const days = (count: number): number => count * 86_400_000;

export const verifyPkiOnMiniStack = async (
  options: PkiVerifyOptions,
): Promise<void> => {
  const { table, config } = options;
  // Production sets removeUndefinedValues; the shared verify client does not.
  const doc = DynamoDBDocumentClient.from(options.dynamo, {
    marshallOptions: { removeUndefinedValues: true },
  });
  const suffix = randomBytes(5).toString("hex");
  const environment = "ministack";
  // One fixed instant for every commit, so an hour boundary cannot flake the quota tests.
  const now = new Date();
  const windows = quotaWindows(now);
  const repository = new PkiRepository(doc, {
    tableName: table,
    directoryIndex: config.pkiDirectoryIndex,
    sleep: async () => undefined,
  });
  let cases = 0;
  const done = (name: string): void => {
    cases += 1;
    process.stdout.write(`PKI ok: ${name}\n`);
  };

  // ---- Probes -------------------------------------------------------------
  let conditionCheck = true;
  let reasons = true;
  const probeA = { pk: `PKI_PROBE#${suffix}`, sk: "A" };
  await doc.send(
    new PutCommand({
      TableName: table,
      Item: { ...probeA, status: "ACTIVE" },
    }),
  );
  // Reasons are positional: the failing ConditionCheck is item 0, the Put that was canceled with it is item 1.
  const probeB = { pk: `PKI_PROBE#${suffix}-b`, sk: "B" };
  try {
    await doc.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            ConditionCheck: {
              TableName: table,
              Key: probeA,
              ConditionExpression: "#status = :inactive",
              ExpressionAttributeNames: { "#status": "status" },
              ExpressionAttributeValues: { ":inactive": "INACTIVE" },
            },
          },
          { Put: { TableName: table, Item: { ...probeB, value: 1 } } },
        ],
      }),
    );
    conditionCheck = false;
    notice(
      "MiniStack did not enforce a failing ConditionCheck; running only the GSI and TTL checks.",
    );
  } catch (error) {
    if (
      !(error instanceof Error) ||
      error.name !== "TransactionCanceledException"
    ) {
      throw error;
    }
    const codes = (
      (error as { CancellationReasons?: { Code?: string }[] })
        .CancellationReasons ?? []
    ).map((reason) => reason.Code);
    if (codes.length !== 2) {
      reasons = false;
      notice(
        "MiniStack returned no CancellationReasons; classification checks expect 'unclassified'.",
      );
    } else {
      check(
        codes[0] === "ConditionalCheckFailed" && codes[1] === "None",
        `the ConditionCheck probe reported unexpected cancellation reasons: ${JSON.stringify(codes)}`,
      );
    }
    check(
      (await doc.send(new GetCommand({ TableName: table, Key: probeB })))
        .Item === undefined,
      "the canceled probe transaction wrote an item",
    );
  }
  done(
    `probe ConditionCheck (${conditionCheck ? "supported" : "unsupported"}, reasons ${reasons ? "present" : "absent"})`,
  );

  const token = createHash("sha256").update(suffix).digest("hex").slice(0, 36);
  const probeC = { pk: `PKI_PROBE#${suffix}-c`, sk: "C" };
  const tokenTransaction = new TransactWriteCommand({
    TransactItems: [
      {
        Put: {
          TableName: table,
          Item: { ...probeC, value: 1 },
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
    ],
    ClientRequestToken: token,
  });
  await doc.send(tokenTransaction);
  let tokenDedupe = true;
  try {
    await doc.send(
      new TransactWriteCommand({
        TransactItems: tokenTransaction.input.TransactItems,
        ClientRequestToken: token,
      }),
    );
  } catch (error) {
    if (
      !(error instanceof Error) ||
      error.name !== "TransactionCanceledException"
    ) {
      throw error;
    }
    tokenDedupe = false;
    notice(
      "MiniStack ignores ClientRequestToken; the replay read-back covers it.",
    );
  }
  done(
    `probe ClientRequestToken (${tokenDedupe ? "deduplicated" : "ignored"})`,
  );

  // ---- Fixtures -----------------------------------------------------------
  interface Fixture {
    readonly caId: string;
    readonly caName: string;
    readonly consumerId: string;
    readonly grantName: string;
    readonly uid: string;
    readonly grantId: string;
    readonly fingerprint: string;
    readonly key: string;
  }
  interface SeedOptions {
    readonly reuseCa?: Fixture;
    readonly ca?: Record<string, unknown>;
    readonly grant?: Record<string, unknown>;
    readonly identity?: Record<string, unknown>;
    readonly agent?: Record<string, unknown>;
  }
  const put = (item: Record<string, unknown>): Promise<unknown> =>
    doc.send(new PutCommand({ TableName: table, Item: item }));
  const getItem = async (
    key: PkiKey,
  ): Promise<Record<string, unknown> | undefined> =>
    (
      await doc.send(
        new GetCommand({
          TableName: table,
          Key: { pk: key.pk, sk: key.sk },
          ConsistentRead: true,
        }),
      )
    ).Item;

  const seed = async (seedOptions: SeedOptions = {}): Promise<Fixture> => {
    const id = randomBytes(6).toString("hex");
    const caBase = seedOptions.reuseCa;
    const fixture: Fixture = {
      caId: caBase?.caId ?? `ca-${id}`,
      caName: caBase?.caName ?? `name-${id}`,
      consumerId: `con-${id}`,
      grantName: `grant-${id}`,
      uid: `uid-${id}`,
      grantId: `grant-${randomUUID()}`,
      fingerprint: createHash("sha256").update(id).digest("hex"),
      key: `idem-${id}-key`,
    };
    if (caBase === undefined) {
      await put({
        ...pkiKeys.caProfile(fixture.caId),
        ...pkiDirectory.ca(environment, fixture.caName),
        caId: fixture.caId,
        environment,
        name: fixture.caName,
        status: "ACTIVE",
        version: "ver-1",
        key: {
          custody: "WRAPPED",
          algorithm: "ECDSA_P256",
          state: "ACTIVE",
        },
        ...seedOptions.ca,
      });
    }
    await put({
      ...pkiKeys.grant(fixture.consumerId, fixture.grantName),
      uid: fixture.uid,
      version: "gv-1",
      status: "ACTIVE",
      ...seedOptions.grant,
    });
    await put({
      pk: `IDENTITY#${fixture.fingerprint}`,
      sk: "PROFILE",
      fingerprint: fixture.fingerprint,
      consumerId: fixture.consumerId,
      environment,
      kind: "api",
      status: "ACTIVE",
      notBefore: new Date(now.getTime() - days(1)).toISOString(),
      notAfter: new Date(now.getTime() + days(1)).toISOString(),
      ...seedOptions.identity,
    });
    await put({
      pk: `AGENT_GRANT#${fixture.grantId}`,
      sk: "PROFILE",
      grantId: fixture.grantId,
      consumerId: fixture.consumerId,
      environment,
      status: "ACTIVE",
      ...seedOptions.agent,
    });
    return fixture;
  };

  interface IssueOptions {
    readonly key?: string;
    readonly serial?: string;
    readonly agent?: boolean;
    readonly perHour?: number;
    readonly perDay?: number;
    readonly caPerHour?: number;
    readonly grantUid?: string;
    readonly grantVersion?: string;
    readonly caVersion?: string;
  }
  const certificate = (
    caId: string,
    serial: string,
    requester: IssuedCertificateRecord["requester"],
  ): IssuedCertificateRecord => ({
    caId,
    environment,
    serial,
    status: "ISSUED",
    certificatePem:
      "-----BEGIN CERTIFICATE-----\nMIIBverify\n-----END CERTIFICATE-----\n",
    fingerprint: createHash("sha256").update(serial).digest("hex"),
    spkiSha256: createHash("sha256").update(`spki${serial}`).digest("hex"),
    subject: "CN=ministack",
    sans: { dns: ["ministack.example.test"], ip: [], uri: [] },
    keyAlgorithm: "ECDSA_P256",
    keyUsages: ["digitalSignature"],
    extendedKeyUsages: ["clientAuth"],
    isCa: false,
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + days(30)).toISOString(),
    issuedAt: now.toISOString(),
    requester,
  });
  const commitFor = (
    fx: Fixture,
    o: IssueOptions = {},
  ): ConsumerIssuanceCommit => {
    const serial = o.serial ?? randomBytes(20).toString("hex");
    const uid = o.grantUid ?? fx.uid;
    const version = o.grantVersion ?? "gv-1";
    return {
      path: "consumer",
      now,
      idempotencyKey: o.key ?? fx.key,
      requestDigest: createHash("sha256").update(serial).digest("hex"),
      certificate: certificate(fx.caId, serial, {
        type: "consumer",
        id: fx.consumerId,
        consumerId: fx.consumerId,
        issuanceGrant: { name: fx.grantName, uid, version },
      }),
      ca: {
        caId: fx.caId,
        version: o.caVersion ?? "ver-1",
        issuancePerHour: o.caPerHour ?? 100,
      },
      consumerId: fx.consumerId,
      identityFingerprint: fx.fingerprint,
      grant: {
        name: fx.grantName,
        uid,
        version,
        perHour: o.perHour ?? 10,
        perDay: o.perDay ?? 100,
      },
      ...(o.agent === false
        ? {}
        : { agentGrant: { grantId: fx.grantId, environment } }),
    };
  };
  const issue = (
    fx: Fixture,
    o: IssueOptions = {},
  ): Promise<IssuanceCommitOutcome> =>
    repository.commitIssuance(commitFor(fx, o));

  const counters = async (fx: Fixture): Promise<number[]> => [
    await repository.getQuotaCount(pkiKeys.grantQuota(fx.uid, windows.hourSk)),
    await repository.getQuotaCount(pkiKeys.grantQuota(fx.uid, windows.daySk)),
    await repository.getQuotaCount(pkiKeys.caQuota(fx.caId, windows.hourSk)),
  ];
  const expectKind = (
    outcome: IssuanceCommitOutcome,
    kind: IssuanceCommitOutcome["kind"],
    label: string,
  ): void => {
    const expected = !reasons && kind !== "committed" ? "unclassified" : kind;
    check(
      outcome.kind === expected,
      `${label}: expected ${expected}, got ${outcome.kind}`,
    );
  };
  const expectSlots = (
    outcome: IssuanceCommitOutcome,
    slots: readonly string[],
    label: string,
  ): void => {
    if (!reasons) {
      return;
    }
    check(
      outcome.kind === "preconditionFailed" &&
        JSON.stringify(outcome.slots) === JSON.stringify(slots),
      `${label}: expected preconditionFailed ${slots.join(",")}, got ${JSON.stringify(outcome)}`,
    );
  };
  const expectNothingCommitted = async (
    fx: Fixture,
    commit: ConsumerIssuanceCommit,
    before: number[],
    label: string,
    certificateSeeded = false,
  ): Promise<void> => {
    const { serial, caId } = commit.certificate;
    const storedCertificate = await getItem(pkiKeys.certificate(caId, serial));
    check(
      certificateSeeded
        ? storedCertificate?.subject === undefined
        : storedCertificate === undefined,
      `${label}: certificate item was written`,
    );
    check(
      (await getItem(
        pkiKeys.consumerCertificate(
          fx.consumerId,
          commit.certificate.issuedAt,
          caId,
          serial,
        ),
      )) === undefined,
      `${label}: consumer pointer was written`,
    );
    check(
      JSON.stringify(await counters(fx)) === JSON.stringify(before),
      `${label}: counters changed`,
    );
  };
  /** A rejected commit must leave nothing behind, and (unless it IS a replay) no replay record either. */
  const rejected = async (
    label: string,
    fx: Fixture,
    o: IssueOptions,
    kind: IssuanceCommitOutcome["kind"],
    slots?: readonly string[],
    certificateSeeded = false,
  ): Promise<void> => {
    const before = await counters(fx);
    const commit = commitFor(fx, o);
    const outcome = await repository.commitIssuance(commit);
    expectKind(outcome, kind, label);
    if (slots !== undefined) {
      expectSlots(outcome, slots, label);
    }
    await expectNothingCommitted(fx, commit, before, label, certificateSeeded);
    if (kind !== "replayExists") {
      check(
        (await repository.getReplayRecord(
          fx.consumerId,
          commit.idempotencyKey,
        )) === undefined,
        `${label}: replay record was written`,
      );
    }
    done(label);
  };

  if (!conditionCheck) {
    // Without ConditionCheck the commit cannot run: check only the GSI keys and TTL attributes.
    const fx = await seed();
    const notAfter = new Date(now.getTime() + days(30)).toISOString();
    await put({
      ...pkiKeys.certificate(fx.caId, "aa01"),
      ...pkiDirectory.certificate(fx.caId, notAfter, "aa01"),
      ttl: pkiTtl.certificate(notAfter),
    });
    await eventually(async () => {
      const found = await doc.send(
        new QueryCommand({
          TableName: table,
          IndexName: config.pkiDirectoryIndex,
          KeyConditionExpression: "#pk = :pk",
          ExpressionAttributeNames: { "#pk": "pkiDirectoryPk" },
          ExpressionAttributeValues: { ":pk": `PKI_CERTS#${fx.caId}` },
        }),
      );
      return found.Items?.length === 1 ? true : undefined;
    }, "the pki-directory index did not return the certificate");
    done("GSI and TTL only");
    process.stdout.write(
      `PKI MiniStack verification passed (${cases} checks, limited).\n`,
    );
    return;
  }

  // ---- Consumer path ------------------------------------------------------
  {
    const fx = await seed();
    const commit = commitFor(fx);
    const built = buildIssuanceCommit(table, commit);
    check(built.slots.length === 10, "agent path must have 10 items");
    const outcome = await repository.commitIssuance(commit);
    check(outcome.kind === "committed", `agent happy path: ${outcome.kind}`);
    const { serial, notAfter, issuedAt } = commit.certificate;
    const stored = await getItem(pkiKeys.certificate(fx.caId, serial));
    check(stored !== undefined, "certificate item missing");
    check(
      stored?.pkiDirectoryPk === `PKI_CERTS#${fx.caId}` &&
        stored.pkiDirectorySk === `${notAfter}#${serial}`,
      "certificate lacks its directory keys",
    );
    check(stored?.ttl === pkiTtl.certificate(notAfter), "certificate ttl");
    const replay = await getItem(pkiKeys.replay(fx.consumerId, fx.key));
    check(replay?.ttl === pkiTtl.replay(notAfter), "replay ttl");
    const pointer = await getItem(
      pkiKeys.consumerCertificate(fx.consumerId, issuedAt, fx.caId, serial),
    );
    check(pointer?.ttl === pkiTtl.consumerPointer(notAfter), "pointer ttl");
    const hour = await getItem(pkiKeys.grantQuota(fx.uid, windows.hourSk));
    const day = await getItem(pkiKeys.grantQuota(fx.uid, windows.daySk));
    const caHour = await getItem(pkiKeys.caQuota(fx.caId, windows.hourSk));
    check(
      hour?.count === 1 && hour.ttl === pkiTtl.hourCounter(windows.hourStart),
      "grant hour counter",
    );
    check(
      day?.count === 1 && day.ttl === pkiTtl.dayCounter(windows.dayStart),
      "grant day counter",
    );
    check(caHour?.count === 1, "CA hour counter");
    await eventually(async () => {
      const found = await doc.send(
        new QueryCommand({
          TableName: table,
          IndexName: config.pkiDirectoryIndex,
          KeyConditionExpression: "#pk = :pk",
          ExpressionAttributeNames: { "#pk": "pkiDirectoryPk" },
          ExpressionAttributeValues: { ":pk": `PKI_CERTS#${fx.caId}` },
        }),
      );
      return found.Items?.some((item) => item.serial === serial)
        ? true
        : undefined;
    }, "the pki-directory index did not return the certificate");
    const read = await repository.getReplayRecord(fx.consumerId, fx.key);
    check(read?.serial === serial && read.caId === fx.caId, "replay read-back");
    done("agent happy path");
  }
  {
    const fx = await seed();
    const commit = commitFor(fx, { agent: false });
    check(
      buildIssuanceCommit(table, commit).slots.length === 9,
      "direct path must have 9 items",
    );
    const outcome = await repository.commitIssuance(commit);
    check(outcome.kind === "committed", `direct consumer: ${outcome.kind}`);
    done("direct consumer commit");
  }

  // Quotas.
  {
    const fx = await seed();
    check((await issue(fx, { perHour: 1 })).kind === "committed", "first");
    const second = await issue(fx, { perHour: 1, key: `${fx.key}-2` });
    expectKind(second, "quotaExhausted", "grant hour quota");
    if (reasons && second.kind === "quotaExhausted") {
      check(
        JSON.stringify(second.quotas) === JSON.stringify(["grantHour"]) &&
          second.retryAfterSeconds > 0,
        "grant hour quota slots",
      );
    }
    check(
      (await counters(fx)).join() === "1,1,1",
      "grant hour quota changed counters",
    );
    done("grant hour quota");
  }
  {
    const fx = await seed();
    check((await issue(fx, { perDay: 1 })).kind === "committed", "first");
    const second = await issue(fx, { perDay: 1, key: `${fx.key}-2` });
    expectKind(second, "quotaExhausted", "grant day quota");
    if (reasons && second.kind === "quotaExhausted") {
      check(
        JSON.stringify(second.quotas) === JSON.stringify(["grantDay"]),
        "grant day quota slots",
      );
    }
    done("grant day quota");
  }
  {
    const first = await seed();
    check((await issue(first, { caPerHour: 1 })).kind === "committed", "first");
    const other = await seed({ reuseCa: first });
    const second = await issue(other, { caPerHour: 1 });
    expectKind(second, "quotaExhausted", "CA hour quota");
    if (reasons && second.kind === "quotaExhausted") {
      check(
        JSON.stringify(second.quotas) === JSON.stringify(["caHour"]),
        "CA hour quota slots",
      );
    }
    done("CA hour quota");
  }

  // Replay, resend, serial collision.
  {
    const fx = await seed();
    check((await issue(fx)).kind === "committed", "first");
    await rejected("replay with a new serial", fx, {}, "replayExists");
  }
  {
    const fx = await seed();
    const commit = commitFor(fx);
    const built = buildIssuanceCommit(table, commit);
    await doc.send(new TransactWriteCommand(built.input));
    let resend: string;
    try {
      await doc.send(new TransactWriteCommand(built.input));
      resend = "committed";
    } catch (error) {
      if (
        !(error instanceof Error) ||
        error.name !== "TransactionCanceledException"
      ) {
        throw error;
      }
      resend = classifyIssuanceCancellation(built, commit, error).kind;
    }
    check(
      resend === "committed" || resend === "replayExists" || !reasons,
      `identical resend: ${resend}`,
    );
    check((await counters(fx)).join() === "1,1,1", "resend changed counters");
    done("identical resend");
  }
  {
    const fx = await seed();
    const serial = randomBytes(20).toString("hex");
    await put({ ...pkiKeys.certificate(fx.caId, serial), status: "ISSUED" });
    await rejected(
      "serial collision",
      fx,
      { serial },
      "serialCollision",
      undefined,
      true,
    );
  }

  // Preconditions.
  const preconditionCases: [string, SeedOptions, IssueOptions, string[]][] = [
    ["grant uid mismatch", {}, { grantUid: "uid-other-grant" }, ["grant"]],
    ["grant version mismatch", {}, { grantVersion: "gv-other" }, ["grant"]],
    ["grant disabled", { grant: { status: "DISABLED" } }, {}, ["grant"]],
    [
      "grant expired",
      { grant: { expiresAt: new Date(now.getTime() - 1000).toISOString() } },
      {},
      ["grant"],
    ],
    ["CA retired", { ca: { status: "RETIRED" } }, {}, ["ca"]],
    ["CA version mismatch", {}, { caVersion: "ver-other" }, ["ca"]],
    [
      "CA key disabled",
      {
        ca: {
          key: {
            custody: "WRAPPED",
            algorithm: "ECDSA_P256",
            state: "DISABLED",
          },
        },
      },
      {},
      ["ca"],
    ],
    ["identity revoked", { identity: { status: "REVOKED" } }, {}, ["identity"]],
    [
      "identity expired",
      { identity: { notAfter: new Date(now.getTime() - 1000).toISOString() } },
      {},
      ["identity"],
    ],
    [
      "identity of another consumer",
      { identity: { consumerId: "con-someone-else" } },
      {},
      ["identity"],
    ],
    [
      "identity not an API identity",
      { identity: { kind: "notify" } },
      {},
      ["identity"],
    ],
    [
      "agent grant pending",
      { agent: { status: "PENDING" } },
      {},
      ["agentGrant"],
    ],
    [
      "agent grant in another environment",
      { agent: { environment: "other-environment" } },
      {},
      ["agentGrant"],
    ],
  ];
  for (const [label, seedOptions, issueOptions, slots] of preconditionCases) {
    const fx = await seed(seedOptions);
    await rejected(label, fx, issueOptions, "preconditionFailed", slots);
  }
  {
    const fx = await seed({
      grant: { expiresAt: new Date(now.getTime() + days(1)).toISOString() },
    });
    check(
      (await issue(fx)).kind === "committed",
      "a grant with a future expiry must commit",
    );
    done("grant with a future expiry commits");
  }

  // Precedence.
  {
    const fx = await seed();
    check((await issue(fx, { perHour: 1 })).kind === "committed", "first");
    await doc.send(
      new UpdateCommand({
        TableName: table,
        Key: pkiKeys.grant(fx.consumerId, fx.grantName),
        UpdateExpression: "SET #status = :disabled",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: { ":disabled": "DISABLED" },
      }),
    );
    await rejected(
      "disabled grant outranks an exhausted quota",
      fx,
      { perHour: 1, key: `${fx.key}-2` },
      "preconditionFailed",
      ["grant"],
    );
  }
  {
    const fx = await seed();
    check((await issue(fx, { perHour: 1 })).kind === "committed", "first");
    await rejected(
      "replay outranks an exhausted quota",
      fx,
      { perHour: 1 },
      "replayExists",
    );
  }

  // Admin path.
  {
    const fx = await seed();
    const actor = { type: "human" as const, id: `admin-${suffix}` };
    const admin = (key: string, limit: number): AdminIssuanceCommit => {
      const serial = randomBytes(20).toString("hex");
      return {
        path: "admin",
        now,
        idempotencyKey: key,
        requestDigest: createHash("sha256").update(serial).digest("hex"),
        certificate: certificate(fx.caId, serial, {
          type: "human",
          id: actor.id,
        }),
        ca: { caId: fx.caId, version: "ver-1", issuancePerHour: 100 },
        actor,
        adminPerHour: limit,
      };
    };
    const first = await repository.commitIssuance(admin("admin-key-0001", 1));
    check(first.kind === "committed", `admin path: ${first.kind}`);
    const record = await getItem(
      pkiKeys.humanIdempotency(actor.id, "admin-key-0001"),
    );
    check(
      record?.status === "COMMITTED" &&
        record.operationType === "pki.certificate.issue",
      "admin idempotency record",
    );
    check(
      (await repository.getQuotaCount(
        pkiKeys.adminQuota(fx.caId, windows.hourSk),
      )) === 1,
      "admin hour counter",
    );
    const second = await repository.commitIssuance(admin("admin-key-0002", 1));
    expectKind(second, "quotaExhausted", "admin hour quota");
    if (reasons && second.kind === "quotaExhausted") {
      check(
        JSON.stringify(second.quotas) === JSON.stringify(["adminHour"]),
        "admin hour quota slots",
      );
    }
    done("admin path");
  }

  // Directory index.
  {
    const fx = await seed();
    await eventually(async () => {
      const response = await doc.send(
        new QueryCommand({
          TableName: table,
          IndexName: config.pkiDirectoryIndex,
          KeyConditionExpression: "#pk = :pk AND begins_with(#sk, :prefix)",
          ExpressionAttributeNames: {
            "#pk": "pkiDirectoryPk",
            "#sk": "pkiDirectorySk",
          },
          ExpressionAttributeValues: {
            ":pk": "PKI_CAS",
            ":prefix": `${environment}#`,
          },
        }),
      );
      return response.Items?.some((item) => item.caId === fx.caId)
        ? true
        : undefined;
    }, "the pki-directory index did not return the CA");
    await eventually(
      async () => ((await repository.hasAnyCa()) ? true : undefined),
      "hasAnyCa did not see the CA",
    );
    done("CA directory query and hasAnyCa");
  }

  // WRAPPED key round trip through KMS.
  {
    const caId = `ca-${suffix}`;
    const generated = await generateCaKeyPair("ECDSA_P256");
    const wrapped = await wrapCaKey(
      options.kms,
      options.keyArn,
      generated.privateKeyDer,
      { caId, environment },
    );
    const signer = new WrappedCaSigner({
      kms: options.kms,
      kmsKeyId: options.keyArn,
      caId,
      environment,
      algorithm: "ECDSA_P256",
      wrapped,
    });
    const message = Buffer.from("hemlig pki verification");
    const signature = await signer.sign(message);
    check(
      verify(
        "sha256",
        message,
        {
          key: createPublicKey({
            key: generated.spkiDer,
            format: "der",
            type: "spki",
          }),
          dsaEncoding: "der",
        },
        signature,
      ),
      "the wrapped CA key signature did not verify",
    );
    const other = new WrappedCaSigner({
      kms: options.kms,
      kmsKeyId: options.keyArn,
      caId: `ca-other-${suffix}`,
      environment,
      algorithm: "ECDSA_P256",
      wrapped,
    });
    let code: string | undefined;
    try {
      await other.sign(message);
    } catch (error) {
      code = error instanceof ApiError ? error.code : undefined;
    }
    check(
      code === "ca_key_unavailable",
      `unwrapping under another caId must give ca_key_unavailable, got ${code}`,
    );
    done("WRAPPED CA key round trip");
  }

  process.stdout.write(
    `PKI MiniStack verification passed (${cases} checks; ConditionCheck ${conditionCheck ? "supported" : "unsupported"}, cancellation reasons ${reasons ? "present" : "absent"}, ClientRequestToken ${tokenDedupe ? "deduplicated" : "ignored"}).\n`,
  );
};
