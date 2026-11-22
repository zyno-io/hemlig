import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { CaRecord, ExternalCaRecord } from "../pki/types";
import {
  buildAbandonCaTransaction,
  buildAcquireCrlLeaseUpdate,
  buildActivateCaTransaction,
  buildAllocateCrlNumberUpdate,
  buildCommitCrlUpdate,
  buildCommitExternalCrlTransaction,
  buildCreateCaTransaction,
  buildDestroyKeyTransaction,
  buildDisableDrainedKeyTransaction,
  buildRetireCaTransaction,
  buildRetireExpiredCaUpdate,
  buildRevokeCaExternallyUpdate,
  buildUpdateCaPolicyTransaction,
  PkiRepository,
  type HumanIdempotencyWrite,
  type NamedItem,
} from "./pki";

const actor = { type: "human" as const, id: "admin-1" };
const idempotency: HumanIdempotencyWrite = {
  actor,
  idempotencyKey: "idem-key-0001",
  operationType: "pki.test",
  requestDigest: "d".repeat(64),
  result: { caId: "ca-prod-one" },
  now: "2026-11-22T10:00:00.000Z",
};
const caId = "ca-prod-one";
const extId = `ext-${"a".repeat(40)}`;

/** Collects every expression string of a built item. */
const expressions = (value: unknown): string[] => {
  const found: string[] = [];
  const visit = (node: unknown): void => {
    if (node === null || typeof node !== "object") {
      return;
    }
    for (const [key, child] of Object.entries(node)) {
      if (
        typeof child === "string" &&
        /Expression$/.test(key) &&
        key !== "KeyConditionExpression"
      ) {
        found.push(child);
      } else {
        visit(child);
      }
    }
  };
  visit(value);
  return found;
};

/** Every identifier in an expression is a `#name`, a `:value`, `pk` or a DynamoDB function/keyword. */
const onlyPlaceholders = (expression: string): boolean => {
  const allowed = new Set([
    "SET",
    "REMOVE",
    "ADD",
    "AND",
    "OR",
    "attribute_not_exists",
    "attribute_exists",
    "if_not_exists",
    "pk",
  ]);
  return (expression.match(/[#:]?[A-Za-z_][A-Za-z0-9_]*/g) ?? []).every(
    (token) =>
      token.startsWith("#") || token.startsWith(":") || allowed.has(token),
  );
};

const ca = {
  caId,
  environment: "prod",
  name: "prod-one",
  subjectKey: "b".repeat(64),
  createdAt: idempotency.now,
} as unknown as CaRecord;

const ext = {
  extId,
  version: "pkv-ext",
  dependents: new Set([caId]),
  environments: new Set(["prod"]),
} as unknown as ExternalCaRecord;

const mutation = {
  idempotency,
  caId,
  loadedVersion: "pkv-1",
  newVersion: "pkv-2",
  now: idempotency.now,
};

const published = {
  number: 3,
  objectKey: "crl/x",
  sha256: "s",
  thisUpdate: "2026-11-22T10:00:00.000Z",
  nextUpdate: "2026-11-29T10:00:00.000Z",
  revision: 1,
  entryCount: 0,
};

describe("admin transaction builders", () => {
  const builds: [string, NamedItem[], string[]][] = [
    [
      "create",
      buildCreateCaTransaction("control", { idempotency, ca }),
      ["idempotency", "name", "subject", "profile"],
    ],
    [
      "activate (new external)",
      buildActivateCaTransaction("control", {
        idempotency,
        caId,
        loadedVersion: "pkv-1",
        newVersion: "pkv-2",
        fields: { serial: "01", effective: {} },
        crl: { revision: 0, lastNumber: 1 },
        external: { kind: "create", record: ext },
        rootSubject: { key: "c".repeat(64), extId, spkiSha256: "s", now: "n" },
      }),
      ["idempotency", "profile", "crl", "external", "rootSubject"],
    ],
    [
      "activate (existing external)",
      buildActivateCaTransaction("control", {
        idempotency,
        caId,
        loadedVersion: "pkv-1",
        newVersion: "pkv-2",
        fields: { serial: "01" },
        crl: { revision: 0, lastNumber: 1 },
        external: {
          kind: "update",
          extId,
          loadedVersion: "pkv-ext",
          newVersion: "pkv-ext2",
          caId,
          environment: "prod",
        },
        rootSubject: { key: "c".repeat(64), extId, spkiSha256: "s", now: "n" },
      }),
      ["idempotency", "profile", "crl", "external", "rootSubject"],
    ],
    [
      "update",
      buildUpdateCaPolicyTransaction("control", {
        ...mutation,
        loadedVersion: "pkv-1",
        policy: {} as CaRecord["policy"],
        maxIssueLifetimeEverSeconds: 10,
      }),
      ["idempotency", "profile"],
    ],
    [
      "abandon",
      buildAbandonCaTransaction("control", mutation),
      ["idempotency", "profile"],
    ],
    [
      "retire",
      buildRetireCaTransaction("control", mutation),
      ["idempotency", "profile"],
    ],
    [
      "destroy",
      buildDestroyKeyTransaction("control", mutation),
      ["idempotency", "profile"],
    ],
    [
      "disable drained",
      buildDisableDrainedKeyTransaction("control", {
        caId,
        newVersion: "v",
        now: "n",
        crlRevision: 2,
        drainAt: "d",
      }),
      ["profile", "crl"],
    ],
    [
      "commit external CRL",
      buildCommitExternalCrlTransaction("control", {
        extId,
        loadedVersion: "pkv-ext",
        newVersion: "pkv-ext2",
        crl: {
          numberHex: "01",
          thisUpdate: "t",
          nextUpdate: "n",
          sha256: "s",
          objectKey: "k",
          uploadedAt: "u",
          uploadedBy: actor,
        },
        idempotency,
      }),
      ["idempotency", "external"],
    ],
  ];

  it.each(builds)(
    "%s has the expected slots and only placeholders",
    (_name, items, slots) => {
      expect(items.map((item) => item.slot)).toEqual(slots);
      for (const expression of expressions(items.map((item) => item.item))) {
        expect(onlyPlaceholders(expression)).toBe(true);
      }
    },
  );

  it("puts the human idempotency record in slot 0 with the replay condition", () => {
    const item = buildCreateCaTransaction("control", { idempotency, ca })[0]!
      .item;
    expect(item.Put).toMatchObject({
      Item: {
        pk: "IDEMPOTENCY#human#admin-1",
        sk: "REQUEST#idem-key-0001",
        operationType: "pki.test",
        status: "COMMITTED",
        result: { caId },
      },
      ConditionExpression: "attribute_not_exists(pk)",
    });
  });

  it("creates claims and the directory-indexed profile", () => {
    const [, name, subject, profile] = buildCreateCaTransaction("control", {
      idempotency,
      ca,
    });
    expect(name!.item.Put!.Item).toMatchObject({
      pk: "PKI_CA_NAME#prod#prod-one",
    });
    expect(subject!.item.Put!.Item).toMatchObject({
      pk: `PKI_SUBJECT#${"b".repeat(64)}`,
      ownerType: "ca",
    });
    expect(profile!.item.Put!.Item).toMatchObject({
      pk: `PKI_CA#${caId}`,
      sk: "PROFILE",
      pkiDirectoryPk: "PKI_CAS",
      pkiDirectorySk: "prod#prod-one",
    });
  });

  it("activation differs between a new and an existing external record", () => {
    const fresh = builds[1]![1][3]!.item;
    const existing = builds[2]![1][3]!.item;
    expect(fresh.Put).toMatchObject({
      ConditionExpression: "attribute_not_exists(pk)",
      Item: { pkiDirectoryPk: "PKI_EXTCAS", dependents: new Set([caId]) },
    });
    expect(existing.Update).toMatchObject({
      UpdateExpression:
        "SET #version = :v ADD #dependents :dependent, #environments :environment",
      ConditionExpression: "#version = :loaded",
    });
    const profile = builds[1]![1][1]!.item.Update!;
    expect(profile.ConditionExpression).toBe(
      "#status = :pending AND #version = :loaded",
    );
    expect(profile.UpdateExpression).toContain("#serial = :serial");
    const root = builds[1]![1][4]!.item.Update!;
    expect(root.UpdateExpression).toContain(
      "if_not_exists(#ownerType, :external)",
    );
  });

  it("builds the lease, allocate and commit variants", () => {
    const lease = buildAcquireCrlLeaseUpdate(
      "control",
      caId,
      "o",
      new Date("2026-11-22T10:00:00.000Z"),
    );
    expect(lease.ExpressionAttributeValues![":lease"]).toEqual({
      owner: "o",
      expiresAt: "2026-11-22T10:01:00.000Z",
    });
    expect(
      buildAllocateCrlNumberUpdate("control", caId, "o").ReturnValues,
    ).toBe("ALL_NEW");
    const clear = buildCommitCrlUpdate("control", {
      caId,
      owner: "o",
      number: 3,
      startRevision: 1,
      published,
      clearDirty: true,
    });
    const keep = buildCommitCrlUpdate("control", {
      caId,
      owner: "o",
      number: 3,
      startRevision: 1,
      published,
      clearDirty: false,
    });
    expect(clear.UpdateExpression).toBe(
      "SET #published = :pub REMOVE #lease, #dirtySince",
    );
    expect(clear.ConditionExpression).toContain("#revision = :startRevision");
    expect(keep.UpdateExpression).toBe("SET #published = :pub REMOVE #lease");
    expect(keep.ConditionExpression).not.toContain("#revision");
    for (const update of [
      lease,
      clear,
      keep,
      buildRetireExpiredCaUpdate("control", { caId, notAfter: "x" }, "n", "v"),
    ]) {
      expect(expressions(update).every(onlyPlaceholders)).toBe(true);
    }
  });

  it("disables the key on external revocation only when it is ACTIVE", () => {
    const revocation = {
      revokedAt: "r",
      reason: "unspecified",
      evidence: "crl:01",
    };
    const active = buildRevokeCaExternallyUpdate(
      "control",
      { caId, serial: "01", key: { state: "ACTIVE" } as CaRecord["key"] },
      revocation,
      extId,
      "v",
    );
    const destroyed = buildRevokeCaExternallyUpdate(
      "control",
      { caId, serial: "01", key: { state: "DESTROYED" } as CaRecord["key"] },
      revocation,
      extId,
      "v",
    );
    expect(active.UpdateExpression).toContain("#key.#state = :disabled");
    expect(destroyed.UpdateExpression).not.toContain("#key.#state");
    expect(destroyed.ExpressionAttributeValues![":loadedKeyState"]).toBe(
      "DESTROYED",
    );
    expect(active.ConditionExpression).toContain("#parent.#id = :extId");
  });
});

const named = (name: string, extra: Record<string, unknown> = {}) =>
  Object.assign(new Error(name), { name, ...extra });

describe("PkiRepository executors", () => {
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
  const items: NamedItem[] = [
    {
      slot: "idempotency",
      item: { Put: { TableName: "control", Item: { pk: "a", sk: "b" } } },
    },
    {
      slot: "profile",
      item: { Put: { TableName: "control", Item: { pk: "c", sk: "d" } } },
    },
  ];
  const canceled = (...codes: string[]) =>
    named("TransactionCanceledException", {
      CancellationReasons: codes.map((Code) => ({ Code })),
    });
  const token = (call: unknown[]): string =>
    (call[0] as { input: { ClientRequestToken: string } }).input
      .ClientRequestToken;

  it("commits and derives a token of at most 36 characters", async () => {
    const send = jest.fn().mockResolvedValue({});
    const { repository } = setup(send);
    await expect(
      repository.transact("x", items, {
        principal: "human:a",
        idempotencyKey: "k",
      }),
    ).resolves.toEqual({ kind: "committed" });
    expect(token(send.mock.calls[0]!)).toHaveLength(36);
  });

  it("retries conflicts with a new token each time, then gives up with 503", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(canceled("None", "TransactionConflict"))
      .mockRejectedValueOnce(canceled("TransactionConflict", "None"))
      .mockResolvedValueOnce({});
    const { repository, sleep } = setup(send);
    await repository.transact("x", items, {
      principal: "p",
      idempotencyKey: "k",
    });
    const tokens = send.mock.calls.map(token);
    expect(new Set(tokens).size).toBe(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    const always = jest
      .fn()
      .mockRejectedValue(canceled("None", "TransactionConflict"));
    await expect(
      setup(always).repository.transact("x", items, {
        principal: "p",
        idempotencyKey: "k",
      }),
    ).rejects.toMatchObject({ statusCode: 503 });
    expect(always).toHaveBeenCalledTimes(4);
  });

  it("resends an ambiguous failure once with the same token", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(named("TimeoutError"))
      .mockResolvedValueOnce({});
    const { repository } = setup(send);
    await repository.transact("x", items, {
      principal: "p",
      idempotencyKey: "k",
    });
    expect(token(send.mock.calls[0]!)).toBe(token(send.mock.calls[1]!));
    const twice = jest.fn().mockRejectedValue(named("TimeoutError"));
    await expect(
      setup(twice).repository.transact("x", items, {
        principal: "p",
        idempotencyKey: "k",
      }),
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it("reports the failed slots, unknown reasons and fatal names", async () => {
    const out = (code: string) =>
      setup(
        jest.fn().mockRejectedValue(canceled(...code.split(","))),
      ).repository.transact("x", items, { principal: "p" });
    await expect(out("None,ConditionalCheckFailed")).resolves.toEqual({
      kind: "canceled",
      failed: ["profile"],
    });
    await expect(
      out("ConditionalCheckFailed,ConditionalCheckFailed"),
    ).resolves.toEqual({
      kind: "canceled",
      failed: ["idempotency", "profile"],
    });
    await expect(
      setup(jest.fn().mockRejectedValue(canceled("None"))).repository.transact(
        "x",
        items,
        { principal: "p" },
      ),
    ).resolves.toEqual({ kind: "canceled", failed: ["unknown"] });
    await expect(
      setup(
        jest.fn().mockRejectedValue(named("TransactionCanceledException")),
      ).repository.transact("x", items, { principal: "p" }),
    ).resolves.toEqual({ kind: "canceled", failed: ["unknown"] });
    jest.spyOn(console, "error").mockImplementation(() => undefined);
    for (const name of ["AccessDeniedException", "ValidationException"]) {
      await expect(
        setup(jest.fn().mockRejectedValue(named(name))).repository.transact(
          "x",
          items,
          { principal: "p" },
        ),
      ).rejects.toMatchObject({ statusCode: 503 });
    }
    await expect(
      out("None,ItemCollectionSizeLimitExceeded"),
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it("updateWithRetry retries conflicts and maps a failed condition", async () => {
    const send = jest
      .fn()
      .mockRejectedValueOnce(named("TransactionConflictException"))
      .mockResolvedValueOnce({ Attributes: { a: 1 } });
    await expect(
      setup(send).repository.updateWithRetry({ TableName: "control", Key: {} }),
    ).resolves.toEqual({ kind: "updated", attributes: { a: 1 } });
    const failed = jest
      .fn()
      .mockRejectedValue(named("ConditionalCheckFailedException"));
    await expect(
      setup(failed).repository.updateWithRetry({
        TableName: "control",
        Key: {},
      }),
    ).resolves.toEqual({ kind: "conditionFailed" });
    jest.spyOn(console, "error").mockImplementation(() => undefined);
    const conflict = jest
      .fn()
      .mockRejectedValue(named("TransactionConflictException"));
    await expect(
      setup(conflict).repository.updateWithRetry({
        TableName: "control",
        Key: {},
      }),
    ).rejects.toMatchObject({ statusCode: 503 });
    expect(conflict).toHaveBeenCalledTimes(4);
  });

  it("maps lease and allocation results", async () => {
    const { repository } = setup(
      jest
        .fn()
        .mockResolvedValueOnce({})
        .mockRejectedValueOnce(named("ConditionalCheckFailedException"))
        .mockResolvedValueOnce({
          Attributes: { lastNumber: 4, revision: 2, published: { number: 3 } },
        })
        .mockRejectedValueOnce(named("ConditionalCheckFailedException")),
    );
    const now = new Date();
    await expect(repository.acquireCrlLease(caId, "o", now)).resolves.toBe(
      "acquired",
    );
    await expect(repository.acquireCrlLease(caId, "o", now)).resolves.toBe(
      "busy",
    );
    await expect(repository.allocateCrlNumber(caId, "o")).resolves.toEqual({
      number: 4,
      startRevision: 2,
      previous: { number: 3 },
    });
    await expect(repository.allocateCrlNumber(caId, "o")).resolves.toBe("lost");
  });

  it("commits a CRL pointer alone or with the idempotency record", async () => {
    const send = jest.fn().mockResolvedValue({});
    const { repository } = setup(send);
    const base = {
      caId,
      owner: "o",
      number: 3,
      startRevision: 1,
      published,
      clearDirty: true,
    };
    await expect(repository.commitCrlPublication(base)).resolves.toBe(
      "committed",
    );
    expect(send.mock.calls[0]![0].constructor.name).toBe("UpdateCommand");
    await expect(
      repository.commitCrlPublication({ ...base, idempotency }),
    ).resolves.toBe("committed");
    expect(send.mock.calls[1]![0].constructor.name).toBe(
      "TransactWriteCommand",
    );
    const replay = jest
      .fn()
      .mockRejectedValue(canceled("ConditionalCheckFailed", "None"));
    await expect(
      setup(replay).repository.commitCrlPublication({ ...base, idempotency }),
    ).resolves.toBe("replay");
    const lost = jest
      .fn()
      .mockRejectedValue(canceled("None", "ConditionalCheckFailed"));
    await expect(
      setup(lost).repository.commitCrlPublication({ ...base, idempotency }),
    ).resolves.toBe("conditionFailed");
  });

  it("gives expired carried revocations a TTL and ignores entries that already have one", async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        Items: [{ sk: "REVOKED#01" }, { sk: "REVOKED#02" }],
      })
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(named("ConditionalCheckFailedException"));
    const { repository } = setup(send);
    await expect(
      repository.expireCarriedRevocations(caId, "2026-11-22T10:00:00.000Z", 99),
    ).resolves.toBe(2);
    const query = send.mock.calls[0]![0].input;
    expect(query.FilterExpression).toBe(
      "#notAfter < :before AND attribute_not_exists(#ttl)",
    );
    expect(query.ConsistentRead).toBe(true);
    expect(send.mock.calls[1]![0].input.ConditionExpression).toBe(
      "attribute_exists(pk) AND attribute_not_exists(#ttl)",
    );
  });

  it("reads revocations with the since filter across pages and rejects malformed entries", async () => {
    const entry = (serial: string) => ({
      pk: `PKI_CA#${caId}`,
      sk: `REVOKED#${serial}`,
      serial,
      revokedAt: "r",
      reason: "keyCompromise",
      notAfter: "n",
    });
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        Items: [entry("01")],
        LastEvaluatedKey: { pk: "x" },
      })
      .mockResolvedValueOnce({ Items: [entry("02")] });
    const { repository } = setup(send);
    const entries = await repository.listRevocationsSince(
      caId,
      "2026-11-22T00:00:00.000Z",
    );
    expect(entries.map((item) => item.serial)).toEqual(["01", "02"]);
    expect(entries[0]).not.toHaveProperty("pk");
    expect(send.mock.calls[0]![0].input).toMatchObject({
      FilterExpression: "#notAfter >= :since",
      ConsistentRead: true,
    });
    const bad = jest.fn().mockResolvedValue({ Items: [{ serial: 1 }] });
    await expect(
      setup(bad).repository.listRevocationsSince(caId),
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it("strips keys from CA reads and rejects malformed records", async () => {
    const item = {
      pk: "p",
      sk: "PROFILE",
      pkiDirectoryPk: "PKI_CAS",
      pkiDirectorySk: "x",
      caId,
      status: "ACTIVE",
      version: "v",
      key: { state: "ACTIVE" },
    };
    const found = await setup(
      jest.fn().mockResolvedValue({ Item: item }),
    ).repository.getCa(caId);
    expect(found).toEqual({
      caId,
      status: "ACTIVE",
      version: "v",
      key: { state: "ACTIVE" },
    });
    expect(
      await setup(jest.fn().mockResolvedValue({})).repository.getCa(caId),
    ).toBeUndefined();
    await expect(
      setup(jest.fn().mockResolvedValue({ Item: { caId } })).repository.getCa(
        caId,
      ),
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it("pages a directory partition with the last evaluated key", async () => {
    const send = jest.fn().mockResolvedValue({
      Items: [{ pk: "PKI_CA#a", caId: "a" }, { pk: "OTHER#b" }],
      LastEvaluatedKey: { pk: "PKI_CA#a" },
    });
    const page = await setup(send).repository.queryDirectoryPage("PKI_CAS", {
      sortPrefix: "prod#",
      limit: 1,
    });
    expect(page.items).toHaveLength(1);
    expect(page.lastEvaluatedKey).toEqual({ pk: "PKI_CA#a" });
    expect(send.mock.calls[0]![0].input.Limit).toBe(1);
  });
});
