import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  type DynamoDBDocumentClient,
  type TransactWriteCommandInput,
} from "@aws-sdk/lib-dynamodb";
import {
  AgentSyncRepository,
  syncPk,
  syncSk,
  type AgentSyncRecord,
} from "./agent-sync";

const record: AgentSyncRecord = {
  secretUid: "uid",
  secretId: "name",
  controlVersionId: "ctl",
  payloadVersionId: "pay",
  state: "ACTIVE",
  metadata: {},
  readConsumerIds: ["consumer"],
};
const cancellation = (codes: string[]) =>
  Object.assign(new Error("transaction cancelled"), {
    name: "TransactionCanceledException",
    CancellationReasons: codes.map((Code) => ({ Code })),
  });

const fixture = () => {
  const rows = new Map<string, Record<string, unknown>>();
  const key = (item: Record<string, unknown>) => `${item.pk}/${item.sk}`;
  const transactions: TransactWriteCommandInput[] = [];
  let reject: Error | undefined;
  const send = jest.fn(async (command: unknown) => {
    if (command instanceof GetCommand)
      return { Item: rows.get(key(command.input.Key ?? {})) };
    if (command instanceof TransactWriteCommand) {
      transactions.push(command.input);
      if (reject !== undefined) {
        const error = reject;
        reject = undefined;
        throw error;
      }
      const staged = new Map(rows);
      for (const [index, action] of (
        command.input.TransactItems ?? []
      ).entries()) {
        if (action.Put !== undefined) {
          const item = action.Put.Item ?? {};
          if (index === 0 && rows.has(key(item)))
            throw cancellation(["ConditionalCheckFailed"]);
          staged.set(key(item), { ...item });
        } else if (action.Delete !== undefined)
          staged.delete(key(action.Delete.Key ?? {}));
        else if (action.Update !== undefined) {
          const itemKey = key(action.Update.Key ?? {});
          const current = rows.get(itemKey) ?? {};
          const values = action.Update.ExpressionAttributeValues ?? {};
          if (
            index === 0 &&
            (current.sequence !== values[":prior"] ||
              current.epoch !== values[":epoch"])
          )
            throw cancellation(["ConditionalCheckFailed"]);
          staged.set(
            itemKey,
            index === 0
              ? { ...current, sequence: values[":next"] }
              : { ...current, syncSequence: values[":sequence"] },
          );
        }
      }
      rows.clear();
      for (const [itemKey, item] of staged) rows.set(itemKey, item);
      return {};
    }
    throw new Error("unexpected test command");
  });
  const repository = new AgentSyncRepository(
    { send } as unknown as DynamoDBDocumentClient,
    "table",
  );
  const publish = (controlVersionId: string) =>
    repository.publish("prod", { ...record, controlVersionId }, (sequence) => [
      {
        Update: {
          TableName: "table",
          Key: { pk: "SECRET#uid", sk: "HEAD" },
          UpdateExpression: "SET syncSequence = :sequence",
          ExpressionAttributeValues: { ":sequence": sequence },
        },
      },
    ]);
  return {
    rows,
    repository,
    send,
    publish,
    transactions,
    rejectNext: (error: Error) => {
      reject = error;
    },
  };
};

it("atomically publishes a committed sequence and coalesces repeated updates to one current entry", async () => {
  const f = fixture();
  await f.publish("first");
  expect(f.rows.get(`${syncPk("prod")}/STATE`)).toMatchObject({
    sequence: 1,
    ready: false,
  });
  expect(f.rows.get("SECRET#uid/HEAD")).toMatchObject({ syncSequence: 1 });
  await f.publish("second");
  const entries = [...f.rows.values()].filter((item) =>
    String(item.sk).startsWith("CHANGE#"),
  );
  expect(entries).toHaveLength(1);
  expect(entries[0]).toMatchObject({
    sk: syncSk(2, "uid"),
    controlVersionId: "second",
  });
  expect(f.rows.get(`${syncPk("prod")}/STATE`)).toMatchObject({ sequence: 2 });
  expect(f.rows.get("SECRET#uid/HEAD")).toMatchObject({ syncSequence: 2 });
  expect(entries[0]).not.toHaveProperty("ttl");
});

it("never advances a checkpoint or removes its previous entry when publication fails", async () => {
  const f = fixture();
  await f.publish("first");
  const before = [...f.rows.entries()];
  f.rejectNext(cancellation(["None", "ConditionalCheckFailed"]));
  await expect(f.publish("failed")).rejects.toMatchObject({
    name: "TransactionCanceledException",
  });
  expect([...f.rows.entries()]).toEqual(before);
  expect(f.transactions).toHaveLength(2);
});

it("retries counter contention while preserving one current entry", async () => {
  const f = fixture();
  await f.publish("first");
  f.rejectNext(cancellation(["ConditionalCheckFailed", "None"]));
  await f.publish("next");
  expect(f.transactions).toHaveLength(3);
  expect(f.rows.get(`${syncPk("prod")}/STATE`)).toMatchObject({ sequence: 2 });
  expect(
    [...f.rows.values()].filter((item) =>
      String(item.sk).startsWith("CHANGE#"),
    ),
  ).toHaveLength(1);
});

it("serializes competing secret publications without losing either committed change", async () => {
  const f = fixture();
  await Promise.all([
    f.publish("first"),
    f.repository.publish(
      "prod",
      { ...record, secretUid: "second", controlVersionId: "second" },
      (sequence) => [
        {
          Update: {
            TableName: "table",
            Key: { pk: "SECRET#second", sk: "HEAD" },
            UpdateExpression: "SET syncSequence = :sequence",
            ExpressionAttributeValues: { ":sequence": sequence },
          },
        },
      ],
    ),
  ]);
  expect(f.rows.get(`${syncPk("prod")}/STATE`)).toMatchObject({ sequence: 2 });
  const entries = [...f.rows.values()].filter((item) =>
    String(item.sk).startsWith("CHANGE#"),
  );
  expect(new Set(entries.map((item) => item.controlVersionId))).toEqual(
    new Set(["first", "second"]),
  );
  expect(
    new Set([
      f.rows.get("SECRET#uid/HEAD")?.syncSequence,
      f.rows.get("SECRET#second/HEAD")?.syncSequence,
    ]),
  ).toEqual(new Set([1, 2]));
});

it("retains archived revocation markers beyond the maximum checkpoint lifetime", async () => {
  const f = fixture();
  await f.repository.publish(
    "prod",
    { ...record, state: "ARCHIVED" },
    () => [],
  );
  const marker = f.rows.get(`${syncPk("prod")}/${syncSk(1, "uid")}`);
  expect(Number(marker?.ttl) - Date.now() / 1_000).toBeGreaterThan(
    7 * 24 * 60 * 60,
  );
});

it("does not query an unchanged frontier and queries bounded primary-key ranges strongly", async () => {
  const send = jest.fn(async (_command: unknown) => ({
    Items: [],
    LastEvaluatedKey: { pk: syncPk("prod"), sk: "last" },
  }));
  const repository = new AgentSyncRepository(
    { send } as unknown as DynamoDBDocumentClient,
    "table",
  );
  const empty = await repository.page("prod", 5, 5);
  expect(empty.records).toEqual([]);
  expect(send).not.toHaveBeenCalled();
  const page = await repository.page("prod", 5, 10, "prior");
  expect(page.lastSk).toBe("last");
  const command = send.mock.calls[0]?.[0] as QueryCommand | undefined;
  expect(command?.input).toMatchObject({
    ConsistentRead: true,
    Limit: 100,
    ExclusiveStartKey: { pk: syncPk("prod"), sk: "prior" },
  });
  expect(command?.input.IndexName).toBeUndefined();
  expect(command?.input.ExpressionAttributeValues?.[":first"]).toBe(
    syncSk(6, ""),
  );
});

it("refuses oversized transactions before a partial write", async () => {
  const f = fixture();
  await expect(
    f.repository.publish("prod", record, () =>
      Array.from({ length: 99 }, (_, i) => ({
        Put: { TableName: "table", Item: { pk: String(i), sk: "row" } },
      })),
    ),
  ).rejects.toMatchObject({ statusCode: 503 });
  expect(f.transactions).toHaveLength(0);
  expect(f.rows.size).toBe(0);
});
