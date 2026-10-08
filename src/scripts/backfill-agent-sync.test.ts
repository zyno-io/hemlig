import {
  GetCommand,
  QueryCommand,
  ScanCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";
import { backfillAgentSync } from "./backfill-agent-sync";

const fixture = () => {
  let head = {
    pk: "SECRET#uid",
    sk: "HEAD",
    secretUid: "uid",
    secretId: "name",
    environment: "prod",
    controlVersionId: "ctl-1",
    workflowState: "READY",
    state: "ACTIVE",
  };
  let state: Record<string, unknown> | undefined;
  let omitControl = false;
  let race = false;
  const transactions: TransactWriteCommand[] = [];
  const send = jest.fn(async (command: unknown) => {
    if (command instanceof QueryCommand) return { Items: [{ name: "prod" }] };
    if (command instanceof ScanCommand) return { Items: [head] };
    if (command instanceof GetCommand) {
      if (command.input.Key?.sk === "STATE") return { Item: state };
      if (command.input.Key?.sk === "HEAD") return { Item: head };
      return {
        Item: omitControl
          ? undefined
          : {
              serialized: {
                schemaVersion: 1,
                secretUid: "uid",
                secretId: "name",
                environment: "prod",
                controlVersionId: head.controlVersionId,
                state: "ACTIVE",
                metadata: {},
                acl: [{ consumerId: "c", permissions: ["read"] }],
              },
            },
      };
    }
    if (command instanceof TransactWriteCommand) {
      transactions.push(command);
      if (race) {
        race = false;
        head = { ...head, controlVersionId: "ctl-2" };
        throw Object.assign(new Error("revision moved"), {
          name: "TransactionCanceledException",
          CancellationReasons: [
            { Code: "None" },
            { Code: "ConditionalCheckFailed" },
          ],
        });
      }
      state = command.input.TransactItems?.[0]?.Put?.Item;
      return {};
    }
    if (command instanceof UpdateCommand) {
      state = { ...state, ready: true };
      return {};
    }
    throw new Error("unexpected command");
  });
  const dynamo = { send } as unknown as DynamoDBDocumentClient;
  return {
    dynamo,
    send,
    transactions,
    state: () => state,
    omitControl: () => {
      omitControl = true;
    },
    race: () => {
      race = true;
    },
  };
};

it("dry-runs metadata inspection without writes or readiness changes", async () => {
  const f = fixture();
  const result = await backfillAgentSync(f.dynamo, "table", false);
  expect(result).toEqual({ heads: 1, environments: 1 });
  expect(f.transactions).toHaveLength(0);
  expect(
    f.send.mock.calls.every(
      (call) =>
        call[0] instanceof QueryCommand || call[0] instanceof ScanCommand,
    ),
  ).toBe(true);
});

it("publishes current metadata and enables readiness only after a complete backfill", async () => {
  const f = fixture();
  await backfillAgentSync(f.dynamo, "table", true);
  const projection = f.transactions[0]?.input.TransactItems?.find((item) =>
    String(item.Put?.Item?.sk).startsWith("CHANGE#"),
  )?.Put?.Item;
  expect(projection).toMatchObject({
    secretUid: "uid",
    controlVersionId: "ctl-1",
    readConsumerIds: ["c"],
  });
  expect(projection).not.toHaveProperty("payload");
  expect(f.state()?.ready).toBe(true);
});

it("does not declare an index ready when a current control cannot be recovered", async () => {
  const f = fixture();
  f.omitControl();
  await expect(
    backfillAgentSync(f.dynamo, "table", true),
  ).rejects.toMatchObject({ code: "sync_backfill_incomplete" });
  expect(f.state()?.ready).not.toBe(true);
});

it("rereads a concurrently changed revision instead of overwriting it", async () => {
  const f = fixture();
  f.race();
  await backfillAgentSync(f.dynamo, "table", true);
  const projection = f.transactions
    .at(-1)
    ?.input.TransactItems?.find((item) =>
      String(item.Put?.Item?.sk).startsWith("CHANGE#"),
    )?.Put?.Item;
  expect(projection?.controlVersionId).toBe("ctl-2");
  expect(f.state()?.ready).toBe(true);
});
