import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  ScanCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  consumerDirectoryPk,
  identityConsumerPk,
  identityConsumerSk,
} from "../repositories/dynamo";

const tableName = process.env.CONTROL_TABLE_NAME;
const apply = process.argv.includes("--apply");

if (tableName === undefined || tableName.trim().length === 0) {
  throw new Error("CONTROL_TABLE_NAME is required.");
}

const run = async (): Promise<void> => {
  const client = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  let candidates = 0;
  let updated = 0;
  do {
    const page = await client.send(
      new ScanCommand({
        TableName: tableName,
        ExclusiveStartKey: lastEvaluatedKey as never,
      }),
    );
    for (const item of page.Items ?? []) {
      const update = indexUpdate(item);
      if (update === undefined) {
        continue;
      }
      candidates += 1;
      if (!apply) {
        continue;
      }
      await client.send(
        new UpdateCommand({
          TableName: tableName,
          ...update,
        }),
      );
      updated += 1;
    }
    lastEvaluatedKey = page.LastEvaluatedKey as
      Record<string, unknown> | undefined;
  } while (lastEvaluatedKey !== undefined);
  process.stdout.write(
    apply
      ? `Backfilled console indexes on ${updated} item(s).\n`
      : `Dry run: ${candidates} item(s) need console index attributes. Re-run with --apply to write them.\n`,
  );
};

const indexUpdate = (
  item: Record<string, unknown>,
):
  | {
      readonly Key: { readonly pk: string; readonly sk: string };
      readonly UpdateExpression: string;
      readonly ExpressionAttributeValues: Record<string, string>;
    }
  | undefined => {
  const pk = stringField(item, "pk");
  const sk = stringField(item, "sk");
  if (pk === undefined || sk === undefined) {
    return undefined;
  }
  if (sk === "PROFILE" && pk.startsWith("CONSUMER#")) {
    const consumerId = stringField(item, "consumerId");
    const environment = stringField(item, "environment");
    if (consumerId === undefined || environment === undefined) {
      return undefined;
    }
    return setIndexAttributes(
      item,
      pk,
      sk,
      "consumerDirectoryPk",
      consumerDirectoryPk(environment),
      "consumerDirectorySk",
      consumerId,
    );
  }
  if (sk === "PROFILE" && pk.startsWith("IDENTITY#")) {
    const consumerId = stringField(item, "consumerId");
    const fingerprint = stringField(item, "fingerprint");
    const notAfter = stringField(item, "notAfter");
    if (
      consumerId === undefined ||
      fingerprint === undefined ||
      notAfter === undefined
    ) {
      return undefined;
    }
    return setIndexAttributes(
      item,
      pk,
      sk,
      "identityConsumerPk",
      identityConsumerPk(consumerId),
      "identityConsumerSk",
      identityConsumerSk(notAfter, fingerprint),
    );
  }
  if (pk.startsWith("SECRET#") && sk.startsWith("CONTROL#")) {
    const serialized = item.serialized;
    if (typeof serialized !== "object" || serialized === null) {
      return undefined;
    }
    const createdAt = stringField(
      serialized as Record<string, unknown>,
      "createdAt",
    );
    const controlVersionId = stringField(
      serialized as Record<string, unknown>,
      "controlVersionId",
    );
    if (createdAt === undefined || controlVersionId === undefined) {
      return undefined;
    }
    return setIndexAttributes(
      item,
      pk,
      sk,
      "revisionPk",
      pk,
      "revisionSk",
      `${createdAt}#${controlVersionId}`,
    );
  }
  return undefined;
};

const setIndexAttributes = (
  item: Record<string, unknown>,
  pk: string,
  sk: string,
  firstName: string,
  firstValue: string,
  secondName: string,
  secondValue: string,
):
  | {
      readonly Key: { readonly pk: string; readonly sk: string };
      readonly UpdateExpression: string;
      readonly ExpressionAttributeValues: Record<string, string>;
    }
  | undefined => {
  if (item[firstName] === firstValue && item[secondName] === secondValue) {
    return undefined;
  }
  return {
    Key: { pk, sk },
    UpdateExpression: `SET ${firstName} = :first, ${secondName} = :second`,
    ExpressionAttributeValues: { ":first": firstValue, ":second": secondValue },
  };
};

const stringField = (
  value: Record<string, unknown>,
  name: string,
): string | undefined => {
  const field = value[name];
  return typeof field === "string" && field.length > 0 ? field : undefined;
};

void run();
