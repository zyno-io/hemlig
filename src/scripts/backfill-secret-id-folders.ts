import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  ScanCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { catalogPk, catalogSk } from "../repositories/dynamo";

type Item = Record<string, unknown>;

interface CatalogUpdate {
  readonly pk: string;
  readonly secretId: string;
  readonly environment: string;
  readonly controlVersionId: string;
  readonly catalogPk: string;
  readonly catalogSk: string;
}

const tableName = process.env.CONTROL_TABLE_NAME;
const apply = process.argv.includes("--apply");

if (tableName === undefined || tableName.trim().length === 0) {
  throw new Error("CONTROL_TABLE_NAME is required.");
}

const run = async (): Promise<void> => {
  const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  let candidates = 0;
  let updated = 0;
  do {
    const response = await dynamo.send(
      new ScanCommand({
        TableName: tableName,
        ExclusiveStartKey: lastEvaluatedKey as never,
      }),
    );
    for (const item of response.Items ?? []) {
      const update = catalogUpdate(item);
      if (update === undefined) {
        continue;
      }
      candidates += 1;
      if (!apply) {
        continue;
      }
      try {
        await dynamo.send(
          new UpdateCommand({
            TableName: tableName,
            Key: { pk: update.pk, sk: "HEAD" },
            UpdateExpression: "SET catalogPk = :catalogPk, catalogSk = :catalogSk",
            ConditionExpression:
              "secretId = :secretId AND environment = :environment AND controlVersionId = :controlVersionId",
            ExpressionAttributeValues: {
              ":catalogPk": update.catalogPk,
              ":catalogSk": update.catalogSk,
              ":secretId": update.secretId,
              ":environment": update.environment,
              ":controlVersionId": update.controlVersionId,
            },
          }),
        );
        updated += 1;
      } catch (error) {
        if (
          error instanceof Error &&
          error.name === "ConditionalCheckFailedException"
        ) {
          // A concurrent writer has installed a newer, correctly indexed HEAD.
          continue;
        }
        throw error;
      }
    }
    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey !== undefined);
  process.stdout.write(
    apply
      ? `Backfilled ID-derived catalog paths on ${updated} secret head(s).\n`
      : `Dry run: ${candidates} secret head(s) need ID-derived catalog paths. Re-run with --apply to write them.\n`,
  );
};

const catalogUpdate = (item: Item): CatalogUpdate | undefined => {
  const pk = stringField(item, "pk");
  const sk = stringField(item, "sk");
  const secretId = stringField(item, "secretId");
  const environment = stringField(item, "environment");
  const controlVersionId = stringField(item, "controlVersionId");
  if (
    pk === undefined ||
    !pk.startsWith("SECRET#") ||
    sk !== "HEAD" ||
    secretId === undefined ||
    environment === undefined ||
    controlVersionId === undefined
  ) {
    return undefined;
  }
  const expectedCatalogPk = catalogPk(environment);
  const expectedCatalogSk = catalogSk(secretId);
  if (
    item.catalogPk === expectedCatalogPk &&
    item.catalogSk === expectedCatalogSk
  ) {
    return undefined;
  }
  return {
    pk,
    secretId,
    environment,
    controlVersionId,
    catalogPk: expectedCatalogPk,
    catalogSk: expectedCatalogSk,
  };
};

const stringField = (
  item: Item,
  field: string,
): string | undefined => {
  const value = item[field];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

void run();
