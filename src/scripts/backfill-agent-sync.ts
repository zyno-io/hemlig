import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  ScanCommand,
} from "@aws-sdk/lib-dynamodb";
import type { EnvironmentRecord, HeadRecord } from "../domain/types";
import { AgentSyncRepository } from "../repositories/agent-sync";

/** Dry-run by default. Output contains counts only, never control contents. */
export const backfillAgentSync = async (
  dynamo: DynamoDBDocumentClient,
  tableName: string,
  apply: boolean,
): Promise<{ heads: number; environments: number }> => {
  const sync = new AgentSyncRepository(dynamo, tableName);
  const environments: EnvironmentRecord[] = [];
  let registryKey: Record<string, unknown> | undefined;
  do {
    const page = await dynamo.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": "SYSTEM#ENVIRONMENTS",
          ":prefix": "ENVIRONMENT#",
        },
        ConsistentRead: true,
        ExclusiveStartKey: registryKey,
      }),
    );
    environments.push(...((page.Items ?? []) as EnvironmentRecord[]));
    registryKey = page.LastEvaluatedKey;
  } while (registryKey !== undefined);
  const knownEnvironments = new Set(environments.map((record) => record.name));
  let scanKey: Record<string, unknown> | undefined;
  let heads = 0;
  do {
    const page = await dynamo.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: "sk = :head AND workflowState = :ready",
        ExpressionAttributeValues: { ":head": "HEAD", ":ready": "READY" },
        ProjectionExpression:
          "pk, sk, secretUid, environment, controlVersionId",
        ExclusiveStartKey: scanKey,
        ConsistentRead: true,
      }),
    );
    for (const candidate of (page.Items ?? []) as HeadRecord[]) {
      if (
        !knownEnvironments.has(candidate.environment) ||
        !candidate.pk.startsWith("SECRET#") ||
        candidate.secretUid === undefined
      )
        throw new Error(
          "A head needs identity/environment migration before sync backfill.",
        );
      heads += 1;
      if (!apply) continue;
      // Reread after each race; publication refuses to replace a newer revision.
      let published = false;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const response = await dynamo.send(
          new GetCommand({
            TableName: tableName,
            Key: { pk: candidate.pk, sk: "HEAD" },
            ConsistentRead: true,
          }),
        );
        const head = response.Item as HeadRecord | undefined;
        if (head === undefined)
          throw new Error("A head disappeared during sync backfill.");
        try {
          await sync.backfillHead(head);
          published = true;
          break;
        } catch (error) {
          if (!revisionRace(error)) throw error;
        }
      }
      if (!published)
        throw new Error(
          "A changing head could not be backfilled; rerun before enabling sync.",
        );
    }
    scanKey = page.LastEvaluatedKey;
  } while (scanKey !== undefined);
  if (apply)
    for (const environment of environments)
      await sync.markReady(environment.name);
  return { heads, environments: environments.length };
};

const revisionRace = (error: unknown): boolean => {
  if (error === null || typeof error !== "object") return false;
  const transaction = error as {
    name?: string;
    CancellationReasons?: { Code?: string }[];
  };
  return (
    transaction.name === "TransactionCanceledException" &&
    transaction.CancellationReasons?.[1]?.Code === "ConditionalCheckFailed"
  );
};

if (require.main === module) {
  const tableName = process.env.CONTROL_TABLE_NAME;
  if (tableName === undefined || tableName.trim() === "")
    throw new Error("CONTROL_TABLE_NAME is required.");
  const apply = process.argv.includes("--apply");
  const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  void backfillAgentSync(dynamo, tableName, apply)
    .then((result) => {
      process.stdout.write(
        `${JSON.stringify({ mode: apply ? "apply" : "dry-run", ...result })}\n`,
      );
    })
    .catch(() => {
      process.stderr.write(
        "Agent sync backfill did not complete. Index readiness was not enabled for this run.\n",
      );
      process.exitCode = 1;
    });
}
