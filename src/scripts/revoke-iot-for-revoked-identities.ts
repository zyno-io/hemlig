import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { IoTClient } from "@aws-sdk/client-iot";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";
import type { AgentNotificationService } from "../services/agent-notifications";
import { AgentNotificationService as Notifications } from "../services/agent-notifications";

/**
 * Revokes the AWS IoT certificate of every REVOKED API identity. Identities
 * revoked before the API revoked IoT certificates stay ACTIVE in IoT.
 * Idempotent; a certificate that was never registered counts as revoked.
 * Output contains counts only.
 */
export const revokeIotForRevokedIdentities = async (
  dynamo: Pick<DynamoDBDocumentClient, "send">,
  tableName: string,
  notifications: Pick<AgentNotificationService, "revoke">,
  dryRun: boolean,
): Promise<number> => {
  let count = 0;
  let exclusiveStartKey: Record<string, unknown> | undefined;
  do {
    const page = await dynamo.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression:
          "begins_with(pk, :prefix) AND sk = :profile AND kind = :api AND #status = :revoked",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":prefix": "IDENTITY#",
          ":profile": "PROFILE",
          ":api": "api",
          ":revoked": "REVOKED",
        },
        ProjectionExpression: "fingerprint",
        ExclusiveStartKey: exclusiveStartKey,
        ConsistentRead: true,
      }),
    );
    for (const item of (page.Items ?? []) as { fingerprint: string }[]) {
      count += 1;
      if (!dryRun) {
        await notifications.revoke(item.fingerprint);
      }
    }
    exclusiveStartKey = page.LastEvaluatedKey;
  } while (exclusiveStartKey !== undefined);
  return count;
};

const run = async (): Promise<void> => {
  const tableName = process.env.CONTROL_TABLE_NAME;
  if (tableName === undefined || tableName.trim().length === 0) {
    throw new Error("CONTROL_TABLE_NAME is required.");
  }
  const dryRun = process.argv.includes("--dry-run");
  const region = process.env.AWS_REGION ?? "us-east-1";
  const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));
  // The policy name is unused by revoke().
  const notifications = new Notifications(new IoTClient({ region }), "unused");
  const count = await revokeIotForRevokedIdentities(
    dynamo,
    tableName,
    notifications,
    dryRun,
  );
  process.stdout.write(
    `${dryRun ? "Would revoke" : "Revoked"} the AWS IoT certificate of ${count} revoked API identit${count === 1 ? "y" : "ies"}.\n`,
  );
};

if (require.main === module) {
  void run().catch((error: unknown) => {
    process.stderr.write(`${String(error)}\n`);
    process.exitCode = 1;
  });
}
