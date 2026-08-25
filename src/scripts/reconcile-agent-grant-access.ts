import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { KMSClient } from "@aws-sdk/client-kms";
import { S3Client } from "@aws-sdk/client-s3";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../aws/config";
import { EnvelopeCrypto } from "../crypto/envelope";
import type { Actor } from "../domain/types";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { EnvironmentService } from "../services/environments";
import { SecretService } from "../services/secrets";

const maintenanceActor: Actor = {
  type: "system",
  id: "maintenance:reconcile-agent-grant-access",
};

interface AgentGrantAccessReconciler {
  readonly repository: Pick<DynamoRepository, "listAgentGrants">;
  readonly secrets: Pick<SecretService, "reconcileAgentReadAccess">;
}

/**
 * Rebuilds the delivery ACL projection from every active canonical AgentGrant.
 * This removes pre-migration ACL-only access and repairs retries safely.
 */
export const reconcileAgentGrantAccess = async (
  application: AgentGrantAccessReconciler,
  actor: Actor = maintenanceActor,
): Promise<number> => {
  let reconciled = 0;
  let nextKey: Record<string, unknown> | undefined;
  do {
    const page = await application.repository.listAgentGrants(nextKey);
    for (const grant of page.grants) {
      if (grant.status !== "ACTIVE") {
        continue;
      }
      await application.secrets.reconcileAgentReadAccess({
        consumerId: grant.consumerId,
        environment: grant.environment,
        secretGrants: grant.secretGrants,
        actor,
      });
      reconciled += 1;
    }
    nextKey = page.nextKey;
  } while (nextKey !== undefined);
  return reconciled;
};

const run = async (): Promise<void> => {
  if (process.env.HEMLIG_UPGRADE_QUIESCED !== "1") {
    throw new Error(
      "Refusing to reconcile before the service is quiesced. Set HEMLIG_UPGRADE_QUIESCED=1 only after following the upgrade guide.",
    );
  }
  const config = maintenanceConfig();
  const common = { region: config.region };
  const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient(common), {
    marshallOptions: { removeUndefinedValues: true },
  });
  const repository = new DynamoRepository(dynamo, config);
  const objects = new ObjectStore(new S3Client(common));
  const crypto = new EnvelopeCrypto(new KMSClient(common), config);
  const environments = new EnvironmentService(repository);
  const secrets = new SecretService(
    repository,
    objects,
    crypto,
    config,
    environments,
  );
  const reconciled = await reconcileAgentGrantAccess({ repository, secrets });
  process.stdout.write(
    `Reconciled derived delivery access for ${reconciled} active AgentGrant(s).\n`,
  );
};

/** Only the two storage coordinates are used by an ACL-only reconciliation. */
const maintenanceConfig = (): AppConfig => {
  const region = process.env.AWS_REGION ?? "us-east-1";
  return {
    region,
    environmentName: "maintenance",
    controlTableName: requiredEnvironment("CONTROL_TABLE_NAME"),
    workflowDueIndex: "unused",
    retentionDueIndex: "unused",
    catalogPathIndex: "unused",
    consumerDirectoryIndex: "unused",
    consumerIdentityIndex: "unused",
    secretRevisionIndex: "unused",
    revisionBucketName: requiredEnvironment("REVISION_BUCKET_NAME"),
    truststoreBucketName: "unused",
    truststoreKeyPrefix: "unused",
    payloadKmsKeyArn: "unused",
    auditBucketName: "unused",
    auditPrefix: "unused",
    deliveryApiCustomDomainName: "unused",
    deliveryApiHostname: "unused",
    iotEndpoint: "unused",
    iotNotificationPolicyName: "unused",
    iotNotificationTopicPrefix: "unused",
    adminJwtIssuer: "unused",
    adminJwtAudience: "unused",
    adminActorSubjectClaim: "unused",
    maxPayloadBytes: 1,
  };
};

const requiredEnvironment = (name: string): string => {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
};

if (require.main === module) {
  void run();
}
