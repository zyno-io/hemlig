import { randomBytes } from "node:crypto";
import {
  CreateTableCommand,
  DescribeTableCommand,
  DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import {
  CreateAliasCommand,
  CreateKeyCommand,
  DescribeKeyCommand,
  KMSClient,
  ListAliasesCommand,
} from "@aws-sdk/client-kms";
import {
  CreateBucketCommand,
  HeadBucketCommand,
  PutBucketVersioningCommand,
  PutObjectLockConfigurationCommand,
  S3Client,
} from "@aws-sdk/client-s3";

/**
 * Provisions a stable local Hemlig environment in MiniStack and starts the dev
 * admin bridge against it. Idempotent: re-running reuses whatever exists.
 *
 * This is a development convenience, not a deployment path. It creates no
 * Object Lock configuration and no API Gateway, so it cannot exercise
 * retention behaviour, mTLS, CORS preflight, or the JWT authorizer. Those
 * still require an isolated AWS account.
 */
const endpoint = process.env.AWS_ENDPOINT_URL ?? "http://127.0.0.1:4566";
const region = process.env.AWS_REGION ?? "us-east-1";
const credentials = { accessKeyId: "test", secretAccessKey: "test" };
const prefix = process.env.DEV_PREFIX ?? "hml-local";
const localEnvironment = process.env.HEMLIG_ENVIRONMENT ?? "dev";

const table = `${prefix}-control`;
const revisionBucket = `${prefix}-revision`;
const auditBucket = `${prefix}-audit`;
const truststoreBucket = `${prefix}-truststore`;

const indexes = [
  ["workflow-due", "workflowDuePk", "workflowDueSk"],
  ["retention-due", "retentionDuePk", "retentionDueSk"],
  ["catalog-path", "catalogPk", "catalogSk"],
  ["consumer-directory", "consumerDirectoryPk", "consumerDirectorySk"],
  ["consumer-identity", "identityConsumerPk", "identityConsumerSk"],
  ["secret-revision", "revisionPk", "revisionSk"],
] as const;

/**
 * The mutation protocol extends Object Lock retention on the object versions it
 * replaces, so the revision and audit buckets must have Object Lock enabled or
 * every payload write fails. Object Lock can only be turned on at creation.
 *
 * Retention is one day locally rather than the deployed 90 days and seven
 * years: COMPLIANCE mode cannot be shortened or removed, so a realistic value
 * would leave undeletable objects on a developer machine. `yarn ministack:down`
 * discards the whole volume regardless.
 */
const ensureBucket = async (
  s3: S3Client,
  name: string,
  objectLock: boolean,
): Promise<void> => {
  try {
    await s3.send(new HeadBucketCommand({ Bucket: name }));
    return;
  } catch {
    // Absent; create it below.
  }
  await s3.send(
    new CreateBucketCommand({ Bucket: name, ObjectLockEnabledForBucket: objectLock }),
  );
  await s3.send(
    new PutBucketVersioningCommand({
      Bucket: name,
      VersioningConfiguration: { Status: "Enabled" },
    }),
  );
  if (objectLock) {
    await s3.send(
      new PutObjectLockConfigurationCommand({
        Bucket: name,
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: { DefaultRetention: { Mode: "COMPLIANCE", Days: 1 } },
        },
      }),
    );
  }
  process.stdout.write(
    `created bucket ${name}${objectLock ? " (object lock)" : ""}\n`,
  );
};

const ensureTable = async (dynamo: DynamoDBClient): Promise<void> => {
  try {
    await dynamo.send(new DescribeTableCommand({ TableName: table }));
    return;
  } catch {
    // Absent; create it below.
  }
  const attributeNames = new Set(["pk", "sk", ...indexes.flatMap(([, pk, sk]) => [pk, sk])]);
  await dynamo.send(
    new CreateTableCommand({
      TableName: table,
      BillingMode: "PAY_PER_REQUEST",
      AttributeDefinitions: [...attributeNames].map((name) => ({
        AttributeName: name,
        AttributeType: "S" as const,
      })),
      KeySchema: [
        { AttributeName: "pk", KeyType: "HASH" },
        { AttributeName: "sk", KeyType: "RANGE" },
      ],
      GlobalSecondaryIndexes: indexes.map(([indexName, pk, sk]) => ({
        IndexName: indexName,
        KeySchema: [
          { AttributeName: pk, KeyType: "HASH" as const },
          { AttributeName: sk, KeyType: "RANGE" as const },
        ],
        Projection: { ProjectionType: "ALL" as const },
      })),
    }),
  );
  process.stdout.write(`created table ${table}\n`);
};

/** Returns the key ARN, which is what the envelope codec addresses. */
const ensureKey = async (kms: KMSClient): Promise<string> => {
  const alias = `alias/${prefix}-application`;
  const aliases = await kms.send(new ListAliasesCommand({}));
  const existing = aliases.Aliases?.find((entry) => entry.AliasName === alias);
  if (existing?.TargetKeyId !== undefined) {
    const described = await kms.send(
      new DescribeKeyCommand({ KeyId: existing.TargetKeyId }),
    );
    const arn = described.KeyMetadata?.Arn;
    if (arn !== undefined) {
      return arn;
    }
  }
  const created = await kms.send(
    new CreateKeyCommand({ Description: `Hemlig local key for ${prefix}` }),
  );
  const keyId = created.KeyMetadata?.KeyId;
  const keyArn = created.KeyMetadata?.Arn;
  if (keyId === undefined || keyArn === undefined) {
    throw new Error("MiniStack KMS did not return a key ARN.");
  }
  await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }));
  process.stdout.write(`created key ${alias}\n`);
  return keyArn;
};

const run = async (): Promise<void> => {
  const s3 = new S3Client({ endpoint, region, credentials, forcePathStyle: true });
  const dynamo = new DynamoDBClient({ endpoint, region, credentials });
  const kms = new KMSClient({ endpoint, region, credentials });

  await Promise.all([
    ensureBucket(s3, revisionBucket, true),
    ensureBucket(s3, auditBucket, true),
    // The truststore bucket is versioned but not locked, matching the stack.
    ensureBucket(s3, truststoreBucket, false),
  ]);
  await ensureTable(dynamo);
  const keyArn = await ensureKey(kms);

  // An ambient AWS_PROFILE outranks static credentials in the SDK's default
  // chain. Local development must never depend on, or reach for, whichever
  // real account the developer happens to have selected.
  delete process.env.AWS_PROFILE;
  delete process.env.AWS_SDK_LOAD_CONFIG;

  // The handler reads its whole configuration from the environment, so the
  // bridge runs against exactly the same code path as the deployed Lambda.
  Object.assign(process.env, {
    AWS_ENDPOINT_URL: endpoint,
    AWS_REGION: region,
    AWS_ACCESS_KEY_ID: credentials.accessKeyId,
    AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
    CONTROL_TABLE_NAME: table,
    WORKFLOW_DUE_INDEX: "workflow-due",
    RETENTION_DUE_INDEX: "retention-due",
    CATALOG_PATH_INDEX: "catalog-path",
    CONSUMER_DIRECTORY_INDEX: "consumer-directory",
    CONSUMER_IDENTITY_INDEX: "consumer-identity",
    SECRET_REVISION_INDEX: "secret-revision",
    REVISION_BUCKET_NAME: revisionBucket,
    TRUSTSTORE_BUCKET_NAME: truststoreBucket,
    TRUSTSTORE_KEY_PREFIX: "truststores",
    PAYLOAD_KMS_KEY_ARN: keyArn,
    AUDIT_BUCKET_NAME: auditBucket,
    AUDIT_PREFIX: "audit",
    HEMLIG_ENVIRONMENT: localEnvironment,
    DELIVERY_API_CUSTOM_DOMAIN_NAME: "api.local.test",
    DELIVERY_API_HOSTNAME: "api.local.test",
    CURSOR_HMAC_KEY:
      process.env.CURSOR_HMAC_KEY ?? randomBytes(48).toString("base64"),
    ADMIN_JWT_ISSUER: process.env.ADMIN_JWT_ISSUER ?? "https://local.test/issuer",
    ADMIN_JWT_AUDIENCE: process.env.ADMIN_JWT_AUDIENCE ?? "hemlig-local",
    ADMIN_ACTOR_SUBJECT_CLAIM: "sub",
    MAX_PAYLOAD_BYTES: "768000",
  });

  // Imported after the environment is set: the handler builds its application
  // from process.env on first use.
  const { startBridge } = await import("./dev-admin-bridge");
  startBridge();
};

void run();
