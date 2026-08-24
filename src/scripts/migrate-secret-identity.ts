import {
  CopyObjectCommand,
  GetObjectRetentionCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  ScanCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { isDeepStrictEqual } from "node:util";

type Item = Record<string, unknown>;

interface ObjectCopy {
  readonly sourceKey: string;
  readonly sourceVersionId: string;
  readonly destinationKey: string;
  destinationVersionId?: string;
}

interface SecretMove {
  readonly source: Item;
  readonly secretId: string;
  readonly environment: string;
  readonly sourcePk: string;
  readonly targetPk: string;
}

interface AccessMove {
  readonly source: Item;
  readonly secretId: string;
  readonly environment: string;
  readonly sourcePk: string;
  readonly sourceSk: string;
  readonly targetSk: string;
}

interface NotificationBackfill {
  readonly eventId: string;
  readonly environment: string;
}

interface MigrationPlan {
  readonly secretMoves: readonly SecretMove[];
  readonly accessMoves: readonly AccessMove[];
  readonly copies: readonly ObjectCopy[];
  readonly pendingNotifications: number;
  readonly notificationBackfills: readonly NotificationBackfill[];
}

const tableName = requiredEnvironment("CONTROL_TABLE_NAME");
const revisionBucketName = requiredEnvironment("REVISION_BUCKET_NAME");
const apply = process.argv.includes("--apply");

const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

const run = async (): Promise<void> => {
  if (apply && process.env.HEMLIG_UPGRADE_QUIESCED !== "1") {
    throw new Error(
      "Refusing to write before the service is quiesced. Set HEMLIG_UPGRADE_QUIESCED=1 only after following the upgrade guide.",
    );
  }
  const items = await scanItems();
  const plan = buildPlan(items);
  printPlan(plan);
  if (!apply || plan.secretMoves.length === 0) {
    return;
  }
  for (const copy of plan.copies) {
    await ensureCopied(copy);
  }
  const orderedSecretMoves = [...plan.secretMoves].sort(
    (left, right) =>
      Number(left.source.sk === "HEAD") - Number(right.source.sk === "HEAD"),
  );
  for (const move of orderedSecretMoves) {
    await moveSecretItem(move, plan.copies);
  }
  for (const move of plan.accessMoves) {
    await moveAccessItem(move);
  }
  for (const backfill of plan.notificationBackfills) {
    await backfillNotificationEnvironment(backfill);
  }
  await verifyMigration(plan);
  process.stdout.write("Secret identity migration completed successfully.\n");
};

const buildPlan = (items: readonly Item[]): MigrationPlan => {
  const legacySecretItems = items.filter((item) =>
    legacySecretId(stringField(item, "pk")),
  );
  const legacyAccessItems = items.filter((item) => isLegacyAccessItem(item));
  const pendingNotifications = items.filter(
    (item) =>
      stringField(item, "pk")?.startsWith("NOTIFICATION#") === true &&
      stringField(item, "status") === "PENDING",
  ).length;
  if (legacySecretItems.length === 0) {
    if (legacyAccessItems.length !== 0) {
      throw new Error(
        "Found legacy consumer access records without legacy secret records.",
      );
    }
    return {
      secretMoves: [],
      accessMoves: [],
      copies: [],
      pendingNotifications,
      notificationBackfills: [],
    };
  }

  const environmentsBySecretId = environmentByLegacySecretId(legacySecretItems);
  const secretMoves = legacySecretItems.map((source) => {
    const sourcePk = requiredString(source, "pk");
    const secretId = requiredLegacySecretId(sourcePk);
    const environment = environmentsBySecretId.get(secretId);
    if (environment === undefined) {
      throw new Error(
        `No HEAD environment was found for legacy secret ${secretId}.`,
      );
    }
    return {
      source,
      secretId,
      environment,
      sourcePk,
      targetPk: secretPk(environment, secretId),
    };
  });
  const destinationSecretPks = new Set(
    secretMoves.map((move) => move.targetPk),
  );
  const unexpectedScopedItems = items.filter((item) => {
    const pk = stringField(item, "pk");
    return (
      pk !== undefined &&
      scopedSecretId(pk) !== undefined &&
      !destinationSecretPks.has(pk)
    );
  });
  if (unexpectedScopedItems.length !== 0) {
    throw new Error(
      "Found scoped secret records that do not belong to this legacy migration.",
    );
  }

  const accessMoves = legacyAccessItems.map((source) => {
    const environment = requiredString(source, "environment");
    const secretId = requiredString(source, "secretId");
    const knownEnvironment = environmentsBySecretId.get(secretId);
    if (knownEnvironment !== environment) {
      throw new Error(
        `Legacy consumer access does not match the HEAD environment for secret ${secretId}.`,
      );
    }
    return {
      source,
      secretId,
      environment,
      sourcePk: requiredString(source, "pk"),
      sourceSk: requiredString(source, "sk"),
      targetSk: accessSk(environment, secretId),
    };
  });
  const notificationBackfills = items
    .filter(
      (item) =>
        stringField(item, "pk")?.startsWith("NOTIFICATION#") === true &&
        stringField(item, "status") === "PENDING",
    )
    .flatMap((item): NotificationBackfill[] => {
      const eventId = requiredString(item, "eventId");
      const secretId = requiredString(item, "secretId");
      const environment = environmentsBySecretId.get(secretId);
      if (environment === undefined) {
        throw new Error(
          `Pending notification ${eventId} refers to a secret without a HEAD record.`,
        );
      }
      const storedEnvironment = stringField(item, "environment");
      if (
        storedEnvironment !== undefined &&
        storedEnvironment !== environment
      ) {
        throw new Error(
          `Pending notification ${eventId} has a mismatched environment.`,
        );
      }
      return storedEnvironment === undefined ? [{ eventId, environment }] : [];
    });

  const copiesBySource = new Map<string, ObjectCopy>();
  for (const move of secretMoves) {
    addItemObjectCopy(move, copiesBySource);
    addHeadObjectCopies(move, copiesBySource);
  }
  return {
    secretMoves,
    accessMoves,
    copies: [...copiesBySource.values()],
    pendingNotifications,
    notificationBackfills,
  };
};

const environmentByLegacySecretId = (
  items: readonly Item[],
): ReadonlyMap<string, string> => {
  const environments = new Map<string, string>();
  for (const item of items) {
    if (stringField(item, "sk") !== "HEAD") {
      continue;
    }
    const secretId = requiredLegacySecretId(requiredString(item, "pk"));
    const fieldSecretId = requiredString(item, "secretId");
    if (fieldSecretId !== secretId) {
      throw new Error(
        `HEAD secret ID does not match its primary key for ${secretId}.`,
      );
    }
    const environment = requiredString(item, "environment");
    const prior = environments.get(secretId);
    if (prior !== undefined && prior !== environment) {
      throw new Error(
        `Legacy secret ${secretId} has conflicting environments.`,
      );
    }
    environments.set(secretId, environment);
  }
  const secretIds = new Set(
    items.map((item) => requiredLegacySecretId(requiredString(item, "pk"))),
  );
  for (const secretId of secretIds) {
    if (!environments.has(secretId)) {
      throw new Error(`Legacy secret ${secretId} has no HEAD record.`);
    }
  }
  return environments;
};

const addItemObjectCopy = (
  move: SecretMove,
  copies: Map<string, ObjectCopy>,
): void => {
  const objectKey = stringField(move.source, "objectKey");
  const objectVersionId = stringField(move.source, "s3VersionId");
  if (objectKey === undefined && objectVersionId === undefined) {
    return;
  }
  if (objectKey === undefined || objectVersionId === undefined) {
    throw new Error(
      `Secret ${move.secretId} has an incomplete immutable object reference.`,
    );
  }
  addCopy(move, objectKey, objectVersionId, copies);
};

const addHeadObjectCopies = (
  move: SecretMove,
  copies: Map<string, ObjectCopy>,
): void => {
  if (stringField(move.source, "sk") !== "HEAD") {
    return;
  }
  addHeadObjectCopy(
    move,
    "control",
    "controlVersionId",
    "controlObjectVersionId",
    copies,
  );
  addHeadObjectCopy(
    move,
    "payload",
    "payloadVersionId",
    "payloadObjectVersionId",
    copies,
  );
};

const addHeadObjectCopy = (
  move: SecretMove,
  kind: "control" | "payload",
  revisionField: string,
  objectVersionField: string,
  copies: Map<string, ObjectCopy>,
): void => {
  const revisionId = stringField(move.source, revisionField);
  const objectVersionId = stringField(move.source, objectVersionField);
  if (revisionId === undefined && objectVersionId === undefined) {
    return;
  }
  if (revisionId === undefined || objectVersionId === undefined) {
    throw new Error(
      `HEAD for secret ${move.secretId} has an incomplete ${kind} object reference.`,
    );
  }
  addCopy(
    move,
    `secrets/${move.secretId}/${kind}/${revisionId}.json`,
    objectVersionId,
    copies,
  );
};

const addCopy = (
  move: SecretMove,
  sourceKey: string,
  sourceVersionId: string,
  copies: Map<string, ObjectCopy>,
): void => {
  const sourcePrefix = `secrets/${move.secretId}/`;
  if (!sourceKey.startsWith(sourcePrefix)) {
    throw new Error(
      `Immutable object ${sourceKey} is outside the legacy prefix for secret ${move.secretId}.`,
    );
  }
  const suffix = sourceKey.slice(sourcePrefix.length);
  if (!/^(control|payload)\/(ctl|pay)-[^/]+\.json$/.test(suffix)) {
    throw new Error(`Unexpected legacy revision object key ${sourceKey}.`);
  }
  const sourceId = objectId(sourceKey, sourceVersionId);
  const prior = copies.get(sourceId);
  const destinationKey = `secrets/${move.environment}/${move.secretId}/${suffix}`;
  if (prior !== undefined) {
    if (prior.destinationKey !== destinationKey) {
      throw new Error(
        `Object ${sourceKey} is referenced by multiple environments.`,
      );
    }
    return;
  }
  copies.set(sourceId, { sourceKey, sourceVersionId, destinationKey });
};

const ensureCopied = async (copy: ObjectCopy): Promise<void> => {
  const source = await s3.send(
    new HeadObjectCommand({
      Bucket: revisionBucketName,
      Key: copy.sourceKey,
      VersionId: copy.sourceVersionId,
      ChecksumMode: "ENABLED",
    }),
  );
  const sourceChecksum = source.ChecksumSHA256;
  if (sourceChecksum === undefined || source.ContentLength === undefined) {
    throw new Error(
      `Source object ${copy.sourceKey} is missing integrity metadata.`,
    );
  }
  const existing = await headObject(copy.destinationKey);
  if (existing !== undefined) {
    if (
      existing.ChecksumSHA256 !== sourceChecksum ||
      existing.ContentLength !== source.ContentLength ||
      existing.VersionId === undefined
    ) {
      throw new Error(
        `Destination object ${copy.destinationKey} already exists with different contents.`,
      );
    }
    copy.destinationVersionId = existing.VersionId;
    return;
  }
  const retention = await s3.send(
    new GetObjectRetentionCommand({
      Bucket: revisionBucketName,
      Key: copy.sourceKey,
      VersionId: copy.sourceVersionId,
    }),
  );
  const copied = await s3.send(
    new CopyObjectCommand({
      Bucket: revisionBucketName,
      Key: copy.destinationKey,
      CopySource: copySource(copy.sourceKey, copy.sourceVersionId),
      MetadataDirective: "COPY",
      TaggingDirective: "COPY",
      ChecksumAlgorithm: "SHA256",
      ...(retention.Retention?.Mode === undefined
        ? {}
        : { ObjectLockMode: retention.Retention.Mode }),
      ...(retention.Retention?.RetainUntilDate === undefined
        ? {}
        : { ObjectLockRetainUntilDate: retention.Retention.RetainUntilDate }),
    }),
  );
  if (copied.VersionId === undefined) {
    throw new Error(
      `S3 did not return a version ID for ${copy.destinationKey}.`,
    );
  }
  const destination = await s3.send(
    new HeadObjectCommand({
      Bucket: revisionBucketName,
      Key: copy.destinationKey,
      VersionId: copied.VersionId,
      ChecksumMode: "ENABLED",
    }),
  );
  if (
    destination.ChecksumSHA256 !== sourceChecksum ||
    destination.ContentLength !== source.ContentLength
  ) {
    throw new Error(
      `Copied object ${copy.destinationKey} failed integrity verification.`,
    );
  }
  copy.destinationVersionId = copied.VersionId;
};

const headObject = async (key: string) => {
  try {
    const response = await s3.send(
      new HeadObjectCommand({
        Bucket: revisionBucketName,
        Key: key,
        ChecksumMode: "ENABLED",
      }),
    );
    return response;
  } catch (error) {
    if (isNotFound(error)) {
      return undefined;
    }
    throw error;
  }
};

const moveSecretItem = async (
  move: SecretMove,
  copies: readonly ObjectCopy[],
): Promise<void> => {
  const target = migratedSecretItem(move, copies);
  await moveItem(
    { pk: move.sourcePk, sk: requiredString(move.source, "sk") },
    { pk: move.targetPk, sk: requiredString(move.source, "sk") },
    target,
  );
};

const moveAccessItem = async (move: AccessMove): Promise<void> => {
  const target = { ...move.source, sk: move.targetSk };
  await moveItem(
    { pk: move.sourcePk, sk: move.sourceSk },
    { pk: move.sourcePk, sk: move.targetSk },
    target,
  );
};

const backfillNotificationEnvironment = async (
  backfill: NotificationBackfill,
): Promise<void> => {
  await dynamo.send(
    new UpdateCommand({
      TableName: tableName,
      Key: { pk: `NOTIFICATION#${backfill.eventId}`, sk: "EVENT" },
      UpdateExpression: "SET environment = :environment",
      ConditionExpression:
        "attribute_exists(pk) AND (attribute_not_exists(environment) OR environment = :environment)",
      ExpressionAttributeValues: { ":environment": backfill.environment },
    }),
  );
};

const moveItem = async (
  sourceKey: { readonly pk: string; readonly sk: string },
  targetKey: { readonly pk: string; readonly sk: string },
  target: Item,
): Promise<void> => {
  const sourceResponse = await dynamo.send(
    new GetCommand({
      TableName: tableName,
      Key: sourceKey,
      ConsistentRead: true,
    }),
  );
  const targetResponse = await dynamo.send(
    new GetCommand({
      TableName: tableName,
      Key: targetKey,
      ConsistentRead: true,
    }),
  );
  if (sourceResponse.Item === undefined) {
    if (
      targetResponse.Item !== undefined &&
      isDeepStrictEqual(targetResponse.Item, target)
    ) {
      return;
    }
    throw new Error(
      `Source record ${sourceKey.pk}/${sourceKey.sk} is missing.`,
    );
  }
  if (targetResponse.Item !== undefined) {
    throw new Error(
      `Target record ${targetKey.pk}/${targetKey.sk} already exists.`,
    );
  }
  await dynamo.send(
    new TransactWriteCommand({
      TransactItems: [
        {
          Put: {
            TableName: tableName,
            Item: target,
            ConditionExpression:
              "attribute_not_exists(pk) AND attribute_not_exists(sk)",
          },
        },
        {
          Delete: {
            TableName: tableName,
            Key: sourceKey,
            ConditionExpression:
              "attribute_exists(pk) AND attribute_exists(sk)",
          },
        },
      ],
    }),
  );
};

const migratedSecretItem = (
  move: SecretMove,
  copies: readonly ObjectCopy[],
): Item => {
  const target: Item = { ...move.source, pk: move.targetPk };
  const revisionPk = stringField(target, "revisionPk");
  if (revisionPk !== undefined) {
    if (revisionPk !== move.sourcePk) {
      throw new Error(
        `Unexpected revision index partition key for ${move.secretId}.`,
      );
    }
    target.revisionPk = move.targetPk;
  }
  updateRecordObjectReference(target, "objectKey", "s3VersionId", copies);
  if (stringField(target, "sk") === "HEAD") {
    updateHeadObjectReference(
      target,
      move.secretId,
      "control",
      "controlVersionId",
      "controlObjectVersionId",
      copies,
    );
    updateHeadObjectReference(
      target,
      move.secretId,
      "payload",
      "payloadVersionId",
      "payloadObjectVersionId",
      copies,
    );
  }
  return target;
};

const updateRecordObjectReference = (
  item: Item,
  keyField: string,
  versionField: string,
  copies: readonly ObjectCopy[],
): void => {
  const key = stringField(item, keyField);
  const version = stringField(item, versionField);
  if (key === undefined && version === undefined) {
    return;
  }
  if (key === undefined || version === undefined) {
    throw new Error("Record has an incomplete immutable object reference.");
  }
  const copy = requiredCopy(copies, key, version);
  item[keyField] = copy.destinationKey;
  item[versionField] = requiredDestinationVersionId(copy);
};

const updateHeadObjectReference = (
  item: Item,
  secretId: string,
  kind: "control" | "payload",
  revisionField: string,
  versionField: string,
  copies: readonly ObjectCopy[],
): void => {
  const revisionId = stringField(item, revisionField);
  const version = stringField(item, versionField);
  if (revisionId === undefined && version === undefined) {
    return;
  }
  if (revisionId === undefined || version === undefined) {
    throw new Error(`HEAD has an incomplete ${kind} object reference.`);
  }
  const copy = requiredCopy(
    copies,
    `secrets/${secretId}/${kind}/${revisionId}.json`,
    version,
  );
  item[versionField] = requiredDestinationVersionId(copy);
};

const verifyMigration = async (plan: MigrationPlan): Promise<void> => {
  for (const copy of plan.copies) {
    const destination = await s3.send(
      new HeadObjectCommand({
        Bucket: revisionBucketName,
        Key: copy.destinationKey,
        VersionId: requiredDestinationVersionId(copy),
        ChecksumMode: "ENABLED",
      }),
    );
    if (destination.ChecksumSHA256 === undefined) {
      throw new Error(
        `Destination object ${copy.destinationKey} has no checksum.`,
      );
    }
  }
  const items = await scanItems();
  const legacySecretItems = items.filter((item) =>
    legacySecretId(stringField(item, "pk")),
  );
  const legacyAccessItems = items.filter((item) => isLegacyAccessItem(item));
  if (legacySecretItems.length !== 0 || legacyAccessItems.length !== 0) {
    throw new Error(
      `Verification found ${legacySecretItems.length} legacy secret item(s) and ${legacyAccessItems.length} legacy access item(s).`,
    );
  }
  const pendingWithoutEnvironment = items.filter(
    (item) =>
      stringField(item, "pk")?.startsWith("NOTIFICATION#") === true &&
      stringField(item, "status") === "PENDING" &&
      stringField(item, "environment") === undefined,
  );
  if (pendingWithoutEnvironment.length !== 0) {
    throw new Error(
      `Verification found ${pendingWithoutEnvironment.length} pending notification(s) without an environment.`,
    );
  }
};

const scanItems = async (): Promise<readonly Item[]> => {
  const items: Item[] = [];
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  do {
    const page = await dynamo.send(
      new ScanCommand({
        TableName: tableName,
        ExclusiveStartKey: lastEvaluatedKey,
        ConsistentRead: true,
      }),
    );
    items.push(...(page.Items ?? []));
    lastEvaluatedKey = page.LastEvaluatedKey;
  } while (lastEvaluatedKey !== undefined);
  return items;
};

const printPlan = (plan: MigrationPlan): void => {
  const headsByEnvironment = new Map<string, number>();
  for (const move of plan.secretMoves) {
    if (stringField(move.source, "sk") !== "HEAD") {
      continue;
    }
    headsByEnvironment.set(
      move.environment,
      (headsByEnvironment.get(move.environment) ?? 0) + 1,
    );
  }
  const environments = [...headsByEnvironment.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([environment, count]) => `${environment}:${count}`)
    .join(", ");
  process.stdout.write(
    `${apply ? "Applying" : "Dry run"}: ${plan.secretMoves.length} secret record(s), ${plan.accessMoves.length} access record(s), and ${plan.copies.length} immutable object(s) require migration${environments.length === 0 ? "." : ` (${environments} secret head(s)).`}\n`,
  );
  process.stdout.write(
    `Pending notification records: ${plan.pendingNotifications}; environment backfills required: ${plan.notificationBackfills.length}.\n`,
  );
};

const requiredCopy = (
  copies: readonly ObjectCopy[],
  sourceKey: string,
  sourceVersionId: string,
): ObjectCopy => {
  const copy = copies.find(
    (candidate) =>
      candidate.sourceKey === sourceKey &&
      candidate.sourceVersionId === sourceVersionId,
  );
  if (copy === undefined) {
    throw new Error(`No copy plan exists for ${sourceKey}.`);
  }
  return copy;
};

const requiredDestinationVersionId = (copy: ObjectCopy): string => {
  if (copy.destinationVersionId === undefined) {
    throw new Error(
      `No destination version exists for ${copy.destinationKey}.`,
    );
  }
  return copy.destinationVersionId;
};

const isLegacyAccessItem = (item: Item): boolean => {
  const pk = stringField(item, "pk");
  const sk = stringField(item, "sk");
  return (
    pk?.startsWith("CONSUMER#") === true && legacySecretId(sk) !== undefined
  );
};

const legacySecretId = (pk: string | undefined): string | undefined => {
  const match = pk?.match(/^SECRET#([^#]+)$/);
  return match?.[1];
};

const scopedSecretId = (pk: string): string | undefined => {
  const match = pk.match(/^SECRET#[^#]+#([^#]+)$/);
  return match?.[1];
};

const requiredLegacySecretId = (pk: string): string => {
  const secretId = legacySecretId(pk);
  if (secretId === undefined) {
    throw new Error(`Expected a legacy secret key, received ${pk}.`);
  }
  return secretId;
};

const secretPk = (environment: string, secretId: string): string =>
  `SECRET#${environment}#${secretId}`;

const accessSk = (environment: string, secretId: string): string =>
  secretPk(environment, secretId);

const objectId = (key: string, versionId: string): string =>
  `${key}\u0000${versionId}`;

const copySource = (key: string, versionId: string): string =>
  `${revisionBucketName}/${encodeURIComponent(key).replace(/%2F/g, "/")}?versionId=${encodeURIComponent(versionId)}`;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

const requiredString = (item: Item, name: string): string => {
  const value = stringField(item, name);
  if (value === undefined) {
    throw new Error(`Record is missing required ${name}.`);
  }
  return value;
};

const stringField = (item: Item, name: string): string | undefined => {
  const value = item[name];
  return typeof value === "string" && value.length !== 0 ? value : undefined;
};

const isNotFound = (error: unknown): boolean =>
  error instanceof Error &&
  (error.name === "NotFound" ||
    ("$metadata" in error &&
      typeof error.$metadata === "object" &&
      error.$metadata !== null &&
      "httpStatusCode" in error.$metadata &&
      error.$metadata.httpStatusCode === 404));

void run();
