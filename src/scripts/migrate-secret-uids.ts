import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  ScanCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import { sha256Hex } from "../util/encoding";

type Item = Record<string, unknown>;

interface SecretMove {
  readonly source: Item;
  readonly target: Item;
  readonly sourceKey: Key;
  readonly secretUid: string;
}

interface AccessMove {
  readonly source: Item;
  readonly target: Item;
  readonly sourceKey: Key;
}

interface AgentGrantUpdate {
  readonly key: Key;
  readonly item: Item;
}

interface Lookup {
  readonly key: Key;
  readonly item: Item;
}

interface Key {
  readonly pk: string;
  readonly sk: string;
}

interface SecretIdentity {
  readonly environment: string;
  readonly secretId: string;
  readonly secretUid: string;
}

interface MigratedAgentSecretGrant {
  readonly secretId: string;
  readonly secretUid: string;
  readonly permissions: readonly ("read" | "write")[];
}

export interface SecretUidMigrationPlan {
  readonly secretMoves: readonly SecretMove[];
  readonly accessMoves: readonly AccessMove[];
  readonly grantUpdates: readonly AgentGrantUpdate[];
  readonly lookups: readonly Lookup[];
  readonly issues: readonly string[];
}

/**
 * Converts public-name-keyed Dynamo rows to immutable UID-keyed rows. Immutable
 * S3 documents are not copied: migrated heads retain their exact old object
 * keys, while all new revisions are written below the UID prefix.
 */
export const buildSecretUidMigrationPlan = (
  items: readonly Item[],
): SecretUidMigrationPlan => {
  const identities = collectSecretIdentities(items);
  const identityByName = new Map(
    identities.map((identity) => [
      nameKey(identity.environment, identity.secretId),
      identity,
    ]),
  );
  const secretMoves = items.flatMap((source): SecretMove[] => {
    if (stringField(source, "secretUid") !== undefined) {
      return [];
    }
    const parsed = legacySecretPk(stringField(source, "pk"));
    const sk = stringField(source, "sk");
    if (parsed === undefined || sk === undefined) {
      return [];
    }
    const identity = identityByName.get(
      nameKey(parsed.environment, parsed.secretId),
    );
    if (identity === undefined) {
      throw new Error(
        `Legacy secret record ${parsed.environment}/${parsed.secretId} has no HEAD record.`,
      );
    }
    return [
      {
        source,
        target: migratedSecretItem(source, identity),
        sourceKey: { pk: requiredString(source, "pk"), sk },
        secretUid: identity.secretUid,
      },
    ];
  });
  const accessMoves = items.flatMap((source): AccessMove[] => {
    if (stringField(source, "secretUid") !== undefined) {
      return [];
    }
    const parsed = legacyAccessSk(stringField(source, "sk"));
    const pk = stringField(source, "pk");
    if (
      parsed === undefined ||
      pk === undefined ||
      !pk.startsWith("CONSUMER#")
    ) {
      return [];
    }
    const identity = identityByName.get(
      nameKey(parsed.environment, parsed.secretId),
    );
    if (identity === undefined) {
      throw new Error(
        `Consumer access for ${parsed.environment}/${parsed.secretId} has no HEAD record.`,
      );
    }
    return [
      {
        source,
        target: {
          ...source,
          sk: accessSk(identity.environment, identity.secretUid),
          secretUid: identity.secretUid,
        },
        sourceKey: { pk, sk: requiredString(source, "sk") },
      },
    ];
  });
  const grantResult = migrateAgentGrants(items, identities);
  const lookups = identities.map((identity): Lookup => ({
    key: {
      pk: secretNamePk(identity.environment, identity.secretId),
      sk: "LOOKUP",
    },
    item: {
      pk: secretNamePk(identity.environment, identity.secretId),
      sk: "LOOKUP",
      secretUid: identity.secretUid,
      secretId: identity.secretId,
      environment: identity.environment,
    },
  }));
  return {
    secretMoves,
    accessMoves,
    grantUpdates: grantResult.updates,
    lookups,
    issues: grantResult.issues,
  };
};

const collectSecretIdentities = (
  items: readonly Item[],
): readonly SecretIdentity[] => {
  const identities = new Map<string, SecretIdentity>();
  for (const item of items) {
    if (
      stringField(item, "sk") !== "HEAD" ||
      stringField(item, "state") === "ARCHIVED"
    ) {
      continue;
    }
    const pk = stringField(item, "pk");
    const legacy = legacySecretPk(pk);
    const environment = stringField(item, "environment");
    const secretId = stringField(item, "secretId");
    if (environment === undefined || secretId === undefined) {
      continue;
    }
    if (
      legacy !== undefined &&
      (legacy.environment !== environment || legacy.secretId !== secretId)
    ) {
      throw new Error(`Legacy HEAD ${pk} disagrees with its stored identity.`);
    }
    const secretUid =
      stringField(item, "secretUid") ??
      deterministicSecretUid(environment, secretId);
    const key = nameKey(environment, secretId);
    const prior = identities.get(key);
    if (prior !== undefined && prior.secretUid !== secretUid) {
      throw new Error(
        `Secret ${environment}/${secretId} has conflicting UIDs.`,
      );
    }
    identities.set(key, { environment, secretId, secretUid });
  }
  return [...identities.values()];
};

const migratedSecretItem = (source: Item, identity: SecretIdentity): Item => {
  const sourcePk = requiredString(source, "pk");
  const sk = requiredString(source, "sk");
  const item: Item = {
    ...source,
    pk: secretPk(identity.secretUid),
    sk,
    secretUid: identity.secretUid,
  };
  if (sk === "HEAD") {
    addHeadObjectKeys(item, identity);
  }
  if (sk.startsWith("CONTROL#")) {
    item.revisionPk = secretPk(identity.secretUid);
    const serialized = objectField(item, "serialized");
    if (serialized !== undefined) {
      item.serialized = { ...serialized, secretUid: identity.secretUid };
    }
  }
  if (sk.startsWith("PAYLOAD#")) {
    const serialized = objectField(item, "serialized");
    if (serialized !== undefined) {
      item.serialized = { ...serialized, secretUid: identity.secretUid };
    }
  }
  // Guard against accidentally treating another record family as a secret.
  if (!legacySecretPk(sourcePk)) {
    throw new Error(
      `Cannot migrate non-legacy secret record ${sourcePk}/${sk}.`,
    );
  }
  return item;
};

const addHeadObjectKeys = (item: Item, identity: SecretIdentity): void => {
  const controlVersionId = stringField(item, "controlVersionId");
  const controlObjectVersionId = stringField(item, "controlObjectVersionId");
  if (controlVersionId === undefined) {
    throw new Error(
      `HEAD ${identity.environment}/${identity.secretId} has no immutable control object reference.`,
    );
  }
  if (controlObjectVersionId === undefined) {
    if (item.workflowState === "PREPARED") {
      return;
    }
    throw new Error(
      `HEAD ${identity.environment}/${identity.secretId} has no immutable control object reference.`,
    );
  }
  item.controlObjectKey =
    stringField(item, "controlObjectKey") ??
    legacyControlKey(identity.environment, identity.secretId, controlVersionId);
  const payloadVersionId = stringField(item, "payloadVersionId");
  const payloadObjectVersionId = stringField(item, "payloadObjectVersionId");
  if (payloadVersionId === undefined && payloadObjectVersionId === undefined) {
    return;
  }
  if (payloadVersionId === undefined || payloadObjectVersionId === undefined) {
    throw new Error(
      `HEAD ${identity.environment}/${identity.secretId} has an incomplete immutable payload reference.`,
    );
  }
  item.payloadObjectKey =
    stringField(item, "payloadObjectKey") ??
    legacyPayloadKey(identity.environment, identity.secretId, payloadVersionId);
};

const migrateAgentGrants = (
  items: readonly Item[],
  identities: readonly SecretIdentity[],
): {
  readonly updates: readonly AgentGrantUpdate[];
  readonly issues: readonly string[];
} => {
  const updates: AgentGrantUpdate[] = [];
  const issues: string[] = [];
  for (const item of items) {
    const pk = stringField(item, "pk");
    const sk = stringField(item, "sk");
    if (
      pk === undefined ||
      !pk.startsWith("AGENT_GRANT#") ||
      sk !== "PROFILE"
    ) {
      continue;
    }
    const canonical = canonicalSecretGrants(item, pk, issues);
    if (
      canonical !== undefined &&
      !hasLegacyScopeFields(item) &&
      !hasParallelScopeFields(item)
    ) {
      continue;
    }
    const environment = stringField(item, "environment");
    if (environment === undefined) {
      issues.push(`${pk} has no environment.`);
      continue;
    }
    const secretGrants =
      canonical ??
      migratedSecretGrants(item, pk, environment, identities, issues);
    if (secretGrants === undefined) {
      continue;
    }
    updates.push({
      key: { pk, sk },
      item: {
        ...withoutLegacyAgentScopeFields(item),
        secretGrants,
      },
    });
  }
  return { updates, issues };
};

const canonicalSecretGrants = (
  item: Item,
  grantPk: string,
  issues: string[],
): readonly MigratedAgentSecretGrant[] | undefined => {
  if (!Object.hasOwn(item, "secretGrants")) {
    return undefined;
  }
  if (!Array.isArray(item.secretGrants)) {
    issues.push(`${grantPk} has an invalid secretGrants value.`);
    return undefined;
  }
  const grants: MigratedAgentSecretGrant[] = [];
  for (const value of item.secretGrants) {
    const entry =
      value !== null && typeof value === "object" && !Array.isArray(value)
        ? (value as Item)
        : undefined;
    if (entry === undefined) {
      issues.push(`${grantPk} has an invalid secretGrants entry.`);
      return undefined;
    }
    const secretId = stringField(entry, "secretId");
    const secretUid = stringField(entry, "secretUid");
    const permissions = stringArray(entry.permissions);
    if (
      secretId === undefined ||
      secretUid === undefined ||
      permissions.length === 0 ||
      permissions.length > 2 ||
      permissions.some(
        (permission) => permission !== "read" && permission !== "write",
      )
    ) {
      issues.push(`${grantPk} has an invalid secretGrants entry.`);
      return undefined;
    }
    const agentPermissions = permissions as readonly ("read" | "write")[];
    grants.push({
      secretId,
      secretUid,
      permissions: [...new Set(agentPermissions)].sort(),
    });
  }
  if (new Set(grants.map((grant) => grant.secretId)).size !== grants.length) {
    issues.push(`${grantPk} has duplicate secretGrants secret IDs.`);
    return undefined;
  }
  return grants.sort((left, right) =>
    left.secretId.localeCompare(right.secretId),
  );
};

const migratedSecretGrants = (
  item: Item,
  grantPk: string,
  environment: string,
  identities: readonly SecretIdentity[],
  issues: string[],
): readonly MigratedAgentSecretGrant[] | undefined => {
  const capabilities = stringArray(item.capabilities);
  const read = secretIdsForGrant(
    item,
    grantPk,
    "read",
    capabilities.includes("read"),
    environment,
    identities,
    issues,
  );
  const write = secretIdsForGrant(
    item,
    grantPk,
    "write",
    capabilities.includes("write"),
    environment,
    identities,
    issues,
  );
  if (read === undefined || write === undefined) {
    return undefined;
  }
  const permissionsBySecretId = new Map<string, Set<"read" | "write">>();
  for (const secretId of read) {
    permissionsBySecretId.set(secretId, new Set<"read" | "write">(["read"]));
  }
  for (const secretId of write) {
    const permissions =
      permissionsBySecretId.get(secretId) ?? new Set<"read" | "write">();
    permissions.add("write");
    permissionsBySecretId.set(secretId, permissions);
  }
  const identitiesByName = new Map(
    identities.map((identity) => [
      nameKey(identity.environment, identity.secretId),
      identity,
    ]),
  );
  const grants: MigratedAgentSecretGrant[] = [];
  for (const [secretId, permissions] of permissionsBySecretId.entries()) {
    const identity = identitiesByName.get(nameKey(environment, secretId));
    if (identity === undefined) {
      issues.push(
        `${grantPk} names secret ${environment}/${secretId}, which is not active during migration.`,
      );
      return undefined;
    }
    grants.push({
      secretId,
      secretUid: identity.secretUid,
      permissions: [...permissions].sort(),
    });
  }
  return grants.sort((left, right) =>
    left.secretId.localeCompare(right.secretId),
  );
};

const hasParallelScopeFields = (item: Item): boolean =>
  Object.hasOwn(item, "readSecretIds") ||
  Object.hasOwn(item, "readSecretUids") ||
  Object.hasOwn(item, "writeSecretIds") ||
  Object.hasOwn(item, "writeSecretUids");

const withoutLegacyAgentScopeFields = (item: Item): Item => {
  const {
    readSecretIds: _readSecretIds,
    readSecretUids: _readSecretUids,
    writeSecretIds: _writeSecretIds,
    writeSecretUids: _writeSecretUids,
    readSecretIdPrefixes: _readSecretIdPrefixes,
    writeSecretIdPrefixes: _writeSecretIdPrefixes,
    readPathPrefixes: _readPathPrefixes,
    writePathPrefixes: _writePathPrefixes,
    ...canonical
  } = item;
  return canonical;
};

const hasLegacyScopeFields = (item: Item): boolean =>
  Object.hasOwn(item, "readSecretIdPrefixes") ||
  Object.hasOwn(item, "writeSecretIdPrefixes") ||
  Object.hasOwn(item, "readPathPrefixes") ||
  Object.hasOwn(item, "writePathPrefixes");

const secretIdsForGrant = (
  item: Item,
  grantPk: string,
  capability: "read" | "write",
  enabled: boolean,
  environment: string,
  identities: readonly SecretIdentity[],
  issues: string[],
): readonly string[] | undefined => {
  const field = `${capability}SecretIds`;
  if (Array.isArray(item[field])) {
    const ids = stringArray(item[field]);
    if (ids.length !== item[field].length) {
      issues.push(`${grantPk} has an invalid ${field} array.`);
      return undefined;
    }
    return ids;
  }
  return migrateScope(
    grantPk,
    capability,
    enabled,
    item[`${capability}SecretIdPrefixes`],
    item[`${capability}PathPrefixes`],
    environment,
    identities,
    issues,
  );
};

const migrateScope = (
  grantPk: string,
  capability: "read" | "write",
  enabled: boolean,
  prefixes: unknown,
  legacyPaths: unknown,
  environment: string,
  identities: readonly SecretIdentity[],
  issues: string[],
): readonly string[] | undefined => {
  if (!enabled) {
    return [];
  }
  if (Array.isArray(legacyPaths)) {
    issues.push(
      `${grantPk} uses unsupported legacy ${capability}PathPrefixes.`,
    );
    return undefined;
  }
  const scope = stringArray(prefixes);
  if (scope.length === 0) {
    issues.push(`${grantPk} has no ${capability}SecretIdPrefixes to snapshot.`);
    return undefined;
  }
  const secretIds = identities
    .filter((identity) => identity.environment === environment)
    .map((identity) => identity.secretId)
    .filter((secretId) =>
      scope.some(
        (prefix) => secretId === prefix || secretId.startsWith(`${prefix}/`),
      ),
    )
    .sort((left, right) => left.localeCompare(right));
  return secretIds;
};

const run = async (): Promise<void> => {
  const tableName = requiredEnvironment("CONTROL_TABLE_NAME");
  const apply = process.argv.includes("--apply");
  if (apply && process.env.HEMLIG_UPGRADE_QUIESCED !== "1") {
    throw new Error(
      "Refusing to write before the service is quiesced. Set HEMLIG_UPGRADE_QUIESCED=1 only after following the upgrade guide.",
    );
  }
  const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  const items = await scanItems(dynamo, tableName);
  const plan = buildSecretUidMigrationPlan(items);
  printPlan(plan);
  if (!apply) {
    return;
  }
  if (plan.issues.length !== 0) {
    throw new Error(
      "Refusing to migrate AgentGrants with unresolved exact scopes.",
    );
  }
  for (const move of plan.secretMoves) {
    await dynamo.send(
      new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: tableName, Item: move.target } },
          { Delete: { TableName: tableName, Key: move.sourceKey } },
        ],
      }),
    );
  }
  for (const move of plan.accessMoves) {
    await dynamo.send(
      new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: tableName, Item: move.target } },
          { Delete: { TableName: tableName, Key: move.sourceKey } },
        ],
      }),
    );
  }
  for (const lookup of plan.lookups) {
    await dynamo.send(
      new PutCommand({ TableName: tableName, Item: lookup.item }),
    );
  }
  for (const update of plan.grantUpdates) {
    await dynamo.send(
      new PutCommand({
        TableName: tableName,
        Item: removeUndefined(update.item),
      }),
    );
  }
  const migratedItems = await scanItems(dynamo, tableName);
  const verification = buildSecretUidMigrationPlan(migratedItems);
  const keys = new Set(
    migratedItems.map(
      (item) =>
        `${requiredString(item, "pk")}\u0000${requiredString(item, "sk")}`,
    ),
  );
  const missingLookups = verification.lookups.filter(
    (lookup) => !keys.has(`${lookup.key.pk}\u0000${lookup.key.sk}`),
  );
  if (
    verification.secretMoves.length !== 0 ||
    verification.accessMoves.length !== 0 ||
    verification.grantUpdates.length !== 0 ||
    verification.issues.length !== 0 ||
    missingLookups.length !== 0
  ) {
    throw new Error("Secret UID migration verification failed.");
  }
  process.stdout.write("Secret UID migration completed successfully.\n");
};

const scanItems = async (
  dynamo: DynamoDBDocumentClient,
  tableName: string,
): Promise<readonly Item[]> => {
  const items: Item[] = [];
  let exclusiveStartKey: Record<string, unknown> | undefined;
  do {
    const page = await dynamo.send(
      new ScanCommand({
        TableName: tableName,
        ExclusiveStartKey: exclusiveStartKey as never,
      }),
    );
    items.push(...((page.Items ?? []) as Item[]));
    exclusiveStartKey = page.LastEvaluatedKey as
      Record<string, unknown> | undefined;
  } while (exclusiveStartKey !== undefined);
  return items;
};

const printPlan = (plan: SecretUidMigrationPlan): void => {
  process.stdout.write(
    `Secret UID migration: ${plan.secretMoves.length} secret row(s), ${plan.accessMoves.length} access row(s), ${plan.lookups.length} lookup(s), ${plan.grantUpdates.length} AgentGrant update(s).\n`,
  );
  for (const issue of plan.issues) {
    process.stderr.write(`ISSUE: ${issue}\n`);
  }
};

const deterministicSecretUid = (
  environment: string,
  secretId: string,
): string => {
  const hash = sha256Hex(
    `hemlig:secret-uid:v1:${environment}\u0000${secretId}`,
  );
  return `sec-${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
};

const legacySecretPk = (
  pk: string | undefined,
): { readonly environment: string; readonly secretId: string } | undefined => {
  if (pk === undefined || !pk.startsWith("SECRET#")) {
    return undefined;
  }
  const separator = pk.indexOf("#", "SECRET#".length);
  if (separator === -1) {
    return undefined;
  }
  const environment = pk.slice("SECRET#".length, separator);
  const secretId = pk.slice(separator + 1);
  return environment.length === 0 || secretId.length === 0
    ? undefined
    : { environment, secretId };
};

const legacyAccessSk = (
  sk: string | undefined,
): { readonly environment: string; readonly secretId: string } | undefined =>
  legacySecretPk(sk);

const secretPk = (secretUid: string): string => `SECRET#${secretUid}`;

const secretNamePk = (environment: string, secretId: string): string =>
  `SECRET_NAME#${environment}#${secretId}`;

const accessSk = (environment: string, secretUid: string): string =>
  `SECRET#${environment}#${secretUid}`;

const legacyControlKey = (
  environment: string,
  secretId: string,
  versionId: string,
): string => `secrets/${environment}/${secretId}/control/${versionId}.json`;

const legacyPayloadKey = (
  environment: string,
  secretId: string,
  versionId: string,
): string => `secrets/${environment}/${secretId}/payload/${versionId}.json`;

const nameKey = (environment: string, secretId: string): string =>
  `${environment}\u0000${secretId}`;

const stringField = (item: Item, name: string): string | undefined => {
  const value = item[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

const requiredString = (item: Item, name: string): string => {
  const value = stringField(item, name);
  if (value === undefined) {
    throw new Error(`Expected ${name} to be a non-empty string.`);
  }
  return value;
};

const objectField = (item: Item, name: string): Item | undefined => {
  const value = item[name];
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Item)
    : undefined;
};

const stringArray = (value: unknown): readonly string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? value
    : [];

const removeUndefined = (item: Item): Item =>
  Object.fromEntries(
    Object.entries(item).filter(([, value]) => value !== undefined),
  );

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
