import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
  type TransactWriteCommandInput,
  type UpdateCommandInput,
} from "@aws-sdk/lib-dynamodb";
import { assertEnvironmentName } from "../domain/validation";
import { serviceUnavailable } from "../domain/errors";
import type { Actor } from "../domain/types";
import type {
  CaCrlState,
  CaRecord,
  ExternalCaRecord,
  IssuedCertificateRecord,
  ReplayRecord,
  RevocationEntryRecord,
} from "../pki/types";
import { newId, sha256Hex, stableJson } from "../util/encoding";

// ---------------------------------------------------------------------------
// Key, GSI and TTL builders. Every PKI time comparison is a lexicographic
// comparison of canonical ISO strings (`new Date(v).toISOString() === v`).
// ---------------------------------------------------------------------------

export interface PkiKey {
  readonly pk: string;
  readonly sk: string;
}

export interface PkiDirectoryKey {
  readonly pkiDirectoryPk: string;
  readonly pkiDirectorySk: string;
}

const patterns = {
  caId: /^ca-[a-z0-9-]{3,80}$/,
  extId: /^ext-[0-9a-f]{40}$/,
  serial: /^[0-9a-f]{2,40}$/,
  identifier: /^[a-z][a-z0-9-]{2,63}$/,
  subjectKey: /^[0-9a-f]{64}$/,
  grantUid: /^[a-z0-9-]{3,80}$/,
  fingerprint: /^[0-9a-f]{64}$/,
  agentGrantId: /^grant-[0-9a-f-]{36}$/,
} as const;

// Inputs are validated upstream: a failure here is a programming error, so these are plain Errors without the value.
const guard = (label: string, value: unknown, pattern: RegExp): string => {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
};

const guardEnvironment = (value: unknown): string => {
  try {
    assertEnvironmentName(value as string);
  } catch {
    throw new Error("Invalid environment.");
  }
  return value as string;
};

const guardIdempotencyKey = (value: unknown): string => {
  if (typeof value !== "string" || value.length < 8 || value.length > 128) {
    throw new Error("Invalid idempotency key.");
  }
  return value;
};

const guardActorId = (value: unknown): string => {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    throw new Error("Invalid actor id.");
  }
  return value;
};

const guardIso = (label: string, value: unknown): string => {
  if (typeof value !== "string") {
    throw new Error(`Invalid ${label}.`);
  }
  let canonical: string;
  try {
    canonical = new Date(value).toISOString();
  } catch {
    throw new Error(`Invalid ${label}.`);
  }
  if (canonical !== value) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
};

const caId = (value: unknown): string => guard("caId", value, patterns.caId);
const serial = (value: unknown): string =>
  guard("serial", value, patterns.serial);
const identifier = (label: string, value: unknown): string =>
  guard(label, value, patterns.identifier);
const grantUid = (value: unknown): string =>
  guard("grant uid", value, patterns.grantUid);

// ---------------------------------------------------------------------------
// Record conversion
// ---------------------------------------------------------------------------

const withoutKeys = (item: Record<string, unknown>): Record<string, unknown> => {
  const {
    pk: _pk,
    sk: _sk,
    pkiDirectoryPk: _directoryPk,
    pkiDirectorySk: _directorySk,
    ...rest
  } = item;
  return rest;
};

const malformed = (what: string) =>
  serviceUnavailable(`A stored PKI ${what} record is malformed.`);

export const toCaRecord = (item: Record<string, unknown>): CaRecord => {
  const record = withoutKeys(item);
  const key = record.key as { state?: unknown } | undefined;
  if (
    typeof record.caId !== "string" ||
    typeof record.status !== "string" ||
    typeof record.version !== "string" ||
    typeof key !== "object" ||
    key === null ||
    typeof key.state !== "string"
  ) {
    throw malformed("CA");
  }
  return record as unknown as CaRecord;
};

export const toExternalCaRecord = (
  item: Record<string, unknown>,
): ExternalCaRecord => {
  const record = withoutKeys(item);
  if (
    typeof record.extId !== "string" ||
    typeof record.version !== "string" ||
    !(record.dependents instanceof Set) ||
    !(record.environments instanceof Set)
  ) {
    throw malformed("external CA");
  }
  return record as unknown as ExternalCaRecord;
};

const toRevocationEntry = (
  item: Record<string, unknown>,
): RevocationEntryRecord => {
  if (
    typeof item.serial !== "string" ||
    typeof item.revokedAt !== "string" ||
    typeof item.reason !== "string" ||
    typeof item.notAfter !== "string"
  ) {
    throw malformed("revocation");
  }
  const { pk: _pk, sk: _sk, ...rest } = item;
  return rest as unknown as RevocationEntryRecord;
};

export const pkiKeys = {
  caProfile: (id: string): PkiKey => ({
    pk: `PKI_CA#${caId(id)}`,
    sk: "PROFILE",
  }),
  caCrl: (id: string): PkiKey => ({ pk: `PKI_CA#${caId(id)}`, sk: "CRL" }),
  revocation: (id: string, certSerial: string): PkiKey => ({
    pk: `PKI_CA#${caId(id)}`,
    sk: `REVOKED#${serial(certSerial)}`,
  }),
  caName: (environment: string, name: string): PkiKey => ({
    pk: `PKI_CA_NAME#${guardEnvironment(environment)}#${identifier("CA name", name)}`,
    sk: "LOOKUP",
  }),
  subject: (key: string): PkiKey => ({
    pk: `PKI_SUBJECT#${guard("subject key", key, patterns.subjectKey)}`,
    sk: "LOOKUP",
  }),
  externalCa: (extId: string): PkiKey => ({
    pk: `PKI_EXTCA#${guard("extId", extId, patterns.extId)}`,
    sk: "PROFILE",
  }),
  certificate: (id: string, certSerial: string): PkiKey => ({
    pk: `PKI_CERT#${caId(id)}#${serial(certSerial)}`,
    sk: "PROFILE",
  }),
  consumerCertificate: (
    consumerId: string,
    issuedAt: string,
    id: string,
    certSerial: string,
  ): PkiKey => ({
    pk: `PKI_CONSUMER#${identifier("consumerId", consumerId)}`,
    sk: `CERT#${guardIso("issuedAt", issuedAt)}#${caId(id)}#${serial(certSerial)}`,
  }),
  grant: (consumerId: string, name: string): PkiKey => ({
    pk: `PKI_GRANT#${identifier("consumerId", consumerId)}`,
    sk: `NAME#${identifier("grant name", name)}`,
  }),
  grantQuota: (uid: string, sk: string): PkiKey => ({
    pk: `PKI_QUOTA#${grantUid(uid)}`,
    sk,
  }),
  adminQuota: (id: string, sk: string): PkiKey => ({
    pk: `PKI_QUOTA#admin#${caId(id)}`,
    sk,
  }),
  caQuota: (id: string, sk: string): PkiKey => ({
    pk: `PKI_QUOTA#ca#${caId(id)}`,
    sk,
  }),
  replay: (consumerId: string, key: string): PkiKey => ({
    pk: `PKI_IDEMPOTENCY#${identifier("consumerId", consumerId)}`,
    sk: `REQUEST#${guardIdempotencyKey(key)}`,
  }),
  humanIdempotency: (actorId: string, key: string): PkiKey => ({
    pk: `IDEMPOTENCY#human#${guardActorId(actorId)}`,
    sk: `REQUEST#${guardIdempotencyKey(key)}`,
  }),
};

export const PKI_DIRECTORY_ATTRIBUTES = [
  "pkiDirectoryPk",
  "pkiDirectorySk",
] as const;

export const pkiDirectory = {
  ca: (environment: string, name: string): PkiDirectoryKey => ({
    pkiDirectoryPk: "PKI_CAS",
    pkiDirectorySk: `${guardEnvironment(environment)}#${identifier("CA name", name)}`,
  }),
  externalCa: (extId: string): PkiDirectoryKey => ({
    pkiDirectoryPk: "PKI_EXTCAS",
    pkiDirectorySk: guard("extId", extId, patterns.extId),
  }),
  grant: (id: string, consumerId: string, name: string): PkiDirectoryKey => ({
    pkiDirectoryPk: `PKI_CA_GRANTS#${caId(id)}`,
    pkiDirectorySk: `${identifier("consumerId", consumerId)}#${identifier("grant name", name)}`,
  }),
  certificate: (
    id: string,
    notAfter: string,
    certSerial: string,
  ): PkiDirectoryKey => ({
    pkiDirectoryPk: `PKI_CERTS#${caId(id)}`,
    pkiDirectorySk: `${guardIso("notAfter", notAfter)}#${serial(certSerial)}`,
  }),
};

const secondsPerDay = 86_400;
const epochSeconds = (iso: string): number =>
  Math.floor(Date.parse(guardIso("time", iso)) / 1000);

/** DynamoDB TTL attribute values, in epoch seconds. */
export const pkiTtl = {
  certificate: (notAfter: string): number =>
    epochSeconds(notAfter) + 90 * secondsPerDay,
  consumerPointer: (notAfter: string): number =>
    epochSeconds(notAfter) + 90 * secondsPerDay,
  replay: (notAfter: string): number =>
    epochSeconds(notAfter) + 400 * secondsPerDay,
  hourCounter: (hourStart: Date): number =>
    Math.floor(hourStart.getTime() / 1000) + 48 * 3600,
  dayCounter: (dayStart: Date): number =>
    Math.floor(dayStart.getTime() / 1000) + 3 * secondsPerDay,
};

export interface QuotaWindows {
  readonly hourSk: string;
  readonly daySk: string;
  readonly hourStart: Date;
  readonly hourEnd: Date;
  readonly dayStart: Date;
  readonly dayEnd: Date;
}

const pad = (value: number, width = 2): string =>
  String(value).padStart(width, "0");

/** UTC quota windows containing `now`. */
export const quotaWindows = (now: Date): QuotaWindows => {
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  const day = now.getUTCDate();
  const hour = now.getUTCHours();
  const ymd = `${pad(year, 4)}${pad(month + 1)}${pad(day)}`;
  return {
    hourSk: `HOUR#${ymd}${pad(hour)}`,
    daySk: `DAY#${ymd}`,
    hourStart: new Date(Date.UTC(year, month, day, hour)),
    hourEnd: new Date(Date.UTC(year, month, day, hour + 1)),
    dayStart: new Date(Date.UTC(year, month, day)),
    dayEnd: new Date(Date.UTC(year, month, day + 1)),
  };
};

// ---------------------------------------------------------------------------
// Issuance commit input
// ---------------------------------------------------------------------------

export type QuotaSlot = "grantHour" | "grantDay" | "adminHour" | "caHour";
export type PreconditionSlot =
  "grant" | "ca" | "identity" | "agentGrant" | "ancestor";
export type IssuanceSlot =
  "replay" | "certificate" | "consumerPointer" | QuotaSlot | PreconditionSlot;

interface IssuanceCommitBase {
  /** The pre-check instant; fixes `:now` and the quota windows for every retry. */
  readonly now: Date;
  readonly idempotencyKey: string;
  readonly requestDigest: string;
  /** Status `ISSUED`. */
  readonly certificate: IssuedCertificateRecord;
  readonly ca: {
    readonly caId: string;
    readonly version: string;
    readonly issuancePerHour: number;
  };
  /** Hemlig ancestor caIds (Phase 7); empty in v1. */
  readonly ancestors?: readonly string[];
}

export interface ConsumerIssuanceCommit extends IssuanceCommitBase {
  readonly path: "consumer";
  readonly consumerId: string;
  readonly identityFingerprint: string;
  readonly grant: {
    readonly name: string;
    readonly uid: string;
    readonly version: string;
    readonly perHour: number;
    readonly perDay: number;
  };
  /** Agents only. */
  readonly agentGrant?: {
    readonly grantId: string;
    readonly environment: string;
  };
}

export interface AdminIssuanceCommit extends IssuanceCommitBase {
  readonly path: "admin";
  /** A human actor. */
  readonly actor: Actor;
  readonly adminPerHour: number;
}

export type IssuanceCommit = ConsumerIssuanceCommit | AdminIssuanceCommit;

export interface BuiltIssuanceCommit {
  readonly input: TransactWriteCommandInput;
  /** `slots[i]` names `input.TransactItems[i]`. */
  readonly slots: readonly IssuanceSlot[];
}

const maxTransactionItems = 100;

const requireLimit = (label: string, value: number): number => {
  if (!Number.isSafeInteger(value) || value < 1) {
    // The attribute_not_exists branch admits the first commit of a window regardless of the limit, so 0 would let one
    // through.
    throw new Error(`${label} must be a safe integer of at least 1.`);
  }
  return value;
};

/**
 * `TransactWriteItems` input for one certificate commit. Item order is the slot index, with the replay item first
 * so it is reported even if evaluation stops early. Every non-key attribute goes through `ExpressionAttributeNames`
 * (`count`, `ttl`, `status`, `key` and `state` are DynamoDB reserved words); `pk` stays bare.
 */
export const buildIssuanceCommit = (
  tableName: string,
  commit: IssuanceCommit,
  generation = 0,
): BuiltIssuanceCommit => {
  const { certificate, ca } = commit;
  if (certificate.status !== "ISSUED" || certificate.caId !== ca.caId) {
    throw new Error("The certificate does not match the commit.");
  }
  if (commit.path === "consumer") {
    if (
      certificate.requester.consumerId !== commit.consumerId ||
      certificate.requester.issuanceGrant?.uid !== commit.grant.uid
    ) {
      throw new Error("The certificate requester does not match the commit.");
    }
    if (
      commit.agentGrant !== undefined &&
      commit.agentGrant.environment !== certificate.environment
    ) {
      throw new Error("The agent grant environment does not match.");
    }
    requireLimit("grant perHour", commit.grant.perHour);
    requireLimit("grant perDay", commit.grant.perDay);
  } else {
    if (
      commit.actor.type !== "human" ||
      certificate.requester.id !== commit.actor.id
    ) {
      throw new Error("The certificate requester does not match the actor.");
    }
    requireLimit("adminPerHour", commit.adminPerHour);
  }
  requireLimit("CA issuancePerHour", ca.issuancePerHour);

  const now = commit.now.toISOString();
  const windows = quotaWindows(commit.now);
  const { serial: certSerial, notAfter, issuedAt } = certificate;
  const certificateKey = pkiKeys.certificate(ca.caId, certSerial);
  const items: NonNullable<TransactWriteCommandInput["TransactItems"]> = [];
  const slots: IssuanceSlot[] = [];
  const add = (
    slot: IssuanceSlot,
    item: NonNullable<TransactWriteCommandInput["TransactItems"]>[number],
  ): void => {
    slots.push(slot);
    items.push(item);
  };

  const certificatePut = {
    Put: {
      TableName: tableName,
      Item: {
        ...certificateKey,
        ...certificate,
        ...pkiDirectory.certificate(ca.caId, notAfter, certSerial),
        ttl: pkiTtl.certificate(notAfter),
      },
      ConditionExpression: "attribute_not_exists(pk)",
    },
  };
  const quota = (
    key: PkiKey,
    limit: number,
    ttl: number,
  ): NonNullable<TransactWriteCommandInput["TransactItems"]>[number] => ({
    Update: {
      TableName: tableName,
      Key: { ...key },
      UpdateExpression: "SET #ttl = if_not_exists(#ttl, :ttl) ADD #count :one",
      ConditionExpression: "attribute_not_exists(#count) OR #count < :limit",
      ExpressionAttributeNames: { "#ttl": "ttl", "#count": "count" },
      ExpressionAttributeValues: { ":ttl": ttl, ":one": 1, ":limit": limit },
    },
  });
  const caCheck = {
    ConditionCheck: {
      TableName: tableName,
      Key: { ...pkiKeys.caProfile(ca.caId) },
      ConditionExpression:
        "#status = :active AND #version = :version AND #key.#state = :active",
      ExpressionAttributeNames: {
        "#status": "status",
        "#version": "version",
        "#key": "key",
        "#state": "state",
      },
      ExpressionAttributeValues: {
        ":active": "ACTIVE",
        ":version": ca.version,
      },
    },
  };

  if (commit.path === "consumer") {
    const { consumerId, grant } = commit;
    add("replay", {
      Put: {
        TableName: tableName,
        Item: {
          ...pkiKeys.replay(consumerId, commit.idempotencyKey),
          requestDigest: commit.requestDigest,
          caId: ca.caId,
          serial: certSerial,
          notAfter,
          grantUid: grant.uid,
          ttl: pkiTtl.replay(notAfter),
        },
        ConditionExpression: "attribute_not_exists(pk)",
      },
    });
    add("certificate", certificatePut);
    add("consumerPointer", {
      Put: {
        TableName: tableName,
        Item: {
          ...pkiKeys.consumerCertificate(
            consumerId,
            issuedAt,
            ca.caId,
            certSerial,
          ),
          caId: ca.caId,
          serial: certSerial,
          environment: certificate.environment,
          notAfter,
          issuedAt,
          issuanceGrant: grant.name,
          issuanceGrantUid: grant.uid,
          ttl: pkiTtl.consumerPointer(notAfter),
        },
        ConditionExpression: "attribute_not_exists(pk)",
      },
    });
    add(
      "grantHour",
      quota(
        pkiKeys.grantQuota(grant.uid, windows.hourSk),
        grant.perHour,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    add(
      "grantDay",
      quota(
        pkiKeys.grantQuota(grant.uid, windows.daySk),
        grant.perDay,
        pkiTtl.dayCounter(windows.dayStart),
      ),
    );
    add(
      "caHour",
      quota(
        pkiKeys.caQuota(ca.caId, windows.hourSk),
        ca.issuancePerHour,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    add("grant", {
      ConditionCheck: {
        TableName: tableName,
        Key: { ...pkiKeys.grant(consumerId, grant.name) },
        ConditionExpression:
          "#uid = :uid AND #version = :version AND #status = :active AND (attribute_not_exists(#expiresAt) OR #expiresAt > :now)",
        ExpressionAttributeNames: {
          "#uid": "uid",
          "#version": "version",
          "#status": "status",
          "#expiresAt": "expiresAt",
        },
        ExpressionAttributeValues: {
          ":uid": grant.uid,
          ":version": grant.version,
          ":active": "ACTIVE",
          ":now": now,
        },
      },
    });
    add("ca", caCheck);
    add("identity", {
      ConditionCheck: {
        TableName: tableName,
        Key: {
          pk: `IDENTITY#${guard("identity fingerprint", commit.identityFingerprint, patterns.fingerprint)}`,
          sk: "PROFILE",
        },
        ConditionExpression:
          "#status = :active AND #kind = :api AND #notAfter > :now AND #consumerId = :consumerId",
        ExpressionAttributeNames: {
          "#status": "status",
          "#kind": "kind",
          "#notAfter": "notAfter",
          "#consumerId": "consumerId",
        },
        ExpressionAttributeValues: {
          ":active": "ACTIVE",
          ":api": "api",
          ":now": now,
          ":consumerId": consumerId,
        },
      },
    });
    if (commit.agentGrant !== undefined) {
      add("agentGrant", {
        ConditionCheck: {
          TableName: tableName,
          Key: {
            pk: `AGENT_GRANT#${guard("agent grant id", commit.agentGrant.grantId, patterns.agentGrantId)}`,
            sk: "PROFILE",
          },
          ConditionExpression:
            "#status = :active AND #environment = :environment AND #consumerId = :consumerId",
          ExpressionAttributeNames: {
            "#status": "status",
            "#environment": "environment",
            "#consumerId": "consumerId",
          },
          ExpressionAttributeValues: {
            ":active": "ACTIVE",
            ":environment": commit.agentGrant.environment,
            ":consumerId": consumerId,
          },
        },
      });
    }
  } else {
    add("replay", {
      Put: {
        TableName: tableName,
        Item: {
          ...pkiKeys.humanIdempotency(commit.actor.id, commit.idempotencyKey),
          operationType: "pki.certificate.issue",
          requestDigest: commit.requestDigest,
          status: "COMMITTED",
          result: { caId: ca.caId, serial: certSerial, notAfter },
          createdAt: now,
        },
        ConditionExpression: "attribute_not_exists(pk)",
      },
    });
    add("certificate", certificatePut);
    add(
      "adminHour",
      quota(
        pkiKeys.adminQuota(ca.caId, windows.hourSk),
        commit.adminPerHour,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    add(
      "caHour",
      quota(
        pkiKeys.caQuota(ca.caId, windows.hourSk),
        ca.issuancePerHour,
        pkiTtl.hourCounter(windows.hourStart),
      ),
    );
    add("ca", caCheck);
  }
  for (const ancestor of commit.ancestors ?? []) {
    add("ancestor", {
      ConditionCheck: {
        TableName: tableName,
        Key: { ...pkiKeys.caProfile(ancestor) },
        ConditionExpression: "#status <> :revoked",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: { ":revoked": "REVOKED" },
      },
    });
  }
  if (items.length > maxTransactionItems) {
    throw new Error("The commit has too many items.");
  }
  const principal =
    commit.path === "consumer"
      ? `consumer:${commit.consumerId}`
      : `human:${commit.actor.id}`;
  return {
    input: {
      TransactItems: items,
      ClientRequestToken: sha256Hex(
        stableJson([
          "pki-issue",
          principal,
          commit.idempotencyKey,
          ca.caId,
          certSerial,
          generation,
        ]),
      ).slice(0, 36),
    },
    slots,
  };
};

// ---------------------------------------------------------------------------
// Cancellation classification
// ---------------------------------------------------------------------------

export type Classified =
  | { readonly kind: "unclassified" }
  | { readonly kind: "replayExists" }
  | {
      readonly kind: "preconditionFailed";
      readonly slots: readonly PreconditionSlot[];
    }
  | {
      readonly kind: "quotaExhausted";
      readonly quotas: readonly QuotaSlot[];
      readonly retryAfterSeconds: number;
    }
  | { readonly kind: "serialCollision" }
  /** Only transient codes: the caller retries internally. */
  | { readonly kind: "retry" };

export type IssuanceCommitOutcome =
  | { readonly kind: "committed" }
  | Exclude<Classified, { readonly kind: "retry" }>
  | { readonly kind: "conflict" }
  | { readonly kind: "ambiguous" };

const preconditionSlots: readonly IssuanceSlot[] = [
  "grant",
  "ca",
  "identity",
  "agentGrant",
  "ancestor",
];
const quotaSlots: readonly IssuanceSlot[] = [
  "grantHour",
  "grantDay",
  "adminHour",
  "caHour",
];
const transientCodes = new Set([
  "TransactionConflict",
  "ThrottlingError",
  "ProvisionedThroughputExceeded",
  "RequestLimitExceeded",
]);

interface CancellationReason {
  readonly Code?: string;
}

const cancellationReasons = (
  error: unknown,
): readonly CancellationReason[] | undefined => {
  const reasons = (error as { CancellationReasons?: unknown })
    .CancellationReasons;
  return Array.isArray(reasons) ? (reasons as CancellationReason[]) : undefined;
};

/** The first matching row wins. */
export const classifyIssuanceCancellation = (
  built: BuiltIssuanceCommit,
  commit: IssuanceCommit,
  error: unknown,
): Classified => {
  const reasons = cancellationReasons(error);
  if (reasons === undefined || reasons.length !== built.slots.length) {
    return { kind: "unclassified" };
  }
  const codes = reasons.map((reason) => reason.Code ?? "None");
  const failed = (slot: IssuanceSlot): boolean => {
    const index = built.slots.indexOf(slot);
    return index !== -1 && codes[index] === "ConditionalCheckFailed";
  };
  const failedWhere = (set: readonly IssuanceSlot[]): IssuanceSlot[] =>
    built.slots.filter(
      (slot, index) =>
        set.includes(slot) && codes[index] === "ConditionalCheckFailed",
    );
  if (failed("replay")) {
    return { kind: "replayExists" };
  }
  const preconditions = failedWhere(preconditionSlots);
  if (preconditions.length > 0) {
    return {
      kind: "preconditionFailed",
      slots: preconditions as PreconditionSlot[],
    };
  }
  const quotas = failedWhere(quotaSlots) as QuotaSlot[];
  if (quotas.length > 0) {
    const windows = quotaWindows(commit.now);
    const retryAfterSeconds = Math.max(
      1,
      ...quotas.map((slot) =>
        Math.ceil(
          ((slot === "grantDay" ? windows.dayEnd : windows.hourEnd).getTime() -
            commit.now.getTime()) /
            1000,
        ),
      ),
    );
    return { kind: "quotaExhausted", quotas, retryAfterSeconds };
  }
  if (failed("certificate") || failed("consumerPointer")) {
    return { kind: "serialCollision" };
  }
  const others = codes.filter((code) => code !== "None");
  if (others.length === 0) {
    return { kind: "unclassified" };
  }
  if (others.every((code) => transientCodes.has(code))) {
    return { kind: "retry" };
  }
  // Codes only: never the items.
  console.error("PKI issuance transaction canceled", { codes: others });
  throw serviceUnavailable("The certificate could not be committed.");
};

// ---------------------------------------------------------------------------
// Admin transactions (Phase 3)
// ---------------------------------------------------------------------------

export type TransactItem = NonNullable<
  TransactWriteCommandInput["TransactItems"]
>[number];

export interface NamedItem {
  readonly slot: string;
  readonly item: TransactItem;
}

export type TransactOutcome =
  | { readonly kind: "committed" }
  | { readonly kind: "canceled"; readonly failed: readonly string[] };

/** The human idempotency record that every admin mutation commits in slot 0. */
export interface HumanIdempotencyWrite {
  readonly actor: Actor;
  readonly idempotencyKey: string;
  readonly operationType: string;
  readonly requestDigest: string;
  readonly result: Record<string, unknown>;
  readonly now: string;
}

const defined = (value: object): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(value).filter(([, field]) => field !== undefined),
  );

export const buildHumanIdempotencyPut = (
  tableName: string,
  write: HumanIdempotencyWrite,
): TransactItem => ({
  Put: {
    TableName: tableName,
    Item: {
      ...pkiKeys.humanIdempotency(write.actor.id, write.idempotencyKey),
      operationType: write.operationType,
      requestDigest: write.requestDigest,
      status: "COMMITTED",
      result: write.result,
      createdAt: write.now,
    },
    ConditionExpression: "attribute_not_exists(pk)",
  },
});

export interface CreateCaTransaction {
  readonly idempotency: HumanIdempotencyWrite;
  readonly ca: CaRecord;
}

export const buildCreateCaTransaction = (
  tableName: string,
  input: CreateCaTransaction,
): NamedItem[] => {
  const { ca } = input;
  const notExists = "attribute_not_exists(pk)";
  return [
    {
      slot: "idempotency",
      item: buildHumanIdempotencyPut(tableName, input.idempotency),
    },
    {
      slot: "name",
      item: {
        Put: {
          TableName: tableName,
          Item: {
            ...pkiKeys.caName(ca.environment, ca.name),
            caId: ca.caId,
            environment: ca.environment,
            name: ca.name,
            claimedAt: ca.createdAt,
          },
          ConditionExpression: notExists,
        },
      },
    },
    {
      slot: "subject",
      item: {
        Put: {
          TableName: tableName,
          Item: {
            ...pkiKeys.subject(ca.subjectKey),
            ownerType: "ca",
            caId: ca.caId,
            environment: ca.environment,
            claimedAt: ca.createdAt,
          },
          ConditionExpression: notExists,
        },
      },
    },
    {
      slot: "profile",
      item: {
        Put: {
          TableName: tableName,
          Item: {
            ...pkiKeys.caProfile(ca.caId),
            ...pkiDirectory.ca(ca.environment, ca.name),
            ...defined(ca),
          },
          ConditionExpression: notExists,
        },
      },
    },
  ];
};

export type ActivationExternal =
  | { readonly kind: "create"; readonly record: ExternalCaRecord }
  | {
      readonly kind: "update";
      readonly extId: string;
      readonly loadedVersion: string;
      readonly newVersion: string;
      readonly caId: string;
      readonly environment: string;
    };

export interface ActivateCaTransaction {
  readonly idempotency: HumanIdempotencyWrite;
  readonly caId: string;
  readonly loadedVersion: string;
  readonly newVersion: string;
  /** The activation fields, excluding `status` and `version`. */
  readonly fields: Record<string, unknown>;
  readonly crl: CaCrlState;
  readonly external: ActivationExternal;
  readonly rootSubject: {
    readonly key: string;
    readonly extId: string;
    readonly spkiSha256: string;
    readonly now: string;
  };
}

export const buildActivateCaTransaction = (
  tableName: string,
  input: ActivateCaTransaction,
): NamedItem[] => {
  const fieldNames = Object.keys(input.fields);
  const profileNames: Record<string, string> = {
    "#status": "status",
    "#version": "version",
  };
  const profileValues: Record<string, unknown> = {
    ":pending": "PENDING_CERTIFICATE",
    ":active": "ACTIVE",
    ":loaded": input.loadedVersion,
    ":v": input.newVersion,
  };
  const assignments = ["#status = :active", "#version = :v"];
  for (const name of fieldNames) {
    profileNames[`#${name}`] = name;
    profileValues[`:${name}`] = input.fields[name];
    assignments.push(`#${name} = :${name}`);
  }
  const external: TransactItem =
    input.external.kind === "create"
      ? {
          Put: {
            TableName: tableName,
            Item: {
              ...pkiKeys.externalCa(input.external.record.extId),
              ...pkiDirectory.externalCa(input.external.record.extId),
              ...defined(input.external.record),
            },
            ConditionExpression: "attribute_not_exists(pk)",
          },
        }
      : {
          Update: {
            TableName: tableName,
            Key: { ...pkiKeys.externalCa(input.external.extId) },
            UpdateExpression:
              "SET #version = :v ADD #dependents :dependent, #environments :environment",
            ConditionExpression: "#version = :loaded",
            ExpressionAttributeNames: {
              "#version": "version",
              "#dependents": "dependents",
              "#environments": "environments",
            },
            ExpressionAttributeValues: {
              ":v": input.external.newVersion,
              ":loaded": input.external.loadedVersion,
              ":dependent": new Set([input.external.caId]),
              ":environment": new Set([input.external.environment]),
            },
          },
        };
  const root = input.rootSubject;
  return [
    {
      slot: "idempotency",
      item: buildHumanIdempotencyPut(tableName, input.idempotency),
    },
    {
      slot: "profile",
      item: {
        Update: {
          TableName: tableName,
          Key: { ...pkiKeys.caProfile(input.caId) },
          UpdateExpression: `SET ${assignments.join(", ")}`,
          ConditionExpression: "#status = :pending AND #version = :loaded",
          ExpressionAttributeNames: profileNames,
          ExpressionAttributeValues: profileValues,
        },
      },
    },
    {
      slot: "crl",
      item: {
        Put: {
          TableName: tableName,
          Item: { ...pkiKeys.caCrl(input.caId), ...defined(input.crl) },
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
    },
    { slot: "external", item: external },
    {
      slot: "rootSubject",
      item: {
        Update: {
          TableName: tableName,
          Key: { ...pkiKeys.subject(root.key) },
          UpdateExpression:
            "SET #ownerType = if_not_exists(#ownerType, :external), #extId = if_not_exists(#extId, :extId), #spkiSha256 = if_not_exists(#spkiSha256, :spki), #claimedAt = if_not_exists(#claimedAt, :now)",
          ConditionExpression:
            "attribute_not_exists(pk) OR (#ownerType = :external AND #spkiSha256 = :spki)",
          ExpressionAttributeNames: {
            "#ownerType": "ownerType",
            "#extId": "extId",
            "#spkiSha256": "spkiSha256",
            "#claimedAt": "claimedAt",
          },
          ExpressionAttributeValues: {
            ":external": "external",
            ":extId": root.extId,
            ":spki": root.spkiSha256,
            ":now": root.now,
          },
        },
      },
    },
  ];
};

export interface CaMutationTransaction {
  readonly idempotency: HumanIdempotencyWrite;
  readonly caId: string;
  readonly loadedVersion: string;
  readonly newVersion: string;
  readonly now: string;
}

export interface UpdateCaPolicyTransaction extends CaMutationTransaction {
  readonly policy: CaRecord["policy"];
  readonly maxIssueLifetimeEverSeconds: number;
  readonly displayName?: string;
}

const profileSlot = (
  tableName: string,
  caId: string,
  update: {
    expression: string;
    condition: string;
    names: Record<string, string>;
    values: Record<string, unknown>;
  },
): TransactItem => ({
  Update: {
    TableName: tableName,
    Key: { ...pkiKeys.caProfile(caId) },
    UpdateExpression: update.expression,
    ConditionExpression: update.condition,
    ExpressionAttributeNames: update.names,
    ExpressionAttributeValues: update.values,
  },
});

/** `loadedVersion` is the `If-Match` value the caller checked. */
export const buildUpdateCaPolicyTransaction = (
  tableName: string,
  input: UpdateCaPolicyTransaction,
): NamedItem[] => [
  {
    slot: "idempotency",
    item: buildHumanIdempotencyPut(tableName, input.idempotency),
  },
  {
    slot: "profile",
    item: profileSlot(tableName, input.caId, {
      expression:
        input.displayName === undefined
          ? "SET #policy = :policy, #maxIssueLifetimeEverSeconds = :max, #version = :v REMOVE #displayName"
          : "SET #policy = :policy, #maxIssueLifetimeEverSeconds = :max, #version = :v, #displayName = :displayName",
      condition:
        "#version = :ifMatch AND (#status = :pending OR #status = :active) AND #maxIssueLifetimeEverSeconds <= :max",
      names: {
        "#policy": "policy",
        "#maxIssueLifetimeEverSeconds": "maxIssueLifetimeEverSeconds",
        "#version": "version",
        "#displayName": "displayName",
        "#status": "status",
      },
      values: {
        ":policy": input.policy,
        ":max": input.maxIssueLifetimeEverSeconds,
        ":v": input.newVersion,
        ":ifMatch": input.loadedVersion,
        ":pending": "PENDING_CERTIFICATE",
        ":active": "ACTIVE",
        ...(input.displayName === undefined
          ? {}
          : { ":displayName": input.displayName }),
      },
    }),
  },
];

export const buildAbandonCaTransaction = (
  tableName: string,
  input: CaMutationTransaction,
): NamedItem[] => [
  {
    slot: "idempotency",
    item: buildHumanIdempotencyPut(tableName, input.idempotency),
  },
  {
    slot: "profile",
    item: profileSlot(tableName, input.caId, {
      expression:
        "SET #status = :failed, #key.#state = :destroyed, #failedAt = :now, #version = :v REMOVE #key.#wrapped",
      condition: "#status = :pending AND #version = :loaded",
      names: {
        "#status": "status",
        "#key": "key",
        "#state": "state",
        "#wrapped": "wrapped",
        "#failedAt": "failedAt",
        "#version": "version",
      },
      values: {
        ":failed": "FAILED",
        ":destroyed": "DESTROYED",
        ":pending": "PENDING_CERTIFICATE",
        ":now": input.now,
        ":v": input.newVersion,
        ":loaded": input.loadedVersion,
      },
    }),
  },
];

export const buildRetireCaTransaction = (
  tableName: string,
  input: CaMutationTransaction,
): NamedItem[] => [
  {
    slot: "idempotency",
    item: buildHumanIdempotencyPut(tableName, input.idempotency),
  },
  {
    slot: "profile",
    item: profileSlot(tableName, input.caId, {
      expression:
        "SET #status = :retired, #retiredAt = :now, #version = :v",
      condition: "#status = :active AND #version = :loaded",
      names: {
        "#status": "status",
        "#retiredAt": "retiredAt",
        "#version": "version",
      },
      values: {
        ":retired": "RETIRED",
        ":active": "ACTIVE",
        ":now": input.now,
        ":v": input.newVersion,
        ":loaded": input.loadedVersion,
      },
    }),
  },
];

export const buildDestroyKeyTransaction = (
  tableName: string,
  input: CaMutationTransaction,
): NamedItem[] => [
  {
    slot: "idempotency",
    item: buildHumanIdempotencyPut(tableName, input.idempotency),
  },
  {
    slot: "profile",
    item: profileSlot(tableName, input.caId, {
      expression:
        "SET #key.#state = :destroyed, #keyDestroyedAt = :now, #version = :v REMOVE #key.#wrapped",
      condition: "#key.#state = :disabled AND #version = :loaded",
      names: {
        "#key": "key",
        "#state": "state",
        "#wrapped": "wrapped",
        "#keyDestroyedAt": "keyDestroyedAt",
        "#version": "version",
      },
      values: {
        ":destroyed": "DESTROYED",
        ":disabled": "DISABLED",
        ":now": input.now,
        ":v": input.newVersion,
        ":loaded": input.loadedVersion,
      },
    }),
  },
];

export interface DisableDrainedKeyTransaction {
  readonly caId: string;
  readonly newVersion: string;
  readonly now: string;
  readonly crlRevision: number;
  readonly drainAt: string;
}

export const buildDisableDrainedKeyTransaction = (
  tableName: string,
  input: DisableDrainedKeyTransaction,
): NamedItem[] => [
  {
    slot: "profile",
    item: profileSlot(tableName, input.caId, {
      expression:
        "SET #key.#state = :disabled, #drainedAt = :now, #version = :v",
      condition: "#status = :retired AND #key.#state = :active",
      names: {
        "#status": "status",
        "#key": "key",
        "#state": "state",
        "#drainedAt": "drainedAt",
        "#version": "version",
      },
      values: {
        ":retired": "RETIRED",
        ":active": "ACTIVE",
        ":disabled": "DISABLED",
        ":now": input.now,
        ":v": input.newVersion,
      },
    }),
  },
  {
    slot: "crl",
    item: {
      ConditionCheck: {
        TableName: tableName,
        Key: { ...pkiKeys.caCrl(input.caId) },
        ConditionExpression:
          "#revision = :rev AND #published.#revision = :rev AND #published.#thisUpdate > :drainAt",
        ExpressionAttributeNames: {
          "#revision": "revision",
          "#published": "published",
          "#thisUpdate": "thisUpdate",
        },
        ExpressionAttributeValues: {
          ":rev": input.crlRevision,
          ":drainAt": input.drainAt,
        },
      },
    },
  },
];

export interface ExternalRevocation {
  readonly revokedAt: string;
  readonly reason: string;
  readonly evidence: string;
}

export const buildRetireExpiredCaUpdate = (
  tableName: string,
  ca: Pick<CaRecord, "caId" | "notAfter">,
  now: string,
  newVersion: string,
): UpdateCommandInput => ({
  TableName: tableName,
  Key: { ...pkiKeys.caProfile(ca.caId) },
  UpdateExpression: "SET #status = :retired, #retiredAt = :notAfter, #version = :v",
  ConditionExpression:
    "#status = :active AND #notAfter = :notAfter AND #notAfter <= :now",
  ExpressionAttributeNames: {
    "#status": "status",
    "#retiredAt": "retiredAt",
    "#version": "version",
    "#notAfter": "notAfter",
  },
  ExpressionAttributeValues: {
    ":retired": "RETIRED",
    ":active": "ACTIVE",
    ":notAfter": ca.notAfter,
    ":now": now,
    ":v": newVersion,
  },
  ReturnValues: "ALL_NEW",
});

export const buildRevokeCaExternallyUpdate = (
  tableName: string,
  ca: Pick<CaRecord, "caId" | "serial" | "key">,
  revocation: ExternalRevocation,
  extId: string,
  newVersion: string,
): UpdateCommandInput => ({
  TableName: tableName,
  Key: { ...pkiKeys.caProfile(ca.caId) },
  UpdateExpression: `SET #status = :revoked, #revokedAt = :at, #revocationReason = :reason, #revocationSource = :external, #revocationEvidence = :evidence, #version = :v${
    ca.key.state === "ACTIVE" ? ", #key.#state = :disabled" : ""
  }`,
  ConditionExpression:
    "(#status = :active OR #status = :retired) AND #parent.#id = :extId AND #serial = :serial AND #key.#state = :loadedKeyState",
  ExpressionAttributeNames: {
    "#status": "status",
    "#revokedAt": "revokedAt",
    "#revocationReason": "revocationReason",
    "#revocationSource": "revocationSource",
    "#revocationEvidence": "revocationEvidence",
    "#version": "version",
    "#parent": "parent",
    "#id": "id",
    "#serial": "serial",
    "#key": "key",
    "#state": "state",
  },
  ExpressionAttributeValues: {
    ":revoked": "REVOKED",
    ":active": "ACTIVE",
    ":retired": "RETIRED",
    ":external": "EXTERNAL",
    ":at": revocation.revokedAt,
    ":reason": revocation.reason,
    ":evidence": revocation.evidence,
    ":v": newVersion,
    ":extId": extId,
    ":serial": ca.serial,
    ":loadedKeyState": ca.key.state,
    ...(ca.key.state === "ACTIVE" ? { ":disabled": "DISABLED" } : {}),
  },
});

export const crlLeaseSeconds = 60;

export const buildAcquireCrlLeaseUpdate = (
  tableName: string,
  caId: string,
  owner: string,
  now: Date,
): UpdateCommandInput => ({
  TableName: tableName,
  Key: { ...pkiKeys.caCrl(caId) },
  UpdateExpression: "SET #lease = :lease",
  ConditionExpression:
    "attribute_exists(pk) AND (attribute_not_exists(#lease) OR #lease.#expiresAt < :now OR #lease.#owner = :owner)",
  ExpressionAttributeNames: {
    "#lease": "lease",
    "#expiresAt": "expiresAt",
    "#owner": "owner",
  },
  ExpressionAttributeValues: {
    ":lease": {
      owner,
      expiresAt: new Date(now.getTime() + crlLeaseSeconds * 1000).toISOString(),
    },
    ":now": now.toISOString(),
    ":owner": owner,
  },
});

export const buildAllocateCrlNumberUpdate = (
  tableName: string,
  caId: string,
  owner: string,
): UpdateCommandInput => ({
  TableName: tableName,
  Key: { ...pkiKeys.caCrl(caId) },
  UpdateExpression: "SET #lastNumber = #lastNumber + :one",
  ConditionExpression: "#lease.#owner = :owner",
  ExpressionAttributeNames: {
    "#lastNumber": "lastNumber",
    "#lease": "lease",
    "#owner": "owner",
  },
  ExpressionAttributeValues: { ":one": 1, ":owner": owner },
  ReturnValues: "ALL_NEW",
});

export interface CrlCommit {
  readonly caId: string;
  readonly owner: string;
  readonly number: number;
  readonly startRevision: number;
  readonly published: NonNullable<CaCrlState["published"]>;
  /** Remove `dirtySince`; only valid while `revision` still equals `startRevision`. */
  readonly clearDirty: boolean;
}

export const buildCommitCrlUpdate = (
  tableName: string,
  commit: CrlCommit,
): NonNullable<TransactItem["Update"]> => ({
  TableName: tableName,
  Key: { ...pkiKeys.caCrl(commit.caId) },
  UpdateExpression: `SET #published = :pub REMOVE #lease${
    commit.clearDirty ? ", #dirtySince" : ""
  }`,
  ConditionExpression: `#lease.#owner = :owner AND (attribute_not_exists(#published) OR #published.#number < :n)${
    commit.clearDirty ? " AND #revision = :startRevision" : ""
  }`,
  ExpressionAttributeNames: {
    "#published": "published",
    "#lease": "lease",
    "#owner": "owner",
    "#number": "number",
    ...(commit.clearDirty
      ? { "#dirtySince": "dirtySince", "#revision": "revision" }
      : {}),
  },
  ExpressionAttributeValues: {
    ":pub": defined(commit.published),
    ":owner": commit.owner,
    ":n": commit.number,
    ...(commit.clearDirty ? { ":startRevision": commit.startRevision } : {}),
  },
});

export interface ExternalCrlCommit {
  readonly extId: string;
  readonly loadedVersion: string;
  readonly newVersion: string;
  readonly crl: NonNullable<ExternalCaRecord["crl"]>;
  readonly idempotency: HumanIdempotencyWrite;
}

export const buildCommitExternalCrlTransaction = (
  tableName: string,
  commit: ExternalCrlCommit,
): NamedItem[] => [
  {
    slot: "idempotency",
    item: buildHumanIdempotencyPut(tableName, commit.idempotency),
  },
  {
    slot: "external",
    item: {
      Update: {
        TableName: tableName,
        Key: { ...pkiKeys.externalCa(commit.extId) },
        UpdateExpression: "SET #crl = :crl, #version = :v",
        ConditionExpression:
          "#version = :loaded AND (attribute_not_exists(#crl) OR (#crl.#numberHex < :nh AND #crl.#thisUpdate <= :tu))",
        ExpressionAttributeNames: {
          "#crl": "crl",
          "#version": "version",
          "#numberHex": "numberHex",
          "#thisUpdate": "thisUpdate",
        },
        ExpressionAttributeValues: {
          ":crl": defined(commit.crl),
          ":v": commit.newVersion,
          ":loaded": commit.loadedVersion,
          ":nh": commit.crl.numberHex,
          ":tu": commit.crl.thisUpdate,
        },
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

export interface PkiRepositoryOptions {
  readonly tableName: string;
  readonly directoryIndex: string;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
}

/** Definitely not applied, and a bug or IAM regression rather than load. */
const fatalErrorNames = new Set([
  "IdempotentParameterMismatchException",
  "ValidationException",
  "ResourceNotFoundException",
  "AccessDeniedException",
  "UnrecognizedClientException",
]);
const maxConflictRetries = 3;
const maxAmbiguousRetries = 1;

const errorName = (error: unknown): string =>
  error instanceof Error ? error.name : typeof error;

/** The `pki-directory` index exists but cannot be queried yet (still backfilling after an upgrade). */
export class PkiIndexNotReadyError extends Error {
  public constructor() {
    super("The PKI directory index is not ready.");
    this.name = "PkiIndexNotReadyError";
  }
}

export class PkiRepository {
  private readonly tableName: string;
  private readonly directoryIndex: string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  public constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    options: PkiRepositoryOptions,
  ) {
    this.tableName = options.tableName;
    this.directoryIndex = options.directoryIndex;
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.random = options.random ?? Math.random;
  }

  /**
   * Reads one `pki-directory` partition. Defence in depth: an item whose `pk` does not start with `PKI_` is ignored
   * even if it carries the index attributes, and paging continues until `limit` valid items are found. Phase 3 and 4
   * readers use this rather than querying the index directly.
   */
  public async queryDirectory(
    partition: string,
    options: { limit?: number; sortPrefix?: string } = {},
  ): Promise<Record<string, unknown>[]> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const found: Record<string, unknown>[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const remaining = limit - found.length;
      let response;
      try {
        response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: this.directoryIndex,
          KeyConditionExpression:
            options.sortPrefix === undefined
              ? "#pk = :pk"
              : "#pk = :pk AND begins_with(#sk, :prefix)",
          ExpressionAttributeNames: {
            "#pk": "pkiDirectoryPk",
            ...(options.sortPrefix === undefined
              ? {}
              : { "#sk": "pkiDirectorySk" }),
          },
          ExpressionAttributeValues: {
            ":pk": partition,
            ...(options.sortPrefix === undefined
              ? {}
              : { ":prefix": options.sortPrefix }),
          },
          ...(Number.isFinite(remaining) ? { Limit: remaining } : {}),
          ...(start === undefined ? {} : { ExclusiveStartKey: start }),
        }),
      );
      } catch (error) {
        if (
          error instanceof Error &&
          error.name === "ValidationException" &&
          /backfill|specified index/i.test(error.message)
        ) {
          throw new PkiIndexNotReadyError();
        }
        throw error;
      }
      for (const item of response.Items ?? []) {
        if (typeof item.pk === "string" && item.pk.startsWith("PKI_")) {
          found.push(item);
          if (found.length >= limit) {
            return found;
          }
        }
      }
      start = response.LastEvaluatedKey;
    } while (start !== undefined);
    return found;
  }

  /** The directory index is eventually consistent; this answers "has any CA ever been created". */
  public async hasAnyCa(): Promise<boolean> {
    return (await this.queryDirectory("PKI_CAS", { limit: 1 })).length > 0;
  }

  public async getReplayRecord(
    consumerId: string,
    key: string,
  ): Promise<ReplayRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { ...pkiKeys.replay(consumerId, key) },
        ConsistentRead: true,
      }),
    );
    const item = response.Item;
    if (item === undefined) {
      return undefined;
    }
    if (
      typeof item.requestDigest !== "string" ||
      typeof item.caId !== "string" ||
      typeof item.serial !== "string" ||
      typeof item.notAfter !== "string" ||
      typeof item.grantUid !== "string"
    ) {
      throw serviceUnavailable("A stored PKI replay record is malformed.");
    }
    return {
      requestDigest: item.requestDigest,
      caId: item.caId,
      serial: item.serial,
      notAfter: item.notAfter,
      grantUid: item.grantUid,
    };
  }

  public async getQuotaCount(key: PkiKey): Promise<number> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk: key.pk, sk: key.sk },
        ConsistentRead: true,
      }),
    );
    if (response.Item === undefined) {
      return 0;
    }
    const count: unknown = response.Item.count;
    if (typeof count !== "number" || !Number.isSafeInteger(count)) {
      throw serviceUnavailable("A stored PKI quota counter is malformed.");
    }
    return count;
  }

  /**
   * Commits one certificate. The input is built once per generation and never rebuilt otherwise: a transaction
   * conflict is definitely not applied and moves to a new generation (a new `ClientRequestToken`, at most 3 times); an
   * ambiguous failure resends the identical input with the same token (at most once), after which the caller reads the
   * replay record back.
   */
  public async commitIssuance(
    commit: IssuanceCommit,
  ): Promise<IssuanceCommitOutcome> {
    let generation = 0;
    let conflicts = 0;
    let ambiguous = 0;
    let built = buildIssuanceCommit(this.tableName, commit, generation);
    for (;;) {
      try {
        await this.dynamo.send(new TransactWriteCommand(built.input));
        return { kind: "committed" };
      } catch (error) {
        const name = errorName(error);
        if (name === "TransactionCanceledException") {
          const classified = classifyIssuanceCancellation(built, commit, error);
          if (classified.kind !== "retry") {
            return classified;
          }
          if (conflicts >= maxConflictRetries) {
            return { kind: "conflict" };
          }
          await this.sleep(this.backoff(conflicts));
          conflicts += 1;
          generation += 1;
          built = buildIssuanceCommit(this.tableName, commit, generation);
          continue;
        }
        if (fatalErrorNames.has(name)) {
          console.error("PKI issuance commit failed", { name });
          throw serviceUnavailable("The certificate could not be committed.");
        }
        // Timeouts, network failures, 5xx, ThrottlingException and TransactionInProgressException.
        if (ambiguous >= maxAmbiguousRetries) {
          return { kind: "ambiguous" };
        }
        await this.sleep(this.backoff(ambiguous));
        ambiguous += 1;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Generic executors
  // -------------------------------------------------------------------------

  /**
   * Runs one transaction. A transaction conflict is definitely not applied and retries under a new token (at most 3
   * times); an ambiguous failure resends the identical input with the same token (at most once). Returns the names
   * of the slots whose condition failed on cancellation.
   */
  public async transact(
    label: string,
    items: readonly NamedItem[],
    token: { principal: string; idempotencyKey?: string },
  ): Promise<TransactOutcome> {
    const nonce = token.idempotencyKey ?? newId();
    const input = (generation: number): TransactWriteCommandInput => ({
      TransactItems: items.map((entry) => entry.item),
      ClientRequestToken: sha256Hex(
        stableJson([
          "pki-admin",
          label,
          token.principal,
          nonce,
          generation,
        ]),
      ).slice(0, 36),
    });
    let generation = 0;
    let conflicts = 0;
    let ambiguous = 0;
    for (;;) {
      try {
        await this.dynamo.send(new TransactWriteCommand(input(generation)));
        return { kind: "committed" };
      } catch (error) {
        const name = errorName(error);
        if (name === "TransactionCanceledException") {
          const reasons = cancellationReasons(error);
          if (reasons === undefined || reasons.length !== items.length) {
            return { kind: "canceled", failed: ["unknown"] };
          }
          const codes = reasons.map((reason) => reason.Code ?? "None");
          const failed = items
            .filter((_, index) => codes[index] === "ConditionalCheckFailed")
            .map((entry) => entry.slot);
          if (failed.length > 0) {
            return { kind: "canceled", failed };
          }
          const others = codes.filter((code) => code !== "None");
          if (others.length === 0) {
            return { kind: "canceled", failed: ["unknown"] };
          }
          if (others.every((code) => transientCodes.has(code))) {
            if (conflicts >= maxConflictRetries) {
              throw serviceUnavailable("The change could not be committed.");
            }
            await this.sleep(this.backoff(conflicts));
            conflicts += 1;
            generation += 1;
            continue;
          }
          console.error("PKI transaction canceled", { label, codes: others });
          throw serviceUnavailable("The change could not be committed.");
        }
        if (fatalErrorNames.has(name)) {
          console.error("PKI transaction failed", { label, name });
          throw serviceUnavailable("The change could not be committed.");
        }
        if (ambiguous >= maxAmbiguousRetries) {
          throw serviceUnavailable("The change could not be confirmed.");
        }
        await this.sleep(this.backoff(ambiguous));
        ambiguous += 1;
      }
    }
  }

  /** A single `UpdateItem` that retries transaction conflicts with jitter. Every `PKI_CA#` single-item write uses it. */
  public async updateWithRetry(
    input: UpdateCommandInput,
  ): Promise<
    | { readonly kind: "updated"; readonly attributes?: Record<string, unknown> }
    | { readonly kind: "conditionFailed" }
  > {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const response = await this.dynamo.send(new UpdateCommand(input));
        return { kind: "updated", attributes: response.Attributes };
      } catch (error) {
        const name = errorName(error);
        if (name === "ConditionalCheckFailedException") {
          return { kind: "conditionFailed" };
        }
        if (name === "TransactionConflictException" && attempt < maxConflictRetries) {
          await this.sleep(this.backoff(attempt));
          continue;
        }
        console.error("PKI update failed", { name });
        throw serviceUnavailable("The change could not be committed.");
      }
    }
  }

  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  private async getItem(key: PkiKey): Promise<Record<string, unknown> | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk: key.pk, sk: key.sk },
        ConsistentRead: true,
      }),
    );
    return response.Item;
  }

  public async getCa(id: string): Promise<CaRecord | undefined> {
    const item = await this.getItem(pkiKeys.caProfile(id));
    return item === undefined ? undefined : toCaRecord(item);
  }

  public async getCaCrlState(id: string): Promise<CaCrlState | undefined> {
    const item = await this.getItem(pkiKeys.caCrl(id));
    if (item === undefined) {
      return undefined;
    }
    if (
      typeof item.revision !== "number" ||
      typeof item.lastNumber !== "number"
    ) {
      throw serviceUnavailable("A stored CRL state record is malformed.");
    }
    const { pk: _pk, sk: _sk, ...state } = item;
    return state as unknown as CaCrlState;
  }

  public async getExternalCa(extId: string): Promise<ExternalCaRecord | undefined> {
    const item = await this.getItem(pkiKeys.externalCa(extId));
    return item === undefined ? undefined : toExternalCaRecord(item);
  }

  public async getSubjectClaim(key: string): Promise<Record<string, unknown> | undefined> {
    return this.getItem(pkiKeys.subject(key));
  }

  public async getCaNameClaim(
    environment: string,
    name: string,
  ): Promise<Record<string, unknown> | undefined> {
    return this.getItem(pkiKeys.caName(environment, name));
  }

  /** One page of a directory partition, with the exclusive start key for the next page. */
  public async queryDirectoryPage(
    partition: string,
    options: {
      sortPrefix?: string;
      limit: number;
      exclusiveStartKey?: Record<string, unknown>;
    },
  ): Promise<{
    items: Record<string, unknown>[];
    lastEvaluatedKey?: Record<string, unknown>;
  }> {
    const found: Record<string, unknown>[] = [];
    let start = options.exclusiveStartKey;
    for (;;) {
      const remaining = options.limit - found.length;
      let response;
      try {
        response = await this.dynamo.send(
          new QueryCommand({
            TableName: this.tableName,
            IndexName: this.directoryIndex,
            KeyConditionExpression:
              options.sortPrefix === undefined
                ? "#pk = :pk"
                : "#pk = :pk AND begins_with(#sk, :prefix)",
            ExpressionAttributeNames: {
              "#pk": "pkiDirectoryPk",
              ...(options.sortPrefix === undefined
                ? {}
                : { "#sk": "pkiDirectorySk" }),
            },
            ExpressionAttributeValues: {
              ":pk": partition,
              ...(options.sortPrefix === undefined
                ? {}
                : { ":prefix": options.sortPrefix }),
            },
            Limit: remaining,
            ...(start === undefined ? {} : { ExclusiveStartKey: start }),
          }),
        );
      } catch (error) {
        if (
          error instanceof Error &&
          error.name === "ValidationException" &&
          /backfill|specified index/i.test(error.message)
        ) {
          throw new PkiIndexNotReadyError();
        }
        throw error;
      }
      for (const item of response.Items ?? []) {
        if (typeof item.pk === "string" && item.pk.startsWith("PKI_")) {
          found.push(item);
        }
      }
      start = response.LastEvaluatedKey;
      if (found.length >= options.limit || start === undefined) {
        return {
          items: found,
          ...(start === undefined ? {} : { lastEvaluatedKey: start }),
        };
      }
    }
  }

  public async listCasPage(options: {
    environment: string;
    limit: number;
    start?: Record<string, unknown>;
  }): Promise<{ cas: CaRecord[]; lastEvaluatedKey?: Record<string, unknown> }> {
    const page = await this.queryDirectoryPage("PKI_CAS", {
      sortPrefix: `${guardEnvironment(options.environment)}#`,
      limit: options.limit,
      exclusiveStartKey: options.start,
    });
    return {
      cas: page.items.map(toCaRecord),
      ...(page.lastEvaluatedKey === undefined
        ? {}
        : { lastEvaluatedKey: page.lastEvaluatedKey }),
    };
  }

  public async listExternalCasPage(options: {
    limit: number;
    start?: Record<string, unknown>;
  }): Promise<{
    externalCas: ExternalCaRecord[];
    lastEvaluatedKey?: Record<string, unknown>;
  }> {
    const page = await this.queryDirectoryPage("PKI_EXTCAS", {
      limit: options.limit,
      exclusiveStartKey: options.start,
    });
    return {
      externalCas: page.items.map(toExternalCaRecord),
      ...(page.lastEvaluatedKey === undefined
        ? {}
        : { lastEvaluatedKey: page.lastEvaluatedKey }),
    };
  }

  /** Revocation entries still relevant to the next CRL: every entry, or those with `notAfter >= since`. */
  public async listRevocationsSince(
    id: string,
    since?: string,
  ): Promise<RevocationEntryRecord[]> {
    const entries: RevocationEntryRecord[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
          ...(since === undefined
            ? {}
            : { FilterExpression: "#notAfter >= :since" }),
          ExpressionAttributeNames:
            since === undefined ? undefined : { "#notAfter": "notAfter" },
          ExpressionAttributeValues: {
            ":pk": pkiKeys.caCrl(id).pk,
            ":prefix": "REVOKED#",
            ...(since === undefined ? {} : { ":since": since }),
          },
          ConsistentRead: true,
          ...(start === undefined ? {} : { ExclusiveStartKey: start }),
        }),
      );
      for (const item of response.Items ?? []) {
        entries.push(toRevocationEntry(item));
      }
      start = response.LastEvaluatedKey;
    } while (start !== undefined);
    return entries;
  }

  public async hasGrantsForCa(id: string): Promise<boolean> {
    return (
      (await this.queryDirectory(`PKI_CA_GRANTS#${caId(id)}`, { limit: 1 }))
        .length > 0
    );
  }

  // -------------------------------------------------------------------------
  // Human mutations (idempotency record in slot 0)
  // -------------------------------------------------------------------------

  private humanToken(write: HumanIdempotencyWrite): {
    principal: string;
    idempotencyKey: string;
  } {
    return {
      principal: `human:${write.actor.id}`,
      idempotencyKey: write.idempotencyKey,
    };
  }

  private async commitHuman(
    label: string,
    write: HumanIdempotencyWrite,
    items: readonly NamedItem[],
  ): Promise<TransactOutcome> {
    return this.transact(label, items, this.humanToken(write));
  }

  public async createCa(
    input: CreateCaTransaction,
  ): Promise<
    | { kind: "created" }
    | { kind: "replay" }
    | { kind: "nameInUse" }
    | { kind: "subjectInUse" }
  > {
    const outcome = await this.commitHuman(
      "create-ca",
      input.idempotency,
      buildCreateCaTransaction(this.tableName, input),
    );
    if (outcome.kind === "committed") {
      return { kind: "created" };
    }
    if (outcome.failed.includes("idempotency")) {
      return { kind: "replay" };
    }
    if (outcome.failed.includes("name")) {
      return { kind: "nameInUse" };
    }
    if (outcome.failed.includes("subject")) {
      return { kind: "subjectInUse" };
    }
    throw serviceUnavailable("The CA could not be created.");
  }

  public async activateCa(
    input: ActivateCaTransaction,
  ): Promise<
    | { kind: "activated" }
    | { kind: "replay" }
    | { kind: "rootSubjectInUse" }
    | { kind: "externalChanged" }
    | { kind: "profileChanged" }
  > {
    const outcome = await this.commitHuman(
      "activate-ca",
      input.idempotency,
      buildActivateCaTransaction(this.tableName, input),
    );
    if (outcome.kind === "committed") {
      return { kind: "activated" };
    }
    if (outcome.failed.includes("idempotency")) {
      return { kind: "replay" };
    }
    if (outcome.failed.includes("rootSubject")) {
      return { kind: "rootSubjectInUse" };
    }
    if (outcome.failed.includes("external")) {
      return { kind: "externalChanged" };
    }
    if (outcome.failed.includes("profile")) {
      return { kind: "profileChanged" };
    }
    throw serviceUnavailable("The CA could not be activated.");
  }

  private async profileMutation(
    label: string,
    write: HumanIdempotencyWrite,
    items: readonly NamedItem[],
  ): Promise<{ kind: "committed" | "replay" | "conditionFailed" }> {
    const outcome = await this.commitHuman(label, write, items);
    if (outcome.kind === "committed") {
      return { kind: "committed" };
    }
    if (outcome.failed.includes("idempotency")) {
      return { kind: "replay" };
    }
    if (outcome.failed.includes("profile")) {
      return { kind: "conditionFailed" };
    }
    throw serviceUnavailable("The change could not be committed.");
  }

  public updateCaPolicy(input: UpdateCaPolicyTransaction) {
    return this.profileMutation(
      "update-ca",
      input.idempotency,
      buildUpdateCaPolicyTransaction(this.tableName, input),
    );
  }

  public abandonCa(input: CaMutationTransaction) {
    return this.profileMutation(
      "abandon-ca",
      input.idempotency,
      buildAbandonCaTransaction(this.tableName, input),
    );
  }

  public retireCa(input: CaMutationTransaction) {
    return this.profileMutation(
      "retire-ca",
      input.idempotency,
      buildRetireCaTransaction(this.tableName, input),
    );
  }

  public destroyKey(input: CaMutationTransaction) {
    return this.profileMutation(
      "destroy-key",
      input.idempotency,
      buildDestroyKeyTransaction(this.tableName, input),
    );
  }

  /** Only the idempotency record (an identical-CRL upload). */
  public async putHumanIdempotency(
    write: HumanIdempotencyWrite,
  ): Promise<"committed" | "replay"> {
    const outcome = await this.commitHuman("idempotency", write, [
      {
        slot: "idempotency",
        item: buildHumanIdempotencyPut(this.tableName, write),
      },
    ]);
    if (outcome.kind === "committed") {
      return "committed";
    }
    if (outcome.failed.includes("idempotency")) {
      return "replay";
    }
    throw serviceUnavailable("The change could not be committed.");
  }

  // -------------------------------------------------------------------------
  // System mutations (maintenance)
  // -------------------------------------------------------------------------

  /** Retires an ACTIVE CA whose certificate expired. Returns the updated record, or undefined when it changed. */
  public async retireExpiredCa(
    ca: Pick<CaRecord, "caId" | "notAfter">,
    now: Date,
  ): Promise<CaRecord | undefined> {
    const result = await this.updateWithRetry(
      buildRetireExpiredCaUpdate(
        this.tableName,
        ca,
        now.toISOString(),
        `pkv-${newId()}`,
      ),
    );
    return result.kind === "updated" && result.attributes !== undefined
      ? toCaRecord(result.attributes)
      : undefined;
  }

  public async disableDrainedKey(
    ca: Pick<CaRecord, "caId">,
    crl: Pick<CaCrlState, "revision">,
    drainAt: string,
    now: Date,
  ): Promise<boolean> {
    const outcome = await this.transact(
      "disable-drained-key",
      buildDisableDrainedKeyTransaction(this.tableName, {
        caId: ca.caId,
        newVersion: `pkv-${newId()}`,
        now: now.toISOString(),
        crlRevision: crl.revision,
        drainAt,
      }),
      { principal: "system:pki-maintenance" },
    );
    return outcome.kind === "committed";
  }

  public async revokeCaExternally(
    ca: Pick<CaRecord, "caId" | "serial" | "key">,
    revocation: ExternalRevocation,
    extId: string,
  ): Promise<"revoked" | "stale"> {
    const result = await this.updateWithRetry(
      buildRevokeCaExternallyUpdate(
        this.tableName,
        ca,
        revocation,
        extId,
        `pkv-${newId()}`,
      ),
    );
    return result.kind === "updated" ? "revoked" : "stale";
  }

  // -------------------------------------------------------------------------
  // CRL publication
  // -------------------------------------------------------------------------

  public async acquireCrlLease(
    id: string,
    owner: string,
    now: Date,
  ): Promise<"acquired" | "busy"> {
    const result = await this.updateWithRetry(
      buildAcquireCrlLeaseUpdate(this.tableName, id, owner, now),
    );
    return result.kind === "updated" ? "acquired" : "busy";
  }

  public async allocateCrlNumber(
    id: string,
    owner: string,
  ): Promise<
    | {
        number: number;
        startRevision: number;
        previous?: NonNullable<CaCrlState["published"]>;
      }
    | "lost"
  > {
    const result = await this.updateWithRetry(
      buildAllocateCrlNumberUpdate(this.tableName, id, owner),
    );
    if (result.kind !== "updated" || result.attributes === undefined) {
      return "lost";
    }
    const { lastNumber, revision, published } = result.attributes;
    if (typeof lastNumber !== "number" || typeof revision !== "number") {
      throw serviceUnavailable("A stored CRL state record is malformed.");
    }
    return {
      number: lastNumber,
      startRevision: revision,
      ...(published === undefined
        ? {}
        : { previous: published as NonNullable<CaCrlState["published"]> }),
    };
  }

  /** Commits the pointer. With `idempotency` the human record is written in the same transaction. */
  public async commitCrlPublication(
    commit: CrlCommit & { idempotency?: HumanIdempotencyWrite },
  ): Promise<"committed" | "conditionFailed" | "replay"> {
    const update = buildCommitCrlUpdate(this.tableName, commit);
    if (commit.idempotency === undefined) {
      const result = await this.updateWithRetry(update);
      return result.kind === "updated" ? "committed" : "conditionFailed";
    }
    const outcome = await this.commitHuman("publish-crl", commit.idempotency, [
      {
        slot: "idempotency",
        item: buildHumanIdempotencyPut(this.tableName, commit.idempotency),
      },
      { slot: "crl", item: { Update: update } },
    ]);
    if (outcome.kind === "committed") {
      return "committed";
    }
    if (outcome.failed.includes("idempotency")) {
      return "replay";
    }
    if (outcome.failed.includes("crl")) {
      return "conditionFailed";
    }
    throw serviceUnavailable("The CRL could not be committed.");
  }

  /** Gives every carried entry whose certificate expired before `before` a DynamoDB TTL. */
  public async expireCarriedRevocations(
    id: string,
    before: string,
    ttl: number,
  ): Promise<number> {
    const expired: string[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
          FilterExpression: "#notAfter < :before AND attribute_not_exists(#ttl)",
          ExpressionAttributeNames: { "#notAfter": "notAfter", "#ttl": "ttl" },
          ExpressionAttributeValues: {
            ":pk": pkiKeys.caCrl(id).pk,
            ":prefix": "REVOKED#",
            ":before": before,
          },
          ConsistentRead: true,
          ...(start === undefined ? {} : { ExclusiveStartKey: start }),
        }),
      );
      for (const item of response.Items ?? []) {
        if (typeof item.sk === "string") {
          expired.push(item.sk);
        }
      }
      start = response.LastEvaluatedKey;
    } while (start !== undefined);
    const pk = pkiKeys.caCrl(id).pk;
    const next = [...expired];
    const worker = async (): Promise<void> => {
      for (let sk = next.pop(); sk !== undefined; sk = next.pop()) {
        const result = await this.updateWithRetry({
          TableName: this.tableName,
          Key: { pk, sk },
          UpdateExpression: "SET #ttl = :ttl",
          ConditionExpression:
            "attribute_exists(pk) AND attribute_not_exists(#ttl)",
          ExpressionAttributeNames: { "#ttl": "ttl" },
          ExpressionAttributeValues: { ":ttl": ttl },
        });
        void result;
      }
    };
    await Promise.all(Array.from({ length: Math.min(10, expired.length) }, worker));
    return expired.length;
  }

  public async markCrlSwept(id: string, thisUpdate: string): Promise<void> {
    await this.updateWithRetry({
      TableName: this.tableName,
      Key: { ...pkiKeys.caCrl(id) },
      UpdateExpression: "SET #sweptThrough = :t",
      ConditionExpression: "#published.#thisUpdate = :t",
      ExpressionAttributeNames: {
        "#sweptThrough": "sweptThrough",
        "#published": "published",
        "#thisUpdate": "thisUpdate",
      },
      ExpressionAttributeValues: { ":t": thisUpdate },
    });
  }

  public async commitExternalCrl(
    commit: ExternalCrlCommit,
  ): Promise<"committed" | "replay" | "externalChanged"> {
    const outcome = await this.commitHuman(
      "upload-root-crl",
      commit.idempotency,
      buildCommitExternalCrlTransaction(this.tableName, commit),
    );
    if (outcome.kind === "committed") {
      return "committed";
    }
    if (outcome.failed.includes("idempotency")) {
      return "replay";
    }
    if (outcome.failed.includes("external")) {
      return "externalChanged";
    }
    throw serviceUnavailable("The CRL could not be committed.");
  }

  private backoff(attempt: number): number {
    return Math.min(400, 25 * 2 ** attempt) + this.random() * 25;
  }
}
