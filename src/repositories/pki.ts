import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  type DynamoDBDocumentClient,
  type TransactWriteCommandInput,
} from "@aws-sdk/lib-dynamodb";
import { assertEnvironmentName } from "../domain/validation";
import { serviceUnavailable } from "../domain/errors";
import type { Actor } from "../domain/types";
import type { IssuedCertificateRecord, ReplayRecord } from "../pki/types";
import { sha256Hex, stableJson } from "../util/encoding";

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

  private backoff(attempt: number): number {
    return Math.min(400, 25 * 2 ** attempt) + this.random() * 25;
  }
}
