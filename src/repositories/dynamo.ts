import {
  DeleteCommand,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactGetCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../aws/config";
import { conflict, notFound, serviceUnavailable } from "../domain/errors";
import type {
  AccessRecord,
  AgentGrantRecord,
  Actor,
  BootstrapCapabilityRecord,
  CatalogPage,
  ChangePage,
  ConsumerSecretGrantPage,
  ConsumerProvisioningResult,
  ConsumerRecord,
  ControlRevision,
  EnvironmentRecord,
  EnrollmentOperationType,
  EnrollmentRecord,
  HeadRecord,
  IdentityRecord,
  IssuerRecord,
  ObjectReference,
  NotificationOutboxRecord,
  PayloadRevision,
  SecretState,
  TruststoreRootRecord,
  WorkflowState,
} from "../domain/types";
import type { StoredCursor } from "../services/cursor";
import { isoNow, newId } from "../util/encoding";

export interface StoredWorkflow {
  readonly pk: string;
  readonly sk: string;
  readonly workflowState: WorkflowState;
  readonly operationId: string;
  readonly objectKey: string;
  readonly checksumSha256: string;
  readonly expiresAt: string;
  readonly serialized?: object;
  readonly s3VersionId?: string;
  readonly workflowKind?: "secret.mutation" | "consumer.enrollment";
}

export interface StoredControlRevision extends StoredWorkflow {
  readonly serialized: ControlRevision;
}

export interface RevisionHistoryPage {
  readonly revisions: readonly StoredControlRevision[];
  readonly truncated: boolean;
}

export interface SecretTreeFolder {
  readonly segment: string;
  readonly path: string;
  readonly secretCount: number;
  /**
   * Folders are derived solely from slash-separated secret IDs.
   */
  readonly kind: "derived";
}

export interface SecretTreePage {
  readonly folders: readonly SecretTreeFolder[];
  readonly secrets: readonly HeadRecord[];
  readonly truncated: boolean;
}

export interface PreparedMutation {
  readonly operationId: string;
  readonly idempotencyKey: string;
  readonly actor: Actor;
  readonly requestDigest: string;
  readonly secretId: string;
  readonly secretUid: string;
  readonly environment: string;
  readonly expectedControlVersionId?: string;
  /** Moves a completed secret out of the live catalog and releases its name. */
  readonly archive?: true;
  readonly control: ControlRevision;
  readonly controlKey: string;
  readonly controlChecksumSha256: string;
  readonly controlBytes: Buffer;
  readonly payload?: {
    readonly revision: PayloadRevision;
    readonly key: string;
    readonly checksumSha256: string;
    readonly bytes: Buffer;
  };
  readonly expiresAt: string;
}

export interface CompletedMutation {
  readonly prepared: PreparedMutation;
  readonly controlObject: ObjectReference;
  readonly payloadObject?: ObjectReference;
  readonly priorHead?: HeadRecord;
  readonly priorAccess: readonly AccessRecord[];
}

export interface AccessAndHead {
  readonly access?: AccessRecord;
  readonly head?: HeadRecord;
}

export interface PreparedEnrollment {
  readonly operationId: string;
  readonly operationType: EnrollmentOperationType;
  readonly idempotencyKey: string;
  readonly actor: Actor;
  readonly requestDigest: string;
  readonly consumerId: string;
  readonly environment: string;
  readonly subjectUri: string;
  readonly rootFingerprint: string;
  readonly apiIdentity: Omit<IdentityRecord, "pk" | "sk" | "status"> & {
    readonly certificatePem: string;
  };
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface TruststoreStateRecord {
  readonly pk: "SYSTEM#TRUSTSTORE";
  readonly sk: "STATE";
  readonly currentTruststoreKey?: string;
  readonly currentTruststoreVersionId?: string;
  readonly currentTruststoreChecksumSha256?: string;
  readonly currentRootFingerprints?: readonly string[];
}

const maximumRevisionHistory = 500;
const maximumBoundedScan = 500;
const maximumEnvironments = 100;

export class DynamoRepository {
  public constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    private readonly config: AppConfig,
  ) {}

  public async getHead(
    environment: string,
    secretId: string,
  ): Promise<HeadRecord | undefined> {
    const secretUid = await this.getSecretUid(environment, secretId);
    return secretUid === undefined
      ? undefined
      : this.getHeadBySecretUid(secretUid);
  }

  public async getSecretUid(
    environment: string,
    secretId: string,
  ): Promise<string | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: secretNamePk(environment, secretId), sk: "LOOKUP" },
        ConsistentRead: true,
      }),
    );
    return typeof response.Item?.secretUid === "string"
      ? response.Item.secretUid
      : undefined;
  }

  public async getHeadBySecretUid(
    secretUid: string,
  ): Promise<HeadRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: secretPk(secretUid), sk: "HEAD" },
        ConsistentRead: true,
      }),
    );
    return response.Item as HeadRecord | undefined;
  }

  /**
   * Pagination state is opaque to callers and expires through the table's TTL
   * attribute. A conditional put turns the already negligible 256-bit token
   * collision chance into a retry rather than a state overwrite.
   */
  public async createCursor(cursor: StoredCursor): Promise<boolean> {
    try {
      await this.dynamo.send(
        new PutCommand({
          TableName: this.config.controlTableName,
          Item: {
            pk: cursorPk(cursor.token),
            sk: "STATE",
            scope: cursor.scope,
            ...(cursor.lastEvaluatedKey === undefined
              ? {}
              : { lastEvaluatedKey: cursor.lastEvaluatedKey }),
            expiresAt: cursor.expiresAt,
            ttl: cursor.ttl,
          },
          ConditionExpression: "attribute_not_exists(pk)",
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  public async getCursor(token: string): Promise<StoredCursor | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: cursorPk(token), sk: "STATE" },
        ConsistentRead: true,
      }),
    );
    if (response.Item === undefined) {
      return undefined;
    }
    const item = response.Item;
    if (
      typeof item.scope !== "string" ||
      typeof item.expiresAt !== "string" ||
      typeof item.ttl !== "number" ||
      (item.lastEvaluatedKey !== undefined &&
        (item.lastEvaluatedKey === null ||
          typeof item.lastEvaluatedKey !== "object" ||
          Array.isArray(item.lastEvaluatedKey)))
    ) {
      return undefined;
    }
    return {
      token,
      scope: item.scope,
      ...(item.lastEvaluatedKey === undefined
        ? {}
        : {
            lastEvaluatedKey: item.lastEvaluatedKey as Record<string, string>,
          }),
      expiresAt: item.expiresAt,
      ttl: item.ttl,
    };
  }

  public async listEnvironments(): Promise<readonly EnvironmentRecord[]> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": environmentsPk,
          ":prefix": "ENVIRONMENT#",
        },
        Limit: maximumEnvironments + 1,
        ConsistentRead: true,
      }),
    );
    if (
      response.LastEvaluatedKey !== undefined ||
      (response.Items?.length ?? 0) > maximumEnvironments
    ) {
      throw serviceUnavailable(
        "The environment registry exceeds its supported size.",
      );
    }
    return (response.Items ?? []) as EnvironmentRecord[];
  }

  public async requireEnvironment(name: string): Promise<EnvironmentRecord> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: environmentsPk, sk: environmentSk(name) },
        ConsistentRead: true,
      }),
    );
    if (response.Item === undefined) {
      throw notFound("The requested environment is not configured.");
    }
    return response.Item as EnvironmentRecord;
  }

  public async createEnvironment(
    environment: EnvironmentRecord,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: environment,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Update: {
                TableName: this.config.controlTableName,
                Key: { pk: environmentsPk, sk: "STATE" },
                UpdateExpression:
                  "SET environmentCount = if_not_exists(environmentCount, :zero) + :one",
                ConditionExpression:
                  "attribute_not_exists(environmentCount) OR environmentCount < :maximum",
                ExpressionAttributeValues: {
                  ":zero": 0,
                  ":one": 1,
                  ":maximum": maximumEnvironments,
                },
              },
            },
          ],
        }),
      );
    } catch {
      throw conflict("The environment already exists or the registry is full.");
    }
  }

  public async requireHead(
    environment: string,
    secretId: string,
  ): Promise<HeadRecord> {
    const head = await this.getHead(environment, secretId);
    if (head === undefined) {
      throw notFound("The requested secret was not found.");
    }
    return head;
  }

  public async requireHeadBySecretUid(secretUid: string): Promise<HeadRecord> {
    const head = await this.getHeadBySecretUid(secretUid);
    if (head === undefined) {
      throw notFound("The requested secret was not found.");
    }
    return head;
  }

  public async getIdentity(
    fingerprint: string,
  ): Promise<IdentityRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `IDENTITY#${fingerprint}`, sk: "PROFILE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as IdentityRecord | undefined;
  }

  public async getConsumer(
    consumerId: string,
  ): Promise<ConsumerRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `CONSUMER#${consumerId}`, sk: "PROFILE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as ConsumerRecord | undefined;
  }

  public async getPendingEnrollmentForConsumer(
    consumerId: string,
  ): Promise<EnrollmentRecord | undefined> {
    const consumer = await this.getConsumer(consumerId);
    if (
      consumer?.status !== "PENDING" ||
      consumer.pendingEnrollmentOperationId === undefined
    ) {
      return undefined;
    }
    return this.getEnrollment(consumer.pendingEnrollmentOperationId);
  }

  public async associateEnrollmentIdempotency(
    operation: EnrollmentRecord,
    actor: Actor,
    idempotencyKey: string,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new PutCommand({
          TableName: this.config.controlTableName,
          Item: {
            pk: idempotencyPk(actor),
            sk: `REQUEST#${idempotencyKey}`,
            requestDigest: operation.requestDigest,
            operationId: operation.operationId,
            operationType: operation.operationType,
            consumerId: operation.consumerId,
            environment: operation.environment,
            rootFingerprint: operation.rootFingerprint,
            apiFingerprint: operation.apiFingerprint,
            status: "PREPARED",
          },
          ConditionExpression: "attribute_not_exists(pk)",
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not associate enrollment idempotency: ${errorMessage(error)}`,
      );
    }
  }

  public async getAgentGrant(
    grantId: string,
  ): Promise<AgentGrantRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: agentGrantPk(grantId), sk: "PROFILE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as AgentGrantRecord | undefined;
  }

  public async getAgentGrantForConsumer(
    consumerId: string,
  ): Promise<AgentGrantRecord | undefined> {
    const mapping = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `CONSUMER#${consumerId}`, sk: "AGENT_GRANT" },
        ConsistentRead: true,
      }),
    );
    const grantId = mapping.Item?.grantId;
    return typeof grantId === "string"
      ? this.getAgentGrant(grantId)
      : undefined;
  }

  public async createAgentGrant(grant: AgentGrantRecord): Promise<void> {
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: grant,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: {
                  pk: `CONSUMER#${grant.consumerId}`,
                  sk: "AGENT_GRANT",
                  grantId: grant.grantId,
                },
                ConditionExpression: "attribute_not_exists(sk)",
              },
            },
          ],
        }),
      );
    } catch (error) {
      throw conflict(`Could not create agent grant: ${errorMessage(error)}`);
    }
  }

  /** Updates policy fields without racing an enrollment status transition. */
  public async updateAgentGrant(
    grant: AgentGrantRecord,
    removeDisplayName: boolean,
  ): Promise<void> {
    const updateExpression = removeDisplayName
      ? "SET capabilities = :capabilities, readSecretIds = :readSecretIds, readSecretUids = :readSecretUids, writeSecretIds = :writeSecretIds, writeSecretUids = :writeSecretUids REMOVE displayName, readSecretIdPrefixes, writeSecretIdPrefixes, readPathPrefixes, writePathPrefixes"
      : "SET capabilities = :capabilities, readSecretIds = :readSecretIds, readSecretUids = :readSecretUids, writeSecretIds = :writeSecretIds, writeSecretUids = :writeSecretUids, displayName = :displayName REMOVE readSecretIdPrefixes, writeSecretIdPrefixes, readPathPrefixes, writePathPrefixes";
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: agentGrantPk(grant.grantId), sk: "PROFILE" },
          UpdateExpression: updateExpression,
          ConditionExpression: "attribute_exists(pk)",
          ExpressionAttributeValues: {
            ":capabilities": grant.capabilities,
            ":readSecretIds": grant.readSecretIds,
            ":readSecretUids": grant.readSecretUids,
            ":writeSecretIds": grant.writeSecretIds,
            ":writeSecretUids": grant.writeSecretUids,
            ...(removeDisplayName ? {} : { ":displayName": grant.displayName }),
          },
        }),
      );
    } catch (error) {
      throw conflict(`Could not update agent grant: ${errorMessage(error)}`);
    }
  }

  public async createBootstrapCapability(
    capability: BootstrapCapabilityRecord,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new PutCommand({
          TableName: this.config.controlTableName,
          Item: capability,
          ConditionExpression: "attribute_not_exists(pk)",
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not create bootstrap capability: ${errorMessage(error)}`,
      );
    }
  }

  public async getBootstrapCapability(
    tokenHash: string,
  ): Promise<BootstrapCapabilityRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: bootstrapPk(tokenHash), sk: "STATE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as BootstrapCapabilityRecord | undefined;
  }

  public async activateAgentGrant(
    grantId: string,
    fingerprint: string,
  ): Promise<void> {
    const grant = await this.getAgentGrant(grantId);
    if (
      grant?.status === "ACTIVE" &&
      grant.activatedFingerprint === fingerprint
    ) {
      return;
    }
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: agentGrantPk(grantId), sk: "PROFILE" },
          UpdateExpression:
            "SET #status = :active, activatedAt = :activatedAt, activatedFingerprint = :fingerprint",
          ConditionExpression: "#status = :pending",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":active": "ACTIVE",
            ":pending": "PENDING",
            ":activatedAt": isoNow(),
            ":fingerprint": fingerprint,
          },
        }),
      );
    } catch (error) {
      throw conflict(`Could not activate agent grant: ${errorMessage(error)}`);
    }
  }

  public async consumeBootstrapCapability(
    tokenHash: string,
    fingerprint: string,
  ): Promise<void> {
    const record = await this.getBootstrapCapability(tokenHash);
    if (
      record?.status === "CONSUMED" &&
      record.consumedFingerprint === fingerprint
    ) {
      return;
    }
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: bootstrapPk(tokenHash), sk: "STATE" },
          UpdateExpression:
            "SET #status = :consumed, consumedAt = :consumedAt, consumedFingerprint = :fingerprint",
          ConditionExpression: "#status = :pending",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":consumed": "CONSUMED",
            ":pending": "PENDING",
            ":consumedAt": isoNow(),
            ":fingerprint": fingerprint,
          },
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not consume bootstrap capability: ${errorMessage(error)}`,
      );
    }
  }

  /** Marks an at-least-once MQTT hint terminal only after the broker accepts it. */
  public async markNotificationDelivered(eventId: string): Promise<boolean> {
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: notificationPk(eventId), sk: "EVENT" },
          UpdateExpression:
            "SET #status = :delivered, deliveredAt = :deliveredAt, #ttl = :ttl",
          ConditionExpression: "#status = :pending",
          ExpressionAttributeNames: { "#status": "status", "#ttl": "ttl" },
          ExpressionAttributeValues: {
            ":pending": "PENDING",
            ":delivered": "DELIVERED",
            ":deliveredAt": isoNow(),
            // Event-source retries can arrive after a successful update. Keep
            // only terminal records for a bounded troubleshooting window.
            ":ttl": Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
          },
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  public async getTruststoreRoot(
    fingerprint: string,
  ): Promise<TruststoreRootRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: "TRUSTSTORE#ROOTS", sk: `ROOT#${fingerprint}` },
        ConsistentRead: true,
      }),
    );
    return response.Item as TruststoreRootRecord | undefined;
  }

  public async getIssuer(): Promise<IssuerRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: "SYSTEM#ISSUER", sk: "PROFILE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as IssuerRecord | undefined;
  }

  /**
   * Persists the one deployment-wide issuer and its public truststore anchor.
   * A concurrent creator returns the already-created issuer instead of creating
   * a second root.
   */
  public async createIssuer(
    issuer: IssuerRecord,
    environment: string,
  ): Promise<IssuerRecord> {
    const root: TruststoreRootRecord = {
      pk: "TRUSTSTORE#ROOTS",
      sk: `ROOT#${issuer.fingerprint}`,
      fingerprint: issuer.fingerprint,
      consumerId: "hemlig",
      environment,
      certificatePem: issuer.rootCertificatePem,
      notBefore: issuer.notBefore,
      notAfter: issuer.notAfter,
      status: "ACTIVE",
      operationId: "issuer",
      createdAt: issuer.createdAt,
    };
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: issuer,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: root,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
          ],
        }),
      );
      return issuer;
    } catch {
      const existing = await this.getIssuer();
      if (existing === undefined) {
        throw conflict("Could not create the Hemlig issuing root.");
      }
      await this.ensureIssuerTruststoreRoot(existing, environment);
      return existing;
    }
  }

  /** Repairs an incomplete legacy/bootstrap write without replacing a root. */
  public async ensureIssuerTruststoreRoot(
    issuer: IssuerRecord,
    environment: string,
  ): Promise<void> {
    const root: TruststoreRootRecord = {
      pk: "TRUSTSTORE#ROOTS",
      sk: `ROOT#${issuer.fingerprint}`,
      fingerprint: issuer.fingerprint,
      consumerId: "hemlig",
      environment,
      certificatePem: issuer.rootCertificatePem,
      notBefore: issuer.notBefore,
      notAfter: issuer.notAfter,
      status: "ACTIVE",
      operationId: "issuer",
      createdAt: issuer.createdAt,
    };
    try {
      await this.dynamo.send(
        new PutCommand({
          TableName: this.config.controlTableName,
          Item: root,
          ConditionExpression: "attribute_not_exists(pk)",
        }),
      );
    } catch {
      const existing = await this.getTruststoreRoot(issuer.fingerprint);
      if (
        existing === undefined ||
        existing.certificatePem !== issuer.rootCertificatePem ||
        existing.status !== "ACTIVE"
      ) {
        throw conflict("The Hemlig issuing-root truststore record is invalid.");
      }
    }
  }

  public async listTruststoreRoots(
    operationId: string,
  ): Promise<TruststoreRootRecord[]> {
    const roots = new Map<string, TruststoreRootRecord>();
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.config.controlTableName,
          KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
          FilterExpression: "#status = :active OR operationId = :operationId",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":pk": "TRUSTSTORE#ROOTS",
            ":prefix": "ROOT#",
            ":active": "ACTIVE",
            ":operationId": operationId,
          },
          ExclusiveStartKey: exclusiveStartKey as never,
          ConsistentRead: true,
        }),
      );
      for (const root of response.Items ?? []) {
        const record = root as TruststoreRootRecord;
        roots.set(record.fingerprint, record);
      }
      exclusiveStartKey = response.LastEvaluatedKey as
        Record<string, unknown> | undefined;
    } while (exclusiveStartKey !== undefined);
    return [...roots.values()].sort((left, right) =>
      left.fingerprint.localeCompare(right.fingerprint),
    );
  }

  public async getEnrollment(
    operationId: string,
  ): Promise<EnrollmentRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `ENROLLMENT#${operationId}`, sk: "STATE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as EnrollmentRecord | undefined;
  }

  public async getTruststoreState(): Promise<
    TruststoreStateRecord | undefined
  > {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: "SYSTEM#TRUSTSTORE", sk: "STATE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as TruststoreStateRecord | undefined;
  }

  public async getAccess(
    consumerId: string,
    environment: string,
    secretId: string,
  ): Promise<AccessRecord | undefined> {
    const secretUid = await this.getSecretUid(environment, secretId);
    if (secretUid === undefined) {
      return undefined;
    }
    return this.getAccessBySecretUid(consumerId, environment, secretUid);
  }

  public async getAccessBySecretUid(
    consumerId: string,
    environment: string,
    secretUid: string,
  ): Promise<AccessRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: {
          pk: `CONSUMER#${consumerId}`,
          sk: accessSk(environment, secretUid),
        },
        ConsistentRead: true,
      }),
    );
    return response.Item as AccessRecord | undefined;
  }

  public async getAccessAndHead(
    consumerId: string,
    environment: string,
    secretId: string,
  ): Promise<AccessAndHead> {
    const secretUid = await this.getSecretUid(environment, secretId);
    if (secretUid === undefined) {
      return {};
    }
    const response = await this.dynamo.send(
      new TransactGetCommand({
        TransactItems: [
          {
            Get: {
              TableName: this.config.controlTableName,
              Key: {
                pk: `CONSUMER#${consumerId}`,
                sk: accessSk(environment, secretUid),
              },
            },
          },
          {
            Get: {
              TableName: this.config.controlTableName,
              Key: { pk: secretPk(secretUid), sk: "HEAD" },
            },
          },
        ],
      }),
    );
    return {
      access: response.Responses?.[0]?.Item as AccessRecord | undefined,
      head: response.Responses?.[1]?.Item as HeadRecord | undefined,
    };
  }

  public async listAccess(
    consumerId: string,
    environment: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<ChangePage> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": `CONSUMER#${consumerId}`,
          ":prefix": accessSkPrefix(environment),
        },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
        ConsistentRead: true,
      }),
    );
    const stored = (response.Items ?? []) as AccessRecord[];
    const changes = await Promise.all(
      stored.map(async (access) => this.currentAccessSnapshot(access)),
    );
    const currentChanges = await this.collapseReusedSecretIds(
      environment,
      changes,
    );
    return {
      changes: currentChanges,
      nextCursor:
        response.LastEvaluatedKey === undefined
          ? undefined
          : JSON.stringify(response.LastEvaluatedKey),
    };
  }

  /**
   * Lists the live ACL entries for one consumer. This is intentionally
   * distinct from listAccess(), which is a delivery change feed and includes
   * durable revocation tombstones needed by consumers to converge.
   */
  public async listConsumerSecretGrants(
    consumerId: string,
    environment: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<ConsumerSecretGrantPage> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": `CONSUMER#${consumerId}`,
          ":prefix": accessSkPrefix(environment),
        },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
        ConsistentRead: true,
      }),
    );
    const accessRecords = (response.Items ?? []) as AccessRecord[];
    const candidates = await Promise.all(
      accessRecords.map(async (access) => {
        if (
          !access.permissions.includes("read") ||
          access.state === "REVOKED"
        ) {
          return undefined;
        }
        const head = await this.getHeadBySecretUid(access.secretUid);
        if (
          head === undefined ||
          head.environment !== environment ||
          head.secretId !== access.secretId ||
          head.state === "ARCHIVED"
        ) {
          return undefined;
        }
        return {
          secretUid: head.secretUid,
          secretId: head.secretId,
          permissions: access.permissions,
          controlVersionId: head.controlVersionId,
          state: head.state,
        };
      }),
    );
    return {
      grants: candidates.filter(
        (grant): grant is NonNullable<typeof grant> => grant !== undefined,
      ),
      ...(response.LastEvaluatedKey === undefined
        ? {}
        : { nextCursor: JSON.stringify(response.LastEvaluatedKey) }),
    };
  }

  /**
   * Access records are grants, not a replicated secret HEAD. Hydrating each
   * grant for the current snapshot lets payload writes advance one HEAD and
   * one grouped outbox event instead of rewriting every authorized consumer.
   */
  private async currentAccessSnapshot(
    access: AccessRecord,
  ): Promise<AccessRecord> {
    if (!access.permissions.includes("read") || access.state === "REVOKED") {
      return access;
    }
    const head = await this.getHeadBySecretUid(access.secretUid);
    if (
      head === undefined ||
      head.environment !== access.environment ||
      head.state !== "ACTIVE"
    ) {
      return {
        ...access,
        permissions: [],
        payloadVersionId: undefined,
        state: "REVOKED",
        changeKind: "secret.revoked",
      };
    }
    return {
      ...access,
      controlVersionId: head.controlVersionId,
      payloadVersionId: head.payloadVersionId,
      state: head.state,
      changeKind: "secret.changed",
    };
  }

  /**
   * An archive leaves a revocation row at the retired UID, while a subsequent
   * create with the same public ID writes a row for a new UID. A consumer
   * materializes by public ID, so its snapshot must choose the live name
   * target rather than let an old revocation remove the replacement secret.
   */
  private async collapseReusedSecretIds(
    environment: string,
    changes: readonly AccessRecord[],
  ): Promise<readonly AccessRecord[]> {
    const bySecretId = new Map<string, AccessRecord[]>();
    for (const change of changes) {
      const group = bySecretId.get(change.secretId);
      if (group === undefined) {
        bySecretId.set(change.secretId, [change]);
      } else {
        group.push(change);
      }
    }
    const current: AccessRecord[] = [];
    for (const [secretId, group] of bySecretId) {
      const first = group[0];
      if (first === undefined) {
        continue;
      }
      if (group.length === 1) {
        current.push(first);
        continue;
      }
      const liveSecretUid = await this.getSecretUid(environment, secretId);
      const liveChange = group.find(
        (change) => change.secretUid === liveSecretUid,
      );
      if (liveChange !== undefined) {
        current.push(liveChange);
        continue;
      }
      const revocation = group.find(
        (change) =>
          change.state === "REVOKED" || !change.permissions.includes("read"),
      );
      current.push(
        revocation ?? {
          ...first,
          permissions: [],
          payloadVersionId: undefined,
          state: "REVOKED",
          changeKind: "secret.revoked",
        },
      );
    }
    return current;
  }

  public async listSecrets(
    environment: string,
    pathPrefix: string | undefined,
    tags: Readonly<Record<string, string>>,
    exclusiveStartKey?: Record<string, string>,
    archived = false,
  ): Promise<CatalogPage> {
    const filter = catalogFilter(environment, pathPrefix, tags, archived);
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.catalogPathIndex,
        KeyConditionExpression:
          "catalogPk = :catalogPk AND begins_with(catalogSk, :pathPrefix)",
        FilterExpression: filter.filterExpression,
        ExpressionAttributeNames: filter.expressionAttributeNames,
        ExpressionAttributeValues: filter.expressionAttributeValues,
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
      }),
    );
    return {
      secrets: (response.Items ?? []) as HeadRecord[],
      nextCursor:
        response.LastEvaluatedKey === undefined
          ? undefined
          : JSON.stringify(response.LastEvaluatedKey),
    };
  }

  /**
   * The plain catalog page above applies its filters
   * (workflowState, tags) after a bounded 100-record read, so a page can come
   * back empty while nextCursor is still set -- a caller has to keep chasing
   * cursors to learn whether there truly are no results. That is tolerable
   * for browsing but wrong for search, where "no matches" must be trustworthy
   * on the first response. So this scans up to the same bounded cap as
   * listSecretTree in one request and returns one complete-or-truncated
   * answer instead of a cursor. The `q` match is case-insensitive substring
   * on secretId and metadata.description, applied in memory because DynamoDB
   * FilterExpression's contains() is case-sensitive.
   */
  public async searchSecrets(
    environment: string,
    pathPrefix: string | undefined,
    tags: Readonly<Record<string, string>>,
    query: string,
    archived = false,
  ): Promise<{
    readonly secrets: readonly HeadRecord[];
    readonly truncated: boolean;
  }> {
    const filter = catalogFilter(environment, pathPrefix, tags, archived);
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.catalogPathIndex,
        KeyConditionExpression:
          "catalogPk = :catalogPk AND begins_with(catalogSk, :pathPrefix)",
        FilterExpression: filter.filterExpression,
        ExpressionAttributeNames: filter.expressionAttributeNames,
        ExpressionAttributeValues: filter.expressionAttributeValues,
        Limit: maximumBoundedScan + 1,
      }),
    );
    const items = (response.Items ?? []) as HeadRecord[];
    const truncated =
      items.length > maximumBoundedScan ||
      response.LastEvaluatedKey !== undefined;
    const needle = query.toLowerCase();
    const secrets = items
      .slice(0, maximumBoundedScan)
      .filter(
        (secret) =>
          secret.secretId.toLowerCase().includes(needle) ||
          (secret.metadata?.description ?? "").toLowerCase().includes(needle),
      );
    return { secrets, truncated };
  }

  /**
   * This method paginates the catalog-path GSI internally, within one
   * request, and groups the result into
   * immediate child folders (counted recursively) and exact-path secrets.
   * It is bounded at maximumBoundedScan and reports `truncated` instead of
   * returning a cursor: a partial tree with a cursor is worse than a
   * bounded, complete-or-truncated one.
   *
   * `folders` is the union of segments implied by slash-separated secret IDs.
   */
  public async listSecretTree(
    environment: string,
    pathPrefix: string | undefined,
    archived = false,
  ): Promise<SecretTreePage> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.catalogPathIndex,
        KeyConditionExpression:
          "catalogPk = :catalogPk AND begins_with(catalogSk, :prefix)",
        FilterExpression: "#workflowState = :ready",
        ExpressionAttributeNames: { "#workflowState": "workflowState" },
        ExpressionAttributeValues: {
          ":catalogPk": catalogPkFor(environment, archived),
          ":prefix": catalogPathPrefix(pathPrefix),
          ":ready": "READY",
        },
        Limit: maximumBoundedScan + 1,
      }),
    );
    const items = (response.Items ?? []) as HeadRecord[];
    const truncated =
      items.length > maximumBoundedScan ||
      response.LastEvaluatedKey !== undefined;
    const bounded = items.slice(0, maximumBoundedScan);

    const secrets: HeadRecord[] = [];
    const folderEntries = new Map<string, { secretCount: number }>();
    for (const item of bounded) {
      const path = secretFolderPath(item.secretId);
      // `path === pathPrefix` also covers the root case (both undefined).
      if (path === pathPrefix) {
        secrets.push(item);
        continue;
      }
      if (path === undefined) {
        // The GSI query normally excludes root secrets below a folder. Keep
        // this guard for resilience against a stale or manually repaired
        // catalog entry while the ID-derived index backfill converges.
        continue;
      }
      const segment = childSegment(path, pathPrefix);
      if (segment === undefined) {
        continue;
      }
      const entry = folderEntries.get(segment) ?? { secretCount: 0 };
      entry.secretCount += 1;
      folderEntries.set(segment, entry);
    }

    const folders = [...folderEntries.entries()]
      .map(([segment, { secretCount }]): SecretTreeFolder => {
        const path =
          pathPrefix === undefined ? segment : `${pathPrefix}/${segment}`;
        return {
          segment,
          path,
          secretCount,
          kind: "derived",
        };
      })
      .sort((left, right) => left.segment.localeCompare(right.segment));
    secrets.sort((left, right) => left.secretId.localeCompare(right.secretId));

    return { folders, secrets, truncated };
  }

  public async listConsumers(
    environment: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<{
    readonly consumers: readonly ConsumerRecord[];
    readonly nextCursor?: string;
  }> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.consumerDirectoryIndex,
        KeyConditionExpression: "consumerDirectoryPk = :directory",
        ExpressionAttributeValues: {
          ":directory": consumerDirectoryPk(environment),
        },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
      }),
    );
    return {
      consumers: (response.Items ?? []) as ConsumerRecord[],
      nextCursor:
        response.LastEvaluatedKey === undefined
          ? undefined
          : JSON.stringify(response.LastEvaluatedKey),
    };
  }

  public async listConsumerApiIdentities(
    consumerId: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<{
    readonly identities: readonly IdentityRecord[];
    readonly nextCursor?: string;
  }> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.consumerIdentityIndex,
        KeyConditionExpression: "identityConsumerPk = :consumer",
        FilterExpression: "kind = :api",
        ExpressionAttributeValues: {
          ":consumer": identityConsumerPk(consumerId),
          ":api": "api",
        },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
        ScanIndexForward: false,
      }),
    );
    return {
      identities: (response.Items ?? []) as IdentityRecord[],
      nextCursor:
        response.LastEvaluatedKey === undefined
          ? undefined
          : JSON.stringify(response.LastEvaluatedKey),
    };
  }

  public async countActiveConsumerApiIdentities(
    consumerId: string,
  ): Promise<number> {
    let count = 0;
    let exclusiveStartKey: Record<string, unknown> | undefined;
    const now = isoNow();
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.config.controlTableName,
          IndexName: this.config.consumerIdentityIndex,
          KeyConditionExpression: "identityConsumerPk = :consumer",
          FilterExpression:
            "#status = :active AND kind = :api AND notAfter > :now",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":consumer": identityConsumerPk(consumerId),
            ":active": "ACTIVE",
            ":api": "api",
            ":now": now,
          },
          Select: "COUNT",
          ExclusiveStartKey: exclusiveStartKey as never,
        }),
      );
      count += response.Count ?? 0;
      exclusiveStartKey = response.LastEvaluatedKey as
        Record<string, unknown> | undefined;
    } while (exclusiveStartKey !== undefined);
    return count;
  }

  /**
   * The revision GSI is chronologically ordered, letting this fixed-size
   * response contain the newest revisions rather than an arbitrary UUID slice.
   */
  public async listRecentControlRevisions(
    environment: string,
    secretId: string,
  ): Promise<RevisionHistoryPage> {
    const head = await this.requireHead(environment, secretId);
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.secretRevisionIndex,
        KeyConditionExpression: "revisionPk = :secret",
        ExpressionAttributeValues: {
          ":secret": secretPk(head.secretUid),
        },
        Limit: maximumRevisionHistory + 1,
        ScanIndexForward: false,
      }),
    );
    const revisions = (response.Items ?? [])
      .slice(0, maximumRevisionHistory)
      .filter(
        (item): item is StoredControlRevision =>
          typeof item === "object" &&
          item !== null &&
          "serialized" in item &&
          typeof (item as { serialized?: unknown }).serialized === "object",
      ) as StoredControlRevision[];
    return {
      revisions,
      truncated:
        (response.Items?.length ?? 0) > maximumRevisionHistory ||
        response.LastEvaluatedKey !== undefined,
    };
  }

  public async getIdempotency(
    actor: Actor,
    idempotencyKey: string,
  ): Promise<Record<string, unknown> | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: idempotencyPk(actor), sk: `REQUEST#${idempotencyKey}` },
        ConsistentRead: true,
      }),
    );
    return response.Item;
  }

  public async startEnrollment(enrollment: PreparedEnrollment): Promise<void> {
    const idempotencyItem = {
      pk: idempotencyPk(enrollment.actor),
      sk: `REQUEST#${enrollment.idempotencyKey}`,
      requestDigest: enrollment.requestDigest,
      operationId: enrollment.operationId,
      operationType: enrollment.operationType,
      consumerId: enrollment.consumerId,
      environment: enrollment.environment,
      rootFingerprint: enrollment.rootFingerprint,
      apiFingerprint: enrollment.apiIdentity.fingerprint,
      status: "PREPARED",
    };
    const identityItem: IdentityRecord = {
      pk: `IDENTITY#${enrollment.apiIdentity.fingerprint}`,
      sk: "PROFILE",
      ...enrollment.apiIdentity,
      status: "PENDING",
      identityConsumerPk: identityConsumerPk(enrollment.consumerId),
      identityConsumerSk: identityConsumerSk(
        enrollment.apiIdentity.notAfter,
        enrollment.apiIdentity.fingerprint,
      ),
    };
    const operationItem = {
      pk: `ENROLLMENT#${enrollment.operationId}`,
      sk: "STATE",
      operationId: enrollment.operationId,
      operationType: enrollment.operationType,
      consumerId: enrollment.consumerId,
      environment: enrollment.environment,
      rootFingerprint: enrollment.rootFingerprint,
      apiFingerprint: enrollment.apiIdentity.fingerprint,
      apiCertificatePem: enrollment.apiIdentity.certificatePem,
      createdAt: enrollment.createdAt,
      workflowState: "PREPARED",
      requestDigest: enrollment.requestDigest,
      actor: enrollment.actor,
      idempotencyKey: enrollment.idempotencyKey,
      workflowDuePk: "WORKFLOW#DUE",
      workflowDueSk: enrollment.expiresAt,
      workflowKind: "consumer.enrollment",
    } satisfies EnrollmentRecord & Record<string, unknown>;
    const transaction: Record<string, unknown>[] = [
      {
        Put: {
          TableName: this.config.controlTableName,
          Item: idempotencyItem,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
      {
        Put: {
          TableName: this.config.controlTableName,
          Item: identityItem,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
      {
        Put: {
          TableName: this.config.controlTableName,
          Item: operationItem,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
    ];
    transaction.push({
      Put: {
        TableName: this.config.controlTableName,
        Item: {
          pk: `CONSUMER#${enrollment.consumerId}`,
          sk: "PROFILE",
          consumerId: enrollment.consumerId,
          environment: enrollment.environment,
          subjectUri: enrollment.subjectUri,
          status: "PENDING",
          createdAt: enrollment.createdAt,
          createdBy: enrollment.actor,
          pendingEnrollmentOperationId: enrollment.operationId,
          consumerDirectoryPk: consumerDirectoryPk(enrollment.environment),
          consumerDirectorySk: enrollment.consumerId,
        } satisfies ConsumerRecord,
        ConditionExpression: "attribute_not_exists(pk)",
      },
    });
    try {
      await this.dynamo.send(
        new TransactWriteCommand({ TransactItems: transaction as never }),
      );
    } catch (error) {
      throw conflict(
        `Could not prepare consumer enrollment: ${errorMessage(error)}`,
      );
    }
  }

  public async acquireTruststoreLease(
    operationId: string,
    expiresAt: string,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: "SYSTEM#TRUSTSTORE", sk: "STATE" },
          UpdateExpression:
            "SET leaseOwner = :owner, leaseExpiresAt = :expires",
          ConditionExpression:
            "attribute_not_exists(leaseExpiresAt) OR leaseExpiresAt < :now OR leaseOwner = :owner",
          ExpressionAttributeValues: {
            ":owner": operationId,
            ":expires": expiresAt,
            ":now": isoNow(),
          },
        }),
      );
    } catch (error) {
      throw serviceUnavailable(
        `Another truststore publication is in progress: ${errorMessage(error)}`,
      );
    }
  }

  public async recordTruststoreBundle(
    operationId: string,
    object: ObjectReference,
    rootFingerprints: readonly string[],
  ): Promise<void> {
    await this.dynamo.send(
      new UpdateCommand({
        TableName: this.config.controlTableName,
        Key: { pk: "SYSTEM#TRUSTSTORE", sk: "STATE" },
        UpdateExpression:
          "SET pendingOperationId = :owner, pendingTruststoreKey = :key, pendingTruststoreVersionId = :version, pendingTruststoreChecksumSha256 = :checksum, pendingRootFingerprints = :roots",
        ConditionExpression: "leaseOwner = :owner",
        ExpressionAttributeValues: {
          ":owner": operationId,
          ":key": object.key,
          ":version": object.versionId,
          ":checksum": object.checksumSha256,
          ":roots": rootFingerprints,
        },
      }),
    );
  }

  public async completeEnrollment(
    operation: EnrollmentRecord,
    truststore: ObjectReference,
    rootFingerprints: readonly string[],
  ): Promise<ConsumerProvisioningResult> {
    const transaction: Record<string, unknown>[] = [
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `IDENTITY#${operation.apiFingerprint}`, sk: "PROFILE" },
          UpdateExpression: "SET #status = :active",
          ConditionExpression:
            "#status = :pending AND consumerId = :consumerId",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":active": "ACTIVE",
            ":pending": "PENDING",
            ":consumerId": operation.consumerId,
          },
        },
      },
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `ENROLLMENT#${operation.operationId}`, sk: "STATE" },
          UpdateExpression:
            "SET workflowState = :ready REMOVE workflowDuePk, workflowDueSk",
          ConditionExpression: "workflowState = :prepared",
          ExpressionAttributeValues: {
            ":ready": "READY",
            ":prepared": "PREPARED",
          },
        },
      },
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: "SYSTEM#TRUSTSTORE", sk: "STATE" },
          UpdateExpression:
            "SET currentTruststoreKey = :key, currentTruststoreVersionId = :version, currentTruststoreChecksumSha256 = :checksum, currentRootFingerprints = :roots REMOVE leaseOwner, leaseExpiresAt, pendingOperationId, pendingTruststoreKey, pendingTruststoreVersionId, pendingTruststoreChecksumSha256, pendingRootFingerprints",
          ConditionExpression: "leaseOwner = :owner",
          ExpressionAttributeValues: {
            ":key": truststore.key,
            ":version": truststore.versionId,
            ":checksum": truststore.checksumSha256,
            ":roots": rootFingerprints,
            ":owner": operation.operationId,
          },
        },
      },
    ];
    if (operation.operationType === "consumer.enroll") {
      transaction.push({
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `CONSUMER#${operation.consumerId}`, sk: "PROFILE" },
          UpdateExpression:
            "SET #status = :active REMOVE pendingEnrollmentOperationId",
          ConditionExpression:
            "#status = :pending AND #environment = :environment",
          ExpressionAttributeNames: {
            "#status": "status",
            "#environment": "environment",
          },
          ExpressionAttributeValues: {
            ":active": "ACTIVE",
            ":pending": "PENDING",
            ":environment": operation.environment,
          },
        },
      });
    }
    await this.dynamo.send(
      new TransactWriteCommand({ TransactItems: transaction as never }),
    );
    return {
      consumerId: operation.consumerId,
      environment: operation.environment,
      rootFingerprint: operation.rootFingerprint,
      apiFingerprint: operation.apiFingerprint,
      apiCertificatePem: operation.apiCertificatePem,
      status: "ACTIVE",
    };
  }

  public async failEnrollment(operation: EnrollmentRecord): Promise<void> {
    const transaction: Record<string, unknown>[] = [
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `IDENTITY#${operation.apiFingerprint}`, sk: "PROFILE" },
          UpdateExpression: "SET #status = :failed",
          ConditionExpression:
            "#status = :pending AND consumerId = :consumerId",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":failed": "FAILED",
            ":pending": "PENDING",
            ":consumerId": operation.consumerId,
          },
        },
      },
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `ENROLLMENT#${operation.operationId}`, sk: "STATE" },
          UpdateExpression:
            "SET workflowState = :failed REMOVE workflowDuePk, workflowDueSk",
          ConditionExpression: "workflowState = :prepared",
          ExpressionAttributeValues: {
            ":failed": "FAILED",
            ":prepared": "PREPARED",
          },
        },
      },
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: "SYSTEM#TRUSTSTORE", sk: "STATE" },
          UpdateExpression:
            "REMOVE leaseOwner, leaseExpiresAt, pendingOperationId, pendingTruststoreKey, pendingTruststoreVersionId, pendingTruststoreChecksumSha256, pendingRootFingerprints",
          ConditionExpression: "leaseOwner = :owner",
          ExpressionAttributeValues: { ":owner": operation.operationId },
        },
      },
    ];
    if (operation.operationType === "consumer.enroll") {
      transaction.push({
        Delete: {
          TableName: this.config.controlTableName,
          Key: { pk: `CONSUMER#${operation.consumerId}`, sk: "PROFILE" },
          ConditionExpression: "#status = :pending",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: { ":pending": "PENDING" },
        },
      });
    }
    await this.dynamo.send(
      new TransactWriteCommand({ TransactItems: transaction as never }),
    );
  }

  public async createApiIdentity(
    actor: Actor,
    idempotencyKey: string,
    requestDigest: string,
    identity: Omit<IdentityRecord, "pk" | "sk" | "status">,
    rootFingerprint: string,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: {
                  pk: idempotencyPk(actor),
                  sk: `REQUEST#${idempotencyKey}`,
                  requestDigest,
                  operationType: "consumer.api.rotate",
                  consumerId: identity.consumerId,
                  environment: identity.environment,
                  rootFingerprint,
                  apiFingerprint: identity.fingerprint,
                  status: "READY",
                },
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: {
                  pk: `IDENTITY#${identity.fingerprint}`,
                  sk: "PROFILE",
                  ...identity,
                  status: "ACTIVE",
                  identityConsumerPk: identityConsumerPk(identity.consumerId),
                  identityConsumerSk: identityConsumerSk(
                    identity.notAfter,
                    identity.fingerprint,
                  ),
                } satisfies IdentityRecord,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
          ],
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not create consumer API identity: ${errorMessage(error)}`,
      );
    }
  }

  public async revokeApiIdentity(
    actor: Actor,
    idempotencyKey: string,
    requestDigest: string,
    consumerId: string,
    fingerprint: string,
  ): Promise<void> {
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.config.controlTableName,
                Item: {
                  pk: idempotencyPk(actor),
                  sk: `REQUEST#${idempotencyKey}`,
                  requestDigest,
                  operationType: "consumer.api.revoke",
                  consumerId,
                  apiFingerprint: fingerprint,
                  status: "READY",
                },
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Update: {
                TableName: this.config.controlTableName,
                Key: { pk: `IDENTITY#${fingerprint}`, sk: "PROFILE" },
                UpdateExpression: "SET #status = :revoked",
                ConditionExpression:
                  "consumerId = :consumerId AND kind = :kind AND #status = :active",
                ExpressionAttributeNames: { "#status": "status" },
                ExpressionAttributeValues: {
                  ":revoked": "REVOKED",
                  ":consumerId": consumerId,
                  ":kind": "api",
                  ":active": "ACTIVE",
                },
              },
            },
          ],
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not revoke consumer API identity: ${errorMessage(error)}`,
      );
    }
  }

  public async prepareMutation(mutation: PreparedMutation): Promise<void> {
    const headKey = {
      pk: secretPk(mutation.secretUid),
      sk: "HEAD",
    };
    const controlItem = workflowItem(
      mutation.environment,
      mutation.secretId,
      mutation.secretUid,
      `CONTROL#${mutation.control.controlVersionId}`,
      mutation.operationId,
      mutation.controlKey,
      mutation.controlChecksumSha256,
      mutation.expiresAt,
      mutation.control,
      {
        createdAt: mutation.control.createdAt,
        controlVersionId: mutation.control.controlVersionId,
      },
    );
    const idempotencyItem = {
      pk: idempotencyPk(mutation.actor),
      sk: `REQUEST#${mutation.idempotencyKey}`,
      requestDigest: mutation.requestDigest,
      operationId: mutation.operationId,
      status: "PREPARED",
      expiresAt: mutation.expiresAt,
    };
    const transaction: Record<string, unknown>[] = [
      {
        Put: {
          TableName: this.config.controlTableName,
          Item: idempotencyItem,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
      {
        Put: {
          TableName: this.config.controlTableName,
          Item: controlItem,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      },
    ];
    if (mutation.payload !== undefined) {
      transaction.push({
        Put: {
          TableName: this.config.controlTableName,
          Item: workflowItem(
            mutation.environment,
            mutation.secretId,
            mutation.secretUid,
            `PAYLOAD#${mutation.payload.revision.payloadVersionId}`,
            mutation.operationId,
            mutation.payload.key,
            mutation.payload.checksumSha256,
            mutation.expiresAt,
            mutation.payload.revision,
          ),
          ConditionExpression: "attribute_not_exists(pk)",
        },
      });
    }
    if (mutation.expectedControlVersionId === undefined) {
      transaction.push({
        Put: {
          TableName: this.config.controlTableName,
          Item: {
            ...headKey,
            secretUid: mutation.secretUid,
            secretId: mutation.secretId,
            environment: mutation.environment,
            controlVersionId: mutation.control.controlVersionId,
            payloadVersionId: mutation.control.payloadVersionId,
            payloadKeyCount: mutation.control.payloadKeyCount,
            state: mutation.control.state,
            metadata: mutation.control.metadata,
            updatedAt: mutation.control.createdAt,
            catalogPk: catalogPk(mutation.environment),
            catalogSk: catalogSk(mutation.secretId),
            catalogTags: mutation.control.metadata.tags ?? {},
            workflowState: "PREPARED",
            leaseOwner: mutation.operationId,
            leaseExpiresAt: mutation.expiresAt,
          },
          ConditionExpression: "attribute_not_exists(pk)",
        },
      });
      transaction.push({
        Put: {
          TableName: this.config.controlTableName,
          Item: {
            pk: secretNamePk(mutation.environment, mutation.secretId),
            sk: "LOOKUP",
            secretUid: mutation.secretUid,
            secretId: mutation.secretId,
            environment: mutation.environment,
          },
          ConditionExpression: "attribute_not_exists(pk)",
        },
      });
    } else {
      transaction.push({
        Update: {
          TableName: this.config.controlTableName,
          Key: headKey,
          UpdateExpression:
            "SET leaseOwner = :owner, leaseExpiresAt = :expires",
          ConditionExpression:
            "controlVersionId = :expected AND (attribute_not_exists(leaseExpiresAt) OR leaseExpiresAt < :now)",
          ExpressionAttributeValues: {
            ":owner": mutation.operationId,
            ":expires": mutation.expiresAt,
            ":expected": mutation.expectedControlVersionId,
            ":now": isoNow(),
          },
        },
      });
    }
    try {
      await this.dynamo.send(
        new TransactWriteCommand({ TransactItems: transaction as never }),
      );
    } catch (error) {
      throw conflict(
        `Could not acquire the secret revision lease: ${errorMessage(error)}`,
      );
    }
  }

  public async completeMutation(completed: CompletedMutation): Promise<void> {
    const { prepared } = completed;
    const accessItems = accessItemsFor(
      prepared.secretUid,
      prepared.control,
      completed.priorAccess,
    );
    const replaceAccess = accessProjectionChanged(
      prepared.control,
      completed.priorAccess,
    );
    const notificationItems = notificationItemsFor(
      prepared.control,
      accessItems,
      replaceAccess,
    );
    const payloadVersionId =
      prepared.payload === undefined
        ? completed.priorHead?.payloadVersionId
        : prepared.payload.revision.payloadVersionId;
    const payloadObjectVersionId =
      completed.payloadObject === undefined
        ? completed.priorHead?.payloadObjectVersionId
        : completed.payloadObject.versionId;
    const payloadObjectKey =
      completed.payloadObject === undefined
        ? completed.priorHead?.payloadObjectKey
        : completed.payloadObject.key;
    const headValues: Record<string, unknown> = {
      ":control": prepared.control.controlVersionId,
      ":controlObjectVersionId": completed.controlObject.versionId,
      ":controlObjectKey": completed.controlObject.key,
      ":state": prepared.control.state,
      ":ready": "READY",
      ":owner": prepared.operationId,
      ":metadata": prepared.control.metadata,
      ":updatedAt": prepared.control.createdAt,
      ":catalogPk": catalogPkFor(
        prepared.control.environment,
        prepared.archive === true,
      ),
      ":catalogSk": catalogSk(prepared.secretId),
      ":catalogTags": prepared.control.metadata.tags ?? {},
    };
    const setClauses = [
      "controlVersionId = :control",
      "controlObjectVersionId = :controlObjectVersionId",
      "controlObjectKey = :controlObjectKey",
      "#state = :state",
      "workflowState = :ready",
      "metadata = :metadata",
      "updatedAt = :updatedAt",
      "catalogPk = :catalogPk",
      "catalogSk = :catalogSk",
      "catalogTags = :catalogTags",
    ];
    const removeClauses = ["leaseOwner", "leaseExpiresAt"];
    if (
      payloadVersionId !== undefined &&
      payloadObjectVersionId !== undefined &&
      payloadObjectKey !== undefined
    ) {
      setClauses.push(
        "payloadVersionId = :payload",
        "payloadObjectVersionId = :payloadObjectVersionId",
        "payloadObjectKey = :payloadObjectKey",
      );
      headValues[":payload"] = payloadVersionId;
      headValues[":payloadObjectVersionId"] = payloadObjectVersionId;
      headValues[":payloadObjectKey"] = payloadObjectKey;
    } else {
      removeClauses.push(
        "payloadVersionId",
        "payloadObjectVersionId",
        "payloadObjectKey",
      );
    }
    if (prepared.control.payloadKeyCount !== undefined) {
      setClauses.push("payloadKeyCount = :payloadKeyCount");
      headValues[":payloadKeyCount"] = prepared.control.payloadKeyCount;
    } else {
      removeClauses.push("payloadKeyCount");
    }
    const headUpdate = `SET ${setClauses.join(", ")} REMOVE ${removeClauses.join(", ")}`;
    const transaction: Record<string, unknown>[] = [
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: {
            pk: secretPk(prepared.secretUid),
            sk: "HEAD",
          },
          UpdateExpression: headUpdate,
          ConditionExpression: "leaseOwner = :owner",
          ExpressionAttributeNames: { "#state": "state" },
          ExpressionAttributeValues: headValues,
        },
      },
      workflowReadyUpdate(
        this.config.controlTableName,
        prepared.secretUid,
        `CONTROL#${prepared.control.controlVersionId}`,
        completed.controlObject,
      ),
    ];
    if (
      prepared.payload !== undefined &&
      completed.payloadObject !== undefined
    ) {
      transaction.push(
        workflowReadyUpdate(
          this.config.controlTableName,
          prepared.secretUid,
          `PAYLOAD#${prepared.payload.revision.payloadVersionId}`,
          completed.payloadObject,
        ),
      );
    }
    if (completed.priorHead !== undefined) {
      const retentionDueAt = new Date(
        Date.now() + 91 * 24 * 60 * 60 * 1000,
      ).toISOString();
      transaction.push(
        retentionCandidateUpdate(
          this.config.controlTableName,
          prepared.secretUid,
          `CONTROL#${completed.priorHead.controlVersionId}`,
          retentionDueAt,
        ),
      );
      if (completed.priorHead.payloadVersionId !== undefined) {
        transaction.push(
          retentionCandidateUpdate(
            this.config.controlTableName,
            prepared.secretUid,
            `PAYLOAD#${completed.priorHead.payloadVersionId}`,
            retentionDueAt,
          ),
        );
      }
    }
    if (prepared.archive === true) {
      transaction.push({
        Delete: {
          TableName: this.config.controlTableName,
          Key: {
            pk: secretNamePk(prepared.environment, prepared.secretId),
            sk: "LOOKUP",
          },
          ConditionExpression: "secretUid = :secretUid",
          ExpressionAttributeValues: { ":secretUid": prepared.secretUid },
        },
      });
    }
    if (replaceAccess) {
      for (const item of accessItems) {
        transaction.push({
          Put: {
            TableName: this.config.controlTableName,
            Item: item,
          },
        });
      }
    }
    for (const item of notificationItems) {
      transaction.push({
        Put: {
          TableName: this.config.controlTableName,
          Item: item,
          ConditionExpression: "attribute_not_exists(pk)",
        },
      });
    }
    if (transaction.length > 100) {
      throw serviceUnavailable(
        "Mutation exceeds the DynamoDB transaction limit.",
      );
    }
    await this.dynamo.send(
      new TransactWriteCommand({ TransactItems: transaction as never }),
    );
  }

  public async markAuditSucceeded(
    actor: Actor,
    idempotencyKey: string,
    eventId: string,
  ): Promise<void> {
    await this.dynamo.send(
      new UpdateCommand({
        TableName: this.config.controlTableName,
        Key: { pk: idempotencyPk(actor), sk: `REQUEST#${idempotencyKey}` },
        UpdateExpression:
          "SET #status = :status, terminalAuditEventId = :eventId",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":status": "SUCCEEDED",
          ":eventId": eventId,
        },
      }),
    );
  }

  public async listExpiredPrepared(now: string): Promise<StoredWorkflow[]> {
    const workflows: StoredWorkflow[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.config.controlTableName,
          IndexName: this.config.workflowDueIndex,
          KeyConditionExpression:
            "workflowDuePk = :pk AND workflowDueSk < :now",
          ExpressionAttributeValues: { ":pk": "WORKFLOW#DUE", ":now": now },
          ExclusiveStartKey: exclusiveStartKey as never,
        }),
      );
      workflows.push(...((response.Items ?? []) as StoredWorkflow[]));
      exclusiveStartKey = response.LastEvaluatedKey as
        Record<string, unknown> | undefined;
    } while (exclusiveStartKey !== undefined);
    return workflows;
  }

  public async markRetryable(workflow: StoredWorkflow): Promise<boolean> {
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: workflow.pk, sk: workflow.sk },
          UpdateExpression:
            "SET workflowState = :retryable REMOVE workflowDuePk, workflowDueSk",
          ConditionExpression: "workflowState = :prepared",
          ExpressionAttributeValues: {
            ":retryable": "RETRYABLE",
            ":prepared": "PREPARED",
          },
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  public async releaseLease(
    secretUid: string,
    operationId: string,
  ): Promise<boolean> {
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: secretPk(secretUid), sk: "HEAD" },
          UpdateExpression: "REMOVE leaseOwner, leaseExpiresAt",
          ConditionExpression: "leaseOwner = :owner",
          ExpressionAttributeValues: { ":owner": operationId },
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  /**
   * An initial create has no prior head to restore. Once its expired workflow
   * has been made retryable, remove that still-prepared head so the explicit
   * secret ID is usable by a new request.
   */
  public async abortPreparedCreate(
    environment: string,
    secretId: string,
    secretUid: string,
    operationId: string,
  ): Promise<boolean> {
    try {
      await this.dynamo.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Delete: {
                TableName: this.config.controlTableName,
                Key: { pk: secretPk(secretUid), sk: "HEAD" },
                ConditionExpression:
                  "leaseOwner = :owner AND workflowState = :prepared",
                ExpressionAttributeValues: {
                  ":owner": operationId,
                  ":prepared": "PREPARED",
                },
              },
            },
            {
              Delete: {
                TableName: this.config.controlTableName,
                Key: { pk: secretNamePk(environment, secretId), sk: "LOOKUP" },
                ConditionExpression: "secretUid = :secretUid",
                ExpressionAttributeValues: { ":secretUid": secretUid },
              },
            },
          ],
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  public async listReadyWorkflows(): Promise<StoredWorkflow[]> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.retentionDueIndex,
        KeyConditionExpression:
          "retentionDuePk = :pk AND retentionDueSk <= :now",
        ExpressionAttributeValues: { ":pk": "RETENTION#DUE", ":now": isoNow() },
      }),
    );
    return (response.Items ?? []) as StoredWorkflow[];
  }

  public async markRetentionDeleted(workflow: StoredWorkflow): Promise<void> {
    await this.dynamo.send(
      new UpdateCommand({
        TableName: this.config.controlTableName,
        Key: { pk: workflow.pk, sk: workflow.sk },
        UpdateExpression:
          "SET workflowState = :deleted REMOVE retentionDuePk, retentionDueSk",
        ConditionExpression: "workflowState = :ready",
        ExpressionAttributeValues: { ":deleted": "DELETED", ":ready": "READY" },
      }),
    );
  }
}

export const secretPk = (secretUid: string): string => `SECRET#${secretUid}`;

export const secretNamePk = (environment: string, secretId: string): string =>
  `SECRET_NAME#${environment}#${secretId}`;

const accessSk = (environment: string, secretUid: string): string =>
  `${accessSkPrefix(environment)}${secretUid}`;

const accessSkPrefix = (environment: string): string =>
  `SECRET#${environment}#`;

export const secretIdentityFromPk = (
  pk: string,
): { readonly secretUid: string } | undefined => {
  if (!pk.startsWith("SECRET#")) {
    return undefined;
  }
  const secretUid = pk.slice("SECRET#".length);
  return secretUid.length === 0 ? undefined : { secretUid };
};

const agentGrantPk = (grantId: string): string => `AGENT_GRANT#${grantId}`;

const bootstrapPk = (tokenHash: string): string => `BOOTSTRAP#${tokenHash}`;

const cursorPk = (token: string): string => `CURSOR#${token}`;

const environmentsPk = "SYSTEM#ENVIRONMENTS";

const environmentSk = (name: string): string => `ENVIRONMENT#${name}`;

const idempotencyPk = (actor: Actor): string =>
  `IDEMPOTENCY#${actor.type}#${actor.id}`;

export const catalogPk = (environment: string): string =>
  `CATALOG#${environment}`;

export const archivedCatalogPk = (environment: string): string =>
  `ARCHIVED_CATALOG#${environment}`;

const catalogPkFor = (environment: string, archived: boolean): string =>
  archived ? archivedCatalogPk(environment) : catalogPk(environment);

export const consumerDirectoryPk = (environment: string): string =>
  `CONSUMERS#${environment}`;

export const identityConsumerPk = (consumerId: string): string =>
  `CONSUMER#${consumerId}`;

export const identityConsumerSk = (
  notAfter: string,
  fingerprint: string,
): string => `${notAfter}#${fingerprint}`;

export const catalogSk = (secretId: string): string =>
  `PATH#${secretFolderPath(secretId) ?? "_"}/SECRET#${secretId}`;

const catalogPathPrefix = (path: string | undefined): string =>
  path === undefined ? "PATH#" : `PATH#${path}/`;

const secretFolderPath = (secretId: string): string | undefined => {
  const separator = secretId.lastIndexOf("/");
  return separator === -1 ? undefined : secretId.slice(0, separator);
};

/**
 * The immediate child segment of `path` below `pathPrefix`, or undefined
 * when `path` is not nested beneath `pathPrefix` at all. Exact equality
 * (`path === pathPrefix`) is handled by the caller before reaching here,
 * since that case means "this level itself", not a child of it.
 */
const childSegment = (
  path: string,
  pathPrefix: string | undefined,
): string | undefined => {
  if (pathPrefix === undefined) {
    return path.split("/")[0];
  }
  if (!path.startsWith(`${pathPrefix}/`)) {
    return undefined;
  }
  return path.slice(pathPrefix.length + 1).split("/")[0];
};

/** Shared READY + exact-tag filter used by both the plain and search catalog queries. */
const catalogFilter = (
  environment: string,
  pathPrefix: string | undefined,
  tags: Readonly<Record<string, string>>,
  archived: boolean,
): {
  readonly expressionAttributeNames: Record<string, string>;
  readonly expressionAttributeValues: Record<string, unknown>;
  readonly filterExpression: string;
} => {
  const expressionAttributeNames: Record<string, string> = {
    "#workflowState": "workflowState",
  };
  const expressionAttributeValues: Record<string, unknown> = {
    ":catalogPk": catalogPkFor(environment, archived),
    ":pathPrefix": catalogPathPrefix(pathPrefix),
    ":ready": "READY",
  };
  const filters = ["#workflowState = :ready"];
  for (const [index, [key, value]] of Object.entries(tags).entries()) {
    const keyName = `#tagKey${index}`;
    const valueName = `:tagValue${index}`;
    expressionAttributeNames[keyName] = key;
    expressionAttributeValues[valueName] = value;
    filters.push(`catalogTags.${keyName} = ${valueName}`);
  }
  return {
    expressionAttributeNames,
    expressionAttributeValues,
    filterExpression: filters.join(" AND "),
  };
};

const workflowItem = (
  environment: string,
  secretId: string,
  secretUid: string,
  sk: string,
  operationId: string,
  objectKey: string,
  checksumSha256: string,
  expiresAt: string,
  serialized: object,
  revisionIndex?: {
    readonly createdAt: string;
    readonly controlVersionId: string;
  },
): Record<string, unknown> => ({
  pk: secretPk(secretUid),
  secretUid,
  sk,
  workflowState: "PREPARED",
  workflowKind: "secret.mutation",
  operationId,
  objectKey,
  checksumSha256,
  expiresAt,
  workflowDuePk: "WORKFLOW#DUE",
  workflowDueSk: expiresAt,
  serialized,
  ...(revisionIndex === undefined
    ? {}
    : {
        revisionPk: secretPk(secretUid),
        revisionSk: `${revisionIndex.createdAt}#${revisionIndex.controlVersionId}`,
      }),
});

const workflowReadyUpdate = (
  tableName: string,
  secretUid: string,
  sk: string,
  object: ObjectReference,
): Record<string, unknown> => ({
  Update: {
    TableName: tableName,
    Key: { pk: secretPk(secretUid), sk },
    UpdateExpression:
      "SET workflowState = :ready, s3VersionId = :versionId, objectKey = :key, checksumSha256 = :checksum REMOVE workflowDuePk, workflowDueSk",
    ConditionExpression: "workflowState = :prepared",
    ExpressionAttributeValues: {
      ":ready": "READY",
      ":versionId": object.versionId,
      ":key": object.key,
      ":checksum": object.checksumSha256,
      ":prepared": "PREPARED",
    },
  },
});

const retentionCandidateUpdate = (
  tableName: string,
  secretUid: string,
  sk: string,
  retentionDueAt: string,
): Record<string, unknown> => ({
  Update: {
    TableName: tableName,
    Key: { pk: secretPk(secretUid), sk },
    UpdateExpression: "SET retentionDuePk = :pk, retentionDueSk = :due",
    ConditionExpression: "workflowState = :ready",
    ExpressionAttributeValues: {
      ":pk": "RETENTION#DUE",
      ":due": retentionDueAt,
      ":ready": "READY",
    },
  },
});

const accessItemsFor = (
  secretUid: string,
  control: ControlRevision,
  prior: readonly AccessRecord[],
): AccessRecord[] => {
  const priorByConsumer = new Map(prior.map((item) => [item.consumerId, item]));
  const nextByConsumer = new Map(
    control.acl.map((grant) => [grant.consumerId, grant]),
  );
  const consumerIds = new Set([
    ...priorByConsumer.keys(),
    ...nextByConsumer.keys(),
  ]);
  return [...consumerIds].map((consumerId): AccessRecord => {
    const grant = nextByConsumer.get(consumerId);
    const hasRead = grant?.permissions.includes("read") ?? false;
    return {
      pk: `CONSUMER#${consumerId}`,
      sk: accessSk(control.environment, secretUid),
      consumerId,
      secretUid,
      secretId: control.secretId,
      environment: control.environment,
      permissions: hasRead ? ["read"] : [],
      controlVersionId: control.controlVersionId,
      payloadVersionId: control.payloadVersionId,
      state: hasRead ? control.state : "REVOKED",
      changeKind: hasRead ? "secret.changed" : "secret.revoked",
    };
  });
};

const accessProjectionChanged = (
  control: ControlRevision,
  prior: readonly AccessRecord[],
): boolean => {
  const grants = new Map(
    control.acl
      .filter((grant) => grant.permissions.includes("read"))
      .map((grant) => [grant.consumerId, grant]),
  );
  const activePrior = new Map(
    prior
      .filter(
        (access) =>
          access.permissions.includes("read") && access.state !== "REVOKED",
      )
      .map((access) => [access.consumerId, access]),
  );
  if (grants.size !== activePrior.size) {
    return true;
  }
  return [...grants.keys()].some((consumerId) => !activePrior.has(consumerId));
};

const notificationItemsFor = (
  control: ControlRevision,
  accessItems: readonly AccessRecord[],
  accessChanged: boolean,
): NotificationOutboxRecord[] => {
  const currentRecipients = accessChanged
    ? accessItems
        .filter(
          (access) =>
            access.permissions.includes("read") && access.state !== "REVOKED",
        )
        .map((access) => access.consumerId)
    : control.acl
        .filter((grant) => grant.permissions.includes("read"))
        .map((grant) => grant.consumerId);
  const revokedRecipients = accessChanged
    ? accessItems
        .filter(
          (access) =>
            !access.permissions.includes("read") || access.state === "REVOKED",
        )
        .map((access) => access.consumerId)
    : [];
  return [
    notificationOutboxRecord(control, "secret.changed", currentRecipients),
    notificationOutboxRecord(control, "secret.revoked", revokedRecipients),
  ].filter(
    (record): record is NotificationOutboxRecord => record !== undefined,
  );
};

const notificationOutboxRecord = (
  control: ControlRevision,
  kind: NotificationOutboxRecord["kind"],
  consumerIds: readonly string[],
): NotificationOutboxRecord | undefined => {
  if (consumerIds.length === 0) {
    return undefined;
  }
  const eventId = newId();
  return {
    pk: notificationPk(eventId),
    sk: "EVENT",
    eventId,
    consumerIds,
    secretId: control.secretId,
    environment: control.environment,
    controlVersionId: control.controlVersionId,
    ...(kind === "secret.revoked" || control.payloadVersionId === undefined
      ? {}
      : { payloadVersionId: control.payloadVersionId }),
    kind,
    createdAt: control.createdAt,
    status: "PENDING",
  };
};

const notificationPk = (eventId: string): string => `NOTIFICATION#${eventId}`;

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown error";

const isConditionalCheckFailure = (error: unknown): boolean =>
  error instanceof Error && error.name === "ConditionalCheckFailedException";
