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
  Actor,
  CatalogPage,
  ChangePage,
  ConsumerProvisioningResult,
  ConsumerRecord,
  ControlRevision,
  EnrollmentOperationType,
  EnrollmentRecord,
  HeadRecord,
  IdentityRecord,
  IssuerRecord,
  ObjectReference,
  PayloadRevision,
  SecretState,
  TruststoreRootRecord,
  WorkflowState,
} from "../domain/types";
import { isoNow } from "../util/encoding";

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

export interface PreparedMutation {
  readonly operationId: string;
  readonly idempotencyKey: string;
  readonly actor: Actor;
  readonly requestDigest: string;
  readonly secretId: string;
  readonly environment: string;
  readonly expectedControlVersionId?: string;
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

export class DynamoRepository {
  public constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    private readonly config: AppConfig,
  ) {}

  public async getHead(secretId: string): Promise<HeadRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: secretPk(secretId), sk: "HEAD" },
        ConsistentRead: true,
      }),
    );
    return response.Item as HeadRecord | undefined;
  }

  public async requireHead(secretId: string): Promise<HeadRecord> {
    const head = await this.getHead(secretId);
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
    secretId: string,
  ): Promise<AccessRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `CONSUMER#${consumerId}`, sk: `SECRET#${secretId}` },
        ConsistentRead: true,
      }),
    );
    return response.Item as AccessRecord | undefined;
  }

  public async getAccessAndHead(
    consumerId: string,
    secretId: string,
  ): Promise<AccessAndHead> {
    const response = await this.dynamo.send(
      new TransactGetCommand({
        TransactItems: [
          {
            Get: {
              TableName: this.config.controlTableName,
              Key: { pk: `CONSUMER#${consumerId}`, sk: `SECRET#${secretId}` },
            },
          },
          {
            Get: {
              TableName: this.config.controlTableName,
              Key: { pk: secretPk(secretId), sk: "HEAD" },
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
        FilterExpression: "#environment = :environment",
        ExpressionAttributeNames: { "#environment": "environment" },
        ExpressionAttributeValues: {
          ":pk": `CONSUMER#${consumerId}`,
          ":prefix": "SECRET#",
          ":environment": environment,
        },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: 100,
        ConsistentRead: true,
      }),
    );
    return {
      changes: (response.Items ?? []) as AccessRecord[],
      nextCursor:
        response.LastEvaluatedKey === undefined
          ? undefined
          : JSON.stringify(response.LastEvaluatedKey),
    };
  }

  public async listSecrets(
    environment: string,
    pathPrefix: string | undefined,
    tags: Readonly<Record<string, string>>,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<CatalogPage> {
    const expressionAttributeNames: Record<string, string> = {
      "#workflowState": "workflowState",
    };
    const expressionAttributeValues: Record<string, unknown> = {
      ":catalogPk": catalogPk(environment),
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
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.catalogPathIndex,
        KeyConditionExpression:
          "catalogPk = :catalogPk AND begins_with(catalogSk, :pathPrefix)",
        FilterExpression: filters.join(" AND "),
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
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

  public async listConsumers(
    environment: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<{ readonly consumers: readonly ConsumerRecord[]; readonly nextCursor?: string }> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.consumerDirectoryIndex,
        KeyConditionExpression: "consumerDirectoryPk = :directory",
        ExpressionAttributeValues: { ":directory": consumerDirectoryPk(environment) },
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
  ): Promise<{ readonly identities: readonly IdentityRecord[]; readonly nextCursor?: string }> {
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

  public async countActiveConsumerApiIdentities(consumerId: string): Promise<number> {
    let count = 0;
    let exclusiveStartKey: Record<string, unknown> | undefined;
    const now = isoNow();
    do {
      const response = await this.dynamo.send(
        new QueryCommand({
          TableName: this.config.controlTableName,
          IndexName: this.config.consumerIdentityIndex,
          KeyConditionExpression: "identityConsumerPk = :consumer",
          FilterExpression: "#status = :active AND kind = :api AND notAfter > :now",
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
      exclusiveStartKey = response.LastEvaluatedKey as Record<string, unknown> | undefined;
    } while (exclusiveStartKey !== undefined);
    return count;
  }

  /**
   * The revision GSI is chronologically ordered, letting this fixed-size
   * response contain the newest revisions rather than an arbitrary UUID slice.
   */
  public async listRecentControlRevisions(secretId: string): Promise<RevisionHistoryPage> {
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.config.controlTableName,
        IndexName: this.config.secretRevisionIndex,
        KeyConditionExpression: "revisionPk = :secret",
        ExpressionAttributeValues: { ":secret": secretPk(secretId) },
        Limit: maximumRevisionHistory + 1,
        ScanIndexForward: false,
      }),
    );
    const revisions = (response.Items ?? [])
      .slice(0, maximumRevisionHistory)
      .filter((item): item is StoredControlRevision =>
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
          ConditionExpression: "#status = :pending AND consumerId = :consumerId",
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
          UpdateExpression: "SET #status = :active",
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
          ConditionExpression: "#status = :pending AND consumerId = :consumerId",
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
    const headKey = { pk: secretPk(mutation.secretId), sk: "HEAD" };
    const controlItem = workflowItem(
      mutation.secretId,
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
            mutation.secretId,
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
            secretId: mutation.secretId,
            environment: mutation.environment,
            controlVersionId: mutation.control.controlVersionId,
            payloadVersionId: mutation.control.payloadVersionId,
            payloadKeyCount: mutation.control.payloadKeyCount,
            state: mutation.control.state,
            metadata: mutation.control.metadata,
            updatedAt: mutation.control.createdAt,
            catalogPk: catalogPk(mutation.environment),
            catalogSk: catalogSk(
              mutation.control.metadata.path,
              mutation.secretId,
            ),
            catalogTags: mutation.control.metadata.tags ?? {},
            workflowState: "PREPARED",
            leaseOwner: mutation.operationId,
            leaseExpiresAt: mutation.expiresAt,
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
    const accessItems = accessItemsFor(prepared.control, completed.priorAccess);
    const payloadVersionId =
      prepared.payload === undefined
        ? completed.priorHead?.payloadVersionId
        : prepared.payload.revision.payloadVersionId;
    const payloadObjectVersionId =
      completed.payloadObject === undefined
        ? completed.priorHead?.payloadObjectVersionId
        : completed.payloadObject.versionId;
    const headValues: Record<string, unknown> = {
      ":control": prepared.control.controlVersionId,
      ":controlObjectVersionId": completed.controlObject.versionId,
      ":state": prepared.control.state,
      ":ready": "READY",
      ":owner": prepared.operationId,
      ":metadata": prepared.control.metadata,
      ":updatedAt": prepared.control.createdAt,
      ":catalogPk": catalogPk(prepared.control.environment),
      ":catalogSk": catalogSk(
        prepared.control.metadata.path,
        prepared.secretId,
      ),
      ":catalogTags": prepared.control.metadata.tags ?? {},
    };
    const setClauses = [
      "controlVersionId = :control",
      "controlObjectVersionId = :controlObjectVersionId",
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
      payloadObjectVersionId !== undefined
    ) {
      setClauses.push(
        "payloadVersionId = :payload",
        "payloadObjectVersionId = :payloadObjectVersionId",
      );
      headValues[":payload"] = payloadVersionId;
      headValues[":payloadObjectVersionId"] = payloadObjectVersionId;
    } else {
      removeClauses.push("payloadVersionId", "payloadObjectVersionId");
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
          Key: { pk: secretPk(prepared.secretId), sk: "HEAD" },
          UpdateExpression: headUpdate,
          ConditionExpression: "leaseOwner = :owner",
          ExpressionAttributeNames: { "#state": "state" },
          ExpressionAttributeValues: headValues,
        },
      },
      workflowReadyUpdate(
        this.config.controlTableName,
        prepared.secretId,
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
          prepared.secretId,
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
          prepared.secretId,
          `CONTROL#${completed.priorHead.controlVersionId}`,
          retentionDueAt,
        ),
      );
      if (completed.priorHead.payloadVersionId !== undefined) {
        transaction.push(
          retentionCandidateUpdate(
            this.config.controlTableName,
            prepared.secretId,
            `PAYLOAD#${completed.priorHead.payloadVersionId}`,
            retentionDueAt,
          ),
        );
      }
    }
    for (const item of accessItems) {
      transaction.push({
        Put: {
          TableName: this.config.controlTableName,
          Item: item,
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
    secretId: string,
    operationId: string,
  ): Promise<boolean> {
    try {
      await this.dynamo.send(
        new UpdateCommand({
          TableName: this.config.controlTableName,
          Key: { pk: secretPk(secretId), sk: "HEAD" },
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
    secretId: string,
    operationId: string,
  ): Promise<boolean> {
    try {
      await this.dynamo.send(
        new DeleteCommand({
          TableName: this.config.controlTableName,
          Key: { pk: secretPk(secretId), sk: "HEAD" },
          ConditionExpression:
            "leaseOwner = :owner AND workflowState = :prepared",
          ExpressionAttributeValues: {
            ":owner": operationId,
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

export const secretPk = (secretId: string): string => `SECRET#${secretId}`;

const idempotencyPk = (actor: Actor): string =>
  `IDEMPOTENCY#${actor.type}#${actor.id}`;

export const catalogPk = (environment: string): string =>
  `CATALOG#${environment}`;

export const consumerDirectoryPk = (environment: string): string =>
  `CONSUMERS#${environment}`;

export const identityConsumerPk = (consumerId: string): string =>
  `CONSUMER#${consumerId}`;

export const identityConsumerSk = (notAfter: string, fingerprint: string): string =>
  `${notAfter}#${fingerprint}`;

export const catalogSk = (path: string | undefined, secretId: string): string =>
  `PATH#${path ?? "_"}\/SECRET#${secretId}`;

const catalogPathPrefix = (path: string | undefined): string =>
  path === undefined ? "PATH#" : `PATH#${path}\/`;

const workflowItem = (
  secretId: string,
  sk: string,
  operationId: string,
  objectKey: string,
  checksumSha256: string,
  expiresAt: string,
  serialized: object,
  revisionIndex?: { readonly createdAt: string; readonly controlVersionId: string },
): Record<string, unknown> => ({
  pk: secretPk(secretId),
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
        revisionPk: secretPk(secretId),
        revisionSk: `${revisionIndex.createdAt}#${revisionIndex.controlVersionId}`,
      }),
});

const workflowReadyUpdate = (
  tableName: string,
  secretId: string,
  sk: string,
  object: ObjectReference,
): Record<string, unknown> => ({
  Update: {
    TableName: tableName,
    Key: { pk: secretPk(secretId), sk },
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
  secretId: string,
  sk: string,
  retentionDueAt: string,
): Record<string, unknown> => ({
  Update: {
    TableName: tableName,
    Key: { pk: secretPk(secretId), sk },
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
      sk: `SECRET#${control.secretId}`,
      consumerId,
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

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown error";

const isConditionalCheckFailure = (error: unknown): boolean =>
  error instanceof Error && error.name === "ConditionalCheckFailedException";
