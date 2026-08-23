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
  ClusterProvisioningResult,
  ClusterRecord,
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
  readonly serialized?: Record<string, unknown>;
  readonly s3VersionId?: string;
  readonly workflowKind?: "secret.mutation" | "cluster.enrollment";
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
  readonly clusterId: string;
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
}

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

  public async getCluster(
    clusterId: string,
  ): Promise<ClusterRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `CLUSTER#${clusterId}`, sk: "PROFILE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as ClusterRecord | undefined;
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
      clusterId: "clavis",
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
        throw conflict("Could not create the Clavis issuing root.");
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
      clusterId: "clavis",
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
        throw conflict("The Clavis issuing-root truststore record is invalid.");
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
    clusterId: string,
    secretId: string,
  ): Promise<AccessRecord | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.config.controlTableName,
        Key: { pk: `CLUSTER#${clusterId}`, sk: `SECRET#${secretId}` },
        ConsistentRead: true,
      }),
    );
    return response.Item as AccessRecord | undefined;
  }

  public async getAccessAndHead(
    clusterId: string,
    secretId: string,
  ): Promise<AccessAndHead> {
    const response = await this.dynamo.send(
      new TransactGetCommand({
        TransactItems: [
          {
            Get: {
              TableName: this.config.controlTableName,
              Key: { pk: `CLUSTER#${clusterId}`, sk: `SECRET#${secretId}` },
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
    clusterId: string,
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
          ":pk": `CLUSTER#${clusterId}`,
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
      clusterId: enrollment.clusterId,
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
    };
    const operationItem = {
      pk: `ENROLLMENT#${enrollment.operationId}`,
      sk: "STATE",
      operationId: enrollment.operationId,
      operationType: enrollment.operationType,
      clusterId: enrollment.clusterId,
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
      workflowKind: "cluster.enrollment",
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
          pk: `CLUSTER#${enrollment.clusterId}`,
          sk: "PROFILE",
          clusterId: enrollment.clusterId,
          environment: enrollment.environment,
          subjectUri: enrollment.subjectUri,
          status: "PENDING",
          createdAt: enrollment.createdAt,
          createdBy: enrollment.actor,
        } satisfies ClusterRecord,
        ConditionExpression: "attribute_not_exists(pk)",
      },
    });
    try {
      await this.dynamo.send(
        new TransactWriteCommand({ TransactItems: transaction as never }),
      );
    } catch (error) {
      throw conflict(
        `Could not prepare cluster enrollment: ${errorMessage(error)}`,
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
  ): Promise<ClusterProvisioningResult> {
    const transaction: Record<string, unknown>[] = [
      {
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `IDENTITY#${operation.apiFingerprint}`, sk: "PROFILE" },
          UpdateExpression: "SET #status = :active",
          ConditionExpression: "#status = :pending AND clusterId = :clusterId",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":active": "ACTIVE",
            ":pending": "PENDING",
            ":clusterId": operation.clusterId,
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
    if (operation.operationType === "cluster.enroll") {
      transaction.push({
        Update: {
          TableName: this.config.controlTableName,
          Key: { pk: `CLUSTER#${operation.clusterId}`, sk: "PROFILE" },
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
      clusterId: operation.clusterId,
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
          ConditionExpression: "#status = :pending AND clusterId = :clusterId",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":failed": "FAILED",
            ":pending": "PENDING",
            ":clusterId": operation.clusterId,
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
    if (operation.operationType === "cluster.enroll") {
      transaction.push({
        Delete: {
          TableName: this.config.controlTableName,
          Key: { pk: `CLUSTER#${operation.clusterId}`, sk: "PROFILE" },
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
                  operationType: "cluster.api.rotate",
                  clusterId: identity.clusterId,
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
                } satisfies IdentityRecord,
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
          ],
        }),
      );
    } catch (error) {
      throw conflict(
        `Could not create cluster API identity: ${errorMessage(error)}`,
      );
    }
  }

  public async revokeApiIdentity(
    actor: Actor,
    idempotencyKey: string,
    requestDigest: string,
    clusterId: string,
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
                  operationType: "cluster.api.revoke",
                  clusterId,
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
                  "clusterId = :clusterId AND kind = :kind AND #status = :active",
                ExpressionAttributeNames: { "#status": "status" },
                ExpressionAttributeValues: {
                  ":revoked": "REVOKED",
                  ":clusterId": clusterId,
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
        `Could not revoke cluster API identity: ${errorMessage(error)}`,
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
    if (transaction.length > 25) {
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
  const priorByCluster = new Map(prior.map((item) => [item.clusterId, item]));
  const nextByCluster = new Map(
    control.acl.map((grant) => [grant.clusterId, grant]),
  );
  const clusterIds = new Set([
    ...priorByCluster.keys(),
    ...nextByCluster.keys(),
  ]);
  return [...clusterIds].map((clusterId): AccessRecord => {
    const grant = nextByCluster.get(clusterId);
    const hasRead = grant?.permissions.includes("read") ?? false;
    return {
      pk: `CLUSTER#${clusterId}`,
      sk: `SECRET#${control.secretId}`,
      clusterId,
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
