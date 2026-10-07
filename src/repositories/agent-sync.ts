import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
  type TransactWriteCommandInput,
} from "@aws-sdk/lib-dynamodb";
import { ApiError, serviceUnavailable } from "../domain/errors";
import type {
  ControlRevision,
  HeadRecord,
  SecretMetadata,
  SecretState,
} from "../domain/types";
import { newId } from "../util/encoding";

export const syncCheckpointLifetime = 7 * 24 * 60 * 60 * 1_000;
const archiveLifetime = 8 * 24 * 60 * 60;
type Transaction = NonNullable<TransactWriteCommandInput["TransactItems"]>;

export interface AgentSyncState {
  readonly epoch: string;
  readonly sequence: number;
  readonly ready: boolean;
}

export interface AgentSyncRecord {
  readonly secretUid: string;
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly state: SecretState;
  readonly metadata: SecretMetadata;
  readonly readConsumerIds: readonly string[];
}

export const syncPk = (environment: string): string =>
  `AGENT_SYNC#${environment}`;
export const syncSk = (sequence: number, secretUid: string): string =>
  `CHANGE#${String(sequence).padStart(16, "0")}#${secretUid}`;

export const syncRecord = (
  secretUid: string,
  control: ControlRevision,
): AgentSyncRecord => ({
  secretUid,
  secretId: control.secretId,
  controlVersionId: control.controlVersionId,
  ...(control.payloadVersionId === undefined
    ? {}
    : { payloadVersionId: control.payloadVersionId }),
  state: control.state,
  metadata: control.metadata,
  readConsumerIds: control.acl
    .filter((grant) => grant.permissions.includes("read"))
    .map((grant) => grant.consumerId),
});

/** Strongly consistent current-state projection; no event history or GSI. */
export class AgentSyncRepository {
  public constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    private readonly tableName: string,
  ) {}

  public emptyState(
    environment: string,
  ): NonNullable<Transaction[number]["Put"]> {
    return {
      TableName: this.tableName,
      Item: {
        pk: syncPk(environment),
        sk: "STATE",
        epoch: newId(),
        sequence: 0,
        ready: true,
      },
      ConditionExpression: "attribute_not_exists(pk)",
    };
  }

  public async state(environment: string): Promise<AgentSyncState | undefined> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk: syncPk(environment), sk: "STATE" },
        ConsistentRead: true,
      }),
    );
    return response.Item as AgentSyncState | undefined;
  }

  public async page(
    environment: string,
    after: number,
    through: number,
    lastSk?: string,
  ): Promise<{
    readonly records: readonly AgentSyncRecord[];
    readonly lastSk?: string;
  }> {
    if (after === through) return { records: [] };
    const response = await this.dynamo.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: "pk = :pk AND sk BETWEEN :first AND :last",
        ExpressionAttributeValues: {
          ":pk": syncPk(environment),
          ":first": syncSk(after + 1, ""),
          ":last": `CHANGE#${String(through).padStart(16, "0")}#\uffff`,
        },
        ...(lastSk === undefined
          ? {}
          : { ExclusiveStartKey: { pk: syncPk(environment), sk: lastSk } }),
        ConsistentRead: true,
        Limit: 100,
      }),
    );
    return {
      records: (response.Items ?? []) as AgentSyncRecord[],
      ...(typeof response.LastEvaluatedKey?.sk === "string"
        ? { lastSk: response.LastEvaluatedKey.sk }
        : {}),
    };
  }

  /** Counter and projection commit with the caller's head/revision transaction. */
  public async publish(
    environment: string,
    record: AgentSyncRecord,
    build: (sequence: number) => Transaction,
  ): Promise<void> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      // This order matters: any newer head publication also changes STATE,
      // so its compare-and-set rejects a stale counter/head combination.
      const state = await this.state(environment);
      const headResponse = await this.dynamo.send(
        new GetCommand({
          TableName: this.tableName,
          Key: { pk: `SECRET#${record.secretUid}`, sk: "HEAD" },
          ConsistentRead: true,
          ProjectionExpression: "syncSequence",
        }),
      );
      const previousSequence = headResponse.Item?.syncSequence as
        number | undefined;
      const sequence = (state?.sequence ?? 0) + 1;
      if (!Number.isSafeInteger(sequence))
        throw serviceUnavailable("The sync index sequence is exhausted.");
      const pk = syncPk(environment);
      const counter: Transaction[number] =
        state === undefined
          ? {
              Put: {
                TableName: this.tableName,
                Item: {
                  pk,
                  sk: "STATE",
                  epoch: newId(),
                  sequence,
                  ready: false,
                },
                ConditionExpression: "attribute_not_exists(pk)",
              },
            }
          : {
              Update: {
                TableName: this.tableName,
                Key: { pk, sk: "STATE" },
                UpdateExpression: "SET #sequence = :next",
                ConditionExpression: "#sequence = :prior AND epoch = :epoch",
                ExpressionAttributeNames: { "#sequence": "sequence" },
                ExpressionAttributeValues: {
                  ":next": sequence,
                  ":prior": state.sequence,
                  ":epoch": state.epoch,
                },
              },
            };
      const items: Transaction = [
        counter,
        ...build(sequence),
        {
          Put: {
            TableName: this.tableName,
            Item: {
              pk,
              sk: syncSk(sequence, record.secretUid),
              ...record,
              ...(record.state === "ARCHIVED"
                ? { ttl: Math.ceil(Date.now() / 1_000) + archiveLifetime }
                : {}),
            },
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
      ];
      if (previousSequence !== undefined)
        items.push({
          Delete: {
            TableName: this.tableName,
            Key: { pk, sk: syncSk(previousSequence, record.secretUid) },
          },
        });
      if (items.length > 100)
        throw serviceUnavailable(
          "Mutation exceeds the DynamoDB transaction limit.",
        );
      try {
        await this.dynamo.send(
          new TransactWriteCommand({ TransactItems: items }),
        );
        return;
      } catch (error) {
        if (!counterContention(error)) throw error;
        if (attempt === 7)
          throw serviceUnavailable(
            "The sync index is busy; retry the mutation.",
          );
        await new Promise((resolve) =>
          setTimeout(resolve, 5 * 2 ** attempt + Math.random() * 10),
        );
      }
    }
  }

  /** Backfill only the still-current immutable control; never clobber a writer. */
  public async backfillHead(head: HeadRecord): Promise<void> {
    const response = await this.dynamo.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk: head.pk, sk: `CONTROL#${head.controlVersionId}` },
        ConsistentRead: true,
      }),
    );
    const control = response.Item?.serialized as ControlRevision | undefined;
    if (
      control === undefined ||
      control.controlVersionId !== head.controlVersionId ||
      control.environment !== head.environment ||
      control.secretId !== head.secretId ||
      (control.secretUid !== undefined && control.secretUid !== head.secretUid)
    ) {
      throw new ApiError(
        503,
        "sync_backfill_incomplete",
        "The current control revision is unavailable for sync backfill.",
      );
    }
    await this.publish(
      head.environment,
      syncRecord(head.secretUid, control),
      (sequence) => [
        {
          Update: {
            TableName: this.tableName,
            Key: { pk: head.pk, sk: "HEAD" },
            UpdateExpression: "SET syncSequence = :sequence",
            ConditionExpression:
              "controlVersionId = :control AND workflowState = :ready",
            ExpressionAttributeValues: {
              ":sequence": sequence,
              ":control": head.controlVersionId,
              ":ready": "READY",
            },
          },
        },
      ],
    );
  }

  public async markReady(environment: string): Promise<void> {
    // An empty existing environment can become ready without any publication.
    const state = await this.state(environment);
    if (state === undefined) {
      try {
        await this.dynamo.send(
          new TransactWriteCommand({
            TransactItems: [{ Put: this.emptyState(environment) }],
          }),
        );
        return;
      } catch (error) {
        if (!counterContention(error)) throw error;
      }
    }
    await this.dynamo.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: syncPk(environment), sk: "STATE" },
        UpdateExpression: "SET ready = :ready",
        ConditionExpression: "attribute_exists(epoch)",
        ExpressionAttributeValues: { ":ready": true },
      }),
    );
  }
}

const counterContention = (error: unknown): boolean => {
  if (error === null || typeof error !== "object") return false;
  const transaction = error as {
    name?: string;
    CancellationReasons?: { Code?: string }[];
  };
  if (transaction.name !== "TransactionCanceledException") return false;
  const reasons = transaction.CancellationReasons ?? [];
  // Do not retry a separate failed lease/revision condition or other rejection.
  return (
    reasons.some(
      (reason) =>
        reason.Code === "ConditionalCheckFailed" ||
        reason.Code === "TransactionConflict",
    ) &&
    reasons.every(
      (reason, index) =>
        reason.Code === undefined ||
        reason.Code === "None" ||
        reason.Code === "TransactionConflict" ||
        (index === 0 && reason.Code === "ConditionalCheckFailed"),
    )
  );
};
