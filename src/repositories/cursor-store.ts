import {
  GetCommand,
  PutCommand,
  type DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";
import type { CursorStore, StoredCursor } from "../services/cursor";

export type CursorKeyPrefix = "CURSOR#" | "PKI_CURSOR#";

/**
 * Pagination state is opaque to callers and expires through the table's TTL
 * attribute. A conditional put turns the already negligible 256-bit token
 * collision chance into a retry rather than a state overwrite. The key prefix
 * keeps PKI pagination state inside the PKI role's `PKI_*` key space.
 */
export class DynamoCursorStore implements CursorStore {
  public constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    private readonly tableName: string,
    private readonly prefix: CursorKeyPrefix,
  ) {}

  public async createCursor(cursor: StoredCursor): Promise<boolean> {
    try {
      await this.dynamo.send(
        new PutCommand({
          TableName: this.tableName,
          Item: {
            pk: `${this.prefix}${cursor.token}`,
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
        TableName: this.tableName,
        Key: { pk: `${this.prefix}${token}`, sk: "STATE" },
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
}

// Not imported from dynamo.ts, which would create a cycle.
const isConditionalCheckFailure = (error: unknown): boolean =>
  error instanceof Error && error.name === "ConditionalCheckFailedException";
