import { randomBytes } from "node:crypto";
import { badRequest, serviceUnavailable } from "../domain/errors";

export interface CursorPayload {
  readonly scope: string;
  readonly lastEvaluatedKey?: Record<string, string>;
  readonly expiresAt: string;
}

export interface StoredCursor extends CursorPayload {
  readonly token: string;
  readonly ttl: number;
}

export interface CursorStore {
  createCursor(cursor: StoredCursor): Promise<boolean>;
  getCursor(token: string): Promise<StoredCursor | undefined>;
}

const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

/**
 * Opaque, bounded pagination state. Unlike a signed self-contained cursor,
 * this keeps the DynamoDB exclusive-start key server-side, so the service does
 * not need a separate HMAC secret or a second key-management path.
 */
export class CursorService {
  public constructor(private readonly store: CursorStore) {}

  public async encode(payload: CursorPayload): Promise<string> {
    const expiresAtMillis = new Date(payload.expiresAt).getTime();
    if (!Number.isFinite(expiresAtMillis)) {
      throw new Error("Cursor expiration must be a valid timestamp.");
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const token = randomBytes(32).toString("base64url");
      const created = await this.store.createCursor({
        ...payload,
        token,
        ttl: Math.ceil(expiresAtMillis / 1_000),
      });
      if (created) {
        return token;
      }
    }
    throw serviceUnavailable("Could not allocate pagination state.");
  }

  public async decode(
    cursor: string,
    scope: string,
    now: Date = new Date(),
  ): Promise<CursorPayload> {
    if (!tokenPattern.test(cursor)) {
      throw badRequest("cursor is malformed.");
    }
    const stored = await this.store.getCursor(cursor);
    if (
      stored === undefined ||
      stored.scope !== scope ||
      new Date(stored.expiresAt).getTime() <= now.getTime()
    ) {
      throw badRequest("cursor is no longer valid for this scope.");
    }
    return {
      scope: stored.scope,
      ...(stored.lastEvaluatedKey === undefined
        ? {}
        : { lastEvaluatedKey: stored.lastEvaluatedKey }),
      expiresAt: stored.expiresAt,
    };
  }
}
