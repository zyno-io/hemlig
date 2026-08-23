import type { AppConfig } from "../aws/config";
import type { Actor } from "../domain/types";
import { badRequest } from "../domain/errors";
import { isoNow, newId, stableJson } from "../util/encoding";
import type { ObjectStore } from "../repositories/object-store";

export type AuditOutcome = "attempted" | "authorized" | "succeeded" | "failed";

export interface AuditEvent {
  readonly eventId: string;
  readonly at: string;
  readonly correlationId: string;
  readonly outcome: AuditOutcome;
  readonly actor: Actor;
  readonly operation: string;
  readonly target?: Readonly<Record<string, string>>;
  readonly permission?: "read";
  readonly sourceIp?: string;
  readonly reasonCode?: string;
}

export interface AuditPage {
  readonly date: string;
  readonly events: readonly AuditEvent[];
  readonly nextContinuationToken?: string;
}

const auditPageSize = 50;
const maximumAuditEpochMilliseconds = 9_999_999_999_999;

export class AuditWriter {
  public constructor(
    private readonly objectStore: ObjectStore,
    private readonly config: AppConfig,
  ) {}

  public async write(
    event: Omit<AuditEvent, "eventId" | "at"> &
      Partial<Pick<AuditEvent, "eventId" | "at">>,
  ): Promise<AuditEvent> {
    const completed: AuditEvent = {
      ...event,
      eventId: event.eventId ?? newId(),
      at: event.at ?? isoNow(),
    };
    const key = auditObjectKey(this.config.auditPrefix, completed);
    const body = Buffer.from(stableJson(completed), "utf8");
    await this.objectStore.putImmutable(this.config.auditBucketName, key, body);
    return completed;
  }
}

/**
 * A separate archive-read component uses this service. Application handlers
 * retain write-only archive access; the returned records are the immutable
 * JSON evidence, never a mutable projection or a request body.
 */
export class AuditQueryService {
  public constructor(
    private readonly objectStore: ObjectStore,
    private readonly config: AppConfig,
  ) {}

  public async list(
    date: string,
    continuationToken?: string,
  ): Promise<AuditPage> {
    const page = await this.objectStore.listKeys(
      this.config.auditBucketName,
      auditPrefixForDate(this.config.auditPrefix, date),
      continuationToken,
      auditPageSize,
    );
    const reads = page.keys.map(async (key) =>
      this.objectStore.getJson<AuditEvent>(this.config.auditBucketName, key),
    );
    const events = await Promise.all(reads);
    return {
      date,
      // New records have reverse-chronological key prefixes. Sorting by
      // the evidence timestamp also makes a mixed legacy/new page clear.
      events: events.sort((left, right) => right.at.localeCompare(left.at)),
      ...(page.nextContinuationToken === undefined
        ? {}
        : { nextContinuationToken: page.nextContinuationToken }),
    };
  }
}

export const parseAuditDate = (
  value: string | undefined,
  now: Date = new Date(),
): string => {
  const date = value ?? now.toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw badRequest("date must use YYYY-MM-DD.");
  }
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== date
  ) {
    throw badRequest("date must be a real UTC calendar date.");
  }
  return date;
};

const auditObjectKey = (auditPrefix: string, event: AuditEvent): string => {
  const timestamp = Date.parse(event.at);
  if (
    !Number.isFinite(timestamp) ||
    timestamp > maximumAuditEpochMilliseconds
  ) {
    throw new Error("audit event timestamp is invalid.");
  }
  const date = event.at.slice(0, 10).replaceAll("-", "/");
  // S3 lists keys lexicographically. An inverted, fixed-width timestamp
  // makes every daily page newest-first without creating a mutable index.
  const order = String(maximumAuditEpochMilliseconds - timestamp).padStart(
    13,
    "0",
  );
  const prefix = auditPrefix.replace(/\/$/, "");
  return `${prefix}/${date}/${order}-${event.eventId}.json`;
};

const auditPrefixForDate = (auditPrefix: string, date: string): string =>
  `${auditPrefix.replace(/\/$/, "")}/${date.replaceAll("-", "/")}/`;
