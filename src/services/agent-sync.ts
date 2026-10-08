import { createHash } from "node:crypto";
import type { AppConfig } from "../aws/config";
import { ApiError, badRequest, forbidden } from "../domain/errors";
import type {
  AgentGrantRecord,
  AgentSyncEntry,
  AgentSyncPage,
} from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import {
  syncCheckpointLifetime,
  type AgentSyncRecord,
} from "../repositories/agent-sync";
import type { CursorService } from "./cursor";

interface Position {
  readonly kind: "checkpoint" | "page";
  readonly epoch: string;
  readonly digest: string;
  readonly after: number;
  readonly through: number;
  readonly snapshot: boolean;
  readonly checkpointExpiresAt: string;
  readonly pageExpiresAt: string;
  readonly lastSk?: string;
}

export class AgentSyncService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly cursors: CursorService,
    private readonly config: AppConfig,
  ) {}

  public async sync(
    consumerId: string,
    environment: string,
    query: {
      readonly syncCursor?: string;
      readonly cursor?: string;
    },
    grant: AgentGrantRecord | undefined,
  ): Promise<AgentSyncPage> {
    if (
      grant?.status !== "ACTIVE" ||
      grant.consumerId !== consumerId ||
      grant.environment !== environment ||
      !Array.isArray(grant.secretGrants)
    ) {
      throw forbidden(
        "An active UID-scoped agent grant is required for synchronization.",
      );
    }
    if (query.syncCursor !== undefined && query.cursor !== undefined)
      throw badRequest("Pass either syncCursor or cursor.");
    const scope = `agent-sync:${environment}:${consumerId}`;
    const digest = grantDigest(grant);
    const state = await this.repository.agentSync.state(environment);
    if (state?.ready !== true)
      throw new ApiError(
        503,
        "sync_index_not_ready",
        "The agent sync index needs a completed backfill.",
      );
    const token = query.cursor ?? query.syncCursor;
    const deadlines = {
      checkpointExpiresAt: new Date(
        Date.now() + syncCheckpointLifetime,
      ).toISOString(),
      pageExpiresAt: new Date(Date.now() + 15 * 60 * 1_000).toISOString(),
    };
    let position: Position = {
      kind: "page",
      epoch: state.epoch,
      digest,
      after: 0,
      through: state.sequence,
      snapshot: true,
      ...deadlines,
    };
    if (token !== undefined) {
      position = await this.decode(token, scope);
      if (
        position.epoch !== state.epoch ||
        position.digest !== digest ||
        position.through > state.sequence
      )
        throw resetRequired();
      if (query.cursor !== undefined) {
        if (position.kind !== "page")
          throw badRequest("cursor must be a page continuation.");
      } else {
        if (position.kind !== "checkpoint")
          throw badRequest("syncCursor must be a completed checkpoint.");
        position = {
          ...position,
          ...deadlines,
          after: position.through,
          through: state.sequence,
          snapshot: false,
          lastSk: undefined,
        };
      }
    }
    const page = await this.repository.agentSync.page(
      environment,
      position.after,
      position.through,
      position.lastSk,
    );
    const secretGrants = new Map(
      grant.secretGrants.map((entry) => [entry.secretUid, entry]),
    );
    const changes = page.records.flatMap((record): AgentSyncEntry[] => {
      const selected = secretGrants.get(record.secretUid);
      if (selected === undefined || selected.secretId !== record.secretId)
        return [];
      return [visibleEntry(record, grant, selected.permissions)];
    });
    const nextCursor =
      page.lastSk === undefined
        ? undefined
        : await this.encode(scope, {
            ...position,
            kind: "page",
            lastSk: page.lastSk,
          });
    const syncCursor =
      nextCursor !== undefined
        ? undefined
        : query.syncCursor !== undefined && position.after === position.through
          ? query.syncCursor
          : await this.encode(scope, {
              ...position,
              kind: "checkpoint",
              after: position.through,
              lastSk: undefined,
            });
    return {
      config: {
        consumerId,
        environment,
        grant: {
          grantId: grant.grantId,
          capabilities: grant.capabilities,
          secretGrants: grant.secretGrants,
        },
        mqtt: {
          endpoint: this.config.iotEndpoint,
          clientId: consumerId,
          topic: `${this.config.iotNotificationTopicPrefix}/${consumerId}`,
        },
      },
      snapshot: position.snapshot,
      changes,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      ...(syncCursor === undefined ? {} : { syncCursor }),
    };
  }

  private async decode(token: string, scope: string): Promise<Position> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token))
      throw badRequest("The sync cursor is malformed.");
    const stored = await this.repository.getCursor(token);
    if (stored === undefined) throw resetRequired();
    if (stored.scope !== scope)
      throw badRequest("The sync cursor belongs to another scope.");
    if (new Date(stored.expiresAt).getTime() <= Date.now())
      throw resetRequired();
    const value = stored.lastEvaluatedKey;
    if (
      value === undefined ||
      (value.kind !== "checkpoint" && value.kind !== "page") ||
      value.epoch === undefined ||
      value.digest === undefined
    )
      throw badRequest("The sync cursor is not a synchronization position.");
    const after = Number(value.after);
    const through = Number(value.through);
    if (
      !Number.isSafeInteger(after) ||
      !Number.isSafeInteger(through) ||
      after < 0 ||
      after > through ||
      (value.snapshot !== "true" && value.snapshot !== "false")
    )
      throw badRequest("The sync cursor position is invalid.");
    if (
      value.checkpointExpiresAt === undefined ||
      value.pageExpiresAt === undefined ||
      !Number.isFinite(Date.parse(value.checkpointExpiresAt)) ||
      !Number.isFinite(Date.parse(value.pageExpiresAt))
    )
      throw badRequest("The sync cursor deadline is invalid.");
    return {
      kind: value.kind,
      epoch: value.epoch,
      digest: value.digest,
      after,
      through,
      snapshot: value.snapshot === "true",
      lastSk: value.lastSk,
      checkpointExpiresAt: value.checkpointExpiresAt,
      pageExpiresAt: value.pageExpiresAt,
    };
  }

  private async encode(scope: string, position: Position): Promise<string> {
    return this.cursors.encode({
      scope,
      lastEvaluatedKey: {
        kind: position.kind,
        epoch: position.epoch,
        digest: position.digest,
        after: String(position.after),
        through: String(position.through),
        snapshot: String(position.snapshot),
        checkpointExpiresAt: position.checkpointExpiresAt,
        pageExpiresAt: position.pageExpiresAt,
        ...(position.lastSk === undefined ? {} : { lastSk: position.lastSk }),
      },
      expiresAt:
        position.kind === "page"
          ? position.pageExpiresAt
          : position.checkpointExpiresAt,
    });
  }
}

const visibleEntry = (
  record: AgentSyncRecord,
  grant: AgentGrantRecord,
  selected: readonly ("read" | "write")[],
): AgentSyncEntry => {
  const live = record.state === "ACTIVE" || record.state === "PENDING_VALUE";
  const write =
    live && grant.capabilities.includes("write") && selected.includes("write");
  const read =
    live &&
    grant.capabilities.includes("read") &&
    selected.includes("read") &&
    record.readConsumerIds.includes(grant.consumerId);
  return {
    secretUid: record.secretUid,
    secretId: record.secretId,
    controlVersionId: record.controlVersionId,
    state:
      read || write ? (record.state as "ACTIVE" | "PENDING_VALUE") : "REVOKED",
    permissions: [
      ...(read ? ["read" as const] : []),
      ...(write ? ["write" as const] : []),
    ],
    ...((read || write) && record.payloadVersionId !== undefined
      ? { payloadVersionId: record.payloadVersionId }
      : {}),
    ...(write ? { metadata: record.metadata } : {}),
  };
};

const grantDigest = (grant: AgentGrantRecord): string =>
  createHash("sha256")
    .update(
      JSON.stringify({
        grantId: grant.grantId,
        capabilities: [...grant.capabilities].sort(),
        secretGrants: grant.secretGrants
          .map((entry) => ({
            secretUid: entry.secretUid,
            secretId: entry.secretId,
            permissions: [...entry.permissions].sort(),
          }))
          .sort((left, right) => left.secretUid.localeCompare(right.secretUid)),
      }),
    )
    .digest("hex");

const resetRequired = (): ApiError =>
  new ApiError(
    410,
    "sync_reset_required",
    "Start a fresh agent sync snapshot.",
  );
