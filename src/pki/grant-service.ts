import { randomUUID } from "node:crypto";
import {
  preconditionFailed,
  serviceUnavailable,
} from "../domain/errors";
import type { Actor } from "../domain/types";
import type { HumanIdempotencyWrite, PkiRepository } from "../repositories/pki";
import { sha256Hex, stableJson } from "../util/encoding";
import {
  assertHumanReplay,
  caGrantContext,
  caStatusReason,
  replayOutcome,
} from "./ca-model";
import {
  caNotActive,
  grantInvalid,
  pkiBadRequest,
  pkiConflict,
  pkiNotFound,
} from "./errors";
import {
  adminGrantView,
  grantCreateDigest,
  grantDeleteDigest,
  grantUpdateDigest,
  MAX_LIVE_GRANTS_PER_CONSUMER,
  parseGrantRequest,
  resolvedQuotas,
  type GrantEnvelope,
} from "./grant-model";
import {
  policyDigest,
  validateGrantPolicy,
  type GrantIssue,
} from "./grant-policy";
import { pageWithCursor } from "./paging";
import type { GrantPolicy } from "./policy-types";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import type { CaRecord, IssuanceGrantRecord } from "./types";

const pageLimit = 100;
const maxCaRetries = 2;

type Json = Record<string, unknown>;

export interface GrantValidationResponse {
  readonly valid: boolean;
  readonly errors: GrantIssue[];
  readonly warnings: GrantIssue[];
  readonly policyDigest?: string;
}

interface Validated {
  readonly ca: CaRecord;
  readonly environment: string;
  readonly policy?: GrantPolicy;
  readonly errors: GrantIssue[];
  readonly warnings: GrantIssue[];
}

export class GrantService {
  public constructor(private readonly deps: PkiServiceDeps) {}

  private get pki(): PkiRepository {
    return this.deps.pki;
  }

  private now(): Date {
    return this.deps.now();
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------------------------

  private idempotency(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
    result: Record<string, unknown>,
  ): HumanIdempotencyWrite {
    return {
      actor,
      idempotencyKey: key,
      operationType,
      requestDigest: digest,
      result,
      now: this.now().toISOString(),
    };
  }

  private async prior(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
  ): Promise<Record<string, unknown> | undefined> {
    const stored = await this.deps.repository.getIdempotency(actor, key);
    if (stored === undefined) {
      return undefined;
    }
    assertHumanReplay(stored, operationType, digest);
    return stored;
  }

  private auditTarget(
    grant: IssuanceGrantRecord,
    extra: Record<string, string> = {},
  ): Record<string, string> {
    return {
      consumerId: grant.consumerId,
      environment: grant.environment,
      caId: grant.caId,
      issuanceGrant: grant.name,
      issuanceGrantUid: grant.uid,
      policyDigest: grant.policyDigest,
      version: grant.version,
      status: grant.status,
      ...extra,
    };
  }

  private success(
    grant: IssuanceGrantRecord,
    status: number,
    warnings: GrantIssue[] = [],
    extra: Record<string, string> = {},
    terminalAudit = true,
  ): MutationResult {
    return {
      body: {
        ...adminGrantView(grant, this.now()),
        ...(warnings.length === 0 ? {} : { warnings }),
      },
      status,
      shouldWriteTerminalAudit: terminalAudit,
      auditTarget: this.auditTarget(grant, extra),
      etag: grant.version,
    };
  }

  /** A replayed request returns the current resource. */
  private async replayResult(
    stored: Record<string, unknown>,
    status: number,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const { consumerId, name } = outcome.result;
    if (typeof consumerId !== "string" || typeof name !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    // A mutation records the generation it wrote. The name may since have been changed, deleted or
    // recreated by someone else, so the response comes from that record, never from a read-back by name.
    const recorded = outcome.result.record ?? outcome.result.deleted;
    if (
      typeof recorded === "object" &&
      recorded !== null &&
      (recorded as { uid?: unknown }).uid === outcome.result.uid
    ) {
      return this.success(
        recorded as IssuanceGrantRecord,
        status,
        [],
        {},
        outcome.shouldWriteTerminalAudit,
      );
    }
    // A receipt that predates the record: read by name. A delete must find its tombstone, since a live
    // grant is a different generation (or a stale read) and must not be returned as the result.
    const grant = await this.pki.getGrant(consumerId, name);
    if (grant === undefined) {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    if (stored.operationType === "pki.grant.delete" && grant.status !== "DELETED") {
      throw serviceUnavailable("The deletion could not be confirmed.");
    }
    return this.success(grant, status, [], {}, outcome.shouldWriteTerminalAudit);
  }

  private async replayAfterCancel(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
    status: number,
  ): Promise<MutationResult> {
    const stored = await this.prior(actor, key, operationType, digest);
    if (stored === undefined) {
      throw serviceUnavailable("The change could not be confirmed.");
    }
    return this.replayResult(stored, status);
  }

  /** The consumer's environment: an agent's grant, else the ACTIVE consumer. */
  private async consumerEnvironment(consumerId: string): Promise<string> {
    const grantId =
      await this.deps.repository.getAgentGrantIdForConsumer(consumerId);
    if (grantId !== undefined) {
      const grant = await this.deps.repository.getAgentGrant(grantId);
      if (grant === undefined) {
        throw serviceUnavailable("The agent grant record is missing.");
      }
      return grant.environment;
    }
    const consumer = await this.deps.repository.getConsumer(consumerId);
    if (consumer === undefined) {
      throw pkiNotFound("consumer_not_found");
    }
    if (consumer.status !== "ACTIVE") {
      throw pkiConflict("consumer_not_active");
    }
    return consumer.environment;
  }

  private async validateFor(
    consumerId: string,
    caId: string,
    policyFields: Json,
  ): Promise<Validated> {
    const environment = await this.consumerEnvironment(consumerId);
    const ca = await this.pki.getCa(caId);
    if (ca === undefined) {
      throw pkiNotFound("ca_not_found");
    }
    if (ca.status !== "ACTIVE") {
      throw caNotActive(caStatusReason[ca.status]);
    }
    if (!ca.policy.issueLeaves) {
      throw caNotActive("leaves_not_permitted");
    }
    if (ca.environment !== environment) {
      throw pkiBadRequest(
        "environment_mismatch",
        "The CA and the consumer are in different environments.",
      );
    }
    const result = validateGrantPolicy(policyFields, {
      ca: caGrantContext(ca),
    });
    const warnings = [...result.warnings];
    if (result.policy !== undefined) {
      const { perHour } = resolvedQuotas(result.policy);
      if (perHour > ca.policy.issuancePerHour) {
        warnings.push({
          code: "quota_exceeds_ca_rate",
          path: "policy.quotas.perHour",
          message: `The grant's hourly quota exceeds the CA's issuance rate of ${ca.policy.issuancePerHour} per hour.`,
        });
      }
    }
    return {
      ca,
      environment,
      ...(result.policy === undefined ? {} : { policy: result.policy }),
      errors: result.errors,
      warnings,
    };
  }

  private validated(v: Validated): GrantPolicy {
    if (v.errors.length > 0 || v.policy === undefined) {
      throw grantInvalid(
        v.errors[0] ?? {
          code: "invalid_policy",
          path: "policy",
          message: "The policy is invalid.",
        },
        v.errors.length,
      );
    }
    return v.policy;
  }

  private validationResponse(v: Validated): GrantValidationResponse {
    return {
      valid: v.errors.length === 0,
      errors: v.errors,
      warnings: v.warnings,
      ...(v.errors.length === 0 && v.policy !== undefined
        ? { policyDigest: policyDigest(v.policy) }
        : {}),
    };
  }

  private async load(
    consumerId: string,
    name: string,
  ): Promise<IssuanceGrantRecord> {
    const grant = await this.pki.getGrant(consumerId, name);
    if (grant === undefined || grant.status === "DELETED") {
      throw pkiNotFound("grant_not_found");
    }
    return grant;
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Reads
  // -----------------------------------------------------------------------------------------------------------------

  /** Tombstones are returned too. */
  public async get(
    consumerId: string,
    name: string,
  ): Promise<{ body: Json; etag: string }> {
    const grant = await this.pki.getGrant(consumerId, name);
    if (grant === undefined) {
      throw pkiNotFound("grant_not_found");
    }
    return { body: adminGrantView(grant, this.now()), etag: grant.version };
  }

  public async listForConsumer(
    actor: Actor,
    consumerId: string,
    options: { includeDeleted: boolean; cursor?: string },
  ): Promise<Json> {
    const scope = `admin:pki:grants:${actor.id}:${sha256Hex(
      stableJson({ consumerId, includeDeleted: options.includeDeleted }),
    )}`;
    const page = await pageWithCursor(this.deps, scope, options.cursor, async (start) => {
      const result = await this.pki.listGrantsPage(consumerId, {
        includeDeleted: options.includeDeleted,
        limit: pageLimit,
        ...(start === undefined ? {} : { start }),
      });
      return {
        items: result.grants,
        ...(result.lastEvaluatedKey === undefined
          ? {}
          : { lastEvaluatedKey: result.lastEvaluatedKey }),
      };
    });
    return {
      grants: page.items.map((grant) => adminGrantView(grant, this.now())),
      ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
      generatedAt: this.now().toISOString(),
    };
  }

  public async listForCa(
    actor: Actor,
    caId: string,
    cursor: string | undefined,
  ): Promise<Json> {
    const scope = `admin:pki:ca-grants:${actor.id}:${caId}`;
    const page = await pageWithCursor(this.deps, scope, cursor, async (start) => {
      const result = await this.pki.listGrantsByCaPage(caId, {
        limit: pageLimit,
        ...(start === undefined ? {} : { start }),
      });
      return {
        items: result.grants,
        ...(result.lastEvaluatedKey === undefined
          ? {}
          : { lastEvaluatedKey: result.lastEvaluatedKey }),
      };
    });
    return {
      grants: page.items.map((grant) => adminGrantView(grant, this.now())),
      ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
      generatedAt: this.now().toISOString(),
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Create
  // -----------------------------------------------------------------------------------------------------------------

  /** `?validateOnly=true`: no idempotency key, no write. */
  public async validateCreate(
    consumerId: string,
    body: unknown,
  ): Promise<GrantValidationResponse> {
    const { envelope, policyFields } = parseGrantRequest(
      body,
      "create",
      this.now(),
    );
    return this.validationResponse(
      await this.validateFor(consumerId, envelope.caId, policyFields),
    );
  }

  public async create(
    actor: Actor,
    key: string,
    consumerId: string,
    body: unknown,
  ): Promise<MutationResult> {
    // A committed request replays before the future-expiry rule can reject its identical retry.
    const digest = grantCreateDigest(consumerId, body);
    const stored = await this.prior(actor, key, "pki.grant.create", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 201);
    }
    const { envelope, policyFields } = parseGrantRequest(
      body,
      "create",
      this.now(),
    );
    const name = envelope.name as string;
    for (let attempt = 0; attempt < maxCaRetries; attempt += 1) {
      const v = await this.validateFor(consumerId, envelope.caId, policyFields);
      const policy = this.validated(v);
      if (attempt === 0) {
        if (
          (await this.pki.countLiveGrants(consumerId)) >=
          MAX_LIVE_GRANTS_PER_CONSUMER
        ) {
          throw pkiConflict("grant_limit_reached");
        }
      }
      const now = this.now().toISOString();
      const grant: IssuanceGrantRecord = {
        uid: `pkg-${randomUUID()}`,
        consumerId,
        environment: v.environment,
        name,
        caId: envelope.caId,
        status: envelope.status ?? "ACTIVE",
        ...(envelope.displayName === undefined
          ? {}
          : { displayName: envelope.displayName }),
        policy,
        policyDigest: policyDigest(policy),
        version: `pkv-${randomUUID()}`,
        ...(envelope.expiresAt === undefined
          ? {}
          : { expiresAt: envelope.expiresAt }),
        createdAt: now,
        createdBy: actor,
        updatedAt: now,
        updatedBy: actor,
      };
      const outcome = await this.pki.createGrant({
        idempotency: this.idempotency(actor, key, "pki.grant.create", digest, {
          consumerId,
          name,
          uid: grant.uid,
          record: grant,
        }),
        grant,
        caVersion: v.ca.version,
      });
      switch (outcome.kind) {
        case "replay":
          return this.replayAfterCancel(
            actor,
            key,
            "pki.grant.create",
            digest,
            201,
          );
        case "exists": {
          const winner = await this.prior(actor, key, "pki.grant.create", digest);
          if (winner !== undefined) {
            return this.replayResult(winner, 201);
          }
          throw pkiConflict("grant_exists");
        }
        case "caChanged":
          continue;
        case "created":
          return this.success(grant, 201, v.warnings);
      }
    }
    await this.caChangedError(envelope.caId);
    throw serviceUnavailable("The grant could not be created.");
  }

  /** After the retry budget: report the CA's state, or ask for a retry when it is ACTIVE again. */
  private async caChangedError(caId: string): Promise<void> {
    const ca = await this.pki.getCa(caId);
    if (ca === undefined) {
      throw pkiNotFound("ca_not_found");
    }
    if (ca.status !== "ACTIVE") {
      throw caNotActive(caStatusReason[ca.status]);
    }
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Update
  // -----------------------------------------------------------------------------------------------------------------

  /** `?validateOnly=true`: `If-Match` is still required; nothing is written and no key is needed. */
  public async validateUpdate(
    consumerId: string,
    name: string,
    ifMatch: string,
    body: unknown,
  ): Promise<GrantValidationResponse> {
    const { envelope, policyFields } = parseGrantRequest(
      body,
      "update",
      this.now(),
      name,
    );
    const current = await this.load(consumerId, name);
    if (current.version !== ifMatch) {
      throw preconditionFailed("The grant was changed; reload it and retry.");
    }
    return this.validationResponse(
      await this.validateFor(consumerId, envelope.caId, policyFields),
    );
  }

  public async update(
    actor: Actor,
    key: string,
    consumerId: string,
    name: string,
    ifMatch: string,
    body: unknown,
  ): Promise<MutationResult> {
    const digest = grantUpdateDigest(consumerId, name, ifMatch, body);
    const stored = await this.prior(actor, key, "pki.grant.update", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 200);
    }
    const { envelope, policyFields } = parseGrantRequest(
      body,
      "update",
      this.now(),
      name,
    );
    for (let attempt = 0; attempt < maxCaRetries; attempt += 1) {
      const current = await this.load(consumerId, name);
      if (current.version !== ifMatch) {
        throw preconditionFailed("The grant was changed; reload it and retry.");
      }
      const v = await this.validateFor(consumerId, envelope.caId, policyFields);
      const policy = this.validated(v);
      const next = this.nextRecord(current, envelope, policy, actor);
      const outcome = await this.pki.updateGrant({
        idempotency: this.idempotency(actor, key, "pki.grant.update", digest, {
          consumerId,
          name,
          uid: next.uid,
          record: next,
        }),
        grant: next,
        ifMatch,
        caVersion: v.ca.version,
      });
      switch (outcome.kind) {
        case "replay":
          return this.replayAfterCancel(
            actor,
            key,
            "pki.grant.update",
            digest,
            200,
          );
        case "stale": {
          const fresh = await this.pki.getGrant(consumerId, name);
          if (
            fresh === undefined ||
            fresh.status === "DELETED" ||
            fresh.version !== ifMatch
          ) {
            if (fresh === undefined || fresh.status === "DELETED") {
              throw pkiNotFound("grant_not_found");
            }
            throw preconditionFailed(
              "The grant was changed; reload it and retry.",
            );
          }
          throw serviceUnavailable("The grant could not be updated.");
        }
        case "caChanged":
          continue;
        case "updated":
          return this.success(
            next,
            200,
            v.warnings,
            current.caId === next.caId ? {} : { previousCaId: current.caId },
          );
      }
    }
    await this.caChangedError(envelope.caId);
    throw serviceUnavailable("The grant could not be updated.");
  }

  private nextRecord(
    current: IssuanceGrantRecord,
    envelope: GrantEnvelope,
    policy: GrantPolicy,
    actor: Actor,
  ): IssuanceGrantRecord {
    return {
      uid: current.uid,
      consumerId: current.consumerId,
      environment: current.environment,
      name: current.name,
      caId: envelope.caId,
      status: envelope.status ?? current.status,
      ...(envelope.displayName === undefined
        ? {}
        : { displayName: envelope.displayName }),
      policy,
      policyDigest: policyDigest(policy),
      version: `pkv-${randomUUID()}`,
      ...(envelope.expiresAt === undefined
        ? {}
        : { expiresAt: envelope.expiresAt }),
      createdAt: current.createdAt,
      createdBy: current.createdBy,
      updatedAt: this.now().toISOString(),
      updatedBy: actor,
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Delete
  // -----------------------------------------------------------------------------------------------------------------

  public async delete(
    actor: Actor,
    key: string,
    consumerId: string,
    name: string,
    ifMatch: string,
  ): Promise<MutationResult> {
    const digest = grantDeleteDigest(consumerId, name, ifMatch);
    const stored = await this.prior(actor, key, "pki.grant.delete", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 200);
    }
    const current = await this.load(consumerId, name);
    if (current.version !== ifMatch) {
      throw preconditionFailed("The grant was changed; reload it and retry.");
    }
    const now = this.now().toISOString();
    const newVersion = `pkv-${randomUUID()}`;
    // Exactly what the transaction writes to the tombstone.
    const deleted: IssuanceGrantRecord = {
      ...current,
      status: "DELETED",
      version: newVersion,
      deletedAt: now,
      deletedBy: actor,
      updatedAt: now,
      updatedBy: actor,
    };
    const outcome = await this.pki.deleteGrant({
      idempotency: this.idempotency(actor, key, "pki.grant.delete", digest, {
        consumerId,
        name,
        uid: current.uid,
        record: deleted,
      }),
      consumerId,
      name,
      ifMatch,
      newVersion,
      now,
      actor,
    });
    if (outcome.kind === "replay") {
      return this.replayAfterCancel(actor, key, "pki.grant.delete", digest, 200);
    }
    if (outcome.kind === "stale") {
      const fresh = await this.pki.getGrant(consumerId, name);
      if (fresh === undefined || fresh.status === "DELETED") {
        throw pkiNotFound("grant_not_found");
      }
      if (fresh.version !== ifMatch) {
        throw preconditionFailed("The grant was changed; reload it and retry.");
      }
      throw serviceUnavailable("The grant could not be deleted.");
    }
    return this.success(deleted, 200);
  }
}
