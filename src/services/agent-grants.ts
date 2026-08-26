import { randomBytes } from "node:crypto";
import { badRequest, conflict, forbidden, notFound } from "../domain/errors";
import type {
  Actor,
  AgentCapability,
  AgentGrantRecord,
  AgentSecretGrant,
  BootstrapCapabilityRecord,
  ConsumerProvisioningResult,
} from "../domain/types";
import {
  assertIdentifier,
  assertSecretIdentifier,
  parseAgentCapabilities,
} from "../domain/validation";
import type { DynamoRepository } from "../repositories/dynamo";
import { isoNow, newId, sha256Hex } from "../util/encoding";
import type { ConsumerService } from "./consumers";
import type { EnvironmentService } from "./environments";
import type { AgentNotificationService } from "./agent-notifications";
import type { SecretService } from "./secrets";

export interface CreateAgentGrantInput {
  readonly consumerId: string;
  readonly environment: string;
  readonly capabilities: unknown;
  /** Canonical request form; UIDs are resolved server-side. */
  readonly secretGrants: unknown;
  readonly displayName?: unknown;
  readonly actor: Actor;
}

export interface UpdateAgentGrantInput {
  readonly capabilities: unknown;
  readonly secretGrants: unknown;
  readonly displayName?: unknown;
  readonly actor: Actor;
}

export interface BootstrapCapabilityResult {
  readonly grantId: string;
  readonly token: string;
  readonly expiresAt: string;
}

export interface BootstrapRedemptionResult extends ConsumerProvisioningResult {
  readonly grant: Pick<
    AgentGrantRecord,
    "grantId" | "consumerId" | "environment" | "capabilities" | "secretGrants"
  >;
}

/** Administrator-managed namespace policy and one-use enrollment capability. */
export class AgentGrantService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly consumers: ConsumerService,
    private readonly environments: EnvironmentService,
    private readonly notifications: AgentNotificationService,
    private readonly secrets: SecretService,
  ) {}

  public async create(input: CreateAgentGrantInput): Promise<AgentGrantRecord> {
    assertIdentifier(input.consumerId, "consumerId");
    await this.environments.require(input.environment);
    if ((await this.repository.getConsumer(input.consumerId)) !== undefined) {
      throw conflict(
        "An agent grant requires a consumer ID that has not been enrolled.",
      );
    }
    const capabilities = parseAgentCapabilities(input.capabilities);
    const secretGrants = await this.resolveSecretGrants(
      input.environment,
      parseSecretGrants(input.secretGrants, capabilities, false),
    );
    if (
      input.displayName !== undefined &&
      (typeof input.displayName !== "string" ||
        input.displayName.length === 0 ||
        input.displayName.length > 256)
    ) {
      throw badRequest(
        "displayName must be a non-empty string of at most 256 characters.",
      );
    }
    const grantId = `grant-${newId()}`;
    const grant: AgentGrantRecord = {
      pk: `AGENT_GRANT#${grantId}`,
      sk: "PROFILE",
      grantId,
      consumerId: input.consumerId,
      environment: input.environment,
      capabilities,
      secretGrants,
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
      status: "PENDING",
      createdAt: isoNow(),
      createdBy: input.actor,
    };
    await this.repository.createAgentGrant(grant);
    return grant;
  }

  /** Updates only the remote policy; the consumer ID, identity, and grant ID stay stable. */
  public async update(
    grantId: string,
    input: UpdateAgentGrantInput,
  ): Promise<AgentGrantRecord> {
    const existing = await this.repository.getAgentGrant(grantId);
    if (existing === undefined) {
      throw notFound("The requested agent grant was not found.");
    }
    const capabilities = parseAgentCapabilities(input.capabilities, true);
    const secretGrants = await this.resolveSecretGrants(
      existing.environment,
      parseSecretGrants(input.secretGrants, capabilities, true),
    );
    if (
      input.displayName !== undefined &&
      (typeof input.displayName !== "string" ||
        input.displayName.length === 0 ||
        input.displayName.length > 256)
    ) {
      throw badRequest(
        "displayName must be a non-empty string of at most 256 characters.",
      );
    }
    const updated: AgentGrantRecord = {
      ...existing,
      capabilities,
      secretGrants,
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
    };
    if (existing.status === "ACTIVE") {
      await this.reconcileReadAccess(updated, input.actor);
    }
    await this.repository.updateAgentGrant(
      updated,
      input.displayName === undefined,
    );
    return updated;
  }

  public async issueBootstrapCapability(
    grantId: string,
    actor: Actor,
  ): Promise<BootstrapCapabilityResult> {
    const grant = await this.repository.getAgentGrant(grantId);
    if (grant === undefined) {
      throw notFound("The requested agent grant was not found.");
    }
    if (grant.status !== "PENDING") {
      throw conflict(
        "A bootstrap capability may only be issued for a pending grant.",
      );
    }
    const token = `hmlb_${randomBytes(32).toString("base64url")}`;
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const capability: BootstrapCapabilityRecord = {
      pk: `BOOTSTRAP#${sha256Hex(token)}`,
      sk: "STATE",
      tokenHash: sha256Hex(token),
      grantId,
      expiresAt,
      ttl: Math.floor(new Date(expiresAt).getTime() / 1000),
      status: "PENDING",
      createdAt: isoNow(),
      createdBy: actor,
    };
    await this.repository.createBootstrapCapability(capability);
    return { grantId, token, expiresAt };
  }

  public async redeem(
    token: string,
    apiCertificateSigningRequestPem: string,
  ): Promise<BootstrapRedemptionResult> {
    const tokenHash = sha256Hex(token);
    const capability = await this.repository.getBootstrapCapability(tokenHash);
    if (capability === undefined) {
      throw forbidden(
        "The bootstrap capability is invalid, expired, or already consumed.",
      );
    }
    if (
      capability.status === "PENDING" &&
      new Date(capability.expiresAt).getTime() <= Date.now()
    ) {
      throw forbidden(
        "The bootstrap capability is invalid, expired, or already consumed.",
      );
    }
    const grant = await this.repository.getAgentGrant(capability.grantId);
    if (grant === undefined) {
      throw forbidden("The bootstrap capability does not name an agent grant.");
    }
    if (capability.status === "CONSUMED" && grant.status !== "ACTIVE") {
      throw forbidden(
        "The bootstrap capability does not name an active agent grant.",
      );
    }
    if (capability.status !== "PENDING" && capability.status !== "CONSUMED") {
      throw forbidden("The bootstrap capability is invalid.");
    }
    const actor: Actor = {
      type: "system",
      id: `bootstrap:${grant.grantId}`,
      consumerId: grant.consumerId,
      environment: grant.environment,
    };
    const recovered = await this.consumers.recoverActiveIdentity({
      consumerId: grant.consumerId,
      environment: grant.environment,
      apiCertificateSigningRequestPem,
    });
    const enrollment =
      recovered === undefined
        ? await this.consumers.enroll({
            consumerId: grant.consumerId,
            environment: grant.environment,
            apiCertificateSigningRequestPem,
            actor,
            idempotencyKey: `redeem-${tokenHash}`,
          })
        : { result: recovered, shouldWriteTerminalAudit: true };
    if (
      capability.status === "CONSUMED" &&
      capability.consumedFingerprint !== enrollment.result.apiFingerprint
    ) {
      throw forbidden(
        "The bootstrap capability does not match this certificate request.",
      );
    }
    await this.notifications.provision({
      consumerId: grant.consumerId,
      certificateFingerprint: enrollment.result.apiFingerprint,
      certificatePem: enrollment.result.apiCertificatePem,
    });
    await this.reconcileReadAccess(grant, actor);
    await this.repository.activateAgentGrant(
      grant.grantId,
      enrollment.result.apiFingerprint,
    );
    if (capability.status === "PENDING") {
      await this.repository.consumeBootstrapCapability(
        tokenHash,
        enrollment.result.apiFingerprint,
      );
    }
    return {
      ...enrollment.result,
      grant: {
        grantId: grant.grantId,
        consumerId: grant.consumerId,
        environment: grant.environment,
        capabilities: grant.capabilities,
        secretGrants: grant.secretGrants,
      },
    };
  }

  /** Repairs the derived ACL/index projection after a migration or retry. */
  public async reconcileActiveGrant(
    grantId: string,
    actor: Actor,
  ): Promise<void> {
    const grant = await this.repository.getAgentGrant(grantId);
    if (grant === undefined) {
      throw notFound("The requested agent grant was not found.");
    }
    if (grant.status !== "ACTIVE") {
      return;
    }
    await this.reconcileReadAccess(grant, actor);
  }

  /** Resolves public IDs once, at policy write time, to immutable targets. */
  private async resolveSecretGrants(
    environment: string,
    grants: readonly ParsedSecretGrant[],
  ): Promise<readonly AgentSecretGrant[]> {
    const heads = await Promise.all(
      grants.map(async (grant) =>
        this.repository.requireHead(environment, grant.secretId),
      ),
    );
    return grants.map((grant, index) => {
      const head = heads[index];
      if (head === undefined) {
        throw new Error("A requested secret head was not resolved.");
      }
      return {
        secretId: grant.secretId,
        secretUid: head.secretUid,
        permissions: grant.permissions,
      };
    });
  }

  private async reconcileReadAccess(
    grant: AgentGrantRecord,
    actor: Actor,
  ): Promise<void> {
    await this.secrets.reconcileAgentReadAccess({
      consumerId: grant.consumerId,
      environment: grant.environment,
      secretGrants: grant.secretGrants,
      actor,
    });
  }
}

interface ParsedSecretGrant {
  readonly secretId: string;
  readonly permissions: readonly AgentCapability[];
}

/**
 * A consumer's policy is an exact allow-list. Keep this comfortably above
 * realistic cluster needs without permitting an unbounded request payload.
 */
export const MAX_AGENT_SECRET_GRANTS = 1_000;

const parseSecretGrants = (
  value: unknown,
  capabilities: readonly AgentCapability[],
  allowEmpty: boolean,
): readonly ParsedSecretGrant[] => {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > MAX_AGENT_SECRET_GRANTS
  ) {
    throw badRequest(
      `secretGrants must contain between one and ${MAX_AGENT_SECRET_GRANTS} grants.`,
    );
  }
  const grants = value.map((entry): ParsedSecretGrant => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw badRequest("Each secret grant must be an object.");
    }
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.secretId !== "string") {
      throw badRequest("Each secret grant must name a secretId.");
    }
    assertSecretIdentifier(candidate.secretId, "secretGrants.secretId");
    const permissions = parseAgentCapabilities(candidate.permissions);
    if (permissions.some((permission) => !capabilities.includes(permission))) {
      throw badRequest(
        "Every secret grant permission must be an agent capability.",
      );
    }
    return { secretId: candidate.secretId, permissions };
  });
  if (new Set(grants.map((grant) => grant.secretId)).size !== grants.length) {
    throw badRequest("secretGrants must not contain duplicate secret IDs.");
  }
  for (const capability of capabilities) {
    if (!grants.some((grant) => grant.permissions.includes(capability))) {
      throw badRequest(
        `secretGrants must include at least one ${capability} permission.`,
      );
    }
  }
  return [...grants].sort((left, right) =>
    left.secretId.localeCompare(right.secretId),
  );
};
