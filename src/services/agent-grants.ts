import { randomBytes } from "node:crypto";
import { badRequest, conflict, forbidden, notFound } from "../domain/errors";
import type {
  Actor,
  AgentCapability,
  AgentGrantRecord,
  BootstrapCapabilityRecord,
  ConsumerProvisioningResult,
} from "../domain/types";
import {
  assertIdentifier,
  parseAgentCapabilities,
  parseAgentSecretIds,
} from "../domain/validation";
import type { DynamoRepository } from "../repositories/dynamo";
import { isoNow, newId, sha256Hex } from "../util/encoding";
import type { ConsumerService } from "./consumers";
import type { EnvironmentService } from "./environments";
import type { AgentNotificationService } from "./agent-notifications";

export interface CreateAgentGrantInput {
  readonly consumerId: string;
  readonly environment: string;
  readonly capabilities: unknown;
  readonly readSecretIds: unknown;
  readonly writeSecretIds: unknown;
  readonly displayName?: unknown;
  readonly actor: Actor;
}

export interface UpdateAgentGrantInput {
  readonly capabilities: unknown;
  readonly readSecretIds: unknown;
  readonly writeSecretIds: unknown;
  readonly displayName?: unknown;
}

export interface BootstrapCapabilityResult {
  readonly grantId: string;
  readonly token: string;
  readonly expiresAt: string;
}

export interface BootstrapRedemptionResult extends ConsumerProvisioningResult {
  readonly grant: Pick<
    AgentGrantRecord,
    | "grantId"
    | "consumerId"
    | "environment"
    | "capabilities"
    | "readSecretIds"
    | "readSecretUids"
    | "writeSecretIds"
    | "writeSecretUids"
  >;
}

/** Administrator-managed namespace policy and one-use enrollment capability. */
export class AgentGrantService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly consumers: ConsumerService,
    private readonly environments: EnvironmentService,
    private readonly notifications: AgentNotificationService,
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
    const readSecretIds = capabilities.includes("read")
      ? parseAgentSecretIds(input.readSecretIds, "readSecretIds")
      : emptySecretIds(input.readSecretIds, "readSecretIds");
    const writeSecretIds = capabilities.includes("write")
      ? parseAgentSecretIds(input.writeSecretIds, "writeSecretIds")
      : emptySecretIds(input.writeSecretIds, "writeSecretIds");
    const readSecretUids = await this.resolveSecretUids(
      input.environment,
      readSecretIds,
    );
    const writeSecretUids = await this.resolveSecretUids(
      input.environment,
      writeSecretIds,
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
      readSecretIds,
      readSecretUids,
      writeSecretIds,
      writeSecretUids,
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
    const capabilities = parseAgentCapabilities(input.capabilities);
    const readSecretIds = capabilities.includes("read")
      ? parseAgentSecretIds(input.readSecretIds, "readSecretIds")
      : emptySecretIds(input.readSecretIds, "readSecretIds");
    const writeSecretIds = capabilities.includes("write")
      ? parseAgentSecretIds(input.writeSecretIds, "writeSecretIds")
      : emptySecretIds(input.writeSecretIds, "writeSecretIds");
    const readSecretUids = await this.resolveSecretUids(
      existing.environment,
      readSecretIds,
    );
    const writeSecretUids = await this.resolveSecretUids(
      existing.environment,
      writeSecretIds,
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
      readSecretIds,
      readSecretUids,
      writeSecretIds,
      writeSecretUids,
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
    };
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
        readSecretIds: grant.readSecretIds,
        readSecretUids: grant.readSecretUids,
        writeSecretIds: grant.writeSecretIds,
        writeSecretUids: grant.writeSecretUids,
      },
    };
  }

  /** Resolves public IDs once, at policy write time, to immutable targets. */
  private async resolveSecretUids(
    environment: string,
    secretIds: readonly string[],
  ): Promise<readonly string[]> {
    const heads = await Promise.all(
      secretIds.map(async (secretId) =>
        this.repository.requireHead(environment, secretId),
      ),
    );
    return heads
      .map((head) => head.secretUid)
      .sort((left, right) => left.localeCompare(right));
  }
}

const emptySecretIds = (value: unknown, field: string): readonly string[] => {
  if (value === undefined) {
    return [];
  }
  if (Array.isArray(value) && value.length === 0) {
    return [];
  }
  throw badRequest(`${field} requires its matching capability.`);
};
