import { forbidden } from "../domain/errors";
import type {
  AccessRecord,
  AgentCapability,
  AgentGrantRecord,
  Actor,
  ControlRevision,
  SecretMetadata,
  SecretPayload,
} from "../domain/types";
import { pathIsWithinPrefixes } from "../domain/validation";
import type { DynamoRepository } from "../repositories/dynamo";
import type { SecretReadResult, SecretService } from "./secrets";

export interface AgentSecretWriteInput {
  readonly consumerId: string;
  readonly environment: string;
  readonly secretId: string;
  readonly expectedControlVersionId?: string;
  readonly metadata?: SecretMetadata;
  readonly payload?: SecretPayload;
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

/**
 * Performs the remote authorization that a Kubernetes namespace cannot enforce
 * by itself. An AgentGrant is required in addition to the ordinary per-secret
 * ACL, and the prefix check happens before decryption or mutation.
 */
export class AgentService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly secrets: SecretService,
  ) {}

  public async config(
    consumerId: string,
    environment: string,
  ): Promise<AgentGrantRecord> {
    return this.requireGrant(consumerId, environment);
  }

  public async read(
    consumerId: string,
    environment: string,
    secretId: string,
    ifNoneMatch: string | undefined,
    onAuthorized?: () => Promise<void>,
  ): Promise<SecretReadResult> {
    const grant = await this.requireCapability(consumerId, environment, "read");
    const control = await this.secrets.getControlRevision(
      environment,
      secretId,
    );
    this.requirePath(control, grant.readPathPrefixes);
    return this.secrets.read(
      consumerId,
      environment,
      secretId,
      ifNoneMatch,
      onAuthorized,
    );
  }

  /**
   * A write-capable exporter needs the current ETag and its own allowed
   * metadata to converge safely, but never needs an administrator ACL view or
   * a plaintext payload. This remains path-scoped before it returns anything.
   */
  public async control(
    consumerId: string,
    environment: string,
    secretId: string,
  ): Promise<ControlRevision> {
    const grant = await this.requireGrant(consumerId, environment);
    if (
      !grant.capabilities.includes("read") &&
      !grant.capabilities.includes("write")
    ) {
      throw forbidden("The agent grant does not allow this operation.");
    }
    const control = await this.secrets.getControlRevision(
      environment,
      secretId,
    );
    const prefixes = grant.capabilities.includes("read")
      ? grant.readPathPrefixes
      : grant.writePathPrefixes;
    this.requirePath(control, prefixes);
    return control;
  }

  public async listChanges(
    consumerId: string,
    environment: string,
    exclusiveStartKey?: Record<string, string>,
  ): Promise<{
    readonly changes: readonly AccessRecord[];
    readonly nextCursor?: string;
  }> {
    const grant = await this.requireCapability(consumerId, environment, "read");
    const page = await this.repository.listAccess(
      consumerId,
      environment,
      exclusiveStartKey,
    );
    const candidates = await Promise.all(
      page.changes.map(async (change) => {
        const head = await this.repository.getHead(
          environment,
          change.secretId,
        );
        if (head === undefined || head.environment !== environment) {
          return undefined;
        }
        if (pathIsWithinPrefixes(head.metadata?.path, grant.readPathPrefixes)) {
          return change;
        }
        // A secret that moves out of a grant's prefix must converge just like
        // an ACL revocation: the namespace may already have materialized it,
        // but must not learn anything about its new location or payload.
        return {
          ...change,
          permissions: [],
          payloadVersionId: undefined,
          state: "REVOKED" as const,
          changeKind: "secret.revoked" as const,
        };
      }),
    );
    return {
      changes: candidates.filter(
        (change): change is AccessRecord => change !== undefined,
      ),
      nextCursor: page.nextCursor,
    };
  }

  public async create(input: AgentSecretWriteInput): Promise<ControlRevision> {
    const grant = await this.requireCapability(
      input.consumerId,
      input.environment,
      "write",
    );
    const metadata = input.metadata;
    if (metadata === undefined) {
      throw forbidden("An agent-created secret requires path metadata.");
    }
    this.requirePath({ metadata }, grant.writePathPrefixes);
    return this.secrets.create({
      secretId: input.secretId,
      environment: input.environment,
      metadata,
      acl: [{ consumerId: input.consumerId, permissions: ["read"] }],
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
    });
  }

  public async update(input: AgentSecretWriteInput): Promise<ControlRevision> {
    if (input.expectedControlVersionId === undefined) {
      throw forbidden("An agent update requires the current control revision.");
    }
    const grant = await this.requireCapability(
      input.consumerId,
      input.environment,
      "write",
    );
    const current = await this.secrets.getControlRevision(
      input.environment,
      input.secretId,
    );
    if (current.environment !== input.environment) {
      throw forbidden();
    }
    if (input.metadata === undefined && input.payload === undefined) {
      throw forbidden("An agent update must change metadata and/or payload.");
    }
    const metadata = input.metadata ?? current.metadata;
    this.requirePath({ metadata }, grant.writePathPrefixes);
    return this.secrets.update({
      secretId: input.secretId,
      environment: input.environment,
      expectedControlVersionId: input.expectedControlVersionId,
      ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
      ...(input.payload === undefined ? {} : { payload: input.payload }),
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
    });
  }

  private async requireGrant(
    consumerId: string,
    environment: string,
  ): Promise<AgentGrantRecord> {
    const grant = await this.repository.getAgentGrantForConsumer(consumerId);
    if (
      grant === undefined ||
      grant.status !== "ACTIVE" ||
      grant.environment !== environment
    ) {
      throw forbidden(
        "The client identity does not have an active agent grant.",
      );
    }
    return grant;
  }

  private async requireCapability(
    consumerId: string,
    environment: string,
    capability: AgentCapability,
  ): Promise<AgentGrantRecord> {
    const grant = await this.requireGrant(consumerId, environment);
    if (!grant.capabilities.includes(capability)) {
      throw forbidden("The agent grant does not allow this operation.");
    }
    return grant;
  }

  private requirePath(
    control: Pick<ControlRevision, "metadata">,
    prefixes: readonly string[],
  ): void {
    if (!pathIsWithinPrefixes(control.metadata.path, prefixes)) {
      throw forbidden("The agent grant does not allow this secret path.");
    }
  }
}
