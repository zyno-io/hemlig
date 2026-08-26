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
 * ACL, and the immutable secret-UID check happens before decryption or
 * mutation. The public secret ID remains only a route and display name.
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
    this.requireReadScope(control, grant);
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
   * a plaintext payload. This remains UID-scoped before it returns anything.
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
    if (grant.capabilities.includes("read")) {
      this.requireReadScope(control, grant);
    } else {
      this.requireWriteScope(control, grant);
    }
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
        const head = await this.repository.getHeadBySecretUid(change.secretUid);
        if (head === undefined || head.environment !== environment) {
          return undefined;
        }
        if (this.isWithinReadScope(head, grant)) {
          return change;
        }
        // A secret removed from a grant's exact allowlist must converge just like
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

  public async update(input: AgentSecretWriteInput): Promise<ControlRevision> {
    if (input.expectedControlVersionId === undefined) {
      throw forbidden("An agent update requires the current control revision.");
    }
    const grant = await this.requireCapability(
      input.consumerId,
      input.environment,
      "write",
    );
    const snapshot = await this.secrets.getControlSnapshot(
      input.environment,
      input.secretId,
    );
    const current = snapshot.control;
    if (current.environment !== input.environment) {
      throw forbidden();
    }
    if (input.metadata === undefined && input.payload === undefined) {
      throw forbidden("An agent update must change metadata and/or payload.");
    }
    this.requireWriteScope(current, grant);
    return this.secrets.updateFromSnapshot(
      {
        secretId: input.secretId,
        environment: input.environment,
        expectedControlVersionId: input.expectedControlVersionId,
        ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
        ...(input.payload === undefined ? {} : { payload: input.payload }),
        actor: input.actor,
        idempotencyKey: input.idempotencyKey,
      },
      snapshot,
    );
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

  private requireReadScope(
    control: { readonly secretUid?: string },
    grant: AgentGrantRecord,
  ): void {
    this.requireSecretPermission(control.secretUid, grant, "read");
  }

  private requireWriteScope(
    control: { readonly secretUid?: string },
    grant: AgentGrantRecord,
  ): void {
    this.requireSecretPermission(control.secretUid, grant, "write");
  }

  private isWithinReadScope(
    control: { readonly secretUid?: string },
    grant: AgentGrantRecord,
  ): boolean {
    return (
      control.secretUid !== undefined &&
      this.hasSecretPermission(grant, control.secretUid, "read")
    );
  }

  private requireSecretPermission(
    secretUid: string | undefined,
    grant: AgentGrantRecord,
    permission: AgentCapability,
  ): void {
    if (
      secretUid === undefined ||
      !this.hasSecretPermission(grant, secretUid, permission)
    ) {
      throw forbidden("The agent grant does not allow this secret.");
    }
  }

  /** A pre-migration record has no canonical pairs and therefore grants nothing. */
  private hasSecretPermission(
    grant: AgentGrantRecord,
    secretUid: string,
    permission: AgentCapability,
  ): boolean {
    return (
      Array.isArray(grant.secretGrants) &&
      grant.secretGrants.some(
        (scope) =>
          scope.secretUid === secretUid &&
          scope.permissions.includes(permission),
      )
    );
  }
}
