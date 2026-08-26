import type { AppConfig } from "../aws/config";
import { EnvelopeCrypto } from "../crypto/envelope";
import {
  conflict,
  forbidden,
  notFound,
  preconditionFailed,
  serviceUnavailable,
} from "../domain/errors";
import type {
  AccessRecord,
  AgentSecretGrant,
  Actor,
  ControlRevision,
  Grant,
  HeadRecord,
  SecretMetadata,
  SecretPayload,
  SecretState,
} from "../domain/types";
import {
  sha256Base64,
  sha256Hex,
  isoNow,
  newId,
  stableJson,
} from "../util/encoding";
import type {
  DynamoRepository,
  PreparedMutation,
} from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import { assertIdentifier, assertSecretIdentifier } from "../domain/validation";
import type { EnvironmentService } from "./environments";

export interface CreateSecretInput {
  readonly secretId: string;
  readonly environment: string;
  readonly metadata: SecretMetadata;
  readonly acl: readonly Grant[];
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

export interface UpdateSecretInput {
  readonly secretId: string;
  readonly environment: string;
  readonly expectedControlVersionId: string;
  readonly metadata?: SecretMetadata;
  readonly acl?: readonly Grant[];
  readonly payload?: SecretPayload;
  readonly actor: Actor;
  readonly idempotencyKey: string;
  /** Internal AgentGrant projection maintenance only. */
  readonly allowAgentAcl?: boolean;
}

export interface ArchiveSecretInput {
  readonly secretId: string;
  readonly environment: string;
  readonly expectedControlVersionId: string;
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

export interface RevokeConsumerSecretGrantInput {
  readonly consumerId: string;
  readonly secretId: string;
  readonly actor: Actor;
  readonly idempotencyKey: string;
  /** Internal AgentGrant projection maintenance only. */
  readonly allowAgentAcl?: boolean;
}

export interface ReconcileAgentReadAccessInput {
  readonly consumerId: string;
  readonly environment: string;
  readonly secretGrants: readonly AgentSecretGrant[];
  readonly actor: Actor;
}

export interface SecretReadResult {
  readonly notModified: boolean;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly payload?: SecretPayload;
}

export interface ActiveSecretPayload {
  readonly controlVersionId: string;
  readonly payloadVersionId: string;
  readonly payload: SecretPayload;
}

/** A consistent control read retained for a conditional follow-up mutation. */
export interface SecretControlSnapshot {
  readonly head: HeadRecord;
  readonly control: ControlRevision;
}

export class SecretService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly objects: ObjectStore,
    private readonly crypto: EnvelopeCrypto,
    private readonly config: AppConfig,
    private readonly environments: EnvironmentService,
  ) {}

  public async create(input: CreateSecretInput): Promise<ControlRevision> {
    await this.environments.require(input.environment);
    const secretId = input.secretId;
    assertSecretIdentifier(secretId, "secretId");
    await this.assertAclEnvironment(input.acl, input.environment);
    const now = isoNow();
    const control: ControlRevision = {
      schemaVersion: 1,
      secretUid: `sec-${newId()}`,
      secretId,
      controlVersionId: `ctl-${newId()}`,
      environment: input.environment,
      state: "PENDING_VALUE",
      createdAt: now,
      createdBy: input.actor,
      metadata: input.metadata,
      acl: input.acl,
    };
    await this.persistMutation({
      control,
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
      expectedControlVersionId: undefined,
    });
    return control;
  }

  /** Returns control-plane metadata and ACL only; it never loads a payload. */
  public async getControlRevision(
    environment: string,
    secretId: string,
  ): Promise<ControlRevision> {
    const snapshot = await this.getControlSnapshot(environment, secretId);
    return snapshot.control;
  }

  /**
   * Reads the current head and immutable control revision together. A scoped
   * agent write reuses this snapshot, so it does not perform a second name
   * lookup between obtaining the ETag and conditionally acquiring the lease.
   */
  public async getControlSnapshot(
    environment: string,
    secretId: string,
  ): Promise<SecretControlSnapshot> {
    const head = await this.repository.requireHead(environment, secretId);
    return { head, control: await this.getControl(head) };
  }

  public async update(input: UpdateSecretInput): Promise<ControlRevision> {
    const snapshot = await this.getControlSnapshot(
      input.environment,
      input.secretId,
    );
    return this.updateFromSnapshot(input, snapshot);
  }

  /**
   * Applies a mutation from a control snapshot. The expected control revision
   * remains the DynamoDB lease condition, so reusing a snapshot never weakens
   * concurrent-writer protection.
   */
  public async updateFromSnapshot(
    input: UpdateSecretInput,
    snapshot: SecretControlSnapshot,
  ): Promise<ControlRevision> {
    const { head, control: currentControl } = snapshot;
    this.assertExpectedVersion(head, input.expectedControlVersionId);
    const metadata = input.metadata ?? currentControl.metadata;
    const acl = input.acl ?? currentControl.acl;
    await this.assertAclEnvironment(
      acl,
      head.environment,
      input.allowAgentAcl ?? false,
      currentControl.acl,
    );
    const createdAt = isoNow();
    let payloadRevision = undefined;
    let payloadVersionId = currentControl.payloadVersionId;
    let payloadKeyCount = currentControl.payloadKeyCount;
    let state: SecretState = currentControl.state;
    if (input.payload !== undefined) {
      payloadVersionId = `pay-${newId()}`;
      payloadKeyCount = Object.keys(input.payload).length;
      state = "ACTIVE";
      payloadRevision = await this.crypto.encrypt(
        input.payload,
        {
          environment: head.environment,
          secretUid: head.secretUid,
          secretId: input.secretId,
          payloadVersionId,
        },
        input.actor,
        createdAt,
      );
    }
    const control: ControlRevision = {
      schemaVersion: 1,
      secretUid: head.secretUid,
      secretId: input.secretId,
      controlVersionId: `ctl-${newId()}`,
      payloadVersionId,
      payloadKeyCount,
      environment: head.environment,
      state,
      createdAt,
      createdBy: input.actor,
      metadata,
      acl,
    };
    const priorAccess = await this.priorAccess(
      currentControl.acl,
      head.environment,
      input.secretId,
    );
    await this.persistMutation({
      control,
      payload: payloadRevision,
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
      expectedControlVersionId: input.expectedControlVersionId,
      priorHead: head,
      priorAccess,
    });
    return control;
  }

  /**
   * Archives one immutable identity. The external name lookup is removed only
   * when the archival control revision commits, which makes the name reusable
   * without ever confusing existing revisions or access grants with a later
   * secret that has the same name.
   */
  public async archive(input: ArchiveSecretInput): Promise<ControlRevision> {
    const head = await this.repository.requireHead(
      input.environment,
      input.secretId,
    );
    this.assertExpectedVersion(head, input.expectedControlVersionId);
    const currentControl = await this.getControl(head);
    const control: ControlRevision = {
      ...currentControl,
      secretUid: head.secretUid,
      controlVersionId: `ctl-${newId()}`,
      state: "ARCHIVED",
      createdAt: isoNow(),
      createdBy: input.actor,
      // An archive is deliberately not an authorization mechanism. Removing
      // every grant makes the mutation publish durable revocations before the
      // live name becomes available for a new secret.
      acl: [],
    };
    const priorAccess = await this.priorAccess(
      currentControl.acl,
      head.environment,
      input.secretId,
    );
    await this.persistMutation({
      control,
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
      expectedControlVersionId: input.expectedControlVersionId,
      priorHead: head,
      priorAccess,
      archive: true,
    });
    return control;
  }

  /**
   * Removes one consumer from the source-of-truth ACL, rather than editing
   * its delivery projection directly. The normal mutation path then emits the
   * durable revocation and notification for the consumer.
   */
  public async revokeConsumerSecretGrant(
    input: RevokeConsumerSecretGrantInput,
  ): Promise<ControlRevision> {
    assertIdentifier(input.consumerId, "consumerId");
    assertSecretIdentifier(input.secretId, "secretId");
    const consumer = await this.repository.getConsumer(input.consumerId);
    if (consumer === undefined) {
      throw notFound("The requested consumer was not found.");
    }
    if (
      !input.allowAgentAcl &&
      (await this.repository.getAgentGrantForConsumer(input.consumerId)) !==
        undefined
    ) {
      throw conflict(
        "Agent consumer access is managed by its AgentGrant, not the secret ACL.",
      );
    }
    const head = await this.repository.requireHead(
      consumer.environment,
      input.secretId,
    );
    const current = await this.getControl(head);
    const acl = current.acl.filter(
      (grant) => grant.consumerId !== input.consumerId,
    );
    if (acl.length === current.acl.length) {
      throw notFound("The consumer does not have access to this secret.");
    }
    return this.update({
      secretId: input.secretId,
      environment: consumer.environment,
      expectedControlVersionId: current.controlVersionId,
      acl,
      actor: input.actor,
      idempotencyKey: input.idempotencyKey,
      allowAgentAcl: input.allowAgentAcl,
    });
  }

  /**
   * Keeps the read ACL/index as an operational projection of a canonical
   * AgentGrant. This is deliberately fail-closed: added ACL entries are not
   * usable until the AgentGrant itself is active, and a partially completed
   * reconciliation can only deny an old permission, never create a new one.
   */
  public async reconcileAgentReadAccess(
    input: ReconcileAgentReadAccessInput,
  ): Promise<void> {
    const desired = new Map(
      input.secretGrants
        .filter((grant) => grant.permissions.includes("read"))
        .map((grant) => [grant.secretUid, grant]),
    );
    const current = await this.listAllConsumerSecretGrants(
      input.consumerId,
      input.environment,
    );
    const currentByUid = new Map(
      current.map((grant) => [grant.secretUid, grant]),
    );
    for (const grant of current) {
      if (desired.has(grant.secretUid)) {
        continue;
      }
      await this.revokeConsumerSecretGrant({
        consumerId: input.consumerId,
        secretId: grant.secretId,
        actor: input.actor,
        idempotencyKey: `agent-acl-revoke-${newId()}`,
        allowAgentAcl: true,
      });
    }
    for (const grant of desired.values()) {
      if (currentByUid.has(grant.secretUid)) {
        continue;
      }
      await this.grantAgentConsumerReadAccess({
        consumerId: input.consumerId,
        environment: input.environment,
        secretId: grant.secretId,
        secretUid: grant.secretUid,
        actor: input.actor,
      });
    }
  }

  /** Reads a historical archive entry by its immutable identity, not its reusable name. */
  public async getArchivedControlRevision(
    environment: string,
    secretUid: string,
  ): Promise<ControlRevision> {
    const head = await this.repository.requireHeadBySecretUid(secretUid);
    if (head.environment !== environment || head.state !== "ARCHIVED") {
      throw notFound("The requested archived secret was not found.");
    }
    return this.getControl(head);
  }

  public async read(
    consumerId: string,
    consumerEnvironment: string,
    secretId: string,
    ifNoneMatch?: string,
    onAuthorized?: () => Promise<void>,
  ): Promise<SecretReadResult> {
    const authorization = await this.repository.getAccessAndHead(
      consumerId,
      consumerEnvironment,
      secretId,
    );
    const { access, head } = authorization;
    if (
      access === undefined ||
      access.environment !== consumerEnvironment ||
      access.secretId !== secretId ||
      !access.permissions.includes("read") ||
      access.state === "REVOKED"
    ) {
      throw forbidden();
    }
    if (
      head === undefined ||
      head.environment !== access.environment ||
      head.secretId !== secretId ||
      head.secretUid !== access.secretUid ||
      head.state !== "ACTIVE"
    ) {
      throw forbidden();
    }
    if (onAuthorized !== undefined) {
      await onAuthorized();
    }
    if (ifNoneMatch === head.controlVersionId) {
      return {
        notModified: true,
        controlVersionId: head.controlVersionId,
        payloadVersionId: head.payloadVersionId,
      };
    }
    const activePayload = await this.readActivePayload(
      consumerEnvironment,
      secretId,
      head,
    );
    return { notModified: false, ...activePayload };
  }

  /**
   * Returns an active payload to an already-authenticated administrator. The
   * handler is responsible for its administrator authorization and audit trail;
   * this method keeps the same immutable-head and envelope binding checks used
   * for consumer delivery.
   */
  public async readAdminPayload(
    environment: string,
    secretId: string,
  ): Promise<ActiveSecretPayload> {
    const head = await this.repository.requireHead(environment, secretId);
    if (head.state !== "ACTIVE") {
      throw notFound("The secret has no active payload.");
    }
    return this.readActivePayload(environment, secretId, head);
  }

  private async readActivePayload(
    environment: string,
    secretId: string,
    head: HeadRecord,
  ): Promise<ActiveSecretPayload> {
    if (head.payloadVersionId === undefined) {
      throw notFound("The secret has no active payload.");
    }
    const control = await this.getControl(head);
    if (
      control.schemaVersion !== 1 ||
      (control.secretUid !== undefined &&
        control.secretUid !== head.secretUid) ||
      control.secretId !== secretId ||
      control.environment !== head.environment ||
      control.controlVersionId !== head.controlVersionId ||
      control.payloadVersionId !== head.payloadVersionId ||
      control.state !== head.state
    ) {
      throw serviceUnavailable(
        "The secret head and control revision do not agree.",
      );
    }
    const payloadObjectVersionId = head.payloadObjectVersionId;
    const payloadObjectKey = head.payloadObjectKey;
    if (
      payloadObjectVersionId === undefined ||
      payloadObjectKey === undefined
    ) {
      throw serviceUnavailable(
        "The secret payload does not have an immutable object version.",
      );
    }
    const payload = await this.objects.getJson<
      Parameters<EnvelopeCrypto["decrypt"]>[0]
    >(this.config.revisionBucketName, payloadObjectKey, payloadObjectVersionId);
    if (
      payload.schemaVersion !== 1 ||
      (payload.secretUid !== undefined &&
        payload.secretUid !== head.secretUid) ||
      payload.secretId !== secretId ||
      payload.environment !== head.environment ||
      payload.payloadVersionId !== head.payloadVersionId
    ) {
      throw serviceUnavailable(
        "The secret payload revision does not match the authorized head.",
      );
    }
    const plaintext = await this.crypto.decrypt(payload);
    return {
      controlVersionId: head.controlVersionId,
      payloadVersionId: head.payloadVersionId,
      payload: plaintext,
    };
  }

  private async persistMutation(input: {
    readonly control: ControlRevision;
    readonly payload?: Parameters<EnvelopeCrypto["decrypt"]>[0];
    readonly actor: Actor;
    readonly idempotencyKey: string;
    readonly expectedControlVersionId?: string;
    readonly priorHead?: HeadRecord;
    readonly priorAccess?: readonly AccessRecord[];
    readonly archive?: true;
  }): Promise<void> {
    const idempotency = await this.repository.getIdempotency(
      input.actor,
      input.idempotencyKey,
    );
    if (idempotency !== undefined) {
      throw conflict("This idempotency key has already been used.");
    }
    const secretUid = input.control.secretUid;
    if (secretUid === undefined) {
      throw serviceUnavailable(
        "The secret mutation does not have an internal ID.",
      );
    }
    const operationId = newId();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const controlBytes = Buffer.from(stableJson(input.control), "utf8");
    const payloadBytes =
      input.payload === undefined
        ? undefined
        : Buffer.from(stableJson(input.payload), "utf8");
    const prepared: PreparedMutation = {
      operationId,
      idempotencyKey: input.idempotencyKey,
      actor: input.actor,
      requestDigest: sha256Hex(
        stableJson({
          control: input.control,
          hasPayload: input.payload !== undefined,
        }),
      ),
      secretId: input.control.secretId,
      secretUid,
      environment: input.control.environment,
      expectedControlVersionId: input.expectedControlVersionId,
      ...(input.archive === true ? { archive: true as const } : {}),
      control: input.control,
      controlKey: controlKey(secretUid, input.control.controlVersionId),
      controlChecksumSha256: sha256Base64(controlBytes),
      controlBytes,
      payload:
        input.payload === undefined || payloadBytes === undefined
          ? undefined
          : {
              revision: input.payload,
              key: payloadKey(secretUid, input.payload.payloadVersionId),
              checksumSha256: sha256Base64(payloadBytes),
              bytes: payloadBytes,
            },
      expiresAt,
    };
    await this.repository.prepareMutation(prepared);
    const controlObject = await this.objects.putImmutable(
      this.config.revisionBucketName,
      prepared.controlKey,
      prepared.controlBytes,
    );
    const payloadObject =
      prepared.payload === undefined
        ? undefined
        : await this.objects.putImmutable(
            this.config.revisionBucketName,
            prepared.payload.key,
            prepared.payload.bytes,
          );
    await this.extendPriorRetention(input.priorHead);
    await this.repository.completeMutation({
      prepared,
      controlObject,
      payloadObject,
      priorHead: input.priorHead,
      priorAccess: input.priorAccess ?? [],
    });
  }

  private async getControl(head: HeadRecord): Promise<ControlRevision> {
    if (
      head.controlObjectVersionId === undefined ||
      head.controlObjectKey === undefined
    ) {
      throw serviceUnavailable(
        "The secret control revision does not have an immutable object version.",
      );
    }
    const control = await this.objects.getJson<ControlRevision>(
      this.config.revisionBucketName,
      head.controlObjectKey,
      head.controlObjectVersionId,
    );
    return { ...control, secretUid: head.secretUid };
  }

  private async priorAccess(
    acl: readonly Grant[],
    environment: string,
    secretId: string,
  ): Promise<readonly AccessRecord[]> {
    const reads = acl.map(async (grant) =>
      this.repository.getAccess(grant.consumerId, environment, secretId),
    );
    const resolved = await Promise.all(reads);
    return resolved.filter((item): item is AccessRecord => item !== undefined);
  }

  private async grantAgentConsumerReadAccess(input: {
    readonly consumerId: string;
    readonly environment: string;
    readonly secretId: string;
    readonly secretUid: string;
    readonly actor: Actor;
  }): Promise<void> {
    const head = await this.repository.requireHead(
      input.environment,
      input.secretId,
    );
    if (head.secretUid !== input.secretUid) {
      // An archived name may have been reused. A grant never silently follows
      // it to a different immutable secret identity.
      return;
    }
    const current = await this.getControl(head);
    if (current.acl.some((grant) => grant.consumerId === input.consumerId)) {
      return;
    }
    await this.update({
      secretId: input.secretId,
      environment: input.environment,
      expectedControlVersionId: current.controlVersionId,
      acl: [
        ...current.acl,
        { consumerId: input.consumerId, permissions: ["read"] },
      ],
      actor: input.actor,
      idempotencyKey: `agent-acl-grant-${newId()}`,
      allowAgentAcl: true,
    });
  }

  private async listAllConsumerSecretGrants(
    consumerId: string,
    environment: string,
  ): Promise<readonly import("../domain/types").ConsumerSecretGrant[]> {
    const grants: import("../domain/types").ConsumerSecretGrant[] = [];
    let cursor: Record<string, string> | undefined;
    do {
      const page = await this.repository.listConsumerSecretGrants(
        consumerId,
        environment,
        cursor,
      );
      grants.push(...page.grants);
      cursor =
        page.nextCursor === undefined
          ? undefined
          : (JSON.parse(page.nextCursor) as Record<string, string>);
    } while (cursor !== undefined);
    return grants;
  }

  private async assertAclEnvironment(
    acl: readonly Grant[],
    environment: string,
    allowAgentAcl = false,
    priorAcl: readonly Grant[] = [],
  ): Promise<void> {
    const records = await Promise.all(
      acl.map(async (grant) => this.repository.getConsumer(grant.consumerId)),
    );
    for (const [index, consumer] of records.entries()) {
      const grant = acl[index];
      if (
        grant === undefined ||
        consumer === undefined ||
        consumer.status !== "ACTIVE" ||
        consumer.environment !== environment
      ) {
        throw forbidden(
          "Every ACL grant must name an active consumer in the secret environment.",
        );
      }
    }
    if (allowAgentAcl) {
      return;
    }
    const consumerIds = new Set([
      ...acl.map((grant) => grant.consumerId),
      ...priorAcl.map((grant) => grant.consumerId),
    ]);
    const agentGrants = await Promise.all(
      [...consumerIds].map(async (consumerId) => ({
        consumerId,
        grant: await this.repository.getAgentGrantForConsumer(consumerId),
      })),
    );
    for (const agentGrant of agentGrants) {
      if (agentGrant.grant === undefined) {
        continue;
      }
      const current = acl.find(
        (grant) => grant.consumerId === agentGrant.consumerId,
      );
      const prior = priorAcl.find(
        (grant) => grant.consumerId === agentGrant.consumerId,
      );
      if (
        current === undefined ||
        prior === undefined ||
        !sameGrant(current, prior)
      ) {
        throw conflict(
          "Agent consumer access is managed by its AgentGrant, not the secret ACL.",
        );
      }
    }
  }

  private async extendPriorRetention(
    head: HeadRecord | undefined,
  ): Promise<void> {
    if (head === undefined) {
      return;
    }
    const retainUntil = new Date(Date.now() + 91 * 24 * 60 * 60 * 1000);
    if (
      head.controlObjectVersionId !== undefined &&
      head.controlObjectKey !== undefined
    ) {
      await this.objects.extendComplianceRetention(
        {
          bucket: this.config.revisionBucketName,
          key: head.controlObjectKey,
          versionId: head.controlObjectVersionId,
          checksumSha256: "",
        },
        retainUntil,
      );
    }
    if (
      head.payloadVersionId !== undefined &&
      head.payloadObjectVersionId !== undefined &&
      head.payloadObjectKey !== undefined
    ) {
      await this.objects.extendComplianceRetention(
        {
          bucket: this.config.revisionBucketName,
          key: head.payloadObjectKey,
          versionId: head.payloadObjectVersionId,
          checksumSha256: "",
        },
        retainUntil,
      );
    }
  }

  private assertExpectedVersion(head: HeadRecord, expected: string): void {
    if (head.controlVersionId !== expected) {
      throw preconditionFailed(
        "If-Match does not name the current control revision.",
      );
    }
  }
}

export const controlKey = (
  secretUid: string,
  controlVersionId: string,
): string => `secrets/${secretUid}/control/${controlVersionId}.json`;

export const payloadKey = (
  secretUid: string,
  payloadVersionId: string,
): string => `secrets/${secretUid}/payload/${payloadVersionId}.json`;

const sameGrant = (left: Grant, right: Grant): boolean =>
  left.consumerId === right.consumerId &&
  left.permissions.length === right.permissions.length &&
  left.permissions.every(
    (permission, index) => permission === right.permissions[index],
  );
