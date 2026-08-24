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
import { assertIdentifier } from "../domain/validation";
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
    assertIdentifier(secretId, "secretId");
    await this.assertAclEnvironment(input.acl, input.environment);
    const now = isoNow();
    const control: ControlRevision = {
      schemaVersion: 1,
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
    const head = await this.repository.requireHead(environment, secretId);
    return this.getControl(head);
  }

  public async update(input: UpdateSecretInput): Promise<ControlRevision> {
    const head = await this.repository.requireHead(
      input.environment,
      input.secretId,
    );
    this.assertExpectedVersion(head, input.expectedControlVersionId);
    const currentControl = await this.getControl(head);
    const metadata = input.metadata ?? currentControl.metadata;
    const acl = input.acl ?? currentControl.acl;
    await this.assertAclEnvironment(acl, head.environment);
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
          secretId: input.secretId,
          payloadVersionId,
        },
        input.actor,
        createdAt,
      );
    }
    const control: ControlRevision = {
      schemaVersion: 1,
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
      !access.permissions.includes("read") ||
      access.state === "REVOKED"
    ) {
      throw forbidden();
    }
    if (
      head === undefined ||
      head.environment !== access.environment ||
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
    if (payloadObjectVersionId === undefined) {
      throw serviceUnavailable(
        "The secret payload does not have an immutable object version.",
      );
    }
    const payload = await this.objects.getJson<
      Parameters<EnvelopeCrypto["decrypt"]>[0]
    >(
      this.config.revisionBucketName,
      payloadKey(environment, secretId, head.payloadVersionId),
      payloadObjectVersionId,
    );
    if (
      payload.schemaVersion !== 1 ||
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
  }): Promise<void> {
    const idempotency = await this.repository.getIdempotency(
      input.actor,
      input.idempotencyKey,
    );
    if (idempotency !== undefined) {
      throw conflict("This idempotency key has already been used.");
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
      environment: input.control.environment,
      expectedControlVersionId: input.expectedControlVersionId,
      control: input.control,
      controlKey: controlKey(
        input.control.environment,
        input.control.secretId,
        input.control.controlVersionId,
      ),
      controlChecksumSha256: sha256Base64(controlBytes),
      controlBytes,
      payload:
        input.payload === undefined || payloadBytes === undefined
          ? undefined
          : {
              revision: input.payload,
              key: payloadKey(
                input.control.environment,
                input.control.secretId,
                input.payload.payloadVersionId,
              ),
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
    if (head.controlObjectVersionId === undefined) {
      throw serviceUnavailable(
        "The secret control revision does not have an immutable object version.",
      );
    }
    return this.objects.getJson<ControlRevision>(
      this.config.revisionBucketName,
      controlKey(head.environment, head.secretId, head.controlVersionId),
      head.controlObjectVersionId,
    );
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

  private async assertAclEnvironment(
    acl: readonly Grant[],
    environment: string,
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
  }

  private async extendPriorRetention(
    head: HeadRecord | undefined,
  ): Promise<void> {
    if (head === undefined) {
      return;
    }
    const retainUntil = new Date(Date.now() + 91 * 24 * 60 * 60 * 1000);
    if (head.controlObjectVersionId !== undefined) {
      await this.objects.extendComplianceRetention(
        {
          bucket: this.config.revisionBucketName,
          key: controlKey(
            head.environment,
            head.secretId,
            head.controlVersionId,
          ),
          versionId: head.controlObjectVersionId,
          checksumSha256: "",
        },
        retainUntil,
      );
    }
    if (
      head.payloadVersionId !== undefined &&
      head.payloadObjectVersionId !== undefined
    ) {
      await this.objects.extendComplianceRetention(
        {
          bucket: this.config.revisionBucketName,
          key: payloadKey(
            head.environment,
            head.secretId,
            head.payloadVersionId,
          ),
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
  environment: string,
  secretId: string,
  controlVersionId: string,
): string =>
  `secrets/${environment}/${secretId}/control/${controlVersionId}.json`;

export const payloadKey = (
  environment: string,
  secretId: string,
  payloadVersionId: string,
): string =>
  `secrets/${environment}/${secretId}/payload/${payloadVersionId}.json`;
