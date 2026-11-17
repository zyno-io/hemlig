import {
  ApiError,
  forbidden,
  invalidCsr,
  rotationReplayInactive,
} from "../domain/errors";
import type { Actor } from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import {
  provisionAndVerify,
  type AgentNotificationService,
} from "./agent-notifications";
import type { ConsumerService } from "./consumers";
import type { IssuerService } from "./issuer";

/** Active API identities a consumer may hold; leaves room for rollback and overlap. */
export const MAX_ACTIVE_AGENT_API_IDENTITIES = 3;

export interface AgentIdentityRotationInput {
  readonly actor: Actor;
  readonly callerCertificatePem: string;
  readonly apiCertificateSigningRequestPem: string;
  readonly idempotencyKey: string;
  /** Invoked after the agent grant check and before any CSR work or issuance. */
  readonly onAuthorized?: () => Promise<void>;
}

export interface AgentIdentityRotationResult {
  readonly consumerId: string;
  readonly environment: string;
  readonly rootFingerprint: string;
  readonly apiFingerprint: string;
  readonly apiCertificatePem: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly status: "ACTIVE";
  readonly shouldWriteTerminalAudit: boolean;
}

/** Lets an agent holding an active mTLS identity replace it with a new-key leaf. */
export class AgentIdentityService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly consumers: ConsumerService,
    private readonly issuer: IssuerService,
    private readonly notifications: AgentNotificationService,
  ) {}

  public async rotate(
    input: AgentIdentityRotationInput,
  ): Promise<AgentIdentityRotationResult> {
    const { actor } = input;
    if (
      actor.type !== "consumer" ||
      actor.consumerId === undefined ||
      actor.environment === undefined
    ) {
      throw forbidden("Only a consumer API identity may rotate itself.");
    }
    const grant = await this.repository.getAgentGrantForConsumer(
      actor.consumerId,
    );
    if (
      grant === undefined ||
      grant.status !== "ACTIVE" ||
      grant.consumerId !== actor.consumerId ||
      grant.environment !== actor.environment
    ) {
      throw forbidden("The consumer does not have an active agent grant.");
    }
    await input.onAuthorized?.();

    let sameKey: boolean;
    try {
      sameKey = this.issuer.certificateRequestMatchesCertificate(
        input.apiCertificateSigningRequestPem,
        input.callerCertificatePem,
      );
    } catch (error) {
      if (error instanceof ApiError && error.statusCode === 400) {
        throw invalidCsr(error.message);
      }
      throw error;
    }
    if (sameKey) {
      throw invalidCsr("The certificate signing request must use a new key.");
    }

    let result;
    try {
      result = await this.consumers.rotateApiIdentity({
        consumerId: actor.consumerId,
        apiCertificateSigningRequestPem: input.apiCertificateSigningRequestPem,
        actor,
        idempotencyKey: input.idempotencyKey,
        selfRotation: {
          callerFingerprint: actor.id,
          maximumActiveIdentities: MAX_ACTIVE_AGENT_API_IDENTITIES,
        },
      });
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.statusCode === 400 &&
        error.code === "bad_request"
      ) {
        throw invalidCsr(error.message);
      }
      throw error;
    }
    if (
      result.apiCertificatePem === undefined ||
      result.notBefore === undefined ||
      result.notAfter === undefined ||
      result.identityStatus !== "ACTIVE" ||
      new Date(result.notAfter).getTime() <= Date.now()
    ) {
      throw rotationReplayInactive(
        "The identity issued for this idempotency key is no longer active; submit a new rotation request.",
      );
    }
    // Idempotent: a replay re-registers a leaf whose first provisioning may have failed.
    await provisionAndVerify(this.notifications, this.repository, {
      consumerId: result.consumerId,
      certificateFingerprint: result.apiFingerprint,
      certificatePem: result.apiCertificatePem,
    });
    return {
      consumerId: result.consumerId,
      environment: result.environment,
      rootFingerprint: result.rootFingerprint,
      apiFingerprint: result.apiFingerprint,
      apiCertificatePem: result.apiCertificatePem,
      notBefore: result.notBefore,
      notAfter: result.notAfter,
      status: "ACTIVE",
      shouldWriteTerminalAudit: result.shouldWriteTerminalAudit,
    };
  }
}
