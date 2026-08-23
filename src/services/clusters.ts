import {
  GetDomainNameCommand,
  UpdateDomainNameCommand,
  type ApiGatewayV2Client,
} from "@aws-sdk/client-apigatewayv2";
import type { AppConfig } from "../aws/config";
import {
  badRequest,
  conflict,
  notFound,
  serviceUnavailable,
} from "../domain/errors";
import type {
  Actor,
  ClusterProvisioningResult,
  EnrollmentRecord,
} from "../domain/types";
import { assertIdentifier } from "../domain/validation";
import type {
  DynamoRepository,
  PreparedEnrollment,
} from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import { IssuerService } from "./issuer";
import { isoNow, newId, sha256Hex, stableJson } from "../util/encoding";

const fingerprint = /^[a-f0-9]{64}$/;
const maximumTruststoreCertificates = 1_000;
const maximumTruststoreBytes = 1_048_576;

export interface EnrollmentInput {
  readonly clusterId: string;
  readonly environment: string;
  readonly apiCertificateSigningRequestPem: string;
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

export interface ApiIdentityInput {
  readonly clusterId: string;
  readonly apiCertificateSigningRequestPem: string;
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

export interface RevocationInput {
  readonly clusterId: string;
  readonly apiFingerprint: string;
  readonly actor: Actor;
  readonly idempotencyKey: string;
}

export interface ClusterOperationResult {
  readonly result: ClusterProvisioningResult;
  readonly shouldWriteTerminalAudit: boolean;
}

export interface ApiIdentityResult {
  readonly clusterId: string;
  readonly environment: string;
  readonly rootFingerprint: string;
  readonly apiFingerprint: string;
  readonly apiCertificatePem?: string;
  readonly status: "ACTIVE" | "REVOKED";
  readonly shouldWriteTerminalAudit: boolean;
}

export class ClusterService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly objects: ObjectStore,
    private readonly apiGateway: ApiGatewayV2Client,
    private readonly issuer: IssuerService,
    private readonly config: AppConfig,
  ) {}

  public async enroll(input: EnrollmentInput): Promise<ClusterOperationResult> {
    assertIdentifier(input.clusterId, "clusterId");
    return this.startOrResume(input);
  }

  public async rotateApiIdentity(
    input: ApiIdentityInput,
  ): Promise<ApiIdentityResult> {
    assertIdentifier(input.clusterId, "clusterId");
    const cluster = await this.repository.getCluster(input.clusterId);
    if (cluster === undefined || cluster.status !== "ACTIVE") {
      throw notFound("The requested active cluster was not found.");
    }
    const csrFingerprint = this.issuer.certificateRequestFingerprint(
      input.apiCertificateSigningRequestPem,
    );
    const rootFingerprint = await this.issuer.issuerFingerprint();
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "cluster.api.rotate",
        clusterId: input.clusterId,
        rootFingerprint,
        csrFingerprint,
      }),
    );
    const prior = await this.repository.getIdempotency(
      input.actor,
      input.idempotencyKey,
    );
    if (prior !== undefined) {
      return this.idempotentApiIdentityResult(
        prior,
        requestDigest,
        input.clusterId,
        cluster.environment,
      );
    }
    const issued = await this.issuer.issueApiIdentity(
      input.clusterId,
      cluster.environment,
      input.apiCertificateSigningRequestPem,
    );
    try {
      await this.repository.createApiIdentity(
        input.actor,
        input.idempotencyKey,
        requestDigest,
        issued.apiIdentity,
        issued.rootFingerprint,
      );
    } catch (error) {
      const winner = await this.repository.getIdempotency(
        input.actor,
        input.idempotencyKey,
      );
      if (winner === undefined) {
        throw error;
      }
      return this.idempotentApiIdentityResult(
        winner,
        requestDigest,
        input.clusterId,
        cluster.environment,
      );
    }
    return {
      clusterId: input.clusterId,
      environment: cluster.environment,
      rootFingerprint: issued.rootFingerprint,
      apiFingerprint: issued.apiIdentity.fingerprint,
      apiCertificatePem: issued.apiIdentity.certificatePem,
      status: "ACTIVE",
      shouldWriteTerminalAudit: true,
    };
  }

  public async revokeApiIdentity(
    input: RevocationInput,
  ): Promise<ApiIdentityResult> {
    assertIdentifier(input.clusterId, "clusterId");
    assertFingerprint(input.apiFingerprint, "apiFingerprint");
    const identity = await this.repository.getIdentity(input.apiFingerprint);
    if (
      identity === undefined ||
      identity.clusterId !== input.clusterId ||
      identity.kind !== "api"
    ) {
      throw notFound("The requested cluster API identity was not found.");
    }
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "cluster.api.revoke",
        clusterId: input.clusterId,
        apiFingerprint: input.apiFingerprint,
      }),
    );
    const prior = await this.repository.getIdempotency(
      input.actor,
      input.idempotencyKey,
    );
    if (prior !== undefined) {
      assertIdempotency(prior, requestDigest, "cluster.api.revoke");
      return {
        clusterId: input.clusterId,
        environment: identity.environment,
        rootFingerprint: "",
        apiFingerprint: input.apiFingerprint,
        status: "REVOKED",
        shouldWriteTerminalAudit: prior.status !== "SUCCEEDED",
      };
    }
    await this.repository.revokeApiIdentity(
      input.actor,
      input.idempotencyKey,
      requestDigest,
      input.clusterId,
      input.apiFingerprint,
    );
    return {
      clusterId: input.clusterId,
      environment: identity.environment,
      rootFingerprint: "",
      apiFingerprint: input.apiFingerprint,
      status: "REVOKED",
      shouldWriteTerminalAudit: true,
    };
  }

  public async resume(operationId: string): Promise<ClusterProvisioningResult> {
    const operation = await this.repository.getEnrollment(operationId);
    if (operation === undefined) {
      throw notFound("The requested enrollment operation was not found.");
    }
    if (operation.workflowState === "READY") {
      return activeResult(operation);
    }
    if (operation.workflowState === "FAILED") {
      throw serviceUnavailable(
        "The enrollment was rejected by API Gateway; submit a corrected bundle with a new idempotency key.",
      );
    }
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await this.repository.acquireTruststoreLease(
      operation.operationId,
      expiresAt,
    );
    const roots = await this.repository.listTruststoreRoots(
      operation.operationId,
    );
    if (
      !roots.some(
        (root) =>
          root.fingerprint === operation.rootFingerprint &&
          root.status === "ACTIVE",
      )
    ) {
      throw conflict(
        "The Clavis issuing root is not available in the truststore.",
      );
    }
    const rootFingerprints = roots.map((root) => root.fingerprint).sort();
    if (roots.length > maximumTruststoreCertificates) {
      throw badRequest(
        `The truststore cannot contain more than ${maximumTruststoreCertificates} certificates.`,
      );
    }
    const truststorePem =
      [...roots]
        .sort((left, right) =>
          left.fingerprint.localeCompare(right.fingerprint),
        )
        .map((root) => root.certificatePem.trim())
        .join("\n") + "\n";
    const truststoreBytes = Buffer.from(truststorePem, "utf8");
    if (truststoreBytes.length > maximumTruststoreBytes) {
      throw badRequest(
        "The truststore PEM bundle exceeds API Gateway's 1 MiB limit.",
      );
    }
    const truststore = await this.objects.putImmutableOrGet(
      this.config.truststoreBucketName,
      truststoreKey(this.config.truststoreKeyPrefix, operation.operationId),
      truststoreBytes,
      "application/x-pem-file",
    );
    await this.repository.recordTruststoreBundle(
      operation.operationId,
      truststore,
      rootFingerprints,
    );
    try {
      await this.publishTruststore(truststore);
    } catch (error) {
      if (error instanceof TruststoreRejectedError) {
        await this.rollbackRejectedTruststore(operation);
      }
      throw error;
    }
    try {
      return await this.repository.completeEnrollment(
        operation,
        truststore,
        rootFingerprints,
      );
    } catch (error) {
      const latest = await this.repository.getEnrollment(operation.operationId);
      if (latest?.workflowState === "READY") {
        return activeResult(latest);
      }
      throw error;
    }
  }

  private async startOrResume(
    input: EnrollmentInput,
  ): Promise<ClusterOperationResult> {
    const csrFingerprint = this.issuer.certificateRequestFingerprint(
      input.apiCertificateSigningRequestPem,
    );
    const rootFingerprint = await this.issuer.issuerFingerprint();
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "cluster.enroll",
        clusterId: input.clusterId,
        environment: input.environment,
        rootFingerprint,
        csrFingerprint,
      }),
    );
    const prior = await this.repository.getIdempotency(
      input.actor,
      input.idempotencyKey,
    );
    if (prior !== undefined) {
      assertIdempotency(prior, requestDigest, "cluster.enroll");
      const operationId = stringField(prior, "operationId");
      const result = await this.resume(operationId);
      return { result, shouldWriteTerminalAudit: prior.status !== "SUCCEEDED" };
    }
    const issued = await this.issuer.issueApiIdentity(
      input.clusterId,
      input.environment,
      input.apiCertificateSigningRequestPem,
    );
    const now = isoNow();
    const operationId = newId();
    const prepared: PreparedEnrollment = {
      operationId,
      operationType: "cluster.enroll",
      idempotencyKey: input.idempotencyKey,
      actor: input.actor,
      requestDigest,
      clusterId: input.clusterId,
      environment: input.environment,
      subjectUri: issued.subjectUri,
      rootFingerprint: issued.rootFingerprint,
      apiIdentity: issued.apiIdentity,
      createdAt: now,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    };
    try {
      await this.repository.startEnrollment(prepared);
    } catch (error) {
      const winner = await this.repository.getIdempotency(
        input.actor,
        input.idempotencyKey,
      );
      if (winner === undefined) {
        throw error;
      }
      assertIdempotency(winner, requestDigest, "cluster.enroll");
      const winnerOperationId = stringField(winner, "operationId");
      const result = await this.resume(winnerOperationId);
      return {
        result,
        shouldWriteTerminalAudit: winner.status !== "SUCCEEDED",
      };
    }
    const result = await this.resume(operationId);
    return { result, shouldWriteTerminalAudit: true };
  }

  private async idempotentApiIdentityResult(
    record: Record<string, unknown>,
    requestDigest: string,
    clusterId: string,
    environment: string,
  ): Promise<ApiIdentityResult> {
    assertIdempotency(record, requestDigest, "cluster.api.rotate");
    const apiFingerprint = stringField(record, "apiFingerprint");
    const rootFingerprint = stringField(record, "rootFingerprint");
    const identity = await this.repository.getIdentity(apiFingerprint);
    if (identity?.certificatePem === undefined) {
      throw conflict("The idempotent API identity record is incomplete.");
    }
    return {
      clusterId,
      environment,
      rootFingerprint,
      apiFingerprint,
      apiCertificatePem: identity.certificatePem,
      status: "ACTIVE",
      shouldWriteTerminalAudit: record.status !== "SUCCEEDED",
    };
  }

  private async publishTruststore(truststore: {
    readonly key: string;
    readonly versionId: string;
  }): Promise<void> {
    const uri = `s3://${this.config.truststoreBucketName}/${truststore.key}`;
    const current = await this.apiGateway.send(
      new GetDomainNameCommand({
        DomainName: this.config.clusterCustomDomainName,
      }),
    );
    if (
      current.MutualTlsAuthentication?.TruststoreUri !== uri ||
      current.MutualTlsAuthentication.TruststoreVersion !== truststore.versionId
    ) {
      await this.apiGateway.send(
        new UpdateDomainNameCommand({
          DomainName: this.config.clusterCustomDomainName,
          MutualTlsAuthentication: {
            TruststoreUri: uri,
            TruststoreVersion: truststore.versionId,
          },
        }),
      );
    }
    // Keep a failed candidate plus its rollback comfortably inside API
    // Gateway's synchronous Lambda integration window. Longer propagation
    // is resumed by the scheduled recovery worker using the same object.
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const observed = await this.apiGateway.send(
        new GetDomainNameCommand({
          DomainName: this.config.clusterCustomDomainName,
        }),
      );
      if (
        truststoreMatches(observed, uri, truststore.versionId) &&
        (observed.MutualTlsAuthentication?.TruststoreWarnings?.length ?? 0) > 0
      ) {
        throw new TruststoreRejectedError();
      }
      if (truststoreIsAvailable(observed, uri, truststore.versionId)) {
        return;
      }
      if (attempt < 3) {
        await delay(500 * 2 ** attempt);
      }
    }
    throw serviceUnavailable(
      "API Gateway has not confirmed an available truststore version.",
    );
  }

  private async rollbackRejectedTruststore(
    operation: EnrollmentRecord,
  ): Promise<void> {
    const state = await this.repository.getTruststoreState();
    if (
      state?.currentTruststoreKey !== undefined &&
      state.currentTruststoreVersionId !== undefined
    ) {
      await this.publishTruststore({
        key: state.currentTruststoreKey,
        versionId: state.currentTruststoreVersionId,
      });
    }
    await this.repository.failEnrollment(operation);
  }
}

const truststoreKey = (prefix: string, operationId: string): string =>
  `${prefix.replace(/\/$/, "")}/bundles/${operationId}.pem`;

const assertIdempotency = (
  record: Record<string, unknown>,
  requestDigest: string,
  operationType: string,
): void => {
  if (
    record.requestDigest !== requestDigest ||
    record.operationType !== operationType
  ) {
    throw conflict(
      "This idempotency key has already been used for a different operation.",
    );
  }
};

const stringField = (record: Record<string, unknown>, name: string): string => {
  const value = record[name];
  if (typeof value !== "string" || value.length === 0) {
    throw conflict("The idempotency record is incomplete.");
  }
  return value;
};

const assertFingerprint = (value: string, field: string): void => {
  if (!fingerprint.test(value)) {
    throw badRequest(
      `${field} must be a lowercase SHA-256 certificate fingerprint.`,
    );
  }
};

const activeResult = (
  operation: EnrollmentRecord,
): ClusterProvisioningResult => ({
  clusterId: operation.clusterId,
  environment: operation.environment,
  rootFingerprint: operation.rootFingerprint,
  apiFingerprint: operation.apiFingerprint,
  apiCertificatePem: operation.apiCertificatePem,
  status: "ACTIVE",
});

const truststoreIsAvailable = (
  domain: {
    readonly MutualTlsAuthentication?: {
      readonly TruststoreUri?: string;
      readonly TruststoreVersion?: string;
      readonly TruststoreWarnings?: readonly string[];
    };
    readonly DomainNameConfigurations?: readonly {
      readonly DomainNameStatus?: string;
    }[];
  },
  uri: string,
  versionId: string,
): boolean => {
  const configurations = domain.DomainNameConfigurations ?? [];
  const authentication = domain.MutualTlsAuthentication;
  return (
    truststoreMatches(domain, uri, versionId) &&
    (authentication?.TruststoreWarnings?.length ?? 0) === 0 &&
    configurations.length > 0 &&
    configurations.every(
      (configuration) => configuration.DomainNameStatus === "AVAILABLE",
    )
  );
};

const truststoreMatches = (
  domain: {
    readonly MutualTlsAuthentication?: {
      readonly TruststoreUri?: string;
      readonly TruststoreVersion?: string;
    };
  },
  uri: string,
  versionId: string,
): boolean =>
  domain.MutualTlsAuthentication?.TruststoreUri === uri &&
  domain.MutualTlsAuthentication.TruststoreVersion === versionId;

const delay = async (milliseconds: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });

class TruststoreRejectedError extends Error {
  public constructor() {
    super("API Gateway rejected the truststore certificate bundle.");
  }
}
