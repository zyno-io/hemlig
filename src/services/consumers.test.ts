import {
  GetDomainNameCommand,
  UpdateDomainNameCommand,
  type ApiGatewayV2Client,
} from "@aws-sdk/client-apigatewayv2";
import type { AppConfig } from "../aws/config";
import type {
  ConsumerRecord,
  EnrollmentRecord,
  IdentityRecord,
  TruststoreRootRecord,
} from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import type { IssuerService } from "./issuer";
import type { EnvironmentService } from "./environments";
import { ConsumerService } from "./consumers";
import { sha256Hex, stableJson } from "../util/encoding";

describe("consumer certificate lifecycle idempotency", () => {
  it("rejects enrollment into an environment that an administrator has not defined", async () => {
    const environments = {
      require: jest.fn().mockRejectedValue({ code: "not_found" }),
    };
    const service = new ConsumerService(
      {} as DynamoRepository,
      {} as ObjectStore,
      {} as ApiGatewayV2Client,
      {} as IssuerService,
      {} as AppConfig,
      environments as unknown as EnvironmentService,
    );

    await expect(
      service.enroll({
        consumerId: "staging-east",
        environment: "staging",
        apiCertificateSigningRequestPem: "CSR",
        actor: { type: "human", id: "admin" },
        idempotencyKey: "defined-environments-only",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(environments.require).toHaveBeenCalledWith("staging");
  });

  it("reconciles an existing truststore onto the configured delivery API domain", async () => {
    const repository = {
      getTruststoreState: jest.fn(async () => ({
        currentTruststoreKey: "truststores/bundles/current.pem",
        currentTruststoreVersionId: "version-current",
      })),
    } as unknown as DynamoRepository;
    let truststoreAttached = false;
    const apiGateway = {
      send: jest.fn(async (command: unknown) => {
        if (command instanceof UpdateDomainNameCommand) {
          truststoreAttached = true;
          return {};
        }
        if (command instanceof GetDomainNameCommand) {
          return truststoreAttached
            ? {
              MutualTlsAuthentication: {
                TruststoreUri: "s3://truststores/truststores/bundles/current.pem",
                TruststoreVersion: "version-current",
              },
              DomainNameConfigurations: [{ DomainNameStatus: "AVAILABLE" }],
            }
            : {};
        }
        throw new Error("Unexpected API Gateway command.");
      }),
    } as unknown as ApiGatewayV2Client;
    const service = new ConsumerService(
      repository,
      {} as ObjectStore,
      apiGateway,
      {} as IssuerService,
      {
        deliveryApiCustomDomainName: "api.example.test",
        truststoreBucketName: "truststores",
      } as AppConfig,
      {} as EnvironmentService,
    );

    await service.reconcileTruststore();

    const getCommand = (apiGateway.send as jest.Mock).mock.calls[0]?.[0] as {
      input: { DomainName: string };
    };
    const updateCommand = (apiGateway.send as jest.Mock).mock.calls[1]?.[0] as {
      input: { DomainName: string; MutualTlsAuthentication: { TruststoreUri: string } };
    };
    expect(getCommand.input.DomainName).toBe("api.example.test");
    expect(updateCommand.input.DomainName).toBe("api.example.test");
    expect(updateCommand.input.MutualTlsAuthentication.TruststoreUri).toBe(
      "s3://truststores/truststores/bundles/current.pem",
    );
  });

  it("does not restart an API Gateway truststore update already in progress", async () => {
    jest.useFakeTimers();
    try {
      const repository = {
        getTruststoreState: jest.fn(async () => ({
          currentTruststoreKey: "truststores/bundles/current.pem",
          currentTruststoreVersionId: "version-current",
        })),
      } as unknown as DynamoRepository;
      const apiGateway = {
        send: jest.fn(async (command: unknown) => {
          if (command instanceof GetDomainNameCommand) {
            return {
              DomainNameConfigurations: [{ DomainNameStatus: "UPDATING" }],
            };
          }
          throw new Error(
            "UpdateDomainName must not be called while updating.",
          );
        }),
      } as unknown as ApiGatewayV2Client;
      const service = new ConsumerService(
        repository,
        {} as ObjectStore,
        apiGateway,
        {} as IssuerService,
        {
          deliveryApiCustomDomainName: "api.example.test",
          truststoreBucketName: "truststores",
        } as AppConfig,
        {} as EnvironmentService,
      );

      const reconciliation = service.reconcileTruststore();
      const rejection = expect(reconciliation).rejects.toMatchObject({
        code: "service_unavailable",
      });
      await jest.runAllTimersAsync();
      await rejection;

      expect(apiGateway.send).toHaveBeenCalledTimes(5);
      expect(
        (apiGateway.send as jest.Mock).mock.calls.every(
          ([command]) => command instanceof GetDomainNameCommand,
        ),
      ).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  it("reuses a matching published truststore when enrolling another leaf", async () => {
    const operation: EnrollmentRecord = {
      pk: "ENROLLMENT#operation-next",
      sk: "STATE",
      operationId: "operation-next",
      operationType: "consumer.enroll",
      consumerId: "prod-west",
      environment: "prod",
      rootFingerprint: "root-current",
      apiFingerprint: "a".repeat(64),
      apiCertificatePem: "certificate",
      createdAt: "2026-08-24T00:00:00.000Z",
      workflowState: "PREPARED",
      requestDigest: "request-digest",
      actor: { type: "human", id: "admin" },
      idempotencyKey: "enrollment-next",
    };
    const roots: TruststoreRootRecord[] = [
      {
        pk: "TRUSTSTORE#ROOTS",
        sk: "ROOT#root-current",
        fingerprint: "root-current",
        consumerId: "issuer",
        environment: "prod",
        certificatePem: "root-certificate",
        notBefore: "2026-08-24T00:00:00.000Z",
        notAfter: "2036-08-24T00:00:00.000Z",
        status: "ACTIVE",
        operationId: "issuer-operation",
        createdAt: "2026-08-24T00:00:00.000Z",
      },
    ];
    const existingTruststore = {
      bucket: "truststores",
      key: "truststores/bundles/current.pem",
      versionId: "version-current",
      checksumSha256: "checksum-current",
    };
    const completeEnrollment = jest.fn(async () => ({
      consumerId: operation.consumerId,
      environment: operation.environment,
      rootFingerprint: operation.rootFingerprint,
      apiFingerprint: operation.apiFingerprint,
      apiCertificatePem: operation.apiCertificatePem,
      status: "ACTIVE" as const,
    }));
    const repository = {
      getEnrollment: jest.fn(async () => operation),
      acquireTruststoreLease: jest.fn(async () => undefined),
      listTruststoreRoots: jest.fn(async () => roots),
      getTruststoreState: jest.fn(async () => ({
        pk: "SYSTEM#TRUSTSTORE" as const,
        sk: "STATE" as const,
        currentTruststoreKey: existingTruststore.key,
        currentTruststoreVersionId: existingTruststore.versionId,
        currentTruststoreChecksumSha256: existingTruststore.checksumSha256,
        currentRootFingerprints: ["root-current"],
      })),
      recordTruststoreBundle: jest.fn(),
      completeEnrollment,
    } as unknown as DynamoRepository;
    const objects = {
      putImmutableOrGet: jest.fn(),
    } as unknown as ObjectStore;
    const apiGateway = {
      send: jest.fn(async (command: unknown) => {
        if (command instanceof GetDomainNameCommand) {
          return {
            MutualTlsAuthentication: {
              TruststoreUri: "s3://truststores/truststores/bundles/current.pem",
              TruststoreVersion: "version-current",
            },
            DomainNameConfigurations: [{ DomainNameStatus: "AVAILABLE" }],
          };
        }
        throw new Error("A matching bundle must not be updated.");
      }),
    } as unknown as ApiGatewayV2Client;
    const service = new ConsumerService(
      repository,
      objects,
      apiGateway,
      {} as IssuerService,
      {
        deliveryApiCustomDomainName: "api.example.test",
        truststoreBucketName: "truststores",
        truststoreKeyPrefix: "truststores",
      } as AppConfig,
      {} as EnvironmentService,
    );

    const result = await service.resume(operation.operationId);

    expect(objects.putImmutableOrGet).not.toHaveBeenCalled();
    expect(repository.recordTruststoreBundle).not.toHaveBeenCalled();
    expect(apiGateway.send).toHaveBeenCalled();
    expect(
      (apiGateway.send as jest.Mock).mock.calls.every(
        ([command]) => command instanceof GetDomainNameCommand,
      ),
    ).toBe(true);
    expect(completeEnrollment).toHaveBeenCalledWith(
      operation,
      existingTruststore,
      ["root-current"],
    );
    expect(result.status).toBe("ACTIVE");
  });

  it("defers enrollment when API Gateway has not accepted a new truststore bundle yet", async () => {
    const repository = {
      getTruststoreState: jest.fn(async () => ({
        currentTruststoreKey: "truststores/bundles/current.pem",
        currentTruststoreVersionId: "version-current",
      })),
    } as unknown as DynamoRepository;
    const apiGateway = {
      send: jest.fn(async (command: unknown) => {
        if (command instanceof GetDomainNameCommand) {
          return {};
        }
        if (command instanceof UpdateDomainNameCommand) {
          throw Object.assign(new Error("bundle is not available yet"), {
            name: "BadRequestException",
          });
        }
        throw new Error("Unexpected API Gateway command.");
      }),
    } as unknown as ApiGatewayV2Client;
    const service = new ConsumerService(
      repository,
      {} as ObjectStore,
      apiGateway,
      {} as IssuerService,
      {
        deliveryApiCustomDomainName: "api.example.test",
        truststoreBucketName: "truststores",
      } as AppConfig,
      {} as EnvironmentService,
    );

    await expect(service.reconcileTruststore()).rejects.toMatchObject({
      code: "service_unavailable",
    });
  });

  it("recovers an active identity only when its certificate matches the submitted CSR", async () => {
    const repository = {
      getConsumer: jest.fn(async () => ({
        consumerId: "staging-agent",
        environment: "staging",
        status: "ACTIVE",
      })),
      listConsumerApiIdentities: jest.fn(async () => ({
        identities: [
          {
            fingerprint: "a".repeat(64),
            environment: "staging",
            status: "ACTIVE",
            certificatePem: "certificate",
          },
        ],
      })),
    } as unknown as DynamoRepository;
    const issuer = {
      certificateRequestMatchesCertificate: jest.fn(() => true),
      issuerFingerprint: jest.fn(async () => "root"),
    } as unknown as IssuerService;
    const service = new ConsumerService(
      repository,
      {} as ObjectStore,
      {} as ApiGatewayV2Client,
      issuer,
      {} as AppConfig,
      {} as EnvironmentService,
    );

    const result = await service.recoverActiveIdentity({
      consumerId: "staging-agent",
      environment: "staging",
      apiCertificateSigningRequestPem: "CSR",
    });

    expect(result).toMatchObject({
      consumerId: "staging-agent",
      environment: "staging",
      rootFingerprint: "root",
      apiFingerprint: "a".repeat(64),
      apiCertificatePem: "certificate",
      status: "ACTIVE",
    });
    expect(issuer.certificateRequestMatchesCertificate).toHaveBeenCalledWith(
      "CSR",
      "certificate",
    );
  });

  it("returns the persisted winning leaf when concurrent CSR rotations race", async () => {
    const consumer: ConsumerRecord = {
      pk: "CONSUMER#prod-east",
      sk: "PROFILE",
      consumerId: "prod-east",
      environment: "prod",
      subjectUri: "spiffe://hemlig/consumer/prod-east",
      status: "ACTIVE",
      createdAt: "2026-08-22T00:00:00.000Z",
      createdBy: { type: "human", id: "operator" },
    };
    const winningIdentity: IdentityRecord = {
      pk: "IDENTITY#winner",
      sk: "PROFILE",
      fingerprint: "winner",
      consumerId: "prod-east",
      environment: "prod",
      kind: "api",
      status: "ACTIVE",
      notBefore: "2026-08-22T00:00:00.000Z",
      notAfter: "2027-08-22T00:00:00.000Z",
      certificatePem: "winning-certificate",
    };
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "consumer.api.rotate",
        consumerId: "prod-east",
        rootFingerprint: "root",
        csrFingerprint: "csr",
      }),
    );
    const repository = {
      getConsumer: jest.fn(async () => consumer),
      getIdempotency: jest
        .fn()
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce({
          requestDigest,
          operationType: "consumer.api.rotate",
          rootFingerprint: "root",
          apiFingerprint: "winner",
          status: "READY",
        }),
      createApiIdentity: jest.fn(async () => {
        throw new Error("conditional write lost");
      }),
      getIdentity: jest.fn(async () => winningIdentity),
    } as unknown as DynamoRepository;
    const issuer = {
      certificateRequestFingerprint: jest.fn(() => "csr"),
      issuerFingerprint: jest.fn(async () => "root"),
      issueApiIdentity: jest.fn(async () => ({
        rootFingerprint: "root",
        subjectUri: consumer.subjectUri,
        apiIdentity: {
          fingerprint: "loser",
          consumerId: "prod-east",
          environment: "prod",
          kind: "api",
          notBefore: "2026-08-22T00:00:00.000Z",
          notAfter: "2027-08-22T00:00:00.000Z",
          certificatePem: "losing-certificate",
        },
      })),
    } as unknown as IssuerService;
    const service = new ConsumerService(
      repository,
      {} as ObjectStore,
      {} as ApiGatewayV2Client,
      issuer,
      {} as AppConfig,
      {} as EnvironmentService,
    );

    const result = await service.rotateApiIdentity({
      consumerId: "prod-east",
      apiCertificateSigningRequestPem: "CSR",
      actor: { type: "human", id: "operator" },
      idempotencyKey: "rotation-123",
    });

    expect(result).toMatchObject({
      rootFingerprint: "root",
      apiFingerprint: "winner",
      apiCertificatePem: "winning-certificate",
      status: "ACTIVE",
    });
  });

  it("resumes a matching pending enrollment when a replacement bootstrap capability arrives", async () => {
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "consumer.enroll",
        consumerId: "staging-agent",
        environment: "staging",
        rootFingerprint: "root",
        csrFingerprint: "csr",
      }),
    );
    const operation = {
      pk: "ENROLLMENT#operation-1",
      sk: "STATE" as const,
      operationId: "operation-1",
      operationType: "consumer.enroll" as const,
      consumerId: "staging-agent",
      environment: "staging",
      rootFingerprint: "root",
      apiFingerprint: "a".repeat(64),
      apiCertificatePem: "certificate",
      createdAt: "2026-08-24T00:00:00.000Z",
      workflowState: "PREPARED" as const,
      requestDigest,
      actor: { type: "system" as const, id: "bootstrap:grant-1" },
      idempotencyKey: "redeem-original",
    };
    const repository = {
      getIdempotency: jest.fn(async () => undefined),
      getPendingEnrollmentForConsumer: jest.fn(async () => operation),
      associateEnrollmentIdempotency: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const issuer = {
      certificateRequestFingerprint: jest.fn(() => "csr"),
      issuerFingerprint: jest.fn(async () => "root"),
      issueApiIdentity: jest.fn(),
    } as unknown as IssuerService;
    const environments = {
      require: jest.fn(async () => undefined),
    } as unknown as EnvironmentService;
    const service = new ConsumerService(
      repository,
      {} as ObjectStore,
      {} as ApiGatewayV2Client,
      issuer,
      {} as AppConfig,
      environments,
    );
    const resume = jest.spyOn(service, "resume").mockResolvedValue({
      consumerId: "staging-agent",
      environment: "staging",
      rootFingerprint: "root",
      apiFingerprint: "a".repeat(64),
      apiCertificatePem: "certificate",
      status: "ACTIVE",
    });

    const result = await service.enroll({
      consumerId: "staging-agent",
      environment: "staging",
      apiCertificateSigningRequestPem: "CSR",
      actor: { type: "system", id: "bootstrap:grant-1" },
      idempotencyKey: "redeem-replacement",
    });

    expect(repository.associateEnrollmentIdempotency).toHaveBeenCalledWith(
      operation,
      { type: "system", id: "bootstrap:grant-1" },
      "redeem-replacement",
    );
    expect(resume).toHaveBeenCalledWith("operation-1");
    expect(issuer.issueApiIdentity).not.toHaveBeenCalled();
    expect(result.result.apiCertificatePem).toBe("certificate");
  });
});

describe("agent self-rotation", () => {
  const consumer: ConsumerRecord = {
    pk: "CONSUMER#prod-east",
    sk: "PROFILE",
    consumerId: "prod-east",
    environment: "prod",
    subjectUri: "spiffe://hemlig/consumer/prod-east",
    status: "ACTIVE",
    createdAt: "2026-08-22T00:00:00.000Z",
    createdBy: { type: "human", id: "operator" },
  };
  const identityRecord = (
    fingerprint: string,
    overrides: Partial<IdentityRecord> = {},
  ): IdentityRecord => ({
    pk: `IDENTITY#${fingerprint}`,
    sk: "PROFILE",
    fingerprint,
    consumerId: "prod-east",
    environment: "prod",
    kind: "api",
    status: "ACTIVE",
    notBefore: "2026-01-01T00:00:00.000Z",
    notAfter: "2999-01-01T00:00:00.000Z",
    certificatePem: `pem-${fingerprint}`,
    ...overrides,
  });
  const requestDigest = sha256Hex(
    stableJson({
      operationType: "consumer.api.rotate",
      consumerId: "prod-east",
      rootFingerprint: "root",
      csrFingerprint: "csr",
    }),
  );
  const actor = { type: "consumer" as const, id: "caller", consumerId: "prod-east" };
  const input = {
    consumerId: "prod-east",
    apiCertificateSigningRequestPem: "CSR",
    actor,
    idempotencyKey: "rotation-123",
    selfRotation: { callerFingerprint: "caller", maximumActiveIdentities: 3 },
  };
  const build = (
    repositoryOverrides: Record<string, unknown>,
  ): {
    service: ConsumerService;
    repository: Record<string, jest.Mock>;
    issuer: Record<string, jest.Mock>;
  } => {
    const repository = {
      getConsumer: jest.fn(async () => consumer),
      getIdempotency: jest.fn(async () => undefined),
      getIdentity: jest.fn(async () => undefined),
      countActiveConsumerApiIdentities: jest.fn(async () => 1),
      createApiIdentity: jest.fn(async () => undefined),
      ...repositoryOverrides,
    } as unknown as Record<string, jest.Mock>;
    const issuer = {
      certificateRequestFingerprint: jest.fn(() => "csr"),
      issuerFingerprint: jest.fn(async () => "root"),
      issueApiIdentity: jest.fn(async () => ({
        rootFingerprint: "root",
        subjectUri: consumer.subjectUri,
        apiIdentity: {
          fingerprint: "new",
          consumerId: "prod-east",
          environment: "prod",
          kind: "api",
          notBefore: "2026-08-22T00:00:00.000Z",
          notAfter: "2999-08-22T00:00:00.000Z",
          certificatePem: "pem-new",
        },
      })),
    } as unknown as Record<string, jest.Mock>;
    return {
      service: new ConsumerService(
        repository as unknown as DynamoRepository,
        {} as ObjectStore,
        {} as ApiGatewayV2Client,
        issuer as unknown as IssuerService,
        {} as AppConfig,
        {} as EnvironmentService,
      ),
      repository,
      issuer,
    };
  };

  it("replays before any caller or cap lookup and reports validity", async () => {
    const { service, repository, issuer } = build({
      getIdempotency: jest.fn(async () => ({
        requestDigest,
        operationType: "consumer.api.rotate",
        rootFingerprint: "root",
        apiFingerprint: "new",
        status: "SUCCEEDED",
      })),
      getIdentity: jest.fn(async () => identityRecord("new")),
      countActiveConsumerApiIdentities: jest.fn(async () => 99),
    });
    const result = await service.rotateApiIdentity(input);
    expect(result).toMatchObject({
      apiFingerprint: "new",
      identityStatus: "ACTIVE",
      notAfter: "2999-01-01T00:00:00.000Z",
      shouldWriteTerminalAudit: false,
    });
    expect(repository.countActiveConsumerApiIdentities).not.toHaveBeenCalled();
    expect(repository.getIdentity).toHaveBeenCalledTimes(1);
    expect(issuer.issueApiIdentity).not.toHaveBeenCalled();
  });

  it("rejects an inactive or foreign caller identity", async () => {
    const { service, issuer } = build({
      getIdentity: jest.fn(async () =>
        identityRecord("caller", { status: "REVOKED" }),
      ),
    });
    await expect(service.rotateApiIdentity(input)).rejects.toMatchObject({
      code: "identity_not_active",
    });
    expect(issuer.issueApiIdentity).not.toHaveBeenCalled();
  });

  it("rejects when the consumer is at the active identity cap", async () => {
    const { service, issuer, repository } = build({
      getIdentity: jest.fn(async () => identityRecord("caller")),
      countActiveConsumerApiIdentities: jest.fn(async () => 3),
    });
    await expect(service.rotateApiIdentity(input)).rejects.toMatchObject({
      statusCode: 409,
      code: "identity_limit_reached",
    });
    expect(issuer.issueApiIdentity).not.toHaveBeenCalled();
    expect(repository.createApiIdentity).not.toHaveBeenCalled();
  });

  it("rejects before KMS when the caller already has an active successor", async () => {
    const { service, issuer } = build({
      getIdentity: jest.fn(async (fingerprint: string) =>
        fingerprint === "caller"
          ? identityRecord("caller", { rotatedTo: "successor" })
          : identityRecord("successor"),
      ),
    });
    await expect(service.rotateApiIdentity(input)).rejects.toMatchObject({
      code: "identity_already_rotated",
    });
    expect(issuer.issueApiIdentity).not.toHaveBeenCalled();
  });

  it("allows replacing a revoked successor", async () => {
    const { service, repository } = build({
      getIdentity: jest.fn(async (fingerprint: string) =>
        fingerprint === "caller"
          ? identityRecord("caller", { rotatedTo: "successor" })
          : identityRecord("successor", { status: "REVOKED" }),
      ),
    });
    const result = await service.rotateApiIdentity(input);
    expect(result).toMatchObject({
      apiFingerprint: "new",
      identityStatus: "ACTIVE",
      notAfter: "2999-08-22T00:00:00.000Z",
    });
    expect(repository.createApiIdentity).toHaveBeenCalledWith(
      actor,
      "rotation-123",
      requestDigest,
      expect.objectContaining({ fingerprint: "new" }),
      "root",
      expect.objectContaining({
        fingerprint: "caller",
        replaceableSuccessor: "successor",
      }),
    );
  });

  it("does not count or link a predecessor on the administrator path", async () => {
    const { service, repository } = build({});
    const { selfRotation: _ignored, ...adminInput } = input;
    await service.rotateApiIdentity({
      ...adminInput,
      actor: { type: "human", id: "operator" },
    });
    expect(repository.countActiveConsumerApiIdentities).not.toHaveBeenCalled();
    expect(repository.getIdentity).not.toHaveBeenCalled();
    expect(repository.createApiIdentity?.mock.calls[0]?.[5]).toBeUndefined();
  });
});

