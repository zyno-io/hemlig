import {
  GetDomainNameCommand,
  UpdateDomainNameCommand,
  type ApiGatewayV2Client,
} from "@aws-sdk/client-apigatewayv2";
import type { AppConfig } from "../aws/config";
import type { ConsumerRecord, IdentityRecord } from "../domain/types";
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
