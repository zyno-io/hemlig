import type { ApiGatewayV2Client } from "@aws-sdk/client-apigatewayv2";
import type { AppConfig } from "../aws/config";
import type { ClusterRecord, IdentityRecord } from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import type { IssuerService } from "./issuer";
import { ClusterService } from "./clusters";
import { sha256Hex, stableJson } from "../util/encoding";

describe("cluster certificate lifecycle idempotency", () => {
  it("returns the persisted winning leaf when concurrent CSR rotations race", async () => {
    const cluster: ClusterRecord = {
      pk: "CLUSTER#prod-east",
      sk: "PROFILE",
      clusterId: "prod-east",
      environment: "prod",
      subjectUri: "spiffe://clavis/cluster/prod-east",
      status: "ACTIVE",
      createdAt: "2026-08-22T00:00:00.000Z",
      createdBy: { type: "human", id: "operator" },
    };
    const winningIdentity: IdentityRecord = {
      pk: "IDENTITY#winner",
      sk: "PROFILE",
      fingerprint: "winner",
      clusterId: "prod-east",
      environment: "prod",
      kind: "api",
      status: "ACTIVE",
      notBefore: "2026-08-22T00:00:00.000Z",
      notAfter: "2027-08-22T00:00:00.000Z",
      certificatePem: "winning-certificate",
    };
    const requestDigest = sha256Hex(
      stableJson({
        operationType: "cluster.api.rotate",
        clusterId: "prod-east",
        rootFingerprint: "root",
        csrFingerprint: "csr",
      }),
    );
    const repository = {
      getCluster: jest.fn(async () => cluster),
      getIdempotency: jest
        .fn()
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce({
          requestDigest,
          operationType: "cluster.api.rotate",
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
        subjectUri: cluster.subjectUri,
        apiIdentity: {
          fingerprint: "loser",
          clusterId: "prod-east",
          environment: "prod",
          kind: "api",
          notBefore: "2026-08-22T00:00:00.000Z",
          notAfter: "2027-08-22T00:00:00.000Z",
          certificatePem: "losing-certificate",
        },
      })),
    } as unknown as IssuerService;
    const service = new ClusterService(
      repository,
      {} as ObjectStore,
      {} as ApiGatewayV2Client,
      issuer,
      {} as AppConfig,
    );

    const result = await service.rotateApiIdentity({
      clusterId: "prod-east",
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
});
