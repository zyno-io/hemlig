import type {
  AgentGrantRecord,
  BootstrapCapabilityRecord,
} from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { AgentNotificationService } from "./agent-notifications";
import type { ConsumerService } from "./consumers";
import type { EnvironmentService } from "./environments";
import { AgentGrantService } from "./agent-grants";

const grant: AgentGrantRecord = {
  pk: "AGENT_GRANT#grant-payments",
  sk: "PROFILE",
  grantId: "grant-payments",
  consumerId: "payments-agent",
  environment: "prod",
  capabilities: ["read"],
  readSecretIds: ["payments/api-key"],
  readSecretUids: ["sec-payments-api-key"],
  writeSecretIds: [],
  writeSecretUids: [],
  status: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  activatedFingerprint: "a".repeat(64),
};

const capability: BootstrapCapabilityRecord = {
  pk: "BOOTSTRAP#hash",
  sk: "STATE",
  tokenHash: "hash",
  grantId: grant.grantId,
  expiresAt: "2026-08-23T00:30:00.000Z",
  ttl: 1,
  status: "CONSUMED",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  consumedFingerprint: "a".repeat(64),
};

describe("AgentGrantService", () => {
  it("recovers an already-active identity before consuming a replacement capability", async () => {
    const pendingGrant = {
      ...grant,
      status: "PENDING" as const,
      activatedFingerprint: undefined,
    };
    const pendingCapability = {
      ...capability,
      status: "PENDING" as const,
      consumedFingerprint: undefined,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const repository = {
      getBootstrapCapability: jest.fn(async () => pendingCapability),
      getAgentGrant: jest.fn(async () => pendingGrant),
      activateAgentGrant: jest.fn(async () => undefined),
      consumeBootstrapCapability: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const consumers = {
      recoverActiveIdentity: jest.fn(async () => ({
        consumerId: pendingGrant.consumerId,
        environment: pendingGrant.environment,
        rootFingerprint: "b".repeat(64),
        apiFingerprint: "a".repeat(64),
        apiCertificatePem: "public-certificate",
        status: "ACTIVE" as const,
      })),
      enroll: jest.fn(),
    } as unknown as ConsumerService;
    const notifications = {
      provision: jest.fn(async () => undefined),
    } as unknown as AgentNotificationService;
    const service = new AgentGrantService(
      repository,
      consumers,
      {} as EnvironmentService,
      notifications,
    );

    await expect(
      service.redeem("hmlb_token", "same-csr"),
    ).resolves.toMatchObject({
      apiFingerprint: "a".repeat(64),
    });

    expect(consumers.recoverActiveIdentity).toHaveBeenCalledWith({
      consumerId: pendingGrant.consumerId,
      environment: pendingGrant.environment,
      apiCertificateSigningRequestPem: "same-csr",
    });
    expect(consumers.enroll).not.toHaveBeenCalled();
    expect(
      (repository as unknown as { consumeBootstrapCapability: jest.Mock })
        .consumeBootstrapCapability,
    ).toHaveBeenCalledWith(expect.any(String), "a".repeat(64));
  });

  it("replays a consumed bootstrap with the CSR-proven active identity", async () => {
    const repository = {
      getBootstrapCapability: jest.fn(async () => capability),
      getAgentGrant: jest.fn(async () => grant),
      activateAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const consumers = {
      recoverActiveIdentity: jest.fn(async () => ({
        consumerId: grant.consumerId,
        environment: grant.environment,
        rootFingerprint: "b".repeat(64),
        apiFingerprint: "a".repeat(64),
        apiCertificatePem: "public-certificate",
        status: "ACTIVE" as const,
      })),
      enroll: jest.fn(),
    } as unknown as ConsumerService;
    const notifications = {
      provision: jest.fn(async () => undefined),
    } as unknown as AgentNotificationService;
    const service = new AgentGrantService(
      repository,
      consumers,
      {} as EnvironmentService,
      notifications,
    );

    const result = await service.redeem("hmlb_token", "same-csr");

    expect(result.apiFingerprint).toBe("a".repeat(64));
    expect(consumers.recoverActiveIdentity).toHaveBeenCalledWith({
      consumerId: grant.consumerId,
      environment: grant.environment,
      apiCertificateSigningRequestPem: "same-csr",
    });
    expect(consumers.enroll).not.toHaveBeenCalled();
    expect(notifications.provision).toHaveBeenCalledWith(
      expect.objectContaining({
        consumerId: grant.consumerId,
        certificateFingerprint: "a".repeat(64),
      }),
    );
    expect(
      (repository as unknown as { consumeBootstrapCapability?: jest.Mock })
        .consumeBootstrapCapability,
    ).toBeUndefined();
  });

  it("requires a distinct exact secret ID for each active capability", async () => {
    const repository = {
      getConsumer: jest.fn(async () => undefined),
      createAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const environments = {
      require: jest.fn(async () => undefined),
    } as unknown as EnvironmentService;
    const service = new AgentGrantService(
      repository,
      {} as ConsumerService,
      environments,
      {} as AgentNotificationService,
    );

    await expect(
      service.create({
        consumerId: "payments-agent",
        environment: "prod",
        capabilities: ["read"],
        readSecretIds: ["payments/api-key", "payments/api-key"],
        writeSecretIds: [],
        actor: { type: "human", id: "admin" },
      }),
    ).rejects.toThrow("duplicate");
  });

  it("resolves selected secret IDs to immutable UIDs when creating a grant", async () => {
    const repository = {
      getConsumer: jest.fn(async () => undefined),
      requireHead: jest.fn(async (_environment: string, secretId: string) => ({
        secretUid: `sec-${secretId.replaceAll("/", "-")}`,
      })),
      createAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const environments = {
      require: jest.fn(async () => undefined),
    } as unknown as EnvironmentService;
    const service = new AgentGrantService(
      repository,
      {} as ConsumerService,
      environments,
      {} as AgentNotificationService,
    );

    const created = await service.create({
      consumerId: "payments-agent",
      environment: "prod",
      capabilities: ["read", "write"],
      readSecretIds: ["payments/api-key"],
      writeSecretIds: ["payments/api-key", "payments/rotate-key"],
      actor: { type: "human", id: "admin" },
    });

    expect(created.readSecretIds).toEqual(["payments/api-key"]);
    expect(created.readSecretUids).toEqual(["sec-payments-api-key"]);
    expect(created.writeSecretIds).toEqual([
      "payments/api-key",
      "payments/rotate-key",
    ]);
    expect(created.writeSecretUids).toEqual([
      "sec-payments-api-key",
      "sec-payments-rotate-key",
    ]);
    expect(
      (repository as unknown as { createAgentGrant: jest.Mock })
        .createAgentGrant,
    ).toHaveBeenCalledWith(created);
  });

  it("updates the policy of an active grant without replacing its identity", async () => {
    const repository = {
      getAgentGrant: jest.fn(async () => grant),
      requireHead: jest.fn(async (_environment: string, secretId: string) => ({
        secretUid: `sec-${secretId.replaceAll("/", "-")}`,
      })),
      updateAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const service = new AgentGrantService(
      repository,
      {} as ConsumerService,
      {} as EnvironmentService,
      {} as AgentNotificationService,
    );

    const updated = await service.update(grant.grantId, {
      capabilities: ["read"],
      readSecretIds: [
        "platform/hemlig/integration",
        "platform/gitlab-agents/staging",
      ],
      writeSecretIds: [],
      displayName: "Staging trusted cluster consumer",
    });

    expect(updated.grantId).toBe(grant.grantId);
    expect(updated.consumerId).toBe(grant.consumerId);
    expect(updated.readSecretIds).toEqual([
      "platform/gitlab-agents/staging",
      "platform/hemlig/integration",
    ]);
    expect(updated.readSecretUids).toEqual([
      "sec-platform-gitlab-agents-staging",
      "sec-platform-hemlig-integration",
    ]);
    expect(
      (repository as unknown as { updateAgentGrant: jest.Mock })
        .updateAgentGrant,
    ).toHaveBeenCalledWith(updated, false);
  });
});
