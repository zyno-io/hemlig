import type { AgentGrantRecord, BootstrapCapabilityRecord } from "../domain/types";
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
  readPathPrefixes: ["payments"],
  writePathPrefixes: [],
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
  it("replays a consumed bootstrap only through the enrollment idempotency key", async () => {
    const repository = {
      getBootstrapCapability: jest.fn(async () => capability),
      getAgentGrant: jest.fn(async () => grant),
      activateAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const consumers = {
      enroll: jest.fn(async () => ({
        shouldWriteTerminalAudit: false,
        result: {
          consumerId: grant.consumerId,
          environment: grant.environment,
          rootFingerprint: "b".repeat(64),
          apiFingerprint: "a".repeat(64),
          apiCertificatePem: "public-certificate",
          status: "ACTIVE" as const,
        },
      })),
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
    expect(consumers.enroll).toHaveBeenCalledWith(expect.objectContaining({
      idempotencyKey: expect.stringMatching(/^redeem-/),
      apiCertificateSigningRequestPem: "same-csr",
    }));
    expect(notifications.provision).toHaveBeenCalledWith(expect.objectContaining({
      consumerId: grant.consumerId,
      certificateFingerprint: "a".repeat(64),
    }));
    expect((repository as unknown as { consumeBootstrapCapability?: jest.Mock }).consumeBootstrapCapability)
      .toBeUndefined();
  });

  it("requires a distinct canonical prefix for each active capability", async () => {
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

    await expect(service.create({
      consumerId: "payments-agent",
      environment: "prod",
      capabilities: ["read"],
      readPathPrefixes: ["payments", "payments"],
      writePathPrefixes: [],
      actor: { type: "human", id: "admin" },
    })).rejects.toThrow("duplicate");
  });
});
