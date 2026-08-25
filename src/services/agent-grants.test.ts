import type {
  AgentGrantRecord,
  BootstrapCapabilityRecord,
} from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { AgentNotificationService } from "./agent-notifications";
import { AgentGrantService } from "./agent-grants";
import type { ConsumerService } from "./consumers";
import type { EnvironmentService } from "./environments";
import type { SecretService } from "./secrets";

const actor = { type: "human" as const, id: "admin" };

const grant: AgentGrantRecord = {
  pk: "AGENT_GRANT#grant-payments",
  sk: "PROFILE",
  grantId: "grant-payments",
  consumerId: "payments-agent",
  environment: "prod",
  capabilities: ["read"],
  secretGrants: [
    {
      secretId: "payments/api-key",
      secretUid: "sec-payments-api-key",
      permissions: ["read"],
    },
  ],
  status: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: actor,
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
  createdBy: actor,
  consumedFingerprint: "a".repeat(64),
};

const secretService = (): SecretService =>
  ({
    reconcileAgentReadAccess: jest.fn(async () => undefined),
  }) as unknown as SecretService;

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
    const secrets = secretService();
    const service = new AgentGrantService(
      repository,
      consumers,
      {} as EnvironmentService,
      notifications,
      secrets,
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
    expect(secrets.reconcileAgentReadAccess).toHaveBeenCalledWith({
      consumerId: pendingGrant.consumerId,
      environment: pendingGrant.environment,
      secretGrants: pendingGrant.secretGrants,
      actor: expect.objectContaining({ type: "system" }),
    });
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
    const secrets = secretService();
    const service = new AgentGrantService(
      repository,
      consumers,
      {} as EnvironmentService,
      notifications,
      secrets,
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

  it("requires one canonical record per secret and rejects duplicate IDs", async () => {
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
      secretService(),
    );

    await expect(
      service.create({
        consumerId: "payments-agent",
        environment: "prod",
        capabilities: ["read"],
        secretGrants: [
          { secretId: "payments/api-key", permissions: ["read"] },
          { secretId: "payments/api-key", permissions: ["read"] },
        ],
        actor,
      }),
    ).rejects.toThrow("duplicate");
  });

  it("resolves each selected ID once and retains its UID beside that same ID", async () => {
    const repository = {
      getConsumer: jest.fn(async () => undefined),
      requireHead: jest.fn(async (_environment: string, secretId: string) => ({
        secretUid:
          secretId === "payments/alpha"
            ? "sec-z-last-when-sorted"
            : "sec-a-first-when-sorted",
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
      secretService(),
    );

    const created = await service.create({
      consumerId: "payments-agent",
      environment: "prod",
      capabilities: ["read", "write"],
      secretGrants: [
        { secretId: "payments/bravo", permissions: ["write"] },
        { secretId: "payments/alpha", permissions: ["read", "write"] },
      ],
      actor,
    });

    expect(created.secretGrants).toEqual([
      {
        secretId: "payments/alpha",
        secretUid: "sec-z-last-when-sorted",
        permissions: ["read", "write"],
      },
      {
        secretId: "payments/bravo",
        secretUid: "sec-a-first-when-sorted",
        permissions: ["write"],
      },
    ]);
    expect(
      (repository as unknown as { createAgentGrant: jest.Mock })
        .createAgentGrant,
    ).toHaveBeenCalledWith(created);
  });

  it("reconciles an active grant before persisting its new policy", async () => {
    const repository = {
      getAgentGrant: jest.fn(async () => grant),
      requireHead: jest.fn(async (_environment: string, secretId: string) => ({
        secretUid: `sec-${secretId.replaceAll("/", "-")}`,
      })),
      updateAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const secrets = secretService();
    const service = new AgentGrantService(
      repository,
      {} as ConsumerService,
      {} as EnvironmentService,
      {} as AgentNotificationService,
      secrets,
    );

    const updated = await service.update(grant.grantId, {
      capabilities: ["read"],
      secretGrants: [
        {
          secretId: "platform/gitlab-agents/staging",
          permissions: ["read"],
        },
      ],
      displayName: "Staging trusted cluster consumer",
      actor,
    });

    expect(updated.grantId).toBe(grant.grantId);
    expect(updated.secretGrants).toEqual([
      {
        secretId: "platform/gitlab-agents/staging",
        secretUid: "sec-platform-gitlab-agents-staging",
        permissions: ["read"],
      },
    ]);
    expect(secrets.reconcileAgentReadAccess).toHaveBeenCalledWith({
      consumerId: grant.consumerId,
      environment: grant.environment,
      secretGrants: updated.secretGrants,
      actor,
    });
    const reconcileOrder = (
      secrets.reconcileAgentReadAccess as unknown as jest.Mock
    ).mock.invocationCallOrder[0];
    const persistOrder = (
      repository as unknown as { updateAgentGrant: jest.Mock }
    ).updateAgentGrant.mock.invocationCallOrder[0];
    expect(reconcileOrder).toBeDefined();
    expect(persistOrder).toBeDefined();
    expect(reconcileOrder ?? 0).toBeLessThan(persistOrder ?? 0);
    expect(
      (repository as unknown as { updateAgentGrant: jest.Mock })
        .updateAgentGrant,
    ).toHaveBeenCalledWith(updated, false);
  });

  it("allows an administrator to remove the final exact permission", async () => {
    const repository = {
      getAgentGrant: jest.fn(async () => grant),
      updateAgentGrant: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const secrets = secretService();
    const service = new AgentGrantService(
      repository,
      {} as ConsumerService,
      {} as EnvironmentService,
      {} as AgentNotificationService,
      secrets,
    );

    const updated = await service.update(grant.grantId, {
      capabilities: [],
      secretGrants: [],
      actor,
    });

    expect(updated.capabilities).toEqual([]);
    expect(updated.secretGrants).toEqual([]);
    expect(secrets.reconcileAgentReadAccess).toHaveBeenCalledWith(
      expect.objectContaining({ secretGrants: [] }),
    );
  });
});
