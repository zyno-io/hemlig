import type { AgentGrantRecord, ControlRevision } from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { SecretService } from "./secrets";
import { AgentService } from "./agents";

const grant: AgentGrantRecord = {
  pk: "AGENT_GRANT#grant-test",
  sk: "PROFILE",
  grantId: "grant-test",
  consumerId: "payments-agent",
  environment: "prod",
  capabilities: ["read", "write"],
  readSecretIds: ["payments/api"],
  readSecretUids: ["sec-payments-api"],
  writeSecretIds: ["payments/api"],
  writeSecretUids: ["sec-payments-api"],
  status: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
};

const control = (
  secretId: string,
  secretUid = "sec-payments-api",
): ControlRevision => ({
  schemaVersion: 1,
  secretUid,
  secretId,
  controlVersionId: "ctl-current",
  environment: "prod",
  state: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: {},
  acl: [{ consumerId: "payments-agent", permissions: ["read"] }],
});

describe("AgentService", () => {
  it("rejects a secret whose immutable UID is not in the grant before payload read", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => ({
        ...grant,
        readSecretUids: ["sec-a-different-secret"],
      })),
    } as unknown as DynamoRepository;
    const secrets = {
      getControlRevision: jest.fn(async () =>
        control("payments-prod/api", "sec-payments-prod-api"),
      ),
      read: jest.fn(),
    } as unknown as SecretService;
    const service = new AgentService(repository, secrets);

    await expect(
      service.read("payments-agent", "prod", "payments-prod/api", undefined),
    ).rejects.toThrow("does not allow this secret");
    expect(secrets.read).not.toHaveBeenCalled();
  });

  it("does not authorize a reused secret ID after the originally granted UID is archived", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => grant),
    } as unknown as DynamoRepository;
    const secrets = {
      getControlRevision: jest.fn(async () =>
        control("payments/api", "sec-reused-payments-api"),
      ),
      read: jest.fn(),
    } as unknown as SecretService;
    const service = new AgentService(repository, secrets);

    await expect(
      service.read("payments-agent", "prod", "payments/api", undefined),
    ).rejects.toThrow("does not allow this secret");

    expect(secrets.read).not.toHaveBeenCalled();
  });

  it("fails closed for a legacy control revision with no immutable UID", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => grant),
    } as unknown as DynamoRepository;
    const secrets = {
      getControlRevision: jest.fn(async () => ({
        ...control("payments/api"),
        secretUid: undefined,
      })),
      read: jest.fn(),
    } as unknown as SecretService;
    const service = new AgentService(repository, secrets);

    await expect(
      service.read("payments-agent", "prod", "payments/api", undefined),
    ).rejects.toThrow("does not allow this secret");
    expect(secrets.read).not.toHaveBeenCalled();
  });

  it("fails closed instead of throwing when an unmigrated grant has no UID scope", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => {
        const { readSecretUids: _readSecretUids, ...legacyGrant } = grant;
        return legacyGrant as AgentGrantRecord;
      }),
    } as unknown as DynamoRepository;
    const secrets = {
      getControlRevision: jest.fn(async () => control("payments/api")),
      read: jest.fn(),
    } as unknown as SecretService;
    const service = new AgentService(repository, secrets);

    await expect(
      service.read("payments-agent", "prod", "payments/api", undefined),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(secrets.read).not.toHaveBeenCalled();
  });

  it("turns a secret removed from the exact allowlist into a revocation", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => ({
        ...grant,
        readSecretUids: ["sec-a-different-secret"],
      })),
      listAccess: jest.fn(async () => ({
        changes: [
          {
            pk: "CONSUMER#payments-agent",
            sk: "SECRET#prod#sec-payments-api",
            consumerId: "payments-agent",
            secretUid: "sec-payments-api",
            secretId: "payments-api",
            environment: "prod",
            permissions: ["read"],
            controlVersionId: "ctl-moved",
            payloadVersionId: "pay-moved",
            state: "ACTIVE",
            changeKind: "secret.changed",
          },
        ],
      })),
      getHeadBySecretUid: jest.fn(async () => ({
        secretUid: "sec-payments-api",
        secretId: "payments-api",
        environment: "prod",
        metadata: {},
      })),
    } as unknown as DynamoRepository;
    const service = new AgentService(repository, {} as SecretService);

    const result = await service.listChanges("payments-agent", "prod");

    expect(result.changes).toEqual([
      expect.objectContaining({
        secretId: "payments-api",
        state: "REVOKED",
        changeKind: "secret.revoked",
        payloadVersionId: undefined,
      }),
    ]);
  });
});
