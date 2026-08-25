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
  readSecretIdPrefixes: ["payments"],
  writeSecretIdPrefixes: ["payments"],
  status: "ACTIVE",
  createdAt: "2026-08-23T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
};

const control = (secretId: string): ControlRevision => ({
  schemaVersion: 1,
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
  it("rejects a lookalike secret ID before the payload-read service is reached", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => grant),
    } as unknown as DynamoRepository;
    const secrets = {
      getControlRevision: jest.fn(async () => control("payments-prod/api")),
      read: jest.fn(),
    } as unknown as SecretService;
    const service = new AgentService(repository, secrets);

    await expect(
      service.read("payments-agent", "prod", "payments-prod/api", undefined),
    ).rejects.toThrow("secret ID");
    expect(secrets.read).not.toHaveBeenCalled();
  });

  it("turns an out-of-scope secret-ID move into a revocation", async () => {
    const repository = {
      getAgentGrantForConsumer: jest.fn(async () => grant),
      listAccess: jest.fn(async () => ({
        changes: [
          {
            pk: "CONSUMER#payments-agent",
            sk: "SECRET#prod#payments-api",
            consumerId: "payments-agent",
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
      getHead: jest.fn(async () => ({
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
