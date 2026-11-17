import { ApiError } from "../domain/errors";
import type { DynamoRepository } from "../repositories/dynamo";
import type { AgentNotificationService } from "./agent-notifications";
import { AgentIdentityService } from "./agent-identities";
import type { ConsumerService } from "./consumers";
import type { IssuerService } from "./issuer";

const actor = {
  type: "consumer" as const,
  id: "caller",
  consumerId: "agent-a",
  environment: "prod",
};

const rotated = {
  consumerId: "agent-a",
  environment: "prod",
  rootFingerprint: "root",
  apiFingerprint: "new",
  apiCertificatePem: "new-pem",
  status: "ACTIVE" as const,
  notBefore: "2026-01-01T00:00:00.000Z",
  notAfter: "2999-01-01T00:00:00.000Z",
  identityStatus: "ACTIVE" as const,
  shouldWriteTerminalAudit: true,
};

const build = (
  options: {
    grant?: unknown;
    matches?: boolean | Error;
    rotate?: unknown;
  } = {},
) => {
  const order: string[] = [];
  const repository = {
    getAgentGrantForConsumer: jest.fn(async () => {
      order.push("grant");
      return "grant" in options
        ? options.grant
        : { consumerId: "agent-a", environment: "prod", status: "ACTIVE" };
    }),
  };
  const issuer = {
    certificateRequestMatchesCertificate: jest.fn(() => {
      order.push("csr");
      if (options.matches instanceof Error) throw options.matches;
      return options.matches ?? false;
    }),
  };
  const consumers = {
    rotateApiIdentity: jest.fn(async () => {
      order.push("rotate");
      return options.rotate ?? rotated;
    }),
  };
  const notifications = { provision: jest.fn(async () => undefined) };
  const service = new AgentIdentityService(
    repository as unknown as DynamoRepository,
    consumers as unknown as ConsumerService,
    issuer as unknown as IssuerService,
    notifications as unknown as AgentNotificationService,
  );
  const call = (onAuthorized?: () => Promise<void>) =>
    service.rotate({
      actor,
      callerCertificatePem: "caller-pem",
      apiCertificateSigningRequestPem: "CSR",
      idempotencyKey: "rotation-123",
      onAuthorized,
    });
  return { call, order, consumers, notifications, issuer };
};

describe("AgentIdentityService.rotate", () => {
  it.each([
    ["no grant", undefined],
    [
      "a pending grant",
      { consumerId: "agent-a", environment: "prod", status: "PENDING" },
    ],
  ])("rejects %s without rotating", async (_name, grant) => {
    const { call, consumers } = build({ grant });
    await expect(call()).rejects.toMatchObject({
      statusCode: 403,
      code: "forbidden",
    });
    expect(consumers.rotateApiIdentity).not.toHaveBeenCalled();
  });

  it("maps a malformed CSR to invalid_csr", async () => {
    const { call, consumers } = build({
      matches: new ApiError(400, "bad_request", "malformed"),
    });
    await expect(call()).rejects.toMatchObject({
      statusCode: 400,
      code: "invalid_csr",
    });
    expect(consumers.rotateApiIdentity).not.toHaveBeenCalled();
  });

  it("rejects a CSR that reuses the caller's key", async () => {
    const { call, consumers } = build({ matches: true });
    await expect(call()).rejects.toMatchObject({
      statusCode: 400,
      code: "invalid_csr",
    });
    expect(consumers.rotateApiIdentity).not.toHaveBeenCalled();
  });

  it("calls onAuthorized after the grant check and before rotation", async () => {
    const { call, order } = build();
    await call(async () => {
      order.push("authorized");
    });
    expect(order).toEqual(["grant", "authorized", "csr", "rotate"]);
  });

  it("rotates with the cap and provisions the new leaf", async () => {
    const { call, consumers, notifications } = build();
    const result = await call();
    expect(consumers.rotateApiIdentity).toHaveBeenCalledWith(
      expect.objectContaining({
        selfRotation: {
          callerFingerprint: "caller",
          maximumActiveIdentities: 3,
        },
      }),
    );
    expect(notifications.provision).toHaveBeenCalledWith({
      consumerId: "agent-a",
      certificateFingerprint: "new",
      certificatePem: "new-pem",
    });
    expect(result).toMatchObject({
      apiFingerprint: "new",
      notAfter: rotated.notAfter,
    });
  });

  it("still provisions on an idempotent replay", async () => {
    const { call, notifications } = build({
      rotate: { ...rotated, shouldWriteTerminalAudit: false },
    });
    const result = await call();
    expect(result.shouldWriteTerminalAudit).toBe(false);
    expect(notifications.provision).toHaveBeenCalledTimes(1);
  });

  it("rejects a replay whose leaf is no longer active", async () => {
    const { call, notifications } = build({
      rotate: { ...rotated, identityStatus: "REVOKED" },
    });
    await expect(call()).rejects.toMatchObject({
      statusCode: 409,
      code: "rotation_replay_inactive",
    });
    expect(notifications.provision).not.toHaveBeenCalled();
  });
});
