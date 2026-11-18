import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { IdentityRejectedError } from "../domain/errors";

jest.mock("../auth/actors", () => ({ consumerActorFromEvent: jest.fn() }));
jest.mock("../app", () => ({ createApplication: jest.fn() }));
jest.mock("../aws/config", () => ({ loadConfig: jest.fn(() => ({})) }));
jest.mock("./shared", () => ({ withErrorResponse: jest.fn() }));
jest.mock("../services/operations", () => ({ humanOperation: jest.fn() }));

const { consumerActorFromEvent } = jest.requireMock("../auth/actors") as {
  readonly consumerActorFromEvent: jest.Mock;
};
const { withErrorResponse } = jest.requireMock("./shared") as {
  readonly withErrorResponse: jest.Mock;
};
const { humanOperation } = jest.requireMock("../services/operations") as {
  readonly humanOperation: jest.Mock;
};

import { handler } from "./identity-rotation";

const actor = {
  type: "consumer",
  id: "caller",
  consumerId: "agent-a",
  environment: "prod",
};

const result = {
  consumerId: "agent-a",
  environment: "prod",
  rootFingerprint: "root",
  apiFingerprint: "new",
  apiCertificatePem: "new-pem",
  notBefore: "2026-01-01T00:00:00.000Z",
  notAfter: "2027-01-01T00:00:00.000Z",
  status: "ACTIVE",
  shouldWriteTerminalAudit: true,
};

const event = (
  overrides: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: unknown;
  } = {},
): APIGatewayProxyEventV2 =>
  ({
    rawPath: overrides.path ?? "/v1/agent/identities/rotate",
    headers: overrides.headers ?? { "idempotency-key": "rotation-123" },
    body: JSON.stringify(
      overrides.body ?? { apiCertificateSigningRequestPem: "CSR" },
    ),
    requestContext: {
      requestId: "request-id",
      http: { method: overrides.method ?? "POST", sourceIp: "127.0.0.1" },
      authentication: { clientCert: { clientCertPem: "caller-pem" } },
    },
  }) as unknown as APIGatewayProxyEventV2;

describe("identity rotation handler", () => {
  const rotate = jest.fn();
  const auditWrite = jest.fn(async () => undefined);

  beforeEach(() => {
    rotate.mockReset();
    auditWrite.mockClear();
    humanOperation.mockReset();
    humanOperation.mockImplementation(
      async (
        _app: unknown,
        _actor: unknown,
        _key: string,
        _correlationId: string,
        _operation: string,
        _sourceIp: string,
        _target: unknown,
        response: () => unknown,
      ) => response(),
    );
    rotate.mockImplementation(
      async (input: { onAuthorized?: () => Promise<void> }) => {
        await input.onAuthorized?.();
        return result;
      },
    );
    consumerActorFromEvent.mockResolvedValue(actor);
    withErrorResponse.mockImplementation(
      async (
        incoming: APIGatewayProxyEventV2,
        action: (
          app: unknown,
          correlationId: string,
          setAuditContext: () => void,
        ) => unknown,
      ) =>
        action(
          {
            repository: {},
            agentIdentities: { rotate },
            audit: { write: auditWrite },
          },
          incoming.requestContext.requestId,
          () => undefined,
        ),
    );
  });

  it.each([
    ["wrong method", { method: "GET" }],
    ["wrong path", { path: "/v1/agent/identities" }],
  ])("rejects a %s", async (_name, overrides) => {
    await expect(handler(event(overrides))).rejects.toMatchObject({
      statusCode: 400,
    });
    expect(rotate).not.toHaveBeenCalled();
  });

  it("requires an Idempotency-Key", async () => {
    await expect(handler(event({ headers: {} }))).rejects.toMatchObject({
      statusCode: 400,
      code: "bad_request",
    });
    expect(rotate).not.toHaveBeenCalled();
  });

  it("requires a string CSR", async () => {
    await expect(handler(event({ body: {} }))).rejects.toMatchObject({
      code: "bad_request",
    });
  });

  it("rejects an oversized CSR as invalid_csr", async () => {
    await expect(
      handler(
        event({
          body: { apiCertificateSigningRequestPem: "x".repeat(16_385) },
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid_csr" });
  });

  it("returns 201 with the new leaf and audits the operation", async () => {
    const response = await handler(event());
    expect(response.statusCode).toBe(201);
    expect(JSON.parse(response.body as string)).toEqual({
      consumerId: "agent-a",
      environment: "prod",
      rootFingerprint: "root",
      apiFingerprint: "new",
      apiCertificatePem: "new-pem",
      notBefore: result.notBefore,
      notAfter: result.notAfter,
      status: "ACTIVE",
    });
    expect(rotate).toHaveBeenCalledWith(
      expect.objectContaining({
        callerCertificatePem: "caller-pem",
        apiCertificateSigningRequestPem: "CSR",
        idempotencyKey: "rotation-123",
      }),
    );
    expect(
      (auditWrite.mock.calls as unknown as [{ outcome: string }][]).map(
        ([entry]) => entry.outcome,
      ),
    ).toEqual(["attempted", "authorized"]);
    expect(humanOperation).toHaveBeenCalledWith(
      expect.anything(),
      actor,
      "rotation-123",
      "request-id",
      "agent.identity.rotate",
      "127.0.0.1",
      { consumerId: "agent-a", apiFingerprint: "new" },
      expect.any(Function),
    );
  });

  it("does not write a terminal audit for a completed replay", async () => {
    rotate.mockResolvedValue({ ...result, shouldWriteTerminalAudit: false });
    const response = await handler(event());
    expect(response.statusCode).toBe(201);
    expect(humanOperation).not.toHaveBeenCalled();
  });

  it("audits a rotation attempted with a revoked certificate", async () => {
    const { createApplication } = jest.requireMock("../app") as {
      readonly createApplication: jest.Mock;
    };
    const { withErrorResponse: realWrapper } = jest.requireActual(
      "./shared",
    ) as { readonly withErrorResponse: typeof withErrorResponse };
    createApplication.mockReturnValue({
      audit: { write: auditWrite },
      repository: {},
    });
    withErrorResponse.mockImplementation(realWrapper);
    consumerActorFromEvent.mockRejectedValue(
      new IdentityRejectedError(
        { type: "consumer", id: "fp", consumerId: "agent-a", environment: "prod" },
        "The client certificate is not an active consumer API identity.",
      ),
    );

    const response = await handler(event());

    expect(response.statusCode).toBe(403);
    expect(auditWrite).toHaveBeenCalledTimes(1);
    expect(auditWrite).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        actor: { type: "consumer", id: "fp", consumerId: "agent-a", environment: "prod" },
        operation: "agent.identity.rotate",
        sourceIp: "127.0.0.1",
        reasonCode: "identity_not_active",
      }),
    );
  });
});
