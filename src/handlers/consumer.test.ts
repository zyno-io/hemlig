import type { APIGatewayProxyEventV2 } from "aws-lambda";
import type { ControlRevision } from "../domain/types";

jest.mock("../auth/actors", () => ({
  consumerActorFromEvent: jest.fn(),
}));

jest.mock("./shared", () => ({ withErrorResponse: jest.fn() }));

const { consumerActorFromEvent } = jest.requireMock("../auth/actors") as {
  readonly consumerActorFromEvent: jest.Mock;
};
const { withErrorResponse } = jest.requireMock("./shared") as {
  readonly withErrorResponse: jest.Mock;
};

import { handler } from "./consumer";

const control: ControlRevision = {
  schemaVersion: 1,
  secretUid: "sec-edge",
  secretId: "platform/access/warpgate/target-sync/edge",
  controlVersionId: "ctl-next",
  payloadVersionId: "pay-next",
  environment: "staging",
  state: "ACTIVE",
  createdAt: "2026-08-26T00:00:00.000Z",
  createdBy: { type: "consumer", id: "agent" },
  metadata: {},
  acl: [],
};

describe("consumer handler agent routes", () => {
  const update = jest.fn(async () => control);
  const auditWrite = jest.fn(async () => undefined);

  beforeEach(() => {
    update.mockClear();
    auditWrite.mockClear();
    consumerActorFromEvent.mockResolvedValue({
      type: "consumer",
      id: "agent-fingerprint",
      consumerId: "staging-trusted",
      environment: "staging",
    });
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (app: unknown, correlationId: string, setAuditContext: () => void) => unknown,
      ) =>
        action(
          {
            config: { maxPayloadBytes: 1_000_000 },
            agents: { update },
            audit: { write: auditWrite },
            repository: {
              getAgentGrantForConsumer: jest.fn(async () => ({})),
            },
          },
          event.requestContext.requestId ?? "request-id",
          () => undefined,
        ),
    );
  });

  it("routes an encoded agent payload write to its payload handler", async () => {
    const event = {
      rawPath:
        "/v1/agent/secrets/platform%2Faccess%2Fwarpgate%2Ftarget-sync%2Fedge/payload",
      body: JSON.stringify({
        payload: { tls: { encoding: "base64", value: "Y2VydGlmaWNhdGU=" } },
      }),
      headers: {
        "idempotency-key": "agent-payload-route",
        "if-match": "ctl-current",
      },
      requestContext: {
        requestId: "request-id",
        http: { method: "PUT", sourceIp: "127.0.0.1" },
      },
    } as unknown as APIGatewayProxyEventV2;

    const response = await handler(event);

    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        secretId: "platform/access/warpgate/target-sync/edge",
        expectedControlVersionId: "ctl-current",
        payload: {
          tls: { encoding: "base64", value: "Y2VydGlmaWNhdGU=" },
        },
      }),
    );
    expect(response.statusCode).toBe(200);
  });
});
