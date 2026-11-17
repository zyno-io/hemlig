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
  let nextReadIsNotModified = false;
  const read = jest.fn(async (...parameters: unknown[]) => {
    // Mirrors SecretService.read: onAuthorized runs only when a value is returned.
    const onAuthorized = parameters[4] as (() => Promise<void>) | undefined;
    if (!nextReadIsNotModified) {
      await onAuthorized?.();
    }
    return {
      controlVersionId: control.controlVersionId,
      payloadVersionId: control.payloadVersionId,
      payload: { token: { encoding: "base64", value: "dG9rZW4=" } },
      notModified: nextReadIsNotModified,
    };
  });
  const auditWrite = jest.fn(async () => undefined);
  const sync = jest.fn(async () => ({
    config: {},
    snapshot: false,
    changes: [],
    syncCursor: "checkpoint",
  }));

  beforeEach(() => {
    update.mockClear();
    read.mockClear();
    auditWrite.mockClear();
    nextReadIsNotModified = false;
    sync.mockClear();
    consumerActorFromEvent.mockResolvedValue({
      type: "consumer",
      id: "agent-fingerprint",
      consumerId: "staging-trusted",
      environment: "staging",
    });
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          app: unknown,
          correlationId: string,
          setAuditContext: () => void,
        ) => unknown,
      ) =>
        action(
          {
            config: { maxPayloadBytes: 1_000_000 },
            agents: { update, read },
            agentSync: { sync },
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

  it("passes scoped opaque cursors to agent synchronization without a payload read", async () => {
    const event = {
      rawPath: "/v1/agent/sync",
      queryStringParameters: { syncCursor: "opaque" },
      headers: {},
      requestContext: {
        requestId: "sync-request",
        http: { method: "GET", sourceIp: "127.0.0.1" },
      },
    } as unknown as APIGatewayProxyEventV2;
    const response = await handler(event);
    expect(sync).toHaveBeenCalledWith(
      "staging-trusted",
      "staging",
      { syncCursor: "opaque", cursor: undefined },
      {},
    );
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body as string)).toMatchObject({
      changes: [],
      syncCursor: "checkpoint",
    });
    expect(update).not.toHaveBeenCalled();
  });

  const readEvent = (headers: Record<string, string> = {}) =>
    ({
      rawPath:
        "/v1/agent/secrets/platform%2Faccess%2Fwarpgate%2Ftarget-sync%2Fedge",
      headers,
      requestContext: {
        requestId: "request-id",
        http: { method: "GET", sourceIp: "127.0.0.1" },
      },
    }) as unknown as APIGatewayProxyEventV2;
  const outcomes = () =>
    (auditWrite.mock.calls as unknown as [{ outcome: string }][]).map(
      ([entry]) => entry.outcome,
    );

  it("audits a read that delivers a value", async () => {
    const response = await handler(readEvent());

    expect(response.statusCode).toBe(200);
    expect(read).toHaveBeenCalledWith(
      "staging-trusted",
      "staging",
      "platform/access/warpgate/target-sync/edge",
      undefined,
      expect.any(Function),
    );
    expect(outcomes()).toEqual(["attempted", "authorized", "succeeded"]);
  });

  it("writes no audit events for a conditional 304 read", async () => {
    nextReadIsNotModified = true;

    const response = await handler(readEvent({ "if-none-match": '"ctl-next"' }));

    expect(response.statusCode).toBe(304);
    expect(auditWrite).not.toHaveBeenCalled();
  });
});
