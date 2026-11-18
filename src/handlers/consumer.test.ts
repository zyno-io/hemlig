import type { APIGatewayProxyEventV2 } from "aws-lambda";
import type { ControlRevision } from "../domain/types";
import { IdentityRejectedError } from "../domain/errors";

jest.mock("../auth/actors", () => ({
  consumerActorFromEvent: jest.fn(),
}));

jest.mock("./shared", () => ({ withErrorResponse: jest.fn() }));
jest.mock("../app", () => ({ createApplication: jest.fn() }));
jest.mock("../aws/config", () => ({ loadConfig: jest.fn(() => ({})) }));

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
            agents: { update, read, control: jest.fn(async () => control) },
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

  const syncEvent = () =>
    ({
      rawPath: "/v1/agent/sync",
      headers: {},
      requestContext: {
        requestId: "sync-request",
        http: { method: "GET", sourceIp: "127.0.0.1" },
      },
    }) as unknown as APIGatewayProxyEventV2;

  it("writes no audit events for a successful agent sync", async () => {
    const response = await handler(syncEvent());

    expect(response.statusCode).toBe(200);
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it("records a failed agent sync through the real error wrapper", async () => {
    const { createApplication } = jest.requireMock("../app") as {
      readonly createApplication: jest.Mock;
    };
    const { withErrorResponse: realWrapper } = jest.requireActual(
      "./shared",
    ) as { readonly withErrorResponse: typeof withErrorResponse };
    createApplication.mockReturnValue({
      audit: { write: auditWrite },
      agentSync: {
        sync: jest.fn(async () => {
          throw new Error("repository failure");
        }),
      },
      repository: { getAgentGrantForConsumer: jest.fn(async () => ({})) },
    });
    withErrorResponse.mockImplementation(realWrapper);
    jest.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await handler(syncEvent());

    expect(response.statusCode).toBe(500);
    expect(outcomes()).toEqual(["failed"]);
    expect(auditWrite).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "agentget:/v1/agent/sync",
        reasonCode: "request_failed",
      }),
    );
  });

  it("still writes attempted for a non-read route", async () => {
    await expect(
      handler({
        ...syncEvent(),
        rawPath: "/v1/agent/unknown-route",
      } as APIGatewayProxyEventV2),
    ).rejects.toBeDefined();
    expect(outcomes()[0]).toBe("attempted");
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

    const response = await handler(
      readEvent({ "if-none-match": '"ctl-next"' }),
    );

    expect(response.statusCode).toBe(304);
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it("still audits the agent control route from its first event", async () => {
    const response = await handler({
      ...readEvent(),
      rawPath:
        "/v1/agent/secrets/platform%2Faccess%2Fwarpgate%2Ftarget-sync%2Fedge/control",
    } as APIGatewayProxyEventV2);

    expect(response.statusCode).toBe(200);
    expect(outcomes()).toEqual(["attempted", "authorized", "succeeded"]);
  });

  it("writes attempted before rejecting a malformed request path", async () => {
    await expect(
      handler({
        ...readEvent(),
        rawPath: "/v1/secrets/%E0%A4%A",
      } as APIGatewayProxyEventV2),
    ).rejects.toMatchObject({ code: "bad_request" });
    expect(outcomes()).toEqual(["attempted"]);
  });

  describe("failures before the final audit context", () => {
    const useRealWrapper = (
      getAgentGrantForConsumer: jest.Mock = jest.fn(async () => ({})),
      claimIdentityRejectionAudit: jest.Mock = jest.fn(async () => true),
    ) => {
      // The real wrapper caches its application at module scope, so reuse
      // that cached object and point its fakes at this scenario.
      const { createApplication } = jest.requireMock("../app") as {
        readonly createApplication: jest.Mock;
      };
      createApplication.mockReturnValue({
        audit: { write: auditWrite },
        repository: { getAgentGrantForConsumer, claimIdentityRejectionAudit },
      });
      const shared = jest.requireActual("./shared") as {
        readonly withErrorResponse: typeof withErrorResponse;
        readonly getApplication: () => {
          audit: { write: unknown };
          repository: {
            getAgentGrantForConsumer: unknown;
            claimIdentityRejectionAudit: unknown;
          };
        };
      };
      const app = shared.getApplication();
      app.audit.write = auditWrite;
      app.repository.getAgentGrantForConsumer = getAgentGrantForConsumer;
      app.repository.claimIdentityRejectionAudit = claimIdentityRejectionAudit;
      const realWrapper = shared.withErrorResponse;
      withErrorResponse.mockImplementation(realWrapper);
      jest.spyOn(console, "error").mockImplementation(() => undefined);
    };
    const events = () =>
      (auditWrite.mock.calls as unknown as [Record<string, unknown>][]).map(
        ([entry]) => entry,
      );

    it("audits a rejected identity with its fingerprint and attributes", async () => {
      useRealWrapper();
      consumerActorFromEvent.mockRejectedValue(
        new IdentityRejectedError(
          {
            type: "consumer",
            id: "fp",
            consumerId: "staging-trusted",
            environment: "staging",
          },
          "The client certificate is not an active consumer API identity.",
        ),
      );

      const response = await handler(readEvent());

      expect(response.statusCode).toBe(403);
      expect(JSON.parse(response.body as string).error).toMatchObject({
        code: "identity_not_active",
        message: "The client certificate is not an active consumer API identity.",
      });
      expect(events()).toEqual([
        expect.objectContaining({
          outcome: "failed",
          actor: {
            type: "consumer",
            id: "fp",
            consumerId: "staging-trusted",
            environment: "staging",
          },
          operation:
            "consumerget:/v1/agent/secrets/platform%2Faccess%2Fwarpgate%2Ftarget-sync%2Fedge",
          sourceIp: "127.0.0.1",
          reasonCode: "identity_not_active",
        }),
      ]);
    });

    describe("rejection rate limit", () => {
      const rejected = () =>
        consumerActorFromEvent.mockRejectedValue(
          new IdentityRejectedError(
            { type: "consumer", id: "fp", consumerId: "c", environment: "staging" },
            "The client certificate is not an active consumer API identity.",
          ),
        );

      it("records the first rejection, suppresses a repeat, and records again after the window", async () => {
        const claim = jest
          .fn()
          .mockResolvedValueOnce(true)
          .mockResolvedValueOnce(false)
          .mockResolvedValueOnce(true);
        useRealWrapper(undefined, claim);
        rejected();

        const first = await handler(readEvent());
        expect(auditWrite).toHaveBeenCalledTimes(1);
        const second = await handler(readEvent());
        expect(auditWrite).toHaveBeenCalledTimes(1);
        expect(second.statusCode).toBe(403);
        expect(second.body?.replace(/"correlationId":"[^"]*"/, "")).toBe(
          first.body?.replace(/"correlationId":"[^"]*"/, ""),
        );
        await handler(readEvent());
        expect(auditWrite).toHaveBeenCalledTimes(2);
        expect(claim).toHaveBeenCalledWith("fp", 600);
      });

      it("fails open when the limiter errors", async () => {
        useRealWrapper(
          undefined,
          jest.fn(async () => {
            throw new Error("dynamo down");
          }),
        );
        rejected();

        const response = await handler(readEvent());

        expect(response.statusCode).toBe(403);
        expect(events()).toEqual([
          expect.objectContaining({ outcome: "failed", reasonCode: "identity_not_active" }),
        ]);
      });
    });

    it("audits an unknown fingerprint with only the fingerprint", async () => {
      useRealWrapper();
      consumerActorFromEvent.mockRejectedValue(
        new IdentityRejectedError({ type: "consumer", id: "fp" }, "no"),
      );

      await handler(readEvent());

      expect(events()).toHaveLength(1);
      expect(events()[0]).toMatchObject({
        outcome: "failed",
        actor: { type: "consumer", id: "fp" },
        reasonCode: "identity_not_active",
      });
      expect(events()[0]?.actor).toEqual({ type: "consumer", id: "fp" });
    });

    it("writes no events when there is no usable certificate", async () => {
      useRealWrapper();
      const { identityNotActive } = jest.requireActual(
        "../domain/errors",
      ) as typeof import("../domain/errors");
      consumerActorFromEvent.mockRejectedValue(identityNotActive("none"));

      const response = await handler(readEvent());

      expect(response.statusCode).toBe(403);
      expect(auditWrite).not.toHaveBeenCalled();
    });

    it.each([
      ["consumerId", { type: "consumer", id: "fp", environment: "staging" }],
      ["environment", { type: "consumer", id: "fp", consumerId: "c" }],
    ])("audits an actor without %s", async (_name, actor) => {
      useRealWrapper();
      consumerActorFromEvent.mockResolvedValue(actor);

      const response = await handler(readEvent());

      expect(response.statusCode).toBe(403);
      expect(events()).toEqual([
        expect.objectContaining({
          outcome: "failed",
          actor,
          reasonCode: "request_failed",
          operation: expect.stringMatching(/^consumerget:/),
        }),
      ]);
    });

    it("audits a failing grant lookup", async () => {
      useRealWrapper(
        jest.fn(async () => {
          throw new Error("lookup failed");
        }),
      );

      const response = await handler(readEvent());

      expect(response.statusCode).toBe(500);
      expect(events()).toEqual([
        expect.objectContaining({
          outcome: "failed",
          operation: expect.stringMatching(/^consumerget:/),
          reasonCode: "request_failed",
        }),
      ]);
    });
  });
});
