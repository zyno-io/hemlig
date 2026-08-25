import { describe, expect, it, vi } from "vitest";
import { HemligApi } from "./client";
import type { RuntimeConfig } from "../config";

const config: RuntimeConfig = {
  deploymentName: "hml-test",
  adminApiUrl: "https://admin.example.com",
  auth: {
    mode: "oidc",
    authority: "https://idp.example.com",
    clientId: "c",
    scopes: ["s"],
  },
};

const tokens = { accessToken: async () => "token" };

const jsonOk = (body: unknown) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

describe("HemligApi transport", () => {
  it("calls the ambient fetch without rebinding its receiver", async () => {
    // Holding window.fetch on an instance and invoking it as this.fetchImpl()
    // throws "Illegal invocation" in a browser. This guards that regression by
    // rejecting any call whose receiver is not the global object.
    const real = vi.fn(async function (this: unknown) {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return jsonOk({ secrets: [], generatedAt: "2026-08-23T00:00:00.000Z" });
    });
    vi.stubGlobal("fetch", real);

    const api = new HemligApi(config, tokens);
    await expect(
      api.listSecrets({ environment: "dev" }),
    ).resolves.toMatchObject({
      secrets: [],
    });

    vi.unstubAllGlobals();
  });

  it("sends the administrator headers a mutation requires", async () => {
    const calls: RequestInit[] = [];
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      calls.push(init ?? {});
      return jsonOk({
        schemaVersion: 1,
        secretId: "s",
        controlVersionId: "ctl-2",
        environment: "dev",
        state: "ACTIVE",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "a" },
        metadata: { description: "test secret" },
        acl: [],
      });
    }) as unknown as typeof fetch;

    const api = new HemligApi(config, tokens, fetchImpl);
    await api.updateSecret(
      "dev",
      "s",
      "ctl-1",
      { metadata: { description: "test secret" } },
      "key-123",
    );

    const headers = calls[0]?.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer token");
    expect(headers["idempotency-key"]).toBe("key-123");
    // Quoted, matching the ETag the service returns.
    expect(headers["if-match"]).toBe('"ctl-1"');
    expect(calls[0]?.credentials).toBe("omit");
    expect(calls[0]?.cache).toBe("no-store");
  });

  it("archives with the current ETag and targets the dedicated archive route", async () => {
    const fetchMock = vi.fn(async (_url: URL, _options?: RequestInit) =>
      jsonOk({
        schemaVersion: 1,
        secretUid: "sec-payments",
        secretId: "payments-api",
        controlVersionId: "ctl-archived",
        environment: "dev",
        state: "ARCHIVED",
        createdAt: "2026-08-25T00:00:00.000Z",
        createdBy: { type: "human", id: "a" },
        metadata: {},
        acl: [],
      }),
    );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await api.archiveSecret("dev", "payments-api", "ctl-1", "archive-key");

    const request = fetchMock.mock.calls[0]?.[0];
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(request?.pathname).toBe("/v1/admin/secrets/payments-api/archive");
    expect(request?.searchParams.get("environment")).toBe("dev");
    expect(options.method).toBe("POST");
    const headers = options.headers as Record<string, string>;
    expect(headers["idempotency-key"]).toBe("archive-key");
    expect(headers["if-match"]).toBe('"ctl-1"');
  });

  it("lists and revokes a consumer's encoded secret grant", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonOk({
          consumerId: "prod-east",
          environment: "prod",
          grants: [
            {
              secretUid: "sec-postgres",
              secretId: "platform/database/postgres",
              permissions: ["read"],
              controlVersionId: "ctl-postgres",
              state: "ACTIVE",
            },
          ],
          generatedAt: "2026-08-25T00:00:00.000Z",
        }),
      )
      .mockResolvedValueOnce(
        jsonOk({
          schemaVersion: 1,
          secretUid: "sec-postgres",
          secretId: "platform/database/postgres",
          controlVersionId: "ctl-revoked",
          environment: "prod",
          state: "ACTIVE",
          createdAt: "2026-08-25T00:00:00.000Z",
          createdBy: { type: "human", id: "admin" },
          metadata: {},
          acl: [],
        }),
      );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await api.listConsumerSecretGrants("prod-east", "cursor-1");
    await api.revokeConsumerSecretGrant(
      "prod-east",
      "platform/database/postgres",
      "revoke-grant-key",
    );

    const listRequest = fetchMock.mock.calls[0]?.[0];
    expect(listRequest?.pathname).toBe("/v1/admin/consumers/prod-east/grants");
    expect(listRequest?.searchParams.get("cursor")).toBe("cursor-1");
    const revokeRequest = fetchMock.mock.calls[1]?.[0];
    const revokeOptions = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(revokeRequest?.pathname).toBe(
      "/v1/admin/consumers/prod-east/grants/platform%2Fdatabase%2Fpostgres",
    );
    expect(revokeOptions.method).toBe("DELETE");
    expect(
      (revokeOptions.headers as Record<string, string>)["idempotency-key"],
    ).toBe("revoke-grant-key");
  });

  it("updates an AgentGrant with the remaining exact permissions", async () => {
    const fetchMock = vi.fn(async (_url: URL, _options?: RequestInit) =>
      jsonOk({
        grantId: "grant-prod-east",
        consumerId: "prod-east",
        environment: "prod",
        capabilities: ["read", "write"],
        readSecretIds: [],
        readSecretUids: [],
        writeSecretIds: ["platform/database/postgres"],
        writeSecretUids: ["sec-postgres"],
        status: "ACTIVE",
        createdAt: "2026-08-25T00:00:00.000Z",
      }),
    );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await api.updateAgentGrant("grant-prod-east", {
      capabilities: ["read", "write"],
      readSecretIds: [],
      writeSecretIds: ["platform/database/postgres"],
    });

    const request = fetchMock.mock.calls[0]?.[0];
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(request?.pathname).toBe("/v1/admin/agent-grants/grant-prod-east");
    expect(options.method).toBe("PUT");
    expect(JSON.parse(options.body as string)).toEqual({
      capabilities: ["read", "write"],
      readSecretIds: [],
      writeSecretIds: ["platform/database/postgres"],
    });
  });

  it("queries archived catalog entries only when the caller opts in", async () => {
    const fetchMock = vi.fn(async (_url: URL, _options?: RequestInit) =>
      jsonOk({ secrets: [], generatedAt: "2026-08-25T00:00:00.000Z" }),
    );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await api.listSecrets({
      environment: "dev",
      q: "payments",
      archived: true,
    });

    const request = fetchMock.mock.calls[0]?.[0];
    expect(request?.searchParams.get("archived")).toBe("true");
  });

  it("reads the current payload through the authenticated administrator route", async () => {
    const fetchMock = vi.fn(async (_url: URL, _options?: RequestInit) =>
      jsonOk({
        secretId: "payments-api",
        controlVersionId: "ctl-2",
        payloadVersionId: "pay-2",
        payload: { PASSWORD: { encoding: "utf8", value: "value" } },
      }),
    );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await expect(
      api.getSecretPayload("dev", "payments-api"),
    ).resolves.toMatchObject({
      payloadVersionId: "pay-2",
    });
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request?.pathname).toBe("/v1/admin/secrets/payments-api/payload");
    expect(request?.searchParams.get("environment")).toBe("dev");
  });

  it("reads a caller-bound audit archive page", async () => {
    const fetchMock = vi.fn(async (_url: URL, _options?: RequestInit) =>
      jsonOk({
        date: "2026-08-23",
        events: [
          {
            eventId: "event-1",
            at: "2026-08-23T10:00:00.000Z",
            correlationId: "corr-1",
            outcome: "succeeded",
            actor: { type: "human", id: "admin-1" },
            operation: "adminget:/v1/admin/secrets",
          },
        ],
        nextCursor: "signed-next",
        generatedAt: "2026-08-23T10:00:01.000Z",
      }),
    );
    const api = new HemligApi(
      config,
      tokens,
      fetchMock as unknown as typeof fetch,
    );

    await expect(
      api.listAudit({
        date: "2026-08-23",
        secretId: "payments-api",
        cursor: "signed-prior",
      }),
    ).resolves.toMatchObject({
      nextCursor: "signed-next",
    });
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request?.pathname).toBe("/v1/admin/audit");
    expect(request?.searchParams.get("date")).toBe("2026-08-23");
    expect(request?.searchParams.get("secretId")).toBe("payments-api");
    expect(request?.searchParams.get("cursor")).toBe("signed-prior");
  });

  it("reports a transport failure as an unknown outcome and keeps the cause", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;

    const api = new HemligApi(config, tokens, fetchImpl);
    await expect(api.getIssuer()).rejects.toMatchObject({
      code: "network",
      outcomeUnknown: true,
      transportDetail: "TypeError: Failed to fetch",
    });
  });

  it("creates an environment without an Idempotency-Key, unlike every other admin mutation", async () => {
    const calls: RequestInit[] = [];
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      calls.push(init ?? {});
      return jsonOk({
        name: "staging",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "a" },
      });
    }) as unknown as typeof fetch;

    const api = new HemligApi(config, tokens, fetchImpl);
    await expect(api.createEnvironment("staging")).resolves.toMatchObject({
      name: "staging",
    });

    const headers = calls[0]?.headers as Record<string, string>;
    expect(headers["idempotency-key"]).toBeUndefined();
    expect(JSON.parse(String(calls[0]?.body))).toEqual({ name: "staging" });
  });
});
