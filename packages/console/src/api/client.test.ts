import { describe, expect, it, vi } from "vitest";
import { HemligApi } from "./client";
import type { RuntimeConfig } from "../config";

const config: RuntimeConfig = {
  deploymentName: "hml-test",
  adminApiUrl: "https://admin.example.com",
  auth: { mode: "oidc", authority: "https://idp.example.com", clientId: "c", scopes: ["s"] },
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
    await expect(api.listSecrets({ environment: "dev" })).resolves.toMatchObject({
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
    await api.updateSecret("s", "ctl-1", { metadata: { description: "test secret" } }, "key-123");

    const headers = calls[0]?.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer token");
    expect(headers["idempotency-key"]).toBe("key-123");
    // Quoted, matching the ETag the service returns.
    expect(headers["if-match"]).toBe('"ctl-1"');
    expect(calls[0]?.credentials).toBe("omit");
    expect(calls[0]?.cache).toBe("no-store");
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
    const api = new HemligApi(config, tokens, fetchMock as unknown as typeof fetch);

    await expect(api.getSecretPayload("payments-api")).resolves.toMatchObject({
      payloadVersionId: "pay-2",
    });
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request?.pathname).toBe(
      "/v1/admin/secrets/payments-api/payload",
    );
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
    await expect(api.createEnvironment("staging")).resolves.toMatchObject({ name: "staging" });

    const headers = calls[0]?.headers as Record<string, string>;
    expect(headers["idempotency-key"]).toBeUndefined();
    expect(JSON.parse(String(calls[0]?.body))).toEqual({ name: "staging" });
  });
});
