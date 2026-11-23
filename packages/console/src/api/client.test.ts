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
        secretGrants: [
          {
            secretId: "platform/database/postgres",
            secretUid: "sec-postgres",
            permissions: ["write"],
          },
        ],
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
      secretGrants: [
        {
          secretId: "platform/database/postgres",
          permissions: ["write"],
        },
      ],
    });

    const request = fetchMock.mock.calls[0]?.[0];
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(request?.pathname).toBe("/v1/admin/agent-grants/grant-prod-east");
    expect(options.method).toBe("PUT");
    expect(JSON.parse(options.body as string)).toEqual({
      capabilities: ["read", "write"],
      secretGrants: [
        {
          secretId: "platform/database/postgres",
          permissions: ["write"],
        },
      ],
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

describe("HemligApi PKI transport", () => {
  const actor = { type: "human", id: "a" };
  const grantBody = {
    consumerId: "c/1",
    environment: "prod",
    name: "web",
    uid: "pkg-1",
    caId: "ca-abc",
    status: "ACTIVE",
    expired: false,
    policy: {},
    policyDigest: "d",
    quotas: { perHour: 1, perDay: 2 },
    version: "v7",
    createdAt: "2026-01-01T00:00:00Z",
    createdBy: actor,
    updatedAt: "2026-01-01T00:00:00Z",
    updatedBy: actor,
  };
  const caBody = {
    caId: "ca-abc",
    environment: "prod",
    name: "prod-issuing-1",
    kind: "EXTERNAL_INTERMEDIATE",
    status: "ACTIVE",
    version: "v3",
    keyAlgorithm: "ECDSA_P256",
    keyState: "ACTIVE",
    createdAt: "2026-01-01T00:00:00Z",
    key: { custody: "KMS", algorithm: "ECDSA_P256", spkiSha256: "x", state: "ACTIVE" },
    subject: { commonName: "x" },
    subjectDn: "CN=x",
    requestedConstraints: {},
    crlIssuers: [],
    policy: {
      issueLeaves: true,
      issueSubordinates: false,
      maxLeafLifetimeSeconds: 300,
      leafKeyAlgorithms: [],
      capacity: 1,
      issuancePerHour: 1,
      crlValiditySeconds: 3600,
    },
    maxIssueLifetimeEverSeconds: 1,
    createdBy: actor,
    drained: false,
  };

  const capture = (body: unknown) => {
    const calls: { url: URL; init: RequestInit }[] = [];
    const fetchImpl = vi.fn(async (url: unknown, init?: RequestInit) => {
      calls.push({ url: url as URL, init: init ?? {} });
      return jsonOk(body);
    }) as unknown as typeof fetch;
    return { calls, api: new HemligApi(config, tokens, fetchImpl) };
  };
  const header = (init: RequestInit, name: string): string | undefined =>
    (init.headers as Record<string, string>)[name];

  it("encodes every PKI path segment", async () => {
    const { calls, api } = capture(grantBody);
    await api.getAdminIssuanceGrant("c/1", "we b");
    expect(calls[0]?.url.pathname).toBe(
      "/v1/admin/pki/consumers/c%2F1/issuance-grants/we%20b",
    );
  });

  it("quotes If-Match on grant PUT, grant DELETE and CA DELETE, with a key", async () => {
    const grant = capture(grantBody);
    await grant.api.updateIssuanceGrant(
      "c1",
      "web",
      "v7",
      { caId: "ca-abc" } as never,
      "key-0001-aaaa",
    );
    await grant.api.deleteIssuanceGrant("c1", "web", "v7", "key-0002-aaaa");
    expect(grant.calls.map((c) => c.init.method)).toEqual(["PUT", "DELETE"]);
    expect(header(grant.calls[0]!.init, "if-match")).toBe('"v7"');
    expect(header(grant.calls[1]!.init, "if-match")).toBe('"v7"');
    expect(header(grant.calls[0]!.init, "idempotency-key")).toBe("key-0001-aaaa");
    expect(header(grant.calls[1]!.init, "idempotency-key")).toBe("key-0002-aaaa");

    const ca = capture(caBody);
    await ca.api.deletePkiCa("ca-abc", "v3", "key-0003-aaaa");
    expect(ca.calls[0]?.init.method).toBe("DELETE");
    expect(header(ca.calls[0]!.init, "if-match")).toBe('"v3"');
    expect(header(ca.calls[0]!.init, "idempotency-key")).toBe("key-0003-aaaa");
  });

  it("sends validateOnly with no idempotency key", async () => {
    const result = { valid: true, errors: [], warnings: [] };
    const { calls, api } = capture(result);
    await api.validateIssuanceGrantCreate("c1", { name: "web" } as never);
    await api.validateIssuanceGrantUpdate("c1", "web", "v7", {} as never);
    for (const call of calls) {
      expect(call.url.searchParams.get("validateOnly")).toBe("true");
      expect(header(call.init, "idempotency-key")).toBeUndefined();
    }
    expect(header(calls[0]!.init, "if-match")).toBeUndefined();
    expect(header(calls[1]!.init, "if-match")).toBe('"v7"');
  });

  it("sends an idempotency key on every PKI mutation", async () => {
    const { calls, api } = capture(caBody);
    await api.createPkiCa({} as never, "key-aaaa-0001");
    await api.activatePkiCa("ca-abc", {} as never, "key-aaaa-0002");
    await api.retirePkiCa("ca-abc", "key-aaaa-0003");
    await api.destroyPkiCaKey("ca-abc", "key-aaaa-0004");
    expect(calls.map((c) => header(c.init, "idempotency-key"))).toEqual([
      "key-aaaa-0001",
      "key-aaaa-0002",
      "key-aaaa-0003",
      "key-aaaa-0004",
    ]);
    expect(calls[2]?.init.body).toBeUndefined();
  });

  it("passes the environment to listPkiCas", async () => {
    const { calls, api } = capture({ cas: [], generatedAt: "2026-01-01T00:00:00Z" });
    await api.listPkiCas({ environment: "prod", cursor: "c1" });
    expect(calls[0]?.url.searchParams.get("environment")).toBe("prod");
    expect(calls[0]?.url.searchParams.get("cursor")).toBe("c1");
  });

  it("returns exact CRL bytes and asks for DER", async () => {
    const der = new Uint8Array([0x30, 0xff, 0x00]);
    const calls: RequestInit[] = [];
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      calls.push(init ?? {});
      return new Response(der, {
        status: 200,
        headers: { "content-type": "application/pkix-crl", etag: '"abc"' },
      });
    }) as unknown as typeof fetch;
    const api = new HemligApi(config, tokens, fetchImpl);

    const result = await api.getAdminCrl("ca-abc");

    expect(Array.from(result.bytes)).toEqual([0x30, 0xff, 0x00]);
    expect(result.etag).toBe('"abc"');
    expect(header(calls[0]!, "accept")).toBe("application/pkix-crl, application/json");
    expect(header(calls[0]!, "if-none-match")).toBeUndefined();
  });

  it("never puts the bearer token in a transport failure", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    const api = new HemligApi(config, tokens, fetchImpl);
    const error = await api.getPkiCa("ca-abc").catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "network" });
    const apiError = error as { message: string; transportDetail?: string };
    expect(apiError.message).not.toContain("Bearer");
    expect(apiError.transportDetail ?? "").not.toContain("Bearer");
    expect(apiError.transportDetail ?? "").not.toContain("token");
  });
});
