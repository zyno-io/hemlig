import assert from "node:assert/strict";
import test from "node:test";
import {
  HemligClient,
  type HemligTransport,
  type TransportRequest,
} from "./index";

test("admin payload write carries the ETag and idempotency key", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 200,
        headers: {},
        body: {
          secretId: "payments-api",
          controlVersionId: "ctl-next",
          payloadVersionId: "pay-next",
          environment: "prod",
          state: "ACTIVE",
          metadata: { description: "Payments API" },
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://admin.example.com"),
    transport,
  );

  await client.putAdminPayload(
    "token",
    "prod",
    "payments-api",
    "ctl-current",
    { API_TOKEN: { encoding: "utf8", value: "value" } },
    "stable-key",
  );

  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request?.url.pathname, "/v1/admin/secrets/payments-api/payload");
  assert.equal(request?.url.searchParams.get("environment"), "prod");
  assert.equal(request?.headers?.authorization, "Bearer token");
  assert.equal(request?.headers?.["if-match"], '"ctl-current"');
  assert.equal(request?.headers?.["idempotency-key"], "stable-key");
});

test("conditional consumer reads return undefined for an unchanged secret", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return { status: 304, headers: { etag: "ctl-current" } };
    },
  };
  const client = new HemligClient(
    new URL("https://api.example.com"),
    transport,
  );

  const secret = await client.getConsumerSecret("payments-api", "ctl-current");

  assert.equal(secret, undefined);
  assert.equal(requests[0]?.headers?.["if-none-match"], '"ctl-current"');
});

test("administrator payload reads use the authenticated administrator route", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 200,
        headers: {},
        body: {
          secretId: "payments-api",
          controlVersionId: "ctl-current",
          payloadVersionId: "pay-current",
          payload: { API_TOKEN: { encoding: "utf8", value: "value" } },
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://admin.example.com"),
    transport,
  );

  const result = await client.getAdminSecretPayload(
    "token",
    "prod",
    "payments-api",
  );

  assert.equal(result.payload.API_TOKEN?.value, "value");
  assert.equal(
    requests[0]?.url.pathname,
    "/v1/admin/secrets/payments-api/payload",
  );
  assert.equal(requests[0]?.url.searchParams.get("environment"), "prod");
  assert.equal(requests[0]?.headers?.authorization, "Bearer token");
});

test("secret paths encode hierarchical IDs as one URL parameter", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 200,
        headers: {},
        body: {
          secretId: "payments/stripe/api-key",
          controlVersionId: "ctl-current",
          payloadVersionId: "pay-current",
          payload: {},
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://admin.example.com"),
    transport,
  );

  await client.getAdminSecretPayload(
    "token",
    "prod",
    "payments/stripe/api-key",
  );

  assert.equal(
    requests[0]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key/payload",
  );
});

test("API identity revocation uses DELETE and requires a caller-provided idempotency key", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 200,
        headers: {},
        body: {
          consumerId: "payments-prod",
          environment: "prod",
          apiFingerprint: "a".repeat(64),
          status: "REVOKED",
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://admin.example.com"),
    transport,
  );

  await client.revokeApiIdentity(
    "token",
    "payments-prod",
    "a".repeat(64),
    "stable-key",
  );

  assert.equal(requests[0]?.method, "DELETE");
  assert.equal(
    requests[0]?.url.pathname,
    `/v1/admin/consumers/payments-prod/api-identities/${"a".repeat(64)}`,
  );
  assert.equal(requests[0]?.headers?.["idempotency-key"], "stable-key");
});

test("bootstrap redemption uses its one-use authorization scheme rather than bearer JWT", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 201,
        headers: {},
        body: {
          consumerId: "payments-agent",
          environment: "prod",
          rootFingerprint: "a".repeat(64),
          apiFingerprint: "b".repeat(64),
          apiCertificatePem: "certificate",
          status: "ACTIVE",
          grant: {
            grantId: "grant-payments",
            consumerId: "payments-agent",
            environment: "prod",
            capabilities: ["read"],
            readSecretIdPrefixes: ["payments"],
            writeSecretIdPrefixes: [],
          },
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://admin.example.com"),
    transport,
  );

  await client.redeemBootstrap("hmlb_opaque", "csr");

  assert.equal(requests[0]?.url.pathname, "/v1/bootstrap/redeem");
  assert.equal(requests[0]?.headers?.authorization, "Bootstrap hmlb_opaque");
});

test("agent control and payload updates use only mTLS transport headers", async () => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return {
        status: 200,
        headers: {},
        body: {
          secretId: "payments-api",
          environment: "prod",
          controlVersionId: "ctl-next",
          state: "ACTIVE",
          metadata: {},
        },
      };
    },
  };
  const client = new HemligClient(
    new URL("https://api.example.com"),
    transport,
  );

  await client.getAgentControl("payments-api");
  await client.putAgentPayload(
    "payments-api",
    "ctl-current",
    { TOKEN: { encoding: "utf8", value: "value" } },
    "stable-key",
  );

  assert.equal(
    requests[0]?.url.pathname,
    "/v1/agent/secrets/payments-api/control",
  );
  assert.equal(requests[0]?.headers?.authorization, undefined);
  assert.equal(
    requests[1]?.url.pathname,
    "/v1/agent/secrets/payments-api/payload",
  );
  assert.equal(requests[1]?.headers?.["if-match"], '"ctl-current"');
});
