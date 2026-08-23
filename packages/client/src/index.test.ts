import assert from "node:assert/strict";
import test from "node:test";
import { HemligClient, type HemligTransport, type TransportRequest } from "./index";

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
          metadata: { name: "payments-api" },
        },
      };
    },
  };
  const client = new HemligClient(new URL("https://admin.example.com"), transport);

  await client.putAdminPayload(
    "token",
    "payments-api",
    "ctl-current",
    { API_TOKEN: { encoding: "utf8", value: "value" } },
    "stable-key",
  );

  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request?.url.pathname, "/v1/admin/secrets/payments-api/payload");
  assert.equal(request?.headers?.authorization, "Bearer token");
  assert.equal(request?.headers?.["if-match"], "\"ctl-current\"");
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
  const client = new HemligClient(new URL("https://api.example.com"), transport);

  const secret = await client.getConsumerSecret("payments-api", "ctl-current");

  assert.equal(secret, undefined);
  assert.equal(requests[0]?.headers?.["if-none-match"], "\"ctl-current\"");
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
  const client = new HemligClient(new URL("https://admin.example.com"), transport);

  await client.revokeApiIdentity("token", "payments-prod", "a".repeat(64), "stable-key");

  assert.equal(requests[0]?.method, "DELETE");
  assert.equal(
    requests[0]?.url.pathname,
    `/v1/admin/consumers/payments-prod/api-identities/${"a".repeat(64)}`,
  );
  assert.equal(requests[0]?.headers?.["idempotency-key"], "stable-key");
});
