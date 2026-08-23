import assert from "node:assert/strict";
import test from "node:test";
import { ClavisClient, type ClavisTransport, type TransportRequest } from "./index";

test("admin payload write carries the ETag and idempotency key", async () => {
  const requests: TransportRequest[] = [];
  const transport: ClavisTransport = {
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
  const client = new ClavisClient(new URL("https://admin.example.com"), transport);

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

test("conditional cluster reads return undefined for an unchanged secret", async () => {
  const requests: TransportRequest[] = [];
  const transport: ClavisTransport = {
    request: async (request) => {
      requests.push(request);
      return { status: 304, headers: { etag: "ctl-current" } };
    },
  };
  const client = new ClavisClient(new URL("https://clusters.example.com"), transport);

  const secret = await client.getClusterSecret("payments-api", "ctl-current");

  assert.equal(secret, undefined);
  assert.equal(requests[0]?.headers?.["if-none-match"], "\"ctl-current\"");
});
