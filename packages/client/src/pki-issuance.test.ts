import assert from "node:assert/strict";
import test from "node:test";
import {
  HemligClient,
  HemligError,
  type HemligTransport,
  type TransportRequest,
  type TransportResponse,
} from "./index";

const url = new URL("https://admin.example.test");

function clientFor(respond: (request: TransportRequest) => TransportResponse) {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return respond(request);
    },
  };
  return { client: new HemligClient(url, transport), requests };
}

const ok = (body: unknown = {}): TransportResponse => ({
  status: 200,
  headers: {},
  body,
});

const grantInput = { caId: "ca-1", names: { maxSans: 1 } };

test("admin grant routes use the documented paths, queries and headers", async () => {
  const { client, requests } = clientFor(() => ok());
  await client.listCaIssuanceGrants("t", "ca-1", { cursor: "c+/=" });
  await client.listAdminIssuanceGrants("t", "web-1", {
    includeDeleted: true,
    cursor: "c1",
  });
  await client.listAdminIssuanceGrants("t", "web-1");
  await client.getAdminIssuanceGrant("t", "web-1", "acc web");
  await client.createIssuanceGrant(
    "t",
    "web-1",
    { ...grantInput, name: "acc-web" },
    "k1",
  );
  await client.updateIssuanceGrant(
    "t",
    "web-1",
    "acc-web",
    "pkv-1",
    grantInput,
    "k2",
  );
  await client.deleteIssuanceGrant("t", "web-1", "acc-web", "pkv-2", "k3");
  await client.evaluateIssuanceGrant("t", "web-1", "acc-web", {
    keyAlgorithm: "ECDSA_P256",
    sans: { dns: ["a.example.com"] },
  });
  const seen = requests.map(
    (r) => `${r.method} ${r.url.pathname}${r.url.search}`,
  );
  assert.deepEqual(seen, [
    "GET /v1/admin/pki/cas/ca-1/issuance-grants?cursor=c%2B%2F%3D",
    "GET /v1/admin/pki/consumers/web-1/issuance-grants?includeDeleted=true&cursor=c1",
    "GET /v1/admin/pki/consumers/web-1/issuance-grants",
    "GET /v1/admin/pki/consumers/web-1/issuance-grants/acc%20web",
    "POST /v1/admin/pki/consumers/web-1/issuance-grants",
    "PUT /v1/admin/pki/consumers/web-1/issuance-grants/acc-web",
    "DELETE /v1/admin/pki/consumers/web-1/issuance-grants/acc-web",
    "POST /v1/admin/pki/consumers/web-1/issuance-grants/acc-web/evaluate",
  ]);
  for (const request of requests)
    assert.equal(request.headers?.authorization, "Bearer t");
  assert.equal(requests[4]?.headers?.["idempotency-key"], "k1");
  assert.equal(requests[4]?.headers?.["if-match"], undefined);
  assert.equal(requests[5]?.headers?.["if-match"], '"pkv-1"');
  assert.equal(requests[5]?.headers?.["idempotency-key"], "k2");
  assert.equal(requests[6]?.headers?.["if-match"], '"pkv-2"');
  assert.equal(requests[6]?.body, undefined);
  assert.equal(requests[7]?.headers?.["idempotency-key"], undefined);
});

test("validateOnly uses the query, keeps If-Match on PUT and sends no key", async () => {
  const { client, requests } = clientFor(() => ok({ valid: true }));
  await client.validateIssuanceGrantCreate("t", "web-1", {
    ...grantInput,
    name: "acc-web",
  });
  await client.validateIssuanceGrantUpdate(
    "t",
    "web-1",
    "acc-web",
    "pkv-1",
    grantInput,
  );
  assert.equal(requests[0]?.method, "POST");
  assert.equal(requests[0]?.url.searchParams.get("validateOnly"), "true");
  assert.equal(requests[0]?.headers?.["idempotency-key"], undefined);
  assert.equal(requests[0]?.headers?.["if-match"], undefined);
  assert.equal(requests[1]?.method, "PUT");
  assert.equal(requests[1]?.url.searchParams.get("validateOnly"), "true");
  assert.equal(requests[1]?.headers?.["if-match"], '"pkv-1"');
  assert.equal(requests[1]?.headers?.["idempotency-key"], undefined);
});

test("certificate inventory, issuance and revocation routes", async () => {
  const { client, requests } = clientFor(() => ok());
  await client.listPkiCertificates("t", "ca-1", {
    status: "REVOKED",
    expiringBefore: "2027-01-01T00:00:00.000Z",
    cursor: "c",
  });
  await client.getPkiCertificate("t", "ca-1", "0a1b");
  await client.issuePkiCertificate(
    "t",
    "ca-1",
    { certificateSigningRequestPem: "CSR", useCsrNames: true },
    "k1",
  );
  await client.revokePkiCertificate(
    "t",
    "ca-1",
    "0a1b",
    { reason: "keyCompromise" },
    "k2",
  );
  await client.listConsumerPkiCertificates("t", "web-1", {
    issuanceGrant: "acc-web",
    includeExpired: true,
  });
  await client.listConsumerPkiCertificates("t", "web-1", {});
  await client.revokeConsumerPkiCertificates(
    "t",
    "web-1",
    { issuanceGrant: "acc-web" },
    "k3",
  );
  const seen = requests.map(
    (r) => `${r.method} ${r.url.pathname}${r.url.search}`,
  );
  assert.deepEqual(seen, [
    "GET /v1/admin/pki/cas/ca-1/certificates?status=REVOKED&expiringBefore=2027-01-01T00%3A00%3A00.000Z&cursor=c",
    "GET /v1/admin/pki/cas/ca-1/certificates/0a1b",
    "POST /v1/admin/pki/cas/ca-1/certificates",
    "POST /v1/admin/pki/cas/ca-1/certificates/0a1b/revoke",
    "GET /v1/admin/pki/consumers/web-1/certificates?issuanceGrant=acc-web&includeExpired=true",
    "GET /v1/admin/pki/consumers/web-1/certificates",
    "POST /v1/admin/pki/consumers/web-1/certificates/revoke",
  ]);
  assert.equal(requests[2]?.headers?.["idempotency-key"], "k1");
  assert.equal(requests[3]?.headers?.["idempotency-key"], "k2");
  assert.equal(requests[6]?.headers?.["idempotency-key"], "k3");
  assert.deepEqual(requests[6]?.body, { issuanceGrant: "acc-web" });
});

test("consumer methods send no bearer token and carry the idempotency key", async () => {
  const { client, requests } = clientFor(() => ok({ grants: [] }));
  await client.listIssuanceGrants();
  await client.getIssuanceGrant("acc web");
  await client.issueCertificate(
    "acc-web",
    {
      certificateSigningRequestPem: "CSR",
      durationSeconds: 3600,
      requester: {
        kubernetes: { namespace: "ns", name: "n", uid: "1234" },
      },
    },
    "csr-hash-1",
  );
  assert.equal(requests[0]?.url.pathname, "/v1/pki/issuance-grants");
  assert.equal(requests[1]?.url.pathname, "/v1/pki/issuance-grants/acc%20web");
  assert.equal(
    requests[2]?.url.pathname,
    "/v1/pki/issuance-grants/acc-web/certificates",
  );
  assert.equal(requests[2]?.method, "POST");
  for (const request of requests)
    assert.equal(request.headers?.authorization, undefined);
  assert.equal(requests[0]?.headers?.["idempotency-key"], undefined);
  assert.equal(requests[2]?.headers?.["idempotency-key"], "csr-hash-1");
});

test("a 429 carries Retry-After seconds and the error details", async () => {
  const { client } = clientFor(() => ({
    status: 429,
    headers: { "retry-after": "120" },
    body: {
      error: {
        code: "issuance_rate_limited",
        message: "slow down",
        details: { reason: "grant_hour", retryAfterSeconds: 120 },
      },
    },
  }));
  await assert.rejects(
    client.issueCertificate(
      "acc-web",
      { certificateSigningRequestPem: "CSR" },
      "key-12345678",
    ),
    (error: unknown) => {
      assert.ok(error instanceof HemligError);
      assert.equal(error.status, 429);
      assert.equal(error.code, "issuance_rate_limited");
      assert.equal(error.retryAfterSeconds, 120);
      assert.deepEqual(error.details, {
        reason: "grant_hour",
        retryAfterSeconds: 120,
      });
      return true;
    },
  );
});
