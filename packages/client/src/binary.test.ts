import assert from "node:assert/strict";
import test from "node:test";
import {
  FetchTransport,
  HemligClient,
  HemligError,
  decodeTransportBody,
  type HemligTransport,
  type TransportRequest,
  type TransportResponse,
} from "./index";

const url = new URL("https://admin.example.test");

test("binary 2xx bodies are returned byte-for-byte, never UTF-8 decoded", () => {
  const raw = Uint8Array.from([0xff, 0xfe, 0x00]);
  const decoded = decodeTransportBody(200, {}, raw, "binary");
  assert.deepEqual(Array.from(decoded.bytes ?? []), [0xff, 0xfe, 0x00]);
  assert.equal(decoded.body, undefined);
});

test("json mode and error responses keep the JSON envelope", () => {
  const json = new TextEncoder().encode('{"a":1}');
  assert.deepEqual(decodeTransportBody(200, {}, json), { body: { a: 1 } });
  assert.deepEqual(decodeTransportBody(409, {}, json, "binary"), {
    body: { a: 1 },
  });
  assert.deepEqual(decodeTransportBody(200, {}, new Uint8Array()), {});
  assert.deepEqual(
    decodeTransportBody(200, {}, Uint8Array.from([0xff]), "json"),
    {},
  );
});

test("304 is explicit in binary mode", () => {
  const decoded = decodeTransportBody(304, {}, new Uint8Array(), "binary");
  assert.equal(decoded.bytes, undefined);
});

const clientFor = (
  respond: (request: TransportRequest) => TransportResponse,
): { client: HemligClient; requests: TransportRequest[] } => {
  const requests: TransportRequest[] = [];
  const transport: HemligTransport = {
    request: async (request) => {
      requests.push(request);
      return respond(request);
    },
  };
  return { client: new HemligClient(url, transport), requests };
};

test("getAdminCrl returns bytes and unquotes the ETag", async () => {
  const { client, requests } = clientFor(() => ({
    status: 200,
    headers: { etag: 'W/"abc123"', "content-type": "application/pkix-crl" },
    bytes: Uint8Array.from([0x30, 0xff]),
  }));
  const result = await client.getAdminCrl("tok", "ca-1234", "old");
  assert.equal(result.status, 200);
  if (result.status === 200) {
    assert.deepEqual(Array.from(result.bytes), [0x30, 0xff]);
    assert.equal(result.contentType, "application/pkix-crl");
  }
  assert.equal(result.etag, "abc123");
  assert.equal(requests[0]?.responseType, "binary");
  assert.equal(requests[0]?.headers?.["if-none-match"], '"old"');
  assert.equal(requests[0]?.url.pathname, "/v1/admin/pki/crls/ca-1234");
});

test("getAdminCrl reports 304 and rejects transports without bytes", async () => {
  const notModified = clientFor(() => ({
    status: 304,
    headers: { etag: '"x"' },
  }));
  assert.deepEqual(await notModified.client.getAdminCrl("t", "ca-1234"), {
    status: 304,
    etag: "x",
  });
  const noBytes = clientFor(() => ({ status: 200, headers: {} }));
  await assert.rejects(
    noBytes.client.getAdminCrl("t", "ca-1234"),
    (error: unknown) =>
      error instanceof HemligError &&
      error.code === "transport_binary_unsupported",
  );
});

test("a JSON error in binary mode becomes a HemligError with details and retry-after", async () => {
  const { client } = clientFor(() => ({
    status: 503,
    headers: { "retry-after": "30" },
    body: {
      error: {
        code: "service_unavailable",
        message: "busy",
        details: { reason: "crl_publication_busy" },
      },
    },
  }));
  await assert.rejects(client.getAdminCrl("t", "ca-1234"), (error: unknown) => {
    assert.ok(error instanceof HemligError);
    assert.equal(error.status, 503);
    assert.equal(error.code, "service_unavailable");
    assert.deepEqual(error.details, { reason: "crl_publication_busy" });
    assert.equal(error.retryAfterSeconds, 30);
    return true;
  });
});

test("a non-numeric retry-after is ignored", async () => {
  const { client } = clientFor(() => ({
    status: 429,
    headers: { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" },
    body: { error: { code: "rate_limited", message: "slow" } },
  }));
  await assert.rejects(
    client.listPkiCas("t", { environment: "prod" }),
    (error: unknown) =>
      error instanceof HemligError && error.retryAfterSeconds === undefined,
  );
});

test("FetchTransport preserves binary bytes and sends the CRL accept header", async () => {
  let seen: { headers?: Record<string, string> } | undefined;
  const fakeFetch = (async (_url: unknown, init?: RequestInit) => {
    seen = init as { headers?: Record<string, string> };
    return new Response(Uint8Array.from([0xff, 0xfe, 0x00]), {
      status: 200,
      headers: { etag: '"e"' },
    });
  }) as typeof globalThis.fetch;
  const response = await new FetchTransport(fakeFetch).request({
    method: "GET",
    url: new URL("/x", url),
    responseType: "binary",
  });
  assert.deepEqual(Array.from(response.bytes ?? []), [0xff, 0xfe, 0x00]);
  assert.equal(seen?.headers?.accept, "application/pkix-crl, application/json");
  assert.equal(response.headers.etag, '"e"');
});

test("FetchTransport still parses JSON in the default mode", async () => {
  const fakeFetch = (async () =>
    new Response('{"ok":true}', { status: 200 })) as typeof globalThis.fetch;
  const response = await new FetchTransport(fakeFetch).request({
    method: "GET",
    url: new URL("/x", url),
  });
  assert.deepEqual(response.body, { ok: true });
});

test("PKI mutations send If-Match and idempotency headers", async () => {
  const { client, requests } = clientFor(() => ({
    status: 200,
    headers: {},
    body: {},
  }));
  await client.updatePkiCa("t", "ca-1", "pkv-1", { policy: {} }, "k1");
  await client.deletePkiCa("t", "ca-1", "pkv-1", "k2");
  await client.uploadExternalCaCrl("t", "ext-" + "a".repeat(40), "CRL", "k3");
  assert.equal(requests[0]?.headers?.["if-match"], '"pkv-1"');
  assert.equal(requests[0]?.headers?.["idempotency-key"], "k1");
  assert.equal(requests[1]?.method, "DELETE");
  assert.equal(requests[1]?.headers?.["if-match"], '"pkv-1"');
  assert.deepEqual(requests[2]?.body, { crl: "CRL" });
  assert.match(requests[2]?.url.pathname ?? "", /\/external-cas\/ext-a+\/crl$/);
});

test("getCrl sends no authorization, a quoted If-None-Match and reads metadata", async () => {
  const { client, requests } = clientFor((request) => ({
    status: request.headers?.["if-none-match"] === '"same"' ? 304 : 200,
    headers: {
      etag: "abc",
      "content-type": "application/pkix-crl",
      "hemlig-crl-number": "17",
      "hemlig-crl-this-update": "2026-01-01T00:00:00.000Z",
      "hemlig-crl-next-update": "2026-01-08T00:00:00.000Z",
    },
    bytes: Uint8Array.from([0x30, 0x01]),
  }));
  const meta = {
    number: "17",
    thisUpdate: "2026-01-01T00:00:00.000Z",
    nextUpdate: "2026-01-08T00:00:00.000Z",
  };
  const ok = await client.getCrl("ext-" + "a".repeat(40), "old");
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.crl, meta);
  assert.equal(ok.etag, "abc");
  if (ok.status === 200) assert.deepEqual(Array.from(ok.bytes), [0x30, 0x01]);
  assert.equal(requests[0]?.headers?.authorization, undefined);
  assert.equal(requests[0]?.headers?.["if-none-match"], '"old"');
  assert.equal(requests[0]?.responseType, "binary");
  assert.equal(requests[0]?.url.pathname, `/v1/pki/crls/ext-${"a".repeat(40)}`);
  const notModified = await client.getCrl("ca-1234", "same");
  assert.deepEqual(notModified, { status: 304, etag: "abc", crl: meta });
});

test("getCrl turns the error envelope into a HemligError with a reason", async () => {
  const { client } = clientFor(() => ({
    status: 404,
    headers: {},
    body: {
      error: {
        code: "not_found",
        message: "SECRET",
        details: { reason: "crl_missing" },
      },
    },
  }));
  await assert.rejects(client.getCrl("ca-1234"), (error: unknown) => {
    assert.ok(error instanceof HemligError);
    assert.equal(error.status, 404);
    assert.deepEqual(error.details, { reason: "crl_missing" });
    return true;
  });
});

test("getCaBundle requests the bundle path", async () => {
  const { client, requests } = clientFor(() => ({
    status: 200,
    headers: {},
    body: { caId: "ca-1234" },
  }));
  const bundle = await client.getCaBundle("ca-1234");
  assert.equal(bundle.caId, "ca-1234");
  assert.equal(requests[0]?.url.pathname, "/v1/pki/cas/ca-1234/bundle");
  assert.equal(requests[0]?.method, "GET");
});
