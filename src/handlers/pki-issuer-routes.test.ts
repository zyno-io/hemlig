import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";
import type { PkiApplication } from "../pki/app";
import { createPkiIssuerHandler } from "./pki-issuer";
import { pkiIssuerRoutes } from "./pki-issuer-routes";
import { createErrorResponder } from "./request";

const mockConsumerActor = jest.fn();
jest.mock("../auth/actors", () => ({
  consumerActorFromEvent: (...args: unknown[]) => mockConsumerActor(...args),
}));

const write = jest.fn(async () => undefined);
const claimAuditSuppression = jest.fn(async () => true);
const claimIdentityRejectionAudit = jest.fn(async () => true);
const issueForConsumer = jest.fn();
const listGrantsPage = jest.fn();
const getGrant = jest.fn();
const getCa = jest.fn(async (_id?: string): Promise<unknown> => undefined);
const getCaCrlState = jest.fn(async (_id?: string): Promise<unknown> => undefined);
const download = jest.fn();
const app = {
  audit: { write },
  repository: { claimAuditSuppression, claimIdentityRejectionAudit },
  issuance: { issueForConsumer },
  pki: { listGrantsPage, getGrant, getCa, getCaCrlState },
  crls: { download },
  now: () => new Date("2026-06-01T00:00:00.000Z"),
} as unknown as PkiApplication;
const respond = createErrorResponder(() => app);
const handler = createPkiIssuerHandler(pkiIssuerRoutes, respond);

const active = {
  type: "consumer" as const,
  id: "f".repeat(64),
  consumerId: "payments-agent",
  environment: "prod",
};
const event = (
  method: string,
  rawPath: string,
  extra: Record<string, unknown> = {},
) =>
  ({
    rawPath,
    headers: {},
    requestContext: {
      requestId: "req-1",
      http: { method, sourceIp: "203.0.113.9" },
    },
    ...extra,
  }) as unknown as APIGatewayProxyEventV2;
const issue = (key = "key-route-0001") =>
  handler(
    event("POST", "/v1/pki/issuance-grants/web/certificates", {
      headers: { "idempotency-key": key },
      body: JSON.stringify({ certificateSigningRequestPem: "x" }),
    }),
  );
const grant = {
  name: "web",
  uid: "pkg-1",
  consumerId: "payments-agent",
  environment: "prod",
  caId: "ca-test-one",
  status: "ACTIVE",
  version: "pkv-1",
  policy: { quotas: {} },
};

describe("consumer PKI routes", () => {
  beforeEach(() => {
    write.mockClear();
    claimAuditSuppression.mockReset().mockResolvedValue(true);
    mockConsumerActor.mockReset().mockResolvedValue(active);
    issueForConsumer.mockReset();
    listGrantsPage.mockReset();
    getGrant.mockReset();
  });

  it("writes no event for a successful read", async () => {
    listGrantsPage.mockResolvedValue({
      grants: [grant, { ...grant, name: "other", environment: "staging" }],
    });
    const list = await handler(event("GET", "/v1/pki/issuance-grants"));
    expect(list.statusCode).toBe(200);
    expect(JSON.parse(list.body ?? "{}").grants).toHaveLength(1);
    getGrant.mockResolvedValue(grant);
    expect((await handler(event("GET", "/v1/pki/issuance-grants/web"))).statusCode).toBe(200);
    expect(write).not.toHaveBeenCalled();
  });

  it("returns a DISABLED grant, and 404 for a deleted or foreign-environment one", async () => {
    getGrant.mockResolvedValue({ ...grant, status: "DISABLED" });
    expect((await handler(event("GET", "/v1/pki/issuance-grants/web"))).statusCode).toBe(200);
    getGrant.mockResolvedValue({ ...grant, status: "DELETED" });
    expect((await handler(event("GET", "/v1/pki/issuance-grants/web"))).statusCode).toBe(404);
    getGrant.mockResolvedValue({ ...grant, environment: "staging" });
    const missing = await handler(event("GET", "/v1/pki/issuance-grants/web"));
    expect(JSON.parse(missing.body ?? "{}").error.code).toBe("issuance_grant_not_found");
  });

  it("writes exactly one succeeded event before the 201", async () => {
    issueForConsumer.mockImplementation(async (ctx: { onTarget: (t: unknown) => void }) => {
      ctx.onTarget({ caId: "ca-test-one", issuanceGrantUid: "pkg-1" });
      return {
        status: 201,
        body: { serial: "0a" },
        replayed: false,
        auditTarget: { consumerId: "payments-agent", serial: "0a", replayed: "false" },
      };
    });
    const result = await issue();
    expect(result.statusCode).toBe(201);
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "succeeded",
        operation: "pki.certificate.issue",
        target: expect.objectContaining({ serial: "0a" }),
      }),
    );
  });

  it("fails the request when the success audit cannot be written", async () => {
    issueForConsumer.mockResolvedValue({
      status: 201,
      body: {},
      replayed: false,
      auditTarget: {},
    });
    write.mockRejectedValueOnce(new Error("s3"));
    expect((await issue()).statusCode).toBe(500);
  });

  it("writes one failed event with the reason and the denied name", async () => {
    issueForConsumer.mockRejectedValue(
      new ApiError(403, "issuance_denied", "No.", "name_not_permitted", {
        details: {
          reason: "name_not_permitted",
          deniedNameType: "dns",
          deniedName: "evil.test",
        },
      }),
    );
    const result = await issue();
    expect(result.statusCode).toBe(403);
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        reasonCode: "name_not_permitted",
        operation: "pki.certificate.issue",
        target: expect.objectContaining({
          consumerId: "payments-agent",
          environment: "prod",
          issuanceGrant: "web",
          deniedNameType: "dns",
          deniedName: "evil.test",
        }),
      }),
    );
    expect(claimAuditSuppression).toHaveBeenCalledWith(
      active.id,
      expect.stringMatching(/^PKI#[0-9a-f]{32}$/),
      600,
    );
    // Precomputed: sha256(["pki.certificate.issue","web","name_not_permitted"]) first 32 hex digits.
    expect(claimAuditSuppression).toHaveBeenCalledWith(
      active.id,
      "PKI#ad88f8e72c1eff55c2d08fa1b0acce81",
      600,
    );
  });

  it("writes nothing when the suppression claim is refused, and fails open when it throws", async () => {
    issueForConsumer.mockRejectedValue(
      new ApiError(403, "issuance_grant_inactive", "No.", "grant_disabled"),
    );
    claimAuditSuppression.mockResolvedValueOnce(false);
    await issue();
    expect(write).not.toHaveBeenCalled();
    claimAuditSuppression.mockRejectedValueOnce(new Error("ddb"));
    await issue();
    expect(write).toHaveBeenCalledTimes(1);
  });

  it("keeps Retry-After and the details on a 429", async () => {
    issueForConsumer.mockRejectedValue(
      new ApiError(429, "issuance_rate_limited", "Slow down.", "grant_hour", {
        details: { reason: "grant_hour", retryAfterSeconds: 90 },
        headers: { "retry-after": "90" },
      }),
    );
    const result = await issue();
    expect(result.statusCode).toBe(429);
    expect(result.headers).toMatchObject({ "retry-after": "90" });
    expect(JSON.parse(result.body ?? "{}").error.details.retryAfterSeconds).toBe(90);
  });

  it("requires an Idempotency-Key", async () => {
    const result = await handler(
      event("POST", "/v1/pki/issuance-grants/web/certificates", {
        body: "{}",
      }),
    );
    expect(result.statusCode).toBe(400);
  });
});

describe("consumer bundle and CRL routes", () => {
  const block = (label: string) =>
    `-----BEGIN CERTIFICATE-----\n${label}\n-----END CERTIFICATE-----\n`;
  const extId = `ext-${"a".repeat(40)}`;
  const ca = {
    caId: "ca-test-one",
    environment: "prod",
    name: "prod-issuing-1",
    status: "ACTIVE",
    key: { state: "ACTIVE" },
    crlIssuers: [
      { type: "ca", id: "ca-test-one" },
      { type: "external", id: extId },
    ],
    certificatePem: block("ISSUING"),
    chainPem: block("INTERMEDIATE") + block("ROOT"),
    fingerprint: "ab".repeat(32),
    notAfter: "2028-01-01T00:00:00.000Z",
  };
  const bundle = (id = "ca-test-one") =>
    handler(event("GET", `/v1/pki/cas/${id}/bundle`));
  const sha = "c".repeat(64);
  const meta = {
    numberText: "17",
    thisUpdate: "2026-06-01T00:00:00.000Z",
    nextUpdate: "2026-06-08T00:00:00.000Z",
  };
  const metaHeaders = {
    "hemlig-crl-number": "17",
    "hemlig-crl-this-update": meta.thisUpdate,
    "hemlig-crl-next-update": meta.nextUpdate,
  };
  const crl = (id: string, headers: Record<string, string> = {}) =>
    handler(event("GET", `/v1/pki/crls/${id}`, { headers }));

  beforeEach(() => {
    write.mockClear();
    claimAuditSuppression.mockReset().mockResolvedValue(true);
    mockConsumerActor.mockReset().mockResolvedValue(active);
    getCa.mockReset().mockResolvedValue(ca);
    getCaCrlState.mockReset().mockResolvedValue(undefined);
    getGrant.mockReset();
    listGrantsPage.mockReset();
    download.mockReset();
  });

  it("returns the bundle without an ETag and without any audit event", async () => {
    const result = await bundle();
    expect(result.statusCode).toBe(200);
    expect(result.headers).toMatchObject({
      "content-type": "application/json",
      "cache-control": "no-store",
    });
    expect(result.headers).not.toHaveProperty("etag");
    const body = JSON.parse(result.body ?? "{}");
    expect(body).toMatchObject({
      caId: "ca-test-one",
      name: "prod-issuing-1",
      status: "ACTIVE",
      drained: false,
      anchorPem: block("ROOT"),
      anchorTrusted: true,
      chainPem: block("ISSUING") + block("INTERMEDIATE"),
      crlIssuers: [
        { id: "ca-test-one", source: "GENERATED" },
        { id: extId, source: "UPLOADED" },
      ],
    });
    expect(Object.keys(body)).toHaveLength(10);
    expect(write).not.toHaveBeenCalled();
    expect(getGrant).not.toHaveBeenCalled();
    expect(listGrantsPage).not.toHaveBeenCalled();
  });

  it("ignores If-None-Match on the bundle", async () => {
    const result = await handler(
      event("GET", "/v1/pki/cas/ca-test-one/bundle", {
        headers: { "if-none-match": "*" },
      }),
    );
    expect(result.statusCode).toBe(200);
  });

  it("reports a drained RETIRED CA and a REVOKED CA with the anchor present", async () => {
    getCa.mockResolvedValue({
      ...ca,
      status: "RETIRED",
      retiredAt: "2026-01-01T00:00:00.000Z",
      key: { state: "DISABLED" },
    });
    getCaCrlState.mockResolvedValue({
      revision: 0,
      published: { thisUpdate: "2026-02-01T00:00:00.000Z", revision: 0 },
    });
    expect(JSON.parse((await bundle()).body ?? "{}")).toMatchObject({
      status: "RETIRED",
      drained: true,
    });
    getCa.mockResolvedValue({ ...ca, status: "REVOKED" });
    const revoked = JSON.parse((await bundle()).body ?? "{}");
    expect(revoked).toMatchObject({
      status: "REVOKED",
      anchorPem: block("ROOT"),
    });
  });

  it("answers a foreign environment like an unknown CA", async () => {
    getCa.mockResolvedValue({ ...ca, environment: "staging" });
    const foreign = await bundle();
    getCa.mockResolvedValue(undefined);
    const unknown = await bundle();
    expect(foreign.statusCode).toBe(404);
    expect(unknown.statusCode).toBe(404);
    const strip = (body: string | undefined) => {
      const parsed = JSON.parse(body ?? "{}");
      delete parsed.error.correlationId;
      return parsed;
    };
    expect(strip(foreign.body)).toEqual(strip(unknown.body));
    expect(strip(unknown.body).error).toMatchObject({
      code: "not_found",
      details: { reason: "ca_not_found" },
    });
  });

  it.each([
    ["PENDING_CERTIFICATE", "pending_certificate"],
    ["FAILED", "failed"],
  ])("answers 409 ca_not_active for a %s CA", async (status, reason) => {
    getCa.mockResolvedValue({ ...ca, status });
    const result = await bundle();
    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body ?? "{}").error).toMatchObject({
      code: "ca_not_active",
      details: { reason },
    });
  });

  it("serves the CRL bytes exactly, up to 1,000,000 bytes", async () => {
    const der = Buffer.alloc(1_000_000, 0xa5);
    download.mockResolvedValue({ kind: "bytes", der, sha256: sha, ...meta });
    const result = await crl("ca-test-one");
    expect(result.statusCode).toBe(200);
    expect(result.isBase64Encoded).toBe(true);
    expect(Buffer.from(result.body ?? "", "base64").equals(der)).toBe(true);
    expect(result.headers).toMatchObject({
      "content-type": "application/pkix-crl",
      "cache-control": "no-store",
      etag: sha,
      "content-disposition": 'attachment; filename="ca-test-one-17.crl"',
      ...metaHeaders,
    });
    expect(download).toHaveBeenCalledWith("ca-test-one", [], {
      environment: "prod",
    });
    expect(write).not.toHaveBeenCalled();
    expect(getGrant).not.toHaveBeenCalled();
  });

  it.each([`"${sha}"`, `W/"${sha}"`, `"x", "${sha}"`, "*"])(
    "answers 304 with the metadata for If-None-Match %s",
    async (header) => {
      download.mockResolvedValue({ kind: "notModified", sha256: sha, ...meta });
      const result = await crl(extId, { "if-none-match": header });
      expect(result.statusCode).toBe(304);
      expect(result.body).toBeUndefined();
      expect(result.headers).toMatchObject({ etag: sha, ...metaHeaders });
      expect(download).toHaveBeenCalledWith(
        extId,
        expect.arrayContaining([header === "*" ? "*" : expect.any(String)]),
        { environment: "prod" },
      );
      expect(write).not.toHaveBeenCalled();
    },
  );

  it("writes one failed event for a missing CRL and claims a suppression scope", async () => {
    download.mockRejectedValue(
      new ApiError(404, "not_found", "No CRL.", "crl_missing", {
        details: { reason: "crl_missing" },
      }),
    );
    expect((await crl(extId)).statusCode).toBe(404);
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        operation: "pki.crl.get",
        reasonCode: "crl_missing",
        target: { consumerId: "payments-agent", environment: "prod", extId },
      }),
    );
    expect(claimAuditSuppression).toHaveBeenCalledWith(
      active.id,
      expect.stringMatching(/^PKI#[0-9a-f]{32}$/),
      600,
    );
    write.mockClear();
    claimAuditSuppression.mockResolvedValueOnce(false);
    expect((await crl(extId)).statusCode).toBe(404);
    expect(write).not.toHaveBeenCalled();
  });

  it("targets a CA CRL failure by caId", async () => {
    download.mockRejectedValue(
      new ApiError(404, "not_found", "No CA.", "ca_not_found", {
        details: { reason: "ca_not_found" },
      }),
    );
    await crl("ca-test-one");
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        target: {
          consumerId: "payments-agent",
          environment: "prod",
          caId: "ca-test-one",
        },
      }),
    );
  });

  it("does not match other paths", async () => {
    expect((await handler(event("GET", "/v1/pki/crls/bogus"))).statusCode).toBe(404);
    expect((await handler(event("GET", "/v1/pki/cas/ca-test-one"))).statusCode).toBe(404);
  });
});
