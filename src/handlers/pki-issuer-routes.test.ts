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
const getCa = jest.fn(async () => undefined);
const app = {
  audit: { write },
  repository: { claimAuditSuppression, claimIdentityRejectionAudit },
  issuance: { issueForConsumer },
  pki: { listGrantsPage, getGrant, getCa },
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
