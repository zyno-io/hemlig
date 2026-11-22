import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError, IdentityRejectedError } from "../domain/errors";
import type { PkiApplication } from "../pki/app";
import { createPkiIssuerHandler, type PkiIssuerRoute } from "./pki-issuer";
import { createErrorResponder } from "./request";

const mockConsumerActor = jest.fn();
jest.mock("../auth/actors", () => ({
  consumerActorFromEvent: (...args: unknown[]) => mockConsumerActor(...args),
}));

const write = jest.fn(async () => undefined);
const claimIdentityRejectionAudit = jest.fn(async () => true);
const app = {
  audit: { write },
  repository: { claimIdentityRejectionAudit },
} as unknown as PkiApplication;
const respond = createErrorResponder(() => app);

const event = (rawPath = "/v1/pki/issuance-grants") =>
  ({
    rawPath,
    headers: {},
    requestContext: {
      requestId: "req-1",
      http: { method: "GET", sourceIp: "203.0.113.9" },
    },
  }) as unknown as APIGatewayProxyEventV2;

const active = {
  type: "consumer" as const,
  id: "f".repeat(64),
  consumerId: "payments-agent",
  environment: "prod",
};
const rejected = () =>
  new IdentityRejectedError(
    { type: "consumer", id: "e".repeat(64) },
    "The client certificate is not an active consumer API identity.",
  );

describe("pki-issuer handler", () => {
  beforeEach(() => {
    write.mockClear();
    claimIdentityRejectionAudit.mockReset().mockResolvedValue(true);
    mockConsumerActor.mockReset();
  });

  it("returns the distinctive 404 for an active identity and writes no audit", async () => {
    mockConsumerActor.mockResolvedValue(active);
    const result = await createPkiIssuerHandler([], respond)(event());
    expect(result).toMatchObject({ statusCode: 404 });
    expect(JSON.parse(result.body ?? "{}").error.message).toBe(
      "This PKI route is not available.",
    );
    expect(write).not.toHaveBeenCalled();
  });

  it("audits one identity rejection with its reason", async () => {
    mockConsumerActor.mockRejectedValue(rejected());
    const result = await createPkiIssuerHandler([], respond)(event());
    expect(result).toMatchObject({ statusCode: 403 });
    expect(JSON.parse(result.body ?? "{}").error.code).toBe(
      "identity_not_active",
    );
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        reasonCode: "identity_not_active",
        operation: "pki.unrouted",
      }),
    );
  });

  it("writes no event when the rejection claim is refused", async () => {
    mockConsumerActor.mockRejectedValue(rejected());
    claimIdentityRejectionAudit.mockResolvedValue(false);
    const result = await createPkiIssuerHandler([], respond)(event());
    expect(result).toMatchObject({ statusCode: 403 });
    expect(write).not.toHaveBeenCalled();
  });

  it("audits a routed request under its operation", async () => {
    mockConsumerActor.mockResolvedValue(active);
    const route: PkiIssuerRoute = {
      method: "GET",
      pattern: /^\/v1\/pki\/issuance-grants$/,
      operation: "pki.grants.list",
      handle: async () => {
        throw new ApiError(403, "issuance_denied", "No.", "grant_disabled");
      },
    };
    await createPkiIssuerHandler([route], respond)(event());
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "pki.grants.list",
        reasonCode: "grant_disabled",
        actor: expect.objectContaining({ consumerId: "payments-agent" }),
      }),
    );
  });

  it("forbids an identity without a consumer or environment", async () => {
    mockConsumerActor.mockResolvedValue({ type: "consumer", id: "x" });
    const result = await createPkiIssuerHandler([], respond)(event());
    expect(result).toMatchObject({ statusCode: 403 });
  });
});
