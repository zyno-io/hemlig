import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";
import type { PkiApplication } from "../pki/app";
import { createPkiAdminHandler, type PkiAdminRoute } from "./pki-admin";
import { createErrorResponder } from "./request";

const write = jest.fn(async () => undefined);
const app = {
  config: {
    adminJwtIssuer: "https://issuer.example.test",
    adminJwtAudience: "hemlig",
    adminActorSubjectClaim: "sub",
  },
  audit: { write },
} as unknown as PkiApplication;
const respond = createErrorResponder(() => app);

const event = (
  withClaims: boolean,
  rawPath = "/v1/admin/pki/cas",
  method = "GET",
) =>
  ({
    rawPath,
    headers: {},
    requestContext: {
      requestId: "req-1",
      http: { method, sourceIp: "203.0.113.9" },
      authorizer: withClaims
        ? {
            jwt: {
              claims: {
                iss: "https://issuer.example.test",
                aud: "hemlig",
                sub: "admin-1",
              },
              scopes: null,
            },
          }
        : undefined,
    },
  }) as unknown as APIGatewayProxyEventV2;

const body = (result: { body?: string }) =>
  JSON.parse(result.body ?? "{}") as {
    error: { code: string; message: string };
  };

describe("pki-admin handler", () => {
  beforeEach(() => write.mockClear());

  it("returns the distinctive 404 for a valid administrator and writes no audit", async () => {
    const result = await createPkiAdminHandler([], respond)(event(true));
    expect(result).toMatchObject({ statusCode: 404 });
    expect(body(result as { body?: string }).error).toMatchObject({
      code: "not_found",
      message: "This PKI route is not available.",
    });
    expect(write).not.toHaveBeenCalled();
  });

  it("rejects a request without validated claims with 403 and no audit", async () => {
    const result = await createPkiAdminHandler([], respond)(event(false));
    expect(result).toMatchObject({ statusCode: 403 });
    expect(write).not.toHaveBeenCalled();
  });

  it("sets the audit context from the routed operation", async () => {
    const route: PkiAdminRoute = {
      method: "GET",
      pattern: /^\/v1\/admin\/pki\/cas$/,
      operation: "pki.ca.list",
      handle: async () => {
        throw new ApiError(400, "bad_request", "No.", "some_reason");
      },
    };
    const result = await createPkiAdminHandler([route], respond)(event(true));
    expect(result).toMatchObject({ statusCode: 400 });
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        operation: "pki.ca.list",
        reasonCode: "some_reason",
        sourceIp: "203.0.113.9",
        actor: expect.objectContaining({ type: "human", id: "admin-1" }),
      }),
    );
  });

  it("passes captured path parameters to the route", async () => {
    const handle = jest.fn(async () => ({ statusCode: 200 }));
    const route: PkiAdminRoute = {
      method: "GET",
      pattern: /^\/v1\/admin\/pki\/cas\/([^/]+)$/,
      operation: "pki.ca.get",
      handle,
    };
    await createPkiAdminHandler(
      [route],
      respond,
    )(event(true, "/v1/admin/pki/cas/ca-one"));
    expect(handle).toHaveBeenCalledWith(expect.anything(), ["ca-one"]);
  });
});
