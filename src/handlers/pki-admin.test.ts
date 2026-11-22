import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";
import type { PkiApplication } from "../pki/app";
import { createPkiAdminHandler, type PkiAdminRoute } from "./pki-admin";
import { pkiAdminRoutes } from "./pki-admin-routes";
import type { PkiRole } from "./pki-routes";
import { createErrorResponder } from "./request";

const write = jest.fn(async () => undefined);
const config: Record<string, string | undefined> = {
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "hemlig",
  adminActorSubjectClaim: "sub",
};
const app = {
  config,
  audit: { write },
} as unknown as PkiApplication;
const respond = createErrorResponder(() => app);

const event = (
  withClaims: boolean,
  rawPath = "/v1/admin/pki/cas",
  method = "GET",
  extraClaims: Record<string, unknown> = {},
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
                ...extraClaims,
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

  describe("PKI roles", () => {
    const probe = (role: PkiRole | undefined): PkiAdminRoute => ({
      method: "POST",
      pattern: /^\/v1\/admin\/pki\/cas$/,
      operation: "pki.ca.create",
      ...(role === undefined ? {} : { role }),
      handle: async () => ({ statusCode: 201 }),
    });
    const call = (
      role: PkiRole | undefined,
      claims: Record<string, unknown> = {},
    ) =>
      createPkiAdminHandler(
        [probe(role)],
        respond,
      )(event(true, "/v1/admin/pki/cas", "POST", claims));
    afterEach(() => {
      delete config.adminPkiCaRole;
      delete config.adminPkiOperatorRole;
    });

    it("allows every role when none is configured (the administrator fallback)", async () => {
      expect(await call("ca-admin")).toMatchObject({ statusCode: 201 });
      expect(await call("operator")).toMatchObject({ statusCode: 201 });
    });

    it("needs only the administrator JWT for a read", async () => {
      config.adminPkiCaRole = "pki-ca-admin";
      expect(await call("read")).toMatchObject({ statusCode: 201 });
      expect(await call(undefined)).toMatchObject({ statusCode: 201 });
    });

    it("rejects a missing configured role with an audited 403", async () => {
      config.adminPkiCaRole = "pki-ca-admin";
      const result = await call("ca-admin", { roles: ["other"] });
      expect(result).toMatchObject({ statusCode: 403 });
      expect(
        JSON.parse((result as { body: string }).body).error.details,
      ).toEqual({
        reason: "pki_role_required",
        role: "ca-admin",
      });
      expect(write).toHaveBeenCalledWith(
        expect.objectContaining({
          outcome: "failed",
          operation: "pki.ca.create",
          reasonCode: "pki_role_required",
        }),
      );
      expect(await call("ca-admin", { roles: ["pki-ca-admin"] })).toMatchObject(
        {
          statusCode: 201,
        },
      );
    });

    it("checks the operator role separately", async () => {
      config.adminPkiOperatorRole = "pki-operator";
      expect(await call("operator", { roles: ["pki-ca-admin"] })).toMatchObject(
        {
          statusCode: 403,
        },
      );
      expect(await call("operator", { roles: ["pki-operator"] })).toMatchObject(
        {
          statusCode: 201,
        },
      );
    });
  });

  describe("route table", () => {
    const ca = "ca-prod-one";
    const ext = `ext-${"a".repeat(40)}`;
    const rows: [string, string, string, PkiRole][] = [
      ["GET", "/cas", "pki.ca.list", "read"],
      ["POST", "/cas", "pki.ca.create", "ca-admin"],
      ["GET", `/cas/${ca}`, "pki.ca.get", "read"],
      ["PUT", `/cas/${ca}`, "pki.ca.update", "ca-admin"],
      ["DELETE", `/cas/${ca}`, "pki.ca.delete", "ca-admin"],
      ["POST", `/cas/${ca}/certificate`, "pki.ca.activate", "ca-admin"],
      ["POST", `/cas/${ca}/retire`, "pki.ca.retire", "ca-admin"],
      ["POST", `/cas/${ca}/destroy-key`, "pki.ca.destroy-key", "ca-admin"],
      ["POST", `/cas/${ca}/crl`, "pki.crl.publish", "operator"],
      ["GET", `/crls/${ca}`, "pki.crl.get", "read"],
      ["GET", `/crls/${ext}`, "pki.crl.get", "read"],
      ["GET", "/external-cas", "pki.external-ca.list", "read"],
      ["GET", `/external-cas/${ext}`, "pki.external-ca.get", "read"],
      [
        "POST",
        `/external-cas/${ext}/crl`,
        "pki.external-ca.upload-crl",
        "ca-admin",
      ],
    ];

    it.each(rows)("%s %s is %s (%s)", (method, path, operation, role) => {
      const matches = pkiAdminRoutes.filter(
        (candidate) =>
          candidate.method === method &&
          candidate.pattern.test(`/v1/admin/pki${path}`),
      );
      expect(matches).toHaveLength(1);
      expect(matches[0]).toMatchObject({ operation, role });
    });

    it("leaves the Phase 4 consumer path unrouted", () => {
      expect(
        pkiAdminRoutes.some((candidate) =>
          candidate.pattern.test("/v1/admin/pki/consumers/x/issuance-grants"),
        ),
      ).toBe(false);
    });
  });
});
