import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { bearerFor, testExp } from "../auth/test-support";
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
    headers: withClaims
      ? {
          authorization: bearerFor({
            iss: "https://issuer.example.test",
            aud: "hemlig",
            sub: "admin-1",
            ...extraClaims,
          }),
        }
      : {},
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
                exp: testExp,
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
      ["POST", `/cas/${ca}/revoke`, "pki.ca.revoke", "ca-admin"],
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
      ["GET", `/cas/${ca}/issuance-grants`, "pki.grant.list", "read"],
      ["GET", "/consumers/payments/issuance-grants", "pki.grant.list", "read"],
      [
        "POST",
        "/consumers/payments/issuance-grants",
        "pki.grant.create",
        "operator",
      ],
      [
        "GET",
        "/consumers/payments/issuance-grants/web",
        "pki.grant.get",
        "read",
      ],
      [
        "PUT",
        "/consumers/payments/issuance-grants/web",
        "pki.grant.update",
        "operator",
      ],
      [
        "DELETE",
        "/consumers/payments/issuance-grants/web",
        "pki.grant.delete",
        "operator",
      ],
      [
        "POST",
        "/consumers/payments/issuance-grants/web/evaluate",
        "pki.grant.evaluate",
        "read",
      ],
      ["GET", `/cas/${ca}/certificates`, "pki.certificate.list", "read"],
      ["POST", `/cas/${ca}/certificates`, "pki.certificate.issue", "operator"],
      ["GET", `/cas/${ca}/certificates/0a1b`, "pki.certificate.get", "read"],
      [
        "POST",
        `/cas/${ca}/certificates/0a1b/revoke`,
        "pki.certificate.revoke",
        "operator",
      ],
      ["GET", "/consumers/payments/certificates", "pki.certificate.list", "read"],
      [
        "POST",
        "/consumers/payments/certificates/revoke",
        "pki.certificate.revoke",
        "operator",
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

    it("labels consumer-scoped routes with the consumer, not a CA", () => {
      const grant = pkiAdminRoutes.find((candidate) =>
        candidate.pattern.test(
          "/v1/admin/pki/consumers/payments/issuance-grants/web",
        ),
      );
      expect(grant?.auditTarget?.(["payments", "web"])).toEqual({
        consumerId: "payments",
        issuanceGrant: "web",
      });
    });
  });

  describe("Phase 4 routes", () => {
    const grants = {
      listForConsumer: jest.fn(),
      validateCreate: jest.fn(async () => ({ valid: true, errors: [], warnings: [] })),
      validateUpdate: jest.fn(async () => ({ valid: true, errors: [], warnings: [] })),
      create: jest.fn(),
    };
    const issuance = { issueForAdmin: jest.fn(), evaluate: jest.fn() };
    const certificates = { bulkRevoke: jest.fn() };
    const cas = { revoke: jest.fn() };
    const markAuditSucceeded = jest.fn(async () => undefined);
    const phase4 = {
      config,
      audit: { write },
      repository: { markAuditSucceeded },
      grants,
      issuance,
      certificates,
      cas,
    } as unknown as PkiApplication;
    const phase4Respond = createErrorResponder(() => phase4);
    const call = (
      method: string,
      path: string,
      options: {
        query?: Record<string, string>;
        headers?: Record<string, string>;
        body?: unknown;
        claims?: Record<string, unknown>;
      } = {},
    ) =>
      createPkiAdminHandler(
        pkiAdminRoutes,
        phase4Respond,
      )({
        ...(base => ({
          ...base,
          headers: { ...base.headers, ...options.headers },
        }))(event(true, `/v1/admin/pki${path}`, method, options.claims)),
        ...(options.query === undefined
          ? {}
          : { queryStringParameters: options.query }),
        ...(options.body === undefined
          ? {}
          : { body: JSON.stringify(options.body) }),
      } as APIGatewayProxyEventV2);
    afterEach(() => {
      delete config.adminPkiOperatorRole;
      delete config.adminPkiCaRole;
    });

    describe("POST /cas/{caId}/revoke", () => {
      const revoke = (
        headers: Record<string, string> = { "idempotency-key": "key-0000001" },
        claims?: Record<string, unknown>,
      ) =>
        call("POST", "/cas/ca-prod-one/revoke", {
          headers,
          body: { reason: "caCompromise" },
          ...(claims === undefined ? {} : { claims }),
        });

      it("needs the CA administrator role", async () => {
        config.adminPkiCaRole = "pki-ca-admin";
        expect(await revoke(undefined, { roles: ["other"] })).toMatchObject({
          statusCode: 403,
        });
        expect(cas.revoke).not.toHaveBeenCalled();
        expect(write).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: "pki.ca.revoke",
            outcome: "failed",
            reasonCode: "pki_role_required",
          }),
        );
      });

      it("needs an Idempotency-Key", async () => {
        expect(await revoke({})).toMatchObject({ statusCode: 400 });
        expect(cas.revoke).not.toHaveBeenCalled();
      });

      it("revokes with the body, sets the ETag and audits pki.ca.revoke", async () => {
        cas.revoke.mockResolvedValueOnce({
          status: 200,
          body: { changed: true },
          shouldWriteTerminalAudit: true,
          auditTarget: { caId: "ca-prod-one", reason: "caCompromise" },
          etag: "pkv-9",
        });
        (write as jest.Mock).mockResolvedValueOnce({ eventId: "e-1" });
        const result = await revoke();
        expect(result).toMatchObject({
          statusCode: 200,
          headers: expect.objectContaining({ etag: "pkv-9" }),
        });
        expect(cas.revoke).toHaveBeenCalledWith(
          expect.objectContaining({ id: "admin-1" }),
          "key-0000001",
          "ca-prod-one",
          { reason: "caCompromise" },
        );
        expect(markAuditSucceeded).toHaveBeenCalled();
        expect(write).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: "pki.ca.revoke",
            outcome: "succeeded",
            target: { caId: "ca-prod-one", reason: "caCompromise" },
          }),
        );
      });

      it("audits a failure under the CA", async () => {
        cas.revoke.mockRejectedValueOnce(
          new ApiError(409, "conflict", "No.", "revoke_at_root", {
            details: { reason: "revoke_at_root" },
          }),
        );
        expect(await revoke()).toMatchObject({ statusCode: 409 });
        expect(write).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: "pki.ca.revoke",
            outcome: "failed",
            reasonCode: "revoke_at_root",
            target: { caId: "ca-prod-one" },
          }),
        );
      });
    });

    it("audits a consumer-scoped failure under consumerId", async () => {
      grants.listForConsumer.mockRejectedValueOnce(
        new ApiError(404, "not_found", "No.", "consumer_not_found"),
      );
      await call("GET", "/consumers/payments/issuance-grants");
      expect(write).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: "pki.grant.list",
          target: { consumerId: "payments" },
        }),
      );
    });

    it("validateOnly needs no key, relabels the audit and writes one read event", async () => {
      const result = await call("POST", "/consumers/payments/issuance-grants", {
        query: { validateOnly: "true" },
        body: { name: "web" },
      });
      expect(result).toMatchObject({ statusCode: 200 });
      expect(grants.validateCreate).toHaveBeenCalled();
      expect(grants.create).not.toHaveBeenCalled();
      expect(write).toHaveBeenCalledTimes(1);
      expect(write).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: "pki.grant.validate",
          permission: "read",
          outcome: "succeeded",
        }),
      );
    });

    it("needs If-Match on a validateOnly PUT, and a key without it", async () => {
      const put = (headers: Record<string, string>, query?: Record<string, string>) =>
        call("PUT", "/consumers/payments/issuance-grants/web", {
          headers,
          body: {},
          ...(query === undefined ? {} : { query }),
        });
      expect(await put({}, { validateOnly: "true" })).toMatchObject({ statusCode: 400 });
      expect(
        await put({ "if-match": '"pkv-1"' }, { validateOnly: "true" }),
      ).toMatchObject({ statusCode: 200 });
      expect(grants.validateUpdate).toHaveBeenCalledWith(
        "payments",
        "web",
        "pkv-1",
        {},
      );
      expect(await put({ "if-match": '"pkv-1"' })).toMatchObject({ statusCode: 400 });
    });

    it("treats evaluate as a read even when the operator role is configured", async () => {
      config.adminPkiOperatorRole = "pki-operator";
      issuance.evaluate.mockResolvedValueOnce({
        decision: "deny",
        denial: { reason: "name_not_permitted" },
        trace: [],
      });
      const result = await call(
        "POST",
        "/consumers/payments/issuance-grants/web/evaluate",
        { body: {}, claims: { roles: [] } },
      );
      expect(result).toMatchObject({ statusCode: 200 });
      expect(write).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: "pki.grant.evaluate",
          permission: "read",
          reasonCode: "name_not_permitted",
          target: expect.objectContaining({ decision: "deny" }),
        }),
      );
      const refused = await call("POST", "/cas/ca-prod-one/certificates", {
        body: {},
        headers: { "idempotency-key": "key-0000001" },
        claims: { roles: [] },
      });
      expect(refused).toMatchObject({ statusCode: 403 });
    });

    it("passes 429 headers through and merges the denied name into the audit target", async () => {
      issuance.issueForAdmin.mockRejectedValueOnce(
        new ApiError(429, "issuance_rate_limited", "Slow down.", "admin_hour", {
          details: { reason: "admin_hour", retryAfterSeconds: 30 },
          headers: { "retry-after": "30" },
        }),
      );
      const limited = await call("POST", "/cas/ca-prod-one/certificates", {
        body: {},
        headers: { "idempotency-key": "key-0000001" },
      });
      expect(limited).toMatchObject({
        statusCode: 429,
        headers: expect.objectContaining({ "retry-after": "30" }),
      });
      issuance.issueForAdmin.mockRejectedValueOnce(
        new ApiError(403, "issuance_denied", "No.", "name_not_permitted", {
          details: {
            reason: "name_not_permitted",
            deniedNameType: "dns",
            deniedName: "evil.test",
          },
        }),
      );
      await call("POST", "/cas/ca-prod-one/certificates", {
        body: {},
        headers: { "idempotency-key": "key-0000002" },
      });
      expect(write).toHaveBeenLastCalledWith(
        expect.objectContaining({
          reasonCode: "name_not_permitted",
          target: {
            caId: "ca-prod-one",
            deniedNameType: "dns",
            deniedName: "evil.test",
          },
        }),
      );
    });

    it("writes an incomplete bulk revoke's audit directly, without marking an idempotency record", async () => {
      const result = {
        body: { complete: false },
        status: 200,
        shouldWriteTerminalAudit: false,
        auditTarget: { consumerId: "payments", bulk: "true", complete: "false" },
        complete: false,
      };
      certificates.bulkRevoke.mockResolvedValueOnce(result);
      const response = await call(
        "POST",
        "/consumers/payments/certificates/revoke",
        { body: {}, headers: { "idempotency-key": "key-0000003" } },
      );
      expect(response).toMatchObject({ statusCode: 200 });
      expect(write).toHaveBeenCalledWith(
        expect.objectContaining({
          outcome: "succeeded",
          operation: "pki.certificate.revoke",
          target: expect.objectContaining({ complete: "false" }),
        }),
      );
      expect(markAuditSucceeded).not.toHaveBeenCalled();
      certificates.bulkRevoke.mockResolvedValueOnce({
        ...result,
        body: { complete: true },
        shouldWriteTerminalAudit: true,
        complete: true,
      });
      (write as jest.Mock).mockResolvedValueOnce({ eventId: "e-1" });
      await call("POST", "/consumers/payments/certificates/revoke", {
        body: {},
        headers: { "idempotency-key": "key-0000004" },
      });
      expect(markAuditSucceeded).toHaveBeenCalledTimes(1);
    });
  });
});
