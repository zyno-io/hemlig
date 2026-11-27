import type { AppConfig } from "../aws/config";
import {
  adminTokenFromEvent,
  assertRoleClaim,
  hasRequiredRole,
  resolveClaim,
} from "./admin-token";
import { adminJwtEvent, testExp, unsignedJwt } from "./test-support";

const ISS = "https://issuer.example.test";
const base = {
  adminJwtIssuer: ISS,
  adminJwtAudience: "hemlig-api",
  adminActorSubjectClaim: "sub",
} as unknown as AppConfig;
const withConfig = (extra: Partial<AppConfig>): AppConfig => ({ ...base, ...extra });
const claimsOf = (extra: Record<string, unknown> = {}) => ({
  iss: ISS,
  aud: "hemlig-api",
  sub: "subject-1",
  ...extra,
});

describe("provider fixture matrix", () => {
  const admin = { adminJwtRole: "Hemlig.Administrator" };
  const cases: Array<{
    name: string;
    config: Partial<AppConfig>;
    claims: Record<string, unknown>;
    allowed: boolean;
  }> = [
    { name: "Entra roles array", config: admin, claims: claimsOf({ roles: ["Hemlig.Administrator"] }), allowed: true },
    { name: "Entra without the role", config: admin, claims: claimsOf({ roles: ["Reader"] }), allowed: false },
    { name: "Entra without a roles claim", config: admin, claims: claimsOf(), allowed: false },
    { name: "Entra multiple roles", config: admin, claims: claimsOf({ roles: ["Reader", "Hemlig.Administrator", "Other"] }), allowed: true },
    {
      name: "Keycloak realm_access pointer",
      config: { ...admin, adminRoleClaim: "/realm_access/roles" },
      claims: claimsOf({ realm_access: { roles: ["offline_access", "Hemlig.Administrator"] } }),
      allowed: true,
    },
    {
      name: "Keycloak pointer with missing intermediate",
      config: { ...admin, adminRoleClaim: "/realm_access/roles" },
      claims: claimsOf({ roles: ["Hemlig.Administrator"] }),
      allowed: false,
    },
    {
      name: "Keycloak client roles pointer",
      config: { ...admin, adminRoleClaim: "/resource_access/hemlig/roles" },
      claims: claimsOf({ resource_access: { hemlig: { roles: ["Hemlig.Administrator"] } } }),
      allowed: true,
    },
    {
      name: "Okta groups",
      config: { adminJwtRole: "Hemlig Admins", adminRoleClaim: "groups" },
      claims: claimsOf({ groups: ["Everyone", "Hemlig Admins"] }),
      allowed: true,
    },
    {
      name: "Auth0 namespaced claim",
      config: { ...admin, adminRoleClaim: "https://hemlig.example.com/roles" },
      claims: claimsOf({ "https://hemlig.example.com/roles": ["Hemlig.Administrator"] }),
      allowed: true,
    },
    {
      name: "Zitadel role object keys",
      config: { ...admin, adminRoleClaim: "urn:zitadel:iam:org:project:roles" },
      claims: claimsOf({ "urn:zitadel:iam:org:project:roles": { "Hemlig.Administrator": { "org-1": "org.example" } } }),
      allowed: true,
    },
    {
      name: "Zitadel object without the role key (value must not match)",
      config: { ...admin, adminRoleClaim: "urn:zitadel:iam:org:project:roles" },
      claims: claimsOf({ "urn:zitadel:iam:org:project:roles": { other: "Hemlig.Administrator" } }),
      allowed: false,
    },
    {
      name: "comma-separated admin role list, any match",
      config: { adminJwtRole: "A, B" },
      claims: claimsOf({ roles: ["B"] }),
      allowed: true,
    },
    {
      name: "unexpected claim type",
      config: admin,
      claims: claimsOf({ roles: [{ "Hemlig.Administrator": true }, 7, null] }),
      allowed: false,
    },
    {
      name: "role claim is a string, compared whole",
      config: admin,
      claims: claimsOf({ roles: "Hemlig.Administrator" }),
      allowed: true,
    },
    {
      name: "space-separated string is not split",
      config: admin,
      claims: claimsOf({ roles: "Reader Hemlig.Administrator" }),
      allowed: false,
    },
    {
      name: "legacy role fallback only when no claim is configured",
      config: admin,
      claims: claimsOf({ role: "Hemlig.Administrator" }),
      allowed: true,
    },
    {
      name: "legacy role fallback ignored when a claim is configured",
      config: { ...admin, adminRoleClaim: "groups" },
      claims: claimsOf({ role: "Hemlig.Administrator" }),
      allowed: false,
    },
    { name: "no role configured", config: {}, claims: claimsOf(), allowed: true },
    {
      name: "blank role list matches nothing",
      config: { adminJwtRole: " , " },
      claims: claimsOf({ roles: [""] }),
      allowed: false,
    },
  ];

  it.each(cases)("$name", ({ config, claims, allowed }) => {
    jest.spyOn(console, "warn").mockImplementation();
    const run = () => adminTokenFromEvent(adminJwtEvent(claims), withConfig(config));
    if (allowed) {
      expect(run().actor).toEqual({ type: "human", id: "subject-1" });
    } else {
      expect(run).toThrow(expect.objectContaining({ statusCode: 403 }));
    }
  });
});

describe("group overage", () => {
  beforeEach(() => jest.spyOn(console, "warn").mockImplementation());
  afterEach(() => jest.restoreAllMocks());

  it.each([
    ["_claim_names.groups", { _claim_names: { groups: "src1" }, _claim_sources: { src1: {} } }, "groups"],
    ["hasgroups", { hasgroups: true }, "groups"],
  ])("refuses %s with a distinct error and never reads groups", (_name, extra, claim) => {
    expect.assertions(2);
    try {
      adminTokenFromEvent(
        adminJwtEvent(claimsOf(extra)),
        withConfig({ adminJwtRole: "g1", adminRoleClaim: claim }),
      );
    } catch (error) {
      expect(error).toMatchObject({ statusCode: 403, message: expect.stringContaining("group-overage") });
      expect(String((console.warn as jest.Mock).mock.calls.at(-1)?.[0])).toContain('"reason":"role_overage"');
    }
  });

  it("does not block a deployment whose role claim is present", () => {
    expect(
      adminTokenFromEvent(
        adminJwtEvent(claimsOf({ roles: ["Hemlig.Administrator"], _claim_names: { groups: "src1" } })),
        withConfig({ adminJwtRole: "Hemlig.Administrator" }),
      ).actor.id,
    ).toBe("subject-1");
  });
});

describe("bearer and binding", () => {
  const config = withConfig({ adminJwtRole: "Hemlig.Administrator" });
  const good = claimsOf({ roles: ["Hemlig.Administrator"] });
  beforeEach(() => jest.spyOn(console, "warn").mockImplementation());
  afterEach(() => jest.restoreAllMocks());
  const reasonOf = () => String((console.warn as jest.Mock).mock.calls.at(-1)?.[0]);

  it("refuses without an authorizer", () => {
    expect(() => adminTokenFromEvent({ headers: {}, requestContext: {} } as never, config)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
  });

  it.each([
    ["no Authorization header", null],
    ["garbage", "Bearer not-a-jwt"],
    ["empty bearer", "Bearer "],
    ["two segments", "Bearer a.b"],
    ["a JWE-shaped token", "Bearer a.b.c.d.e"],
    ["non-base64url payload", "Bearer a.%%%.c"],
    ["non-JSON payload", `Bearer a.${Buffer.from("nope").toString("base64url")}.c`],
    ["an array payload", `Bearer ${unsignedJwt([1])}`],
    ["a string payload", `Bearer ${unsignedJwt("x")}`],
  ])("refuses %s", (_name, bearer) => {
    expect(() => adminTokenFromEvent(adminJwtEvent(good, { bearer }), config)).toThrow(
      expect.objectContaining({ statusCode: 403, code: "forbidden" }),
    );
    expect(reasonOf()).toContain("bearer_unreadable");
  });

  it("accepts a lowercase scheme, a raw token and a mixed-case header name", () => {
    const token = unsignedJwt({ exp: testExp, ...good });
    for (const header of [`bearer ${token}`, `BEARER   ${token}`, token]) {
      expect(adminTokenFromEvent(adminJwtEvent(good, { bearer: header }), config).actor.id).toBe("subject-1");
    }
    expect(
      adminTokenFromEvent(
        adminJwtEvent(good, { bearer: null, headers: { Authorization: `Bearer ${token}` } }),
        config,
      ).actor.id,
    ).toBe("subject-1");
  });

  it.each([
    ["iss", { ...good, iss: "https://other.example.test" }],
    ["exp", { ...good, exp: testExp + 1 }],
    ["missing exp", { ...good, exp: undefined }],
    ["string exp in the bearer", { ...good, exp: String(testExp) }],
    ["subject", { ...good, sub: "someone-else" }],
    ["missing subject", { ...good, sub: undefined }],
    ["aud", { ...good, aud: "another-api" }],
    ["aud as an extra array element", { ...good, aud: ["hemlig-api", "extra"] }],
    ["aud removed in favour of client_id", { ...good, aud: undefined, client_id: "hemlig-api" }],
  ])("refuses a bearer whose %s differs from the gateway", (_name, bearer) => {
    expect(() => adminTokenFromEvent(adminJwtEvent(good, { bearer }), config)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
    expect(reasonOf()).toContain('"reason":"binding"');
  });

  it("refuses a bearer carrying roles the gateway token did not", () => {
    // Same iss/exp/sub/aud, different token: still the validated bearer's own roles that count.
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(claimsOf({ roles: ["Hemlig.Administrator"] }), { bearer: claimsOf({ roles: ["Reader"] }) }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
  });

  it("binds exp numerically when the gateway renders it as a string", () => {
    const event = adminJwtEvent(good);
    (event.requestContext.authorizer.jwt.claims as Record<string, unknown>).exp = String(testExp);
    expect(adminTokenFromEvent(event, config).actor.id).toBe("subject-1");
    (event.requestContext.authorizer.jwt.claims as Record<string, unknown>).exp = "not-a-number";
    expect(() => adminTokenFromEvent(event, config)).toThrow(expect.objectContaining({ statusCode: 403 }));
  });

  it("binds an array aud rendered by the gateway as `[a b]`", () => {
    const multi = withConfig({ adminJwtAudience: "x, hemlig-api" });
    const bearer = { ...good, aud: ["hemlig-api", "other"] };
    const event = adminJwtEvent({ ...good, aud: "[hemlig-api other]" }, { bearer });
    expect(adminTokenFromEvent(event, multi).actor.id).toBe("subject-1");
  });

  it("denies a forged bearer that copies the identity claims and adds the admin role", () => {
    const identity = { iss: ISS, aud: "hemlig-api", sub: "subject-1", oid: "oid-1" };
    const gatewayReader = { ...identity, roles: ["Reader"] };
    for (const forged of [
      { ...identity, roles: ["Hemlig.Administrator"] },
      { ...identity, roles: ["Reader", "Hemlig.Administrator"] },
      { ...identity, roles: ["Reader", { x: 1 }, "Hemlig.Administrator"] },
      identity, // forged claim set without roles, gateway reported roles
    ]) {
      expect(() => adminTokenFromEvent(adminJwtEvent(gatewayReader, { bearer: forged }), config)).toThrow(
        expect.objectContaining({ statusCode: 403 }),
      );
    }
    // The forged token adds a claim the gateway never saw.
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(identity, { bearer: { ...identity, roles: ["Hemlig.Administrator"] } }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
    expect(reasonOf()).toContain('"reason":"binding"');
    // Gateway claims the bearer lacks.
    expect(() =>
      adminTokenFromEvent(adminJwtEvent({ ...identity, extra: "x" }, { bearer: identity }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
  });

  it("binds the duplicate-key case: the last value parsed must match the gateway", () => {
    const payload = (roles: string) =>
      `{"iss":"${ISS}","aud":"hemlig-api","sub":"subject-1","exp":${testExp},"roles":["Reader"],"roles":${roles}}`;
    const header = (json: string) => `Bearer h.${Buffer.from(json).toString("base64url")}.s`;
    const reader = { ...good, roles: ["Reader"] };
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(reader, { bearer: header(payload('["Hemlig.Administrator"]')) }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(reader, { bearer: header(payload('["Reader"]')) }), config),
    ).toThrow("does not satisfy"); // binds, then no admin role
  });

  it("compares aud as a true set", () => {
    const withAud = (gateway: unknown, bearer: unknown) =>
      adminJwtEvent({ ...good, aud: gateway as string }, { bearer: { ...good, aud: bearer } });
    expect(() => adminTokenFromEvent(withAud("[hemlig-api other]", ["hemlig-api", "hemlig-api"]), config)).toThrow();
    expect(() => adminTokenFromEvent(withAud("[hemlig-api]", ["hemlig-api", "other"]), config)).toThrow();
    expect(adminTokenFromEvent(withAud("[hemlig-api other]", ["other", "hemlig-api"]), config).actor.id).toBe("subject-1");
    expect(adminTokenFromEvent(withAud(["hemlig-api", "other"], ["hemlig-api", "other"]), config).actor.id).toBe("subject-1");
  });

  it("treats aud null as absent", () => {
    const noAud = { iss: ISS, sub: "subject-1", client_id: "hemlig-api", roles: ["Hemlig.Administrator"] };
    expect(
      adminTokenFromEvent(adminJwtEvent(noAud, { bearer: { ...noAud, aud: null } }), config).actor.id,
    ).toBe("subject-1");
    // A gateway that reports an aud contradicts a null aud in the bearer.
    expect(() =>
      adminTokenFromEvent(adminJwtEvent({ ...noAud, aud: "other" }, { bearer: { ...noAud, aud: null } }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
  });

  it.each([[""], [true], ["01"], ["1e9"], [1.5], [`${testExp}.0`]])(
    "requires the gateway exp to be a canonical integer (%p)",
    (exp) => {
      const event = adminJwtEvent(good);
      (event.requestContext.authorizer.jwt.claims as Record<string, unknown>).exp = exp;
      expect(() => adminTokenFromEvent(event, config)).toThrow(expect.objectContaining({ statusCode: 403 }));
    },
  );

  it("does not let a scalar claim differ between gateway and bearer", () => {
    expect(() =>
      adminTokenFromEvent(adminJwtEvent({ ...good, email: "a@x.test" }, { bearer: { ...good, email: "b@x.test" } }), config),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
  });

  it("never logs the token or claim values", () => {
    const secret = unsignedJwt({ exp: testExp, ...good, email: "secret@example.test" });
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(good, { bearer: `Bearer ${secret}` }), withConfig({ adminJwtRole: "Nope" })),
    ).toThrow();
    const logged = JSON.stringify((console.warn as jest.Mock).mock.calls);
    for (const value of [secret, "subject-1", "Hemlig.Administrator", "secret@example.test"]) {
      expect(logged).not.toContain(value);
    }
  });
});

describe("audience, scope and actor", () => {
  beforeEach(() => jest.spyOn(console, "warn").mockImplementation());
  afterEach(() => jest.restoreAllMocks());

  it("accepts any audience from a comma-separated list, and a single value as before", () => {
    const list = withConfig({ adminJwtAudience: "a, hemlig-api ,b" });
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf()), list).actor.id).toBe("subject-1");
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf({ aud: "b" })), list).actor.id).toBe("subject-1");
    expect(() => adminTokenFromEvent(adminJwtEvent(claimsOf({ aud: "c" })), list)).toThrow("does not satisfy");
    expect(() => adminTokenFromEvent(adminJwtEvent(claimsOf({ aud: "hemlig-api-2" })), base)).toThrow("does not satisfy");
  });

  it("matches an array aud any-of and uses client_id only when aud is absent", () => {
    const aud = ["other", "hemlig-api"];
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf({ aud })), base).actor.id).toBe("subject-1");
    const { aud: _aud, ...noAud } = claimsOf();
    expect(adminTokenFromEvent(adminJwtEvent({ ...noAud, client_id: "hemlig-api" }), base).actor.id).toBe("subject-1");
    expect(() =>
      adminTokenFromEvent(adminJwtEvent(claimsOf({ aud: "other", client_id: "hemlig-api" })), base),
    ).toThrow("does not satisfy");
  });

  it("requires the scope as a string or array in scope or scp", () => {
    const scoped = withConfig({ adminJwtScope: "hemlig.admin" });
    expect(() => adminTokenFromEvent(adminJwtEvent(claimsOf()), scoped)).toThrow("does not satisfy");
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf({ scp: "x hemlig.admin" })), scoped).actor.id).toBe("subject-1");
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf({ scope: ["hemlig.admin"] })), scoped).actor.id).toBe("subject-1");
  });

  it("exposes role values for PKI roles from the same claim", () => {
    const token = adminTokenFromEvent(
      adminJwtEvent(claimsOf({ realm_access: { roles: ["pki-ca-admin", "pki-operator"] } })),
      withConfig({ adminRoleClaim: "/realm_access/roles" }),
    );
    expect(hasRequiredRole(token.roleValues, "pki-ca-admin")).toBe(true);
    expect(hasRequiredRole(token.roleValues, "x,pki-operator")).toBe(true);
    expect(hasRequiredRole(token.roleValues, "pki-other")).toBe(false);
    expect(hasRequiredRole(token.roleValues, undefined)).toBe(true);
  });

  it("enforces the tenant claim from the bearer", () => {
    const tenanted = withConfig({ adminActorTenantClaim: "tid", adminExpectedTenantId: "t1" });
    expect(adminTokenFromEvent(adminJwtEvent(claimsOf({ tid: "t1" })), tenanted).actor).toMatchObject({ tenantId: "t1" });
    expect(() => adminTokenFromEvent(adminJwtEvent(claimsOf({ tid: "t2" })), tenanted)).toThrow(
      expect.objectContaining({ statusCode: 403 }),
    );
  });
});

describe("resolveClaim", () => {
  const claims = {
    "cognito:groups": ["a"],
    "a/b": 1,
    "a~b": 2,
    nested: { "x/y": { z: ["v"] }, list: [{ id: "first" }] },
    __proto__x: 1,
  };
  it("reads names and JSON Pointers with escapes", () => {
    expect(resolveClaim(claims, "cognito:groups")).toEqual(["a"]);
    expect(resolveClaim(claims, "/nested/x~1y/z")).toEqual(["v"]);
    expect(resolveClaim(claims, "/a~1b")).toBe(1);
    expect(resolveClaim(claims, "/a~0b")).toBe(2);
    expect(resolveClaim(claims, "/nested/list/0/id")).toBe("first");
  });
  it("returns undefined for missing, inherited and mistyped paths", () => {
    expect(resolveClaim(claims, "/missing/x")).toBeUndefined();
    expect(resolveClaim(claims, "/nested/z/q")).toBeUndefined();
    expect(resolveClaim(claims, "constructor")).toBeUndefined();
    expect(resolveClaim(claims, "/nested/list/length")).toBeUndefined();
    expect(resolveClaim(claims, "/cognito:groups/x")).toBeUndefined();
  });
  it("rejects malformed pointers at config time", () => {
    expect(() => assertRoleClaim("/a~2b")).toThrow("JSON Pointer");
    expect(() => assertRoleClaim("/a~")).toThrow("JSON Pointer");
    expect(() => assertRoleClaim("/a~0b")).not.toThrow();
    expect(() => assertRoleClaim("roles")).not.toThrow();
  });
});
