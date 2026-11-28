import { generateKeyPairSync, sign, type JsonWebKey } from "node:crypto";
import type { AppConfig } from "../aws/config";
import { adminTokenFromEvent } from "../auth/admin-token";
import {
  GatewayRejection,
  flattenClaims,
  gatewayEvent,
  verifyAccessToken,
  type AuthorizerSettings,
} from "./oidc-gateway-emulator";

const ISS = "https://idp.example.test/realms/t";
const NOW = 1_800_000_000;
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...(pair.publicKey.export({ format: "jwk" }) as JsonWebKey),
  kid: "k1",
  use: "sig",
  alg: "RS256",
};

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
const mint = (
  payload: Record<string, unknown>,
  key = pair.privateKey,
  header: Record<string, unknown> = {},
) => {
  const body = `${b64({ alg: "RS256", kid: "k1", ...header })}.${b64(payload)}`;
  return `${body}.${sign("RSA-SHA256", Buffer.from(body), key).toString("base64url")}`;
};
const claims = {
  iss: ISS,
  sub: "u1",
  aud: ["other", "hemlig-api"],
  exp: NOW + 600,
  scope: "openid hemlig.admin",
  realm_access: { roles: ["hemlig-admin", "x"] },
  roles: ["hemlig-admin", "x"],
  email_verified: true,
};
const settings: AuthorizerSettings = {
  issuer: ISS,
  audiences: ["hemlig-api"],
  scopes: ["hemlig.admin"],
  jwks: [jwk as never],
  now: NOW,
};
const reason = (
  token: string,
  override: Partial<AuthorizerSettings> = {},
): string | undefined => {
  try {
    verifyAccessToken(token, { ...settings, ...override });
  } catch (error) {
    return error instanceof GatewayRejection ? error.reason : "other";
  }
  return undefined;
};

describe("verifyAccessToken", () => {
  it("accepts a valid token", () => {
    expect(verifyAccessToken(mint(claims), settings).sub).toBe("u1");
  });
  it("rejects a tampered payload", () => {
    const [h, , s] = mint(claims).split(".");
    expect(reason(`${h}.${b64({ ...claims, sub: "evil" })}.${s}`)).toBe(
      "signature",
    );
  });
  it("rejects a foreign signing key and a non-RS256 alg", () => {
    expect(reason(mint(claims, other.privateKey))).toBe("signature");
    expect(reason(mint(claims, pair.privateKey, { alg: "none" }))).toBe(
      "signature",
    );
    expect(reason(mint(claims, pair.privateKey, { kid: "unknown" }))).toBe(
      "signature",
    );
  });
  it("checks iss, aud, exp, nbf and scope", () => {
    expect(reason(mint({ ...claims, iss: "https://evil.test" }))).toBe(
      "issuer",
    );
    expect(reason(mint({ ...claims, aud: "other" }))).toBe("audience");
    expect(
      reason(mint({ ...claims, aud: undefined, client_id: "hemlig-api" })),
    ).toBeUndefined();
    expect(reason(mint({ ...claims, exp: NOW - 1 }))).toBe("expired");
    expect(reason(mint({ ...claims, nbf: NOW + 5 }))).toBe("not_yet_valid");
    expect(reason(mint({ ...claims, scope: "openid" }))).toBe("scope");
    expect(
      reason(mint({ ...claims, scope: undefined, scp: ["hemlig.admin"] })),
    ).toBeUndefined();
  });
  it("rejects malformed tokens", () => {
    expect(reason("a.b")).toBe("malformed");
    expect(reason("!!.b.c")).toBe("malformed");
  });
});

describe("flattenClaims", () => {
  it("renders strings, numbers, booleans, arrays and objects as the gateway does", () => {
    expect(flattenClaims(claims)).toEqual({
      iss: ISS,
      sub: "u1",
      aud: "[other hemlig-api]",
      exp: String(NOW + 600),
      scope: "openid hemlig.admin",
      realm_access: "map[roles:[hemlig-admin x]]",
      roles: "[hemlig-admin x]",
      email_verified: "true",
    });
  });
});

describe("emulated gateway event against adminTokenFromEvent", () => {
  const config = {
    adminJwtIssuer: ISS,
    adminJwtAudience: "hemlig-api",
    adminActorSubjectClaim: "sub",
    adminJwtScope: "hemlig.admin",
    adminJwtRole: "hemlig-admin",
    adminRoleClaim: "/realm_access/roles",
  } as unknown as AppConfig;

  it("accepts the nested and top-level role forms", () => {
    const event = gatewayEvent(claims, `Bearer ${mint(claims)}`, [
      "hemlig.admin",
    ]);
    expect(adminTokenFromEvent(event, config).actor.id).toBe("u1");
    const top = { ...config, adminRoleClaim: "roles" } as AppConfig;
    expect([...adminTokenFromEvent(event, top).roleValues]).toContain(
      "hemlig-admin",
    );
  });
  it("rejects a forged bearer whose top-level roles differ from the gateway's", () => {
    const plain = { ...claims, roles: ["x"] };
    const event = gatewayEvent(plain, `Bearer ${mint(claims)}`, [
      "hemlig.admin",
    ]);
    const top = { ...config, adminRoleClaim: "roles" } as AppConfig;
    jest.spyOn(console, "warn").mockImplementation(() => undefined);
    expect(() => adminTokenFromEvent(event, top)).toThrow();
  });
});
