import { createPublicKey, verify, type JsonWebKey } from "node:crypto";
import type { APIGatewayProxyEventV2WithJWTAuthorizer } from "aws-lambda";

/**
 * Emulates what an API Gateway HTTP API JWT authorizer does before Hemlig's
 * Lambda runs. There is no real gateway in CI, so this reproduces the
 * documented checks (signature, iss, aud, exp, nbf, route scopes) and the
 * payload 2.0 claim flattening that `src/auth/admin-token.ts` has to cope with.
 * Everything here is test tooling; it is never part of the Lambda bundle.
 */

export type JwtClaims = Record<string, unknown>;

export interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly use?: string;
  readonly alg?: string;
  readonly [name: string]: unknown;
}

export interface AuthorizerSettings {
  readonly issuer: string;
  /** Accepted audiences; the token's `aud` (or `client_id`) must include one. */
  readonly audiences: readonly string[];
  /** Route scopes; the token must carry at least one, like the gateway. */
  readonly scopes: readonly string[];
  readonly jwks: readonly Jwk[];
  /** Seconds since epoch; injectable for tests. */
  readonly now?: number;
}

export class GatewayRejection extends Error {
  public constructor(
    public readonly reason:
      | "malformed"
      | "signature"
      | "issuer"
      | "audience"
      | "expired"
      | "not_yet_valid"
      | "scope",
    message: string,
  ) {
    super(message);
  }
}

const decodeJson = (part: string | undefined): Record<string, unknown> => {
  if (part === undefined || !/^[A-Za-z0-9_-]+$/.test(part)) {
    throw new GatewayRejection("malformed", "token segment is not base64url");
  }
  try {
    const value: unknown = JSON.parse(
      Buffer.from(part, "base64url").toString("utf8"),
    );
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new GatewayRejection("malformed", "token segment is not a JSON object");
};

/** Verifies an RS256 JWT against the JWKS, then iss/aud/exp/nbf/scope. Returns the claims. */
export const verifyAccessToken = (
  token: string,
  settings: AuthorizerSettings,
): JwtClaims => {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new GatewayRejection(
      "malformed",
      "token does not have three segments",
    );
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [
    string,
    string,
    string,
  ];
  const header = decodeJson(encodedHeader);
  if (header.alg !== "RS256") {
    throw new GatewayRejection(
      "signature",
      `unsupported alg ${String(header.alg)}`,
    );
  }
  const candidates = settings.jwks.filter(
    (key) =>
      key.kty === "RSA" &&
      (key.use === undefined || key.use === "sig") &&
      (key.alg === undefined || key.alg === "RS256") &&
      (header.kid === undefined || key.kid === header.kid),
  );
  if (candidates.length === 0 || !/^[A-Za-z0-9_-]+$/.test(encodedSignature)) {
    throw new GatewayRejection("signature", "no matching signing key");
  }
  const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  const signature = Buffer.from(encodedSignature, "base64url");
  const valid = candidates.some((key) =>
    verify(
      "RSA-SHA256",
      signed,
      createPublicKey({ key: key as JsonWebKey, format: "jwk" }),
      signature,
    ),
  );
  if (!valid) {
    throw new GatewayRejection("signature", "signature does not verify");
  }

  const claims = decodeJson(encodedPayload);
  const now = settings.now ?? Math.floor(Date.now() / 1000);
  if (claims.iss !== settings.issuer) {
    throw new GatewayRejection(
      "issuer",
      "iss does not match the authorizer issuer",
    );
  }
  const audienceValue = claims.aud ?? claims.client_id;
  const audience =
    typeof audienceValue === "string"
      ? [audienceValue]
      : Array.isArray(audienceValue)
        ? audienceValue
        : [];
  if (
    !audience.some(
      (value) =>
        typeof value === "string" && settings.audiences.includes(value),
    )
  ) {
    throw new GatewayRejection(
      "audience",
      "aud does not include a configured audience",
    );
  }
  if (typeof claims.exp !== "number" || claims.exp <= now) {
    throw new GatewayRejection("expired", "token is expired or has no exp");
  }
  if (
    claims.nbf !== undefined &&
    (typeof claims.nbf !== "number" || claims.nbf > now)
  ) {
    throw new GatewayRejection("not_yet_valid", "token is not yet valid");
  }
  const granted = [claims.scope, claims.scp].flatMap((value) =>
    Array.isArray(value)
      ? value.filter((entry): entry is string => typeof entry === "string")
      : typeof value === "string"
        ? value.split(" ")
        : [],
  );
  if (
    settings.scopes.length > 0 &&
    !settings.scopes.some((scope) => granted.includes(scope))
  ) {
    throw new GatewayRejection(
      "scope",
      "token carries none of the route scopes",
    );
  }
  return claims;
};

type FlatClaim = string | string[];

const renderValue = (value: unknown): string => {
  if (Array.isArray(value)) {
    return `[${value.map(renderValue).join(" ")}]`;
  }
  if (typeof value === "object" && value !== null) {
    // Go's map rendering, which is what the gateway emits for object claims.
    const entries = Object.entries(value).map(
      ([key, entry]) => `${key}:${renderValue(entry)}`,
    );
    return `map[${entries.join(" ")}]`;
  }
  return String(value);
};

/**
 * Renders claims the way the gateway presents `authorizer.jwt.claims`: every
 * value is a string, arrays become `[a b]`, objects become `map[k:v]`.
 */
export const flattenClaims = (claims: JwtClaims): Record<string, FlatClaim> =>
  Object.fromEntries(
    Object.entries(claims).map(([name, value]) => [name, renderValue(value)]),
  );

/** An HTTP API payload 2.0 event with the original Authorization header kept. */
export const gatewayEvent = (
  claims: JwtClaims,
  authorization: string,
  scopes: readonly string[],
): APIGatewayProxyEventV2WithJWTAuthorizer =>
  ({
    version: "2.0",
    routeKey: "GET /v1/admin/secrets",
    rawPath: "/v1/admin/secrets",
    headers: { authorization },
    requestContext: {
      authorizer: {
        jwt: { claims: flattenClaims(claims), scopes: [...scopes] },
      },
    },
  }) as unknown as APIGatewayProxyEventV2WithJWTAuthorizer;
