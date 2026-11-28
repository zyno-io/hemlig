/**
 * Proves Hemlig's provider-neutral admin auth against a real, non-Entra OIDC
 * provider (Keycloak). Real Keycloak-signed access tokens are verified by a
 * small API Gateway JWT-authorizer emulator, turned into payload 2.0 events,
 * and handed to Hemlig's real `adminTokenFromEvent` with the Keycloak profile
 * (`ADMIN_ROLE_CLAIM=/realm_access/roles`, and `roles` for the top-level form).
 *
 * Token acquisition: the OAuth password grant against TEST-ONLY public clients
 * in test/oidc/keycloak-realm.json. Real deployments use authorization code
 * with PKCE (a browser round trip). CI needs headless tokens, and the grant
 * type does not change the access token Keycloak signs, which is all this
 * checks. The realm's credentials are throwaway values.
 *
 * Run locally (docker; podman works the same with `podman compose`):
 *   docker compose -f docker-compose.oidc.yml up -d
 *   until curl -fs http://localhost:8080/realms/hemlig-test/.well-known/openid-configuration >/dev/null; do sleep 2; done
 *   KEYCLOAK_URL=http://localhost:8080 yarn verify:oidc
 *   docker compose -f docker-compose.oidc.yml down -v
 */
import { loadConfig, type AppConfig } from "../aws/config";
import { adminTokenFromEvent } from "../auth/admin-token";
import { humanActorFromEvent } from "../auth/actors";
import { ApiError } from "../domain/errors";
import {
  GatewayRejection,
  gatewayEvent,
  verifyAccessToken,
  type AuthorizerSettings,
  type Jwk,
} from "./oidc-gateway-emulator";

const baseUrl = (process.env.KEYCLOAK_URL ?? "http://localhost:8080").replace(
  /\/+$/,
  "",
);
const realm = "hemlig-test";
const issuer = `${baseUrl}/realms/${realm}`;
const audience = "hemlig-api";
const adminScope = "hemlig.admin";
const adminRole = "hemlig-admin";
const adminSubject = "11111111-1111-4111-8111-111111111111";
const plainSubject = "22222222-2222-4222-8222-222222222222";

const configFor = (roleClaim: string): AppConfig =>
  loadConfig({
    HEMLIG_ENVIRONMENT: "oidc-verify",
    CONTROL_TABLE_NAME: "unused",
    WORKFLOW_DUE_INDEX: "unused",
    RETENTION_DUE_INDEX: "unused",
    CATALOG_PATH_INDEX: "unused",
    CONSUMER_DIRECTORY_INDEX: "unused",
    CONSUMER_IDENTITY_INDEX: "unused",
    SECRET_REVISION_INDEX: "unused",
    REVISION_BUCKET_NAME: "unused",
    TRUSTSTORE_BUCKET_NAME: "unused",
    TRUSTSTORE_KEY_PREFIX: "unused",
    PAYLOAD_KMS_KEY_ARN: "unused",
    AUDIT_BUCKET_NAME: "unused",
    AUDIT_PREFIX: "unused",
    DELIVERY_API_CUSTOM_DOMAIN_NAME: "unused",
    DELIVERY_API_HOSTNAME: "unused",
    IOT_ENDPOINT: "unused",
    IOT_NOTIFICATION_POLICY_NAME: "unused",
    IOT_NOTIFICATION_TOPIC_PREFIX: "unused",
    ADMIN_JWT_ISSUER: issuer,
    ADMIN_JWT_AUDIENCE: audience,
    ADMIN_ACTOR_SUBJECT_CLAIM: "sub",
    ADMIN_JWT_SCOPE: adminScope,
    ADMIN_JWT_ROLE: adminRole,
    ADMIN_ROLE_CLAIM: roleClaim,
  });

const nested = configFor("/realm_access/roles");
const topLevel = configFor("roles");

const getJson = async (
  url: string,
  init?: RequestInit,
): Promise<Record<string, unknown>> => {
  const response = await fetch(url, init);
  if (!response.ok) {
    throw new Error(
      `${init?.method ?? "GET"} ${url} returned ${response.status}`,
    );
  }
  return (await response.json()) as Record<string, unknown>;
};

const fetchToken = async (
  clientId: string,
  username: string,
  password: string,
  scope: string,
): Promise<string> => {
  const body = await getJson(`${issuer}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      client_id: clientId,
      username,
      password,
      scope,
    }),
  });
  if (typeof body.access_token !== "string") {
    throw new Error("token response has no access_token");
  }
  return body.access_token;
};

const decodePayload = (token: string): Record<string, unknown> =>
  JSON.parse(
    Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
  ) as Record<string, unknown>;

let failures = 0;
const check = (name: string, ok: boolean, detail = ""): void => {
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}${ok || detail === "" ? "" : ` (${detail})`}`,
  );
  if (!ok) {
    failures += 1;
  }
};

/** Runs Hemlig's code, capturing the structured rejection log it writes. */
const hemlig = (
  event: ReturnType<typeof gatewayEvent>,
  config: AppConfig,
):
  | { allowed: true; subject: string; roles: string[]; actorId: string }
  | { allowed: false; status: number; reason: string } => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (message: unknown) => void warnings.push(String(message));
  try {
    const token = adminTokenFromEvent(event, config);
    const actor = humanActorFromEvent(event, config);
    return {
      allowed: true,
      subject: String(token.claims.sub),
      roles: [...token.roleValues],
      actorId: actor.id,
    };
  } catch (error) {
    const status = error instanceof ApiError ? error.statusCode : 0;
    const reason =
      (JSON.parse(warnings[0] ?? "{}") as { reason?: string }).reason ?? "none";
    return { allowed: false, status, reason };
  } finally {
    console.warn = original;
  }
};

const run = async (): Promise<void> => {
  const discovery = await getJson(`${issuer}/.well-known/openid-configuration`);
  check(
    "discovery issuer equals the configured issuer",
    discovery.issuer === issuer,
    String(discovery.issuer),
  );
  const jwks = ((await getJson(String(discovery.jwks_uri))).keys ??
    []) as Jwk[];
  check(
    "issuer publishes RSA signing keys",
    jwks.some((key) => key.kty === "RSA"),
  );
  const gateway: AuthorizerSettings = {
    issuer,
    audiences: [audience],
    scopes: [adminScope],
    jwks,
  };

  const adminToken = await fetchToken(
    "hemlig-test-cli",
    "admin-user",
    "test-only-admin-password",
    `openid ${adminScope}`,
  );
  const plainToken = await fetchToken(
    "hemlig-test-cli",
    "plain-user",
    "test-only-plain-password",
    `openid ${adminScope}`,
  );
  const otherAudToken = await fetchToken(
    "other-test-client",
    "admin-user",
    "test-only-admin-password",
    `openid ${adminScope}`,
  );
  const noScopeToken = await fetchToken(
    "hemlig-test-cli",
    "admin-user",
    "test-only-admin-password",
    "openid",
  );

  const adminPayload = decodePayload(adminToken);
  check(
    "access token carries nested realm_access.roles",
    JSON.stringify(adminPayload.realm_access).includes(adminRole),
  );
  check(
    "access token carries top-level roles",
    Array.isArray(adminPayload.roles) && adminPayload.roles.includes(adminRole),
  );
  check(
    "access token aud contains the Hemlig audience",
    Array.isArray(adminPayload.aud)
      ? adminPayload.aud.includes(audience)
      : adminPayload.aud === audience,
  );

  const throughGateway = (token: string): ReturnType<typeof gatewayEvent> => {
    const claims = verifyAccessToken(token, gateway);
    return gatewayEvent(claims, `Bearer ${token}`, [adminScope]);
  };
  const gatewayDenies = (token: string): string => {
    try {
      verifyAccessToken(token, gateway);
      return "allowed";
    } catch (error) {
      return error instanceof GatewayRejection ? error.reason : "error";
    }
  };

  for (const [label, config] of [
    ["/realm_access/roles", nested],
    ["roles", topLevel],
  ] as const) {
    const allowed = hemlig(throughGateway(adminToken), config);
    check(
      `[${label}] admin token is allowed with the right subject and roles`,
      allowed.allowed &&
        allowed.subject === adminSubject &&
        allowed.actorId === adminSubject &&
        allowed.roles.includes(adminRole),
      JSON.stringify(allowed),
    );
    const denied = hemlig(throughGateway(plainToken), config);
    check(
      `[${label}] non-admin token is denied with 403 (role)`,
      !denied.allowed && denied.status === 403 && denied.reason === "role",
      JSON.stringify(denied),
    );
  }

  const [head, , signature] = plainToken.split(".");
  const forgedPayload = decodePayload(plainToken);
  (forgedPayload.realm_access as { roles: string[] }).roles.push(adminRole);
  const tampered = `${head}.${Buffer.from(JSON.stringify(forgedPayload)).toString("base64url")}.${signature}`;
  check(
    "tampered payload is denied by the signature check",
    gatewayDenies(tampered) === "signature",
    gatewayDenies(tampered),
  );

  const forgedBearer = (changes: Record<string, unknown>): string => {
    const payload = { ...decodePayload(plainToken), ...changes };
    return `${head}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${signature}`;
  };
  const plainClaims = verifyAccessToken(plainToken, gateway);
  const forgedRoles = hemlig(
    gatewayEvent(
      plainClaims,
      `Bearer ${forgedBearer({ roles: [...(decodePayload(plainToken).roles as string[]), adminRole] })}`,
      [adminScope],
    ),
    topLevel,
  );
  check(
    "forged bearer with extra roles is denied by Hemlig's binding",
    !forgedRoles.allowed &&
      forgedRoles.status === 403 &&
      forgedRoles.reason === "binding",
    JSON.stringify(forgedRoles),
  );
  const forgedSubject = hemlig(
    gatewayEvent(plainClaims, `Bearer ${forgedBearer({ sub: adminSubject })}`, [
      adminScope,
    ]),
    nested,
  );
  check(
    "forged bearer with another subject is denied by Hemlig's binding",
    !forgedSubject.allowed &&
      forgedSubject.status === 403 &&
      forgedSubject.reason === "binding",
    JSON.stringify(forgedSubject),
  );

  check(
    "other-audience token is denied by the gateway (aud)",
    gatewayDenies(otherAudToken) === "audience",
    gatewayDenies(otherAudToken),
  );
  const bypass = hemlig(
    gatewayEvent(decodePayload(otherAudToken), `Bearer ${otherAudToken}`, [
      adminScope,
    ]),
    nested,
  );
  check(
    "other-audience token is also denied by Hemlig itself (audience)",
    !bypass.allowed && bypass.status === 403 && bypass.reason === "audience",
    JSON.stringify(bypass),
  );
  check(
    "token without the hemlig.admin scope is denied by the gateway (scope)",
    gatewayDenies(noScopeToken) === "scope",
    gatewayDenies(noScopeToken),
  );
  check(
    "plain user subject is the expected fixture",
    plainClaims.sub === plainSubject,
  );
};

run()
  .then(() => {
    if (failures > 0) {
      console.error(`${failures} OIDC check(s) failed.`);
      process.exit(1);
    }
    console.log("All OIDC checks passed.");
  })
  .catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
