import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { badRequest } from "../domain/errors";
import type { Actor, AgentCapability, AgentSecretGrant } from "../domain/types";
import { empty, json, parseJsonBody } from "../http/responses";
import { isObject } from "../domain/validation";
import { withErrorResponse } from "./shared";

/**
 * This is deliberately separate from the JWT-protected administrator handler:
 * a one-use bootstrap capability establishes the caller's first mTLS identity.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> =>
  withErrorResponse(event, async (app, correlationId, setAuditContext) => {
    if (
      event.requestContext.http.method !== "POST" ||
      event.rawPath !== "/v1/bootstrap/redeem"
    ) {
      throw badRequest("The requested bootstrap route is not supported.");
    }
    const authorization = event.headers.authorization;
    const token = authorization?.match(
      /^Bootstrap (hmlb_[A-Za-z0-9_-]{43})$/,
    )?.[1];
    if (token === undefined) {
      throw badRequest(
        "A valid Bootstrap authorization capability is required.",
      );
    }
    const body = parseJsonBody(event.body);
    if (
      !isObject(body) ||
      typeof body.apiCertificateSigningRequestPem !== "string"
    ) {
      throw badRequest("apiCertificateSigningRequestPem is required.");
    }
    if (body.apiCertificateSigningRequestPem.length > 16_384) {
      throw badRequest("apiCertificateSigningRequestPem is too large.");
    }
    const result = await app.agentGrants.redeem(
      token,
      body.apiCertificateSigningRequestPem,
    );
    const actor: Actor = {
      type: "consumer",
      id: result.apiFingerprint,
      consumerId: result.consumerId,
      environment: result.environment,
    };
    const operation = "bootstrap.redeem";
    const target = {
      grantId: result.grant.grantId,
      consumerId: result.consumerId,
    };
    setAuditContext({
      actor,
      operation,
      target,
      sourceIp: event.requestContext.http.sourceIp,
    });
    await app.audit.write({
      correlationId,
      outcome: "attempted",
      actor,
      operation,
      target,
      sourceIp: event.requestContext.http.sourceIp,
    });
    await app.audit.write({
      correlationId,
      outcome: "authorized",
      actor,
      operation,
      target,
      sourceIp: event.requestContext.http.sourceIp,
    });
    await app.audit.write({
      correlationId,
      outcome: "succeeded",
      actor,
      operation,
      target,
      sourceIp: event.requestContext.http.sourceIp,
    });
    return json(201, {
      ...result,
      grant: {
        ...result.grant,
        // Retained for older bootstrap clients. These are derived from one
        // paired canonical sequence, not independently sorted arrays.
        readSecretIds: secretIdsForPermission(
          result.grant.secretGrants,
          "read",
        ),
        readSecretUids: secretUidsForPermission(
          result.grant.secretGrants,
          "read",
        ),
        writeSecretIds: secretIdsForPermission(
          result.grant.secretGrants,
          "write",
        ),
        writeSecretUids: secretUidsForPermission(
          result.grant.secretGrants,
          "write",
        ),
      },
    });
  });

const secretIdsForPermission = (
  grants: readonly AgentSecretGrant[],
  permission: AgentCapability,
): readonly string[] =>
  grants
    .filter((grant) => grant.permissions.includes(permission))
    .map((grant) => grant.secretId);

const secretUidsForPermission = (
  grants: readonly AgentSecretGrant[],
  permission: AgentCapability,
): readonly string[] =>
  grants
    .filter((grant) => grant.permissions.includes(permission))
    .map((grant) => grant.secretUid);
