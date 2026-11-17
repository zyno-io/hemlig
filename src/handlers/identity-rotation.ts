import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { consumerActorFromEvent } from "../auth/actors";
import { badRequest, invalidCsr } from "../domain/errors";
import { isObject } from "../domain/validation";
import { json, parseJsonBody } from "../http/responses";
import { humanOperation } from "../services/operations";
import { withErrorResponse } from "./shared";

/**
 * Isolated from the generic consumer handler so that only this function holds
 * issuer-CA decrypt and IoT registration permissions.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> =>
  withErrorResponse(event, async (app, correlationId, setAuditContext) => {
    if (
      event.requestContext.http.method !== "POST" ||
      event.rawPath !== "/v1/agent/identities/rotate"
    ) {
      throw badRequest("The requested identity route is not supported.");
    }
    const actor = await consumerActorFromEvent(event, app.repository);
    const operation = "agent.identity.rotate";
    const sourceIp = event.requestContext.http.sourceIp;
    setAuditContext({ actor, operation, sourceIp });
    await app.audit.write({
      correlationId,
      outcome: "attempted",
      actor,
      operation,
      sourceIp,
    });
    const key = requireIdempotencyKey(event.headers["idempotency-key"]);
    const body = parseJsonBody(event.body);
    if (
      !isObject(body) ||
      typeof body.apiCertificateSigningRequestPem !== "string"
    ) {
      throw badRequest("apiCertificateSigningRequestPem is required.");
    }
    if (body.apiCertificateSigningRequestPem.length > 16_384) {
      throw invalidCsr("apiCertificateSigningRequestPem is too large.");
    }
    const callerCertificatePem =
      event.requestContext.authentication?.clientCert?.clientCertPem;
    if (callerCertificatePem === undefined) {
      throw badRequest("A client certificate is required.");
    }
    const result = await app.agentIdentities.rotate({
      actor,
      callerCertificatePem,
      apiCertificateSigningRequestPem: body.apiCertificateSigningRequestPem,
      idempotencyKey: key,
      onAuthorized: async () => {
        await app.audit.write({
          correlationId,
          outcome: "authorized",
          actor,
          operation,
          sourceIp,
        });
      },
    });
    const response = (): APIGatewayProxyStructuredResultV2 =>
      json(201, {
        consumerId: result.consumerId,
        environment: result.environment,
        rootFingerprint: result.rootFingerprint,
        apiFingerprint: result.apiFingerprint,
        apiCertificatePem: result.apiCertificatePem,
        notBefore: result.notBefore,
        notAfter: result.notAfter,
        status: result.status,
      });
    if (!result.shouldWriteTerminalAudit) {
      return response();
    }
    return humanOperation(
      app,
      actor,
      key,
      correlationId,
      operation,
      sourceIp,
      { consumerId: result.consumerId, apiFingerprint: result.apiFingerprint },
      response,
    );
  });

const requireIdempotencyKey = (value: string | undefined): string => {
  if (value === undefined || value.length < 8 || value.length > 128) {
    throw badRequest(
      "Idempotency-Key is required and must be 8-128 characters.",
    );
  }
  return value;
};
