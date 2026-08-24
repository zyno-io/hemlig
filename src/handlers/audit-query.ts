import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyEventV2WithJWTAuthorizer,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { humanActorFromEvent } from "../auth/actors";
import { badRequest } from "../domain/errors";
import { json } from "../http/responses";
import { parseAuditDate, parseAuditEnvironment, parseAuditSecretId } from "../services/audit";
import { isoNow, sha256Hex, stableJson } from "../util/encoding";
import { withErrorResponse } from "./shared";

/**
 * Archive reads deliberately run in their own Lambda role. This route has the
 * same JWT authorization as the administrator API, but the write-capable
 * administrator Lambda never receives s3:GetObject or s3:ListBucket on the
 * seven-year audit archive.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> =>
  withErrorResponse(event, async (app, correlationId, setAuditContext) => {
    const jwtEvent = event as APIGatewayProxyEventV2WithJWTAuthorizer;
    const actor = humanActorFromEvent(jwtEvent, app.config);
    const operation = `admin${event.requestContext.http.method.toLowerCase()}:${event.rawPath}`;
    const sourceIp = event.requestContext.http.sourceIp;
    setAuditContext({ actor, operation, sourceIp });
    await app.audit.write({
      correlationId,
      outcome: "attempted",
      actor,
      operation,
      sourceIp,
    });
    await app.audit.write({
      correlationId,
      outcome: "authorized",
      actor,
      operation,
      sourceIp,
    });
    if (
      event.requestContext.http.method !== "GET" ||
      event.rawPath !== "/v1/admin/audit"
    ) {
      throw badRequest("The requested audit route is not supported.");
    }
    const date = parseAuditDate(event.queryStringParameters?.date);
    const secretId = parseAuditSecretId(event.queryStringParameters?.secretId);
    const environment = parseAuditEnvironment(event.queryStringParameters?.environment);
    const filterScope = sha256Hex(stableJson({ date, environment, secretId }));
    const scope = `admin:audit:${actor.id}:${filterScope}`;
    const rawCursor = event.queryStringParameters?.cursor;
    const decoded =
      rawCursor === undefined
        ? undefined
        : await app.cursors.decode(rawCursor, scope);
    const page = await app.auditQueries.list(
      date,
      decoded?.lastEvaluatedKey?.continuationToken,
      secretId,
      environment,
    );
    const nextCursor =
      page.nextContinuationToken === undefined
        ? undefined
        : await app.cursors.encode({
            scope,
            lastEvaluatedKey: { continuationToken: page.nextContinuationToken },
            expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
          });
    await app.audit.write({
      correlationId,
      outcome: "succeeded",
      actor,
      operation,
      target: {
        date,
        ...(secretId === undefined ? {} : { secretId }),
      },
      sourceIp,
    });
    return json(200, {
      date: page.date,
      events: page.events,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      generatedAt: isoNow(),
    });
  });
