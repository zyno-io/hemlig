import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { clusterActorFromEvent } from "../auth/actors";
import { badRequest, forbidden } from "../domain/errors";
import { empty, json } from "../http/responses";
import { isoNow } from "../util/encoding";
import { withErrorResponse } from "./shared";

export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> =>
  withErrorResponse(event, async (app, correlationId, setAuditContext) => {
    const actor = await clusterActorFromEvent(event, app.repository);
    const clusterId = actor.clusterId;
    if (clusterId === undefined) {
      throw forbidden();
    }
    const environment = actor.environment;
    if (environment === undefined) {
      throw forbidden();
    }
    const operation = `cluster${event.requestContext.http.method.toLowerCase()}:${event.rawPath}`;
    setAuditContext({
      actor,
      operation,
      sourceIp: event.requestContext.http.sourceIp,
    });
    await app.audit.write({
      correlationId,
      outcome: "attempted",
      actor,
      operation,
      sourceIp: event.requestContext.http.sourceIp,
    });
    const secretMatch = /^\/v1\/secrets\/([a-z][a-z0-9-]{2,63})$/.exec(
      event.rawPath,
    );
    if (event.requestContext.http.method === "GET" && secretMatch !== null) {
      const ifNoneMatch = event.headers["if-none-match"]?.replaceAll('"', "");
      const secretId = secretMatch[1] as string;
      setAuditContext({
        actor,
        operation,
        target: { secretId },
        permission: "read",
        sourceIp: event.requestContext.http.sourceIp,
      });
      const result = await app.secrets.read(
        clusterId,
        environment,
        secretId,
        ifNoneMatch,
        async () => {
          await app.audit.write({
            correlationId,
            outcome: "authorized",
            actor,
            operation,
            target: { secretId },
            permission: "read",
            sourceIp: event.requestContext.http.sourceIp,
          });
        },
      );
      await app.audit.write({
        correlationId,
        outcome: "succeeded",
        actor,
        operation,
        target: { secretId, controlVersionId: result.controlVersionId },
        permission: "read",
        sourceIp: event.requestContext.http.sourceIp,
        reasonCode: result.notModified ? "not_modified" : undefined,
      });
      if (result.notModified) {
        return empty(304, { etag: result.controlVersionId });
      }
      return json(
        200,
        {
          secretId: secretMatch[1] as string,
          controlVersionId: result.controlVersionId,
          payloadVersionId: result.payloadVersionId,
          payload: result.payload,
        },
        { etag: result.controlVersionId },
      );
    }
    if (
      event.requestContext.http.method === "GET" &&
      event.rawPath === "/v1/changes"
    ) {
      await app.audit.write({
        correlationId,
        outcome: "authorized",
        actor,
        operation,
        sourceIp: event.requestContext.http.sourceIp,
      });
      const rawCursor = event.queryStringParameters?.cursor;
      const decoded =
        rawCursor === undefined
          ? undefined
          : app.cursors.decode(rawCursor, clusterId);
      const page = await app.repository.listAccess(
        clusterId,
        environment,
        decoded?.lastEvaluatedKey,
      );
      const nextCursor =
        page.nextCursor === undefined
          ? undefined
          : app.cursors.encode({
              clusterId,
              lastEvaluatedKey: JSON.parse(page.nextCursor) as Record<
                string,
                string
              >,
              expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
            });
      await app.audit.write({
        correlationId,
        outcome: "succeeded",
        actor,
        operation,
        sourceIp: event.requestContext.http.sourceIp,
      });
      return json(200, {
        changes: page.changes.map((change) => ({
          secretId: change.secretId,
          controlVersionId: change.controlVersionId,
          payloadVersionId: change.payloadVersionId,
          state: change.state,
          changeKind: change.changeKind,
        })),
        nextCursor,
        generatedAt: isoNow(),
      });
    }
    throw badRequest(
      "The requested cluster route is not supported by this handler.",
    );
  });
