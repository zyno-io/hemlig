import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { consumerActorFromEvent } from "../auth/actors";
import { badRequest, forbidden } from "../domain/errors";
import { empty, json, parseJsonBody } from "../http/responses";
import { isObject, parseMetadata, parsePayload } from "../domain/validation";
import { isoNow } from "../util/encoding";
import { withErrorResponse } from "./shared";

export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> =>
  withErrorResponse(event, async (app, correlationId, setAuditContext) => {
    const actor = await consumerActorFromEvent(event, app.repository);
    const consumerId = actor.consumerId;
    if (consumerId === undefined) {
      throw forbidden();
    }
    const environment = actor.environment;
    if (environment === undefined) {
      throw forbidden();
    }
    // An agent identity is deliberately unable to fall back to the generic
    // delivery routes: doing so would let a compromised namespace bypass its
    // remote AgentGrant path boundary by guessing a secret ID.
    const isAgent =
      (await app.repository.getAgentGrantForConsumer(consumerId)) !== undefined;
    const operation = `${isAgent ? "agent" : "consumer"}${event.requestContext.http.method.toLowerCase()}:${event.rawPath}`;
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
    const decodedPath = decodeRequestPath(event.rawPath);
    const secretMatch = new RegExp(`^/v1/secrets/(${secretIdRoutePart})$`).exec(
      decodedPath,
    );
    const agentSecretMatch = new RegExp(
      `^/v1/agent/secrets/(${secretIdRoutePart})$`,
    ).exec(decodedPath);
    const agentPayloadMatch = new RegExp(
      `^/v1/agent/secrets/(${secretIdRoutePart})/payload$`,
    ).exec(decodedPath);
    const agentControlMatch = new RegExp(
      `^/v1/agent/secrets/(${secretIdRoutePart})/control$`,
    ).exec(decodedPath);
    if (
      event.requestContext.http.method === "GET" &&
      event.rawPath === "/v1/agent/config"
    ) {
      const grant = await app.agents.config(consumerId, environment);
      await app.audit.write({
        correlationId,
        outcome: "authorized",
        actor,
        operation,
        sourceIp: event.requestContext.http.sourceIp,
      });
      await app.audit.write({
        correlationId,
        outcome: "succeeded",
        actor,
        operation,
        target: { grantId: grant.grantId },
        sourceIp: event.requestContext.http.sourceIp,
      });
      return json(200, {
        consumerId: grant.consumerId,
        environment: grant.environment,
        grant: {
          grantId: grant.grantId,
          capabilities: grant.capabilities,
          readSecretIdPrefixes: grant.readSecretIdPrefixes ?? [],
          writeSecretIdPrefixes: grant.writeSecretIdPrefixes ?? [],
        },
        mqtt: {
          endpoint: app.config.iotEndpoint,
          clientId: grant.consumerId,
          topic: `${app.config.iotNotificationTopicPrefix}/${grant.consumerId}`,
        },
      });
    }
    if (
      event.requestContext.http.method === "POST" &&
      event.rawPath === "/v1/agent/secrets"
    ) {
      const key = requireIdempotencyKey(event.headers["idempotency-key"]);
      const body = parseObjectBody(event.body);
      const control = await app.agents.create({
        consumerId,
        environment,
        secretId: requiredString(body, "secretId"),
        metadata: parseMetadata(body.metadata),
        actor,
        idempotencyKey: key,
      });
      await agentMutationAudit(
        app,
        correlationId,
        actor,
        operation,
        event,
        environment,
        control.secretId,
        control.controlVersionId,
      );
      return json(201, control, { etag: control.controlVersionId });
    }
    if (
      event.requestContext.http.method === "GET" &&
      agentControlMatch !== null
    ) {
      const control = await app.agents.control(
        consumerId,
        environment,
        agentControlMatch[1] as string,
      );
      await app.audit.write({
        correlationId,
        outcome: "authorized",
        actor,
        operation,
        target: { environment, secretId: control.secretId },
        sourceIp: event.requestContext.http.sourceIp,
      });
      await app.audit.write({
        correlationId,
        outcome: "succeeded",
        actor,
        operation,
        target: {
          secretId: control.secretId,
          environment,
          controlVersionId: control.controlVersionId,
        },
        sourceIp: event.requestContext.http.sourceIp,
      });
      return json(200, agentControlResponse(control), {
        etag: control.controlVersionId,
      });
    }
    if (
      event.requestContext.http.method === "PUT" &&
      agentSecretMatch !== null
    ) {
      const key = requireIdempotencyKey(event.headers["idempotency-key"]);
      const body = parseObjectBody(event.body);
      const control = await app.agents.update({
        consumerId,
        environment,
        secretId: agentSecretMatch[1] as string,
        expectedControlVersionId: requireIfMatch(event.headers["if-match"]),
        ...(body.metadata === undefined
          ? {}
          : { metadata: parseMetadata(body.metadata) }),
        actor,
        idempotencyKey: key,
      });
      await agentMutationAudit(
        app,
        correlationId,
        actor,
        operation,
        event,
        environment,
        control.secretId,
        control.controlVersionId,
      );
      return json(200, control, { etag: control.controlVersionId });
    }
    if (
      event.requestContext.http.method === "PUT" &&
      agentPayloadMatch !== null
    ) {
      const key = requireIdempotencyKey(event.headers["idempotency-key"]);
      const body = parseObjectBody(event.body);
      const control = await app.agents.update({
        consumerId,
        environment,
        secretId: agentPayloadMatch[1] as string,
        expectedControlVersionId: requireIfMatch(event.headers["if-match"]),
        payload: parsePayload(body.payload, app.config.maxPayloadBytes),
        actor,
        idempotencyKey: key,
      });
      await agentMutationAudit(
        app,
        correlationId,
        actor,
        operation,
        event,
        environment,
        control.secretId,
        control.controlVersionId,
      );
      return json(200, control, { etag: control.controlVersionId });
    }
    if (
      event.requestContext.http.method === "GET" &&
      (secretMatch !== null || agentSecretMatch !== null)
    ) {
      const ifNoneMatch = event.headers["if-none-match"]?.replaceAll('"', "");
      const secretId = (agentSecretMatch?.[1] ?? secretMatch?.[1]) as string;
      setAuditContext({
        actor,
        operation,
        target: { environment, secretId },
        permission: "read",
        sourceIp: event.requestContext.http.sourceIp,
      });
      const result =
        isAgent || agentSecretMatch !== null
          ? await app.agents.read(
              consumerId,
              environment,
              secretId,
              ifNoneMatch,
              async () => {
                await app.audit.write({
                  correlationId,
                  outcome: "authorized",
                  actor,
                  operation,
                  target: { environment, secretId },
                  permission: "read",
                  sourceIp: event.requestContext.http.sourceIp,
                });
              },
            )
          : await app.secrets.read(
              consumerId,
              environment,
              secretId,
              ifNoneMatch,
              async () => {
                await app.audit.write({
                  correlationId,
                  outcome: "authorized",
                  actor,
                  operation,
                  target: { environment, secretId },
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
        target: {
          environment,
          secretId,
          controlVersionId: result.controlVersionId,
        },
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
          secretId,
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
          : await app.cursors.decode(rawCursor, consumerId);
      const page = isAgent
        ? await app.agents.listChanges(
            consumerId,
            environment,
            decoded?.lastEvaluatedKey,
          )
        : await app.repository.listAccess(
            consumerId,
            environment,
            decoded?.lastEvaluatedKey,
          );
      const nextCursor =
        page.nextCursor === undefined
          ? undefined
          : await app.cursors.encode({
              scope: consumerId,
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
      "The requested consumer route is not supported by this handler.",
    );
  });

const secretIdRoutePart = "[a-z][a-z0-9-]{2,63}(?:/[a-z][a-z0-9-]{2,63})*";

const decodeRequestPath = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    throw badRequest("The request path is not valid URL encoding.");
  }
};

const parseObjectBody = (body: string | undefined): Record<string, unknown> => {
  const parsed = parseJsonBody(body);
  if (!isObject(parsed)) {
    throw badRequest("The request body must be a JSON object.");
  }
  return parsed;
};

const requiredString = (
  body: Record<string, unknown>,
  name: string,
): string => {
  const value = body[name];
  if (typeof value !== "string" || value.length === 0) {
    throw badRequest(`${name} is required.`);
  }
  return value;
};

const requireIdempotencyKey = (value: string | undefined): string => {
  if (value === undefined || value.length < 8 || value.length > 128) {
    throw badRequest(
      "Idempotency-Key is required and must be 8-128 characters.",
    );
  }
  return value;
};

const requireIfMatch = (value: string | undefined): string => {
  if (value === undefined || value.length === 0) {
    throw badRequest("If-Match is required.");
  }
  return value.replaceAll('"', "");
};

const agentMutationAudit = async (
  app: Parameters<Parameters<typeof withErrorResponse>[1]>[0],
  correlationId: string,
  actor: Awaited<ReturnType<typeof consumerActorFromEvent>>,
  operation: string,
  event: APIGatewayProxyEventV2,
  environment: string,
  secretId: string,
  controlVersionId: string,
): Promise<void> => {
  await app.audit.write({
    correlationId,
    outcome: "authorized",
    actor,
    operation,
    target: { environment, secretId },
    sourceIp: event.requestContext.http.sourceIp,
  });
  await app.audit.write({
    correlationId,
    outcome: "succeeded",
    actor,
    operation,
    target: { environment, secretId, controlVersionId },
    sourceIp: event.requestContext.http.sourceIp,
  });
};

const agentControlResponse = (
  control: import("../domain/types").ControlRevision,
): Record<string, unknown> => ({
  secretId: control.secretId,
  environment: control.environment,
  controlVersionId: control.controlVersionId,
  ...(control.payloadVersionId === undefined
    ? {}
    : { payloadVersionId: control.payloadVersionId }),
  ...(control.payloadKeyCount === undefined
    ? {}
    : { payloadKeyCount: control.payloadKeyCount }),
  state: control.state,
  metadata: control.metadata,
});
