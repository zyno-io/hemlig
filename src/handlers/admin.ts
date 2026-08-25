import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyEventV2WithJWTAuthorizer,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { humanActorFromEvent } from "../auth/actors";
import { badRequest, notFound } from "../domain/errors";
import type {
  AgentGrantRecord,
  ConsumerRecord,
  EnvironmentRecord,
  HeadRecord,
  IdentityRecord,
  IssuerRecord,
} from "../domain/types";
import {
  isObject,
  parseCatalogPathPrefix,
  parseCatalogSearchQuery,
  parseCatalogTagFilters,
  parseGrants,
  parseMetadata,
  parsePayload,
} from "../domain/validation";
import { empty, errorResponse, json, parseJsonBody } from "../http/responses";
import type { TruststoreStateRecord } from "../repositories/dynamo";
import { humanOperation } from "../services/operations";
import { IssuerService } from "../services/issuer";
import { isoNow, sha256Hex, stableJson } from "../util/encoding";
import { withErrorResponse } from "./shared";

export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> => {
  // API Gateway routes preflight around the JWT-authorized $default route.
  // It adds configured CORS headers itself; this avoids creating audit evidence
  // for a browser capability check rather than an administrator operation.
  if (event.requestContext.http.method === "OPTIONS") {
    return empty(204);
  }
  return withErrorResponse(
    event,
    async (app, correlationId, setAuditContext) => {
      const jwtEvent = event as APIGatewayProxyEventV2WithJWTAuthorizer;
      const actor = humanActorFromEvent(jwtEvent, app.config);
      const operation = `admin${event.requestContext.http.method.toLowerCase()}:${event.rawPath}`;
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
      await app.audit.write({
        correlationId,
        outcome: "authorized",
        actor,
        operation,
        sourceIp: event.requestContext.http.sourceIp,
      });
      if (
        event.requestContext.http.method === "GET" &&
        event.rawPath === "/v1/admin/environments"
      ) {
        const environments = await app.environments.list();
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, {
          environments: environments.map((environment) =>
            environmentResponse(environment),
          ),
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "POST" &&
        event.rawPath === "/v1/admin/environments"
      ) {
        const body = parseObjectBody(event.body);
        const environment = await app.environments.create({
          name: requiredString(body, "name"),
          actor,
        });
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { environment: environment.name },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(201, environmentResponse(environment));
      }
      if (
        event.requestContext.http.method === "GET" &&
        event.rawPath === "/v1/admin/secrets"
      ) {
        const environment = requireQueryString(event, "environment");
        await app.environments.require(environment);
        const pathPrefix = parseCatalogPathPrefix(
          event.queryStringParameters?.pathPrefix,
        );
        const tags = parseCatalogTagFilters(event.queryStringParameters?.tags);
        const q = parseCatalogSearchQuery(event.queryStringParameters?.q);
        if (q !== undefined) {
          // The plain catalog page below applies its filters (workflowState,
          // tags) after a bounded read, so a page can come back empty while
          // nextCursor is still set -- the caller has to keep chasing cursors
          // to learn whether there are really no results. That is tolerable
          // for browsing but wrong for search, where "no matches" must be
          // trustworthy on the first response. So a search paginates
          // internally up to the same bounded cap as the tree route and
          // returns one complete-or-truncated answer instead of a cursor.
          const results = await app.repository.searchSecrets(
            environment,
            pathPrefix,
            tags,
            q,
          );
          await app.audit.write({
            correlationId,
            outcome: "succeeded",
            actor,
            operation,
            sourceIp: event.requestContext.http.sourceIp,
          });
          return json(200, {
            secrets: results.secrets.map((secret) =>
              secretCatalogEntry(secret),
            ),
            truncated: results.truncated,
            generatedAt: isoNow(),
          });
        }
        const rawCursor = event.queryStringParameters?.cursor;
        const cursorScope = `admin:${actor.id}:${sha256Hex(stableJson({ environment, pathPrefix, tags }))}`;
        const decoded =
          rawCursor === undefined
            ? undefined
            : await app.cursors.decode(rawCursor, cursorScope);
        const page = await app.repository.listSecrets(
          environment,
          pathPrefix,
          tags,
          decoded?.lastEvaluatedKey,
        );
        const nextCursor =
          page.nextCursor === undefined
            ? undefined
            : await app.cursors.encode({
                scope: cursorScope,
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
          secrets: page.secrets.map((secret) => secretCatalogEntry(secret)),
          nextCursor,
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "POST" &&
        event.rawPath === "/v1/admin/secrets"
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const body = parseObjectBody(event.body);
        const control = await app.secrets.create({
          secretId: requiredString(body, "secretId"),
          environment: requiredString(body, "environment"),
          metadata: parseMetadata(body.metadata),
          acl: parseGrants(body.acl),
          actor,
          idempotencyKey: key,
        });
        return await humanOperation(
          app,
          actor,
          key,
          correlationId,
          operation,
          event.requestContext.http.sourceIp,
          {
            environment: control.environment,
            secretId: control.secretId,
            controlVersionId: control.controlVersionId,
          },
          () => json(201, control, { etag: control.controlVersionId }),
        );
      }
      // Every admin request writes three audit objects into a seven-year Object
      // Lock Compliance archive, so letting the console browse a subtree one
      // folder at a time -- one request per folder opened -- would multiply
      // that archive write for no operational benefit. This route paginates
      // the catalog-path GSI internally instead and returns one bounded,
      // complete-or-truncated tree page.
      if (
        event.requestContext.http.method === "GET" &&
        event.rawPath === "/v1/admin/secrets/tree"
      ) {
        const environment = requireQueryString(event, "environment");
        await app.environments.require(environment);
        const pathPrefix = parseCatalogPathPrefix(
          event.queryStringParameters?.pathPrefix,
        );
        const tree = await app.repository.listSecretTree(
          environment,
          pathPrefix,
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, {
          environment,
          ...(pathPrefix === undefined ? {} : { pathPrefix }),
          folders: tree.folders,
          secrets: tree.secrets.map((secret) => secretCatalogEntry(secret)),
          truncated: tree.truncated,
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "POST" &&
        event.rawPath === "/v1/admin/agent-grants"
      ) {
        const body = parseObjectBody(event.body);
        const grant = await app.agentGrants.create({
          consumerId: requiredString(body, "consumerId"),
          environment: requiredString(body, "environment"),
          capabilities: body.capabilities,
          readSecretIdPrefixes: body.readSecretIdPrefixes,
          writeSecretIdPrefixes: body.writeSecretIdPrefixes,
          ...(body.displayName === undefined
            ? {}
            : { displayName: body.displayName }),
          actor,
        });
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { grantId: grant.grantId, consumerId: grant.consumerId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(201, agentGrantResponse(grant));
      }
      const agentGrantMatch =
        /^\/v1\/admin\/agent-grants\/(grant-[a-z0-9-]{3,80})$/.exec(
          event.rawPath,
        );
      if (
        event.requestContext.http.method === "PUT" &&
        agentGrantMatch !== null
      ) {
        const body = parseObjectBody(event.body);
        const grant = await app.agentGrants.update(
          agentGrantMatch[1] as string,
          {
            capabilities: body.capabilities,
            readSecretIdPrefixes: body.readSecretIdPrefixes,
            writeSecretIdPrefixes: body.writeSecretIdPrefixes,
            ...(body.displayName === undefined
              ? {}
              : { displayName: body.displayName }),
          },
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { grantId: grant.grantId, consumerId: grant.consumerId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, agentGrantResponse(grant));
      }
      const bootstrapCapabilityMatch =
        /^\/v1\/admin\/agent-grants\/(grant-[a-z0-9-]{3,80})\/bootstrap-capabilities$/.exec(
          event.rawPath,
        );
      if (
        event.requestContext.http.method === "POST" &&
        bootstrapCapabilityMatch !== null
      ) {
        const capability = await app.agentGrants.issueBootstrapCapability(
          bootstrapCapabilityMatch[1] as string,
          actor,
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { grantId: capability.grantId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        // This is the only response that contains the bootstrap capability.
        return json(201, capability);
      }
      if (
        event.requestContext.http.method === "GET" &&
        event.rawPath === "/v1/admin/consumers"
      ) {
        const environment = requireQueryString(event, "environment");
        await app.environments.require(environment);
        const rawCursor = event.queryStringParameters?.cursor;
        const cursorScope = `admin:consumers:${actor.id}:${sha256Hex(stableJson({ environment }))}`;
        const decoded =
          rawCursor === undefined
            ? undefined
            : await app.cursors.decode(rawCursor, cursorScope);
        const page = await app.repository.listConsumers(
          environment,
          decoded?.lastEvaluatedKey,
        );
        const nextCursor =
          page.nextCursor === undefined
            ? undefined
            : await app.cursors.encode({
                scope: cursorScope,
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
          consumers: page.consumers.map((consumer) =>
            consumerSummary(consumer),
          ),
          nextCursor,
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "POST" &&
        event.rawPath === "/v1/admin/consumers"
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const body = parseObjectBody(event.body);
        const enrollment = await app.consumers.enroll({
          consumerId: requiredString(body, "consumerId"),
          environment: requiredString(body, "environment"),
          apiCertificateSigningRequestPem: requiredString(
            body,
            "apiCertificateSigningRequestPem",
          ),
          actor,
          idempotencyKey: key,
        });
        const response = () => json(201, enrollment.result);
        return enrollment.shouldWriteTerminalAudit
          ? humanOperation(
              app,
              actor,
              key,
              correlationId,
              operation,
              event.requestContext.http.sourceIp,
              {
                consumerId: enrollment.result.consumerId,
                rootFingerprint: enrollment.result.rootFingerprint,
                apiFingerprint: enrollment.result.apiFingerprint,
              },
              response,
            )
          : response();
      }
      if (
        event.requestContext.http.method === "GET" &&
        event.rawPath === "/v1/admin/issuer"
      ) {
        const [issuer, truststore] = await Promise.all([
          app.repository.getIssuer(),
          app.repository.getTruststoreState(),
        ]);
        if (issuer === undefined) {
          throw notFound(
            "The Hemlig issuing root does not exist until the first consumer is enrolled.",
          );
        }
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { rootFingerprint: issuer.fingerprint },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, issuerStatusResponse(issuer, truststore));
      }
      if (
        event.requestContext.http.method === "POST" &&
        event.rawPath === "/v1/admin/issuer"
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        // The issuing root is otherwise created lazily inside the first
        // enrollment. Operators need to provision it deliberately so the
        // truststore anchor exists and can be distributed before anyone
        // enrolls. ensureIssuer() shares getOrCreateIssuer() with that lazy
        // path, so the two can never diverge, and creation is already
        // race-safe -- no additional lock is needed to call this repeatedly
        // or concurrently.
        const issuerService = new IssuerService(
          app.repository,
          app.clients.kms,
          app.config,
        );
        const [{ issuer, created }, truststore] = await Promise.all([
          issuerService.ensureIssuer(),
          app.repository.getTruststoreState(),
        ]);
        return await humanOperation(
          app,
          actor,
          key,
          correlationId,
          operation,
          event.requestContext.http.sourceIp,
          {
            rootFingerprint: issuer.fingerprint,
          },
          () =>
            json(created ? 201 : 200, issuerStatusResponse(issuer, truststore)),
        );
      }
      const consumerMatch =
        /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})$/.exec(event.rawPath);
      if (
        event.requestContext.http.method === "GET" &&
        consumerMatch !== null
      ) {
        const consumerId = consumerMatch[1] as string;
        const consumer = await app.repository.getConsumer(consumerId);
        if (consumer === undefined) {
          throw notFound("The requested consumer was not found.");
        }
        const [activeApiIdentityCount, issuer] = await Promise.all([
          app.repository.countActiveConsumerApiIdentities(consumerId),
          app.repository.getIssuer(),
        ]);
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: { consumerId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, {
          ...consumerSummary(consumer),
          createdBy: consumer.createdBy,
          activeApiIdentityCount,
          ...(issuer === undefined
            ? {}
            : { rootFingerprint: issuer.fingerprint }),
        });
      }
      const apiIdentityMatch =
        /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})\/api-identities$/.exec(
          event.rawPath,
        );
      if (
        event.requestContext.http.method === "GET" &&
        apiIdentityMatch !== null
      ) {
        const consumerId = apiIdentityMatch[1] as string;
        const consumer = await app.repository.getConsumer(consumerId);
        if (consumer === undefined) {
          throw notFound("The requested consumer was not found.");
        }
        const rawCursor = event.queryStringParameters?.cursor;
        const cursorScope = `admin:consumer-identities:${actor.id}:${consumerId}`;
        const decoded =
          rawCursor === undefined
            ? undefined
            : await app.cursors.decode(rawCursor, cursorScope);
        const [page, issuer] = await Promise.all([
          app.repository.listConsumerApiIdentities(
            consumerId,
            decoded?.lastEvaluatedKey,
          ),
          app.repository.getIssuer(),
        ]);
        const nextCursor =
          page.nextCursor === undefined
            ? undefined
            : await app.cursors.encode({
                scope: cursorScope,
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
          target: { consumerId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, {
          consumerId,
          environment: consumer.environment,
          ...(issuer === undefined
            ? {}
            : { rootFingerprint: issuer.fingerprint }),
          apiIdentities: page.identities.map((identity) =>
            apiIdentityDetail(identity),
          ),
          nextCursor,
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "POST" &&
        apiIdentityMatch !== null
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const body = parseObjectBody(event.body);
        const identity = await app.consumers.rotateApiIdentity({
          consumerId: apiIdentityMatch[1] as string,
          apiCertificateSigningRequestPem: requiredString(
            body,
            "apiCertificateSigningRequestPem",
          ),
          actor,
          idempotencyKey: key,
        });
        const response = () => json(201, apiIdentityResponse(identity));
        return identity.shouldWriteTerminalAudit
          ? humanOperation(
              app,
              actor,
              key,
              correlationId,
              operation,
              event.requestContext.http.sourceIp,
              {
                consumerId: identity.consumerId,
                apiFingerprint: identity.apiFingerprint,
              },
              response,
            )
          : response();
      }
      const revokeMatch =
        /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})\/api-identities\/([a-f0-9]{64})$/.exec(
          event.rawPath,
        );
      if (
        event.requestContext.http.method === "DELETE" &&
        revokeMatch !== null
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const identity = await app.consumers.revokeApiIdentity({
          consumerId: revokeMatch[1] as string,
          apiFingerprint: revokeMatch[2] as string,
          actor,
          idempotencyKey: key,
        });
        const response = () => json(200, apiIdentityResponse(identity));
        return identity.shouldWriteTerminalAudit
          ? humanOperation(
              app,
              actor,
              key,
              correlationId,
              operation,
              event.requestContext.http.sourceIp,
              {
                consumerId: identity.consumerId,
                apiFingerprint: identity.apiFingerprint,
              },
              response,
            )
          : response();
      }
      const decodedPath = decodeRequestPath(event.rawPath);
      const secretMatch = new RegExp(
        `^/v1/admin/secrets/(${secretIdRoutePart})$`,
      ).exec(decodedPath);
      // Do not capture a suffix route with the general secret-ID expression:
      // its slash segments are otherwise greedy and would make `payload` or
      // `revisions` part of the secret ID. Extract the fixed terminal suffix
      // first, then validate the remaining ID independently.
      const revisionSecretId = secretIdFromSuffixedPath(
        decodedPath,
        "/revisions",
      );
      const payloadSecretId = secretIdFromSuffixedPath(
        decodedPath,
        "/payload",
      );
      if (
        event.requestContext.http.method === "GET" &&
        revisionSecretId !== undefined
      ) {
        const secretId = revisionSecretId;
        const environment = requireQueryString(event, "environment");
        const current = await app.secrets.getControlRevision(
          environment,
          secretId,
        );
        const history = await app.repository.listRecentControlRevisions(
          environment,
          secretId,
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: {
            environment,
            secretId,
            controlVersionId: current.controlVersionId,
          },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, {
          secretId,
          revisions: history.revisions.map((workflow) => ({
            controlVersionId: workflow.serialized.controlVersionId,
            payloadVersionId: workflow.serialized.payloadVersionId,
            payloadKeyCount: workflow.serialized.payloadKeyCount,
            createdAt: workflow.serialized.createdAt,
            createdBy: workflow.serialized.createdBy,
            isCurrent:
              workflow.serialized.controlVersionId === current.controlVersionId,
            // A revision is retrievable only once its immutable object was
            // committed. Prepared, retryable, failed, and retention-deleted
            // workflow rows remain useful history but have no available body.
            objectAvailable: workflow.workflowState === "READY",
          })),
          truncated: history.truncated,
          generatedAt: isoNow(),
        });
      }
      if (
        event.requestContext.http.method === "GET" &&
        secretMatch !== null &&
        payloadSecretId === undefined &&
        revisionSecretId === undefined
      ) {
        const environment = requireQueryString(event, "environment");
        const control = await app.secrets.getControlRevision(
          environment,
          secretMatch[1] as string,
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: {
            environment,
            secretId: control.secretId,
            controlVersionId: control.controlVersionId,
          },
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(200, control, { etag: control.controlVersionId });
      }
      if (
        event.requestContext.http.method === "GET" &&
        payloadSecretId !== undefined
      ) {
        const secretId = payloadSecretId;
        const environment = requireQueryString(event, "environment");
        setAuditContext({
          actor,
          operation,
          target: { environment, secretId },
          permission: "read",
          sourceIp: event.requestContext.http.sourceIp,
        });
        const payload = await app.secrets.readAdminPayload(
          environment,
          secretId,
        );
        await app.audit.write({
          correlationId,
          outcome: "succeeded",
          actor,
          operation,
          target: {
            environment,
            secretId,
            controlVersionId: payload.controlVersionId,
            payloadVersionId: payload.payloadVersionId,
          },
          permission: "read",
          sourceIp: event.requestContext.http.sourceIp,
        });
        return json(
          200,
          {
            secretId,
            controlVersionId: payload.controlVersionId,
            payloadVersionId: payload.payloadVersionId,
            payload: payload.payload,
          },
          { etag: payload.controlVersionId },
        );
      }
      if (
        event.requestContext.http.method === "PUT" &&
        secretMatch !== null &&
        payloadSecretId === undefined &&
        revisionSecretId === undefined
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const body = parseObjectBody(event.body);
        const environment = requireQueryString(event, "environment");
        const secretId = secretMatch[1] as string;
        setAuditContext({
          actor,
          operation,
          target: { environment, secretId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        const control = await app.secrets.update({
          secretId,
          environment,
          expectedControlVersionId: requireIfMatch(event.headers["if-match"]),
          metadata:
            body.metadata === undefined
              ? undefined
              : parseMetadata(body.metadata),
          acl: body.acl === undefined ? undefined : parseGrants(body.acl),
          actor,
          idempotencyKey: key,
        });
        return await humanOperation(
          app,
          actor,
          key,
          correlationId,
          operation,
          event.requestContext.http.sourceIp,
          {
            environment: control.environment,
            secretId: control.secretId,
            controlVersionId: control.controlVersionId,
          },
          () => json(200, control, { etag: control.controlVersionId }),
        );
      }
      if (
        event.requestContext.http.method === "PUT" &&
        payloadSecretId !== undefined
      ) {
        const key = requireIdempotencyKey(event.headers["idempotency-key"]);
        const body = parseObjectBody(event.body);
        const environment = requireQueryString(event, "environment");
        const secretId = payloadSecretId;
        setAuditContext({
          actor,
          operation,
          target: { environment, secretId },
          sourceIp: event.requestContext.http.sourceIp,
        });
        const control = await app.secrets.update({
          secretId,
          environment,
          expectedControlVersionId: requireIfMatch(event.headers["if-match"]),
          payload: parsePayload(body.payload, app.config.maxPayloadBytes),
          actor,
          idempotencyKey: key,
        });
        return await humanOperation(
          app,
          actor,
          key,
          correlationId,
          operation,
          event.requestContext.http.sourceIp,
          {
            environment: control.environment,
            secretId: control.secretId,
            controlVersionId: control.controlVersionId,
            payloadVersionId: control.payloadVersionId ?? "",
          },
          () => json(200, control, { etag: control.controlVersionId }),
        );
      }
      throw badRequest(
        "The requested administrative route is not supported by this handler.",
      );
    },
  );
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

const secretIdRoutePart = "[a-z][a-z0-9-]{2,63}(?:/[a-z][a-z0-9-]{2,63})*";

const secretIdFromSuffixedPath = (
  decodedPath: string,
  suffix: "/payload" | "/revisions",
): string | undefined => {
  const prefix = "/v1/admin/secrets/";
  if (!decodedPath.startsWith(prefix) || !decodedPath.endsWith(suffix)) {
    return undefined;
  }
  const secretId = decodedPath.slice(prefix.length, -suffix.length);
  return new RegExp(`^${secretIdRoutePart}$`).test(secretId)
    ? secretId
    : undefined;
};

const decodeRequestPath = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    throw badRequest("The request path is not valid URL encoding.");
  }
};

const requireQueryString = (
  event: APIGatewayProxyEventV2,
  name: string,
): string => {
  const value = event.queryStringParameters?.[name];
  if (value === undefined || value.length === 0 || value.length > 128) {
    throw badRequest(`${name} is required and must be at most 128 characters.`);
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

const apiIdentityResponse = (identity: {
  readonly consumerId: string;
  readonly environment: string;
  readonly rootFingerprint: string;
  readonly apiFingerprint: string;
  readonly apiCertificatePem?: string;
  readonly status: "ACTIVE" | "REVOKED";
}): Record<string, string> => ({
  consumerId: identity.consumerId,
  environment: identity.environment,
  rootFingerprint: identity.rootFingerprint,
  apiFingerprint: identity.apiFingerprint,
  ...(identity.apiCertificatePem === undefined
    ? {}
    : { apiCertificatePem: identity.apiCertificatePem }),
  status: identity.status,
});

const consumerSummary = (consumer: ConsumerRecord): Record<string, string> => ({
  consumerId: consumer.consumerId,
  environment: consumer.environment,
  status: consumer.status,
  subjectUri: consumer.subjectUri,
  createdAt: consumer.createdAt,
});

const apiIdentityDetail = (
  identity: IdentityRecord,
): Record<string, string> => ({
  apiFingerprint: identity.fingerprint,
  status: identity.status,
  kind: identity.kind,
  notBefore: identity.notBefore,
  notAfter: identity.notAfter,
  ...(identity.certificatePem === undefined
    ? {}
    : { apiCertificatePem: identity.certificatePem }),
});

const secretCatalogEntry = (secret: HeadRecord): Record<string, unknown> => ({
  secretId: secret.secretId,
  environment: secret.environment,
  controlVersionId: secret.controlVersionId,
  payloadVersionId: secret.payloadVersionId,
  payloadKeyCount: secret.payloadKeyCount,
  state: secret.state,
  metadata: secret.metadata,
  updatedAt: secret.updatedAt,
});

const environmentResponse = (
  environment: EnvironmentRecord,
): Record<string, unknown> => ({
  name: environment.name,
  createdAt: environment.createdAt,
  createdBy: environment.createdBy,
});

const agentGrantResponse = (
  grant: AgentGrantRecord,
): Record<string, unknown> => ({
  grantId: grant.grantId,
  consumerId: grant.consumerId,
  environment: grant.environment,
  capabilities: grant.capabilities,
  readSecretIdPrefixes: grant.readSecretIdPrefixes ?? [],
  writeSecretIdPrefixes: grant.writeSecretIdPrefixes ?? [],
  ...(grant.displayName === undefined
    ? {}
    : { displayName: grant.displayName }),
  status: grant.status,
  createdAt: grant.createdAt,
  createdBy: grant.createdBy,
  ...(grant.activatedAt === undefined
    ? {}
    : { activatedAt: grant.activatedAt }),
  ...(grant.activatedFingerprint === undefined
    ? {}
    : { activatedFingerprint: grant.activatedFingerprint }),
});

// An explicit field allowlist -- not a delete-key -- is what keeps
// encryptedPrivateKey out of every issuer response. The lazy GET and the
// deliberate POST both funnel through this one mapping so they can never
// diverge on what is safe to return.
const issuerStatusResponse = (
  issuer: IssuerRecord,
  truststore: TruststoreStateRecord | undefined,
): Record<string, unknown> => ({
  rootFingerprint: issuer.fingerprint,
  rootCertificatePem: issuer.rootCertificatePem,
  notBefore: issuer.notBefore,
  notAfter: issuer.notAfter,
  createdAt: issuer.createdAt,
  ...(truststore?.currentTruststoreKey === undefined ||
  truststore.currentTruststoreVersionId === undefined
    ? {}
    : {
        truststore: {
          objectKey: truststore.currentTruststoreKey,
          versionId: truststore.currentTruststoreVersionId,
          anchorCount: truststore.currentRootFingerprints?.length ?? 0,
        },
      }),
});
