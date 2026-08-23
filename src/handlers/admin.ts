import type { APIGatewayProxyEventV2, APIGatewayProxyEventV2WithJWTAuthorizer, APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { humanActorFromEvent } from '../auth/actors';
import { badRequest } from '../domain/errors';
import {
    isObject,
    parseCatalogPathPrefix,
    parseCatalogTagFilters,
    parseGrants,
    parseMetadata,
    parsePayload,
} from '../domain/validation';
import { errorResponse, json, parseJsonBody } from '../http/responses';
import { humanOperation } from '../services/operations';
import { isoNow, sha256Hex, stableJson } from '../util/encoding';
import { withErrorResponse } from './shared';

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyStructuredResultV2> =>
    withErrorResponse(event, async (app, correlationId, setAuditContext) => {
        const jwtEvent = event as APIGatewayProxyEventV2WithJWTAuthorizer;
        const actor = humanActorFromEvent(jwtEvent, app.config);
        const operation = `admin${event.requestContext.http.method.toLowerCase()}:${event.rawPath}`;
        setAuditContext({ actor, operation, sourceIp: event.requestContext.http.sourceIp });
        await app.audit.write({
            correlationId,
            outcome: 'attempted',
            actor,
            operation,
            sourceIp: event.requestContext.http.sourceIp,
        });
        await app.audit.write({
            correlationId,
            outcome: 'authorized',
            actor,
            operation,
            sourceIp: event.requestContext.http.sourceIp,
        });
        if (event.requestContext.http.method === 'GET' && event.rawPath === '/v1/admin/secrets') {
            const environment = requireQueryString(event, 'environment');
            const pathPrefix = parseCatalogPathPrefix(event.queryStringParameters?.pathPrefix);
            const tags = parseCatalogTagFilters(event.queryStringParameters?.tags);
            const rawCursor = event.queryStringParameters?.cursor;
            const cursorScope = `admin:${actor.id}:${sha256Hex(stableJson({ environment, pathPrefix, tags }))}`;
            const decoded = rawCursor === undefined ? undefined : app.cursors.decode(rawCursor, cursorScope);
            const page = await app.repository.listSecrets(environment, pathPrefix, tags, decoded?.lastEvaluatedKey);
            const nextCursor = page.nextCursor === undefined
                ? undefined
                : app.cursors.encode({
                    clusterId: cursorScope,
                    lastEvaluatedKey: JSON.parse(page.nextCursor) as Record<string, string>,
                    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
                });
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                sourceIp: event.requestContext.http.sourceIp,
            });
            return json(200, {
                secrets: page.secrets.map((secret) => ({
                    secretId: secret.secretId,
                    environment: secret.environment,
                    controlVersionId: secret.controlVersionId,
                    payloadVersionId: secret.payloadVersionId,
                    state: secret.state,
                    metadata: secret.metadata,
                    updatedAt: secret.updatedAt,
                })),
                nextCursor,
                generatedAt: isoNow(),
            });
        }
        if (event.requestContext.http.method === 'POST' && event.rawPath === '/v1/admin/secrets') {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const control = await app.secrets.create({
                secretId: optionalString(body, 'secretId'),
                environment: requiredString(body, 'environment'),
                metadata: parseMetadata(body.metadata),
                acl: parseGrants(body.acl),
                actor,
                idempotencyKey: key,
            });
            return await humanOperation(app, actor, key, correlationId, operation, {
                secretId: control.secretId,
                controlVersionId: control.controlVersionId,
            }, () => json(201, control, { etag: control.controlVersionId }));
        }
        if (event.requestContext.http.method === 'POST' && event.rawPath === '/v1/admin/clusters') {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const enrollment = await app.clusters.enroll({
                clusterId: requiredString(body, 'clusterId'),
                environment: requiredString(body, 'environment'),
                apiCertificateSigningRequestPem: requiredString(body, 'apiCertificateSigningRequestPem'),
                actor,
                idempotencyKey: key,
            });
            const response = () => json(201, enrollment.result);
            return enrollment.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, {
                    clusterId: enrollment.result.clusterId,
                    rootFingerprint: enrollment.result.rootFingerprint,
                    apiFingerprint: enrollment.result.apiFingerprint,
                }, response)
                : response();
        }
        const apiIdentityMatch = /^\/v1\/admin\/clusters\/([a-z][a-z0-9-]{2,63})\/api-identities$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'POST' && apiIdentityMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const identity = await app.clusters.rotateApiIdentity({
                clusterId: apiIdentityMatch[1] as string,
                apiCertificateSigningRequestPem: requiredString(body, 'apiCertificateSigningRequestPem'),
                actor,
                idempotencyKey: key,
            });
            const response = () => json(201, apiIdentityResponse(identity));
            return identity.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, {
                    clusterId: identity.clusterId,
                    apiFingerprint: identity.apiFingerprint,
                }, response)
                : response();
        }
        const revokeMatch = /^\/v1\/admin\/clusters\/([a-z][a-z0-9-]{2,63})\/api-identities\/([a-f0-9]{64})$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'DELETE' && revokeMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const identity = await app.clusters.revokeApiIdentity({
                clusterId: revokeMatch[1] as string,
                apiFingerprint: revokeMatch[2] as string,
                actor,
                idempotencyKey: key,
            });
            const response = () => json(200, apiIdentityResponse(identity));
            return identity.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, {
                    clusterId: identity.clusterId,
                    apiFingerprint: identity.apiFingerprint,
                }, response)
                : response();
        }
        const secretMatch = /^\/v1\/admin\/secrets\/([a-z][a-z0-9-]{2,63})$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'GET' && secretMatch !== null) {
            const control = await app.secrets.getControlRevision(secretMatch[1] as string);
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                target: { secretId: control.secretId, controlVersionId: control.controlVersionId },
                sourceIp: event.requestContext.http.sourceIp,
            });
            return json(200, control, { etag: control.controlVersionId });
        }
        if (event.requestContext.http.method === 'PUT' && secretMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const control = await app.secrets.update({
                secretId: secretMatch[1] as string,
                expectedControlVersionId: requireIfMatch(event.headers['if-match']),
                metadata: body.metadata === undefined ? undefined : parseMetadata(body.metadata),
                acl: body.acl === undefined ? undefined : parseGrants(body.acl),
                actor,
                idempotencyKey: key,
            });
            return await humanOperation(app, actor, key, correlationId, operation, {
                secretId: control.secretId,
                controlVersionId: control.controlVersionId,
            }, () => json(200, control, { etag: control.controlVersionId }));
        }
        const payloadMatch = /^\/v1\/admin\/secrets\/([a-z][a-z0-9-]{2,63})\/payload$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'PUT' && payloadMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const control = await app.secrets.update({
                secretId: payloadMatch[1] as string,
                expectedControlVersionId: requireIfMatch(event.headers['if-match']),
                payload: parsePayload(body.payload, app.config.maxPayloadBytes),
                actor,
                idempotencyKey: key,
            });
            return await humanOperation(app, actor, key, correlationId, operation, {
                secretId: control.secretId,
                controlVersionId: control.controlVersionId,
                payloadVersionId: control.payloadVersionId ?? '',
            }, () => json(200, control, { etag: control.controlVersionId }));
        }
        throw badRequest('The requested administrative route is not supported by this handler.');
    });

const parseObjectBody = (body: string | undefined): Record<string, unknown> => {
    const parsed = parseJsonBody(body);
    if (!isObject(parsed)) {
        throw badRequest('The request body must be a JSON object.');
    }
    return parsed;
};

const requiredString = (body: Record<string, unknown>, name: string): string => {
    const value = body[name];
    if (typeof value !== 'string' || value.length === 0) {
        throw badRequest(`${name} is required.`);
    }
    return value;
};

const optionalString = (body: Record<string, unknown>, name: string): string | undefined => {
    const value = body[name];
    if (value === undefined) {
        return undefined;
    }
    if (typeof value !== 'string' || value.length === 0) {
        throw badRequest(`${name} must be a non-empty string.`);
    }
    return value;
};

const requireQueryString = (event: APIGatewayProxyEventV2, name: string): string => {
    const value = event.queryStringParameters?.[name];
    if (value === undefined || value.length === 0 || value.length > 128) {
        throw badRequest(`${name} is required and must be at most 128 characters.`);
    }
    return value;
};

const requireIdempotencyKey = (value: string | undefined): string => {
    if (value === undefined || value.length < 8 || value.length > 128) {
        throw badRequest('Idempotency-Key is required and must be 8-128 characters.');
    }
    return value;
};

const requireIfMatch = (value: string | undefined): string => {
    if (value === undefined || value.length === 0) {
        throw badRequest('If-Match is required.');
    }
    return value.replaceAll('"', '');
};

const apiIdentityResponse = (identity: {
    readonly clusterId: string;
    readonly environment: string;
    readonly rootFingerprint: string;
    readonly apiFingerprint: string;
    readonly apiCertificatePem?: string;
    readonly status: 'ACTIVE' | 'REVOKED';
}): Record<string, string> => ({
    clusterId: identity.clusterId,
    environment: identity.environment,
    rootFingerprint: identity.rootFingerprint,
    apiFingerprint: identity.apiFingerprint,
    ...(identity.apiCertificatePem === undefined ? {} : { apiCertificatePem: identity.apiCertificatePem }),
    status: identity.status,
});
