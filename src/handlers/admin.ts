import type { APIGatewayProxyEventV2, APIGatewayProxyEventV2WithJWTAuthorizer, APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { humanActorFromEvent } from '../auth/actors';
import { badRequest, notFound } from '../domain/errors';
import type { ConsumerRecord, IdentityRecord } from '../domain/types';
import {
    isObject,
    parseCatalogPathPrefix,
    parseCatalogTagFilters,
    parseGrants,
    parseMetadata,
    parsePayload,
} from '../domain/validation';
import { empty, errorResponse, json, parseJsonBody } from '../http/responses';
import { humanOperation } from '../services/operations';
import { isoNow, sha256Hex, stableJson } from '../util/encoding';
import { withErrorResponse } from './shared';

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyStructuredResultV2> => {
    // API Gateway routes preflight around the JWT-authorized $default route.
    // It adds configured CORS headers itself; this avoids creating audit evidence
    // for a browser capability check rather than an administrator operation.
    if (event.requestContext.http.method === 'OPTIONS') {
        return empty(204);
    }
    return withErrorResponse(event, async (app, correlationId, setAuditContext) => {
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
                    scope: cursorScope,
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
                    payloadKeyCount: secret.payloadKeyCount,
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
            return await humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
                secretId: control.secretId,
                controlVersionId: control.controlVersionId,
            }, () => json(201, control, { etag: control.controlVersionId }));
        }
        if (event.requestContext.http.method === 'GET' && event.rawPath === '/v1/admin/consumers') {
            const environment = requireQueryString(event, 'environment');
            const rawCursor = event.queryStringParameters?.cursor;
            const cursorScope = `admin:consumers:${actor.id}:${sha256Hex(stableJson({ environment }))}`;
            const decoded = rawCursor === undefined ? undefined : app.cursors.decode(rawCursor, cursorScope);
            const page = await app.repository.listConsumers(environment, decoded?.lastEvaluatedKey);
            const nextCursor = page.nextCursor === undefined
                ? undefined
                : app.cursors.encode({
                    scope: cursorScope,
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
                consumers: page.consumers.map((consumer) => consumerSummary(consumer)),
                nextCursor,
                generatedAt: isoNow(),
            });
        }
        if (event.requestContext.http.method === 'POST' && event.rawPath === '/v1/admin/consumers') {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const enrollment = await app.consumers.enroll({
                consumerId: requiredString(body, 'consumerId'),
                environment: requiredString(body, 'environment'),
                apiCertificateSigningRequestPem: requiredString(body, 'apiCertificateSigningRequestPem'),
                actor,
                idempotencyKey: key,
            });
            const response = () => json(201, enrollment.result);
            return enrollment.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
                    consumerId: enrollment.result.consumerId,
                    rootFingerprint: enrollment.result.rootFingerprint,
                    apiFingerprint: enrollment.result.apiFingerprint,
                }, response)
                : response();
        }
        if (event.requestContext.http.method === 'GET' && event.rawPath === '/v1/admin/issuer') {
            const [issuer, truststore] = await Promise.all([
                app.repository.getIssuer(),
                app.repository.getTruststoreState(),
            ]);
            if (issuer === undefined) {
                throw notFound('The Hemlig issuing root does not exist until the first consumer is enrolled.');
            }
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                target: { rootFingerprint: issuer.fingerprint },
                sourceIp: event.requestContext.http.sourceIp,
            });
            return json(200, {
                rootFingerprint: issuer.fingerprint,
                rootCertificatePem: issuer.rootCertificatePem,
                notBefore: issuer.notBefore,
                notAfter: issuer.notAfter,
                createdAt: issuer.createdAt,
                ...(truststore?.currentTruststoreKey === undefined || truststore.currentTruststoreVersionId === undefined
                    ? {}
                    : {
                        truststore: {
                            objectKey: truststore.currentTruststoreKey,
                            versionId: truststore.currentTruststoreVersionId,
                            anchorCount: truststore.currentRootFingerprints?.length ?? 0,
                        },
                    }),
            });
        }
        const consumerMatch = /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'GET' && consumerMatch !== null) {
            const consumerId = consumerMatch[1] as string;
            const consumer = await app.repository.getConsumer(consumerId);
            if (consumer === undefined) {
                throw notFound('The requested consumer was not found.');
            }
            const [activeApiIdentityCount, issuer] = await Promise.all([
                app.repository.countActiveConsumerApiIdentities(consumerId),
                app.repository.getIssuer(),
            ]);
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                target: { consumerId },
                sourceIp: event.requestContext.http.sourceIp,
            });
            return json(200, {
                ...consumerSummary(consumer),
                createdBy: consumer.createdBy,
                activeApiIdentityCount,
                ...(issuer === undefined ? {} : { rootFingerprint: issuer.fingerprint }),
            });
        }
        const apiIdentityMatch = /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})\/api-identities$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'GET' && apiIdentityMatch !== null) {
            const consumerId = apiIdentityMatch[1] as string;
            const consumer = await app.repository.getConsumer(consumerId);
            if (consumer === undefined) {
                throw notFound('The requested consumer was not found.');
            }
            const rawCursor = event.queryStringParameters?.cursor;
            const cursorScope = `admin:consumer-identities:${actor.id}:${consumerId}`;
            const decoded = rawCursor === undefined ? undefined : app.cursors.decode(rawCursor, cursorScope);
            const [page, issuer] = await Promise.all([
                app.repository.listConsumerApiIdentities(consumerId, decoded?.lastEvaluatedKey),
                app.repository.getIssuer(),
            ]);
            const nextCursor = page.nextCursor === undefined
                ? undefined
                : app.cursors.encode({
                    scope: cursorScope,
                    lastEvaluatedKey: JSON.parse(page.nextCursor) as Record<string, string>,
                    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
                });
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                target: { consumerId },
                sourceIp: event.requestContext.http.sourceIp,
            });
            return json(200, {
                consumerId,
                environment: consumer.environment,
                ...(issuer === undefined ? {} : { rootFingerprint: issuer.fingerprint }),
                apiIdentities: page.identities.map((identity) => apiIdentityDetail(identity)),
                nextCursor,
                generatedAt: isoNow(),
            });
        }
        if (event.requestContext.http.method === 'POST' && apiIdentityMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const body = parseObjectBody(event.body);
            const identity = await app.consumers.rotateApiIdentity({
                consumerId: apiIdentityMatch[1] as string,
                apiCertificateSigningRequestPem: requiredString(body, 'apiCertificateSigningRequestPem'),
                actor,
                idempotencyKey: key,
            });
            const response = () => json(201, apiIdentityResponse(identity));
            return identity.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
                    consumerId: identity.consumerId,
                    apiFingerprint: identity.apiFingerprint,
                }, response)
                : response();
        }
        const revokeMatch = /^\/v1\/admin\/consumers\/([a-z][a-z0-9-]{2,63})\/api-identities\/([a-f0-9]{64})$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'DELETE' && revokeMatch !== null) {
            const key = requireIdempotencyKey(event.headers['idempotency-key']);
            const identity = await app.consumers.revokeApiIdentity({
                consumerId: revokeMatch[1] as string,
                apiFingerprint: revokeMatch[2] as string,
                actor,
                idempotencyKey: key,
            });
            const response = () => json(200, apiIdentityResponse(identity));
            return identity.shouldWriteTerminalAudit
                ? humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
                    consumerId: identity.consumerId,
                    apiFingerprint: identity.apiFingerprint,
                }, response)
                : response();
        }
        const secretMatch = /^\/v1\/admin\/secrets\/([a-z][a-z0-9-]{2,63})$/.exec(event.rawPath);
        const revisionMatch = /^\/v1\/admin\/secrets\/([a-z][a-z0-9-]{2,63})\/revisions$/.exec(event.rawPath);
        if (event.requestContext.http.method === 'GET' && revisionMatch !== null) {
            const secretId = revisionMatch[1] as string;
            const current = await app.secrets.getControlRevision(secretId);
            const history = await app.repository.listRecentControlRevisions(secretId);
            await app.audit.write({
                correlationId,
                outcome: 'succeeded',
                actor,
                operation,
                target: { secretId, controlVersionId: current.controlVersionId },
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
                    isCurrent: workflow.serialized.controlVersionId === current.controlVersionId,
                    // A revision is retrievable only once its immutable object was
                    // committed. Prepared, retryable, failed, and retention-deleted
                    // workflow rows remain useful history but have no available body.
                    objectAvailable: workflow.workflowState === 'READY',
                })),
                truncated: history.truncated,
                generatedAt: isoNow(),
            });
        }
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
            return await humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
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
            return await humanOperation(app, actor, key, correlationId, operation, event.requestContext.http.sourceIp, {
                secretId: control.secretId,
                controlVersionId: control.controlVersionId,
                payloadVersionId: control.payloadVersionId ?? '',
            }, () => json(200, control, { etag: control.controlVersionId }));
        }
        throw badRequest('The requested administrative route is not supported by this handler.');
    });
};

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
    readonly consumerId: string;
    readonly environment: string;
    readonly rootFingerprint: string;
    readonly apiFingerprint: string;
    readonly apiCertificatePem?: string;
    readonly status: 'ACTIVE' | 'REVOKED';
}): Record<string, string> => ({
    consumerId: identity.consumerId,
    environment: identity.environment,
    rootFingerprint: identity.rootFingerprint,
    apiFingerprint: identity.apiFingerprint,
    ...(identity.apiCertificatePem === undefined ? {} : { apiCertificatePem: identity.apiCertificatePem }),
    status: identity.status,
});

const consumerSummary = (consumer: ConsumerRecord): Record<string, string> => ({
    consumerId: consumer.consumerId,
    environment: consumer.environment,
    status: consumer.status,
    subjectUri: consumer.subjectUri,
    createdAt: consumer.createdAt,
});

const apiIdentityDetail = (identity: IdentityRecord): Record<string, string> => ({
    apiFingerprint: identity.fingerprint,
    status: identity.status,
    kind: identity.kind,
    notBefore: identity.notBefore,
    notAfter: identity.notAfter,
    ...(identity.certificatePem === undefined ? {} : { apiCertificatePem: identity.certificatePem }),
});
