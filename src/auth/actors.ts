import { X509Certificate, createHash } from 'node:crypto';
import type { APIGatewayProxyEventV2, APIGatewayProxyEventV2WithJWTAuthorizer } from 'aws-lambda';
import type { AppConfig } from '../aws/config';
import { forbidden } from '../domain/errors';
import type { Actor, IdentityRecord } from '../domain/types';

export interface IdentityLookup {
    getIdentity(fingerprint: string): Promise<IdentityRecord | undefined>;
}

export const humanActorFromEvent = (event: APIGatewayProxyEventV2WithJWTAuthorizer, config: AppConfig): Actor => {
    const claims = event.requestContext.authorizer?.jwt?.claims;
    if (claims === undefined) {
        throw forbidden('A validated administrator JWT is required.');
    }
    const issuer = claim(claims, 'iss');
    const audience = claim(claims, 'aud') ?? claim(claims, 'client_id');
    const subject = claim(claims, config.adminActorSubjectClaim);
    if (
        issuer !== config.adminJwtIssuer ||
        !audienceMatches(audience, config.adminJwtAudience) ||
        subject === undefined ||
        !hasRequiredScope(claims, config.adminJwtScope)
    ) {
        throw forbidden('The administrator JWT does not satisfy this API configuration.');
    }
    const tenant = config.adminActorTenantClaim === undefined
        ? undefined
        : claim(claims, config.adminActorTenantClaim);
    if (config.adminExpectedTenantId !== undefined && tenant !== config.adminExpectedTenantId) {
        throw forbidden('The administrator JWT tenant is not permitted.');
    }
    return tenant === undefined
        ? { type: 'human', id: subject }
        : { type: 'human', id: subject, tenantId: tenant };
};

export const consumerActorFromEvent = async (
    event: APIGatewayProxyEventV2,
    identities: IdentityLookup,
    now: Date = new Date(),
): Promise<Actor> => {
    const pem = event.requestContext.authentication?.clientCert?.clientCertPem;
    if (pem === undefined) {
        throw forbidden('A client certificate is required.');
    }
    let certificate: X509Certificate;
    try {
        certificate = new X509Certificate(pem);
    } catch {
        throw forbidden('The client certificate is invalid.');
    }
    const fingerprint = createHash('sha256').update(certificate.raw).digest('hex');
    const identity = await identities.getIdentity(fingerprint);
    if (
        identity === undefined ||
        identity.kind !== 'api' ||
        identity.status !== 'ACTIVE' ||
        new Date(identity.notBefore).getTime() > now.getTime() ||
        new Date(identity.notAfter).getTime() <= now.getTime()
    ) {
        throw forbidden('The client certificate is not an active consumer API identity.');
    }
    return {
        type: 'consumer',
        id: fingerprint,
        consumerId: identity.consumerId,
        environment: identity.environment,
    };
};

const claim = (claims: Record<string, string | number | boolean | string[]>, name: string): string | undefined => {
    const value = claims[name];
    return typeof value === 'string' ? value : undefined;
};

const audienceMatches = (audience: string | undefined, expected: string): boolean =>
    audience !== undefined && audience.split(' ').includes(expected);

const hasRequiredScope = (
    claims: Record<string, string | number | boolean | string[]>,
    requiredScope: string | undefined,
): boolean => {
    if (requiredScope === undefined) {
        return true;
    }
    const declared = [claims.scope, claims.scp]
        .flatMap((value) => Array.isArray(value) ? value : typeof value === 'string' ? value.split(' ') : []);
    return declared.includes(requiredScope);
};
