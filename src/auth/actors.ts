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
    const issuerMatchesConfig = issuer === config.adminJwtIssuer;
    const audienceMatchesConfig = audienceMatches(audience, config.adminJwtAudience);
    const scopeMatchesConfig = hasRequiredScope(claims, config.adminJwtScope);
    const roleMatchesConfig = hasRequiredRole(claims, config.adminJwtRole);
    if (
        !issuerMatchesConfig ||
        !audienceMatchesConfig ||
        subject === undefined ||
        !scopeMatchesConfig ||
        !roleMatchesConfig
    ) {
        // This code path runs only after API Gateway has verified the JWT. Log
        // match booleans and claim names—not token or claim values—so an operator
        // can reconcile the handler's independent defense-in-depth check safely.
        console.warn(JSON.stringify({
            event: 'admin_jwt_rejected_by_handler',
            issuerMatches: issuerMatchesConfig,
            audienceMatches: audienceMatchesConfig,
            subjectClaim: config.adminActorSubjectClaim,
            subjectPresent: subject !== undefined,
            scopeMatches: scopeMatchesConfig,
            roleMatches: roleMatchesConfig,
            roleClaimType: Array.isArray(claims.roles ?? claims.role)
                ? 'array'
                : typeof (claims.roles ?? claims.role),
            claimNames: Object.keys(claims).sort(),
        }));
        throw forbidden('The administrator JWT does not satisfy this API configuration.');
    }
    const tenant = config.adminActorTenantClaim === undefined
        ? undefined
        : claim(claims, config.adminActorTenantClaim);
    if (config.adminExpectedTenantId !== undefined && tenant !== config.adminExpectedTenantId) {
        throw forbidden('The administrator JWT tenant is not permitted.');
    }
    // This is display-only evidence. Authorization, idempotency, and durable
    // ownership continue to use the configured stable subject claim above.
    const email = claim(claims, 'email');
    return tenant === undefined
        ? {
            type: 'human',
            id: subject,
            ...(email === undefined ? {} : { email }),
        }
        : {
            type: 'human',
            id: subject,
            tenantId: tenant,
            ...(email === undefined ? {} : { email }),
        };
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

const hasRequiredRole = (
    claims: Record<string, string | number | boolean | string[]>,
    requiredRole: string | undefined,
): boolean => {
    if (requiredRole === undefined) {
        return true;
    }
    const roles = claimValues(claims.roles ?? claims.role);
    return roles.includes(requiredRole);
};

/**
 * HTTP API integrations normally preserve a JWT array claim as a string array,
 * but some gateway payload paths serialise it as a JSON string. Entra app roles
 * are an array claim, so accept both representations without weakening the
 * required-role comparison.
 */
const claimValues = (value: string | number | boolean | string[] | undefined): string[] => {
    if (Array.isArray(value)) {
        return value;
    }
    if (typeof value !== 'string') {
        return [];
    }
    try {
        const parsed: unknown = JSON.parse(value);
        if (Array.isArray(parsed) && parsed.every((entry): entry is string => typeof entry === 'string')) {
            return parsed;
        }
    } catch {
        // A normal single role or space-delimited claim is not JSON.
    }
    // Preserve the role-token alphabet and treat all other characters as
    // separators. This covers gateway serializations such as
    // `[Hemlig.Administrator]` or a comma-delimited role list while the final
    // comparison still requires an exact configured role token.
    return value.split(/[^A-Za-z0-9._:/-]+/).filter((entry) => entry.length > 0);
};
