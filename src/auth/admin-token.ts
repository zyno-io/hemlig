import type { APIGatewayProxyEventV2WithJWTAuthorizer } from 'aws-lambda';
import type { AppConfig } from '../aws/config';
import { forbidden } from '../domain/errors';
import type { Actor } from '../domain/types';

/**
 * Provider-neutral administrator authorization.
 *
 * API Gateway's JWT authorizer has already verified the bearer's signature,
 * `iss`, `aud`, `exp` and route scopes. API Gateway flattens claims, which
 * cannot represent nested claims (Keycloak `realm_access.roles`, Zitadel role
 * objects), so this module reads the claims from the `Authorization` bearer
 * itself. It does NOT re-verify the signature. It binds the decoded payload to
 * the authorizer's claims and refuses on any mismatch, so it can only ever read
 * the token the gateway validated. Every failure is a 403; nothing grants
 * administrator because a claim was unreadable.
 */

type RawClaims = Record<string, string | number | boolean | string[]>;
type Claims = Record<string, unknown>;

export interface AdminToken {
    readonly actor: Actor;
    /** Claims decoded from the validated bearer. Never log these. */
    readonly claims: Claims;
    /** Values of the configured role claim, for the administrator and PKI roles. */
    readonly roleValues: ReadonlySet<string>;
}

export type RejectReason =
    | 'authorizer_claims_missing'
    | 'bearer_unreadable'
    | 'binding'
    | 'issuer'
    | 'audience'
    | 'scope'
    | 'subject'
    | 'tenant'
    | 'role'
    | 'role_overage';

const GENERIC_MESSAGE = 'The administrator JWT does not satisfy this API configuration.';
const OVERAGE_MESSAGE =
    'The administrator JWT carries a group-overage reference instead of its groups, so roles cannot be read. '
    + 'Use app roles, or restrict the groups claim to the groups assigned to this application.';

export const adminTokenFromEvent = (
    event: APIGatewayProxyEventV2WithJWTAuthorizer,
    config: AppConfig,
): AdminToken => {
    const gateway = event.requestContext.authorizer?.jwt?.claims as RawClaims | undefined;
    if (gateway === undefined) {
        throw forbidden('A validated administrator JWT is required.');
    }
    const roleClaim = config.adminRoleClaim;
    const reject = (reason: RejectReason, extra: Record<string, unknown> = {}): never => {
        // This code path runs only after API Gateway has verified the JWT. Log
        // the reason, match booleans and claim names, never token or claim
        // values, so an operator can reconcile this independent check safely.
        console.warn(JSON.stringify({
            event: 'admin_jwt_rejected_by_handler',
            reason,
            subjectClaim: config.adminActorSubjectClaim,
            roleClaim: roleClaim ?? 'roles',
            ...extra,
        }));
        throw forbidden(reason === 'role_overage' ? OVERAGE_MESSAGE : GENERIC_MESSAGE);
    };

    const claims = decodeBearer(event.headers);
    if (claims === undefined) {
        return reject('bearer_unreadable');
    }
    if (!bindsToGateway(claims, gateway, config.adminActorSubjectClaim)) {
        return reject('binding');
    }

    // Seam for ID-token mode (`azp` and `aud` rules, no scope): add the profile
    // check here, before the claim checks below. Only access tokens are
    // supported today.
    const issuerMatches = claims.iss === config.adminJwtIssuer;
    const audience = audienceClaim(claims);
    const audienceMatches = audience.some((value) => parseList(config.adminJwtAudience).includes(value));
    const scopeMatches = hasRequiredScope(claims, config.adminJwtScope);
    const subject = stringClaim(claims, config.adminActorSubjectClaim);
    const resolved = resolveRoleValues(claims, roleClaim);
    const roleMatches = hasRequiredRole(resolved.values, config.adminJwtRole);
    if (!issuerMatches || !audienceMatches || subject === undefined || !scopeMatches || !roleMatches) {
        const overage = resolved.type === 'missing' && hasGroupOverage(claims, roleClaim);
        const reason: RejectReason = !issuerMatches
            ? 'issuer'
            : !audienceMatches
                ? 'audience'
                : subject === undefined
                    ? 'subject'
                    : !scopeMatches
                        ? 'scope'
                        : overage
                            ? 'role_overage'
                            : 'role';
        return reject(reason, {
            issuerMatches,
            audienceMatches,
            subjectPresent: subject !== undefined,
            scopeMatches,
            roleMatches,
            roleClaimType: resolved.type,
            roleClaimOverage: overage,
            claimNames: Object.keys(claims).sort(),
        });
    }

    const tenant = config.adminActorTenantClaim === undefined
        ? undefined
        : stringClaim(claims, config.adminActorTenantClaim);
    if (config.adminExpectedTenantId !== undefined && tenant !== config.adminExpectedTenantId) {
        return reject('tenant');
    }
    // Display-only evidence. Authorization, idempotency and durable ownership
    // use the configured stable subject claim.
    const email = stringClaim(claims, 'email');
    const actor: Actor = tenant === undefined
        ? { type: 'human', id: subject, ...(email === undefined ? {} : { email }) }
        : { type: 'human', id: subject, tenantId: tenant, ...(email === undefined ? {} : { email }) };
    return { actor, claims, roleValues: new Set(resolved.values) };
};

/** Parses a comma-separated env value into trimmed, non-empty entries. */
export const parseList = (value: string | undefined): string[] =>
    value === undefined ? [] : value.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0);

/**
 * Any-of match against a comma-separated list of required roles. Unset means
 * no requirement. A set value with no usable entries matches nothing.
 */
export const hasRequiredRole = (values: Iterable<string>, required: string | undefined): boolean => {
    if (required === undefined) {
        return true;
    }
    const present = new Set(values);
    return parseList(required).some((role) => present.has(role));
};

/** Throws if `claim` is not a plain name or a valid RFC 6901 pointer. Used at config load. */
export const assertRoleClaim = (claim: string): void => {
    if (claim.startsWith('/')) {
        pointerSegments(claim);
    }
};

const pointerSegments = (pointer: string): string[] =>
    pointer.slice(1).split('/').map((segment) => {
        if (/~(?![01])/.test(segment)) {
            throw new Error('ADMIN_ROLE_CLAIM is not a valid JSON Pointer.');
        }
        return segment.replace(/~1/g, '/').replace(/~0/g, '~');
    });

const lookup = (value: unknown, segment: string): unknown => {
    if (Array.isArray(value)) {
        return /^(0|[1-9][0-9]*)$/.test(segment) ? value[Number(segment)] : undefined;
    }
    return isObject(value) && Object.hasOwn(value, segment) ? value[segment] : undefined;
};

/** A claim name, or a JSON Pointer when it starts with `/`. Returns undefined when absent. */
export const resolveClaim = (claims: Claims, claim: string): unknown => {
    if (!claim.startsWith('/')) {
        return Object.hasOwn(claims, claim) ? claims[claim] : undefined;
    }
    let current: unknown = claims;
    for (const segment of pointerSegments(claim)) {
        current = lookup(current, segment);
        if (current === undefined) {
            return undefined;
        }
    }
    return current;
};

const firstSegment = (claim: string): string => (claim.startsWith('/') ? pointerSegments(claim)[0] ?? '' : claim);

/** A string is one value, an array gives its string elements, an object gives its keys (Zitadel). */
const normaliseValues = (value: unknown): { values: string[]; type: string } => {
    if (value === undefined || value === null) {
        return { values: [], type: 'missing' };
    }
    if (typeof value === 'string') {
        return { values: [value], type: 'string' };
    }
    if (Array.isArray(value)) {
        return { values: value.filter((entry): entry is string => typeof entry === 'string'), type: 'array' };
    }
    if (isObject(value)) {
        return { values: Object.keys(value), type: 'object' };
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
        return { values: [String(value)], type: typeof value };
    }
    return { values: [], type: 'unsupported' };
};

const resolveRoleValues = (claims: Claims, roleClaim: string | undefined): { values: string[]; type: string } => {
    // Unset keeps the legacy `roles`, falling back to `role`, behaviour.
    const value = roleClaim === undefined ? claims.roles ?? claims.role : resolveClaim(claims, roleClaim);
    return normaliseValues(value);
};

/**
 * Entra replaces an oversized `groups` claim with `_claim_names.groups` (and
 * `hasgroups`). The groups cannot be read without calling Graph, which is never
 * done: the request is refused with a distinct reason.
 */
const hasGroupOverage = (claims: Claims, roleClaim: string | undefined): boolean => {
    if (claims.hasgroups === true) {
        return true;
    }
    const names = claims._claim_names;
    return isObject(names) && Object.hasOwn(names, firstSegment(roleClaim ?? 'roles'));
};

const hasRequiredScope = (claims: Claims, requiredScope: string | undefined): boolean => {
    if (requiredScope === undefined) {
        return true;
    }
    const declared = [claims.scope, claims.scp].flatMap((value) =>
        Array.isArray(value)
            ? value.filter((entry): entry is string => typeof entry === 'string')
            : typeof value === 'string' ? value.split(' ') : []);
    return declared.includes(requiredScope);
};

/** `aud` as a string or array; `client_id` only when `aud` is absent (Cognito access tokens). */
const audienceClaim = (claims: Claims): string[] => {
    const value = claims.aud ?? claims.client_id;
    return typeof value === 'string' ? [value] : Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
};

const stringClaim = (claims: Claims, name: string): string | undefined => {
    const value = Object.hasOwn(claims, name) ? claims[name] : undefined;
    return typeof value === 'string' ? value : undefined;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const decodeBearer = (headers: Record<string, string | undefined> | undefined): Claims | undefined => {
    if (headers === undefined) {
        return undefined;
    }
    const name = Object.keys(headers).find((key) => key.toLowerCase() === 'authorization');
    const header = name === undefined ? undefined : headers[name];
    if (typeof header !== 'string') {
        return undefined;
    }
    const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
    const token = match?.[1] ?? header.trim();
    const parts = token.split('.');
    const encoded = parts[1];
    if (parts.length !== 3 || encoded === undefined || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
        return undefined;
    }
    try {
        const payload: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        return isObject(payload) ? payload : undefined;
    } catch {
        return undefined;
    }
};

/**
 * The decoded payload must be the token the gateway validated: equal `iss`,
 * numerically equal `exp` (the gateway may render it as a string), an equal
 * subject claim, and equal `aud` (or `client_id` when `aud` is absent). Any
 * claim the gateway did not carry or that differs refuses.
 */
const bindsToGateway = (decoded: Claims, gateway: RawClaims, subjectClaim: string): boolean => {
    const exp = decoded.exp;
    const gatewayExp = gateway.exp;
    if (typeof exp !== 'number' || !Number.isFinite(exp) || gatewayExp === undefined || Array.isArray(gatewayExp)) {
        return false;
    }
    if (typeof decoded.iss !== 'string' || decoded.iss !== gateway.iss || Number(gatewayExp) !== exp) {
        return false;
    }
    const subject = stringClaim(decoded, subjectClaim);
    if (subject === undefined || subject !== gateway[subjectClaim]) {
        return false;
    }
    const audienceName = decoded.aud === undefined ? 'client_id' : 'aud';
    const gatewayAudience = gateway[audienceName];
    const decodedAudience = audienceClaim(decoded);
    if (gatewayAudience === undefined || (audienceName === 'client_id' && gateway.aud !== undefined)) {
        return false;
    }
    // The gateway renders an array `aud` as a string (`[a b]`) or an array.
    const gatewayValues = Array.isArray(gatewayAudience)
        ? gatewayAudience
        : String(gatewayAudience).split(/[\s,[\]"]+/).filter((entry) => entry.length > 0);
    return decodedAudience.length > 0
        && decodedAudience.length === gatewayValues.length
        && decodedAudience.every((value) => gatewayValues.includes(value));
};
