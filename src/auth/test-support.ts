import type { APIGatewayProxyEventV2WithJWTAuthorizer } from 'aws-lambda';

/** Far-future default so fixtures need not state an expiry. */
export const testExp = 4102444800;

/** An unsigned JWT. The handler never verifies signatures; API Gateway does. */
export const unsignedJwt = (payload: unknown): string => {
    const part = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    return `${part({ alg: 'none', typ: 'JWT' })}.${part(payload)}.sig`;
};

export const bearerFor = (claims: Record<string, unknown>): string =>
    `Bearer ${unsignedJwt({ exp: testExp, ...claims })}`;

/**
 * Builds an admin event the way API Gateway would: the authorizer carries
 * (flattened) claims and the `authorization` header carries the validated bearer.
 * `bearer` overrides the decoded payload, or the whole header when a string, or
 * removes it when null.
 */
export const adminJwtEvent = (
    claims: Record<string, unknown>,
    options: { bearer?: Record<string, unknown> | string | null; headers?: Record<string, string> } = {},
): APIGatewayProxyEventV2WithJWTAuthorizer => {
    const gatewayClaims = { exp: testExp, ...claims };
    const bearer = options.bearer === undefined
        ? bearerFor(claims)
        : typeof options.bearer === 'string' || options.bearer === null
            ? options.bearer
            : `Bearer ${unsignedJwt({ exp: testExp, ...options.bearer })}`;
    return {
        headers: { ...(bearer === null ? {} : { authorization: bearer }), ...options.headers },
        requestContext: { authorizer: { jwt: { claims: gatewayClaims, scopes: [] } } },
    } as unknown as APIGatewayProxyEventV2WithJWTAuthorizer;
};
