import { X509Certificate, createHash } from 'node:crypto';
import type { APIGatewayProxyEventV2, APIGatewayProxyEventV2WithJWTAuthorizer } from 'aws-lambda';
import type { AppConfig } from '../aws/config';
import { IdentityRejectedError, identityNotActive } from '../domain/errors';
import type { Actor, IdentityRecord } from '../domain/types';
import { adminTokenFromEvent } from './admin-token';

export interface IdentityLookup {
    getIdentity(fingerprint: string): Promise<IdentityRecord | undefined>;
}

export const humanActorFromEvent = (event: APIGatewayProxyEventV2WithJWTAuthorizer, config: AppConfig): Actor =>
    adminTokenFromEvent(event, config).actor;

export const consumerActorFromEvent = async (
    event: APIGatewayProxyEventV2,
    identities: IdentityLookup,
    now: Date = new Date(),
): Promise<Actor> => {
    const pem = event.requestContext.authentication?.clientCert?.clientCertPem;
    if (pem === undefined) {
        throw identityNotActive('A client certificate is required.');
    }
    let certificate: X509Certificate;
    try {
        certificate = new X509Certificate(pem);
    } catch {
        throw identityNotActive('The client certificate is invalid.');
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
        const known = identity === undefined ? {} : { consumerId: identity.consumerId, environment: identity.environment };
        throw new IdentityRejectedError(
            { type: 'consumer', id: fingerprint, ...known },
            'The client certificate is not an active consumer API identity.',
        );
    }
    return {
        type: 'consumer',
        id: fingerprint,
        consumerId: identity.consumerId,
        environment: identity.environment,
    };
};
