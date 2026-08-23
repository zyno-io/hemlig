import type { APIGatewayProxyEventV2WithJWTAuthorizer } from 'aws-lambda';
import type { AppConfig } from '../aws/config';
import { humanActorFromEvent } from './actors';

const config: AppConfig = {
    region: 'us-east-1',
    environmentName: 'test',
    controlTableName: 'control',
    workflowDueIndex: 'workflow-due',
    retentionDueIndex: 'retention-due',
    catalogPathIndex: 'catalog-path',
    revisionBucketName: 'revisions',
    truststoreBucketName: 'truststores',
    truststoreKeyPrefix: 'truststores',
    payloadKmsKeyArn: 'arn:aws:kms:us-east-1:000000000000:key/test',
    auditBucketName: 'audit',
    auditPrefix: 'audit',
    clusterCustomDomainName: 'clusters.example.test',
    clusterApiHostname: 'clusters.example.test',
    cursorHmacKey: Buffer.alloc(32, 7),
    adminJwtIssuer: 'https://issuer.example.test',
    adminJwtAudience: 'clavis-api',
    adminActorSubjectClaim: 'sub',
    maxPayloadBytes: 768000,
};

const jwtEvent = (claims: Record<string, string>): APIGatewayProxyEventV2WithJWTAuthorizer => ({
    requestContext: { authorizer: { jwt: { claims, scopes: [] } } },
} as unknown as APIGatewayProxyEventV2WithJWTAuthorizer);

describe('humanActorFromEvent', () => {
    it('accepts client_id when aud is absent, matching HTTP API JWT authorizers', () => {
        const actor = humanActorFromEvent(jwtEvent({
            iss: 'https://issuer.example.test',
            client_id: 'clavis-api',
            sub: 'external-subject',
        }), config);
        expect(actor).toEqual({ type: 'human', id: 'external-subject' });
    });

    it('uses aud in preference to client_id when both claims are present', () => {
        expect(() => humanActorFromEvent(jwtEvent({
            iss: 'https://issuer.example.test',
            aud: 'another-api',
            client_id: 'clavis-api',
            sub: 'external-subject',
        }), config)).toThrow('does not satisfy');
    });
});
