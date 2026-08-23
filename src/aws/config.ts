import { badRequest } from '../domain/errors';

export interface AppConfig {
    readonly region: string;
    /** Stable deployment name used in the Clavis issuing-root subject. */
    readonly environmentName: string;
    readonly controlTableName: string;
    readonly workflowDueIndex: string;
    readonly retentionDueIndex: string;
    readonly catalogPathIndex: string;
    readonly revisionBucketName: string;
    readonly truststoreBucketName: string;
    readonly truststoreKeyPrefix: string;
    readonly payloadKmsKeyArn: string;
    readonly auditBucketName: string;
    readonly auditPrefix: string;
    readonly clusterCustomDomainName: string;
    readonly clusterApiHostname: string;
    readonly cursorHmacKey: Buffer;
    readonly adminJwtIssuer: string;
    readonly adminJwtAudience: string;
    readonly adminActorSubjectClaim: string;
    readonly adminActorTenantClaim?: string;
    readonly adminExpectedTenantId?: string;
    readonly maxPayloadBytes: number;
    readonly awsEndpointUrl?: string;
}

export const loadConfig = (environment: NodeJS.ProcessEnv = process.env): AppConfig => {
    const cursorHmacKey = Buffer.from(required(environment, 'CURSOR_HMAC_KEY'), 'base64');
    if (cursorHmacKey.length < 32) {
        throw badRequest('CURSOR_HMAC_KEY must decode to at least 32 bytes.');
    }
    const maxPayloadBytes = Number.parseInt(environment.MAX_PAYLOAD_BYTES ?? '768000', 10);
    if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes <= 0 || maxPayloadBytes > 768000) {
        throw badRequest('MAX_PAYLOAD_BYTES must be an integer between 1 and 768000.');
    }
    return {
        region: environment.AWS_REGION ?? 'us-east-1',
        environmentName: required(environment, 'CLAVIS_ENVIRONMENT'),
        controlTableName: required(environment, 'CONTROL_TABLE_NAME'),
        workflowDueIndex: required(environment, 'WORKFLOW_DUE_INDEX'),
        retentionDueIndex: required(environment, 'RETENTION_DUE_INDEX'),
        catalogPathIndex: required(environment, 'CATALOG_PATH_INDEX'),
        revisionBucketName: required(environment, 'REVISION_BUCKET_NAME'),
        truststoreBucketName: required(environment, 'TRUSTSTORE_BUCKET_NAME'),
        truststoreKeyPrefix: required(environment, 'TRUSTSTORE_KEY_PREFIX'),
        payloadKmsKeyArn: required(environment, 'PAYLOAD_KMS_KEY_ARN'),
        auditBucketName: required(environment, 'AUDIT_BUCKET_NAME'),
        auditPrefix: required(environment, 'AUDIT_PREFIX'),
        clusterCustomDomainName: required(environment, 'CLUSTER_CUSTOM_DOMAIN_NAME'),
        clusterApiHostname: required(environment, 'CLUSTER_API_HOSTNAME'),
        cursorHmacKey,
        adminJwtIssuer: required(environment, 'ADMIN_JWT_ISSUER'),
        adminJwtAudience: required(environment, 'ADMIN_JWT_AUDIENCE'),
        adminActorSubjectClaim: required(environment, 'ADMIN_ACTOR_SUBJECT_CLAIM'),
        adminActorTenantClaim: optional(environment, 'ADMIN_ACTOR_TENANT_CLAIM'),
        adminExpectedTenantId: optional(environment, 'ADMIN_EXPECTED_TENANT_ID'),
        maxPayloadBytes,
        awsEndpointUrl: optional(environment, 'AWS_ENDPOINT_URL'),
    };
};

const required = (environment: NodeJS.ProcessEnv, name: string): string => {
    const value = environment[name];
    if (value === undefined || value.trim().length === 0) {
        throw new Error(`${name} is required.`);
    }
    return value;
};

const optional = (environment: NodeJS.ProcessEnv, name: string): string | undefined => {
    const value = environment[name];
    return value === undefined || value.trim().length === 0 ? undefined : value;
};
