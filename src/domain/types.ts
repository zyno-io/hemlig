export type EnvironmentName = string;

export type Permission = 'read';

export type SecretState = 'PENDING_VALUE' | 'ACTIVE' | 'REVOKED';

export type WorkflowState = 'PREPARED' | 'READY' | 'RETRYABLE' | 'FAILED' | 'DELETED';

export type IdentityStatus = 'PENDING' | 'ACTIVE' | 'REVOKED' | 'EXPIRED' | 'FAILED';

export type ConsumerStatus = 'PENDING' | 'ACTIVE' | 'FAILED';

export type EnrollmentOperationType = 'consumer.enroll';

export interface Actor {
    readonly type: 'human' | 'consumer' | 'system';
    readonly id: string;
    readonly tenantId?: string;
    readonly consumerId?: string;
    readonly environment?: EnvironmentName;
}

export interface SecretEntry {
    readonly encoding: 'utf8' | 'base64';
    readonly value: string;
}

export type SecretPayload = Readonly<Record<string, SecretEntry>>;

export interface SecretMetadata {
    readonly name: string;
    readonly description?: string;
    /** Canonical, slash-delimited organizational location. It has no authorization meaning. */
    readonly path?: string;
    /** Bounded, exact-match organizational labels. They have no authorization meaning. */
    readonly tags?: Readonly<Record<string, string>>;
}

export interface Grant {
    readonly consumerId: string;
    readonly permissions: readonly Permission[];
}

export interface ControlRevision {
    readonly schemaVersion: 1;
    readonly secretId: string;
    readonly controlVersionId: string;
    readonly payloadVersionId?: string;
    /** Number of entries in the current payload; plaintext names are never retained here. */
    readonly payloadKeyCount?: number;
    readonly environment: EnvironmentName;
    readonly state: SecretState;
    readonly createdAt: string;
    readonly createdBy: Actor;
    readonly metadata: SecretMetadata;
    readonly acl: readonly Grant[];
}

export interface EncryptedPayload {
    readonly algorithm: 'AES-256-GCM';
    readonly encryptedDataKey: string;
    readonly iv: string;
    readonly tag: string;
    readonly ciphertext: string;
}

export interface PayloadRevision {
    readonly schemaVersion: 1;
    readonly secretId: string;
    readonly payloadVersionId: string;
    readonly environment: EnvironmentName;
    readonly createdAt: string;
    readonly createdBy: Actor;
    readonly payload: EncryptedPayload;
}

export interface HeadRecord {
    readonly pk: string;
    readonly sk: 'HEAD';
    readonly secretId: string;
    readonly environment: EnvironmentName;
    readonly controlVersionId: string;
    readonly controlObjectVersionId?: string;
    readonly payloadVersionId?: string;
    readonly payloadObjectVersionId?: string;
    readonly payloadKeyCount?: number;
    readonly state: SecretState;
    readonly metadata?: SecretMetadata;
    readonly updatedAt?: string;
    readonly catalogPk?: string;
    readonly catalogSk?: string;
    readonly catalogTags?: Readonly<Record<string, string>>;
    readonly leaseOwner?: string;
    readonly leaseExpiresAt?: string;
}

export interface AccessRecord {
    readonly pk: string;
    readonly sk: string;
    readonly consumerId: string;
    readonly secretId: string;
    readonly environment: EnvironmentName;
    readonly permissions: readonly Permission[];
    readonly controlVersionId: string;
    readonly payloadVersionId?: string;
    readonly state: SecretState;
    readonly changeKind: 'secret.changed' | 'secret.revoked';
}

export interface IdentityRecord {
    readonly pk: string;
    readonly sk: 'PROFILE';
    readonly fingerprint: string;
    readonly consumerId: string;
    readonly environment: EnvironmentName;
    readonly kind: 'api' | 'notify';
    readonly status: IdentityStatus;
    readonly notBefore: string;
    readonly notAfter: string;
    readonly certificatePem?: string;
    /** Sparse GSI projection for administrative identity browsing. */
    readonly identityConsumerPk?: string;
    readonly identityConsumerSk?: string;
}

export interface IssuerKeyEnvelope {
    readonly algorithm: 'AES-256-GCM';
    readonly encryptedDataKey: string;
    readonly iv: string;
    readonly tag: string;
    readonly ciphertext: string;
}

export interface IssuerRecord {
    readonly pk: 'SYSTEM#ISSUER';
    readonly sk: 'PROFILE';
    readonly rootCertificatePem: string;
    readonly encryptedPrivateKey: IssuerKeyEnvelope;
    readonly fingerprint: string;
    readonly notBefore: string;
    readonly notAfter: string;
    readonly createdAt: string;
}

export interface ConsumerRecord {
    readonly pk: string;
    readonly sk: 'PROFILE';
    readonly consumerId: string;
    readonly environment: EnvironmentName;
    readonly subjectUri: string;
    readonly status: ConsumerStatus;
    readonly createdAt: string;
    readonly createdBy: Actor;
    /** Sparse GSI projection for administrative consumer browsing. */
    readonly consumerDirectoryPk?: string;
    readonly consumerDirectorySk?: string;
}

export interface TruststoreRootRecord {
    readonly pk: 'TRUSTSTORE#ROOTS';
    readonly sk: string;
    readonly fingerprint: string;
    readonly consumerId: string;
    readonly environment: EnvironmentName;
    readonly certificatePem: string;
    readonly notBefore: string;
    readonly notAfter: string;
    readonly status: IdentityStatus;
    readonly operationId: string;
    readonly createdAt: string;
}

export interface EnrollmentRecord {
    readonly pk: string;
    readonly sk: 'STATE';
    readonly operationId: string;
    readonly operationType: EnrollmentOperationType;
    readonly consumerId: string;
    readonly environment: EnvironmentName;
    readonly rootFingerprint: string;
    readonly apiFingerprint: string;
    /** Public, Hemlig-issued leaf returned when enrollment becomes active. */
    readonly apiCertificatePem: string;
    readonly createdAt: string;
    readonly workflowState: WorkflowState;
    readonly requestDigest: string;
    readonly actor: Actor;
    readonly idempotencyKey: string;
}

export interface ConsumerProvisioningResult {
    readonly consumerId: string;
    readonly environment: EnvironmentName;
    readonly rootFingerprint: string;
    readonly apiFingerprint: string;
    /** Public client certificate corresponding to the submitted CSR. */
    readonly apiCertificatePem: string;
    readonly status: 'ACTIVE';
}

export interface ObjectReference {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly checksumSha256: string;
}

export interface ChangePage {
    readonly changes: readonly AccessRecord[];
    readonly nextCursor?: string;
}

export interface CatalogPage {
    readonly secrets: readonly HeadRecord[];
    readonly nextCursor?: string;
}
