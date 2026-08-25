export type EnvironmentName = string;

/** Administrator-defined namespace for secrets and consumer identities. */
export interface EnvironmentRecord {
  readonly pk: "SYSTEM#ENVIRONMENTS";
  readonly sk: string;
  readonly name: EnvironmentName;
  readonly createdAt: string;
  readonly createdBy: Actor;
}

export type Permission = "read";

/** Capabilities granted to a non-administrator Hemlig agent identity. */
export type AgentCapability = "read" | "write";

export type AgentGrantStatus = "PENDING" | "ACTIVE";

export type SecretState = "PENDING_VALUE" | "ACTIVE" | "REVOKED" | "ARCHIVED";

export type WorkflowState =
  "PREPARED" | "READY" | "RETRYABLE" | "FAILED" | "DELETED";

export type IdentityStatus =
  "PENDING" | "ACTIVE" | "REVOKED" | "EXPIRED" | "FAILED";

export type ConsumerStatus = "PENDING" | "ACTIVE" | "FAILED";

export type EnrollmentOperationType = "consumer.enroll";

export interface Actor {
  readonly type: "human" | "consumer" | "system";
  readonly id: string;
  /**
   * Point-in-time display email from an administrator's verified OIDC token.
   * The immutable `id` remains the configured, stable subject claim.
   */
  readonly email?: string;
  readonly tenantId?: string;
  readonly consumerId?: string;
  readonly environment?: EnvironmentName;
}

export interface SecretEntry {
  readonly encoding: "utf8" | "base64";
  readonly value: string;
}

export type SecretPayload = Readonly<Record<string, SecretEntry>>;

export interface SecretMetadata {
  readonly description?: string;
  /** Bounded, exact-match organizational labels. They have no authorization meaning. */
  readonly tags?: Readonly<Record<string, string>>;
}

export interface Grant {
  readonly consumerId: string;
  readonly permissions: readonly Permission[];
}

/** One immutable target and its exact agent operations. */
export interface AgentSecretGrant {
  readonly secretId: string;
  readonly secretUid: string;
  readonly permissions: readonly AgentCapability[];
}

export interface ControlRevision {
  readonly schemaVersion: 1;
  /** Present on UID-native revisions; legacy revisions remain readable. */
  readonly secretUid?: string;
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
  readonly algorithm: "AES-256-GCM";
  readonly encryptedDataKey: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
}

export interface PayloadRevision {
  readonly schemaVersion: 1;
  /** Present on UID-native revisions; legacy revisions remain decryptable. */
  readonly secretUid?: string;
  readonly secretId: string;
  readonly payloadVersionId: string;
  readonly environment: EnvironmentName;
  readonly createdAt: string;
  readonly createdBy: Actor;
  readonly payload: EncryptedPayload;
}

export interface HeadRecord {
  readonly pk: string;
  readonly sk: "HEAD";
  readonly secretUid: string;
  readonly secretId: string;
  readonly environment: EnvironmentName;
  readonly controlVersionId: string;
  readonly controlObjectVersionId?: string;
  /** Exact immutable object key; preserves legacy revision locations after migration. */
  readonly controlObjectKey?: string;
  readonly payloadVersionId?: string;
  readonly payloadObjectVersionId?: string;
  /** Exact immutable object key; preserves legacy revision locations after migration. */
  readonly payloadObjectKey?: string;
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
  readonly secretUid: string;
  readonly secretId: string;
  readonly environment: EnvironmentName;
  readonly permissions: readonly Permission[];
  /**
   * Last revision written while this grant changed. Consumer delivery always
   * authorizes against the transactionally-read current HEAD, so ordinary
   * payload writes do not rewrite every consumer grant just to advance this
   * projection.
   */
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly state: SecretState;
  readonly changeKind: "secret.changed" | "secret.revoked";
}

/** One currently effective secret ACL entry, projected for consumer management. */
export interface ConsumerSecretGrant {
  readonly secretUid: string;
  readonly secretId: string;
  readonly permissions: readonly Permission[];
  readonly controlVersionId: string;
  readonly state: SecretState;
}

export interface ConsumerSecretGrantPage {
  readonly grants: readonly ConsumerSecretGrant[];
  readonly nextCursor?: string;
}

export interface IdentityRecord {
  readonly pk: string;
  readonly sk: "PROFILE";
  readonly fingerprint: string;
  readonly consumerId: string;
  readonly environment: EnvironmentName;
  readonly kind: "api" | "notify";
  readonly status: IdentityStatus;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly certificatePem?: string;
  /** Sparse GSI projection for administrative identity browsing. */
  readonly identityConsumerPk?: string;
  readonly identityConsumerSk?: string;
}

export interface IssuerKeyEnvelope {
  readonly algorithm: "AES-256-GCM";
  readonly encryptedDataKey: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
}

export interface IssuerRecord {
  readonly pk: "SYSTEM#ISSUER";
  readonly sk: "PROFILE";
  readonly rootCertificatePem: string;
  readonly encryptedPrivateKey: IssuerKeyEnvelope;
  readonly fingerprint: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly createdAt: string;
}

export interface ConsumerRecord {
  readonly pk: string;
  readonly sk: "PROFILE";
  readonly consumerId: string;
  readonly environment: EnvironmentName;
  readonly subjectUri: string;
  readonly status: ConsumerStatus;
  readonly createdAt: string;
  readonly createdBy: Actor;
  /**
   * Present only while the first enrollment is still being published.  It
   * lets a replacement bootstrap capability resume that one operation
   * instead of attempting a second consumer creation.
   */
  readonly pendingEnrollmentOperationId?: string;
  /** Sparse GSI projection for administrative consumer browsing. */
  readonly consumerDirectoryPk?: string;
  readonly consumerDirectorySk?: string;
}

/**
 * Administrator-owned remote policy for an enrolled namespace agent. Each
 * entry binds its display ID, immutable UID, and exact read/write operations
 * together so the two identifiers can never drift apart.
 */
export interface AgentGrantRecord {
  readonly pk: string;
  readonly sk: "PROFILE";
  readonly grantId: string;
  readonly consumerId: string;
  readonly environment: EnvironmentName;
  readonly capabilities: readonly AgentCapability[];
  readonly secretGrants: readonly AgentSecretGrant[];
  readonly displayName?: string;
  readonly status: AgentGrantStatus;
  readonly createdAt: string;
  readonly createdBy: Actor;
  readonly activatedAt?: string;
  readonly activatedFingerprint?: string;
}

/** Hash-only, single-use bootstrap capability; never store the plaintext token. */
export interface BootstrapCapabilityRecord {
  readonly pk: string;
  readonly sk: "STATE";
  readonly tokenHash: string;
  readonly grantId: string;
  readonly expiresAt: string;
  readonly ttl: number;
  readonly status: "PENDING" | "CONSUMED";
  readonly createdAt: string;
  readonly createdBy: Actor;
  readonly consumedAt?: string;
  readonly consumedFingerprint?: string;
}

/**
 * Payload-free, at-least-once delivery hint. One record groups all recipients
 * for a secret change, so an ordinary payload write is O(1); the background
 * publisher fans out the MQTT prompts. The authoritative state remains the
 * transactionally-read control head and consumer grant snapshot.
 */
export interface NotificationOutboxRecord {
  readonly pk: string;
  readonly sk: "EVENT";
  readonly eventId: string;
  /** Recipients captured atomically with the secret change. */
  readonly consumerIds?: readonly string[];
  /** Legacy single-recipient records created before grouped fan-out. */
  readonly consumerId?: string;
  readonly secretId: string;
  readonly environment: EnvironmentName;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly kind: "secret.changed" | "secret.revoked";
  readonly createdAt: string;
  readonly status: "PENDING" | "DELIVERED";
  /** Set only after publish so undelivered evidence cannot expire silently. */
  readonly ttl?: number;
}

export interface TruststoreRootRecord {
  readonly pk: "TRUSTSTORE#ROOTS";
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
  readonly sk: "STATE";
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
  readonly status: "ACTIVE";
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
