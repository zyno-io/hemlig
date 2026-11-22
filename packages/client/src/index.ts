export interface SecretEntry {
  readonly encoding: "utf8" | "base64";
  readonly value: string;
}

export type SecretPayload = Readonly<Record<string, SecretEntry>>;

export interface SecretMetadata {
  readonly description?: string;
  readonly path?: string;
  readonly tags?: Readonly<Record<string, string>>;
}

export interface Grant {
  readonly consumerId: string;
  readonly permissions: readonly ["read"] | readonly "read"[];
}

export interface ControlRevision {
  readonly secretUid: string;
  readonly secretId: string;
  readonly environment: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly payloadKeyCount?: number;
  readonly state: "PENDING_VALUE" | "ACTIVE" | "REVOKED" | "ARCHIVED";
  readonly metadata: SecretMetadata;
  readonly acl?: readonly Grant[];
  /** Returned only by the admin GET secret route: ACL consumers whose rows are managed by an AgentGrant. */
  readonly agentManagedConsumerIds?: readonly string[];
}

export interface ConsumerSecretResponse {
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId: string;
  readonly payload: SecretPayload;
}

export interface AdminSecretPayloadResponse {
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId: string;
  readonly payload: SecretPayload;
}

export interface SecretCatalogEntry {
  readonly secretUid: string;
  readonly secretId: string;
  readonly environment: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly payloadKeyCount?: number;
  readonly state: ControlRevision["state"];
  readonly metadata: SecretMetadata;
  readonly updatedAt?: string;
}

export interface SecretCatalogPage {
  readonly secrets: readonly SecretCatalogEntry[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface SecretRevision {
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly payloadKeyCount?: number;
  readonly createdAt: string;
  readonly createdBy: Record<string, unknown>;
  readonly isCurrent: boolean;
  readonly objectAvailable: boolean;
}

export interface SecretRevisionPage {
  readonly secretId: string;
  readonly revisions: readonly SecretRevision[];
  readonly truncated: boolean;
  readonly generatedAt: string;
}

export interface ConsumerSummary {
  readonly consumerId: string;
  readonly environment: string;
  readonly status: "PENDING" | "ACTIVE" | "FAILED";
  readonly subjectUri: string;
  readonly createdAt: string;
}

export interface ConsumerListPage {
  readonly consumers: readonly ConsumerSummary[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface ConsumerDetail extends ConsumerSummary {
  readonly createdBy: Record<string, unknown>;
  readonly activeApiIdentityCount: number;
  readonly rootFingerprint?: string;
}

export interface ApiIdentityDetail {
  readonly apiFingerprint: string;
  readonly status: "PENDING" | "ACTIVE" | "REVOKED" | "EXPIRED" | "FAILED";
  readonly kind: "api" | "notify";
  readonly notBefore: string;
  readonly notAfter: string;
  readonly apiCertificatePem?: string;
}

export interface ApiIdentityListPage {
  readonly consumerId: string;
  readonly environment: string;
  readonly rootFingerprint?: string;
  readonly apiIdentities: readonly ApiIdentityDetail[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface IssuerStatus {
  readonly rootFingerprint: string;
  readonly rootCertificatePem: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly createdAt: string;
  readonly truststore?: {
    readonly objectKey: string;
    readonly versionId: string;
    readonly anchorCount: number;
  };
}

export interface ConsumerProvisioningResult {
  readonly consumerId: string;
  readonly environment: string;
  readonly rootFingerprint: string;
  readonly apiFingerprint: string;
  readonly apiCertificatePem: string;
  readonly status: "ACTIVE";
}

export interface AgentIdentityRotation extends ConsumerProvisioningResult {
  readonly notBefore: string;
  readonly notAfter: string;
}

export interface AgentGrant {
  readonly grantId: string;
  readonly consumerId: string;
  readonly environment: string;
  readonly capabilities: readonly ("read" | "write")[];
  readonly secretGrants: readonly AgentSecretGrant[];
  readonly displayName?: string;
  readonly status: "PENDING" | "ACTIVE";
  readonly createdAt: string;
}

/** One immutable secret target and its exact agent operations. */
export interface AgentSecretGrant {
  readonly secretId: string;
  readonly secretUid: string;
  readonly permissions: readonly ("read" | "write")[];
}

export interface BootstrapCapability {
  readonly grantId: string;
  /** Revealed once. Store only in the intended bootstrap Secret. */
  readonly token: string;
  readonly expiresAt: string;
}

export interface AgentMqttConfig {
  readonly endpoint: string;
  readonly clientId: string;
  readonly topic: string;
}

export interface AgentConfig {
  readonly consumerId: string;
  readonly environment: string;
  readonly grant: Pick<
    AgentGrant,
    "grantId" | "capabilities" | "secretGrants"
  > & {
    /** @deprecated Derive from secretGrants instead. */
    readonly readSecretIds?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly readSecretUids?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly writeSecretIds?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly writeSecretUids?: readonly string[];
  };
  readonly mqtt: AgentMqttConfig;
}

export interface AgentBootstrapResult extends ConsumerProvisioningResult {
  readonly grant: Pick<
    AgentGrant,
    "grantId" | "consumerId" | "environment" | "capabilities" | "secretGrants"
  > & {
    /** @deprecated Derive from secretGrants instead. */
    readonly readSecretIds?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly readSecretUids?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly writeSecretIds?: readonly string[];
    /** @deprecated Derive from secretGrants instead. */
    readonly writeSecretUids?: readonly string[];
  };
}

export interface ConsumerChange {
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly state: "PENDING_VALUE" | "ACTIVE" | "REVOKED";
  readonly changeKind: "secret.changed" | "secret.revoked";
}

export interface ConsumerChangePage {
  readonly changes: readonly ConsumerChange[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface AgentSyncEntry {
  readonly secretUid: string;
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly state: "PENDING_VALUE" | "ACTIVE" | "REVOKED";
  readonly permissions: readonly ("read" | "write")[];
  readonly metadata?: SecretMetadata;
}

export interface AgentSyncPage {
  readonly config: AgentConfig;
  readonly snapshot: boolean;
  readonly changes: readonly AgentSyncEntry[];
  readonly nextCursor?: string;
  readonly syncCursor?: string;
}

export interface AgentControl {
  readonly secretId: string;
  readonly environment: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly payloadKeyCount?: number;
  readonly state: "PENDING_VALUE" | "ACTIVE" | "REVOKED";
  readonly metadata: SecretMetadata;
}

export interface ApiIdentityResult {
  readonly consumerId: string;
  readonly environment: string;
  readonly rootFingerprint?: string;
  readonly apiFingerprint: string;
  readonly apiCertificatePem?: string;
  readonly status: "ACTIVE" | "REVOKED";
}

export type PkiCaStatus =
  "PENDING_CERTIFICATE" | "ACTIVE" | "RETIRED" | "REVOKED" | "FAILED";
export type PkiKeyState = "ACTIVE" | "DISABLED" | "DESTROYED";
export type PkiKeyAlgorithm =
  "ECDSA_P256" | "ECDSA_P384" | "RSA_3072" | "RSA_4096" | "ED25519";
export type PkiLeafKeyAlgorithm =
  | "ECDSA_P256"
  | "ECDSA_P384"
  | "ECDSA_P521"
  | "ED25519"
  | "RSA_2048"
  | "RSA_3072"
  | "RSA_4096"
  | "RSA_8192";
export type PkiCrlState = "MISSING" | "CURRENT" | "STALE";

export interface PkiCaSubject {
  readonly commonName: string;
  readonly organization?: string;
  readonly organizationalUnit?: string;
  readonly country?: string;
  readonly locality?: string;
  readonly state?: string;
}

export interface PkiNameSubtrees {
  readonly dns?: readonly string[];
  readonly ip?: readonly string[];
  readonly uri?: readonly string[];
}

export interface PkiNameConstraints {
  readonly permitted?: PkiNameSubtrees;
  readonly excluded?: PkiNameSubtrees;
}

export interface PkiRequestedConstraints {
  readonly nameConstraints?: PkiNameConstraints;
  readonly extendedKeyUsages?: readonly ("serverAuth" | "clientAuth")[];
}

export interface PkiCaPolicyInput {
  readonly maxLeafLifetimeSeconds?: number;
  readonly leafKeyAlgorithms?: readonly PkiLeafKeyAlgorithm[];
  readonly capacity?: number;
  readonly issuancePerHour?: number;
  readonly crlValiditySeconds?: number;
}

export interface PkiCaPolicy {
  readonly maxLeafLifetimeSeconds: number;
  readonly leafKeyAlgorithms: readonly PkiLeafKeyAlgorithm[];
  readonly capacity: number;
  readonly issuancePerHour: number;
  readonly crlValiditySeconds: number;
  readonly issueLeaves: boolean;
  readonly issueSubordinates: boolean;
}

export interface PkiCreateCaRequest {
  readonly environment: string;
  readonly name: string;
  readonly kind: "EXTERNAL_INTERMEDIATE";
  readonly keyAlgorithm: PkiKeyAlgorithm;
  readonly subject: PkiCaSubject;
  readonly requestedConstraints?: PkiRequestedConstraints;
  readonly policy?: PkiCaPolicyInput;
  readonly crl?: { readonly validitySeconds?: number };
  readonly displayName?: string;
}

export interface PkiUpdateCaRequest {
  readonly displayName?: string;
  readonly policy: PkiCaPolicyInput;
}

export interface PkiActivateCaRequest {
  readonly certificatePem: string;
  readonly chainPem: string;
  /** PEM or base64 DER. */
  readonly rootCrl?: string;
  readonly acceptBroaderConstraints?: boolean;
}

export interface PkiUploadCrlRequest {
  /** PEM or base64 DER. */
  readonly crl: string;
}

export interface PkiWarning {
  readonly code: string;
  readonly message: string;
}

export interface PkiCrlView {
  readonly number: number;
  readonly thisUpdate: string;
  readonly nextUpdate: string;
  readonly entryCount: number;
  readonly sha256: string;
  readonly revision: number;
  readonly pendingRevocations: number;
  readonly dirtySince?: string;
  readonly state: PkiCrlState;
}

export interface PkiRootCrlView {
  readonly extId: string;
  readonly state: PkiCrlState;
  readonly numberHex?: string;
  readonly thisUpdate?: string;
  readonly nextUpdate?: string;
}

export interface PkiCaSummary {
  readonly caId: string;
  readonly environment: string;
  readonly name: string;
  readonly displayName?: string;
  readonly kind: "EXTERNAL_INTERMEDIATE";
  readonly status: PkiCaStatus;
  readonly version: string;
  readonly keyAlgorithm: PkiKeyAlgorithm;
  readonly keyState: PkiKeyState;
  readonly fingerprint?: string;
  readonly notAfter?: string;
  readonly createdAt: string;
}

export interface PkiCaDetail extends PkiCaSummary {
  readonly key: {
    readonly custody: string;
    readonly algorithm: PkiKeyAlgorithm;
    readonly spkiSha256: string;
    readonly state: PkiKeyState;
  };
  readonly subject: PkiCaSubject;
  readonly subjectDn: string;
  readonly requestedConstraints: PkiRequestedConstraints;
  readonly effectiveConstraints?: PkiRequestedConstraints;
  readonly acceptBroaderConstraints?: boolean;
  readonly csrPem?: string;
  readonly certificatePem?: string;
  readonly chainPem?: string;
  readonly serial?: string;
  readonly notBefore?: string;
  readonly parent?: { readonly type: string; readonly id: string };
  readonly crlIssuers: readonly {
    readonly type: string;
    readonly id: string;
  }[];
  readonly policy: PkiCaPolicy;
  readonly maxIssueLifetimeEverSeconds: number;
  readonly createdBy: Record<string, unknown>;
  readonly activatedAt?: string;
  readonly retiredAt?: string;
  readonly revokedAt?: string;
  readonly revocationReason?: string;
  readonly revocationSource?: string;
  readonly revocationEvidence?: string;
  readonly drained: boolean;
  readonly drainAt?: string;
  readonly crl?: PkiCrlView;
  readonly rootCrl?: PkiRootCrlView;
  readonly warnings?: readonly PkiWarning[];
  readonly capacity?: PkiCaCapacityView;
}

export interface PkiCaCapacityView {
  readonly capacity: number;
  readonly issuancePerHour: number;
  readonly count?: number;
  readonly countFrom?: string;
  readonly countedAt?: string;
}

export interface PkiCreateCaResponse extends PkiCaDetail {
  readonly csrPem: string;
}

export interface PkiCaListPage {
  readonly cas: readonly PkiCaSummary[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface PkiCrlPublishResponse {
  readonly caId: string;
  readonly crl: PkiCrlView;
}

export interface PkiExternalCaCrlPointer {
  readonly numberHex: string;
  readonly thisUpdate: string;
  readonly nextUpdate: string;
  readonly sha256: string;
  readonly uploadedAt?: string;
}

export interface PkiExternalCaSummary {
  readonly extId: string;
  readonly fingerprint: string;
  readonly subjectDn: string;
  readonly notAfter: string;
  readonly crlState: PkiCrlState;
  readonly version: string;
  readonly createdAt: string;
}

export interface PkiExternalCaDetail extends PkiExternalCaSummary {
  readonly certificatePem: string;
  readonly spkiSha256: string;
  readonly subjectKeyIdentifier: string;
  readonly dependents: readonly string[];
  readonly environments: readonly string[];
  readonly crl?: PkiExternalCaCrlPointer;
}

export interface PkiExternalCaListPage {
  readonly externalCas: readonly PkiExternalCaSummary[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface PkiUploadCrlResponse {
  readonly extId: string;
  readonly crl: PkiExternalCaCrlPointer;
  readonly changed: boolean;
  readonly revokedCaIds: readonly string[];
}

export type PkiGrantStatus = "ACTIVE" | "DISABLED" | "DELETED";
export type PkiCertificateStatus = "ISSUED" | "REVOKED" | "EXPIRED";
export type PkiRevocationReason =
  | "unspecified"
  | "keyCompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "privilegeWithdrawn";

export interface PkiGrantNameRules {
  readonly allow?: readonly string[];
  readonly deny?: readonly string[];
}

export interface PkiGrantDnsRules extends PkiGrantNameRules {
  readonly allowWildcardNames?: boolean;
}

export interface PkiGrantNames {
  readonly dns?: PkiGrantDnsRules;
  readonly ip?: PkiGrantNameRules;
  readonly uri?: PkiGrantNameRules;
  readonly commonName?: Readonly<Record<string, unknown>>;
  readonly maxSans?: number;
}

/** The grant policy fields (the grant shape minus its envelope). */
export interface PkiGrantPolicyFields {
  readonly names?: PkiGrantNames;
  readonly subject?: {
    readonly allow?: Readonly<Record<string, readonly string[]>>;
  };
  readonly keyAlgorithms?: readonly PkiLeafKeyAlgorithm[];
  readonly keyUsages?: readonly string[];
  readonly extendedKeyUsages?: {
    readonly allow: readonly string[];
    readonly default: readonly string[];
  };
  readonly lifetime?: {
    readonly defaultSeconds: number;
    readonly maxSeconds: number;
    readonly minSeconds?: number;
  };
  readonly forced?: {
    readonly subject?: Readonly<Record<string, string>>;
    readonly sans?: PkiNameSubtrees;
    readonly certificatePolicies?: readonly string[];
  };
  readonly quotas?: { readonly perHour?: number; readonly perDay?: number };
}

/** Body of a grant PUT: policy fields plus the envelope. */
export interface PkiIssuanceGrantInput extends PkiGrantPolicyFields {
  readonly caId: string;
  readonly displayName?: string;
  readonly status?: "ACTIVE" | "DISABLED";
  readonly expiresAt?: string;
}

export interface PkiCreateIssuanceGrantRequest extends PkiIssuanceGrantInput {
  readonly name: string;
}

export interface PkiGrantQuotas {
  readonly perHour: number;
  readonly perDay: number;
}

export interface PkiIssuanceGrant {
  readonly consumerId: string;
  readonly environment: string;
  readonly name: string;
  readonly uid: string;
  readonly caId: string;
  readonly status: PkiGrantStatus;
  readonly expired: boolean;
  readonly displayName?: string;
  readonly expiresAt?: string;
  readonly policy: PkiGrantPolicyFields;
  readonly policyDigest: string;
  readonly quotas: PkiGrantQuotas;
  readonly version: string;
  readonly createdAt: string;
  readonly createdBy: Record<string, unknown>;
  readonly updatedAt: string;
  readonly updatedBy: Record<string, unknown>;
  readonly deletedAt?: string;
  readonly deletedBy?: Record<string, unknown>;
  readonly warnings?: readonly PkiGrantIssue[];
}

export interface PkiIssuanceGrantListPage {
  readonly grants: readonly PkiIssuanceGrant[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface PkiGrantIssue {
  readonly code: string;
  readonly path: string;
  readonly message: string;
}

export interface PkiGrantValidationResult {
  readonly valid: boolean;
  readonly errors: readonly PkiGrantIssue[];
  readonly warnings: readonly PkiGrantIssue[];
  readonly policyDigest?: string;
}

export interface PkiEvaluateRequest {
  readonly certificateSigningRequestPem?: string;
  readonly keyAlgorithm?: PkiLeafKeyAlgorithm;
  readonly sans?: {
    readonly dns?: readonly string[];
    readonly ip?: readonly string[];
    readonly uri?: readonly string[];
  };
  readonly commonName?: string;
  readonly subject?: Readonly<Record<string, string>>;
  readonly durationSeconds?: number;
  readonly usages?: readonly string[];
  readonly isCA?: boolean;
}

export interface PkiTraceStep {
  readonly step: number;
  readonly name: string;
  readonly outcome: string;
  readonly [key: string]: unknown;
}

export interface PkiEvaluateResponse {
  readonly decision: "allow" | "deny";
  readonly denial?: {
    readonly reason: string;
    readonly detail?: string;
    readonly deniedNameType?: string;
    readonly deniedName?: string;
  };
  readonly trace: readonly PkiTraceStep[];
  readonly plan?: Readonly<Record<string, unknown>>;
  readonly context: Readonly<Record<string, unknown>>;
}

/** Consumer issue request: names come from the CSR only. */
export interface PkiIssueCertificateRequest {
  readonly certificateSigningRequestPem: string;
  readonly durationSeconds?: number;
  readonly usages?: readonly string[];
  readonly isCA?: boolean;
  readonly requester?: {
    readonly kubernetes?: {
      readonly namespace: string;
      readonly name: string;
      readonly uid: string;
      readonly certificateName?: string;
      readonly revision?: string;
    };
  };
}

export interface PkiAdminIssueCertificateRequest {
  readonly certificateSigningRequestPem: string;
  readonly useCsrNames?: boolean;
  readonly sans?: {
    readonly dns?: readonly string[];
    readonly ip?: readonly string[];
    readonly uri?: readonly string[];
  };
  readonly subject?: Partial<
    Record<
      | "commonName"
      | "organization"
      | "organizationalUnit"
      | "country"
      | "locality"
      | "state",
      string
    >
  >;
  readonly durationSeconds?: number;
  readonly usages?: readonly string[];
  readonly isCA?: boolean;
}

export interface PkiIssuedCertificate {
  readonly caId: string;
  readonly serial: string;
  readonly fingerprint: string;
  readonly certificatePem: string;
  readonly chainPem: string;
  readonly caPem: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly lifetimeClamped: boolean;
  readonly issuanceGrant?: string;
}

export interface PkiCertificateSummary {
  readonly caId: string;
  readonly serial: string;
  readonly status: PkiCertificateStatus | "CA_REVOKED";
  readonly storedStatus: "ISSUED" | "REVOKED";
  readonly fingerprint: string;
  readonly subject: string;
  readonly sans: Readonly<Record<string, readonly string[]>>;
  readonly keyAlgorithm?: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly issuedAt: string;
  readonly requester: Readonly<Record<string, unknown>>;
  readonly revocation?: Readonly<Record<string, unknown>>;
}

export interface PkiCertificateDetail extends PkiCertificateSummary {
  readonly certificatePem: string;
  readonly spkiSha256: string;
  readonly keyUsages: readonly string[];
  readonly extendedKeyUsages: readonly string[];
  readonly lifetimeClamped: boolean;
}

export interface PkiCertificateListPage {
  readonly certificates: readonly PkiCertificateSummary[];
  readonly nextCursor?: string;
  readonly generatedAt: string;
}

export interface PkiRevokeCertificateRequest {
  readonly reason?: PkiRevocationReason;
  readonly invalidityDate?: string;
}

export interface PkiRevokeCertificateResponse {
  readonly certificate: PkiCertificateDetail;
  readonly crlEntry: boolean;
  readonly crlPublished: boolean;
  readonly crlNumber?: number;
  readonly changed: boolean;
  readonly crl?: {
    readonly number?: number;
    readonly pendingRevocations?: number;
  };
}

export interface PkiBulkRevokeRequest {
  readonly reason?: PkiRevocationReason;
  readonly invalidityDate?: string;
  readonly issuanceGrant?: string;
  readonly issuanceGrantUid?: string;
}

export interface PkiBulkRevokeResponse {
  readonly consumerId: string;
  readonly issuanceGrant?: string;
  /** False when the run hit its deadline: retry with the same idempotency key. */
  readonly complete: boolean;
  readonly revoked: number;
  readonly alreadyRevoked: number;
  readonly caIds: readonly string[];
  readonly crls?: readonly {
    readonly caId: string;
    readonly crlPublished: boolean;
    readonly crlNumber?: number;
  }[];
}

export interface PkiConsumerIssuanceGrant {
  readonly name: string;
  readonly uid: string;
  readonly status: PkiGrantStatus;
  readonly expired: boolean;
  readonly version: string;
  readonly expiresAt?: string;
  readonly policy: PkiGrantPolicyFields;
  readonly quotas: PkiGrantQuotas;
  readonly ca: {
    readonly caId: string;
    readonly name?: string;
    readonly fingerprint?: string;
    readonly notAfter?: string;
    readonly status: PkiCaStatus | "UNKNOWN";
  };
}

export interface PkiConsumerIssuanceGrantList {
  readonly grants: readonly PkiConsumerIssuanceGrant[];
  readonly generatedAt: string;
}

export interface TransportRequest {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly url: URL;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
  /** `binary` keeps a 2xx body as raw bytes; errors are still JSON envelopes. */
  readonly responseType?: "json" | "binary";
}

export interface TransportResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body?: unknown;
  /** Set for a 2xx response when `responseType` was `binary`. */
  readonly bytes?: Uint8Array;
}

/**
 * Decodes a raw response body. A 2xx (except 304) binary response is returned
 * byte-for-byte and never UTF-8 decoded; every other response is parsed as JSON.
 */
export const decodeTransportBody = (
  status: number,
  _headers: Readonly<Record<string, string | undefined>>,
  raw: Uint8Array,
  responseType: "json" | "binary" = "json",
): { body?: unknown; bytes?: Uint8Array } => {
  if (
    responseType === "binary" &&
    status >= 200 &&
    status < 300 &&
    status !== 304
  ) {
    return { bytes: raw };
  }
  const text = new TextDecoder().decode(raw);
  if (text.length === 0) {
    return {};
  }
  try {
    return { body: JSON.parse(text) as unknown };
  } catch {
    return {};
  }
};

export type BinaryResult =
  | {
      readonly status: 200;
      readonly bytes: Uint8Array;
      readonly etag?: string;
      readonly contentType?: string;
    }
  | { readonly status: 304; readonly etag?: string };

export interface HemligTransport {
  request(request: TransportRequest): Promise<TransportResponse>;
}

export class HemligError extends Error {
  public constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
    readonly details?: Readonly<Record<string, string | number | boolean>>,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

export class HemligClient {
  public constructor(
    private readonly baseUrl: URL,
    private readonly transport: HemligTransport,
  ) {}

  /**
   * Returns undefined for a conditional GET that received 304 Not Modified.
   */
  public async getConsumerSecret(
    secretId: string,
    ifNoneMatch?: string,
  ): Promise<ConsumerSecretResponse | undefined> {
    return this.request<ConsumerSecretResponse>(
      "GET",
      `/v1/secrets/${encodeURIComponent(secretId)}`,
      undefined,
      undefined,
      undefined,
      undefined,
      ifNoneMatch,
      true,
    );
  }

  /** Redeems the one-time bootstrap capability on the administrator origin. */
  public async redeemBootstrap(
    bootstrapToken: string,
    apiCertificateSigningRequestPem: string,
  ): Promise<AgentBootstrapResult> {
    const response = await this.transport.request({
      method: "POST",
      url: new URL("/v1/bootstrap/redeem", this.baseUrl),
      headers: { authorization: `Bootstrap ${bootstrapToken}` },
      body: { apiCertificateSigningRequestPem },
    });
    return this.responseBody<AgentBootstrapResult>(response);
  }

  public async getAgentConfig(): Promise<AgentConfig> {
    return this.request("GET", "/v1/agent/config");
  }

  /**
   * Replaces the calling mTLS identity with a leaf for a new key. Reuse the same
   * idempotency key (for example a hash of the CSR) when retrying a CSR.
   */
  public async rotateAgentIdentity(
    apiCertificateSigningRequestPem: string,
    idempotencyKey: string,
  ): Promise<AgentIdentityRotation> {
    return this.request(
      "POST",
      "/v1/agent/identities/rotate",
      undefined,
      { apiCertificateSigningRequestPem },
      idempotencyKey,
    );
  }

  public async getAgentSecret(
    secretId: string,
    ifNoneMatch?: string,
  ): Promise<ConsumerSecretResponse | undefined> {
    return this.request<ConsumerSecretResponse>(
      "GET",
      `/v1/agent/secrets/${encodeURIComponent(secretId)}`,
      undefined,
      undefined,
      undefined,
      undefined,
      ifNoneMatch,
      true,
    );
  }

  public async getAgentControl(secretId: string): Promise<AgentControl> {
    return this.request(
      "GET",
      `/v1/agent/secrets/${encodeURIComponent(secretId)}/control`,
    );
  }

  public async listAgentChanges(cursor?: string): Promise<ConsumerChangePage> {
    return this.request("GET", withQuery("/v1/changes", { cursor }));
  }

  public async syncAgent(
    query: { readonly syncCursor?: string; readonly cursor?: string } = {},
  ): Promise<AgentSyncPage> {
    return this.request("GET", withQuery("/v1/agent/sync", query));
  }

  public async updateAgentSecret(
    secretId: string,
    controlVersionId: string,
    metadata: SecretMetadata,
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      `/v1/agent/secrets/${encodeURIComponent(secretId)}`,
      undefined,
      { metadata },
      idempotencyKey,
      controlVersionId,
    );
  }

  public async putAgentPayload(
    secretId: string,
    controlVersionId: string,
    payload: SecretPayload,
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      `/v1/agent/secrets/${encodeURIComponent(secretId)}/payload`,
      undefined,
      { payload },
      idempotencyKey,
      controlVersionId,
    );
  }

  public async getAdminSecret(
    token: string,
    environment: string,
    secretId: string,
  ): Promise<ControlRevision> {
    return this.request(
      "GET",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}`, {
        environment,
      }),
      token,
    );
  }

  /** Reads an archived secret using its immutable UID because its old ID can be reused. */
  public async getArchivedAdminSecret(
    token: string,
    environment: string,
    secretUid: string,
  ): Promise<ControlRevision> {
    return this.request(
      "GET",
      withQuery(`/v1/admin/archived-secrets/${encodeURIComponent(secretUid)}`, {
        environment,
      }),
      token,
    );
  }

  public async getAdminSecretPayload(
    token: string,
    environment: string,
    secretId: string,
  ): Promise<AdminSecretPayloadResponse> {
    return this.request(
      "GET",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}/payload`, {
        environment,
      }),
      token,
    );
  }

  public async listSecrets(
    token: string,
    query: {
      readonly environment: string;
      readonly pathPrefix?: string;
      readonly tags?: Readonly<Record<string, string>>;
      readonly cursor?: string;
      readonly archived?: boolean;
    },
  ): Promise<SecretCatalogPage> {
    const tags =
      query.tags === undefined
        ? undefined
        : Object.entries(query.tags)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([key, value]) => `${key}:${value}`)
            .join(",");
    return this.request(
      "GET",
      withQuery("/v1/admin/secrets", {
        environment: query.environment,
        pathPrefix: query.pathPrefix,
        tags,
        cursor: query.cursor,
        archived: query.archived ? "true" : undefined,
      }),
      token,
    );
  }

  public async listSecretRevisions(
    token: string,
    environment: string,
    secretId: string,
  ): Promise<SecretRevisionPage> {
    return this.request(
      "GET",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}/revisions`, {
        environment,
      }),
      token,
    );
  }

  public async listConsumers(
    token: string,
    query: { readonly environment: string; readonly cursor?: string },
  ): Promise<ConsumerListPage> {
    return this.request("GET", withQuery("/v1/admin/consumers", query), token);
  }

  public async getConsumer(
    token: string,
    consumerId: string,
  ): Promise<ConsumerDetail> {
    return this.request(
      "GET",
      `/v1/admin/consumers/${encodeURIComponent(consumerId)}`,
      token,
    );
  }

  public async listApiIdentities(
    token: string,
    consumerId: string,
    cursor?: string,
  ): Promise<ApiIdentityListPage> {
    return this.request(
      "GET",
      withQuery(
        `/v1/admin/consumers/${encodeURIComponent(consumerId)}/api-identities`,
        { cursor },
      ),
      token,
    );
  }

  public async getIssuer(token: string): Promise<IssuerStatus> {
    return this.request("GET", "/v1/admin/issuer", token);
  }

  public async createAdminSecret(
    token: string,
    input: {
      readonly secretId: string;
      readonly environment: string;
      readonly metadata: SecretMetadata;
      readonly acl: readonly Grant[];
    },
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "POST",
      "/v1/admin/secrets",
      token,
      input,
      idempotencyKey,
    );
  }

  public async createAgentGrant(
    token: string,
    input: {
      readonly consumerId: string;
      readonly environment: string;
      readonly capabilities: readonly ("read" | "write")[];
      readonly secretGrants: readonly {
        readonly secretId: string;
        readonly permissions: readonly ("read" | "write")[];
      }[];
      readonly displayName?: string;
    },
  ): Promise<AgentGrant> {
    return this.request("POST", "/v1/admin/agent-grants", token, input);
  }

  public async updateAgentGrant(
    token: string,
    grantId: string,
    input: {
      readonly capabilities: readonly ("read" | "write")[];
      readonly secretGrants: readonly {
        readonly secretId: string;
        readonly permissions: readonly ("read" | "write")[];
      }[];
      readonly displayName?: string;
    },
  ): Promise<AgentGrant> {
    return this.request(
      "PUT",
      `/v1/admin/agent-grants/${encodeURIComponent(grantId)}`,
      token,
      input,
    );
  }

  public async issueBootstrapCapability(
    token: string,
    grantId: string,
  ): Promise<BootstrapCapability> {
    return this.request(
      "POST",
      `/v1/admin/agent-grants/${encodeURIComponent(grantId)}/bootstrap-capabilities`,
      token,
    );
  }

  public async updateAdminSecret(
    token: string,
    environment: string,
    secretId: string,
    controlVersionId: string,
    input: Partial<Pick<ControlRevision, "metadata" | "acl">> & {
      /**
       * Keep AgentGrant-managed ACL rows the submitted `acl` omits. Send only
       * to servers that report `agentManagedConsumerIds`.
       */
      readonly preserveAgentAcl?: boolean;
    },
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}`, {
        environment,
      }),
      token,
      input,
      idempotencyKey,
      controlVersionId,
    );
  }

  public async archiveAdminSecret(
    token: string,
    environment: string,
    secretId: string,
    controlVersionId: string,
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "POST",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}/archive`, {
        environment,
      }),
      token,
      undefined,
      idempotencyKey,
      controlVersionId,
    );
  }

  public async putAdminPayload(
    token: string,
    environment: string,
    secretId: string,
    controlVersionId: string,
    payload: SecretPayload,
    idempotencyKey: string,
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      withQuery(`/v1/admin/secrets/${encodeURIComponent(secretId)}/payload`, {
        environment,
      }),
      token,
      { payload },
      idempotencyKey,
      controlVersionId,
    );
  }

  public async enrollConsumer(
    token: string,
    input: {
      readonly consumerId: string;
      readonly environment: string;
      readonly apiCertificateSigningRequestPem: string;
    },
    idempotencyKey: string,
  ): Promise<ConsumerProvisioningResult> {
    return this.request(
      "POST",
      "/v1/admin/consumers",
      token,
      input,
      idempotencyKey,
    );
  }

  public async rotateApiIdentity(
    token: string,
    consumerId: string,
    apiCertificateSigningRequestPem: string,
    idempotencyKey: string,
  ): Promise<ApiIdentityResult> {
    return this.request(
      "POST",
      `/v1/admin/consumers/${encodeURIComponent(consumerId)}/api-identities`,
      token,
      { apiCertificateSigningRequestPem },
      idempotencyKey,
    );
  }

  public async revokeApiIdentity(
    token: string,
    consumerId: string,
    apiFingerprint: string,
    idempotencyKey: string,
  ): Promise<ApiIdentityResult> {
    return this.request(
      "DELETE",
      `/v1/admin/consumers/${encodeURIComponent(consumerId)}/api-identities/${encodeURIComponent(apiFingerprint)}`,
      token,
      undefined,
      idempotencyKey,
    );
  }

  public async listPkiCas(
    token: string,
    query: { readonly environment: string; readonly cursor?: string },
  ): Promise<PkiCaListPage> {
    return this.request("GET", withQuery("/v1/admin/pki/cas", query), token);
  }

  public async getPkiCa(token: string, caId: string): Promise<PkiCaDetail> {
    return this.request("GET", pkiCaPath(caId), token);
  }

  public async createPkiCa(
    token: string,
    input: PkiCreateCaRequest,
    idempotencyKey: string,
  ): Promise<PkiCreateCaResponse> {
    return this.request(
      "POST",
      "/v1/admin/pki/cas",
      token,
      input,
      idempotencyKey,
    );
  }

  public async updatePkiCa(
    token: string,
    caId: string,
    version: string,
    input: PkiUpdateCaRequest,
    idempotencyKey: string,
  ): Promise<PkiCaDetail> {
    return this.request(
      "PUT",
      pkiCaPath(caId),
      token,
      input,
      idempotencyKey,
      version,
    );
  }

  public async deletePkiCa(
    token: string,
    caId: string,
    version: string,
    idempotencyKey: string,
  ): Promise<PkiCaDetail> {
    return this.request(
      "DELETE",
      pkiCaPath(caId),
      token,
      undefined,
      idempotencyKey,
      version,
    );
  }

  public async activatePkiCa(
    token: string,
    caId: string,
    input: PkiActivateCaRequest,
    idempotencyKey: string,
  ): Promise<PkiCaDetail> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/certificate`,
      token,
      input,
      idempotencyKey,
    );
  }

  public async retirePkiCa(
    token: string,
    caId: string,
    idempotencyKey: string,
  ): Promise<PkiCaDetail> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/retire`,
      token,
      undefined,
      idempotencyKey,
    );
  }

  public async destroyPkiCaKey(
    token: string,
    caId: string,
    idempotencyKey: string,
  ): Promise<PkiCaDetail> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/destroy-key`,
      token,
      undefined,
      idempotencyKey,
    );
  }

  public async publishPkiCrl(
    token: string,
    caId: string,
    idempotencyKey: string,
  ): Promise<PkiCrlPublishResponse> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/crl`,
      token,
      undefined,
      idempotencyKey,
    );
  }

  /** Downloads the current CRL (DER) for a CA or external CA. */
  public async getAdminCrl(
    token: string,
    issuerId: string,
    ifNoneMatch?: string,
  ): Promise<BinaryResult> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
    };
    if (ifNoneMatch !== undefined) {
      headers["if-none-match"] = `"${ifNoneMatch}"`;
    }
    const response = await this.transport.request({
      method: "GET",
      url: new URL(
        `/v1/admin/pki/crls/${encodeURIComponent(issuerId)}`,
        this.baseUrl,
      ),
      headers,
      responseType: "binary",
    });
    const etag = unquoteEtag(response.headers.etag);
    if (response.status === 304) {
      return etag === undefined ? { status: 304 } : { status: 304, etag };
    }
    if (response.status < 200 || response.status >= 300) {
      return this.responseBody<never>(response);
    }
    if (response.bytes === undefined) {
      throw new HemligError(
        response.status,
        "The transport did not return binary data.",
        "transport_binary_unsupported",
      );
    }
    const contentType = response.headers["content-type"];
    return {
      status: 200,
      bytes: response.bytes,
      ...(etag === undefined ? {} : { etag }),
      ...(contentType === undefined ? {} : { contentType }),
    };
  }

  public async listExternalCas(
    token: string,
    query: { readonly cursor?: string } = {},
  ): Promise<PkiExternalCaListPage> {
    return this.request(
      "GET",
      withQuery("/v1/admin/pki/external-cas", query),
      token,
    );
  }

  public async getExternalCa(
    token: string,
    extId: string,
  ): Promise<PkiExternalCaDetail> {
    return this.request(
      "GET",
      `/v1/admin/pki/external-cas/${encodeURIComponent(extId)}`,
      token,
    );
  }

  public async uploadExternalCaCrl(
    token: string,
    extId: string,
    crl: string,
    idempotencyKey: string,
  ): Promise<PkiUploadCrlResponse> {
    return this.request(
      "POST",
      `/v1/admin/pki/external-cas/${encodeURIComponent(extId)}/crl`,
      token,
      { crl },
      idempotencyKey,
    );
  }

  public async listCaIssuanceGrants(
    token: string,
    caId: string,
    query: { readonly cursor?: string } = {},
  ): Promise<PkiIssuanceGrantListPage> {
    return this.request(
      "GET",
      withQuery(`${pkiCaPath(caId)}/issuance-grants`, query),
      token,
    );
  }

  public async listAdminIssuanceGrants(
    token: string,
    consumerId: string,
    query: { readonly includeDeleted?: boolean; readonly cursor?: string } = {},
  ): Promise<PkiIssuanceGrantListPage> {
    return this.request(
      "GET",
      withQuery(pkiGrantsPath(consumerId), {
        includeDeleted: query.includeDeleted ? "true" : undefined,
        cursor: query.cursor,
      }),
      token,
    );
  }

  public async getAdminIssuanceGrant(
    token: string,
    consumerId: string,
    name: string,
  ): Promise<PkiIssuanceGrant> {
    return this.request("GET", pkiGrantPath(consumerId, name), token);
  }

  public async createIssuanceGrant(
    token: string,
    consumerId: string,
    input: PkiCreateIssuanceGrantRequest,
    idempotencyKey: string,
  ): Promise<PkiIssuanceGrant> {
    return this.request(
      "POST",
      pkiGrantsPath(consumerId),
      token,
      input,
      idempotencyKey,
    );
  }

  /** Dry-runs a grant create: nothing is written and no key is needed. */
  public async validateIssuanceGrantCreate(
    token: string,
    consumerId: string,
    input: PkiCreateIssuanceGrantRequest,
  ): Promise<PkiGrantValidationResult> {
    return this.request(
      "POST",
      withQuery(pkiGrantsPath(consumerId), { validateOnly: "true" }),
      token,
      input,
    );
  }

  public async updateIssuanceGrant(
    token: string,
    consumerId: string,
    name: string,
    version: string,
    input: PkiIssuanceGrantInput,
    idempotencyKey: string,
  ): Promise<PkiIssuanceGrant> {
    return this.request(
      "PUT",
      pkiGrantPath(consumerId, name),
      token,
      input,
      idempotencyKey,
      version,
    );
  }

  /** Dry-runs a grant update: `If-Match` is required, no key is sent. */
  public async validateIssuanceGrantUpdate(
    token: string,
    consumerId: string,
    name: string,
    version: string,
    input: PkiIssuanceGrantInput,
  ): Promise<PkiGrantValidationResult> {
    return this.request(
      "PUT",
      withQuery(pkiGrantPath(consumerId, name), { validateOnly: "true" }),
      token,
      input,
      undefined,
      version,
    );
  }

  public async deleteIssuanceGrant(
    token: string,
    consumerId: string,
    name: string,
    version: string,
    idempotencyKey: string,
  ): Promise<PkiIssuanceGrant> {
    return this.request(
      "DELETE",
      pkiGrantPath(consumerId, name),
      token,
      undefined,
      idempotencyKey,
      version,
    );
  }

  public async evaluateIssuanceGrant(
    token: string,
    consumerId: string,
    name: string,
    input: PkiEvaluateRequest,
  ): Promise<PkiEvaluateResponse> {
    return this.request(
      "POST",
      `${pkiGrantPath(consumerId, name)}/evaluate`,
      token,
      input,
    );
  }

  public async listPkiCertificates(
    token: string,
    caId: string,
    query: {
      readonly status?: PkiCertificateStatus;
      readonly expiringBefore?: string;
      readonly cursor?: string;
    } = {},
  ): Promise<PkiCertificateListPage> {
    return this.request(
      "GET",
      withQuery(`${pkiCaPath(caId)}/certificates`, query),
      token,
    );
  }

  public async getPkiCertificate(
    token: string,
    caId: string,
    serial: string,
  ): Promise<PkiCertificateDetail> {
    return this.request(
      "GET",
      `${pkiCaPath(caId)}/certificates/${encodeURIComponent(serial)}`,
      token,
    );
  }

  public async issuePkiCertificate(
    token: string,
    caId: string,
    input: PkiAdminIssueCertificateRequest,
    idempotencyKey: string,
  ): Promise<PkiIssuedCertificate> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/certificates`,
      token,
      input,
      idempotencyKey,
    );
  }

  public async revokePkiCertificate(
    token: string,
    caId: string,
    serial: string,
    input: PkiRevokeCertificateRequest,
    idempotencyKey: string,
  ): Promise<PkiRevokeCertificateResponse> {
    return this.request(
      "POST",
      `${pkiCaPath(caId)}/certificates/${encodeURIComponent(serial)}/revoke`,
      token,
      input,
      idempotencyKey,
    );
  }

  public async listConsumerPkiCertificates(
    token: string,
    consumerId: string,
    query: {
      readonly issuanceGrant?: string;
      readonly includeExpired?: boolean;
      readonly cursor?: string;
    } = {},
  ): Promise<PkiCertificateListPage> {
    return this.request(
      "GET",
      withQuery(
        `/v1/admin/pki/consumers/${encodeURIComponent(consumerId)}/certificates`,
        {
          issuanceGrant: query.issuanceGrant,
          includeExpired: query.includeExpired ? "true" : undefined,
          cursor: query.cursor,
        },
      ),
      token,
    );
  }

  /**
   * Revokes a consumer's certificates. When `complete` is false the run hit its
   * deadline: repeat the call with the same idempotency key.
   */
  public async revokeConsumerPkiCertificates(
    token: string,
    consumerId: string,
    input: PkiBulkRevokeRequest,
    idempotencyKey: string,
  ): Promise<PkiBulkRevokeResponse> {
    return this.request(
      "POST",
      `/v1/admin/pki/consumers/${encodeURIComponent(consumerId)}/certificates/revoke`,
      token,
      input,
      idempotencyKey,
    );
  }

  /** Lists the calling consumer's live grants (mTLS; no token). */
  public async listIssuanceGrants(): Promise<PkiConsumerIssuanceGrantList> {
    return this.request("GET", "/v1/pki/issuance-grants");
  }

  public async getIssuanceGrant(
    name: string,
  ): Promise<PkiConsumerIssuanceGrant> {
    return this.request(
      "GET",
      `/v1/pki/issuance-grants/${encodeURIComponent(name)}`,
    );
  }

  /** Reuse the same idempotency key (for example a CSR hash) when retrying. */
  public async issueCertificate(
    name: string,
    input: PkiIssueCertificateRequest,
    idempotencyKey: string,
  ): Promise<PkiIssuedCertificate> {
    return this.request(
      "POST",
      `/v1/pki/issuance-grants/${encodeURIComponent(name)}/certificates`,
      undefined,
      input,
      idempotencyKey,
    );
  }

  private request<T>(
    method: TransportRequest["method"],
    path: string,
    bearerToken?: string,
    body?: unknown,
    idempotencyKey?: string,
    ifMatch?: string,
    ifNoneMatch?: string,
    acceptNotModified?: false,
  ): Promise<T>;
  private request<T>(
    method: TransportRequest["method"],
    path: string,
    bearerToken: string | undefined,
    body: unknown,
    idempotencyKey: string | undefined,
    ifMatch: string | undefined,
    ifNoneMatch: string | undefined,
    acceptNotModified: true,
  ): Promise<T | undefined>;
  private async request<T>(
    method: TransportRequest["method"],
    path: string,
    bearerToken?: string,
    body?: unknown,
    idempotencyKey?: string,
    ifMatch?: string,
    ifNoneMatch?: string,
    acceptNotModified: boolean = false,
  ): Promise<T | undefined> {
    const headers: Record<string, string> = {};
    if (bearerToken !== undefined) {
      headers.authorization = `Bearer ${bearerToken}`;
    }
    if (idempotencyKey !== undefined) {
      headers["idempotency-key"] = idempotencyKey;
    }
    if (ifMatch !== undefined) {
      headers["if-match"] = `"${ifMatch}"`;
    }
    if (ifNoneMatch !== undefined) {
      headers["if-none-match"] = `"${ifNoneMatch}"`;
    }
    const response = await this.transport.request({
      method,
      url: new URL(path, this.baseUrl),
      headers,
      body,
    });
    if (response.status === 304 && acceptNotModified) {
      return undefined;
    }
    return this.responseBody<T>(response);
  }

  private responseBody<T>(response: TransportResponse): T {
    if (response.status < 200 || response.status >= 300) {
      const error = response.body as
        | {
            error?: {
              code?: string;
              message?: string;
              details?: Readonly<Record<string, string | number | boolean>>;
            };
          }
        | undefined;
      const retryAfter = response.headers["retry-after"];
      throw new HemligError(
        response.status,
        error?.error?.message ??
          `Hemlig request failed with status ${response.status}.`,
        error?.error?.code,
        error?.error?.details,
        retryAfter !== undefined && /^\d+$/.test(retryAfter.trim())
          ? Number(retryAfter.trim())
          : undefined,
      );
    }
    return response.body as T;
  }
}

/** Browser-safe transport built on the platform's global fetch implementation. */
export class FetchTransport implements HemligTransport {
  public constructor(
    private readonly fetchImplementation: typeof globalThis.fetch = globalThis.fetch,
  ) {}

  public async request(request: TransportRequest): Promise<TransportResponse> {
    const body =
      request.body === undefined ? undefined : JSON.stringify(request.body);
    const binary = request.responseType === "binary";
    const headers: Record<string, string> = {
      accept: binary
        ? "application/pkix-crl, application/json"
        : "application/json",
      ...request.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    const response = await this.fetchImplementation(request.url, {
      method: request.method,
      headers,
      body,
    });
    const raw = new Uint8Array(await response.arrayBuffer());
    const responseHeaders: Record<string, string | undefined> = {};
    response.headers.forEach((value, name) => {
      responseHeaders[name] = value;
    });
    const decoded = decodeTransportBody(
      response.status,
      responseHeaders,
      raw,
      request.responseType,
    );
    return { status: response.status, headers: responseHeaders, ...decoded };
  }
}

const withQuery = (
  path: string,
  query: Readonly<Record<string, string | undefined>>,
): string => {
  const pairs = Object.entries(query)
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
    );
  return pairs.length === 0 ? path : `${path}?${pairs.join("&")}`;
};

const pkiCaPath = (caId: string): string =>
  `/v1/admin/pki/cas/${encodeURIComponent(caId)}`;

const pkiGrantsPath = (consumerId: string): string =>
  `/v1/admin/pki/consumers/${encodeURIComponent(consumerId)}/issuance-grants`;

const pkiGrantPath = (consumerId: string, name: string): string =>
  `${pkiGrantsPath(consumerId)}/${encodeURIComponent(name)}`;

const unquoteEtag = (value: string | undefined): string | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim().replace(/^W\//, "");
  return trimmed.replace(/^"(.*)"$/, "$1");
};
