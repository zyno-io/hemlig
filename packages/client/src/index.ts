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

export interface TransportRequest {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly url: URL;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface TransportResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body?: unknown;
}

export interface HemligTransport {
  request(request: TransportRequest): Promise<TransportResponse>;
}

export class HemligError extends Error {
  public constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
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
    input: Pick<ControlRevision, "metadata" | "acl">,
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
        { error?: { code?: string; message?: string } } | undefined;
      throw new HemligError(
        response.status,
        error?.error?.message ??
          `Hemlig request failed with status ${response.status}.`,
        error?.error?.code,
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
    const headers: Record<string, string> = {
      accept: "application/json",
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
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text.length === 0 ? undefined : JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    const responseHeaders: Record<string, string | undefined> = {};
    response.headers.forEach((value, name) => {
      responseHeaders[name] = value;
    });
    return { status: response.status, headers: responseHeaders, body: parsed };
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
