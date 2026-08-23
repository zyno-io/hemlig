import { randomUUID } from "node:crypto";
import * as https from "node:https";

export interface SecretEntry {
  readonly encoding: "utf8" | "base64";
  readonly value: string;
}

export type SecretPayload = Readonly<Record<string, SecretEntry>>;

export interface SecretMetadata {
  readonly name: string;
  readonly description?: string;
  readonly path?: string;
  readonly tags?: Readonly<Record<string, string>>;
}

export interface Grant {
  readonly clusterId: string;
  readonly permissions: readonly ["read"] | readonly "read"[];
}

export interface ControlRevision {
  readonly secretId: string;
  readonly environment: string;
  readonly controlVersionId: string;
  readonly payloadVersionId?: string;
  readonly state: "PENDING_VALUE" | "ACTIVE" | "REVOKED";
  readonly metadata: SecretMetadata;
  readonly acl?: readonly Grant[];
}

export interface ClusterSecretResponse {
  readonly secretId: string;
  readonly controlVersionId: string;
  readonly payloadVersionId: string;
  readonly payload: SecretPayload;
}

export interface TransportRequest {
  readonly method: "GET" | "POST" | "PUT";
  readonly url: URL;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface TransportResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body?: unknown;
}

export interface ClavisTransport {
  request(request: TransportRequest): Promise<TransportResponse>;
}

export class ClavisError extends Error {
  public constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

export class ClavisClient {
  public constructor(
    private readonly baseUrl: URL,
    private readonly transport: ClavisTransport,
  ) {}

  /**
   * Returns undefined for a conditional GET that received 304 Not Modified.
   */
  public async getClusterSecret(
    secretId: string,
    ifNoneMatch?: string,
  ): Promise<ClusterSecretResponse | undefined> {
    return this.request<ClusterSecretResponse>(
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

  public async getAdminSecret(
    token: string,
    secretId: string,
  ): Promise<ControlRevision> {
    return this.request("GET", `/v1/admin/secrets/${encodeURIComponent(secretId)}`, token);
  }

  public async createAdminSecret(
    token: string,
    input: {
      readonly secretId: string;
      readonly environment: string;
      readonly metadata: SecretMetadata;
      readonly acl: readonly Grant[];
    },
    idempotencyKey: string = randomUUID(),
  ): Promise<ControlRevision> {
    return this.request("POST", "/v1/admin/secrets", token, input, idempotencyKey);
  }

  public async updateAdminSecret(
    token: string,
    secretId: string,
    controlVersionId: string,
    input: Pick<ControlRevision, "metadata" | "acl">,
    idempotencyKey: string = randomUUID(),
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      `/v1/admin/secrets/${encodeURIComponent(secretId)}`,
      token,
      input,
      idempotencyKey,
      controlVersionId,
    );
  }

  public async putAdminPayload(
    token: string,
    secretId: string,
    controlVersionId: string,
    payload: SecretPayload,
    idempotencyKey: string = randomUUID(),
  ): Promise<ControlRevision> {
    return this.request(
      "PUT",
      `/v1/admin/secrets/${encodeURIComponent(secretId)}/payload`,
      token,
      { payload },
      idempotencyKey,
      controlVersionId,
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
    if (response.status < 200 || response.status >= 300) {
      const error = response.body as { error?: { code?: string; message?: string } } | undefined;
      throw new ClavisError(
        response.status,
        error?.error?.message ?? `Clavis request failed with status ${response.status}.`,
        error?.error?.code,
      );
    }
    return response.body as T;
  }
}

export class NodeHttpsTransport implements ClavisTransport {
  public constructor(private readonly options: https.AgentOptions = {}) {}

  public async request(request: TransportRequest): Promise<TransportResponse> {
    const body = request.body === undefined ? undefined : JSON.stringify(request.body);
    const headers: Record<string, string> = {
      accept: "application/json",
      ...request.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(Buffer.byteLength(body));
    }
    return new Promise((resolve, reject) => {
      const response = https.request(
        request.url,
        { method: request.method, headers, ...this.options },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
          incoming.on("error", reject);
          incoming.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let parsed: unknown;
            try {
              parsed = text.length === 0 ? undefined : JSON.parse(text);
            } catch {
              parsed = undefined;
            }
            const responseHeaders: Record<string, string | undefined> = {};
            for (const [name, value] of Object.entries(incoming.headers)) {
              responseHeaders[name] = Array.isArray(value) ? value.join(",") : value;
            }
            resolve({ status: incoming.statusCode ?? 500, headers: responseHeaders, body: parsed });
          });
        },
      );
      response.on("error", reject);
      if (body !== undefined) {
        response.write(body);
      }
      response.end();
    });
  }
}
