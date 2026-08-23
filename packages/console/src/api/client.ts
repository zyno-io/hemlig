import type { RuntimeConfig } from "../config";
import { ApiError, errorFromResponse } from "./errors";
import * as s from "./schemas";
import type { ZodType } from "zod";

export interface TokenSource {
  /** Returns undefined in dev-bridge mode, where no bearer token exists. */
  accessToken(): Promise<string | undefined>;
  /** Sent only in dev-bridge mode so the local handler can resolve an actor. */
  devSubject?: string;
}

interface RequestOptions {
  readonly method?: "GET" | "POST" | "PUT" | "DELETE";
  readonly query?: Readonly<Record<string, string | undefined>>;
  readonly body?: unknown;
  readonly idempotencyKey?: string;
  readonly ifMatch?: string;
}

export class HemligApi {
  private readonly fetchImpl: typeof fetch;

  public constructor(
    private readonly config: RuntimeConfig,
    private readonly tokens: TokenSource,
    fetchImpl?: typeof fetch,
  ) {
    // `window.fetch` throws "Illegal invocation" if it is called with any
    // receiver other than the window, which is exactly what happens when it is
    // held as an instance property and invoked as `this.fetchImpl(...)`.
    this.fetchImpl = fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  public listSecrets(input: {
    environment: string;
    pathPrefix?: string;
    tags?: string;
    cursor?: string;
  }): Promise<s.CatalogPage> {
    return this.request(s.catalogPage, "/v1/admin/secrets", {
      query: {
        environment: input.environment,
        pathPrefix: input.pathPrefix,
        tags: input.tags,
        cursor: input.cursor,
      },
    });
  }

  public getSecret(secretId: string): Promise<s.ControlRevision> {
    return this.request(s.controlRevision, `/v1/admin/secrets/${encode(secretId)}`);
  }

  public listRevisions(secretId: string): Promise<s.SecretRevisionPage> {
    return this.request(
      s.secretRevisionPage,
      `/v1/admin/secrets/${encode(secretId)}/revisions`,
    );
  }

  public createSecret(
    input: {
      secretId?: string;
      environment: string;
      metadata: s.Metadata;
      acl: readonly s.Grant[];
    },
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(s.controlRevision, "/v1/admin/secrets", {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  }

  public updateSecret(
    secretId: string,
    controlVersionId: string,
    input: { metadata?: s.Metadata; acl?: readonly s.Grant[] },
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(s.controlRevision, `/v1/admin/secrets/${encode(secretId)}`, {
      method: "PUT",
      body: input,
      idempotencyKey,
      ifMatch: controlVersionId,
    });
  }

  public putPayload(
    secretId: string,
    controlVersionId: string,
    payload: Readonly<Record<string, { encoding: "utf8" | "base64"; value: string }>>,
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/secrets/${encode(secretId)}/payload`,
      { method: "PUT", body: { payload }, idempotencyKey, ifMatch: controlVersionId },
    );
  }

  public listConsumers(input: {
    environment: string;
    cursor?: string;
  }): Promise<s.ConsumerListPage> {
    return this.request(s.consumerListPage, "/v1/admin/consumers", {
      query: { environment: input.environment, cursor: input.cursor },
    });
  }

  public getConsumer(consumerId: string): Promise<s.ConsumerDetail> {
    return this.request(s.consumerDetail, `/v1/admin/consumers/${encode(consumerId)}`);
  }

  public listApiIdentities(
    consumerId: string,
    cursor?: string,
  ): Promise<s.ApiIdentityListPage> {
    return this.request(
      s.apiIdentityListPage,
      `/v1/admin/consumers/${encode(consumerId)}/api-identities`,
      { query: { cursor } },
    );
  }

  public enrollConsumer(
    input: {
      consumerId: string;
      environment: string;
      apiCertificateSigningRequestPem: string;
    },
    idempotencyKey: string,
  ): Promise<s.EnrollmentResult> {
    return this.request(s.enrollmentResult, "/v1/admin/consumers", {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  }

  public rotateApiIdentity(
    consumerId: string,
    apiCertificateSigningRequestPem: string,
    idempotencyKey: string,
  ): Promise<s.ApiIdentityResult> {
    return this.request(
      s.apiIdentityResult,
      `/v1/admin/consumers/${encode(consumerId)}/api-identities`,
      { method: "POST", body: { apiCertificateSigningRequestPem }, idempotencyKey },
    );
  }

  public revokeApiIdentity(
    consumerId: string,
    apiFingerprint: string,
    idempotencyKey: string,
  ): Promise<s.ApiIdentityResult> {
    return this.request(
      s.apiIdentityResult,
      `/v1/admin/consumers/${encode(consumerId)}/api-identities/${encode(apiFingerprint)}`,
      { method: "DELETE", idempotencyKey },
    );
  }

  public getIssuer(): Promise<s.IssuerStatus> {
    return this.request(s.issuerStatus, "/v1/admin/issuer");
  }

  private async request<T>(
    schema: ZodType<T>,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const url = new URL(path, this.config.adminApiUrl);
    for (const [name, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined && value.length > 0) {
        url.searchParams.set(name, value);
      }
    }
    const headers: Record<string, string> = { accept: "application/json" };
    const token = await this.tokens.accessToken();
    if (token !== undefined) {
      headers.authorization = `Bearer ${token}`;
    }
    if (this.tokens.devSubject !== undefined) {
      headers["x-hemlig-dev-subject"] = this.tokens.devSubject;
    }
    if (options.idempotencyKey !== undefined) {
      headers["idempotency-key"] = options.idempotencyKey;
    }
    if (options.ifMatch !== undefined) {
      headers["if-match"] = `"${options.ifMatch}"`;
    }
    if (options.body !== undefined) {
      headers["content-type"] = "application/json";
    }

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: options.method ?? "GET",
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        cache: "no-store",
        credentials: "omit",
        mode: "cors",
      });
    } catch (cause) {
      // A transport failure on a mutation is an unknown outcome, not a failure.
      // The cause is carried through: without it a CORS rejection, a DNS
      // failure, and a refused connection are indistinguishable to whoever has
      // to fix the deployment.
      throw new ApiError(
        0,
        "network",
        "The request did not reach Hemlig.",
        undefined,
        cause,
      );
    }
    if (!response.ok) {
      throw await errorFromResponse(response);
    }
    return schema.parse(await response.json());
  }
}

const encode = (value: string): string => encodeURIComponent(value);
