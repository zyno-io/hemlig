import type { RuntimeConfig } from "../config";
import { ApiError, errorFromResponse } from "./errors";
import * as s from "./schemas";
import * as p from "./pki-schemas";
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
  /** Overrides the default `application/json` accept header. */
  readonly accept?: string;
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

  /**
   * `q` (1-128 chars) matches case-insensitively against `secretId` and
   * `metadata.description` and composes with `pathPrefix`/`tags`. Its
   * presence changes the response shape: a search page is bounded-complete
   * (`truncated`, no `nextCursor`) rather than cursor-paginated, so callers
   * should not pass both `q` and `cursor` — see `CatalogPage`.
   */
  public listSecrets(input: {
    environment: string;
    pathPrefix?: string;
    tags?: string;
    q?: string;
    cursor?: string;
    archived?: boolean;
  }): Promise<s.CatalogPage> {
    return this.request(s.catalogPage, "/v1/admin/secrets", {
      query: {
        environment: input.environment,
        pathPrefix: input.pathPrefix,
        tags: input.tags,
        q: input.q,
        cursor: input.cursor,
        archived: input.archived ? "true" : undefined,
      },
    });
  }

  /**
   * One bounded, complete level of the path tree: folders directly under
   * `pathPrefix` plus secrets whose path equals it exactly (or, at the root,
   * secrets with no path at all). There is no cursor; a level that would not
   * fit comes back with `truncated: true` instead of a next page.
   */
  public getSecretsTree(input: {
    environment: string;
    pathPrefix?: string;
    archived?: boolean;
  }): Promise<s.SecretTreePage> {
    return this.request(s.secretTreePage, "/v1/admin/secrets/tree", {
      query: {
        environment: input.environment,
        pathPrefix: input.pathPrefix,
        archived: input.archived ? "true" : undefined,
      },
    });
  }

  public getSecret(
    environment: string,
    secretId: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/secrets/${encode(secretId)}`,
      { query: { environment } },
    );
  }

  /** Archived identities are addressed by UID because their old name is reusable. */
  public getArchivedSecret(
    environment: string,
    secretUid: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/archived-secrets/${encode(secretUid)}`,
      { query: { environment } },
    );
  }

  public getSecretPayload(
    environment: string,
    secretId: string,
  ): Promise<s.SecretReadResponse> {
    return this.request(
      s.secretReadResponse,
      `/v1/admin/secrets/${encode(secretId)}/payload`,
      { query: { environment } },
    );
  }

  public listRevisions(
    environment: string,
    secretId: string,
  ): Promise<s.SecretRevisionPage> {
    return this.request(
      s.secretRevisionPage,
      `/v1/admin/secrets/${encode(secretId)}/revisions`,
      { query: { environment } },
    );
  }

  public createSecret(
    input: {
      secretId: string;
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
    environment: string,
    secretId: string,
    controlVersionId: string,
    input: { metadata?: s.Metadata; acl?: readonly s.Grant[] },
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/secrets/${encode(secretId)}`,
      {
        method: "PUT",
        query: { environment },
        body: input,
        idempotencyKey,
        ifMatch: controlVersionId,
      },
    );
  }

  public archiveSecret(
    environment: string,
    secretId: string,
    controlVersionId: string,
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/secrets/${encode(secretId)}/archive`,
      {
        method: "POST",
        query: { environment },
        idempotencyKey,
        ifMatch: controlVersionId,
      },
    );
  }

  public putPayload(
    environment: string,
    secretId: string,
    controlVersionId: string,
    payload: Readonly<
      Record<string, { encoding: "utf8" | "base64"; value: string }>
    >,
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/secrets/${encode(secretId)}/payload`,
      {
        method: "PUT",
        query: { environment },
        body: { payload },
        idempotencyKey,
        ifMatch: controlVersionId,
      },
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
    return this.request(
      s.consumerDetail,
      `/v1/admin/consumers/${encode(consumerId)}`,
    );
  }

  public updateAgentGrant(
    grantId: string,
    input: {
      readonly capabilities: readonly ("read" | "write")[];
      readonly secretGrants: readonly {
        readonly secretId: string;
        readonly permissions: readonly ("read" | "write")[];
      }[];
      readonly displayName?: string;
    },
  ): Promise<s.AgentGrant> {
    return this.request(
      s.agentGrant,
      `/v1/admin/agent-grants/${encode(grantId)}`,
      { method: "PUT", body: input },
    );
  }

  public listConsumerSecretGrants(
    consumerId: string,
    cursor?: string,
  ): Promise<s.ConsumerSecretGrantPage> {
    return this.request(
      s.consumerSecretGrantPage,
      `/v1/admin/consumers/${encode(consumerId)}/grants`,
      { query: { cursor } },
    );
  }

  public revokeConsumerSecretGrant(
    consumerId: string,
    secretId: string,
    idempotencyKey: string,
  ): Promise<s.ControlRevision> {
    return this.request(
      s.controlRevision,
      `/v1/admin/consumers/${encode(consumerId)}/grants/${encode(secretId)}`,
      { method: "DELETE", idempotencyKey },
    );
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
      {
        method: "POST",
        body: { apiCertificateSigningRequestPem },
        idempotencyKey,
      },
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

  /**
   * Environments are administrator-defined records, bounded to 100, not a
   * deployment constant — a fresh deployment starts with none.
   */
  public listEnvironments(): Promise<s.EnvironmentListResponse> {
    return this.request(s.environmentListResponse, "/v1/admin/environments");
  }

  /**
   * Unlike every other admin mutation, this route takes no `Idempotency-Key`:
   * there is nothing here that needs replay-on-retry semantics, since a
   * reused name simply reports the conflict it already would. A duplicate
   * name fails an `attribute_not_exists` condition server-side and comes
   * back as a plain `conflict`, which callers should treat as "this name is
   * already taken" rather than as a failed mutation.
   */
  public createEnvironment(name: string): Promise<s.EnvironmentDefinition> {
    return this.request(s.environmentDefinition, "/v1/admin/environments", {
      method: "POST",
      body: { name },
    });
  }

  /**
   * Reads immutable application evidence through the dedicated archive-query
   * route. A cursor is bound to this administrator, one UTC date, and any
   * exact secret filter.
   */
  public listAudit(input: {
    date: string;
    environment?: string;
    secretId?: string;
    cursor?: string;
  }): Promise<s.AuditPage> {
    return this.request(s.auditPage, "/v1/admin/audit", {
      query: input,
    });
  }

  public getIssuer(): Promise<s.IssuerStatus> {
    return this.request(s.issuerStatus, "/v1/admin/issuer");
  }

  /**
   * Creates the issuing root if it is absent (201) or returns the existing
   * one (200) — safe to call as an explicit action instead of waiting for the
   * lazy creation an enrollment would otherwise trigger.
   */
  public createIssuer(idempotencyKey: string): Promise<s.IssuerStatus> {
    return this.request(s.issuerStatus, "/v1/admin/issuer", {
      method: "POST",
      idempotencyKey,
    });
  }

  // ------------------------------------------------------------- PKI
  //
  // Mirrors the client's PKI methods (names and arguments, minus the token).
  // Every PKI read is audited server-side: callers use `PKI_QUERY_OPTIONS`.
  // The console never sends `If-None-Match`: the deployed CORS policy does not
  // allow it.

  public listPkiCas(input: {
    environment: string;
    cursor?: string;
  }): Promise<p.PkiCaListPage> {
    return this.request(p.pkiCaListPage, "/v1/admin/pki/cas", {
      query: { environment: input.environment, cursor: input.cursor },
    });
  }

  public getPkiCa(caId: string): Promise<p.PkiCaDetail> {
    return this.request(p.pkiCaDetail, pkiCa(caId));
  }

  public createPkiCa(
    input: p.PkiCreateCaInput,
    idempotencyKey: string,
  ): Promise<p.PkiCreateCaResponse> {
    return this.request(p.pkiCreateCaResponse, "/v1/admin/pki/cas", {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  }

  public activatePkiCa(
    caId: string,
    input: p.PkiActivateCaInput,
    idempotencyKey: string,
  ): Promise<p.PkiCaDetail> {
    return this.request(p.pkiCaDetail, `${pkiCa(caId)}/certificate`, {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  }

  public retirePkiCa(caId: string, idempotencyKey: string): Promise<p.PkiCaDetail> {
    return this.request(p.pkiCaDetail, `${pkiCa(caId)}/retire`, {
      method: "POST",
      idempotencyKey,
    });
  }

  /** Abandons a `PENDING_CERTIFICATE` CA. */
  public deletePkiCa(
    caId: string,
    version: string,
    idempotencyKey: string,
  ): Promise<p.PkiCaDetail> {
    return this.request(p.pkiCaDetail, pkiCa(caId), {
      method: "DELETE",
      idempotencyKey,
      ifMatch: version,
    });
  }

  public destroyPkiCaKey(
    caId: string,
    idempotencyKey: string,
  ): Promise<p.PkiCaDetail> {
    return this.request(p.pkiCaDetail, `${pkiCa(caId)}/destroy-key`, {
      method: "POST",
      idempotencyKey,
    });
  }

  public publishPkiCrl(
    caId: string,
    idempotencyKey: string,
  ): Promise<p.PkiCrlPublishResponse> {
    return this.request(p.pkiCrlPublishResponse, `${pkiCa(caId)}/crl`, {
      method: "POST",
      idempotencyKey,
    });
  }

  /** The DER CRL of a CA or an external root, as exact bytes. */
  public async getAdminCrl(
    issuerId: string,
  ): Promise<{ bytes: Uint8Array; etag?: string }> {
    const response = await this.fetchResponse(
      `/v1/admin/pki/crls/${encode(issuerId)}`,
      { accept: "application/pkix-crl, application/json" },
    );
    const bytes = new Uint8Array(await response.arrayBuffer());
    const etag = response.headers.get("etag");
    return etag === null ? { bytes } : { bytes, etag };
  }

  public listExternalCas(
    input: { cursor?: string } = {},
  ): Promise<p.PkiExternalCaListPage> {
    return this.request(p.pkiExternalCaListPage, "/v1/admin/pki/external-cas", {
      query: { cursor: input.cursor },
    });
  }

  public uploadExternalCaCrl(
    extId: string,
    crl: string,
    idempotencyKey: string,
  ): Promise<p.PkiUploadCrlResponse> {
    return this.request(
      p.pkiUploadCrlResponse,
      `/v1/admin/pki/external-cas/${encode(extId)}/crl`,
      { method: "POST", body: { crl }, idempotencyKey },
    );
  }

  public listCaIssuanceGrants(
    caId: string,
    input: { cursor?: string } = {},
  ): Promise<p.PkiIssuanceGrantListPage> {
    return this.request(
      p.pkiIssuanceGrantListPage,
      `${pkiCa(caId)}/issuance-grants`,
      { query: { cursor: input.cursor } },
    );
  }

  public listAdminIssuanceGrants(
    consumerId: string,
    input: { includeDeleted?: boolean; cursor?: string } = {},
  ): Promise<p.PkiIssuanceGrantListPage> {
    return this.request(
      p.pkiIssuanceGrantListPage,
      pkiGrants(consumerId),
      {
        query: {
          includeDeleted: input.includeDeleted ? "true" : undefined,
          cursor: input.cursor,
        },
      },
    );
  }

  public getAdminIssuanceGrant(
    consumerId: string,
    name: string,
  ): Promise<p.PkiIssuanceGrant> {
    return this.request(p.pkiIssuanceGrant, pkiGrant(consumerId, name));
  }

  public createIssuanceGrant(
    consumerId: string,
    input: p.PkiCreateGrantInput,
    idempotencyKey: string,
  ): Promise<p.PkiIssuanceGrant> {
    return this.request(p.pkiIssuanceGrant, pkiGrants(consumerId), {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  }

  /** Writes nothing and takes no idempotency key. */
  public validateIssuanceGrantCreate(
    consumerId: string,
    input: p.PkiCreateGrantInput,
  ): Promise<p.PkiGrantValidationResult> {
    return this.request(p.pkiGrantValidationResult, pkiGrants(consumerId), {
      method: "POST",
      query: { validateOnly: "true" },
      body: input,
    });
  }

  /** A `PUT` replaces the whole grant. */
  public updateIssuanceGrant(
    consumerId: string,
    name: string,
    version: string,
    input: p.PkiGrantInput,
    idempotencyKey: string,
  ): Promise<p.PkiIssuanceGrant> {
    return this.request(p.pkiIssuanceGrant, pkiGrant(consumerId, name), {
      method: "PUT",
      body: input,
      idempotencyKey,
      ifMatch: version,
    });
  }

  /** `If-Match` is required here too, although nothing is written. */
  public validateIssuanceGrantUpdate(
    consumerId: string,
    name: string,
    version: string,
    input: p.PkiGrantInput,
  ): Promise<p.PkiGrantValidationResult> {
    return this.request(
      p.pkiGrantValidationResult,
      pkiGrant(consumerId, name),
      {
        method: "PUT",
        query: { validateOnly: "true" },
        body: input,
        ifMatch: version,
      },
    );
  }

  public deleteIssuanceGrant(
    consumerId: string,
    name: string,
    version: string,
    idempotencyKey: string,
  ): Promise<p.PkiIssuanceGrant> {
    return this.request(p.pkiIssuanceGrant, pkiGrant(consumerId, name), {
      method: "DELETE",
      idempotencyKey,
      ifMatch: version,
    });
  }

  /** Evaluates the stored grant; there is no route for a draft. */
  public evaluateIssuanceGrant(
    consumerId: string,
    name: string,
    input: p.PkiEvaluateInput,
  ): Promise<p.PkiEvaluateResponse> {
    return this.request(
      p.pkiEvaluateResponse,
      `${pkiGrant(consumerId, name)}/evaluate`,
      { method: "POST", body: input },
    );
  }

  public listPkiCertificates(
    caId: string,
    input: { status?: string; expiringBefore?: string; cursor?: string } = {},
  ): Promise<p.PkiCertificateListPage> {
    return this.request(
      p.pkiCertificateListPage,
      `${pkiCa(caId)}/certificates`,
      {
        query: {
          status: input.status,
          expiringBefore: input.expiringBefore,
          cursor: input.cursor,
        },
      },
    );
  }

  public getPkiCertificate(
    caId: string,
    serial: string,
  ): Promise<p.PkiCertificateDetail> {
    return this.request(
      p.pkiCertificateDetail,
      `${pkiCa(caId)}/certificates/${encode(serial)}`,
    );
  }

  public revokePkiCertificate(
    caId: string,
    serial: string,
    input: { reason?: p.PkiLeafRevocationReason; invalidityDate?: string },
    idempotencyKey: string,
  ): Promise<p.PkiRevokeCertificateResponse> {
    return this.request(
      p.pkiRevokeCertificateResponse,
      `${pkiCa(caId)}/certificates/${encode(serial)}/revoke`,
      { method: "POST", body: input, idempotencyKey },
    );
  }

  public listConsumerPkiCertificates(
    consumerId: string,
    input: {
      issuanceGrant?: string;
      includeExpired?: boolean;
      cursor?: string;
    } = {},
  ): Promise<p.PkiCertificateListPage> {
    return this.request(
      p.pkiCertificateListPage,
      `/v1/admin/pki/consumers/${encode(consumerId)}/certificates`,
      {
        query: {
          issuanceGrant: input.issuanceGrant,
          includeExpired: input.includeExpired ? "true" : undefined,
          cursor: input.cursor,
        },
      },
    );
  }

  public revokeConsumerPkiCertificates(
    consumerId: string,
    input: p.PkiBulkRevokeInput,
    idempotencyKey: string,
  ): Promise<p.PkiBulkRevokeResponse> {
    return this.request(
      p.pkiBulkRevokeResponse,
      `/v1/admin/pki/consumers/${encode(consumerId)}/certificates/revoke`,
      { method: "POST", body: input, idempotencyKey },
    );
  }

  private async request<T>(
    schema: ZodType<T>,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const response = await this.fetchResponse(path, options);
    return schema.parse(await response.json());
  }

  private async fetchResponse(
    path: string,
    options: RequestOptions = {},
  ): Promise<Response> {
    const url = new URL(path, this.config.adminApiUrl);
    for (const [name, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined && value.length > 0) {
        url.searchParams.set(name, value);
      }
    }
    const headers: Record<string, string> = {
      accept: options.accept ?? "application/json",
    };
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
        body:
          options.body === undefined ? undefined : JSON.stringify(options.body),
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
    return response;
  }
}

const encode = (value: string): string => encodeURIComponent(value);

const pkiCa = (caId: string): string => `/v1/admin/pki/cas/${encode(caId)}`;
const pkiGrants = (consumerId: string): string =>
  `/v1/admin/pki/consumers/${encode(consumerId)}/issuance-grants`;
const pkiGrant = (consumerId: string, name: string): string =>
  `${pkiGrants(consumerId)}/${encode(name)}`;
