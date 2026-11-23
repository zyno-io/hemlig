import { randomUUID } from "node:crypto";
import {
  ApiError,
  preconditionFailed,
  serviceUnavailable,
} from "../domain/errors";
import type { Actor } from "../domain/types";
import {
  pkiKeys,
  quotaRetryAfterSeconds,
  quotaWindows,
  type HumanIdempotencyWrite,
  type PkiRepository,
} from "../repositories/pki";
import { sha256Hex, stableJson } from "../util/encoding";
import {
  assertHumanReplay,
  assertRootPolicyUpdate,
  caDetail,
  caStatusReason,
  caSummary,
  ekuOidsToNames,
  parseActivateRequest,
  parseCreateCaRequest,
  parseUpdateCaRequest,
  replayOutcome,
  requestDigest,
  resolvePolicy,
  subjectDn,
  type CreateCaInput,
} from "./ca-model";
import { verifySignature } from "./asn1/algorithms";
import {
  assembleCertificate,
  generateSerial,
  parseCertificate,
  buildCaTbs,
  buildRootTbs,
} from "./asn1/certificate";
import { parseCrl, type ParsedCrl } from "./asn1/crl";
import { buildExternalIntermediateCsr, parseRawCsr } from "./asn1/csr";
import { canonicalSerialHex } from "./asn1/der";
import { fromPem, toPem } from "./asn1/pem";
import { keyIdentifierFromSpki } from "./asn1/extensions";
import { verifyActivationChain } from "./chain";
import { CapacityService } from "./capacity-service";
import {
  buildSignedCrl,
  crlObjectKey,
  CrlService,
  drainPoint,
  floorSeconds,
  publishInlineBestEffort,
  pkiObjectRead,
  type CrlIssuerMaterial,
} from "./crl-service";
import {
  decodeCrlInput,
  verifyRootCrl,
  type VerifiedRootCrl,
} from "./crl-verify";
import {
  caCapacityExceeded,
  caKeyUnavailable,
  caNotActive,
  caSubjectInUse,
  issuanceRateLimited,
  chainInvalid,
  crlInvalid,
  crlPublicationBusy,
  pkiConflict,
  pkiNotFound,
} from "./errors";
import {
  assertBuiltCaCertificate,
  assertParentCanIssue,
  deriveChildConstraints,
  childValidity,
  externalRootRecommended,
  parseRevokeCaRequest,
  rootValidity,
  ROOT_PATH_LEN,
} from "./hierarchy-model";
import { ADMIN_ISSUANCE_PER_HOUR } from "./issuance-model";
import { reasonOfQuotas } from "./issuance-service";
import { emitPkiMetrics, PKI_METRICS } from "./metrics";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import { pkcs8Signer, signWithPkcs8 } from "./signer";
import {
  buildCaSubject,
  matchesIdentityRoot,
  parseRestrictedName,
  type IdentityRootReference,
  type RestrictedName,
} from "./subject";
import type {
  CaCrlState,
  CaRecord,
  CaStatus,
  ExternalCaRecord,
  IssuedCertificateRecord,
  RevocationReason,
} from "./types";
import { generateCaKeyPair, wrapCaKey } from "./wrapped-keys";

const maxActivationReruns = 3;
const cursorLifetimeMs = 15 * 60 * 1000;

const ed25519Warning = {
  code: "ed25519_compatibility",
  message:
    "Ed25519 CA keys are not accepted by every TLS client and verifier. Prefer ECDSA_P256 unless you have verified compatibility.",
};

const statusReason = caStatusReason;

const mapLimit = async <T>(
  items: readonly T[],
  limit: number,
  work: (item: T) => Promise<void>,
): Promise<void> => {
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let index = next++; index < items.length; index = next++) {
      await work(items[index] as T);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
};

const parentWindow = (
  parent: CaRecord,
): { notBefore: string; notAfter: string } => ({
  notBefore: parent.notBefore ?? "",
  notAfter: parent.notAfter ?? "",
});

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const versionId = (): string => `pkv-${randomUUID()}`;

/** Normalizes an `If-Match`-style value. */
export const stripEtag = (value: string): string =>
  value.replace(/^W\//, "").replace(/^"(.*)"$/, "$1");

export type CaDetailResponse = {
  readonly body: Record<string, unknown>;
  readonly etag: string;
};

/** Carries a replayed result out of the fail-fast checks. */
class ReplayRequested extends Error {
  public constructor(public readonly result: MutationResult) {
    super("replay");
  }
}

export class CaService {
  private readonly emit: typeof emitPkiMetrics;
  private readonly capacity: CapacityService;

  public constructor(
    private readonly deps: PkiServiceDeps,
    private readonly crls: CrlService,
  ) {
    this.emit = deps.emit ?? emitPkiMetrics;
    this.capacity = new CapacityService(deps.pki);
  }

  private get pki(): PkiRepository {
    return this.deps.pki;
  }

  private now(): Date {
    return this.deps.now();
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Shared helpers
  // -----------------------------------------------------------------------------------------------------------------

  private idempotency(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
    result: Record<string, unknown>,
  ): HumanIdempotencyWrite {
    return {
      actor,
      idempotencyKey: key,
      operationType,
      requestDigest: digest,
      result,
      now: this.now().toISOString(),
    };
  }

  /** The stored record for a retried request, or undefined. A different operation under the same key is a 409. */
  private async prior(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
  ): Promise<Record<string, unknown> | undefined> {
    const stored = await this.deps.repository.getIdempotency(actor, key);
    if (stored === undefined) {
      return undefined;
    }
    assertHumanReplay(stored, operationType, digest);
    return stored;
  }

  private async load(caId: string): Promise<CaRecord> {
    const ca = await this.pki.getCa(caId);
    if (ca === undefined) {
      throw pkiNotFound("ca_not_found");
    }
    return ca;
  }

  private async externalOf(
    ca: CaRecord,
  ): Promise<ExternalCaRecord | undefined> {
    return ca.parent?.type === "external"
      ? this.pki.getExternalCa(ca.parent.id)
      : undefined;
  }

  private auditTarget(ca: CaRecord): Record<string, string> {
    return {
      caId: ca.caId,
      environment: ca.environment,
      name: ca.name,
      kind: ca.kind,
      keyAlgorithm: ca.key.algorithm,
      version: ca.version,
    };
  }

  /** The current resource, as every success and replay response. */
  private async detail(
    caId: string,
    warningsOf?: (
      ca: CaRecord,
    ) => { code: string; message: string }[] | undefined,
  ): Promise<{ ca: CaRecord; body: Record<string, unknown> }> {
    const ca = await this.load(caId);
    const warnings = warningsOf?.(ca);
    const crl =
      ca.status === "PENDING_CERTIFICATE" || ca.status === "FAILED"
        ? undefined
        : await this.pki.getCaCrlState(caId);
    const external = await this.externalOf(ca);
    return {
      ca,
      body: caDetail(ca, {
        ...(crl === undefined ? {} : { crl }),
        ...(external === undefined ? {} : { external }),
        now: this.now(),
        ...(warnings === undefined ? {} : { warnings }),
      }),
    };
  }

  private async replayResult(
    stored: Record<string, unknown>,
    status: number,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const caId = outcome.result.caId;
    if (typeof caId !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    const { ca, body } = await this.detail(caId, (loaded) =>
      this.warningsFor(loaded, status === 201),
    );
    return {
      body,
      status,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget:
        status === 201 ? this.createTarget(ca) : this.auditTarget(ca),
      etag: ca.version,
    };
  }

  private warningsFor(
    ca: Pick<CaRecord, "kind"> & { key: Pick<CaRecord["key"], "algorithm"> },
    created: boolean,
  ): { code: string; message: string }[] | undefined {
    if (!created) {
      return undefined;
    }
    const warnings = [
      ...(ca.key.algorithm === "ED25519" ? [ed25519Warning] : []),
      ...(ca.kind === "ROOT" ? [externalRootRecommended] : []),
    ];
    return warnings.length === 0 ? undefined : warnings;
  }

  /** `pki.ca.create` target: the CA, plus the certificate and anchor of a Hemlig CA. */
  private createTarget(ca: CaRecord): Record<string, string> {
    if (ca.kind === "EXTERNAL_INTERMEDIATE" || ca.fingerprint === undefined) {
      return this.auditTarget(ca);
    }
    const anchorFingerprint =
      ca.kind === "ROOT"
        ? ca.fingerprint
        : parseCertificate(
            fromPem(
              (ca.chainPem ?? "").match(
                /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
              )?.[0] ?? "",
              "CERTIFICATE",
            ),
          ).fingerprint;
    return {
      ...this.auditTarget(ca),
      ...(ca.parentCaId === undefined ? {} : { parentCaId: ca.parentCaId }),
      fingerprint: ca.fingerprint,
      serial: ca.serial ?? "",
      anchorFingerprint,
    };
  }

  private async replayAfterCancel(
    actor: Actor,
    key: string,
    operationType: string,
    digest: string,
    status: number,
  ): Promise<MutationResult> {
    const stored = await this.prior(actor, key, operationType, digest);
    if (stored === undefined) {
      throw serviceUnavailable("The change could not be confirmed.");
    }
    return this.replayResult(stored, status);
  }

  private success(
    ca: CaRecord,
    body: Record<string, unknown>,
    status = 200,
  ): MutationResult {
    return {
      body,
      status,
      shouldWriteTerminalAudit: true,
      auditTarget: this.auditTarget(ca),
      etag: ca.version,
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Reads
  // -----------------------------------------------------------------------------------------------------------------

  public async get(caId: string): Promise<CaDetailResponse> {
    const { ca, body } = await this.detail(caId);
    return { body, etag: ca.version };
  }

  public async list(
    actor: Actor,
    environment: string,
    rawCursor: string | undefined,
  ): Promise<Record<string, unknown>> {
    await this.deps.repository.requireEnvironment(environment);
    const scope = `admin:pki:cas:${actor.id}:${sha256Hex(stableJson({ environment }))}`;
    const decoded =
      rawCursor === undefined
        ? undefined
        : await this.deps.cursors.decode(rawCursor, scope, this.now());
    const page = await this.pki.listCasPage({
      environment,
      limit: 100,
      ...(decoded?.lastEvaluatedKey === undefined
        ? {}
        : { start: decoded.lastEvaluatedKey }),
    });
    const nextCursor =
      page.lastEvaluatedKey === undefined
        ? undefined
        : await this.deps.cursors.encode({
            scope,
            lastEvaluatedKey: page.lastEvaluatedKey as Record<string, string>,
            expiresAt: new Date(
              this.now().getTime() + cursorLifetimeMs,
            ).toISOString(),
          });
    return {
      cas: page.cas.map(caSummary),
      ...(nextCursor === undefined ? {} : { nextCursor }),
      generatedAt: this.now().toISOString(),
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Create
  // -----------------------------------------------------------------------------------------------------------------

  private async identityReference(): Promise<IdentityRootReference> {
    const issuer = await this.deps.repository.getIssuer();
    if (issuer === undefined) {
      return {};
    }
    // `IssuerRecord` carries no subject or SPKI fields: derive them from the stored root certificate.
    const root = parseCertificate(
      fromPem(issuer.rootCertificatePem, "CERTIFICATE"),
    );
    let subjectKey: string | undefined;
    try {
      subjectKey = parseRestrictedName(root.subjectDer, "external").key;
    } catch {
      subjectKey = undefined;
    }
    return {
      ...(subjectKey === undefined ? {} : { subjectKey }),
      spkiSha256: root.spkiSha256,
      fingerprint: root.fingerprint,
    };
  }

  public async create(
    actor: Actor,
    key: string,
    body: unknown,
  ): Promise<MutationResult> {
    const input = parseCreateCaRequest(body);
    const digest = requestDigest("pki.ca.create", input);
    const stored = await this.prior(actor, key, "pki.ca.create", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 201);
    }
    await this.deps.repository.requireEnvironment(input.environment);
    const subject = buildCaSubject(input.subject);
    // Layer 6: a Hemlig CA never takes the identity root's subject.
    const identity = await this.identityReference();
    if (
      matchesIdentityRoot(
        { subjectKey: subject.key },
        this.deps.config.environmentName,
        identity,
      )
    ) {
      throw caSubjectInUse("identity_root_reserved");
    }
    // Fail fast; the transaction's claims are authoritative.
    // An identical request that committed since the first check owns these claims: replay it, don't conflict.
    const claimed = async (error: ApiError): Promise<never> => {
      const winner = await this.prior(actor, key, "pki.ca.create", digest);
      if (winner !== undefined) {
        throw new ReplayRequested(await this.replayResult(winner, 201));
      }
      throw error;
    };
    try {
      if (
        (await this.pki.getCaNameClaim(input.environment, input.name)) !==
        undefined
      ) {
        await claimed(pkiConflict("name_in_use"));
      }
      if ((await this.pki.getSubjectClaim(subject.key)) !== undefined) {
        await claimed(caSubjectInUse("subject_claimed"));
      }
    } catch (error) {
      if (error instanceof ReplayRequested) {
        return error.result;
      }
      throw error;
    }
    // The GSI lags, so the limit is best effort.
    const existing = await this.pki.queryDirectory("PKI_CAS", {
      sortPrefix: `${input.environment}#`,
    });
    if (existing.filter((item) => item.status !== "FAILED").length >= 50) {
      throw pkiConflict("ca_limit_reached");
    }
    if (input.kind === "ROOT") {
      return this.createRoot(actor, key, digest, input, subject);
    }
    if (input.kind === "INTERMEDIATE") {
      return this.createIntermediate(actor, key, digest, input, subject);
    }

    const caId = `ca-${randomUUID()}`;
    const generated = await generateCaKeyPair(input.keyAlgorithm);
    let csrDer: Buffer;
    let wrapped;
    try {
      // The CSR is signed in process with the plaintext key: KMS is not involved until the key is wrapped.
      csrDer = await buildExternalIntermediateCsr({
        subjectDer: subject.der,
        spkiDer: generated.spkiDer,
        keyAlgorithm: input.keyAlgorithm,
        ...(input.requested.nameConstraints === undefined
          ? {}
          : { nameConstraints: input.requested.nameConstraints }),
        ...(input.requested.extendedKeyUsages === undefined
          ? {}
          : { extendedKeyUsage: input.requested.extendedKeyUsages }),
        sign: async (info) =>
          signWithPkcs8(input.keyAlgorithm, generated.privateKeyDer, info),
      });
      const raw = parseRawCsr(csrDer);
      if (
        !verifySignature(
          raw.spkiDer,
          raw.signatureAlgorithm,
          raw.infoDer,
          raw.signature,
        )
      ) {
        throw serviceUnavailable("The generated CSR failed verification.");
      }
      wrapped = await wrapCaKey(
        this.deps.kms,
        this.deps.config.payloadKmsKeyArn,
        generated.privateKeyDer,
        { caId, environment: input.environment },
      );
    } finally {
      generated.privateKeyDer.fill(0);
    }

    const createdAt = this.now().toISOString();
    const ca: CaRecord = {
      caId,
      environment: input.environment,
      name: input.name,
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
      kind: input.kind,
      status: "PENDING_CERTIFICATE",
      version: versionId(),
      crlIssuers: [],
      key: {
        custody: "WRAPPED",
        algorithm: input.keyAlgorithm,
        spkiSha256: generated.spkiSha256,
        state: "ACTIVE",
        wrapped,
      },
      subject: input.subject,
      subjectKey: subject.key,
      requested: input.requested,
      csrPem: toPem(csrDer, "CERTIFICATE REQUEST"),
      policy: input.policy,
      maxIssueLifetimeEverSeconds: input.policy.maxLeafLifetimeSeconds,
      createdAt,
      createdBy: actor,
    };
    const outcome = await this.pki.createCa({
      idempotency: this.idempotency(actor, key, "pki.ca.create", digest, {
        caId,
      }),
      ca,
    });
    switch (outcome.kind) {
      case "replay":
        return this.replayAfterCancel(actor, key, "pki.ca.create", digest, 201);
      case "nameInUse":
        throw pkiConflict("name_in_use");
      case "subjectInUse":
        throw caSubjectInUse("subject_claimed");
      case "created":
        break;
    }
    const { body: view } = await this.detail(caId, () =>
      this.warningsFor(ca, true),
    );
    return this.success(ca, view, 201);
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Hemlig ROOT and INTERMEDIATE
  // -----------------------------------------------------------------------------------------------------------------

  /** The CA's first, empty CRL: number 1, signed with the plaintext key before it is wrapped. */
  private crlStateOf(published: {
    number: number;
    objectKey: string;
    sha256: string;
    thisUpdate: Date;
    nextUpdate: Date;
  }): CaCrlState {
    return {
      revision: 0,
      lastNumber: 1,
      published: {
        number: published.number,
        objectKey: published.objectKey,
        sha256: published.sha256,
        thisUpdate: published.thisUpdate.toISOString(),
        nextUpdate: published.nextUpdate.toISOString(),
        revision: 0,
        entryCount: 0,
      },
      sweptThrough: published.thisUpdate.toISOString(),
    };
  }

  private async createRoot(
    actor: Actor,
    key: string,
    digest: string,
    input: Extract<CreateCaInput, { kind: "ROOT" }>,
    subject: RestrictedName,
  ): Promise<MutationResult> {
    const now = this.now();
    const caId = `ca-${randomUUID()}`;
    const validity = rootValidity(input.validitySeconds, now);
    const generated = await generateCaKeyPair(input.keyAlgorithm);
    let certificateDer: Buffer;
    let parsed;
    let crl: { der: Buffer; sha256: string };
    let wrapped;
    const thisUpdate = floorSeconds(now);
    const nextUpdate = new Date(
      thisUpdate.getTime() + input.policy.crlValiditySeconds * 1000,
    );
    try {
      // The root signs itself and its CRL with the plaintext key in process: KMS sees the key only once, to wrap it.
      const signer = pkcs8Signer(input.keyAlgorithm, generated.privateKeyDer);
      const built = buildRootTbs({
        algorithm: input.keyAlgorithm,
        serial: generateSerial(),
        notBefore: validity.notBefore,
        notAfter: validity.notAfter,
        subjectDer: subject.der,
        spkiDer: generated.spkiDer,
        pathLen: ROOT_PATH_LEN,
        ...(input.requested.nameConstraints === undefined
          ? {}
          : { nameConstraints: input.requested.nameConstraints }),
        ...(input.requested.extendedKeyUsages === undefined
          ? {}
          : { extendedKeyUsage: input.requested.extendedKeyUsages }),
      });
      certificateDer = assembleCertificate(
        built.tbs,
        built.signatureAlgorithm,
        await signer.sign(built.tbs),
      );
      parsed = assertBuiltCaCertificate(certificateDer, built, {
        issuerSpkiDer: generated.spkiDer,
        pathLen: ROOT_PATH_LEN,
      });
      crl = await buildSignedCrl(
        {
          subjectDer: subject.der.toString("base64"),
          subjectKeyIdentifier: hex(
            parsed.subjectKeyIdentifier ?? Buffer.alloc(0),
          ),
          spkiDer: generated.spkiDer,
        },
        signer,
        { number: 1, thisUpdate, nextUpdate, entries: [] },
      );
      wrapped = await wrapCaKey(
        this.deps.kms,
        this.deps.config.payloadKmsKeyArn,
        generated.privateKeyDer,
        { caId, environment: input.environment },
      );
    } finally {
      generated.privateKeyDer.fill(0);
    }
    const objectKey = crlObjectKey(caId, "1", crl.sha256);
    await this.deps.objects.putImmutableOrGet(
      this.deps.config.pkiBucketName,
      objectKey,
      crl.der,
      "application/pkix-crl",
    );

    const createdAt = now.toISOString();
    const certificatePem = toPem(certificateDer, "CERTIFICATE");
    const ca: CaRecord = {
      caId,
      environment: input.environment,
      name: input.name,
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
      kind: "ROOT",
      status: "ACTIVE",
      version: versionId(),
      crlIssuers: [{ type: "ca", id: caId }],
      key: {
        custody: "WRAPPED",
        algorithm: input.keyAlgorithm,
        spkiSha256: generated.spkiSha256,
        state: "ACTIVE",
        wrapped,
      },
      subject: input.subject,
      subjectKey: subject.key,
      requested: input.requested,
      certificatePem,
      chainPem: certificatePem,
      serial: canonicalSerialHex(parsed.serialHex),
      fingerprint: parsed.fingerprint,
      subjectDer: subject.der.toString("base64"),
      subjectKeyIdentifier: hex(parsed.subjectKeyIdentifier ?? Buffer.alloc(0)),
      notBefore: parsed.notBefore.toISOString(),
      notAfter: parsed.notAfter.toISOString(),
      effective: {
        ...(input.requested.nameConstraints === undefined
          ? {}
          : { nameConstraints: input.requested.nameConstraints }),
        ...(input.requested.extendedKeyUsages === undefined
          ? {}
          : { extendedKeyUsages: input.requested.extendedKeyUsages }),
      },
      policy: input.policy,
      maxIssueLifetimeEverSeconds: 0,
      createdAt,
      createdBy: actor,
      activatedAt: createdAt,
    };
    const outcome = await this.pki.createCa({
      idempotency: this.idempotency(actor, key, "pki.ca.create", digest, {
        caId,
      }),
      ca,
      crl: this.crlStateOf({
        number: 1,
        objectKey,
        sha256: crl.sha256,
        thisUpdate,
        nextUpdate,
      }),
    });
    switch (outcome.kind) {
      case "replay":
        return this.replayAfterCancel(actor, key, "pki.ca.create", digest, 201);
      case "nameInUse":
        throw pkiConflict("name_in_use");
      case "subjectInUse":
        throw caSubjectInUse("subject_claimed");
      case "created":
        break;
    }
    const { body: view } = await this.detail(caId, () =>
      this.warningsFor(ca, true),
    );
    return {
      ...this.success(ca, view, 201),
      auditTarget: this.createTarget(ca),
    };
  }

  private async createIntermediate(
    actor: Actor,
    key: string,
    digest: string,
    input: Extract<CreateCaInput, { kind: "INTERMEDIATE" }>,
    subject: RestrictedName,
  ): Promise<MutationResult> {
    const replayed = async (): Promise<MutationResult | undefined> => {
      const winner = await this.prior(actor, key, "pki.ca.create", digest);
      return winner === undefined ? undefined : this.replayResult(winner, 201);
    };
    let parent = assertParentCanIssue(
      await this.pki.getCa(input.parentCaId),
      input.environment,
      this.now(),
    );
    let effective = deriveChildConstraints(parent.effective, input.requested);
    childValidity(parentWindow(parent), input.validitySeconds, this.now());

    // Pre-check, as an administrator issuance does: the child counts against the parent's capacity and quotas.
    {
      const now = this.now();
      const windows = quotaWindows(now);
      const adminKey = pkiKeys.adminQuota(parent.caId, windows.hourSk);
      const caKey = pkiKeys.caQuota(parent.caId, windows.hourSk);
      const [count, adminCount, caCount] = await Promise.all([
        this.pki
          .getCaCrlState(parent.caId)
          .then((crl) => this.capacity.current(parent, crl, now)),
        this.pki.getQuotaCount(adminKey),
        this.pki.getQuotaCount(caKey),
      ]);
      const failing: ("adminHour" | "caHour")[] = [
        ...(adminCount >= ADMIN_ISSUANCE_PER_HOUR
          ? (["adminHour"] as const)
          : []),
        ...(caCount >= parent.policy.issuancePerHour
          ? (["caHour"] as const)
          : []),
      ];
      const refusal =
        count >= parent.policy.capacity
          ? caCapacityExceeded()
          : failing.length > 0
            ? issuanceRateLimited(
                reasonOfQuotas(failing),
                quotaRetryAfterSeconds(failing, now),
              )
            : undefined;
      if (refusal !== undefined) {
        const winner = await replayed();
        if (winner !== undefined) {
          return winner;
        }
        throw refusal;
      }
    }

    // The child's key, CRL #1 and wrapped envelope are made once and kept across parent-changed reruns.
    const caId = `ca-${randomUUID()}`;
    const generated = await generateCaKeyPair(input.keyAlgorithm);
    const crlNow = this.now();
    const thisUpdate = floorSeconds(crlNow);
    const nextUpdate = new Date(
      thisUpdate.getTime() + input.policy.crlValiditySeconds * 1000,
    );
    let crl: { der: Buffer; sha256: string };
    let wrapped;
    try {
      crl = await buildSignedCrl(
        {
          subjectDer: subject.der.toString("base64"),
          subjectKeyIdentifier: hex(keyIdentifierFromSpki(generated.spkiDer)),
          spkiDer: generated.spkiDer,
        },
        pkcs8Signer(input.keyAlgorithm, generated.privateKeyDer),
        { number: 1, thisUpdate, nextUpdate, entries: [] },
      );
      wrapped = await wrapCaKey(
        this.deps.kms,
        this.deps.config.payloadKmsKeyArn,
        generated.privateKeyDer,
        { caId, environment: input.environment },
      );
    } finally {
      generated.privateKeyDer.fill(0);
    }
    const objectKey = crlObjectKey(caId, "1", crl.sha256);
    await this.deps.objects.putImmutableOrGet(
      this.deps.config.pkiBucketName,
      objectKey,
      crl.der,
      "application/pkix-crl",
    );
    const crlState = this.crlStateOf({
      number: 1,
      objectKey,
      sha256: crl.sha256,
      thisUpdate,
      nextUpdate,
    });

    for (let attempt = 0; attempt < maxActivationReruns; attempt += 1) {
      if (attempt > 0) {
        const winner = await replayed();
        if (winner !== undefined) {
          return winner;
        }
        parent = assertParentCanIssue(
          await this.pki.getCa(input.parentCaId),
          input.environment,
          this.now(),
        );
        effective = deriveChildConstraints(parent.effective, input.requested);
      }
      const now = this.now();
      const validity = childValidity(
        parentWindow(parent),
        input.validitySeconds,
        now,
      );
      const parentCert = parseCertificate(
        fromPem(parent.certificatePem ?? "", "CERTIFICATE"),
      );
      let rerun = false;
      for (let serialAttempt = 0; serialAttempt < 3; serialAttempt += 1) {
        const built = buildCaTbs({
          issuer: parentCert,
          serial: generateSerial(),
          notBefore: validity.notBefore,
          notAfter: validity.notAfter,
          subjectDer: subject.der,
          spkiDer: generated.spkiDer,
          pathLen: 0,
          ...(effective.nameConstraints === undefined
            ? {}
            : { nameConstraints: effective.nameConstraints }),
          ...(effective.extendedKeyUsages === undefined
            ? {}
            : { extendedKeyUsage: effective.extendedKeyUsages }),
        });
        let signature: Uint8Array;
        try {
          signature = await this.deps.signerFor(parent).sign(built.tbs);
        } catch (error) {
          if (error instanceof ApiError) {
            if (error.code === "ca_key_unavailable") {
              this.emit(this.deps.config.environmentName, {
                [PKI_METRICS.caKeyUnavailable]: 1,
              });
            } else if (error.safeReason === "kms_access_denied") {
              this.emit(this.deps.config.environmentName, {
                [PKI_METRICS.kmsAccessDenied]: 1,
              });
            }
          }
          throw error;
        }
        const certificateDer = assembleCertificate(
          built.tbs,
          built.signatureAlgorithm,
          signature,
        );
        const parsed = assertBuiltCaCertificate(certificateDer, built, {
          issuerSpkiDer: parentCert.spkiDer,
          pathLen: 0,
        });
        const createdAt = now.toISOString();
        const certificatePem = toPem(certificateDer, "CERTIFICATE");
        const serialHex = canonicalSerialHex(parsed.serialHex);
        const ca: CaRecord = {
          caId,
          environment: input.environment,
          name: input.name,
          ...(input.displayName === undefined
            ? {}
            : { displayName: input.displayName }),
          kind: "INTERMEDIATE",
          status: "ACTIVE",
          version: versionId(),
          parent: { type: "ca", id: parent.caId },
          parentCaId: parent.caId,
          crlIssuers: [
            { type: "ca", id: caId },
            { type: "ca", id: parent.caId },
          ],
          key: {
            custody: "WRAPPED",
            algorithm: input.keyAlgorithm,
            spkiSha256: generated.spkiSha256,
            state: "ACTIVE",
            wrapped,
          },
          subject: input.subject,
          subjectKey: subject.key,
          requested: input.requested,
          certificatePem,
          chainPem: `${(parent.certificatePem ?? "").trim()}\n`,
          serial: serialHex,
          fingerprint: parsed.fingerprint,
          subjectDer: subject.der.toString("base64"),
          subjectKeyIdentifier: hex(
            parsed.subjectKeyIdentifier ?? Buffer.alloc(0),
          ),
          notBefore: parsed.notBefore.toISOString(),
          notAfter: parsed.notAfter.toISOString(),
          effective: {
            ...(effective.nameConstraints === undefined
              ? {}
              : { nameConstraints: effective.nameConstraints }),
            ...(effective.extendedKeyUsages === undefined
              ? {}
              : { extendedKeyUsages: effective.extendedKeyUsages }),
          },
          policy: input.policy,
          maxIssueLifetimeEverSeconds: input.policy.maxLeafLifetimeSeconds,
          createdAt,
          createdBy: actor,
          activatedAt: createdAt,
        };
        const row: IssuedCertificateRecord = {
          caId: parent.caId,
          environment: input.environment,
          serial: serialHex,
          status: "ISSUED",
          certificatePem,
          fingerprint: parsed.fingerprint,
          spkiSha256: generated.spkiSha256,
          subject: subjectDn(subject.attributes),
          sans: { dns: [], ip: [], uri: [] },
          keyAlgorithm: input.keyAlgorithm,
          keyUsages: ["keyCertSign", "cRLSign"],
          extendedKeyUsages: ekuOidsToNames(effective.extendedKeyUsages ?? []),
          isCa: true,
          childCaId: caId,
          lifetimeClamped: validity.clamped,
          notBefore: ca.notBefore ?? createdAt,
          notAfter: ca.notAfter ?? createdAt,
          issuedAt: createdAt,
          requester: { type: "human", id: actor.id },
        };
        const outcome = await this.pki.createIntermediateCa({
          idempotency: this.idempotency(actor, key, "pki.ca.create", digest, {
            caId,
          }),
          ca,
          crl: crlState,
          certificate: row,
          parent: {
            caId: parent.caId,
            version: parent.version,
            issuancePerHour: parent.policy.issuancePerHour,
            loadedMaxIssueLifetimeEverSeconds:
              parent.maxIssueLifetimeEverSeconds,
            childLifetimeSeconds: Math.ceil(validity.lifetimeSeconds),
          },
          now,
          adminPerHour: ADMIN_ISSUANCE_PER_HOUR,
        });
        switch (outcome.kind) {
          case "created": {
            const { body: view } = await this.detail(caId, () =>
              this.warningsFor(ca, true),
            );
            return {
              ...this.success(ca, view, 201),
              auditTarget: this.createTarget(ca),
            };
          }
          case "replay":
            return this.replayAfterCancel(
              actor,
              key,
              "pki.ca.create",
              digest,
              201,
            );
          case "nameInUse":
            throw pkiConflict("name_in_use");
          case "subjectInUse":
            throw caSubjectInUse("subject_claimed");
          case "quotaExhausted": {
            const winner = await replayed();
            if (winner !== undefined) {
              return winner;
            }
            throw issuanceRateLimited(
              reasonOfQuotas(outcome.quotas),
              outcome.retryAfterSeconds,
            );
          }
          case "serialCollision":
            continue;
          case "parentChanged":
            rerun = true;
            break;
        }
        break;
      }
      if (!rerun) {
        break;
      }
    }
    throw serviceUnavailable("The CA could not be created.");
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Activate
  // -----------------------------------------------------------------------------------------------------------------

  public async activate(
    actor: Actor,
    key: string,
    caId: string,
    body: unknown,
  ): Promise<MutationResult> {
    const input = parseActivateRequest(body);
    const digest = requestDigest("pki.ca.activate", {
      caId,
      certificatePemSha256: sha256Hex(input.certificatePem),
      chainPemSha256: sha256Hex(input.chainPem),
      rootCrlSha256:
        input.rootCrl === undefined ? null : sha256Hex(input.rootCrl),
      acceptBroaderConstraints: input.acceptBroaderConstraints,
    });
    let profileReruns = 0;
    for (let attempt = 0; attempt < maxActivationReruns; attempt += 1) {
      const stored = await this.prior(actor, key, "pki.ca.activate", digest);
      if (stored !== undefined) {
        return this.replayResult(stored, 200);
      }
      const ca = await this.load(caId);
      if (ca.status !== "PENDING_CERTIFICATE") {
        throw pkiConflict("ca_not_pending");
      }
      const caSpki = parseRawCsr(
        fromPem(ca.csrPem ?? "", "CERTIFICATE REQUEST"),
      ).spkiDer;
      if (sha256Hex(caSpki) !== ca.key.spkiSha256) {
        throw serviceUnavailable("The CA record is inconsistent.");
      }
      const now = this.now();
      const identity = await this.identityReference();
      const chain = verifyActivationChain({
        certificatePem: input.certificatePem,
        chainPem: input.chainPem,
        now,
        caSpkiDer: caSpki,
        requestedSubjectKey: ca.subjectKey,
        requested: ca.requested,
        acceptBroaderConstraints: input.acceptBroaderConstraints,
        deploymentName: this.deps.config.environmentName,
        identity,
      });
      const { certificate, root } = chain;
      const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
      const ext = await this.pki.getExternalCa(extId);

      // Check 7: the root CRL.
      let seeded: VerifiedRootCrl | undefined;
      let inForce: ParsedCrl | undefined;
      if (ext !== undefined) {
        if (
          chain.rootSubject.key !== ext.subjectKey ||
          hex(root.subjectKeyIdentifier ?? Buffer.alloc(0)) !==
            ext.subjectKeyIdentifier
        ) {
          throw chainInvalid("external_ca_mismatch");
        }
        if (
          input.rootCrl !== undefined &&
          (ext.crl === undefined ||
            sha256Hex(decodeCrlInput(input.rootCrl)) !== ext.crl.sha256)
        ) {
          throw crlInvalid("upload_first");
        }
        if (ext.crl !== undefined) {
          const bytes = await pkiObjectRead(
            this.deps.objects,
            this.deps.config.pkiBucketName,
            ext.crl.objectKey,
          );
          if (sha256Hex(bytes) !== ext.crl.sha256) {
            throw serviceUnavailable(
              "The stored root CRL failed its integrity check.",
            );
          }
          inForce = parseCrl(bytes);
        }
      } else if (input.rootCrl !== undefined) {
        seeded = verifyRootCrl({ crl: input.rootCrl, issuer: root, now });
        inForce = seeded.parsed;
      }
      const serial = canonicalSerialHex(certificate.serialHex);
      if (
        inForce?.entries.some(
          (entry) => canonicalSerialHex(entry.serialHex) === serial,
        ) === true
      ) {
        throw caNotActive("revoked_by_parent");
      }

      // The initial CRL: number 1, empty, signed through KMS.
      const thisUpdate = floorSeconds(now);
      const nextUpdate = new Date(
        thisUpdate.getTime() + ca.policy.crlValiditySeconds * 1000,
      );
      const issuer: CrlIssuerMaterial = {
        subjectDer: certificate.subjectDer.toString("base64"),
        subjectKeyIdentifier: hex(
          certificate.subjectKeyIdentifier ?? Buffer.alloc(0),
        ),
        spkiDer: certificate.spkiDer,
      };
      const built = await buildSignedCrl(
        issuer,
        this.deps.signerFor(ca),
        { number: 1, thisUpdate, nextUpdate, entries: [] },
        (error) => {
          if (error.code === "ca_key_unavailable") {
            this.emit(this.deps.config.environmentName, {
              [PKI_METRICS.caKeyUnavailable]: 1,
            });
          } else if (error.safeReason === "kms_access_denied") {
            this.emit(this.deps.config.environmentName, {
              [PKI_METRICS.kmsAccessDenied]: 1,
            });
          }
        },
      );
      const objectKey = crlObjectKey(caId, "1", built.sha256);
      await this.deps.objects.putImmutableOrGet(
        this.deps.config.pkiBucketName,
        objectKey,
        built.der,
        "application/pkix-crl",
      );
      let seededPointer: NonNullable<ExternalCaRecord["crl"]> | undefined;
      if (seeded !== undefined) {
        const rootObjectKey = crlObjectKey(
          extId,
          seeded.numberHex,
          seeded.sha256,
        );
        await this.deps.objects.putImmutableOrGet(
          this.deps.config.pkiBucketName,
          rootObjectKey,
          seeded.der,
          "application/pkix-crl",
        );
        seededPointer = {
          numberHex: seeded.numberHex,
          thisUpdate: seeded.thisUpdate.toISOString(),
          nextUpdate: seeded.nextUpdate.toISOString(),
          sha256: seeded.sha256,
          objectKey: rootObjectKey,
          uploadedAt: now.toISOString(),
          uploadedBy: actor,
        };
      }

      const nowIso = now.toISOString();
      const effective = chain.effective;
      const fields: Record<string, unknown> = {
        certificatePem: toPem(certificate.der, "CERTIFICATE"),
        chainPem: toPem(root.der, "CERTIFICATE"),
        serial,
        fingerprint: certificate.fingerprint,
        subjectDer: certificate.subjectDer.toString("base64"),
        subjectKeyIdentifier: issuer.subjectKeyIdentifier,
        notBefore: certificate.notBefore.toISOString(),
        notAfter: certificate.notAfter.toISOString(),
        parent: { type: "external", id: extId },
        crlIssuers: [
          { type: "ca", id: caId },
          { type: "external", id: extId },
        ],
        effective,
        activatedAt: nowIso,
        ...(chain.broaderThanRequested
          ? { acceptBroaderConstraints: true }
          : {}),
      };
      const crlState: CaCrlState = {
        revision: 0,
        lastNumber: 1,
        published: {
          number: 1,
          objectKey,
          sha256: built.sha256,
          thisUpdate: thisUpdate.toISOString(),
          nextUpdate: nextUpdate.toISOString(),
          revision: 0,
          entryCount: 0,
        },
        sweptThrough: thisUpdate.toISOString(),
      };
      const newVersion = versionId();
      const outcome = await this.pki.activateCa({
        idempotency: this.idempotency(actor, key, "pki.ca.activate", digest, {
          caId,
        }),
        caId,
        loadedVersion: ca.version,
        newVersion,
        fields,
        crl: crlState,
        external:
          ext === undefined
            ? {
                kind: "create",
                record: {
                  extId,
                  certificatePem: toPem(root.der, "CERTIFICATE"),
                  fingerprint: root.fingerprint,
                  spkiSha256: root.spkiSha256,
                  subjectDer: root.subjectDer.toString("base64"),
                  subjectAttributes: [...chain.rootSubject.attributes],
                  subjectKey: chain.rootSubject.key,
                  subjectKeyIdentifier: hex(
                    root.subjectKeyIdentifier ?? Buffer.alloc(0),
                  ),
                  notAfter: root.notAfter.toISOString(),
                  createdAt: nowIso,
                  dependents: new Set([caId]),
                  environments: new Set([ca.environment]),
                  version: versionId(),
                  ...(seededPointer === undefined
                    ? {}
                    : { crl: seededPointer }),
                },
              }
            : {
                kind: "update",
                extId,
                loadedVersion: ext.version,
                newVersion: versionId(),
                caId,
                environment: ca.environment,
              },
        rootSubject: {
          key: chain.rootSubject.key,
          extId,
          spkiSha256: root.spkiSha256,
          now: nowIso,
        },
      });
      switch (outcome.kind) {
        case "replay":
          return this.replayAfterCancel(
            actor,
            key,
            "pki.ca.activate",
            digest,
            200,
          );
        case "rootSubjectInUse":
          throw caSubjectInUse("root_subject_claimed");
        case "externalChanged":
          continue;
        case "profileChanged": {
          const fresh = await this.pki.getCa(caId);
          if (
            fresh?.status === "PENDING_CERTIFICATE" &&
            fresh.version !== ca.version &&
            profileReruns < 1
          ) {
            profileReruns += 1;
            continue;
          }
          throw pkiConflict("ca_not_pending");
        }
        case "activated": {
          const { ca: activated, body: view } = await this.detail(caId);
          return {
            ...this.success(activated, view),
            auditTarget: {
              ...this.auditTarget(activated),
              fingerprint: certificate.fingerprint,
              anchorFingerprint: root.fingerprint,
              extId,
            },
          };
        }
      }
    }
    throw serviceUnavailable("The CA could not be activated.");
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Update, abandon, retire, destroy-key, publish
  // -----------------------------------------------------------------------------------------------------------------

  private async assertIfMatch(
    caId: string,
    ifMatch: string,
  ): Promise<CaRecord> {
    const ca = await this.load(caId);
    if (ca.version !== ifMatch) {
      throw preconditionFailed("The CA was changed; reload it and retry.");
    }
    return ca;
  }

  public async update(
    actor: Actor,
    key: string,
    caId: string,
    ifMatch: string,
    body: unknown,
  ): Promise<MutationResult> {
    const input = parseUpdateCaRequest(body);
    const digest = requestDigest("pki.ca.update", {
      caId,
      ifMatch,
      // Omitted, null and every string hash differently: an absent field leaves the key out.
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
      policy: input.policy,
    });
    const stored = await this.prior(actor, key, "pki.ca.update", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 200);
    }
    const ca = await this.assertIfMatch(caId, ifMatch);
    if (ca.status !== "PENDING_CERTIFICATE" && ca.status !== "ACTIVE") {
      throw caNotActive(statusReason[ca.status]);
    }
    if (ca.kind === "ROOT") {
      assertRootPolicyUpdate(input.policy, ca.policy);
    }
    const policy = resolvePolicy(input.policy, ca.policy);
    const outcome = await this.pki.updateCaPolicy({
      idempotency: this.idempotency(actor, key, "pki.ca.update", digest, {
        caId,
      }),
      caId,
      loadedVersion: ifMatch,
      newVersion: versionId(),
      now: this.now().toISOString(),
      policy,
      // A ROOT's value is raised only by child creation: a PUT that carried it would race every new child.
      ...(ca.kind === "ROOT"
        ? {}
        : {
            maxIssueLifetimeEverSeconds: Math.max(
              ca.maxIssueLifetimeEverSeconds,
              policy.maxLeafLifetimeSeconds,
            ),
          }),
      ...(input.displayName === undefined
        ? {}
        : { displayName: input.displayName }),
    });
    if (outcome.kind === "replay") {
      return this.replayAfterCancel(actor, key, "pki.ca.update", digest, 200);
    }
    if (outcome.kind === "conditionFailed") {
      const fresh = await this.load(caId);
      if (fresh.version !== ifMatch) {
        throw preconditionFailed("The CA was changed; reload it and retry.");
      }
      throw caNotActive(statusReason[fresh.status]);
    }
    const { ca: updated, body: view } = await this.detail(caId);
    return this.success(updated, view);
  }

  public async abandon(
    actor: Actor,
    key: string,
    caId: string,
    ifMatch: string,
  ): Promise<MutationResult> {
    const digest = requestDigest("pki.ca.delete", { caId, ifMatch });
    const stored = await this.prior(actor, key, "pki.ca.delete", digest);
    if (stored !== undefined) {
      return this.replayResult(stored, 200);
    }
    const ca = await this.assertIfMatch(caId, ifMatch);
    if (ca.status !== "PENDING_CERTIFICATE") {
      throw pkiConflict("ca_not_pending");
    }
    const outcome = await this.pki.abandonCa({
      idempotency: this.idempotency(actor, key, "pki.ca.delete", digest, {
        caId,
      }),
      caId,
      loadedVersion: ifMatch,
      newVersion: versionId(),
      now: this.now().toISOString(),
    });
    if (outcome.kind === "replay") {
      return this.replayAfterCancel(actor, key, "pki.ca.delete", digest, 200);
    }
    if (outcome.kind === "conditionFailed") {
      const fresh = await this.load(caId);
      if (fresh.version !== ifMatch) {
        throw preconditionFailed("The CA was changed; reload it and retry.");
      }
      throw pkiConflict("ca_not_pending");
    }
    const { ca: abandoned, body: view } = await this.detail(caId);
    return this.success(abandoned, view);
  }

  public async retire(
    actor: Actor,
    key: string,
    caId: string,
  ): Promise<MutationResult> {
    const digest = requestDigest("pki.ca.retire", { caId });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const stored = await this.prior(actor, key, "pki.ca.retire", digest);
      if (stored !== undefined) {
        return this.replayResult(stored, 200);
      }
      const ca = await this.load(caId);
      if (ca.status !== "ACTIVE") {
        throw caNotActive(statusReason[ca.status]);
      }
      const outcome = await this.pki.retireCa({
        idempotency: this.idempotency(actor, key, "pki.ca.retire", digest, {
          caId,
        }),
        caId,
        loadedVersion: ca.version,
        newVersion: versionId(),
        now: this.now().toISOString(),
      });
      if (outcome.kind === "replay") {
        return this.replayAfterCancel(actor, key, "pki.ca.retire", digest, 200);
      }
      if (outcome.kind === "conditionFailed") {
        const fresh = await this.load(caId);
        if (fresh.status === "ACTIVE" && attempt === 0) {
          continue;
        }
        throw caNotActive(statusReason[fresh.status]);
      }
      const warnings = (await this.pki.hasGrantsForCa(caId))
        ? [
            {
              code: "issuance_grants_reference_ca",
              message:
                "Issuance grants reference this CA and will stop issuing.",
            },
          ]
        : undefined;
      const { ca: retired, body: view } = await this.detail(
        caId,
        () => warnings,
      );
      return {
        ...this.success(retired, view),
        auditTarget: {
          ...this.auditTarget(retired),
          reason: "manual",
        },
      };
    }
    throw serviceUnavailable("The CA could not be retired.");
  }

  public async destroyKey(
    actor: Actor,
    key: string,
    caId: string,
  ): Promise<MutationResult> {
    const digest = requestDigest("pki.ca.destroy-key", { caId });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const stored = await this.prior(actor, key, "pki.ca.destroy-key", digest);
      if (stored !== undefined) {
        return this.replayResult(stored, 200);
      }
      const ca = await this.load(caId);
      if (ca.key.state === "ACTIVE") {
        throw pkiConflict("key_not_disabled");
      }
      if (ca.key.state === "DESTROYED") {
        throw pkiConflict("key_destroyed");
      }
      const outcome = await this.pki.destroyKey({
        idempotency: this.idempotency(
          actor,
          key,
          "pki.ca.destroy-key",
          digest,
          {
            caId,
          },
        ),
        caId,
        loadedVersion: ca.version,
        newVersion: versionId(),
        now: this.now().toISOString(),
      });
      if (outcome.kind === "replay") {
        return this.replayAfterCancel(
          actor,
          key,
          "pki.ca.destroy-key",
          digest,
          200,
        );
      }
      if (outcome.kind === "conditionFailed") {
        const fresh = await this.load(caId);
        if (fresh.key.state === "DISABLED" && attempt === 0) {
          continue;
        }
        throw pkiConflict(
          fresh.key.state === "ACTIVE" ? "key_not_disabled" : "key_destroyed",
        );
      }
      const { ca: destroyed, body: view } = await this.detail(caId);
      return this.success(destroyed, view);
    }
    throw serviceUnavailable("The CA key could not be destroyed.");
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Revoke a Hemlig CA
  // -----------------------------------------------------------------------------------------------------------------

  private revokeResult(
    ca: CaRecord,
    view: Record<string, unknown>,
    flags: {
      changed: boolean;
      crlEntry: boolean;
      crlPublished: boolean;
      crlNumber?: number;
      revokedCaIds: string[];
      complete: boolean;
    },
    terminalAudit: boolean,
  ): MutationResult {
    return {
      body: {
        ca: view,
        changed: flags.changed,
        crlEntry: flags.crlEntry,
        crlPublished: flags.crlPublished,
        ...(flags.crlNumber === undefined
          ? {}
          : { crlNumber: flags.crlNumber }),
        revokedCaIds: flags.revokedCaIds,
        complete: flags.complete,
      },
      status: 200,
      shouldWriteTerminalAudit: terminalAudit,
      auditTarget: {
        ...this.auditTarget(ca),
        reason: ca.revocationReason ?? "unspecified",
        changed: String(flags.changed),
        crlEntry: String(flags.crlEntry),
        crlPublished: String(flags.crlPublished),
        ...(flags.crlNumber === undefined
          ? {}
          : { crlNumber: String(flags.crlNumber) }),
        ...(ca.parentCaId === undefined ? {} : { parentCaId: ca.parentCaId }),
        revokedCaIds: flags.revokedCaIds.join(","),
        complete: String(flags.complete),
      },
      etag: ca.version,
    };
  }

  public async revoke(
    actor: Actor,
    key: string,
    caId: string,
    body: unknown,
  ): Promise<MutationResult> {
    const { raw, reason, invalidityDate } = parseRevokeCaRequest(
      body,
      this.now(),
    );
    const digest = requestDigest("pki.ca.revoke", { caId, body: raw });
    const stored = await this.prior(actor, key, "pki.ca.revoke", digest);
    if (stored !== undefined) {
      return this.revokeReplay(stored);
    }
    for (let attempt = 0; attempt < maxActivationReruns; attempt += 1) {
      const ca = await this.load(caId);
      if (ca.kind === "EXTERNAL_INTERMEDIATE") {
        throw pkiConflict("revoke_at_root");
      }
      const result =
        ca.kind === "ROOT"
          ? await this.revokeRoot(actor, key, digest, ca, reason)
          : await this.revokeIntermediate(
              actor,
              key,
              digest,
              ca,
              reason,
              invalidityDate,
            );
      if (result !== "rerun") {
        return result;
      }
    }
    throw serviceUnavailable("The CA could not be revoked.");
  }

  /** Records only the idempotency key; `true` when a concurrent identical request already did. */
  private async revokeNoop(
    actor: Actor,
    key: string,
    digest: string,
    result: Record<string, unknown>,
  ): Promise<boolean> {
    return (
      (await this.pki.putHumanIdempotency(
        this.idempotency(actor, key, "pki.ca.revoke", digest, result),
      )) === "replay"
    );
  }

  private async revokeReplayAfterCancel(
    actor: Actor,
    key: string,
    digest: string,
  ): Promise<MutationResult> {
    const again = await this.prior(actor, key, "pki.ca.revoke", digest);
    if (again === undefined) {
      throw serviceUnavailable("The change could not be confirmed.");
    }
    return this.revokeReplay(again);
  }

  private async revokeIntermediate(
    actor: Actor,
    key: string,
    digest: string,
    ca: CaRecord,
    reason: RevocationReason,
    invalidityDate: string | undefined,
  ): Promise<MutationResult | "rerun"> {
    const parentCaId = ca.parentCaId;
    if (parentCaId === undefined || ca.serial === undefined) {
      throw serviceUnavailable("The CA record is inconsistent.");
    }
    if (ca.status === "REVOKED") {
      const crlEntry =
        (await this.pki.getRevocationEntry(parentCaId, ca.serial)) !==
        undefined;
      if (
        await this.revokeNoop(actor, key, digest, {
          caId: ca.caId,
          changed: false,
          crlEntry,
        })
      ) {
        return this.revokeReplayAfterCancel(actor, key, digest);
      }
      return this.revokeResponse(ca.caId, {
        changed: false,
        crlEntry,
        terminalAudit: true,
      });
    }
    const parent = await this.pki.getCa(parentCaId);
    if (parent === undefined) {
      throw serviceUnavailable("The parent CA record is unavailable.");
    }
    const row = await this.pki.getCertificate(parentCaId, ca.serial);
    const now = this.now();
    let mode: "entry" | "expired" | "inventory" | undefined;
    if (row?.status === "ISSUED") {
      mode =
        parent.status === "REVOKED"
          ? "inventory"
          : Date.parse(row.notAfter) <= now.getTime()
            ? "expired"
            : "entry";
    }
    const crlEntry = mode === "entry";
    const outcome = await this.pki.revokeIntermediateCa({
      idempotency: this.idempotency(actor, key, "pki.ca.revoke", digest, {
        caId: ca.caId,
        changed: true,
        crlEntry,
      }),
      ca,
      newVersion: versionId(),
      now: now.toISOString(),
      reason,
      ...(invalidityDate === undefined ? {} : { invalidityDate }),
      by: actor,
      evidence: `parent:${parentCaId}`,
      ...(mode === undefined || row === undefined
        ? {}
        : { row: { mode, notAfter: row.notAfter } }),
    });
    if (outcome.kind === "canceled") {
      if (outcome.failed.includes("idempotency")) {
        return this.revokeReplayAfterCancel(actor, key, digest);
      }
      // The child, the parent's row or the parent's CRL moved: read again and redo the decision.
      return "rerun";
    }
    const published = crlEntry
      ? await publishInlineBestEffort(this.crls, parent, this.now())
      : { crlPublished: false };
    return this.revokeResponse(ca.caId, {
      changed: true,
      crlEntry,
      crlPublished: published.crlPublished,
      ...(published.crlNumber === undefined
        ? {}
        : { crlNumber: published.crlNumber }),
      terminalAudit: true,
    });
  }

  private async revokeRoot(
    actor: Actor,
    key: string,
    digest: string,
    ca: CaRecord,
    reason: RevocationReason,
  ): Promise<MutationResult | "rerun"> {
    let changed = false;
    if (ca.status === "REVOKED") {
      if (
        await this.revokeNoop(actor, key, digest, {
          caId: ca.caId,
          changed: false,
        })
      ) {
        return this.revokeReplayAfterCancel(actor, key, digest);
      }
    } else {
      const outcome = await this.pki.distrustRootCa({
        idempotency: this.idempotency(actor, key, "pki.ca.revoke", digest, {
          caId: ca.caId,
          changed: true,
        }),
        ca,
        newVersion: versionId(),
        now: this.now().toISOString(),
        reason,
        evidence: "local-distrust",
      });
      if (outcome.kind === "replay") {
        return this.revokeReplayAfterCancel(actor, key, digest);
      }
      if (outcome.kind === "conditionFailed") {
        return "rerun";
      }
      changed = true;
    }
    return this.revokeResponse(ca.caId, { changed, terminalAudit: true });
  }

  /** The 200 body from current state. A ROOT re-runs the walk, so a retry finishes what a failed one missed. */
  private async revokeResponse(
    caId: string,
    flags: {
      changed: boolean;
      crlEntry?: boolean;
      crlPublished?: boolean;
      crlNumber?: number;
      terminalAudit: boolean;
    },
  ): Promise<MutationResult> {
    const loaded = await this.load(caId);
    let revokedCaIds: string[] = [];
    let complete = true;
    if (loaded.kind === "ROOT") {
      const walk = await this.revokeChildrenOf(loaded);
      revokedCaIds = walk.revokedCaIds;
      complete = walk.remaining.length === 0;
    } else if (flags.changed) {
      revokedCaIds = [caId];
    }
    const { ca, body: view } = await this.detail(caId);
    let crlPublished = flags.crlPublished ?? false;
    let crlNumber = flags.crlNumber;
    if (
      flags.crlPublished === undefined &&
      flags.crlEntry === true &&
      ca.parentCaId !== undefined &&
      ca.revokedAt !== undefined
    ) {
      const parentCrl = await this.pki.getCaCrlState(ca.parentCaId);
      if (
        parentCrl?.published !== undefined &&
        parentCrl.published.thisUpdate >= ca.revokedAt
      ) {
        crlPublished = true;
        crlNumber = parentCrl.published.number;
      }
    }
    return this.revokeResult(
      ca,
      view,
      {
        changed: flags.changed,
        crlEntry: flags.crlEntry ?? false,
        crlPublished,
        ...(crlNumber === undefined ? {} : { crlNumber }),
        revokedCaIds,
        complete,
      },
      flags.terminalAudit,
    );
  }

  private async revokeReplay(
    stored: Record<string, unknown>,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const caId = outcome.result.caId;
    if (typeof caId !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    const response = await this.revokeResponse(caId, {
      changed: outcome.result.changed === true,
      crlEntry: outcome.result.crlEntry === true,
      terminalAudit: outcome.shouldWriteTerminalAudit,
    });
    return response;
  }

  /**
   * Flips each child of a REVOKED ROOT. Best effort: the ancestor checks at issuance are the security boundary, and the
   * maintenance pass finishes whatever this walk misses.
   */
  public async revokeChildrenOf(
    root: CaRecord,
  ): Promise<{ revokedCaIds: string[]; remaining: string[] }> {
    let childIds: string[];
    try {
      const items = await this.pki.queryDirectory("PKI_CAS", {
        sortPrefix: `${root.environment}#`,
      });
      childIds = items
        .filter((item) => item.parentCaId === root.caId)
        .map((item) => String(item.caId));
    } catch {
      return { revokedCaIds: [], remaining: ["<unknown>"] };
    }
    const revokedCaIds: string[] = [];
    const remaining: string[] = [];
    const settle = async (id: string): Promise<void> => {
      let child = await this.pki.getCa(id);
      if (child === undefined || child.parentCaId !== root.caId) {
        return;
      }
      if (child.status === "ACTIVE" || child.status === "RETIRED") {
        try {
          await this.revokeForRevokedAncestor(child, root);
        } catch {
          // Classified from the reread below.
        }
        child = await this.pki.getCa(id).catch(() => undefined);
      }
      if (child?.status === "REVOKED") {
        revokedCaIds.push(id);
      } else if (child?.status === "ACTIVE" || child?.status === "RETIRED") {
        remaining.push(id);
      }
    };
    await mapLimit(childIds, 8, settle);
    return { revokedCaIds: revokedCaIds.sort(), remaining: remaining.sort() };
  }

  /** The system flip of a child under a REVOKED ancestor; undefined when the child changed meanwhile. */
  public async revokeForRevokedAncestor(
    child: CaRecord,
    ancestor: CaRecord,
  ): Promise<CaRecord | undefined> {
    if (ancestor.status !== "REVOKED") {
      throw new Error("The ancestor is not revoked.");
    }
    return this.pki.revokeForRevokedAncestor(
      child,
      {
        revokedAt: this.now().toISOString(),
        reason: ancestor.revocationReason ?? "unspecified",
        evidence: `ancestor:${ancestor.caId}`,
      },
      ancestor.caId,
    );
  }

  public async forcePublish(
    actor: Actor,
    key: string,
    caId: string,
  ): Promise<MutationResult> {
    const digest = requestDigest("pki.crl.publish", { caId });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const stored = await this.prior(actor, key, "pki.crl.publish", digest);
      if (stored !== undefined) {
        return this.publishReplay(stored);
      }
      const ca = await this.load(caId);
      if (ca.status !== "ACTIVE" && ca.status !== "RETIRED") {
        throw caNotActive(statusReason[ca.status]);
      }
      if (ca.key.state !== "ACTIVE") {
        throw caKeyUnavailable();
      }
      const result = await this.crls.publish(ca, {
        trigger: "force",
        idempotency: this.idempotency(actor, key, "pki.crl.publish", digest, {
          caId,
        }),
        waitForLeaseMs: 5000,
      });
      switch (result.kind) {
        case "busy":
        case "deadline":
          throw crlPublicationBusy();
        case "superseded":
          if (attempt === 0) {
            continue;
          }
          throw crlPublicationBusy();
        case "replay": {
          const again = await this.prior(actor, key, "pki.crl.publish", digest);
          if (again === undefined) {
            throw serviceUnavailable("The change could not be confirmed.");
          }
          return this.publishReplay(again);
        }
        case "published": {
          const body = await this.publishBody(caId);
          return {
            body,
            status: 200,
            shouldWriteTerminalAudit: true,
            auditTarget: {
              caId,
              environment: ca.environment,
              crlNumber: String(result.pointer.number),
              entryCount: String(result.pointer.entryCount),
              trigger: "force",
            },
          };
        }
      }
    }
    throw crlPublicationBusy();
  }

  private async publishBody(caId: string): Promise<Record<string, unknown>> {
    const { body } = await this.detail(caId);
    return { caId, crl: body.crl };
  }

  private async publishReplay(
    stored: Record<string, unknown>,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const caId = outcome.result.caId;
    if (typeof caId !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    const ca = await this.load(caId);
    return {
      body: await this.publishBody(caId),
      status: 200,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget: {
        caId,
        environment: ca.environment,
        trigger: "force",
      },
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // System operations for maintenance
  // -----------------------------------------------------------------------------------------------------------------

  /** Retires an ACTIVE CA past its `notAfter`. Returns the updated record, or undefined when it changed meanwhile. */
  public retireExpired(ca: CaRecord): Promise<CaRecord | undefined> {
    return this.pki.retireExpiredCa(ca, this.now());
  }

  /** Disables the key of a drained retired CA. */
  public disableDrainedKey(ca: CaRecord, crl: CaCrlState): Promise<boolean> {
    return this.pki.disableDrainedKey(ca, crl, drainPoint(ca), this.now());
  }
}
