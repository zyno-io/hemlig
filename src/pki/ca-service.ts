import { randomUUID } from "node:crypto";
import { preconditionFailed, serviceUnavailable } from "../domain/errors";
import type { Actor } from "../domain/types";
import type { HumanIdempotencyWrite, PkiRepository } from "../repositories/pki";
import { sha256Hex, stableJson } from "../util/encoding";
import {
  assertHumanReplay,
  caDetail,
  caSummary,
  parseActivateRequest,
  parseCreateCaRequest,
  parseUpdateCaRequest,
  replayOutcome,
  requestDigest,
  resolvePolicy,
} from "./ca-model";
import { verifySignature } from "./asn1/algorithms";
import { parseCertificate } from "./asn1/certificate";
import { parseCrl, type ParsedCrl } from "./asn1/crl";
import { buildExternalIntermediateCsr, parseRawCsr } from "./asn1/csr";
import { canonicalSerialHex } from "./asn1/der";
import { fromPem, toPem } from "./asn1/pem";
import { verifyActivationChain } from "./chain";
import {
  buildSignedCrl,
  crlObjectKey,
  CrlService,
  drainPoint,
  floorSeconds,
  pkiObjectRead,
  type CrlIssuerMaterial,
} from "./crl-service";
import {
  decodeCrlInput,
  verifyRootCrl,
  type VerifiedRootCrl,
} from "./crl-verify";
import {
  caKeyUnavailable,
  caNotActive,
  caSubjectInUse,
  chainInvalid,
  crlInvalid,
  crlPublicationBusy,
  pkiConflict,
  pkiNotFound,
} from "./errors";
import { emitPkiMetrics, PKI_METRICS } from "./metrics";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import { signWithPkcs8 } from "./signer";
import {
  buildCaSubject,
  matchesIdentityRoot,
  parseRestrictedName,
  type IdentityRootReference,
} from "./subject";
import type { CaCrlState, CaRecord, CaStatus, ExternalCaRecord } from "./types";
import { generateCaKeyPair, wrapCaKey } from "./wrapped-keys";

const maxActivationReruns = 3;
const cursorLifetimeMs = 15 * 60 * 1000;

const ed25519Warning = {
  code: "ed25519_compatibility",
  message:
    "Ed25519 CA keys are not accepted by every TLS client and verifier. Prefer ECDSA_P256 unless you have verified compatibility.",
};

const statusReason: Record<CaStatus, string> = {
  PENDING_CERTIFICATE: "pending_certificate",
  ACTIVE: "active",
  RETIRED: "retired",
  REVOKED: "revoked",
  FAILED: "failed",
};

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const versionId = (): string => `pkv-${randomUUID()}`;

/** Normalizes an `If-Match`-style value. */
export const stripEtag = (value: string): string =>
  value.replace(/^W\//, "").replace(/^"(.*)"$/, "$1");

export type CaDetailResponse = {
  readonly body: Record<string, unknown>;
  readonly etag: string;
};

export class CaService {
  private readonly emit: typeof emitPkiMetrics;

  public constructor(
    private readonly deps: PkiServiceDeps,
    private readonly crls: CrlService,
  ) {
    this.emit = deps.emit ?? emitPkiMetrics;
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
      this.warningsFor(loaded.key.algorithm, status === 201),
    );
    return {
      body,
      status,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget: this.auditTarget(ca),
      etag: ca.version,
    };
  }

  private warningsFor(
    algorithm: string,
    created: boolean,
  ): { code: string; message: string }[] | undefined {
    return created && algorithm === "ED25519" ? [ed25519Warning] : undefined;
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
    if (
      (await this.pki.getCaNameClaim(input.environment, input.name)) !==
      undefined
    ) {
      throw pkiConflict("name_in_use");
    }
    if ((await this.pki.getSubjectClaim(subject.key)) !== undefined) {
      throw caSubjectInUse("subject_claimed");
    }
    // The GSI lags, so the limit is best effort.
    const existing = await this.pki.queryDirectory("PKI_CAS", {
      sortPrefix: `${input.environment}#`,
    });
    if (existing.filter((item) => item.status !== "FAILED").length >= 50) {
      throw pkiConflict("ca_limit_reached");
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
      this.warningsFor(input.keyAlgorithm, true),
    );
    return this.success(ca, view, 201);
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
      displayName: input.displayName === undefined ? "keep" : input.displayName,
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
      maxIssueLifetimeEverSeconds: Math.max(
        ca.maxIssueLifetimeEverSeconds,
        policy.maxLeafLifetimeSeconds,
      ),
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
