import { createHash } from "node:crypto";
import { serviceUnavailable } from "../domain/errors";
import type { Actor } from "../domain/types";
import type {
  BulkRevokeBatch,
  HumanIdempotencyWrite,
  PkiRepository,
  RevokeMode,
  TransactOutcome,
} from "../repositories/pki";
import { maxBulkRevokeBatch } from "../repositories/pki";
import { sha256Hex, stableJson } from "../util/encoding";
import { assertHumanReplay, replayOutcome, requestDigest } from "./ca-model";
import { publishInlineBestEffort, type CrlService } from "./crl-service";
import { pkiBadRequest, pkiConflict, pkiNotFound } from "./errors";
import { pageWithCursor } from "./paging";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import type {
  CaRecord,
  IssuedCertificateRecord,
  RevocationEntryRecord,
  RevocationReason,
} from "./types";

type Json = Record<string, unknown>;

const pageLimit = 100;
const bulkReadBudgetMs = 20_000;
const bulkPublishBudgetMs = 25_000;
const maxBatchRetries = 3;
const hydrateConcurrency = 10;
const bulkConcurrency = 16;

const reasons: readonly RevocationReason[] = [
  "unspecified",
  "keyCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
];

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

interface RevokeFields {
  reason: RevocationReason;
  invalidityDate?: string;
}

const parseReason = (
  body: Json,
  now: Date,
): RevokeFields => {
  let reason: RevocationReason = "unspecified";
  if (body.reason !== undefined) {
    if (
      typeof body.reason !== "string" ||
      !(reasons as readonly string[]).includes(body.reason)
    ) {
      throw pkiBadRequest("invalid_reason", "The revocation reason is invalid.");
    }
    reason = body.reason as RevocationReason;
  }
  let invalidityDate: string | undefined;
  if (body.invalidityDate !== undefined) {
    if (reason !== "keyCompromise") {
      throw pkiBadRequest(
        "invalidity_date_requires_key_compromise",
        "invalidityDate requires the keyCompromise reason.",
      );
    }
    const parsed =
      typeof body.invalidityDate === "string"
        ? new Date(body.invalidityDate)
        : new Date(Number.NaN);
    // CRL times are GeneralizedTime with a four-digit year; the CA's own history starts no earlier than 1950.
    const year = parsed.getUTCFullYear();
    if (
      Number.isNaN(parsed.getTime()) ||
      parsed.getTime() > now.getTime() ||
      year < 1950 ||
      year > 9999
    ) {
      throw pkiBadRequest(
        "invalid_invalidity_date",
        "invalidityDate must be a time that is not in the future.",
      );
    }
    invalidityDate = parsed.toISOString();
  }
  return { reason, ...(invalidityDate === undefined ? {} : { invalidityDate }) };
};

const strictBody = (body: unknown, allowed: readonly string[]): Json => {
  if (!isRecord(body)) {
    throw pkiBadRequest("invalid_body", "The request body must be an object.");
  }
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw pkiBadRequest("unknown_field", "The request has an unknown field.");
    }
  }
  return body;
};

export const parseRevokeRequest = (
  body: unknown,
  now: Date,
): { raw: Json; fields: RevokeFields } => {
  const raw = strictBody(body, ["reason", "invalidityDate"]);
  return { raw, fields: parseReason(raw, now) };
};

export const parseBulkRevokeRequest = (
  body: unknown,
  now: Date,
): { raw: Json; fields: RevokeFields; grantName?: string; grantUid?: string } => {
  const raw = strictBody(body, [
    "reason",
    "invalidityDate",
    "issuanceGrant",
    "issuanceGrantUid",
  ]);
  const fields = parseReason(raw, now);
  const patterns = {
    issuanceGrant: /^[a-z][a-z0-9-]{2,63}$/,
    issuanceGrantUid: /^pkg-[a-z0-9-]{1,76}$/,
  } as const;
  for (const field of ["issuanceGrant", "issuanceGrantUid"] as const) {
    const value = raw[field];
    if (
      value !== undefined &&
      (typeof value !== "string" || !patterns[field].test(value))
    ) {
      throw pkiBadRequest(
        "invalid_filter",
        `${field} is not a valid identifier.`,
      );
    }
  }
  return {
    raw,
    fields,
    ...(raw.issuanceGrant === undefined
      ? {}
      : { grantName: raw.issuanceGrant as string }),
    ...(raw.issuanceGrantUid === undefined
      ? {}
      : { grantUid: raw.issuanceGrantUid as string }),
  };
};

export const effectiveStatus = (
  cert: Pick<IssuedCertificateRecord, "status" | "notAfter">,
  ca: Pick<CaRecord, "status"> | undefined,
  now: Date,
): "ISSUED" | "REVOKED" | "CA_REVOKED" | "EXPIRED" => {
  if (cert.status === "REVOKED") {
    return "REVOKED";
  }
  if (ca?.status === "REVOKED") {
    return "CA_REVOKED";
  }
  if (Date.parse(cert.notAfter) <= now.getTime()) {
    return "EXPIRED";
  }
  return "ISSUED";
};

export const certificateSummary = (
  cert: IssuedCertificateRecord,
  ca: Pick<CaRecord, "status"> | undefined,
  now: Date,
): Json => ({
  caId: cert.caId,
  serial: cert.serial,
  status: effectiveStatus(cert, ca, now),
  storedStatus: cert.status,
  fingerprint: cert.fingerprint,
  subject: cert.subject,
  sans: cert.sans,
  keyAlgorithm: cert.keyAlgorithm,
  notBefore: cert.notBefore,
  notAfter: cert.notAfter,
  issuedAt: cert.issuedAt,
  ...(cert.isCa ? { isCa: true } : {}),
  ...(cert.childCaId === undefined ? {} : { childCaId: cert.childCaId }),
  requester: {
    type: cert.requester.type,
    id: cert.requester.id,
    ...(cert.requester.consumerId === undefined
      ? {}
      : { consumerId: cert.requester.consumerId }),
    ...(cert.requester.issuanceGrant === undefined
      ? {}
      : { issuanceGrant: cert.requester.issuanceGrant }),
  },
  ...(cert.revocation === undefined
    ? {}
    : {
        revocation: {
          at: cert.revocation.at,
          reason: cert.revocation.reason,
          ...(cert.revocation.invalidityDate === undefined
            ? {}
            : { invalidityDate: cert.revocation.invalidityDate }),
          ...(cert.revocation.upgradedAt === undefined
            ? {}
            : { upgradedAt: cert.revocation.upgradedAt }),
        },
      }),
});

export const certificateDetail = (
  cert: IssuedCertificateRecord,
  ca: Pick<CaRecord, "status"> | undefined,
  now: Date,
): Json => {
  const summary = certificateSummary(cert, ca, now);
  return {
    ...summary,
    certificatePem: cert.certificatePem,
    spkiSha256: cert.spkiSha256,
    keyUsages: cert.keyUsages,
    extendedKeyUsages: cert.extendedKeyUsages,
    lifetimeClamped: cert.lifetimeClamped === true,
    requester: {
      ...(summary.requester as Json),
      ...(cert.requester.asserted === undefined
        ? {}
        : { asserted: cert.requester.asserted }),
    },
    ...(cert.revocation === undefined
      ? {}
      : {
          revocation: {
            ...(summary.revocation as Json),
            by: cert.revocation.by,
          },
        }),
  };
};

const mapLimit = async <T, R>(
  items: readonly T[],
  limit: number,
  work: (item: T) => Promise<R>,
): Promise<R[]> => {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let index = next++; index < items.length; index = next++) {
      results[index] = await work(items[index] as T);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
  return results;
};

export type BulkRevokeResult = MutationResult & { readonly complete: boolean };

interface BulkProgress {
  revoked: number;
  alreadyRevoked: number;
  caIds: Set<string>;
  withEntries: Set<string>;
}

export class CertificateService {
  public constructor(
    private readonly deps: PkiServiceDeps,
    private readonly crls: CrlService,
  ) {}

  private get pki(): PkiRepository {
    return this.deps.pki;
  }

  private now(): Date {
    return this.deps.now();
  }

  private idempotency(
    actor: Actor,
    key: string,
    digest: string,
    result: Record<string, unknown>,
  ): HumanIdempotencyWrite {
    return {
      actor,
      idempotencyKey: key,
      operationType: "pki.certificate.revoke",
      requestDigest: digest,
      result,
      now: this.now().toISOString(),
    };
  }

  private async prior(
    actor: Actor,
    key: string,
    digest: string,
  ): Promise<Record<string, unknown> | undefined> {
    const stored = await this.deps.repository.getIdempotency(actor, key);
    if (stored === undefined) {
      return undefined;
    }
    assertHumanReplay(stored, "pki.certificate.revoke", digest);
    return stored;
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Inventory
  // -----------------------------------------------------------------------------------------------------------------

  public async get(
    caId: string,
    serial: string,
  ): Promise<Json> {
    const [cert, ca] = await Promise.all([
      this.pki.getCertificate(caId, serial),
      this.pki.getCa(caId),
    ]);
    if (cert === undefined) {
      throw pkiNotFound("certificate_not_found");
    }
    return certificateDetail(cert, ca, this.now());
  }

  public async list(
    actor: Actor,
    caId: string,
    options: {
      status?: "ISSUED" | "REVOKED" | "EXPIRED";
      expiringBefore?: string;
      cursor?: string;
    },
  ): Promise<Json> {
    const ca = await this.pki.getCa(caId);
    if (ca === undefined) {
      throw pkiNotFound("ca_not_found");
    }
    const now = this.now();
    let expiringBefore: string | undefined;
    if (options.expiringBefore !== undefined) {
      const parsed = new Date(options.expiringBefore);
      if (Number.isNaN(parsed.getTime())) {
        throw pkiBadRequest(
          "invalid_expiring_before",
          "expiringBefore must be a timestamp.",
        );
      }
      expiringBefore = parsed.toISOString();
    }
    const nowIso = now.toISOString();
    const query: {
      before?: string;
      after?: string;
      status?: "ISSUED" | "REVOKED";
    } = {};
    if (options.status === "ISSUED") {
      query.after = nowIso;
      query.status = "ISSUED";
    } else if (options.status === "EXPIRED") {
      query.before =
        expiringBefore !== undefined && expiringBefore < nowIso
          ? expiringBefore
          : nowIso;
      query.status = "ISSUED";
    } else if (options.status === "REVOKED") {
      query.status = "REVOKED";
    }
    if (expiringBefore !== undefined && options.status !== "EXPIRED") {
      query.before = expiringBefore;
    }
    const scope = `admin:pki:certs:${actor.id}:${requestDigest("list", {
      caId,
      status: options.status ?? null,
      expiringBefore: expiringBefore ?? null,
    })}`;
    const page = await pageWithCursor(
      this.deps,
      scope,
      options.cursor,
      async (start) => {
        const result = await this.pki.queryCertificatesPage(caId, {
          ...query,
          limit: pageLimit,
          ...(start === undefined ? {} : { start }),
        });
        return {
          items: result.certificates,
          ...(result.lastEvaluatedKey === undefined
            ? {}
            : { lastEvaluatedKey: result.lastEvaluatedKey }),
        };
      },
    );
    return {
      certificates: page.items.map((cert) =>
        certificateSummary(cert, ca, now),
      ),
      ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
      generatedAt: now.toISOString(),
    };
  }

  public async listForConsumer(
    actor: Actor,
    consumerId: string,
    options: {
      issuanceGrant?: string;
      includeExpired?: boolean;
      cursor?: string;
    },
  ): Promise<Json> {
    const now = this.now();
    const scope = `admin:pki:consumer-certs:${actor.id}:${requestDigest("list", {
      consumerId,
      issuanceGrant: options.issuanceGrant ?? null,
      includeExpired: options.includeExpired === true,
    })}`;
    const page = await pageWithCursor(
      this.deps,
      scope,
      options.cursor,
      async (start) => {
        const result = await this.pki.listConsumerPointersPage(consumerId, {
          ...(options.includeExpired === true
            ? {}
            : { notAfterAfter: now.toISOString() }),
          ...(options.issuanceGrant === undefined
            ? {}
            : { grantName: options.issuanceGrant }),
          newestFirst: true,
          limit: pageLimit,
          ...(start === undefined ? {} : { start }),
        });
        return {
          items: result.pointers,
          ...(result.lastEvaluatedKey === undefined
            ? {}
            : { lastEvaluatedKey: result.lastEvaluatedKey }),
        };
      },
    );
    const cas = new Map<string, CaRecord | undefined>();
    for (const caId of new Set(page.items.map((pointer) => pointer.caId))) {
      cas.set(caId, await this.pki.getCa(caId));
    }
    const certificates = await mapLimit(
      page.items,
      hydrateConcurrency,
      (pointer) => this.pki.getCertificate(pointer.caId, pointer.serial),
    );
    return {
      certificates: certificates
        .filter((cert): cert is IssuedCertificateRecord => cert !== undefined)
        .map((cert) => certificateSummary(cert, cas.get(cert.caId), now)),
      ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
      generatedAt: now.toISOString(),
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Revoke
  // -----------------------------------------------------------------------------------------------------------------

  private crlReference(
    crl: { published?: { number: number }; revision: number } | undefined,
    publishedRevision: number | undefined,
  ): Json {
    return {
      number: crl?.published?.number ?? 0,
      pendingRevocations:
        crl === undefined
          ? 0
          : Math.max(0, crl.revision - (publishedRevision ?? 0)),
    };
  }

  private async revokeBody(
    caId: string,
    serial: string,
    flags: {
      crlEntry: boolean;
      changed: boolean;
      crlRevision?: number;
      crlPublished?: boolean;
      crlNumber?: number;
    },
  ): Promise<{ body: Json; cert: IssuedCertificateRecord; ca: CaRecord }> {
    const [cert, ca, crl] = await Promise.all([
      this.pki.getCertificate(caId, serial),
      this.pki.getCa(caId),
      this.pki.getCaCrlState(caId),
    ]);
    if (cert === undefined || ca === undefined) {
      throw serviceUnavailable("The certificate record is unavailable.");
    }
    const crlPublished =
      flags.crlPublished ??
      (flags.crlEntry &&
        crl?.published !== undefined &&
        cert.revocation !== undefined &&
        (flags.crlRevision === undefined
          ? // A receipt from before the recorded revision keeps its original full-precision comparison.
            crl.published.thisUpdate >= cert.revocation.at
          : // `thisUpdate` is floored to the second and `at` is not.
            crl.published.thisUpdate >=
              `${cert.revocation.at.slice(0, 19)}.000Z` &&
            crl.published.revision >= flags.crlRevision));
    const crlNumber =
      flags.crlNumber ??
      (crlPublished === true ? crl?.published?.number : undefined);
    return {
      cert,
      ca,
      body: {
        certificate: certificateDetail(cert, ca, this.now()),
        crlEntry: flags.crlEntry,
        crlPublished: crlPublished === true,
        ...(crlNumber === undefined ? {} : { crlNumber }),
        changed: flags.changed,
        crl: this.crlReference(crl, crl?.published?.revision),
      },
    };
  }

  private revokeTarget(
    cert: IssuedCertificateRecord,
    reason: RevocationReason,
    flags: {
      crlEntry: boolean;
      crlPublished: boolean;
      crlNumber?: number;
      changed: boolean;
    },
  ): Record<string, string> {
    return {
      caId: cert.caId,
      environment: cert.environment,
      serial: cert.serial,
      reason,
      crlEntry: String(flags.crlEntry),
      crlPublished: String(flags.crlPublished),
      ...(flags.crlNumber === undefined
        ? {}
        : { crlNumber: String(flags.crlNumber) }),
      changed: String(flags.changed),
    };
  }

  private async replayRevoke(
    stored: Record<string, unknown>,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const { caId, serial } = outcome.result;
    if (typeof caId !== "string" || typeof serial !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    const flags = {
      crlEntry: outcome.result.crlEntry === true,
      changed: outcome.result.changed === true,
      ...(typeof outcome.result.crlRevision === "number"
        ? { crlRevision: outcome.result.crlRevision }
        : {}),
    };
    const { body, cert } = await this.revokeBody(caId, serial, flags);
    return {
      body,
      status: 200,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget: this.revokeTarget(
        cert,
        cert.revocation?.reason ?? "unspecified",
        {
          ...flags,
          crlPublished: body.crlPublished === true,
          ...(typeof body.crlNumber === "number"
            ? { crlNumber: body.crlNumber }
            : {}),
        },
      ),
    };
  }

  private publishInline(
    ca: CaRecord,
  ): Promise<{ crlPublished: boolean; crlNumber?: number }> {
    return publishInlineBestEffort(this.crls, ca, this.now());
  }

  public async revoke(
    actor: Actor,
    key: string,
    caId: string,
    serial: string,
    body: unknown,
  ): Promise<MutationResult> {
    const { raw, fields } = parseRevokeRequest(body, this.now());
    const digest = requestDigest("pki.certificate.revoke", {
      caId,
      serial,
      body: raw,
    });
    const stored = await this.prior(actor, key, digest);
    if (stored !== undefined) {
      return this.replayRevoke(stored);
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const cert = await this.pki.getCertificate(caId, serial);
      if (cert === undefined) {
        throw pkiNotFound("certificate_not_found");
      }
      if (cert.childCaId !== undefined) {
        throw pkiConflict("use_ca_revoke");
      }
      const ca = await this.pki.getCa(caId);
      if (ca === undefined) {
        throw serviceUnavailable("The CA record is unavailable.");
      }
      const now = this.now();
      const nowIso = now.toISOString();
      const entry: RevocationEntryRecord | undefined =
        cert.status === "REVOKED"
          ? await this.pki.getRevocationEntry(caId, serial)
          : undefined;
      let mode: RevokeMode | "none";
      let crlEntry: boolean;
      let expired = false;
      let entryLive = false;
      if (cert.status === "ISSUED") {
        if (ca.status === "REVOKED") {
          mode = "inventory";
          crlEntry = false;
        } else if (Date.parse(cert.notAfter) <= now.getTime()) {
          mode = "inventory";
          crlEntry = false;
          expired = true;
        } else {
          mode = "entry";
          crlEntry = true;
        }
      } else if (
        fields.reason === "keyCompromise" &&
        cert.revocation?.reason !== "keyCompromise"
      ) {
        mode = "upgrade";
        entryLive = entry !== undefined && entry.ttl === undefined;
        crlEntry = entry !== undefined;
      } else {
        mode = "none";
        crlEntry = (await this.pki.getRevocationEntry(caId, serial)) !== undefined;
      }
      const changed = mode !== "none";
      // The bump makes the CRL's revision at least this: a replay tests a published CRL against it.
      const crlRevision =
        mode === "entry" || (mode === "upgrade" && entryLive)
          ? ((await this.pki.getCaCrlState(caId))?.revision ?? 0) + 1
          : undefined;
      const idempotency = this.idempotency(actor, key, digest, {
        caId,
        serial,
        crlEntry,
        changed,
        ...(crlRevision === undefined ? {} : { crlRevision }),
      });
      let outcome: TransactOutcome;
      if (mode === "none") {
        const result = await this.pki.putHumanIdempotency(idempotency);
        outcome =
          result === "committed"
            ? { kind: "committed" }
            : { kind: "canceled", failed: ["idempotency"] };
      } else {
        outcome = await this.pki.revokeCertificate({
          mode,
          idempotency,
          caId,
          serial,
          notAfter: cert.notAfter,
          now: nowIso,
          reason: fields.reason,
          ...(fields.invalidityDate === undefined
            ? {}
            : { invalidityDate: fields.invalidityDate }),
          by: actor,
          expired,
          entryLive,
          ...(crlRevision === undefined
            ? {}
            : { expectCrlRevision: crlRevision - 1 }),
        });
      }
      if (outcome.kind === "canceled") {
        if (outcome.failed.includes("idempotency")) {
          const again = await this.prior(actor, key, digest);
          if (again === undefined) {
            throw serviceUnavailable("The change could not be confirmed.");
          }
          return this.replayRevoke(again);
        }
        // The certificate, entry or CRL item moved: read again and redo the table.
        continue;
      }
      let published: { crlPublished: boolean; crlNumber?: number } = {
        crlPublished: false,
      };
      const wroteEntry = mode === "entry" || (mode === "upgrade" && entryLive);
      if (wroteEntry) {
        published = await this.publishInline(ca);
      }
      const view = await this.revokeBody(caId, serial, {
        crlEntry,
        changed,
        crlPublished: published.crlPublished,
        ...(published.crlNumber === undefined
          ? {}
          : { crlNumber: published.crlNumber }),
      });
      return {
        body: view.body,
        status: 200,
        shouldWriteTerminalAudit: true,
        auditTarget: this.revokeTarget(view.cert, fields.reason, {
          crlEntry,
          changed,
          crlPublished: published.crlPublished,
          ...(published.crlNumber === undefined
            ? {}
            : { crlNumber: published.crlNumber }),
        }),
      };
    }
    throw serviceUnavailable("The certificate could not be revoked.");
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Bulk revoke
  // -----------------------------------------------------------------------------------------------------------------

  public async bulkRevoke(
    actor: Actor,
    key: string,
    consumerId: string,
    body: unknown,
  ): Promise<BulkRevokeResult> {
    const { raw, fields, grantName, grantUid } = parseBulkRevokeRequest(
      body,
      this.now(),
    );
    const digest = requestDigest("pki.certificate.revoke", {
      consumerId,
      body: raw,
    });
    const stored = await this.prior(actor, key, digest);
    if (stored !== undefined) {
      return this.bulkReplay(stored, consumerId);
    }

    const start = this.now().getTime();
    const deadline = start + bulkReadBudgetMs;
    const progress: BulkProgress = {
      revoked: 0,
      alreadyRevoked: 0,
      caIds: new Set(),
      withEntries: new Set(),
    };
    let complete = true;

    // Read page by page and revoke each page's chunks as they are read, so a slow read still makes progress. The
    // first chunk of a run always runs; later chunks and further pages stop at the deadline.
    const cas = new Map<string, CaRecord>();
    const touched = new Set<string>();
    const loadCa = async (caId: string): Promise<CaRecord> => {
      let ca = cas.get(caId);
      if (ca === undefined) {
        ca = await this.pki.getCa(caId);
        if (ca === undefined) {
          throw serviceUnavailable("The CA record is unavailable.");
        }
        cas.set(caId, ca);
      }
      return ca;
    };
    let ranChunk = false;
    let startKey: Record<string, unknown> | undefined;
    const nowIso = new Date(start).toISOString();
    do {
      const page = await this.pki.listConsumerPointersPage(consumerId, {
        notAfterAfter: nowIso,
        ...(grantName === undefined ? {} : { grantName }),
        ...(grantUid === undefined ? {} : { grantUid }),
        newestFirst: false,
        limit: pageLimit,
        ...(startKey === undefined ? {} : { start: startKey }),
      });
      const certs = await mapLimit(page.pointers, bulkConcurrency, (pointer) =>
        this.pki.getCertificate(pointer.caId, pointer.serial),
      );
      const byCa = new Map<string, { serial: string; notAfter: string }[]>();
      for (const cert of certs) {
        if (cert === undefined) {
          continue;
        }
        touched.add(cert.caId);
        if (cert.status === "REVOKED") {
          progress.alreadyRevoked += 1;
        } else if (Date.parse(cert.notAfter) > start) {
          const list = byCa.get(cert.caId) ?? [];
          list.push({ serial: cert.serial, notAfter: cert.notAfter });
          byCa.set(cert.caId, list);
        }
      }
      for (const [caId, items] of byCa) {
        const ca = await loadCa(caId);
        const withEntries = ca.status !== "REVOKED";
        for (
          let offset = 0;
          offset < items.length && complete;
          offset += maxBulkRevokeBatch
        ) {
          if (ranChunk && this.now().getTime() > deadline) {
            complete = false;
            break;
          }
          ranChunk = true;
          const done = await this.revokeChunk(
            actor,
            key,
            {
              caId,
              items: items.slice(offset, offset + maxBulkRevokeBatch),
              withEntries,
              now: this.now().toISOString(),
              actor,
              reason: fields.reason,
              ...(fields.invalidityDate === undefined
                ? {}
                : { invalidityDate: fields.invalidityDate }),
            },
            progress,
          );
          if (done > 0) {
            progress.caIds.add(caId);
            if (withEntries) {
              progress.withEntries.add(caId);
            }
          }
        }
      }
      startKey = page.lastEvaluatedKey;
      if (complete && startKey !== undefined && this.now().getTime() > deadline) {
        complete = false;
      }
    } while (startKey !== undefined && complete);

    const progressBody = (crls: Json[]): Json => ({
      consumerId,
      ...(grantName === undefined ? {} : { issuanceGrant: grantName }),
      complete,
      revoked: progress.revoked,
      alreadyRevoked: progress.alreadyRevoked,
      caIds: [...progress.caIds].sort(),
      crls,
    });
    const target = (): Record<string, string> => ({
      consumerId,
      bulk: "true",
      count: String(progress.revoked),
      alreadyRevoked: String(progress.alreadyRevoked),
      reason: fields.reason,
      caIds: [...progress.caIds].sort().join(","),
      ...(grantName === undefined ? {} : { issuanceGrant: grantName }),
      complete: String(complete),
    });
    if (!complete) {
      // No idempotency record: a rerun with the same key starts over and the conditions make it idempotent.
      return {
        body: progressBody([]),
        status: 200,
        shouldWriteTerminalAudit: false,
        auditTarget: target(),
        complete: false,
      };
    }

    // One inline publication per CA that received entries or still has an unpublished revocation of this consumer's
    // certificates; none starts after 25 seconds.
    const toPublish = new Set(progress.withEntries);
    for (const caId of touched) {
      if (toPublish.has(caId)) {
        continue;
      }
      const ca = await loadCa(caId);
      const crl = await this.pki.getCaCrlState(caId);
      if (
        ca.status !== "REVOKED" &&
        crl !== undefined &&
        crl.revision > (crl.published?.revision ?? 0)
      ) {
        toPublish.add(caId);
      }
    }
    const crls: Json[] = [];
    for (const caId of [...toPublish].sort()) {
      const ca = await loadCa(caId);
      if (this.now().getTime() - start > bulkPublishBudgetMs) {
        crls.push({ caId, crlPublished: false });
        continue;
      }
      const published = await this.publishInline(ca);
      crls.push({
        caId,
        crlPublished: published.crlPublished,
        ...(published.crlNumber === undefined
          ? {}
          : { crlNumber: published.crlNumber }),
      });
    }
    const result = progressBody(crls);
    const outcome = await this.pki.putHumanIdempotency(
      this.idempotency(actor, key, digest, result),
    );
    if (outcome === "replay") {
      const again = await this.prior(actor, key, digest);
      if (again !== undefined) {
        return this.bulkReplay(again, consumerId);
      }
    }
    return {
      body: result,
      status: 200,
      shouldWriteTerminalAudit: true,
      auditTarget: target(),
      complete: true,
    };
  }

  private bulkReplay(
    stored: Record<string, unknown>,
    consumerId: string,
  ): BulkRevokeResult {
    const outcome = replayOutcome(stored);
    const result = outcome.result;
    return {
      body: result,
      status: 200,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget: {
        consumerId,
        bulk: "true",
        count: String(result.revoked ?? 0),
        alreadyRevoked: String(result.alreadyRevoked ?? 0),
        complete: "true",
      },
      complete: true,
    };
  }

  /** One batch with the cancellation loop; returns the number of certificates this run revoked. */
  private async revokeChunk(
    actor: Actor,
    key: string,
    batch: BulkRevokeBatch,
    progress: BulkProgress,
  ): Promise<number> {
    let items = batch.items;
    let revoked = 0;
    for (let attempt = 0; attempt < maxBatchRetries && items.length > 0; attempt += 1) {
      const outcome = await this.pki.revokeBatch({ ...batch, items });
      if (outcome.kind === "committed") {
        progress.revoked += items.length;
        return revoked + items.length;
      }
      const failed = new Set(
        outcome.failed
          .filter((slot) => slot.startsWith("cert:"))
          .map((slot) => slot.slice("cert:".length)),
      );
      if (failed.size === 0) {
        throw serviceUnavailable("The certificates could not be revoked.");
      }
      const remaining: { serial: string; notAfter: string }[] = [];
      for (const item of items) {
        if (!failed.has(item.serial)) {
          remaining.push(item);
          continue;
        }
        const cert = await this.pki.getCertificate(batch.caId, item.serial);
        if (cert === undefined || cert.status === "REVOKED") {
          progress.alreadyRevoked += 1;
        } else if (Date.parse(cert.notAfter) <= this.now().getTime()) {
          if (await this.revokeExpired(actor, key, batch, item)) {
            progress.revoked += 1;
            revoked += 1;
          } else {
            progress.alreadyRevoked += 1;
          }
        } else {
          remaining.push(item);
        }
      }
      items = remaining;
    }
    if (items.length > 0) {
      throw serviceUnavailable("The certificates could not be revoked.");
    }
    return revoked;
  }

  /** An expired certificate that fell out of a batch goes through the single `inventory` transaction. */
  private async revokeExpired(
    actor: Actor,
    key: string,
    batch: BulkRevokeBatch,
    item: { serial: string; notAfter: string },
  ): Promise<boolean> {
    const derived = `bulk-${createHash("sha256")
      .update(stableJson([key, batch.caId, item.serial]))
      .digest("hex")
      .slice(0, 32)}`;
    const nowIso = this.now().toISOString();
    const outcome = await this.pki.revokeCertificate({
      mode: "inventory",
      idempotency: {
        actor,
        idempotencyKey: derived,
        operationType: "pki.certificate.revoke",
        requestDigest: sha256Hex(derived),
        result: { caId: batch.caId, serial: item.serial },
        now: nowIso,
      },
      caId: batch.caId,
      serial: item.serial,
      notAfter: item.notAfter,
      now: nowIso,
      reason: batch.reason,
      ...(batch.invalidityDate === undefined
        ? {}
        : { invalidityDate: batch.invalidityDate }),
      by: actor,
      expired: true,
    });
    return outcome.kind === "committed";
  }
}
