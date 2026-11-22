import { randomUUID } from "node:crypto";
import { serviceUnavailable } from "../domain/errors";
import type { Actor } from "../domain/types";
import { sha256Hex } from "../util/encoding";
import { parseCertificate } from "./asn1/certificate";
import { canonicalSerialHex } from "./asn1/der";
import { fromPem } from "./asn1/pem";
import {
  assertHumanReplay,
  crlReasonName,
  externalCaDetail,
  externalCaSummary,
  parseUploadCrlRequest,
  replayOutcome,
  requestDigest,
} from "./ca-model";
import { crlObjectKey } from "./crl-service";
import { verifyRootCrl } from "./crl-verify";
import { crlNotNewer, pkiNotFound } from "./errors";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import type { ExternalCaRecord } from "./types";

const maxUploadLoops = 3;
const flipChunk = 25;
const cursorLifetimeMs = 15 * 60 * 1000;

const crlPointerView = (crl: NonNullable<ExternalCaRecord["crl"]>) => ({
  numberHex: crl.numberHex,
  thisUpdate: crl.thisUpdate,
  nextUpdate: crl.nextUpdate,
  sha256: crl.sha256,
  uploadedAt: crl.uploadedAt,
});

export class ExternalCaService {
  public constructor(private readonly deps: PkiServiceDeps) {}

  private async load(extId: string): Promise<ExternalCaRecord> {
    const ext = await this.deps.pki.getExternalCa(extId);
    if (ext === undefined) {
      throw pkiNotFound("external_ca_not_found");
    }
    return ext;
  }

  public async get(
    extId: string,
  ): Promise<{ body: Record<string, unknown>; etag: string }> {
    const ext = await this.load(extId);
    return { body: externalCaDetail(ext, this.deps.now()), etag: ext.version };
  }

  public async list(
    actor: Actor,
    rawCursor: string | undefined,
  ): Promise<Record<string, unknown>> {
    const scope = `admin:pki:external-cas:${actor.id}`;
    const now = this.deps.now();
    const decoded =
      rawCursor === undefined
        ? undefined
        : await this.deps.cursors.decode(rawCursor, scope, now);
    const page = await this.deps.pki.listExternalCasPage({
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
            expiresAt: new Date(now.getTime() + cursorLifetimeMs).toISOString(),
          });
    return {
      externalCas: page.externalCas.map((ext) => externalCaSummary(ext, now)),
      ...(nextCursor === undefined ? {} : { nextCursor }),
      generatedAt: now.toISOString(),
    };
  }

  private async replay(
    stored: Record<string, unknown>,
  ): Promise<MutationResult> {
    const outcome = replayOutcome(stored);
    const extId = outcome.result.extId;
    if (typeof extId !== "string") {
      throw serviceUnavailable("The stored idempotency record is incomplete.");
    }
    const ext = await this.load(extId);
    const unchanged = outcome.result.changed === false;
    return {
      body: {
        extId,
        ...(ext.crl === undefined ? {} : { crl: crlPointerView(ext.crl) }),
        changed: outcome.result.changed === true,
        revokedCaIds: Array.isArray(outcome.result.revokedCaIds)
          ? outcome.result.revokedCaIds
          : [],
      },
      status: 200,
      shouldWriteTerminalAudit: outcome.shouldWriteTerminalAudit,
      auditTarget: {
        extId,
        crlNumber: String(outcome.result.numberHex ?? ""),
        revokedCaIds: Array.isArray(outcome.result.revokedCaIds)
          ? outcome.result.revokedCaIds.join(",")
          : "",
        unchanged: unchanged ? "true" : "false",
      },
    };
  }

  /** Verifies, orders and stores a root CRL, then flips every dependent CA the CRL revokes. */
  public async uploadCrl(
    actor: Actor,
    key: string,
    extId: string,
    body: unknown,
  ): Promise<MutationResult> {
    const input = parseUploadCrlRequest(body);
    const digest = requestDigest("pki.external-ca.upload-crl", {
      extId,
      crlSha256: sha256Hex(input.crl),
    });
    const operation = "pki.external-ca.upload-crl";
    const prior = async (): Promise<Record<string, unknown> | undefined> => {
      const stored = await this.deps.repository.getIdempotency(actor, key);
      if (stored === undefined) {
        return undefined;
      }
      assertHumanReplay(stored, operation, digest);
      return stored;
    };
    const write = (result: Record<string, unknown>) => ({
      actor,
      idempotencyKey: key,
      operationType: operation,
      requestDigest: digest,
      result,
      now: this.deps.now().toISOString(),
    });
    const storedBefore = await prior();
    if (storedBefore !== undefined) {
      return this.replay(storedBefore);
    }
    const replayAfterCancel = async (): Promise<MutationResult> => {
      const stored = await prior();
      if (stored === undefined) {
        throw serviceUnavailable("The change could not be confirmed.");
      }
      return this.replay(stored);
    };

    // Across loops: a CA flipped in one loop is skipped (already REVOKED) in the next but still belongs in the result.
    const revokedByUpload = new Set<string>();
    for (let loop = 0; loop < maxUploadLoops; loop += 1) {
      const ext = await this.load(extId);
      const now = this.deps.now();
      const verified = verifyRootCrl({
        crl: input.crl,
        issuer: parseCertificate(fromPem(ext.certificatePem, "CERTIFICATE")),
        now,
      });
      const stored = ext.crl;
      if (stored !== undefined) {
        if (verified.sha256 === stored.sha256) {
          const result = {
            extId,
            numberHex: stored.numberHex,
            sha256: stored.sha256,
            revokedCaIds: [] as string[],
            changed: false,
          };
          if (
            (await this.deps.pki.putHumanIdempotency(write(result))) ===
            "replay"
          ) {
            return replayAfterCancel();
          }
          return {
            body: {
              extId,
              crl: crlPointerView(stored),
              changed: false,
              revokedCaIds: [],
            },
            status: 200,
            shouldWriteTerminalAudit: true,
            auditTarget: {
              extId,
              crlNumber: stored.numberHex,
              revokedCaIds: "",
              unchanged: "true",
            },
          };
        }
        if (
          verified.numberHex <= stored.numberHex ||
          verified.thisUpdate.toISOString() < stored.thisUpdate
        ) {
          throw crlNotNewer();
        }
      }
      const objectKey = crlObjectKey(
        extId,
        verified.numberHex,
        verified.sha256,
      );
      await this.deps.objects.putImmutableOrGet(
        this.deps.config.pkiBucketName,
        objectKey,
        verified.der,
        "application/pkix-crl",
      );

      // Flip every dependent the CRL revokes before the pointer commits, so a visible CRL implies the flips.
      const dependents = [...ext.dependents].sort();
      for (let index = 0; index < dependents.length; index += flipChunk) {
        const chunk = dependents.slice(index, index + flipChunk);
        const flipped = await Promise.all(
          chunk.map((caId) => this.flip(caId, extId, verified)),
        );
        for (const id of flipped) {
          if (id !== undefined) {
            revokedByUpload.add(id);
          }
        }
      }

      const revokedCaIds = [...revokedByUpload].sort();
      const pointer: NonNullable<ExternalCaRecord["crl"]> = {
        numberHex: verified.numberHex,
        thisUpdate: verified.thisUpdate.toISOString(),
        nextUpdate: verified.nextUpdate.toISOString(),
        sha256: verified.sha256,
        objectKey,
        uploadedAt: now.toISOString(),
        uploadedBy: actor,
      };
      const outcome = await this.deps.pki.commitExternalCrl({
        extId,
        loadedVersion: ext.version,
        newVersion: `pkv-${randomUUID()}`,
        crl: pointer,
        idempotency: write({
          extId,
          numberHex: verified.numberHex,
          sha256: verified.sha256,
          revokedCaIds,
          changed: true,
        }),
      });
      if (outcome === "replay") {
        return replayAfterCancel();
      }
      if (outcome === "externalChanged") {
        // A concurrent upload or activation changed the record: re-verify ordering and re-flip against it.
        continue;
      }
      return {
        body: {
          extId,
          crl: crlPointerView(pointer),
          changed: true,
          revokedCaIds,
        },
        status: 200,
        shouldWriteTerminalAudit: true,
        auditTarget: {
          extId,
          crlNumber: verified.numberHex,
          revokedCaIds: revokedCaIds.join(","),
          unchanged: "false",
        },
      };
    }
    throw serviceUnavailable("The CRL could not be committed.");
  }

  /** Revokes one dependent CA if the CRL lists its serial (any reason counts, `certificateHold` included). */
  private async flip(
    caId: string,
    extId: string,
    verified: ReturnType<typeof verifyRootCrl>,
  ): Promise<string | undefined> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const ca = await this.deps.pki.getCa(caId);
      // Already revoked by this very CRL (an earlier loop, or an upload that crashed before its pointer commit).
      if (
        ca?.status === "REVOKED" &&
        ca.revocationSource === "EXTERNAL" &&
        ca.revocationEvidence === `crl:${verified.numberHex}`
      ) {
        return caId;
      }
      if (
        ca === undefined ||
        (ca.status !== "ACTIVE" && ca.status !== "RETIRED") ||
        ca.serial === undefined
      ) {
        return undefined;
      }
      const entry = verified.entries.find(
        (candidate) => canonicalSerialHex(candidate.serialHex) === ca.serial,
      );
      if (entry === undefined) {
        return undefined;
      }
      const result = await this.deps.pki.revokeCaExternally(
        ca,
        {
          revokedAt: entry.revocationDate.toISOString(),
          reason: crlReasonName(entry.reason),
          evidence: `crl:${verified.numberHex}`,
        },
        extId,
      );
      if (result === "revoked") {
        return caId;
      }
    }
    throw serviceUnavailable("A dependent CA could not be revoked.");
  }
}
