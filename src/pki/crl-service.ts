import { randomUUID } from "node:crypto";
import { ApiError, serviceUnavailable } from "../domain/errors";
import type { HumanIdempotencyWrite } from "../repositories/pki";
import { sha256Hex } from "../util/encoding";
import { caSignatureAlgorithmIdentifier } from "./asn1/algorithms";
import { parseCertificate } from "./asn1/certificate";
import {
  assembleCrl,
  buildTbsCertList,
  parseCrl,
  verifyCrlSignature,
} from "./asn1/crl";
import { fromPem } from "./asn1/pem";
import { caKeyUnavailable, crlPublicationBusy, pkiNotFound } from "./errors";
import { emitPkiMetrics, PKI_METRICS } from "./metrics";
import type { CaSigner } from "./signer";
import type { PkiServiceDeps } from "./service-types";
import type {
  CaCrlState,
  CaRecord,
  PkiKeyAlgorithm,
  RevocationEntryRecord,
  RevocationReason,
} from "./types";

// ---------------------------------------------------------------------------------------------------------------------
// Scheduling (pure)
// ---------------------------------------------------------------------------------------------------------------------

/** A CRL is refreshed this long before `nextUpdate`: a third of its validity, at least 45 minutes, at most half. */
export const crlRefreshMarginSeconds = (validitySeconds: number): number =>
  Math.min(Math.max(validitySeconds / 3, 2700), validitySeconds / 2);

/** The alarm threshold for the time left to `nextUpdate`: a third of the margin, at most two days. */
export const crlStaleThresholdSeconds = (validitySeconds: number): number =>
  Math.min(172_800, crlRefreshMarginSeconds(validitySeconds) / 3);

type DrainCa = Pick<
  CaRecord,
  "status" | "retiredAt" | "maxIssueLifetimeEverSeconds" | "notAfter" | "key"
>;
type PublishedCrl = NonNullable<CaCrlState["published"]>;

/** The instant after which a retired CA can have no unexpired leaf: `min(retiredAt + longest lifetime ever, notAfter)`. */
export const drainPoint = (
  ca: Pick<DrainCa, "retiredAt" | "maxIssueLifetimeEverSeconds" | "notAfter">,
): string => {
  const retired = Date.parse(ca.retiredAt ?? "");
  const byLifetime = retired + ca.maxIssueLifetimeEverSeconds * 1000;
  const notAfter = Date.parse(ca.notAfter ?? "");
  return new Date(Math.min(byLifetime, notAfter)).toISOString();
};

/** A retired CA is drained once the CRL published after its drain point covers every revocation. */
export const isDrained = (
  ca: DrainCa,
  crl: Pick<CaCrlState, "revision"> & { published?: PublishedCrl },
): boolean =>
  ca.status === "RETIRED" &&
  (ca.key.state !== "ACTIVE" ||
    (crl.published !== undefined &&
      crl.published.thisUpdate > drainPoint(ca) &&
      crl.published.revision === crl.revision));

export type CrlReason = "dirty" | "refresh" | "drop" | "drain";

export interface CrlEvaluation {
  readonly signable: boolean;
  readonly alarmable: boolean;
  readonly drainAt?: string;
  readonly drained: boolean;
  readonly reasons: CrlReason[];
  readonly secondsToNextUpdate?: number;
  readonly stale: boolean;
}

export const evaluateCrl = (
  ca: Pick<CaRecord, "status" | "key" | "policy"> & DrainCa,
  crl:
    (Pick<CaCrlState, "revision"> & { published?: PublishedCrl }) | undefined,
  now: Date,
): CrlEvaluation => {
  const published = crl?.published;
  const drained =
    crl !== undefined
      ? isDrained(ca, crl)
      : ca.status === "RETIRED" && ca.key.state !== "ACTIVE";
  const signable =
    (ca.status === "ACTIVE" || ca.status === "RETIRED") &&
    ca.key.state === "ACTIVE" &&
    published !== undefined;
  const alarmable =
    ca.status === "ACTIVE" || (ca.status === "RETIRED" && !drained);
  const drainAt =
    ca.status === "RETIRED" &&
    ca.retiredAt !== undefined &&
    ca.notAfter !== undefined
      ? drainPoint(ca)
      : undefined;
  const nowIso = now.toISOString();
  const reasons: CrlReason[] = [];
  let secondsToNextUpdate: number | undefined;
  let validity = ca.policy.crlValiditySeconds;
  if (published !== undefined && crl !== undefined) {
    validity =
      (Date.parse(published.nextUpdate) - Date.parse(published.thisUpdate)) /
      1000;
    secondsToNextUpdate =
      (Date.parse(published.nextUpdate) - now.getTime()) / 1000;
    if (signable) {
      if (crl.revision > published.revision) {
        reasons.push("dirty");
      }
      if (
        now.getTime() >=
        Date.parse(published.nextUpdate) -
          crlRefreshMarginSeconds(validity) * 1000
      ) {
        reasons.push("refresh");
      }
      if (published.dropDueAt !== undefined && nowIso > published.dropDueAt) {
        reasons.push("drop");
      }
      if (
        ca.status === "RETIRED" &&
        drainAt !== undefined &&
        nowIso > drainAt &&
        !drained
      ) {
        reasons.push("drain");
      }
    }
  }
  const stale =
    alarmable &&
    (published === undefined ||
      (secondsToNextUpdate ?? 0) < crlStaleThresholdSeconds(validity));
  return {
    signable,
    alarmable,
    ...(drainAt === undefined ? {} : { drainAt }),
    drained,
    reasons,
    ...(secondsToNextUpdate === undefined ? {} : { secondsToNextUpdate }),
    stale,
  };
};

/** Entries whose certificate had not expired before the previous CRL's `thisUpdate`. */
export const selectCrlEntries = (
  entries: readonly RevocationEntryRecord[],
  previous?: Pick<PublishedCrl, "thisUpdate">,
): RevocationEntryRecord[] =>
  entries.filter(
    (entry) => previous === undefined || entry.notAfter >= previous.thisUpdate,
  );

/** The earliest `notAfter` among included entries that have not expired yet at `thisUpdate`. */
export const computeDropDueAt = (
  included: readonly Pick<RevocationEntryRecord, "notAfter">[],
  thisUpdate: string,
): string | undefined =>
  included
    .map((entry) => entry.notAfter)
    .filter((notAfter) => notAfter >= thisUpdate)
    .sort()[0];

/** `numberText` is the decimal CRL number for a `ca-` issuer and the 40-hex number for an `ext-` issuer. */
export const crlObjectKey = (
  issuerId: string,
  numberText: string,
  sha256: string,
): string => `crl/${issuerId}/${numberText}-${sha256.slice(0, 16)}.crl`;

export const floorSeconds = (date: Date): Date =>
  new Date(Math.floor(date.getTime() / 1000) * 1000);

// ---------------------------------------------------------------------------------------------------------------------
// Building and signing
// ---------------------------------------------------------------------------------------------------------------------

export interface CrlIssuerMaterial {
  /** Base64 DER: the byte-exact subject Name of the CA certificate. */
  readonly subjectDer: string;
  /** Lowercase hex SubjectKeyIdentifier. */
  readonly subjectKeyIdentifier: string;
  readonly spkiDer: Uint8Array;
}

export const issuerMaterialOf = (
  ca: Pick<CaRecord, "subjectDer" | "subjectKeyIdentifier" | "certificatePem">,
): CrlIssuerMaterial => {
  if (
    ca.subjectDer === undefined ||
    ca.subjectKeyIdentifier === undefined ||
    ca.certificatePem === undefined
  ) {
    throw serviceUnavailable("The CA record has no certificate.");
  }
  return {
    subjectDer: ca.subjectDer,
    subjectKeyIdentifier: ca.subjectKeyIdentifier,
    spkiDer: parseCertificate(fromPem(ca.certificatePem, "CERTIFICATE"))
      .spkiDer,
  };
};

export interface CrlBuildInput {
  readonly number: number;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
  readonly entries: readonly RevocationEntryRecord[];
}

/** Builds, signs and self-verifies a CRL. A signing failure is reported through `onFailure` and rethrown. */
export const buildSignedCrl = async (
  issuer: CrlIssuerMaterial,
  signer: CaSigner,
  input: CrlBuildInput,
  onFailure?: (error: ApiError) => void,
): Promise<{ der: Buffer; sha256: string }> => {
  const algorithm: PkiKeyAlgorithm = signer.algorithm;
  const signatureAlgorithm = caSignatureAlgorithmIdentifier(algorithm);
  const tbs = buildTbsCertList({
    signatureAlgorithm,
    issuerDer: Buffer.from(issuer.subjectDer, "base64"),
    thisUpdate: input.thisUpdate,
    nextUpdate: input.nextUpdate,
    crlNumber: BigInt(input.number),
    authorityKeyId: Buffer.from(issuer.subjectKeyIdentifier, "hex"),
    entries: input.entries.map((entry) => ({
      serialHex: entry.serial,
      revokedAt: new Date(entry.revokedAt),
      reason: entry.reason as RevocationReason,
      ...(entry.invalidityDate === undefined
        ? {}
        : { invalidityDate: new Date(entry.invalidityDate) }),
    })),
  });
  let signature: Uint8Array;
  try {
    signature = await signer.sign(tbs);
  } catch (error) {
    if (error instanceof ApiError) {
      onFailure?.(error);
    }
    throw error;
  }
  const der = assembleCrl(tbs, signatureAlgorithm, signature);
  const parsed = parseCrl(der);
  if (
    !verifyCrlSignature(parsed, issuer.spkiDer) ||
    parsed.crlNumber === undefined ||
    BigInt(`0x${parsed.crlNumber.toString("hex")}`) !== BigInt(input.number) ||
    parsed.entries.length !== input.entries.length
  ) {
    throw serviceUnavailable("The generated CRL failed verification.");
  }
  return { der, sha256: sha256Hex(der) };
};

/** Reads a PKI object; any storage failure (a missing key is a 403 without `ListBucket`) is a 503. */
export const pkiObjectRead = async (
  objects: PkiServiceDeps["objects"],
  bucket: string,
  key: string,
): Promise<Buffer> => {
  try {
    const bytes = await objects.getBytes(bucket, key);
    if (bytes.length === 0) {
      throw new Error("empty");
    }
    return bytes;
  } catch {
    throw serviceUnavailable("The CRL object is unavailable.");
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------------------------------

export type PublishResult =
  | { kind: "published"; pointer: PublishedCrl }
  | { kind: "busy" }
  | { kind: "superseded" }
  | { kind: "replay" };

export interface PublishOptions {
  readonly trigger: "force" | "maintenance" | "inline";
  readonly idempotency?: HumanIdempotencyWrite;
  readonly waitForLeaseMs?: number;
}

export type CrlDownload =
  | { kind: "notModified"; sha256: string }
  | { kind: "bytes"; der: Buffer; sha256: string; numberText: string };

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export class CrlService {
  private readonly emit: typeof emitPkiMetrics;

  public constructor(
    private readonly deps: PkiServiceDeps,
    private readonly wait: (ms: number) => Promise<void> = sleep,
  ) {
    this.emit = deps.emit ?? emitPkiMetrics;
  }

  /** Lease, allocate a number, sign, put an immutable object, then commit a monotone pointer. */
  public async publish(
    ca: CaRecord,
    options: PublishOptions,
  ): Promise<PublishResult> {
    const { pki, config, objects } = this.deps;
    if (ca.key.state !== "ACTIVE") {
      throw caKeyUnavailable();
    }
    const owner = `crl-${randomUUID()}`;
    const waitForLeaseMs = options.waitForLeaseMs ?? 0;
    for (let waitedMs = 0; ; waitedMs += 500) {
      const lease = await pki.acquireCrlLease(ca.caId, owner, this.deps.now());
      if (lease === "acquired") {
        break;
      }
      if (waitedMs >= waitForLeaseMs) {
        return { kind: "busy" };
      }
      await this.wait(500);
    }
    // Re-read under the lease: the caller's record may be stale (revoked, key disabled) since it was loaded.
    const current = await pki.getCa(ca.caId);
    if (
      current === undefined ||
      (current.status !== "ACTIVE" && current.status !== "RETIRED") ||
      current.key.state !== "ACTIVE"
    ) {
      return { kind: "superseded" };
    }
    ca = current;
    const allocation = await pki.allocateCrlNumber(ca.caId, owner);
    if (allocation === "lost") {
      return { kind: "superseded" };
    }
    const { number, startRevision, previous } = allocation;
    const thisUpdate = floorSeconds(this.deps.now());
    const nextUpdate = new Date(
      thisUpdate.getTime() + ca.policy.crlValiditySeconds * 1000,
    );
    const entries = selectCrlEntries(
      await pki.listRevocationsSince(ca.caId, previous?.thisUpdate),
      previous,
    );
    const built = await buildSignedCrl(
      issuerMaterialOf(ca),
      this.deps.signerFor(ca),
      { number, thisUpdate, nextUpdate, entries },
      (error) => this.report(error),
    );
    const objectKey = crlObjectKey(ca.caId, String(number), built.sha256);
    await objects.putImmutableOrGet(
      config.pkiBucketName,
      objectKey,
      built.der,
      "application/pkix-crl",
    );
    const dropDueAt = computeDropDueAt(entries, thisUpdate.toISOString());
    const published: PublishedCrl = {
      number,
      objectKey,
      sha256: built.sha256,
      thisUpdate: thisUpdate.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      revision: startRevision,
      entryCount: entries.length,
      ...(dropDueAt === undefined ? {} : { dropDueAt }),
    };
    const base = {
      caId: ca.caId,
      owner,
      number,
      startRevision,
      published,
      ...(options.idempotency === undefined
        ? {}
        : { idempotency: options.idempotency }),
    };
    let outcome = await pki.commitCrlPublication({ ...base, clearDirty: true });
    if (outcome === "conditionFailed") {
      const current = await pki.getCaCrlState(ca.caId);
      if (
        current?.lease?.owner !== owner ||
        (current.published !== undefined && current.published.number >= number)
      ) {
        return { kind: "superseded" };
      }
      // A revocation landed mid-generation: keep `dirtySince` so the next pass republishes.
      outcome = await pki.commitCrlPublication({ ...base, clearDirty: false });
      if (outcome === "conditionFailed" || outcome === "inactive") {
        return { kind: "superseded" };
      }
    }
    if (outcome === "replay") {
      return { kind: "replay" };
    }
    if (outcome === "inactive") {
      return { kind: "superseded" };
    }
    try {
      await pki.expireCarriedRevocations(
        ca.caId,
        published.thisUpdate,
        Math.floor(this.deps.now().getTime() / 1000) + 86_400,
      );
      await pki.markCrlSwept(ca.caId, published.thisUpdate);
    } catch (error) {
      // Maintenance finishes an interrupted sweep: `sweptThrough` still differs from `thisUpdate`.
      console.error("PKI CRL sweep failed", {
        caId: ca.caId,
        name: error instanceof Error ? error.name : typeof error,
      });
    }
    return { kind: "published", pointer: published };
  }

  /** Reports a signing failure to the alarm metrics. */
  private report(error: ApiError): void {
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

  /** The admin download: a conditional read of the published pointer's object. */
  public async download(
    issuerId: string,
    ifNoneMatch?: readonly string[],
  ): Promise<CrlDownload> {
    const { pki, config, objects } = this.deps;
    let pointer: { sha256: string; objectKey: string } | undefined;
    let numberText = "";
    if (issuerId.startsWith("ext-")) {
      const ext = await pki.getExternalCa(issuerId);
      if (ext === undefined) {
        throw pkiNotFound("external_ca_not_found");
      }
      pointer = ext.crl;
      numberText = ext.crl?.numberHex ?? "";
    } else {
      if ((await pki.getCa(issuerId)) === undefined) {
        throw pkiNotFound("ca_not_found");
      }
      const state = await pki.getCaCrlState(issuerId);
      pointer = state?.published;
      numberText = String(state?.published?.number ?? "");
    }
    if (pointer === undefined) {
      throw pkiNotFound("crl_missing");
    }
    if (
      ifNoneMatch?.includes("*") === true ||
      ifNoneMatch?.includes(pointer.sha256) === true
    ) {
      return { kind: "notModified", sha256: pointer.sha256 };
    }
    const der = await pkiObjectRead(
      objects,
      config.pkiBucketName,
      pointer.objectKey,
    );
    if (sha256Hex(der) !== pointer.sha256) {
      throw serviceUnavailable("The stored CRL failed its integrity check.");
    }
    return { kind: "bytes", der, sha256: pointer.sha256, numberText };
  }

  /** Maps the busy outcome of a forced publication to the API error. */
  public static busyError(): ApiError {
    return crlPublicationBusy();
  }
}
