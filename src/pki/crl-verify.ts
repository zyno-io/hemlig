import { createHash } from "node:crypto";
import {
  parseCrl,
  verifyCrlSignature,
  type ParsedCrl,
  type ParsedCrlEntry,
} from "./asn1/crl";
import { DerError } from "./asn1/der";
import type { ParsedCertificate } from "./asn1/certificate";
import { EXT } from "./asn1/extensions";
import { fromPem, PemError } from "./asn1/pem";
import { crlInvalid } from "./errors";
import { parseRestrictedName } from "./subject";

/** Uploaded CRL limits: at most 512 KiB, and `nextUpdate - thisUpdate` at most 400 days. */
export const maximumUploadedCrlBytes = 512 * 1024;
const maximumValidityMs = 400 * 24 * 60 * 60 * 1000;
const futureToleranceMs = 5 * 60 * 1000;

export interface VerifyRootCrlInput {
  /** PEM (`X509 CRL`) or base64 DER. */
  readonly crl: string;
  /** The external root certificate whose CRL this is. */
  readonly issuer: ParsedCertificate;
  readonly now: Date;
}

export interface VerifiedRootCrl {
  readonly parsed: ParsedCrl;
  readonly der: Buffer;
  readonly sha256: string;
  /** The CRL number as 40 hex digits, zero-padded (covers RFC 5280's 20 octets), comparable as a string. */
  readonly numberHex: string;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
  readonly entries: readonly ParsedCrlEntry[];
}

const decodeInput = (text: string): Buffer => {
  const trimmed = text.trim();
  if (trimmed.length > Math.ceil((maximumUploadedCrlBytes * 4) / 3) + 256) {
    throw crlInvalid("too_large");
  }
  let der: Buffer;
  if (trimmed.startsWith("-----BEGIN")) {
    try {
      der = fromPem(
        trimmed,
        "X509 CRL",
        Math.ceil((maximumUploadedCrlBytes * 4) / 3) + 256,
      );
    } catch (error) {
      if (error instanceof PemError) {
        throw crlInvalid(
          error.reason === "multiple_blocks" ? "multiple_crls" : error.reason,
        );
      }
      throw error;
    }
  } else {
    const base64 = trimmed.replace(/\s+/g, "");
    der = Buffer.from(base64, "base64");
    if (der.length === 0 || der.toString("base64") !== base64) {
      throw crlInvalid("malformed");
    }
  }
  if (der.length > maximumUploadedCrlBytes) {
    throw crlInvalid("too_large");
  }
  return der;
};

/** The checks of "Uploaded root CRLs". Throws `400 crl_invalid` with a `safeReason`. */
export const verifyRootCrl = (input: VerifyRootCrlInput): VerifiedRootCrl => {
  const der = decodeInput(input.crl);
  let crl: ParsedCrl;
  try {
    crl = parseCrl(der);
  } catch (error) {
    if (error instanceof DerError) {
      throw crlInvalid("malformed");
    }
    throw error;
  }
  if (crl.version !== 1) {
    throw crlInvalid("not_v2");
  }
  if (crl.crlNumber === undefined) {
    throw crlInvalid("missing_crl_number");
  }
  if (crl.crlNumber.length > 20) {
    throw crlInvalid("crl_number_too_large");
  }

  // Exact issuer.
  let issuerKey: string | undefined;
  try {
    issuerKey = parseRestrictedName(crl.issuerDer, "external").key;
  } catch {
    issuerKey = undefined;
  }
  const expected = parseRestrictedName(input.issuer.subjectDer, "external").key;
  if (issuerKey !== expected) {
    throw crlInvalid("issuer_mismatch");
  }
  if (!verifyCrlSignature(crl, input.issuer.spkiDer)) {
    throw crlInvalid("bad_signature");
  }
  if (
    input.issuer.keyUsage === undefined ||
    !input.issuer.keyUsage.includes("cRLSign")
  ) {
    throw crlInvalid("issuer_cannot_sign_crl");
  }
  if (crl.authorityKeyIdentifier === undefined) {
    throw crlInvalid("missing_aki");
  }
  if (
    input.issuer.subjectKeyIdentifier === undefined ||
    !crl.authorityKeyIdentifier.equals(input.issuer.subjectKeyIdentifier)
  ) {
    throw crlInvalid("aki_mismatch");
  }

  // Current.
  const now = input.now.getTime();
  if (crl.thisUpdate.getTime() > now + futureToleranceMs) {
    throw crlInvalid("this_update_in_future");
  }
  if (crl.nextUpdate === undefined) {
    throw crlInvalid("missing_next_update");
  }
  if (crl.nextUpdate.getTime() <= now) {
    throw crlInvalid("expired");
  }
  if (crl.nextUpdate.getTime() <= crl.thisUpdate.getTime()) {
    throw crlInvalid("invalid_validity");
  }
  if (crl.nextUpdate.getTime() - crl.thisUpdate.getTime() > maximumValidityMs) {
    throw crlInvalid("validity_too_long");
  }

  // Direct and full.
  const present = (oid: string): boolean =>
    crl.extensions.some((extension) => extension.oid === oid);
  if (present(EXT.issuingDistributionPoint)) {
    throw crlInvalid("issuing_distribution_point");
  }
  if (present(EXT.deltaCrlIndicator) || present(EXT.freshestCrl)) {
    throw crlInvalid("delta_crl");
  }
  for (const entry of crl.entries) {
    if (entry.reason === 8) {
      throw crlInvalid("remove_from_crl");
    }
    if (
      entry.extensions.some(
        (extension) => extension.oid === EXT.certificateIssuer,
      )
    ) {
      throw crlInvalid("indirect_crl");
    }
    if (
      entry.extensions.some(
        (extension) =>
          extension.critical &&
          extension.oid !== EXT.reasonCode &&
          extension.oid !== EXT.invalidityDate,
      )
    ) {
      throw crlInvalid("unrecognized_critical_extension");
    }
  }
  if (
    crl.extensions.some(
      (extension) =>
        extension.critical &&
        extension.oid !== EXT.crlNumber &&
        extension.oid !== EXT.authorityKeyIdentifier,
    )
  ) {
    throw crlInvalid("unrecognized_critical_extension");
  }

  return {
    parsed: crl,
    der,
    sha256: createHash("sha256").update(der).digest("hex"),
    numberHex: crl.crlNumber.toString("hex").padStart(40, "0"),
    thisUpdate: crl.thisUpdate,
    nextUpdate: crl.nextUpdate,
    entries: crl.entries,
  };
};
