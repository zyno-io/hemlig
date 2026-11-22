import { createHash } from "node:crypto";
import {
  describePublicKey,
  leafKeyAlgorithm,
  PublicKeyError,
  verifySignature,
  type PublicKeyInfo,
} from "./asn1/algorithms";
import { parseRawCsr } from "./asn1/csr";
import { children, DerError, parseDer } from "./asn1/der";
import {
  decodeBasicConstraints,
  decodeExtendedKeyUsage,
  decodeExtensions,
  decodeKeyUsage,
  EXT,
} from "./asn1/extensions";
import {
  decodeName,
  decodeSubjectAltName,
  type SubjectAltNames,
} from "./asn1/names";
import { fromPem, PemError } from "./asn1/pem";
import { csrInvalid, issuanceDenied } from "./errors";
import type { KeyUsageName, LeafKeyAlgorithm } from "./types";

/** CSR limits: one PEM block of at most 32 KiB (matches `issuer.ts`). */
export const maximumCsrBytes = 32_768;

export interface CsrSubjectAttribute {
  readonly oid: string;
  readonly value: string;
}

export interface ParsedCsr {
  readonly der: Buffer;
  readonly derSha256: string;
  readonly subjectDer: Buffer;
  /** One entry per RDN, in encoded order. */
  readonly subject: readonly CsrSubjectAttribute[];
  /** Names as requested, uncanonicalized. Policy canonicalizes and denies unsupported name types. */
  readonly san: SubjectAltNames;
  readonly keyUsage?: KeyUsageName[];
  readonly extendedKeyUsage?: string[];
  readonly basicConstraints?: { ca: boolean; pathLen?: number };
  readonly spkiDer: Buffer;
  readonly spkiSha256: string;
  readonly keyAlgorithm: LeafKeyAlgorithm;
}

export interface ParseCsrOptions {
  /** Reserved-keys hook: return true for an SPKI SHA-256 (hex) that must never be certified. */
  readonly isReservedKey?: (spkiSha256: string) => boolean;
}

/** Odd primes below 1,000 (Hemlig rejects RSA moduli divisible by any). */
const smallPrimes = ((): bigint[] => {
  const primes: bigint[] = [];
  for (let n = 3; n < 1000; n += 2) {
    if (primes.every((prime) => n % Number(prime) !== 0)) {
      primes.push(BigInt(n));
    }
  }
  return primes;
})();

const checkKey = (info: PublicKeyInfo): LeafKeyAlgorithm => {
  if (info.kind === "rsa") {
    if (info.bits < 2048) {
      throw csrInvalid("weak_rsa_key");
    }
    if (info.bits > 8192) {
      throw csrInvalid("rsa_key_too_large");
    }
    if (
      info.modulus % 2n === 0n ||
      smallPrimes.some((prime) => info.modulus % prime === 0n)
    ) {
      throw csrInvalid("invalid_rsa_modulus");
    }
    if (info.exponent !== 65537n) {
      throw csrInvalid("invalid_rsa_exponent");
    }
  }
  const algorithm = leafKeyAlgorithm(info);
  if (algorithm === undefined) {
    // RSA sizes between 2048 and 8192 other than the four allowed ones.
    throw issuanceDenied("key_algorithm_not_permitted");
  }
  return algorithm;
};

/** Parses and validates a CSR exactly as "CSR validation" specifies. Never logs or echoes the request. */
export const parseCsr = (
  pem: string,
  options: ParseCsrOptions = {},
): ParsedCsr => {
  let der: Buffer;
  try {
    der = fromPem(pem, "CERTIFICATE REQUEST", maximumCsrBytes);
  } catch (error) {
    throw csrInvalid(error instanceof PemError ? error.reason : "malformed");
  }
  let raw;
  try {
    raw = parseRawCsr(der);
  } catch {
    throw csrInvalid("malformed");
  }
  if (raw.version !== 0) {
    throw csrInvalid("unsupported_version");
  }

  let info: PublicKeyInfo;
  try {
    info = describePublicKey(raw.spkiDer);
  } catch (error) {
    if (error instanceof PublicKeyError) {
      if (error.reason === "unsupported_curve") {
        throw issuanceDenied("key_algorithm_not_permitted");
      }
      throw csrInvalid(error.reason);
    }
    throw csrInvalid("malformed_public_key");
  }
  const keyAlgorithm = checkKey(info);

  if (
    !verifySignature(
      raw.spkiDer,
      raw.signatureAlgorithm,
      raw.infoDer,
      raw.signature,
    )
  ) {
    throw csrInvalid("bad_signature");
  }

  const spkiSha256 = createHash("sha256").update(raw.spkiDer).digest("hex");
  if (options.isReservedKey?.(spkiSha256) === true) {
    throw csrInvalid("reserved_key");
  }

  let subject: CsrSubjectAttribute[];
  try {
    subject = decodeName(raw.subjectDer).map((rdn) => {
      const [attribute, ...more] = rdn;
      if (attribute?.value === undefined || more.length > 0) {
        throw new DerError("Unsupported subject.");
      }
      return { oid: attribute.oid, value: attribute.value };
    });
  } catch {
    throw csrInvalid("unsupported_subject");
  }

  // Only extensionRequest is accepted, at most once, and of its extensions only SAN, KU, EKU and BC are read.
  if (
    raw.attributes.length > 1 ||
    raw.attributes.some((attribute) => attribute.oid !== EXT.extensionRequest)
  ) {
    throw csrInvalid("unsupported_attribute");
  }
  let san: SubjectAltNames = {
    dns: [],
    ip: [],
    uri: [],
    email: [],
    unsupported: [],
  };
  let keyUsage: KeyUsageName[] | undefined;
  let extendedKeyUsage: string[] | undefined;
  let basicConstraints: { ca: boolean; pathLen?: number } | undefined;
  const request = raw.attributes[0];
  if (request !== undefined) {
    const [extensions, ...more] = request.values;
    if (extensions === undefined || more.length > 0) {
      throw csrInvalid("malformed");
    }
    try {
      // Re-parse strictly; the values were already DER-checked while splitting.
      parseDer(extensions.raw);
      children(extensions);
      for (const extension of decodeExtensions(extensions)) {
        switch (extension.oid) {
          case EXT.subjectAltName:
            san = decodeSubjectAltName(extension.value);
            break;
          case EXT.keyUsage:
            keyUsage = decodeKeyUsage(extension.value);
            break;
          case EXT.extendedKeyUsage:
            extendedKeyUsage = decodeExtendedKeyUsage(extension.value);
            break;
          case EXT.basicConstraints:
            basicConstraints = decodeBasicConstraints(extension.value);
            break;
          default:
            // Everything else is ignored and never copied.
            break;
        }
      }
    } catch {
      throw csrInvalid("malformed_extension");
    }
  }

  return {
    der,
    derSha256: createHash("sha256").update(der).digest("hex"),
    subjectDer: raw.subjectDer,
    subject,
    san,
    keyUsage,
    extendedKeyUsage,
    basicConstraints,
    spkiDer: raw.spkiDer,
    spkiSha256,
    keyAlgorithm,
  };
};
