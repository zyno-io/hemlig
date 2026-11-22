import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificateList } from "@peculiar/asn1-x509";
import type { RevocationReason } from "../types";
import {
  parseAlgorithmIdentifier,
  verifySignature,
  type AlgorithmIdentifierParts,
} from "./algorithms";
import {
  bitString,
  children,
  decodeTime,
  decodeUnsignedInteger,
  DerError,
  encodeTime,
  expectTag,
  explicit,
  parseDer,
  seq,
  smallInteger,
  TAG,
  unsignedInteger,
} from "./der";
import {
  authorityKeyIdentifierValue,
  crlNumberValue,
  decodeAuthorityKeyIdentifier,
  decodeExtensions,
  extension,
  EXT,
  invalidityDateValue,
  reasonCodeValue,
  type RawExtension,
} from "./extensions";

export interface CrlEntryInput {
  /** Lowercase hex serial (content octets). */
  readonly serialHex: string;
  readonly revokedAt: Date;
  /** `unspecified` is encoded by omitting the reason. */
  readonly reason?: RevocationReason;
  readonly invalidityDate?: Date;
}

export interface TbsCertListInput {
  /** DER AlgorithmIdentifier; must equal the one used for the outer signature. */
  readonly signatureAlgorithm: Uint8Array;
  /** Byte-exact copy of the CA certificate's subject Name. */
  readonly issuerDer: Uint8Array;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
  readonly crlNumber: bigint;
  /** The CA's SubjectKeyIdentifier bytes. */
  readonly authorityKeyId: Uint8Array;
  readonly entries: readonly CrlEntryInput[];
}

const compareSerials = (left: string, right: string): number =>
  left.length === right.length
    ? left < right
      ? -1
      : left > right
        ? 1
        : 0
    : left.length - right.length;

const entry = (input: CrlEntryInput): Buffer => {
  const extensions = [
    ...(input.reason !== undefined && input.reason !== "unspecified"
      ? [extension(EXT.reasonCode, false, reasonCodeValue(input.reason))]
      : []),
    ...(input.invalidityDate !== undefined
      ? [
          extension(
            EXT.invalidityDate,
            false,
            invalidityDateValue(input.invalidityDate),
          ),
        ]
      : []),
  ];
  return seq(
    unsignedInteger(Buffer.from(input.serialHex, "hex")),
    encodeTime(input.revokedAt),
    ...(extensions.length > 0 ? [seq(...extensions)] : []),
  );
};

/** A full, direct v2 TBSCertList with AKI and CRLNumber only. Entries are ordered by serial. */
export const buildTbsCertList = (input: TbsCertListInput): Buffer => {
  const entries = [...input.entries].sort((left, right) =>
    compareSerials(left.serialHex, right.serialHex),
  );
  return seq(
    smallInteger(1),
    input.signatureAlgorithm,
    input.issuerDer,
    encodeTime(input.thisUpdate),
    encodeTime(input.nextUpdate),
    ...(entries.length > 0 ? [seq(...entries.map(entry))] : []),
    explicit(
      0,
      seq(
        extension(
          EXT.authorityKeyIdentifier,
          false,
          authorityKeyIdentifierValue(input.authorityKeyId),
        ),
        extension(EXT.crlNumber, false, crlNumberValue(input.crlNumber)),
      ),
    ),
  );
};

/** CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }. */
export const assembleCrl = (
  tbs: Uint8Array,
  signatureAlgorithm: Uint8Array,
  signature: Uint8Array,
): Buffer => seq(tbs, signatureAlgorithm, bitString(signature));

export interface ParsedCrlEntry {
  readonly serialHex: string;
  readonly revocationDate: Date;
  /** CRLReason code, when present. */
  readonly reason?: number;
  readonly extensions: readonly RawExtension[];
}

export interface ParsedCrl {
  readonly der: Buffer;
  readonly tbsDer: Buffer;
  readonly version?: number;
  readonly issuerDer: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate?: Date;
  readonly signatureAlgorithm: AlgorithmIdentifierParts;
  readonly tbsSignatureAlgorithm: AlgorithmIdentifierParts;
  readonly signature: Buffer;
  readonly entries: readonly ParsedCrlEntry[];
  readonly extensions: readonly RawExtension[];
  /** Unsigned CRLNumber content octets (up to 20 are valid per RFC 5280). */
  readonly crlNumber?: Buffer;
  readonly authorityKeyIdentifier?: Buffer;
}

export const parseCrl = (input: Uint8Array): ParsedCrl => {
  const der = Buffer.from(input);
  try {
    const root = parseDer(der);
    expectTag(root, TAG.sequence, "a CertificateList");
    const [tbs, outerAlgorithm, signatureBits, ...extra] = children(root);
    if (
      tbs === undefined ||
      outerAlgorithm === undefined ||
      signatureBits === undefined ||
      extra.length > 0
    ) {
      throw new DerError("Malformed CertificateList.");
    }
    expectTag(tbs, TAG.sequence, "a TBSCertList");
    expectTag(signatureBits, TAG.bitString, "a signature");
    if (signatureBits.value[0] !== 0 || signatureBits.value.length < 2) {
      throw new DerError("Malformed signature BIT STRING.");
    }
    AsnConvert.parse(der, CertificateList);

    const fields = children(tbs);
    let index = 0;
    let version: number | undefined;
    if (fields[0]?.tag === TAG.integer) {
      version = fields[0].value[0];
      index = 1;
    }
    const tbsAlgorithm = fields[index];
    const issuer = fields[index + 1];
    const thisUpdate = fields[index + 2];
    if (
      tbsAlgorithm === undefined ||
      issuer === undefined ||
      thisUpdate === undefined
    ) {
      throw new DerError("Truncated TBSCertList.");
    }
    expectTag(issuer, TAG.sequence, "an issuer");
    index += 3;
    let nextUpdate: Date | undefined;
    const next = fields[index];
    if (
      next !== undefined &&
      (next.tag === TAG.utcTime || next.tag === TAG.generalizedTime)
    ) {
      nextUpdate = decodeTime(next);
      index += 1;
    }
    const entries: ParsedCrlEntry[] = [];
    const revoked = fields[index];
    if (revoked !== undefined && revoked.tag === TAG.sequence) {
      for (const item of children(revoked)) {
        const [serial, date, list, ...more] = children(item);
        if (serial === undefined || date === undefined || more.length > 0) {
          throw new DerError("Malformed revoked certificate entry.");
        }
        const extensions = list === undefined ? [] : decodeExtensions(list);
        const reason = extensions.find(
          (candidate) => candidate.oid === EXT.reasonCode,
        );
        entries.push({
          serialHex: decodeUnsignedInteger(serial).toString("hex"),
          revocationDate: decodeTime(date),
          reason:
            reason === undefined
              ? undefined
              : expectTag(parseDer(reason.value), TAG.enumerated, "a CRLReason")
                  .value[0],
          extensions,
        });
      }
      index += 1;
    }
    let extensions: RawExtension[] = [];
    for (const field of fields.slice(index)) {
      if (field.tag !== 0xa0) {
        throw new DerError("Unexpected TBSCertList field.");
      }
      const container = children(field)[0];
      if (container === undefined) {
        throw new DerError("Malformed CRL extensions.");
      }
      extensions = decodeExtensions(container);
    }
    const number = extensions.find(
      (candidate) => candidate.oid === EXT.crlNumber,
    );
    const aki = extensions.find(
      (candidate) => candidate.oid === EXT.authorityKeyIdentifier,
    );
    return {
      der,
      tbsDer: tbs.raw,
      version,
      issuerDer: issuer.raw,
      thisUpdate: decodeTime(thisUpdate),
      nextUpdate,
      signatureAlgorithm: parseAlgorithmIdentifier(outerAlgorithm),
      tbsSignatureAlgorithm: parseAlgorithmIdentifier(tbsAlgorithm),
      signature: signatureBits.value.subarray(1),
      entries,
      extensions,
      crlNumber:
        number === undefined
          ? undefined
          : decodeUnsignedInteger(parseDer(number.value)),
      authorityKeyIdentifier:
        aki === undefined
          ? undefined
          : decodeAuthorityKeyIdentifier(aki.value).keyIdentifier,
    };
  } catch (error) {
    throw error instanceof DerError ? error : new DerError("Malformed CRL.");
  }
};

export const verifyCrlSignature = (
  crl: ParsedCrl,
  issuerSpkiDer: Uint8Array,
): boolean =>
  crl.signatureAlgorithm.raw.equals(crl.tbsSignatureAlgorithm.raw) &&
  verifySignature(
    issuerSpkiDer,
    crl.signatureAlgorithm,
    crl.tbsDer,
    crl.signature,
  );
