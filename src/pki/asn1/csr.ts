import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificationRequest } from "@peculiar/asn1-csr";
import type { NameConstraintSet, PkiKeyAlgorithm } from "../types";
import {
  caSignatureAlgorithmIdentifier,
  parseAlgorithmIdentifier,
  type AlgorithmIdentifierParts,
} from "./algorithms";
import {
  bitString,
  children,
  decodeOid,
  decodeUnsignedInteger,
  DerError,
  expectTag,
  oid,
  parseDer,
  seq,
  set,
  smallInteger,
  TAG,
  tlv,
  type Tlv,
} from "./der";
import {
  basicConstraintsValue,
  extendedKeyUsageValue,
  extension,
  EXT,
  keyIdentifierFromSpki,
  keyIdentifierValue,
  keyUsageValue,
} from "./extensions";
import { encodeNameConstraints } from "./names";

export interface ExternalIntermediateCsrInput {
  readonly subjectDer: Uint8Array;
  readonly spkiDer: Uint8Array;
  readonly keyAlgorithm: PkiKeyAlgorithm;
  readonly nameConstraints?: NameConstraintSet;
  readonly extendedKeyUsage?: readonly string[];
  /** Signs the CertificationRequestInfo with the new CA key (a `CaSigner.sign`). */
  readonly sign: (certificationRequestInfo: Uint8Array) => Promise<Uint8Array>;
}

/**
 * The CSR for an externally signed intermediate: critical BasicConstraints (cA=true, pathLen 0), critical KeyUsage
 * (keyCertSign, cRLSign), optional critical NameConstraints, optional EKU and an SKI.
 */
export const buildExternalIntermediateCsr = async (
  input: ExternalIntermediateCsrInput,
): Promise<Buffer> => {
  const constrained =
    input.nameConstraints !== undefined &&
    input.nameConstraints.permitted.length +
      input.nameConstraints.excluded.length >
      0;
  const extensions = [
    extension(EXT.basicConstraints, true, basicConstraintsValue(true, 0)),
    extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign", "cRLSign"])),
    ...(constrained && input.nameConstraints !== undefined
      ? [
          extension(
            EXT.nameConstraints,
            true,
            encodeNameConstraints(input.nameConstraints),
          ),
        ]
      : []),
    ...(input.extendedKeyUsage !== undefined &&
    input.extendedKeyUsage.length > 0
      ? [
          extension(
            EXT.extendedKeyUsage,
            false,
            extendedKeyUsageValue(input.extendedKeyUsage),
          ),
        ]
      : []),
    extension(
      EXT.subjectKeyIdentifier,
      false,
      keyIdentifierValue(keyIdentifierFromSpki(input.spkiDer)),
    ),
  ];
  const info = seq(
    smallInteger(0),
    input.subjectDer,
    input.spkiDer,
    tlv(0xa0, seq(oid(EXT.extensionRequest), set(seq(...extensions)))),
  );
  const signature = await input.sign(info);
  return seq(
    info,
    caSignatureAlgorithmIdentifier(input.keyAlgorithm),
    bitString(signature),
  );
};

export interface RawCsrAttribute {
  readonly oid: string;
  readonly values: readonly Tlv[];
}

export interface RawCsr {
  readonly der: Buffer;
  /** The signed CertificationRequestInfo. */
  readonly infoDer: Buffer;
  readonly version: number;
  readonly subjectDer: Buffer;
  readonly spkiDer: Buffer;
  readonly attributes: readonly RawCsrAttribute[];
  readonly signatureAlgorithm: AlgorithmIdentifierParts;
  readonly signature: Buffer;
}

/** Splits a DER CertificationRequest into its parts. Throws DerError when it is malformed. */
export const parseRawCsr = (input: Uint8Array): RawCsr => {
  const der = Buffer.from(input);
  try {
    const root = parseDer(der);
    expectTag(root, TAG.sequence, "a CertificationRequest");
    const [info, algorithm, signatureBits, ...extra] = children(root);
    if (
      info === undefined ||
      algorithm === undefined ||
      signatureBits === undefined ||
      extra.length > 0
    ) {
      throw new DerError("Malformed CertificationRequest.");
    }
    expectTag(info, TAG.sequence, "a CertificationRequestInfo");
    expectTag(signatureBits, TAG.bitString, "a signature");
    if (signatureBits.value[0] !== 0 || signatureBits.value.length < 2) {
      throw new DerError("Malformed signature BIT STRING.");
    }
    AsnConvert.parse(der, CertificationRequest);
    const [version, subject, spki, attributes, ...rest] = children(info);
    if (
      version === undefined ||
      subject === undefined ||
      spki === undefined ||
      rest.length > 0
    ) {
      throw new DerError("Malformed CertificationRequestInfo.");
    }
    expectTag(subject, TAG.sequence, "a subject");
    expectTag(spki, TAG.sequence, "a SubjectPublicKeyInfo");
    if (attributes !== undefined && attributes.tag !== 0xa0) {
      throw new DerError("Malformed CSR attributes.");
    }
    return {
      der,
      infoDer: info.raw,
      version: parseInt(decodeUnsignedInteger(version).toString("hex"), 16),
      subjectDer: subject.raw,
      spkiDer: spki.raw,
      attributes: (attributes === undefined ? [] : children(attributes)).map(
        (attribute) => {
          expectTag(attribute, TAG.sequence, "an Attribute");
          const [type, values, ...more] = children(attribute);
          if (type === undefined || values === undefined || more.length > 0) {
            throw new DerError("Malformed Attribute.");
          }
          expectTag(values, TAG.set, "attribute values");
          return { oid: decodeOid(type), values: children(values) };
        },
      ),
      signatureAlgorithm: parseAlgorithmIdentifier(algorithm),
      signature: signatureBits.value.subarray(1),
    };
  } catch (error) {
    throw error instanceof DerError ? error : new DerError("Malformed CSR.");
  }
};
