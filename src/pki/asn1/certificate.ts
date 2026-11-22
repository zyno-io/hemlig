import { createHash, randomBytes } from "node:crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import type { KeyUsageName, NameConstraintSet } from "../types";
import {
  caSignatureAlgorithmIdentifier,
  describePublicKey,
  parseAlgorithmIdentifier,
  pkiKeyAlgorithm,
  verifySignature,
  type AlgorithmIdentifierParts,
} from "./algorithms";
import {
  bitString,
  children,
  decodeTime,
  decodeVersion,
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
  basicConstraintsValue,
  certificatePoliciesValue,
  decodeAuthorityKeyIdentifier,
  decodeBasicConstraints,
  decodeExtendedKeyUsage,
  decodeExtensions,
  decodeKeyIdentifier,
  decodeKeyUsage,
  extendedKeyUsageValue,
  extension,
  EXT,
  keyIdentifierFromSpki,
  keyIdentifierValue,
  keyUsageValue,
  type RawExtension,
} from "./extensions";
import {
  decodeNameConstraintsDetailed,
  encodeNameConstraints,
  encodeSubjectAltName,
  type SubjectAltNameInput,
} from "./names";

/** Extensions a relying party is expected to understand when critical (see "Activation", check 5). */
const recognizedCritical = new Set<string>([
  EXT.basicConstraints,
  EXT.keyUsage,
  EXT.extendedKeyUsage,
  EXT.subjectAltName,
  EXT.subjectKeyIdentifier,
  EXT.authorityKeyIdentifier,
  EXT.nameConstraints,
  EXT.certificatePolicies,
]);

export const policyExtensions: readonly string[] = [
  EXT.policyConstraints,
  EXT.inhibitAnyPolicy,
  EXT.policyMappings,
];

export interface ParsedCertificate {
  readonly der: Buffer;
  readonly tbsDer: Buffer;
  readonly issuerDer: Buffer;
  readonly subjectDer: Buffer;
  readonly spkiDer: Buffer;
  /** Lowercase hex of the serial's content octets without sign padding. */
  readonly serialHex: string;
  readonly version: number;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly signatureAlgorithm: AlgorithmIdentifierParts;
  /** The AlgorithmIdentifier inside the TBSCertificate. */
  readonly tbsSignatureAlgorithm: AlgorithmIdentifierParts;
  readonly signature: Buffer;
  readonly extensions: readonly RawExtension[];
  readonly basicConstraints?: {
    ca: boolean;
    pathLen?: number;
    critical: boolean;
  };
  readonly keyUsage?: KeyUsageName[];
  readonly keyUsageCritical?: boolean;
  readonly extendedKeyUsage?: string[];
  readonly subjectKeyIdentifier?: Buffer;
  readonly authorityKeyIdentifier?: Buffer;
  readonly authorityCertIssuer?: { tag: number; value: Buffer }[];
  readonly authorityCertSerialHex?: string;
  /** NameConstraints carry a GeneralName form Hemlig does not enforce (directoryName, rfc822Name, ...). */
  readonly nameConstraintsUnsupported: boolean;
  readonly nameConstraints?: NameConstraintSet;
  readonly fingerprint: string;
  readonly spkiSha256: string;
  /** OIDs of critical extensions outside the recognized set. */
  readonly unrecognizedCritical: string[];
}

export const sha256Hex = (value: Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

/** Parses one DER certificate. Throws DerError when it is malformed. */
export const parseCertificate = (input: Uint8Array): ParsedCertificate => {
  const der = Buffer.from(input);
  try {
    const root = parseDer(der);
    expectTag(root, TAG.sequence, "a Certificate");
    const [tbs, outerAlgorithm, signatureBits, ...extra] = children(root);
    if (
      tbs === undefined ||
      outerAlgorithm === undefined ||
      signatureBits === undefined ||
      extra.length > 0
    ) {
      throw new DerError("Malformed Certificate.");
    }
    expectTag(tbs, TAG.sequence, "a TBSCertificate");
    expectTag(signatureBits, TAG.bitString, "a signature");
    if (signatureBits.value[0] !== 0 || signatureBits.value.length < 2) {
      throw new DerError("Malformed signature BIT STRING.");
    }
    // The typed schema parse rejects structures the light walk below would tolerate.
    AsnConvert.parse(der, Certificate);

    const fields = children(tbs);
    let index = 0;
    let version = 0;
    if (fields[0]?.tag === 0xa0) {
      const [inner, ...more] = children(fields[0]);
      if (inner === undefined || more.length > 0) {
        throw new DerError("Malformed version.");
      }
      version = decodeVersion(inner, [0, 1, 2]);
      index = 1;
    }
    const serial = fields[index];
    const tbsAlgorithm = fields[index + 1];
    const issuer = fields[index + 2];
    const validity = fields[index + 3];
    const subject = fields[index + 4];
    const spki = fields[index + 5];
    if (
      serial === undefined ||
      tbsAlgorithm === undefined ||
      issuer === undefined ||
      validity === undefined ||
      subject === undefined ||
      spki === undefined
    ) {
      throw new DerError("Truncated TBSCertificate.");
    }
    const [notBefore, notAfter, ...rest] = children(validity);
    if (notBefore === undefined || notAfter === undefined || rest.length > 0) {
      throw new DerError("Malformed Validity.");
    }
    expectTag(serial, TAG.integer, "a serial number");
    expectTag(issuer, TAG.sequence, "an issuer");
    expectTag(subject, TAG.sequence, "a subject");
    expectTag(spki, TAG.sequence, "a SubjectPublicKeyInfo");

    let extensions: RawExtension[] = [];
    // Optional trailing fields, each at most once and in order: [1] issuerUniqueID, [2] subjectUniqueID, [3]
    // extensions. Nothing may follow the extensions.
    let lastTag = 0;
    for (const field of fields.slice(index + 6)) {
      if (field.tag < 0xa1 || field.tag > 0xa3 || field.tag <= lastTag) {
        throw new DerError("Unexpected TBSCertificate field.");
      }
      lastTag = field.tag;
      if (field.tag === 0xa3) {
        const [container, ...more] = children(field);
        if (container === undefined || more.length > 0) {
          throw new DerError("Malformed extensions.");
        }
        extensions = decodeExtensions(container);
      }
    }

    const find = (oidValue: string): RawExtension | undefined =>
      extensions.find((item) => item.oid === oidValue);
    const bc = find(EXT.basicConstraints);
    const ku = find(EXT.keyUsage);
    const eku = find(EXT.extendedKeyUsage);
    const ski = find(EXT.subjectKeyIdentifier);
    const aki = find(EXT.authorityKeyIdentifier);
    const nc = find(EXT.nameConstraints);
    const akiParts =
      aki === undefined ? undefined : decodeAuthorityKeyIdentifier(aki.value);
    const ncParts =
      nc === undefined ? undefined : decodeNameConstraintsDetailed(nc.value);
    return {
      der,
      tbsDer: tbs.raw,
      issuerDer: issuer.raw,
      subjectDer: subject.raw,
      spkiDer: spki.raw,
      serialHex: decodeUnsignedInteger(serial).toString("hex"),
      version,
      notBefore: decodeTime(notBefore),
      notAfter: decodeTime(notAfter),
      signatureAlgorithm: parseAlgorithmIdentifier(outerAlgorithm),
      tbsSignatureAlgorithm: parseAlgorithmIdentifier(tbsAlgorithm),
      signature: signatureBits.value.subarray(1),
      extensions,
      basicConstraints:
        bc === undefined
          ? undefined
          : { ...decodeBasicConstraints(bc.value), critical: bc.critical },
      keyUsage: ku === undefined ? undefined : decodeKeyUsage(ku.value),
      keyUsageCritical: ku?.critical,
      extendedKeyUsage:
        eku === undefined ? undefined : decodeExtendedKeyUsage(eku.value),
      subjectKeyIdentifier:
        ski === undefined ? undefined : decodeKeyIdentifier(ski.value),
      authorityKeyIdentifier: akiParts?.keyIdentifier,
      authorityCertIssuer: akiParts?.authorityCertIssuer,
      authorityCertSerialHex: akiParts?.authorityCertSerialHex,
      nameConstraints: ncParts?.constraints,
      nameConstraintsUnsupported: ncParts?.unsupported ?? false,
      fingerprint: sha256Hex(der),
      spkiSha256: sha256Hex(spki.raw),
      unrecognizedCritical: extensions
        .filter((item) => item.critical && !recognizedCritical.has(item.oid))
        .map((item) => item.oid),
    };
  } catch (error) {
    throw error instanceof DerError
      ? error
      : new DerError("Malformed certificate.");
  }
};

/** True when the certificate's signature, and its inner/outer algorithm match, verify under `issuerSpkiDer`. */
export const verifyCertificateSignature = (
  certificate: ParsedCertificate,
  issuerSpkiDer: Uint8Array,
): boolean =>
  certificate.signatureAlgorithm.raw.equals(
    certificate.tbsSignatureAlgorithm.raw,
  ) &&
  verifySignature(
    issuerSpkiDer,
    certificate.signatureAlgorithm,
    certificate.tbsDer,
    certificate.signature,
  );

// ---------------------------------------------------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------------------------------------------------

/** 20 random bytes with the top bit cleared and a non-zero first byte: positive, about 159 bits. */
export const generateSerial = (): Buffer => {
  for (;;) {
    const serial = randomBytes(20);
    serial[0] = (serial[0] as number) & 0x7f;
    // A zero first byte would be dropped from the minimal INTEGER encoding, so the stored hex (and the CRL entry
    // and parsed forms) would differ from the generated one. Keep one canonical 20-byte form.
    if (serial[0] !== 0) {
      return serial;
    }
  }
};

export interface TbsCertificateInput {
  /** Unsigned big-endian serial. */
  readonly serial: Uint8Array;
  /** DER AlgorithmIdentifier; must equal the one used for the outer signature. */
  readonly signatureAlgorithm: Uint8Array;
  /** Byte-exact copy of the issuer's subject Name. */
  readonly issuerDer: Uint8Array;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly subjectDer: Uint8Array;
  readonly spkiDer: Uint8Array;
  /** Complete Extension encodings. */
  readonly extensions: readonly Uint8Array[];
}

/** A v3 TBSCertificate. The issuer bytes are spliced in untouched. */
export const buildTbsCertificate = (input: TbsCertificateInput): Buffer =>
  seq(
    explicit(0, smallInteger(2)),
    unsignedInteger(input.serial),
    input.signatureAlgorithm,
    input.issuerDer,
    seq(encodeTime(input.notBefore), encodeTime(input.notAfter)),
    input.subjectDer,
    input.spkiDer,
    ...(input.extensions.length > 0
      ? [explicit(3, seq(...input.extensions))]
      : []),
  );

/** Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }. */
export const assembleCertificate = (
  tbs: Uint8Array,
  signatureAlgorithm: Uint8Array,
  signature: Uint8Array,
): Buffer => seq(tbs, signatureAlgorithm, bitString(signature));

export interface IssuedTbsInput {
  /** The issuing CA certificate: supplies the issuer DN bytes, the AKI and the signature algorithm. */
  readonly issuer: ParsedCertificate;
  readonly serial: Uint8Array;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly subjectDer: Uint8Array;
  readonly spkiDer: Uint8Array;
}

export interface LeafTbsInput extends IssuedTbsInput {
  readonly keyUsage: readonly KeyUsageName[];
  /** Always present on a Hemlig leaf. */
  readonly extendedKeyUsage: readonly string[];
  readonly san: SubjectAltNameInput;
  /** True when the subject Name has no RDNs: SubjectAltName must then exist and is critical. */
  readonly subjectEmpty: boolean;
  readonly policies?: readonly string[];
}

export interface BuiltTbs {
  readonly tbs: Buffer;
  readonly signatureAlgorithm: Buffer;
}

const issuerParameters = (
  issuer: ParsedCertificate,
): { signatureAlgorithm: Buffer; authorityKeyId: Buffer } => {
  const algorithm = pkiKeyAlgorithm(describePublicKey(issuer.spkiDer));
  if (algorithm === undefined) {
    throw new Error("The issuer key is not a supported CA key.");
  }
  if (issuer.subjectKeyIdentifier === undefined) {
    throw new Error("The issuer certificate has no SubjectKeyIdentifier.");
  }
  return {
    signatureAlgorithm: caSignatureAlgorithmIdentifier(algorithm),
    authorityKeyId: issuer.subjectKeyIdentifier,
  };
};

/**
 * The leaf profile from "Extensions Hemlig builds (leaf)": BasicConstraints (critical, cA=false), KeyUsage (critical),
 * ExtendedKeyUsage, SubjectAltName (critical only for an empty subject), SKI (RFC 7093 method 1), AKI (the issuer's
 * SKI) and optional CertificatePolicies. The issuer DN is copied byte-exact from the issuer certificate.
 */
export const buildLeafTbs = (input: LeafTbsInput): BuiltTbs => {
  const { signatureAlgorithm, authorityKeyId } = issuerParameters(input.issuer);
  const hasSan =
    (input.san.dns?.length ?? 0) +
      (input.san.ip?.length ?? 0) +
      (input.san.uri?.length ?? 0) >
    0;
  if (input.subjectEmpty && !hasSan) {
    throw new Error(
      "A certificate with an empty subject needs a SubjectAltName.",
    );
  }
  if (input.keyUsage.length === 0 || input.extendedKeyUsage.length === 0) {
    throw new Error("A leaf always carries KeyUsage and ExtendedKeyUsage.");
  }
  const extensions = [
    extension(EXT.basicConstraints, true, basicConstraintsValue(false)),
    extension(EXT.keyUsage, true, keyUsageValue(input.keyUsage)),
    extension(
      EXT.extendedKeyUsage,
      false,
      extendedKeyUsageValue(input.extendedKeyUsage),
    ),
    ...(hasSan
      ? [
          extension(
            EXT.subjectAltName,
            input.subjectEmpty,
            encodeSubjectAltName(input.san),
          ),
        ]
      : []),
    extension(
      EXT.subjectKeyIdentifier,
      false,
      keyIdentifierValue(keyIdentifierFromSpki(input.spkiDer)),
    ),
    extension(
      EXT.authorityKeyIdentifier,
      false,
      authorityKeyIdentifierValue(authorityKeyId),
    ),
    ...(input.policies !== undefined && input.policies.length > 0
      ? [
          extension(
            EXT.certificatePolicies,
            false,
            certificatePoliciesValue(input.policies),
          ),
        ]
      : []),
  ];
  return {
    signatureAlgorithm,
    tbs: buildTbsCertificate({
      serial: input.serial,
      signatureAlgorithm,
      issuerDer: input.issuer.subjectDer,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      subjectDer: input.subjectDer,
      spkiDer: input.spkiDer,
      extensions,
    }),
  };
};

export interface CaTbsInput extends IssuedTbsInput {
  readonly pathLen: number;
  readonly nameConstraints?: NameConstraintSet;
  readonly extendedKeyUsage?: readonly string[];
}

/** A subordinate CA certificate: critical BasicConstraints and KeyUsage keyCertSign+cRLSign, SKI and AKI. */
export const buildCaTbs = (input: CaTbsInput): BuiltTbs => {
  const { signatureAlgorithm, authorityKeyId } = issuerParameters(input.issuer);
  const constrained =
    input.nameConstraints !== undefined &&
    input.nameConstraints.permitted.length +
      input.nameConstraints.excluded.length >
      0;
  const extensions = [
    extension(
      EXT.basicConstraints,
      true,
      basicConstraintsValue(true, input.pathLen),
    ),
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
    extension(
      EXT.authorityKeyIdentifier,
      false,
      authorityKeyIdentifierValue(authorityKeyId),
    ),
  ];
  return {
    signatureAlgorithm,
    tbs: buildTbsCertificate({
      serial: input.serial,
      signatureAlgorithm,
      issuerDer: input.issuer.subjectDer,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      subjectDer: input.subjectDer,
      spkiDer: input.spkiDer,
      extensions,
    }),
  };
};
