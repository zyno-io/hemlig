import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificationRequest } from "@peculiar/asn1-csr";
import { Certificate, CertificateList } from "@peculiar/asn1-x509";
import {
  bigUint,
  bitString,
  bool,
  children,
  decodeBitString,
  decodeBool,
  decodeOid,
  decodeSmallInt,
  decodeTime,
  decodeUint,
  DerError,
  enumerated,
  explicit,
  extension,
  implicitPrimitive,
  nullValue,
  oid,
  octetString,
  parseDer,
  seq,
  smallInt,
  TAG,
  time,
  uint,
  generalizedTime,
  type Tlv,
} from "./ez-der";
import { EzError } from "./ez-error";
import {
  assertRestrictedName,
  describeName,
  formatIp,
  isIdentityRootName,
  parseCidr,
  encodeSubject,
  type RestrictedName,
  type Subject,
} from "./ez-name";

/**
 * X.509 encoding, parsing and profile checks for the EZ offline root. MIT, independent of the server's AGPL
 * implementation, and deliberately free of any import of `@zyno-io/hemlig-client`.
 */

export const OID = {
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  sha256WithRsa: "1.2.840.113549.1.1.11",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  rsaPss: "1.2.840.113549.1.1.10",
  ed25519: "1.3.101.112",
  extensionRequest: "1.2.840.113549.1.9.14",
  ski: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  issuerAltName: "2.5.29.18",
  basicConstraints: "2.5.29.19",
  crlNumber: "2.5.29.20",
  reasonCode: "2.5.29.21",
  invalidityDate: "2.5.29.24",
  deltaCrlIndicator: "2.5.29.27",
  issuingDistributionPoint: "2.5.29.28",
  certificateIssuer: "2.5.29.29",
  nameConstraints: "2.5.29.30",
  crlDistributionPoints: "2.5.29.31",
  certificatePolicies: "2.5.29.32",
  policyMappings: "2.5.29.33",
  aki: "2.5.29.35",
  policyConstraints: "2.5.29.36",
  extendedKeyUsage: "2.5.29.37",
  freshestCrl: "2.5.29.46",
  inhibitAnyPolicy: "2.5.29.54",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  clientAuth: "1.3.6.1.5.5.7.3.2",
} as const;

const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
export const floorSeconds = (date: Date): Date => new Date(Math.floor(date.getTime() / 1000) * 1000);
export const sha256Hex = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

// ---------------------------------------------------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------------------------------------------------

/** Key types EZ can generate for a new root. */
export type EzKeyAlgorithm = "ECDSA_P384" | "ECDSA_P256" | "RSA_3072" | "RSA_4096";
export const EZ_KEY_ALGORITHMS: readonly EzKeyAlgorithm[] = ["ECDSA_P384", "ECDSA_P256", "RSA_3072", "RSA_4096"];

export interface SignatureAlgorithm {
  readonly name: string;
  readonly oid: string;
  /** The digest passed to `crypto.sign`, or null for Ed25519. */
  readonly hash: "sha256" | "sha384" | "sha512" | null;
  readonly keyType: "ec" | "rsa" | "ed25519";
  /** DER AlgorithmIdentifier. ECDSA and Ed25519 carry no parameters; RSA carries NULL. */
  readonly algorithmIdentifier: Buffer;
}

const defineAlgorithm = (
  name: string,
  algorithmOid: string,
  hash: SignatureAlgorithm["hash"],
  keyType: SignatureAlgorithm["keyType"],
): SignatureAlgorithm => ({
  name,
  oid: algorithmOid,
  hash,
  keyType,
  algorithmIdentifier:
    keyType === "rsa" ? seq(oid(algorithmOid), nullValue()) : seq(oid(algorithmOid)),
});

export const SIGNATURE_ALGORITHMS: Readonly<Record<string, SignatureAlgorithm>> = Object.fromEntries(
  [
    defineAlgorithm("ecdsa-with-SHA256", OID.ecdsaSha256, "sha256", "ec"),
    defineAlgorithm("ecdsa-with-SHA384", OID.ecdsaSha384, "sha384", "ec"),
    defineAlgorithm("ecdsa-with-SHA512", OID.ecdsaSha512, "sha512", "ec"),
    defineAlgorithm("sha256WithRSAEncryption", OID.sha256WithRsa, "sha256", "rsa"),
    defineAlgorithm("sha384WithRSAEncryption", OID.sha384WithRsa, "sha384", "rsa"),
    defineAlgorithm("sha512WithRSAEncryption", OID.sha512WithRsa, "sha512", "rsa"),
    defineAlgorithm("Ed25519", OID.ed25519, null, "ed25519"),
  ].map((a) => [a.oid, a]),
);

/** Parses an AlgorithmIdentifier (DER) into a supported, non-PSS signature algorithm; undefined otherwise. */
export const parseSignatureAlgorithm = (algorithmIdentifier: Buffer): SignatureAlgorithm | undefined => {
  try {
    const root = parseDer(algorithmIdentifier);
    if (root.tag !== TAG.sequence) return undefined;
    const [id, params, ...extra] = children(root);
    if (id === undefined || extra.length > 0) return undefined;
    const algorithm = SIGNATURE_ALGORITHMS[decodeOid(id)];
    if (algorithm === undefined) return undefined;
    if (algorithm.keyType === "rsa") {
      if (params !== undefined && (params.tag !== TAG.null || params.value.length !== 0)) return undefined;
    } else if (params !== undefined) {
      return undefined;
    }
    return algorithm;
  } catch {
    return undefined;
  }
};

export interface KeyInfo {
  /** `ECDSA_P256`, `ECDSA_P384`, `ECDSA_P521`, `RSA_<bits>` or `ED25519`. */
  readonly algorithm: string;
  readonly keyType: "ec" | "rsa" | "ed25519";
  /** Byte length of one ECDSA coordinate (for raw r||s signatures). */
  readonly coordinateLength?: number;
}

export const describeSpki = (spkiDer: Buffer): KeyInfo => {
  let key;
  try {
    key = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  } catch {
    throw new EzError(2, "key_invalid", "The public key could not be parsed.");
  }
  const details = key.asymmetricKeyDetails ?? {};
  if (key.asymmetricKeyType === "ec") {
    const curves: Record<string, [string, number]> = {
      prime256v1: ["ECDSA_P256", 32],
      secp384r1: ["ECDSA_P384", 48],
      secp521r1: ["ECDSA_P521", 66],
    };
    const curve = curves[details.namedCurve ?? ""];
    if (curve === undefined) throw new EzError(2, "key_invalid", "Unsupported elliptic curve.");
    return { algorithm: curve[0], keyType: "ec", coordinateLength: curve[1] };
  }
  if (key.asymmetricKeyType === "rsa") {
    return { algorithm: `RSA_${details.modulusLength ?? 0}`, keyType: "rsa" };
  }
  if (key.asymmetricKeyType === "ed25519") return { algorithm: "ED25519", keyType: "ed25519" };
  throw new EzError(2, "key_invalid", "Unsupported public key type.");
};

/** The signature algorithm EZ uses when signing with this key. */
export const signatureAlgorithmForSpki = (spkiDer: Buffer): SignatureAlgorithm => {
  const info = describeSpki(spkiDer);
  const pick = (algorithmOid: string): SignatureAlgorithm => SIGNATURE_ALGORITHMS[algorithmOid] as SignatureAlgorithm;
  switch (info.algorithm) {
    case "ECDSA_P256":
      return pick(OID.ecdsaSha256);
    case "ECDSA_P384":
      return pick(OID.ecdsaSha384);
    case "ECDSA_P521":
      return pick(OID.ecdsaSha512);
    case "ED25519":
      return pick(OID.ed25519);
    default:
      return pick(OID.sha256WithRsa);
  }
};

/** True when `signature` is a valid signature over `data` by `spkiDer` under the AlgorithmIdentifier. Never throws. */
export const verifySignature = (
  spkiDer: Buffer,
  algorithmIdentifier: Buffer,
  data: Uint8Array,
  signature: Uint8Array,
): boolean => {
  try {
    const algorithm = parseSignatureAlgorithm(algorithmIdentifier);
    if (algorithm === undefined) return false;
    const key = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== algorithm.keyType) return false;
    return algorithm.keyType === "ec"
      ? cryptoVerify(algorithm.hash, data, { key, dsaEncoding: "der" }, signature)
      : cryptoVerify(algorithm.hash, data, key, signature);
  } catch {
    return false;
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------------------------------------------------

export const toPem = (der: Uint8Array, label: string): string =>
  `-----BEGIN ${label}-----\n${(Buffer.from(der).toString("base64").match(/.{1,64}/g) ?? []).join("\n")}\n-----END ${label}-----\n`;

/** Decodes exactly one PEM block with the given label. */
export const fromPem = (text: string, label: string): Buffer => {
  const blocks = [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g)];
  const only = blocks[0];
  if (blocks.length !== 1 || only === undefined || only[1] !== label) {
    throw new EzError(2, "pem_invalid", `Expected exactly one ${label} PEM block.`);
  }
  const body = (only[2] as string).replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length === 0) {
    throw new EzError(2, "pem_invalid", `The ${label} PEM block is not valid base64.`);
  }
  return Buffer.from(body, "base64");
};

// ---------------------------------------------------------------------------------------------------------------------
// Key identifiers, serials
// ---------------------------------------------------------------------------------------------------------------------

/** RFC 7093 method 1: the leftmost 160 bits of SHA-256 over the subjectPublicKey BIT STRING contents. */
export const keyIdentifier = (spkiDer: Buffer): Buffer => {
  const parts = children(parseDer(spkiDer));
  const bits = decodeBitString(parts[1] as Tlv);
  return createHash("sha256").update(bits.bytes).digest().subarray(0, 20);
};

/** 20 random bytes, top bit clear, first byte non-zero. */
export const randomSerial = (): Buffer => {
  for (;;) {
    const serial = randomBytes(20);
    serial[0] = (serial[0] as number) & 0x7f;
    if (serial[0] !== 0) return serial;
  }
};

/** Lowercase hex of the unsigned magnitude with leading zero bytes removed (the canonical serial text). */
export const serialHex = (magnitude: Uint8Array): string => {
  const hex = Buffer.from(magnitude).toString("hex").replace(/^(00)+(?=.)/, "");
  return hex === "" ? "00" : hex;
};

export const serialMagnitude = (hex: string): Buffer => {
  if (!/^[0-9a-f]+$/i.test(hex)) throw new EzError(2, "invalid_input", "A serial must be hexadecimal.");
  return Buffer.from(hex.length % 2 ? `0${hex}` : hex, "hex");
};

// ---------------------------------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------------------------------

export interface ParsedExtension {
  readonly oid: string;
  readonly critical: boolean;
  /** The DER inside the extnValue OCTET STRING. */
  readonly value: Buffer;
  /** The complete Extension TLV, for byte-for-byte copying. */
  readonly raw: Buffer;
}

const parseExtensions = (container: Tlv): ParsedExtension[] => {
  if (container.tag !== TAG.sequence) throw new DerError("Expected Extensions.");
  const seen = new Set<string>();
  return children(container).map((item) => {
    if (item.tag !== TAG.sequence) throw new DerError("Expected an Extension.");
    const [id, second, third, ...extra] = children(item);
    if (id === undefined || second === undefined || extra.length > 0) throw new DerError("Malformed Extension.");
    const critical = second.tag === TAG.boolean ? decodeBool(second) : false;
    const valueElement = second.tag === TAG.boolean ? third : second;
    if (valueElement === undefined || valueElement.tag !== TAG.octetString || (second.tag !== TAG.boolean && third !== undefined)) {
      throw new DerError("Malformed Extension value.");
    }
    const extensionOid = decodeOid(id);
    if (seen.has(extensionOid)) throw new DerError(`Duplicate extension ${extensionOid}.`);
    seen.add(extensionOid);
    return { oid: extensionOid, critical, value: valueElement.value, raw: item.raw };
  });
};

const signatureBytes = (element: Tlv | undefined): Buffer => {
  if (element === undefined) throw new DerError("Missing signature.");
  const { bytes, unusedBits } = decodeBitString(element);
  if (unusedBits !== 0) throw new DerError("A signature BIT STRING must have no unused bits.");
  return bytes;
};

export interface BasicConstraintsValue {
  readonly ca: boolean;
  readonly pathLen: number | undefined;
}

export const parseBasicConstraints = (value: Buffer): BasicConstraintsValue => {
  const root = parseDer(value);
  if (root.tag !== TAG.sequence) throw new DerError("Malformed BasicConstraints.");
  const parts = children(root);
  let index = 0;
  let ca = false;
  if (parts[index]?.tag === TAG.boolean) {
    ca = decodeBool(parts[index] as Tlv);
    index += 1;
  }
  let pathLen: number | undefined;
  if (parts[index]?.tag === TAG.integer) {
    pathLen = decodeSmallInt(parts[index] as Tlv);
    index += 1;
  }
  if (index !== parts.length) throw new DerError("Malformed BasicConstraints.");
  return { ca, pathLen };
};

/** Key usage bit positions per RFC 5280 (bit 0 is the most significant bit of the first byte). */
export const KEY_USAGE_BIT = { keyCertSign: 5, cRLSign: 6 } as const;

export const parseKeyUsageBits = (value: Buffer): Set<number> => {
  const { bytes, unusedBits } = decodeBitString(parseDer(value));
  const bits = new Set<number>();
  const total = bytes.length * 8 - unusedBits;
  for (let i = 0; i < total; i++) {
    if ((bytes[i >> 3] as number) & (0x80 >> (i & 7))) bits.add(i);
  }
  return bits;
};

export interface ParsedCertificate {
  readonly der: Buffer;
  readonly fingerprint: string;
  /** The signed TBSCertificate TLV, sliced from the input and never re-encoded. */
  readonly tbs: Buffer;
  readonly version: 1 | 2 | 3;
  readonly serialMagnitude: Buffer;
  readonly serialHex: string;
  /** AlgorithmIdentifier inside the TBS. */
  readonly innerAlgorithm: Buffer;
  /** AlgorithmIdentifier of the outer Certificate. */
  readonly outerAlgorithm: Buffer;
  readonly signature: Buffer;
  readonly issuerDer: Buffer;
  readonly subjectDer: Buffer;
  readonly spkiDer: Buffer;
  readonly spkiSha256: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly extensions: readonly ParsedExtension[];
  readonly subjectKeyIdentifier: Buffer | undefined;
  readonly authorityKeyIdentifier: Buffer | undefined;
}

const findExtension = (extensions: readonly ParsedExtension[], extensionOid: string): ParsedExtension | undefined =>
  extensions.find((e) => e.oid === extensionOid);

const parseAki = (value: Buffer): Buffer | undefined => {
  const root = parseDer(value);
  if (root.tag !== TAG.sequence) throw new DerError("Malformed AuthorityKeyIdentifier.");
  return children(root).find((c) => c.tag === 0x80)?.value;
};

const parseSki = (value: Buffer): Buffer => {
  const element = parseDer(value);
  if (element.tag !== TAG.octetString) throw new DerError("Malformed SubjectKeyIdentifier.");
  return element.value;
};

export const parseCertificate = (der: Buffer): ParsedCertificate => {
  const bad = (message: string): never => {
    throw new EzError(2, "certificate_invalid", message);
  };
  try {
    const root = parseDer(der);
    if (root.tag !== TAG.sequence) return bad("Not a certificate.");
    const [tbs, outerAlgorithm, signatureBits, ...extra] = children(root);
    if (tbs === undefined || outerAlgorithm === undefined || signatureBits === undefined || extra.length > 0) {
      return bad("Malformed certificate.");
    }
    if (tbs.tag !== TAG.sequence) return bad("Malformed TBSCertificate.");
    const fields = children(tbs);
    let index = 0;
    let version: 1 | 2 | 3 = 1;
    if (fields[index]?.tag === 0xa0) {
      const v = decodeSmallInt(children(fields[index] as Tlv)[0] as Tlv);
      if (v > 2) return bad("Unsupported certificate version.");
      version = (v + 1) as 1 | 2 | 3;
      index += 1;
    }
    const serial = decodeUint(fields[index++] as Tlv);
    const innerAlgorithm = fields[index++] as Tlv;
    const issuer = fields[index++] as Tlv;
    const validity = fields[index++] as Tlv;
    const subject = fields[index++] as Tlv;
    const spki = fields[index++] as Tlv;
    if (![innerAlgorithm, issuer, validity, subject, spki].every((e) => e !== undefined && e.tag === TAG.sequence)) {
      return bad("Malformed TBSCertificate.");
    }
    let extensions: ParsedExtension[] = [];
    for (; index < fields.length; index++) {
      const field = fields[index] as Tlv;
      if (field.tag === 0xa3) {
        if (version !== 3) return bad("Extensions in a pre-v3 certificate.");
        extensions = parseExtensions(children(field)[0] as Tlv);
      } else if (field.tag !== 0xa1 && field.tag !== 0xa2) {
        return bad("Unexpected TBSCertificate field.");
      }
    }
    const [notBefore, notAfter, ...rest] = children(validity);
    if (notBefore === undefined || notAfter === undefined || rest.length > 0) return bad("Malformed validity.");
    const skiExtension = findExtension(extensions, OID.ski);
    const akiExtension = findExtension(extensions, OID.aki);
    return {
      der,
      fingerprint: sha256Hex(der),
      tbs: tbs.raw,
      version,
      serialMagnitude: serial,
      serialHex: serialHex(serial),
      innerAlgorithm: innerAlgorithm.raw,
      outerAlgorithm: outerAlgorithm.raw,
      signature: signatureBytes(signatureBits),
      issuerDer: issuer.raw,
      subjectDer: subject.raw,
      spkiDer: spki.raw,
      spkiSha256: sha256Hex(spki.raw),
      notBefore: decodeTime(notBefore),
      notAfter: decodeTime(notAfter),
      extensions,
      subjectKeyIdentifier: skiExtension && parseSki(skiExtension.value),
      authorityKeyIdentifier: akiExtension && parseAki(akiExtension.value),
    };
  } catch (error) {
    if (error instanceof DerError) throw new EzError(2, "certificate_invalid", `Malformed certificate: ${error.message}`);
    // A truncated structure (an empty wrapper, a missing field) dereferences undefined: still malformed input.
    if (error instanceof TypeError || error instanceof RangeError) throw new EzError(2, "certificate_invalid", `Malformed certificate.`);
    throw error;
  }
};

/** Verifies a certificate's signature under the issuer's SPKI, using the outer algorithm. */
export const verifyCertificateSignature = (cert: ParsedCertificate, issuerSpki: Buffer): boolean =>
  verifySignature(issuerSpki, cert.outerAlgorithm, cert.tbs, cert.signature);

export type CrlReasonName =
  | "unspecified"
  | "keyCompromise"
  | "caCompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "certificateHold"
  | "privilegeWithdrawn"
  | "aACompromise";

const REASON_CODES: Readonly<Record<CrlReasonName, number>> = {
  unspecified: 0,
  keyCompromise: 1,
  caCompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  privilegeWithdrawn: 9,
  aACompromise: 10,
};
export const CRL_REASON_NAMES = Object.keys(REASON_CODES) as CrlReasonName[];
export const reasonName = (code: number): CrlReasonName | undefined =>
  (Object.entries(REASON_CODES).find(([, c]) => c === code)?.[0]) as CrlReasonName | undefined;

/** Reasons EZ may use for a new revocation. `certificateHold` and `removeFromCRL` never. */
export const NEW_REVOCATION_REASONS: readonly CrlReasonName[] = [
  "unspecified",
  "keyCompromise",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
];

export interface CrlEntry {
  /** Lowercase hex serial. */
  readonly serial: string;
  readonly revokedAt: Date;
  readonly reason?: CrlReasonName;
  readonly invalidityDate?: Date;
  /** Parsed CRLs only: the raw reason code (even one with no name) and the entry's extensions. */
  readonly reasonCode?: number;
  readonly extensions?: readonly ParsedExtension[];
}

export interface ParsedCrl {
  readonly der: Buffer;
  readonly sha256: string;
  readonly tbs: Buffer;
  readonly version: number | undefined;
  readonly innerAlgorithm: Buffer;
  readonly outerAlgorithm: Buffer;
  readonly signature: Buffer;
  readonly issuerDer: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | undefined;
  readonly entries: readonly CrlEntry[];
  readonly extensions: readonly ParsedExtension[];
  readonly number: bigint | undefined;
  readonly authorityKeyIdentifier: Buffer | undefined;
}

export const parseCrl = (der: Buffer): ParsedCrl => {
  const bad = (message: string): never => {
    throw new EzError(2, "crl_invalid", message);
  };
  try {
    const root = parseDer(der);
    const [tbs, outerAlgorithm, signatureBits, ...extra] = children(root);
    if (root.tag !== TAG.sequence || tbs === undefined || outerAlgorithm === undefined || signatureBits === undefined || extra.length > 0) {
      return bad("Malformed CRL.");
    }
    const fields = children(tbs);
    let index = 0;
    let version: number | undefined;
    if (fields[index]?.tag === TAG.integer) version = decodeSmallInt(fields[index++] as Tlv);
    const innerAlgorithm = fields[index++] as Tlv;
    const issuer = fields[index++] as Tlv;
    const thisUpdate = decodeTime(fields[index++] as Tlv);
    let nextUpdate: Date | undefined;
    if (fields[index]?.tag === TAG.utcTime || fields[index]?.tag === TAG.generalizedTime) {
      nextUpdate = decodeTime(fields[index++] as Tlv);
    }
    const entries: CrlEntry[] = [];
    if (fields[index]?.tag === TAG.sequence) {
      for (const item of children(fields[index++] as Tlv)) {
        const [serial, revoked, entryExtensions] = children(item);
        if (serial === undefined || revoked === undefined) return bad("Malformed CRL entry.");
        let reason: CrlReasonName | undefined;
        let invalidityDate: Date | undefined;
        let reasonCode: number | undefined;
        let parsedEntryExtensions: ParsedExtension[] = [];
        if (entryExtensions !== undefined) {
          parsedEntryExtensions = parseExtensions(entryExtensions);
          for (const e of parsedEntryExtensions) {
            if (e.oid === OID.reasonCode) {
              const code = parseDer(e.value);
              if (code.tag !== TAG.enumerated || code.value.length !== 1) return bad("Malformed reason code.");
              reasonCode = code.value[0] as number;
              reason = reasonName(reasonCode);
            } else if (e.oid === OID.invalidityDate) {
              invalidityDate = decodeTime(parseDer(e.value));
            }
          }
        }
        entries.push({ serial: serialHex(decodeUint(serial)), revokedAt: decodeTime(revoked), reason, invalidityDate, reasonCode, extensions: parsedEntryExtensions });
      }
    }
    let extensions: ParsedExtension[] = [];
    if (fields[index]?.tag === 0xa0) extensions = parseExtensions(children(fields[index++] as Tlv)[0] as Tlv);
    if (index !== fields.length || innerAlgorithm === undefined || issuer === undefined) return bad("Malformed TBSCertList.");
    const numberExtension = findExtension(extensions, OID.crlNumber);
    const akiExtension = findExtension(extensions, OID.aki);
    return {
      der,
      sha256: sha256Hex(der),
      tbs: tbs.raw,
      version,
      innerAlgorithm: innerAlgorithm.raw,
      outerAlgorithm: outerAlgorithm.raw,
      signature: signatureBytes(signatureBits),
      issuerDer: issuer.raw,
      thisUpdate,
      nextUpdate,
      entries,
      extensions,
      number: numberExtension && BigInt(`0x${decodeUint(parseDer(numberExtension.value)).toString("hex")}`),
      authorityKeyIdentifier: akiExtension && parseAki(akiExtension.value),
    };
  } catch (error) {
    if (error instanceof DerError) throw new EzError(2, "crl_invalid", `Malformed CRL: ${error.message}`);
    // A truncated structure (an empty wrapper, a missing field) dereferences undefined: still malformed input.
    if (error instanceof TypeError || error instanceof RangeError) throw new EzError(2, "crl_invalid", `Malformed CRL.`);
    throw error;
  }
};

export const verifyCrlSignature = (crl: ParsedCrl, issuerSpki: Buffer): boolean =>
  verifySignature(issuerSpki, crl.outerAlgorithm, crl.tbs, crl.signature);

// ---------------------------------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------------------------------

const basicConstraintsValue = (pathLen: number | undefined): Buffer =>
  seq(bool(true), ...(pathLen === undefined ? [] : [smallInt(pathLen)]));
/** keyCertSign | cRLSign: bits 5 and 6, one unused bit. */
const CA_KEY_USAGE_VALUE = bitString(Buffer.from([0x06]), 1);

export interface RootTemplate {
  /** The root's Name, DER. It is used verbatim as both issuer and subject. */
  readonly subjectDer: Buffer;
  readonly spkiDer: Buffer;
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly notBefore: Date;
  readonly notAfter: Date;
  /** Omitted by default (no limit). A value must be at least 1. */
  readonly pathLen?: number;
  readonly serial?: Buffer;
  /** Defaults to RFC 7093 method 1; a re-issued root keeps its original value. */
  readonly subjectKeyIdentifier?: Buffer;
}

export interface BuiltTbs {
  readonly tbs: Buffer;
  /** The AlgorithmIdentifier that must be used for the outer signatureAlgorithm (same buffer as inside the TBS). */
  readonly algorithmIdentifier: Buffer;
}

export interface BuiltRootTbs extends BuiltTbs {
  readonly serialHex: string;
  readonly subjectKeyIdentifier: Buffer;
}

/** Self-signed root profile: v3, critical BC CA:TRUE, critical KU keyCertSign|cRLSign, SKI; no AKI, NC, EKU or policies. */
export const buildRootTbs = (template: RootTemplate): BuiltRootTbs => {
  if (template.pathLen !== undefined && (!Number.isInteger(template.pathLen) || template.pathLen < 1)) {
    throw new EzError(2, "invalid_input", "pathLen must be at least 1 for a root.");
  }
  assertValidity(template.notBefore, template.notAfter);
  const serial = template.serial ?? randomSerial();
  const ski = template.subjectKeyIdentifier ?? keyIdentifier(template.spkiDer);
  const algorithmIdentifier = template.signatureAlgorithm.algorithmIdentifier;
  const tbs = seq(
    explicit(0, smallInt(2)),
    uint(serial),
    algorithmIdentifier,
    template.subjectDer,
    seq(time(template.notBefore), time(template.notAfter)),
    template.subjectDer,
    template.spkiDer,
    explicit(
      3,
      seq(
        extension(OID.basicConstraints, true, basicConstraintsValue(template.pathLen)),
        extension(OID.keyUsage, true, CA_KEY_USAGE_VALUE),
        extension(OID.ski, false, octetString(ski)),
      ),
    ),
  );
  return { tbs, algorithmIdentifier, serialHex: serialHex(serial), subjectKeyIdentifier: ski };
};

const assertValidity = (notBefore: Date, notAfter: Date): void => {
  if (notBefore.getTime() % 1000 !== 0 || notAfter.getTime() % 1000 !== 0) {
    throw new EzError(2, "invalid_input", "Validity times must be whole seconds.");
  }
  if (!(notAfter.getTime() > notBefore.getTime())) {
    throw new EzError(2, "invalid_input", "notAfter must be after notBefore.");
  }
};

export interface IssuerReference {
  /** The root's subject Name, DER (used verbatim as the issuer). */
  readonly subjectDer: Buffer;
  readonly subjectKeyIdentifier: Buffer;
}

export interface IntermediateTemplate {
  readonly root: IssuerReference;
  readonly csr: ValidatedCsr;
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly serial?: Buffer;
}

export interface BuiltIntermediateTbs extends BuiltTbs {
  readonly serialHex: string;
}

const akiValue = (ski: Buffer): Buffer => seq(implicitPrimitive(0, ski));

/**
 * Intermediate profile: the CSR's requested extensions byte for byte (already validated), then AKI keyIdentifier equal
 * to the root's SKI. Subject and SPKI are the CSR's bytes; the issuer is the root's subject bytes.
 */
export const buildIntermediateTbs = (template: IntermediateTemplate): BuiltIntermediateTbs => {
  assertValidity(template.notBefore, template.notAfter);
  const serial = template.serial ?? randomSerial();
  const algorithmIdentifier = template.signatureAlgorithm.algorithmIdentifier;
  const tbs = seq(
    explicit(0, smallInt(2)),
    uint(serial),
    algorithmIdentifier,
    template.root.subjectDer,
    seq(time(template.notBefore), time(template.notAfter)),
    template.csr.subjectDer,
    template.csr.spkiDer,
    explicit(
      3,
      seq(...template.csr.extensions, extension(OID.aki, false, akiValue(template.root.subjectKeyIdentifier))),
    ),
  );
  return { tbs, algorithmIdentifier, serialHex: serialHex(serial) };
};

export interface IntermediateValidity {
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/**
 * notBefore = max(now - 1 h, root.notBefore); notAfter = min(now + days, root.notAfter). Refuses when the root is not yet
 * valid or less than `minimumDays` (default 90) remain after clamping.
 */
export const computeIntermediateValidity = (input: {
  readonly now: Date;
  readonly days: number;
  readonly root: { readonly notBefore: Date; readonly notAfter: Date };
  readonly minimumDays?: number;
}): IntermediateValidity => {
  const now = floorSeconds(input.now);
  if (input.root.notBefore.getTime() > now.getTime()) {
    throw new EzError(5, "root_not_valid", "The root certificate is not yet valid.");
  }
  if (input.root.notAfter.getTime() <= now.getTime()) {
    throw new EzError(5, "root_not_valid", "The root certificate has expired.");
  }
  const notBefore = new Date(Math.max(now.getTime() - HOUR_MS, input.root.notBefore.getTime()));
  const notAfter = new Date(Math.min(now.getTime() + input.days * DAY_MS, input.root.notAfter.getTime()));
  const minimum = input.minimumDays ?? 90;
  if (notAfter.getTime() - now.getTime() < minimum * DAY_MS) {
    throw new EzError(5, "validity_too_short", `Less than ${minimum} days of validity would remain after the root's notAfter clamp.`, {
      notAfter: notAfter.toISOString(),
    });
  }
  return { notBefore, notAfter };
};

export const assembleCertificate = (tbs: Buffer, algorithmIdentifier: Buffer, signature: Uint8Array): Buffer =>
  seq(tbs, algorithmIdentifier, bitString(signature));

export interface CrlTemplate {
  readonly issuer: IssuerReference;
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly number: bigint;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
  readonly entries: readonly CrlEntry[];
}

export const MAX_CRL_VALIDITY_MS = 400 * DAY_MS;

/** CRL profile: v2, AKI keyid + CRLNumber, entries sorted by serial, reason code omitted for `unspecified`. */
export const buildCrlTbs = (template: CrlTemplate): BuiltTbs => {
  assertValidity(template.thisUpdate, template.nextUpdate);
  if (template.nextUpdate.getTime() - template.thisUpdate.getTime() > MAX_CRL_VALIDITY_MS) {
    throw new EzError(2, "invalid_input", "A CRL may not be valid for more than 400 days.");
  }
  if (template.number < 1n || template.number >= 1n << 159n) {
    throw new EzError(2, "invalid_input", "CRL number out of range.");
  }
  const sorted = [...template.entries].sort((a, b) => {
    const x = BigInt(`0x${a.serial}`);
    const y = BigInt(`0x${b.serial}`);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  for (let i = 1; i < sorted.length; i++) {
    if (BigInt(`0x${(sorted[i] as CrlEntry).serial}`) === BigInt(`0x${(sorted[i - 1] as CrlEntry).serial}`)) {
      throw new EzError(2, "invalid_input", "Duplicate serial in the CRL entries.");
    }
  }
  const algorithmIdentifier = template.signatureAlgorithm.algorithmIdentifier;
  const entryTlvs = sorted.map((entry) => {
    const extensions = [
      ...(entry.reason !== undefined && entry.reason !== "unspecified"
        ? [extension(OID.reasonCode, false, enumerated(REASON_CODES[entry.reason]))]
        : []),
      ...(entry.invalidityDate !== undefined
        ? [extension(OID.invalidityDate, false, generalizedTime(entry.invalidityDate))]
        : []),
    ];
    return seq(
      uint(serialMagnitude(entry.serial)),
      time(entry.revokedAt),
      ...(extensions.length > 0 ? [seq(...extensions)] : []),
    );
  });
  const tbs = seq(
    smallInt(1),
    algorithmIdentifier,
    template.issuer.subjectDer,
    time(template.thisUpdate),
    time(template.nextUpdate),
    ...(entryTlvs.length > 0 ? [seq(...entryTlvs)] : []),
    explicit(
      0,
      seq(
        extension(OID.aki, false, akiValue(template.issuer.subjectKeyIdentifier)),
        extension(OID.crlNumber, false, bigUint(template.number)),
      ),
    ),
  );
  return { tbs, algorithmIdentifier };
};

export const assembleCrl = assembleCertificate;

// ---------------------------------------------------------------------------------------------------------------------
// Name constraints
// ---------------------------------------------------------------------------------------------------------------------

export interface NameConstraintEntry {
  readonly type: "dns" | "uri" | "ip";
  /** dns and uri lowercased; ip as CIDR text. */
  readonly value: string;
  /** Comparison key: ip is `ip:<address><mask>` hex with host bits cleared. */
  readonly key: string;
}

export interface NameConstraintsValue {
  readonly permitted: readonly NameConstraintEntry[];
  readonly excluded: readonly NameConstraintEntry[];
}

const sortKeys = (entries: readonly NameConstraintEntry[]): string[] => entries.map((e) => `${e.type}:${e.key}`).sort();

export const nameConstraintsEqual = (a: NameConstraintsValue, b: NameConstraintsValue): boolean =>
  JSON.stringify(sortKeys(a.permitted)) === JSON.stringify(sortKeys(b.permitted)) &&
  JSON.stringify(sortKeys(a.excluded)) === JSON.stringify(sortKeys(b.excluded));

/** A DNS-style host constraint: non-empty labels of [A-Za-z0-9-], with one optional leading dot. */
const HOST_PATTERN = /^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/;
export const isValidHostConstraint = (value: string): boolean => value.length <= 253 && HOST_PATTERN.test(value);

const hostEntry = (type: "dns" | "uri", value: string): NameConstraintEntry => {
  if (!isValidHostConstraint(value)) {
    throw new DerError(`Invalid ${type} name constraint.`);
  }
  return { type, value: value.toLowerCase(), key: value.toLowerCase() };
};
const dnsEntry = (value: string): NameConstraintEntry => hostEntry("dns", value);
const uriEntry = (value: string): NameConstraintEntry => hostEntry("uri", value);
const ipEntry = (cidr: { address: Buffer; mask: Buffer; prefix: number }): NameConstraintEntry => ({
  type: "ip",
  value: `${formatIp(cidr.address)}/${cidr.prefix}`,
  key: Buffer.concat([cidr.address, cidr.mask]).toString("hex"),
});

/** The constraint shapes the admin API uses: `{dns: [...], ip: [...], uri: [...]}` or a list of `{type, value}`. */
export type NameConstraintsInput = {
  readonly permitted?: ConstraintGroup;
  readonly excluded?: ConstraintGroup;
};
type ConstraintGroup =
  | { readonly dns?: readonly string[]; readonly ip?: readonly string[]; readonly uri?: readonly string[] }
  | readonly { readonly type: string; readonly value: string }[];

const normalizeGroup = (group: ConstraintGroup | undefined): NameConstraintEntry[] => {
  if (group === undefined) return [];
  const pairs: [string, string][] = Array.isArray(group)
    ? (group as readonly { type: string; value: string }[]).map((e) => [e.type, e.value])
    : Object.entries(group as Record<string, readonly string[] | undefined>).flatMap(([type, values]) =>
        (values ?? []).map((value): [string, string] => [type, value]),
      );
  return pairs.map(([type, value]) => {
    if (type === "dns" || type === "uri") {
      try {
        return type === "dns" ? dnsEntry(value) : uriEntry(value);
      } catch {
        throw new EzError(2, "invalid_input", `Invalid ${type} name constraint.`);
      }
    }
    if (type === "ip") {
      const cidr = parseCidr(value);
      if (cidr === undefined) throw new EzError(2, "invalid_input", `Invalid CIDR ${value}.`);
      return ipEntry(cidr);
    }
    throw new EzError(2, "invalid_input", `Unsupported name constraint type ${type}.`);
  });
};

export const normalizeNameConstraints = (input: NameConstraintsInput | null | undefined): NameConstraintsValue => ({
  permitted: normalizeGroup(input?.permitted),
  excluded: normalizeGroup(input?.excluded),
});

const decodeSubtrees = (container: Tlv): NameConstraintEntry[] => {
  const entries = decodeSubtreeList(container);
  if (entries.length === 0) throw new DerError("Empty subtree list in NameConstraints.");
  if (new Set(entries.map((e) => `${e.type}:${e.key}`)).size !== entries.length) {
    throw new DerError("Duplicate name constraint.");
  }
  return entries;
};

const decodeSubtreeList = (container: Tlv): NameConstraintEntry[] =>
  children(container).map((subtree) => {
    if (subtree.tag !== TAG.sequence) throw new DerError("Malformed GeneralSubtree.");
    const [base, ...limits] = children(subtree);
    if (base === undefined || limits.length > 0) throw new DerError("GeneralSubtree minimum and maximum are not supported.");
    if (base.tag === 0x82) return dnsEntry(base.value.toString("latin1"));
    if (base.tag === 0x86) return uriEntry(base.value.toString("latin1"));
    if (base.tag === 0x87) {
      const length = base.value.length;
      if (length !== 8 && length !== 32) throw new DerError("Malformed iPAddress constraint.");
      const address = base.value.subarray(0, length / 2);
      const mask = base.value.subarray(length / 2);
      let prefix = 0;
      while (prefix < address.length * 8 && (mask[prefix >> 3] as number) & (0x80 >> (prefix & 7))) prefix++;
      const cidr = parseCidr(`${formatIp(address)}/${prefix}`);
      if (cidr === undefined || !cidr.mask.equals(mask)) throw new DerError("Non-contiguous iPAddress mask.");
      if (!cidr.address.equals(address)) throw new DerError("iPAddress constraint has host bits set.");
      return ipEntry(cidr);
    }
    throw new DerError("Unsupported GeneralName type in a name constraint.");
  });

export const parseNameConstraints = (value: Buffer): NameConstraintsValue => {
  const root = parseDer(value);
  if (root.tag !== TAG.sequence) throw new DerError("Malformed NameConstraints.");
  let permitted: NameConstraintEntry[] = [];
  let excluded: NameConstraintEntry[] = [];
  const parts = children(root);
  let index = 0;
  if (parts[index]?.tag === 0xa0) permitted = decodeSubtrees(parts[index++] as Tlv);
  if (parts[index]?.tag === 0xa1) excluded = decodeSubtrees(parts[index++] as Tlv);
  if (index !== parts.length) throw new DerError("Malformed NameConstraints (order, duplicates or unknown field).");
  return { permitted, excluded };
};

// ---------------------------------------------------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------------------------------------------------

export interface ParsedCsr {
  readonly der: Buffer;
  readonly sha256: string;
  /** The signed CertificationRequestInfo TLV, sliced from the input. */
  readonly infoDer: Buffer;
  readonly version: number;
  readonly subjectDer: Buffer;
  readonly spkiDer: Buffer;
  readonly attributes: readonly { readonly oid: string; readonly values: readonly Buffer[] }[];
  readonly signatureAlgorithm: Buffer;
  readonly signature: Buffer;
}

/** Decodes a CSR from PEM or DER. A file containing a private key is refused outright. */
export const decodeCsrInput = (input: Buffer | string): Buffer => {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  const text = bytes.toString("latin1");
  if (/PRIVATE KEY-----/.test(text)) {
    throw new EzError(2, "csr_invalid", "That file contains a private key, not a certificate request.");
  }
  if (text.includes("-----BEGIN")) {
    const label = /-----BEGIN ((?:NEW )?CERTIFICATE REQUEST)-----/.exec(text)?.[1];
    if (label === undefined) throw new EzError(2, "csr_invalid", "Expected a CERTIFICATE REQUEST PEM block.");
    return fromPem(text, label);
  }
  return Buffer.from(bytes);
};

export const parseCsr = (der: Buffer): ParsedCsr => {
  const bad = (message: string): never => {
    throw new EzError(2, "csr_invalid", message);
  };
  try {
    const root = parseDer(der);
    const [info, algorithm, signatureBits, ...extra] = children(root);
    if (root.tag !== TAG.sequence || info === undefined || algorithm === undefined || signatureBits === undefined || extra.length > 0) {
      return bad("Malformed CertificationRequest.");
    }
    const [version, subject, spki, attrs, ...more] = children(info);
    if (version === undefined || subject === undefined || spki === undefined || attrs === undefined || more.length > 0 || attrs.tag !== 0xa0) {
      return bad("Malformed CertificationRequestInfo.");
    }
    const attributes = children(attrs).map((attribute) => {
      const [type, values, ...rest] = children(attribute);
      if (type === undefined || values === undefined || rest.length > 0 || values.tag !== TAG.set) {
        return bad("Malformed CSR attribute.");
      }
      return { oid: decodeOid(type), values: children(values).map((v) => v.raw) };
    });
    return {
      der,
      sha256: sha256Hex(der),
      infoDer: info.raw,
      version: decodeSmallInt(version),
      subjectDer: subject.raw,
      spkiDer: spki.raw,
      attributes,
      signatureAlgorithm: algorithm.raw,
      signature: signatureBytes(signatureBits),
    };
  } catch (error) {
    if (error instanceof DerError) throw new EzError(2, "csr_invalid", `Malformed CSR: ${error.message}`);
    // A truncated structure (an empty wrapper, a missing field) dereferences undefined: still malformed input.
    if (error instanceof TypeError || error instanceof RangeError) throw new EzError(2, "csr_invalid", `Malformed CSR.`);
    throw error;
  }
};

export type ExtendedKeyUsageName = "serverAuth" | "clientAuth";
const EKU_OIDS: Readonly<Record<string, ExtendedKeyUsageName>> = {
  [OID.serverAuth]: "serverAuth",
  [OID.clientAuth]: "clientAuth",
};

export interface CsrExpectations {
  /** `sha256` of the CSR's SPKI as the CA record states it. Absent: the key is unbound and a warning is produced. */
  readonly spkiSha256?: string;
  /** The CA record's subject. The CSR subject DER must equal its encoding. */
  readonly subject?: Subject;
  /** The CA record's requested name constraints (`null`: none requested). `undefined` skips the comparison. */
  readonly nameConstraints?: NameConstraintsInput | null;
  /** The record's requested EKUs (`null` or empty: none). `undefined` skips the comparison. */
  readonly extendedKeyUsages?: readonly string[] | null;
  /** The signing root's subject; the CSR subject must differ from it. */
  readonly rootSubjectDer?: Buffer;
}

export interface ValidatedCsr {
  readonly der: Buffer;
  readonly sha256: string;
  readonly subjectDer: Buffer;
  readonly subject: RestrictedName;
  readonly spkiDer: Buffer;
  readonly spkiSha256: string;
  readonly keyInfo: KeyInfo;
  readonly signatureAlgorithm: SignatureAlgorithm;
  /** The requested Extension TLVs in CSR order, copied verbatim into the certificate. */
  readonly extensions: readonly Buffer[];
  readonly nameConstraints: NameConstraintsValue | undefined;
  readonly extendedKeyUsages: readonly ExtendedKeyUsageName[];
  readonly subjectKeyIdentifier: Buffer;
  readonly warnings: readonly string[];
}

const unexpected = (message: string): never => {
  throw new EzError(2, "csr_unexpected_extension", message);
};

/**
 * Validates a CSR (design section 3, items 2, 3, 5, 6, 7): signature over the raw CertificationRequestInfo, key binding,
 * subject, the exact extension profile, and the comparison against the CA record. Record-state checks (kind, status,
 * environment) belong to the caller, which owns the API response.
 */
export const validateCsr = (input: Buffer | string, expectations: CsrExpectations = {}): ValidatedCsr => {
  const der = decodeCsrInput(input);
  const csr = parseCsr(der);
  try {
    AsnConvert.parse(der, CertificationRequest);
  } catch {
    throw new EzError(2, "csr_invalid", "The CSR is not a valid PKCS#10 structure.");
  }
  if (csr.version !== 0) throw new EzError(2, "csr_invalid", "Unsupported CSR version.");
  const signatureAlgorithm = parseSignatureAlgorithm(csr.signatureAlgorithm);
  if (signatureAlgorithm === undefined) throw new EzError(2, "csr_invalid", "Unsupported CSR signature algorithm.");
  const keyInfo = describeSpki(csr.spkiDer);
  if (!verifySignature(csr.spkiDer, csr.signatureAlgorithm, csr.infoDer, csr.signature)) {
    throw new EzError(2, "csr_invalid", "The CSR signature does not verify.");
  }
  const spkiSha256 = sha256Hex(csr.spkiDer);
  const warnings: string[] = [];
  if (expectations.spkiSha256 === undefined) {
    warnings.push("csr_unbound");
  } else if (expectations.spkiSha256.toLowerCase() !== spkiSha256) {
    throw new EzError(5, "csr_key_mismatch", "The CSR's public key is not the CA key Hemlig holds.", {
      expected: expectations.spkiSha256.toLowerCase(),
      actual: spkiSha256,
    });
  }
  const subject = assertRestrictedName(csr.subjectDer, "hemlig", "csr_invalid");
  if (expectations.subject !== undefined && !encodeSubject(expectations.subject).equals(csr.subjectDer)) {
    throw new EzError(5, "csr_subject_mismatch", "The CSR subject is not the CA record's subject.");
  }
  if (expectations.rootSubjectDer !== undefined) {
    const root = assertRestrictedName(expectations.rootSubjectDer, "external");
    if (root.key === subject.key) {
      throw new EzError(5, "csr_subject_is_root", "The intermediate's subject must differ from the root's.");
    }
  }

  // Exactly one extensionRequest holding one Extensions.
  if (csr.attributes.length !== 1 || (csr.attributes[0] as { oid: string }).oid !== OID.extensionRequest) {
    unexpected("The CSR must carry exactly one extensionRequest attribute and no other attribute.");
  }
  const values = (csr.attributes[0] as { values: readonly Buffer[] }).values;
  if (values.length !== 1) unexpected("The extensionRequest must hold one set of extensions.");
  let extensions: ParsedExtension[];
  try {
    extensions = parseExtensions(parseDer(values[0] as Buffer));
  } catch (error) {
    if (error instanceof DerError) throw new EzError(2, "csr_invalid", `Malformed requested extensions: ${error.message}`);
    throw error;
  }

  let sawBasicConstraints = false;
  let sawKeyUsage = false;
  let subjectKeyIdentifierValue: Buffer | undefined;
  let nameConstraints: NameConstraintsValue | undefined;
  let ekus: ExtendedKeyUsageName[] = [];
  try {
    for (const e of extensions) {
      switch (e.oid) {
        case OID.basicConstraints: {
          const bc = parseBasicConstraints(e.value);
          if (!e.critical || !bc.ca || bc.pathLen !== 0) unexpected("BasicConstraints must be critical with cA:TRUE and pathLen 0.");
          sawBasicConstraints = true;
          break;
        }
        case OID.keyUsage: {
          const bits = parseKeyUsageBits(e.value);
          if (!e.critical || bits.size !== 2 || !bits.has(KEY_USAGE_BIT.keyCertSign) || !bits.has(KEY_USAGE_BIT.cRLSign)) {
            unexpected("KeyUsage must be critical with exactly keyCertSign and cRLSign.");
          }
          sawKeyUsage = true;
          break;
        }
        case OID.nameConstraints:
          if (!e.critical) unexpected("NameConstraints must be critical.");
          nameConstraints = parseNameConstraints(e.value);
          break;
        case OID.extendedKeyUsage: {
          if (e.critical) unexpected("ExtendedKeyUsage must not be critical.");
          const ekuRoot = parseDer(e.value);
          if (ekuRoot.tag !== TAG.sequence) throw new DerError("Malformed ExtendedKeyUsage.");
          const parsed = children(ekuRoot).map((o) => decodeOid(o));
          if (parsed.length === 0 || parsed.some((o) => EKU_OIDS[o] === undefined) || new Set(parsed).size !== parsed.length) {
            unexpected("ExtendedKeyUsage may only list serverAuth and clientAuth.");
          }
          ekus = parsed.map((o) => EKU_OIDS[o] as ExtendedKeyUsageName);
          break;
        }
        case OID.ski:
          if (e.critical) unexpected("SubjectKeyIdentifier must not be critical.");
          subjectKeyIdentifierValue = parseSki(e.value);
          break;
        default:
          unexpected(`The CSR requests an extension that EZ does not sign (${e.oid}).`);
      }
    }
  } catch (error) {
    if (error instanceof DerError) throw new EzError(2, "csr_unexpected_extension", `Malformed requested extension: ${error.message}`);
    throw error;
  }
  if (!sawBasicConstraints || !sawKeyUsage || subjectKeyIdentifierValue === undefined) {
    unexpected("The CSR must request BasicConstraints, KeyUsage and SubjectKeyIdentifier.");
  }
  if (nameConstraints !== undefined && nameConstraints.permitted.length + nameConstraints.excluded.length === 0) {
    unexpected("NameConstraints is empty.");
  }
  if (!(subjectKeyIdentifierValue as Buffer).equals(keyIdentifier(csr.spkiDer))) {
    unexpected("The requested SubjectKeyIdentifier is not the key's RFC 7093 method 1 identifier.");
  }
  if (expectations.nameConstraints !== undefined) {
    const wanted = normalizeNameConstraints(expectations.nameConstraints);
    const wantedNone = wanted.permitted.length + wanted.excluded.length === 0;
    if (nameConstraints === undefined ? !wantedNone : wantedNone || !nameConstraintsEqual(nameConstraints, wanted)) {
      throw new EzError(5, "csr_constraints_mismatch", "The CSR's name constraints are not the ones the CA record requested.");
    }
  }
  if (expectations.extendedKeyUsages !== undefined) {
    const wanted = [...(expectations.extendedKeyUsages ?? [])].sort();
    if (JSON.stringify(wanted) !== JSON.stringify([...ekus].sort())) {
      throw new EzError(5, "csr_constraints_mismatch", "The CSR's extended key usages are not the ones the CA record requested.");
    }
  }
  return {
    der,
    sha256: csr.sha256,
    subjectDer: csr.subjectDer,
    subject,
    spkiDer: csr.spkiDer,
    spkiSha256,
    keyInfo,
    signatureAlgorithm,
    extensions: extensions.map((e) => e.raw),
    nameConstraints,
    extendedKeyUsages: ekus,
    subjectKeyIdentifier: subjectKeyIdentifierValue as Buffer,
    warnings,
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Root certificate validation (also used when adopting an existing root)
// ---------------------------------------------------------------------------------------------------------------------

/** Reasons that only a re-issued root certificate (same key and name) can fix. */
export const EXTENSION_PROFILE_REASONS: ReadonlySet<string> = new Set([
  "root_not_ca",
  "root_basic_constraints_not_critical",
  "root_key_usage",
  "root_missing_ski",
  "root_path_len",
]);

const KNOWN_EXTENSIONS = new Set<string>([
  OID.ski,
  OID.aki,
  OID.keyUsage,
  OID.basicConstraints,
  OID.extendedKeyUsage,
  OID.subjectAltName,
  OID.issuerAltName,
  OID.certificatePolicies,
  OID.crlDistributionPoints,
  OID.authorityInfoAccess,
]);

export interface RootValidationOptions {
  readonly now?: Date;
  /** Days that must remain. Generated roots use 0; adoption uses 90. */
  readonly minimumRemainingDays?: number;
  /** When given, the certificate's SPKI must equal it. */
  readonly spkiDer?: Buffer;
  /** Skip the time checks (a certificate just issued is checked at its own issuance instant). */
  readonly ignoreValidity?: boolean;
}

export interface RootValidation {
  readonly certificate: ParsedCertificate;
  /** Every failed rule, using the server's reason strings. Empty when the root is acceptable. */
  readonly reasons: readonly string[];
}

export const validateRootCertificate = (der: Buffer, options: RootValidationOptions = {}): RootValidation => {
  const cert = parseCertificate(der);
  const now = options.now ?? new Date();
  const reasons: string[] = [];
  if (!cert.issuerDer.equals(cert.subjectDer)) reasons.push("root_not_self_signed");
  if (!cert.innerAlgorithm.equals(cert.outerAlgorithm) || !verifyCertificateSignature(cert, cert.spkiDer)) {
    reasons.push("root_signature_invalid");
  }
  if (options.spkiDer !== undefined && !options.spkiDer.equals(cert.spkiDer)) reasons.push("key_mismatch");
  if (options.ignoreValidity === true) {
    // checked by the caller
  } else if (cert.notBefore.getTime() > now.getTime() || cert.notAfter.getTime() <= now.getTime()) {
    reasons.push("root_not_valid");
  } else if (cert.notAfter.getTime() - now.getTime() < (options.minimumRemainingDays ?? 0) * DAY_MS) {
    reasons.push("root_expires_soon");
  }
  if (cert.version !== 3) reasons.push("root_not_v3");
  const bcExtension = cert.extensions.find((e) => e.oid === OID.basicConstraints);
  const bc = bcExtension && parseBasicConstraints(bcExtension.value);
  if (bc === undefined || !bc.ca) reasons.push("root_not_ca");
  else if (!bcExtension?.critical) reasons.push("root_basic_constraints_not_critical");
  if (bc?.pathLen !== undefined && bc.pathLen < 1) reasons.push("root_path_len");
  const kuExtension = cert.extensions.find((e) => e.oid === OID.keyUsage);
  const ku = kuExtension && parseKeyUsageBits(kuExtension.value);
  if (ku === undefined || !ku.has(KEY_USAGE_BIT.keyCertSign) || !ku.has(KEY_USAGE_BIT.cRLSign)) reasons.push("root_key_usage");
  if (cert.subjectKeyIdentifier === undefined) reasons.push("root_missing_ski");
  if (cert.extensions.some((e) => e.oid === OID.nameConstraints)) reasons.push("root_name_constraints_unsupported");
  if (cert.extensions.some((e) => [OID.policyConstraints, OID.inhibitAnyPolicy, OID.policyMappings].includes(e.oid as never))) {
    reasons.push("policy_extension_present");
  }
  if (cert.extensions.some((e) => e.critical && !KNOWN_EXTENSIONS.has(e.oid) && e.oid !== OID.nameConstraints && ![OID.policyConstraints, OID.inhibitAnyPolicy, OID.policyMappings].includes(e.oid as never))) {
    reasons.push("unrecognized_critical_extension");
  }
  try {
    const name = assertRestrictedName(cert.subjectDer, "external");
    if (isIdentityRootName(name)) reasons.push("identity_root_reserved");
  } catch {
    reasons.push("root_subject_unsupported");
  }
  return { certificate: cert, reasons };
};

// ---------------------------------------------------------------------------------------------------------------------
// Self checks (run before any artifact is released)
// ---------------------------------------------------------------------------------------------------------------------

const selfCheckFailed = (message: string): never => {
  throw new EzError(7, "signature_self_check_failed", message);
};

/** Parses the certificate back with a second implementation and verifies its signature under `issuerSpki`. */
export const selfCheckCertificate = (
  der: Buffer,
  issuerSpki: Buffer,
  profile: { readonly kind: "root" } | { readonly kind: "intermediate"; readonly issuerSubjectDer: Buffer; readonly issuerSki: Buffer },
): ParsedCertificate => {
  try {
    AsnConvert.parse(der, Certificate);
  } catch {
    return selfCheckFailed("The generated certificate does not parse back.");
  }
  const cert = parseCertificate(der);
  if (!cert.innerAlgorithm.equals(cert.outerAlgorithm)) return selfCheckFailed("The certificate's two signature algorithm fields differ.");
  if (!verifyCertificateSignature(cert, issuerSpki)) return selfCheckFailed("The certificate signature does not verify.");
  if (profile.kind === "root") {
    const result = validateRootCertificate(der, { spkiDer: issuerSpki, ignoreValidity: true });
    if (result.reasons.length > 0) return selfCheckFailed(`The generated root violates the profile (${result.reasons.join(", ")}).`);
  } else {
    if (!cert.issuerDer.equals(profile.issuerSubjectDer)) return selfCheckFailed("The certificate's issuer is not the root's subject.");
    if (!cert.authorityKeyIdentifier?.equals(profile.issuerSki)) return selfCheckFailed("The certificate's AKI is not the root's SKI.");
  }
  return cert;
};

export const selfCheckCrl = (
  der: Buffer,
  issuer: { readonly spkiDer: Buffer; readonly subjectDer: Buffer; readonly subjectKeyIdentifier: Buffer },
): ParsedCrl => {
  try {
    AsnConvert.parse(der, CertificateList);
  } catch {
    return selfCheckFailed("The generated CRL does not parse back.");
  }
  const crl = parseCrl(der);
  if (crl.version !== 1) return selfCheckFailed("The CRL is not v2.");
  if (!crl.innerAlgorithm.equals(crl.outerAlgorithm)) return selfCheckFailed("The CRL's two signature algorithm fields differ.");
  if (!crl.issuerDer.equals(issuer.subjectDer)) return selfCheckFailed("The CRL issuer is not the root's subject.");
  if (!crl.authorityKeyIdentifier?.equals(issuer.subjectKeyIdentifier)) return selfCheckFailed("The CRL's AKI is not the root's SKI.");
  if (!verifyCrlSignature(crl, issuer.spkiDer)) return selfCheckFailed("The CRL signature does not verify.");
  if (crl.number === undefined || crl.nextUpdate === undefined) return selfCheckFailed("The CRL lacks a number or nextUpdate.");
  return crl;
};

/** What the operator is asked to confirm before a certificate is signed. */
export interface CsrSummary {
  readonly subject: string;
  readonly keyAlgorithm: string;
  readonly spkiSha256: string;
  readonly nameConstraints: { readonly permitted: readonly string[]; readonly excluded: readonly string[] } | undefined;
  readonly extendedKeyUsages: readonly string[];
  readonly warnings: readonly string[];
}

/** Escapes anything outside printable ASCII, so a hostile value can never move the cursor or forge a display line. */
export const displaySafe = (text: string): string =>
  text.replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);

export const summarizeCsr = (csr: ValidatedCsr): CsrSummary => ({
  subject: displaySafe(describeName(csr.subject)),
  keyAlgorithm: csr.keyInfo.algorithm,
  spkiSha256: csr.spkiSha256,
  nameConstraints:
    csr.nameConstraints === undefined
      ? undefined
      : {
          permitted: csr.nameConstraints.permitted.map((e) => displaySafe(`${e.type}:${e.value}`)),
          excluded: csr.nameConstraints.excluded.map((e) => displaySafe(`${e.type}:${e.value}`)),
        },
  extendedKeyUsages: csr.extendedKeyUsages,
  warnings: csr.warnings,
});
