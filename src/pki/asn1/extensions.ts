import { createHash } from "node:crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  BasicConstraints,
  CertificatePolicies,
  ExtendedKeyUsage,
  KeyUsage,
  PolicyInformation,
} from "@peculiar/asn1-x509";
import type { KeyUsageName, RevocationReason } from "../types";
import {
  boolTrue,
  canonicalSerialHex,
  children,
  decodeOid,
  DerError,
  encodeGeneralizedTime,
  expectTag,
  octetString,
  oid,
  parseDer,
  seq,
  TAG,
  tlv,
  unsignedInteger,
  type Tlv,
} from "./der";

export const EXT = {
  subjectKeyIdentifier: "2.5.29.14",
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
  certificatePolicies: "2.5.29.32",
  policyMappings: "2.5.29.33",
  authorityKeyIdentifier: "2.5.29.35",
  policyConstraints: "2.5.29.36",
  extendedKeyUsage: "2.5.29.37",
  freshestCrl: "2.5.29.46",
  inhibitAnyPolicy: "2.5.29.54",
  extensionRequest: "1.2.840.113549.1.9.14",
} as const;

export const EKU = {
  any: "2.5.29.37.0",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  clientAuth: "1.3.6.1.5.5.7.3.2",
} as const;

export interface RawExtension {
  readonly oid: string;
  readonly critical: boolean;
  /** The DER value inside the extnValue OCTET STRING. */
  readonly value: Buffer;
}

/** One Extension: extnID, optional critical flag (omitted when false, per DER) and extnValue. */
export const extension = (
  extensionOid: string,
  critical: boolean,
  value: Uint8Array,
): Buffer =>
  seq(oid(extensionOid), ...(critical ? [boolTrue()] : []), octetString(value));

/** Decodes an `Extensions` SEQUENCE. Duplicate extensions are refused (RFC 5280 4.2). */
export const decodeExtensions = (container: Tlv): RawExtension[] => {
  expectTag(container, TAG.sequence, "Extensions");
  const seen = new Set<string>();
  return children(container).map((item) => {
    expectTag(item, TAG.sequence, "an Extension");
    const [id, second, third, ...extra] = children(item);
    if (id === undefined || second === undefined || extra.length > 0) {
      throw new DerError("Malformed Extension.");
    }
    const flag = third === undefined ? undefined : second;
    const body = third ?? second;
    if (
      flag !== undefined &&
      (flag.tag !== TAG.boolean || flag.value.length !== 1)
    ) {
      throw new DerError("Malformed Extension critical flag.");
    }
    expectTag(body, TAG.octetString, "an extnValue");
    const extensionOid = decodeOid(id);
    if (seen.has(extensionOid)) {
      throw new DerError("Duplicate extension.");
    }
    seen.add(extensionOid);
    return {
      oid: extensionOid,
      critical: flag !== undefined && flag.value[0] !== 0,
      value: body.value,
    };
  });
};

const serialize = (value: object): Buffer =>
  Buffer.from(AsnConvert.serialize(value));

export const basicConstraintsValue = (ca: boolean, pathLen?: number): Buffer =>
  serialize(
    new BasicConstraints({
      cA: ca,
      pathLenConstraint: ca ? pathLen : undefined,
    }),
  );

const keyUsageFlags: Record<KeyUsageName, number> = {
  digitalSignature: 1,
  nonRepudiation: 2,
  keyEncipherment: 4,
  dataEncipherment: 8,
  keyAgreement: 16,
  keyCertSign: 32,
  cRLSign: 64,
  encipherOnly: 128,
  decipherOnly: 256,
};

export const keyUsageValue = (usages: readonly KeyUsageName[]): Buffer =>
  serialize(
    new KeyUsage(
      usages.reduce((flags, usage) => flags | keyUsageFlags[usage], 0),
    ),
  );

export const extendedKeyUsageValue = (oids: readonly string[]): Buffer =>
  serialize(new ExtendedKeyUsage([...oids]));

export const certificatePoliciesValue = (oids: readonly string[]): Buffer =>
  serialize(
    new CertificatePolicies(
      oids.map(
        (policyIdentifier) => new PolicyInformation({ policyIdentifier }),
      ),
    ),
  );

export const decodeCertificatePolicies = (value: Uint8Array): string[] =>
  AsnConvert.parse(value, CertificatePolicies).map(
    (policy) => policy.policyIdentifier,
  );

export const keyIdentifierValue = (keyId: Uint8Array): Buffer =>
  octetString(keyId);

export const authorityKeyIdentifierValue = (keyId: Uint8Array): Buffer =>
  seq(tlv(0x80, keyId));

/** RFC 7093 method 1: the leftmost 160 bits of the SHA-256 of the subjectPublicKey BIT STRING contents. */
export const keyIdentifierFromSpki = (spkiDer: Uint8Array): Buffer => {
  const bits = expectTag(
    children(parseDer(spkiDer))[1],
    TAG.bitString,
    "a subjectPublicKey",
  );
  return createHash("sha256")
    .update(bits.value.subarray(1))
    .digest()
    .subarray(0, 20);
};

export const crlNumberValue = (number: bigint): Buffer => {
  if (number < 0n || number >= 1n << 159n) {
    throw new RangeError("CRL number out of range.");
  }
  const hex = number.toString(16);
  return unsignedInteger(
    Buffer.from(hex.length % 2 === 1 ? `0${hex}` : hex, "hex"),
  );
};

const reasonCodes: Record<Exclude<RevocationReason, "unspecified">, number> = {
  keyCompromise: 1,
  caCompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  privilegeWithdrawn: 9,
};

export const reasonCodeValue = (
  reason: Exclude<RevocationReason, "unspecified">,
): Buffer => tlv(TAG.enumerated, Buffer.from([reasonCodes[reason]]));

export const invalidityDateValue = (date: Date): Buffer =>
  encodeGeneralizedTime(date);

// ---------------------------------------------------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------------------------------------------------

export const decodeBasicConstraints = (
  value: Uint8Array,
): { ca: boolean; pathLen?: number } => {
  parseDer(value);
  const decoded = AsnConvert.parse(value, BasicConstraints);
  if (
    decoded.pathLenConstraint !== undefined &&
    decoded.pathLenConstraint < 0
  ) {
    throw new DerError("Negative pathLenConstraint.");
  }
  return { ca: decoded.cA, pathLen: decoded.pathLenConstraint };
};

export const decodeKeyUsage = (value: Uint8Array): KeyUsageName[] => {
  parseDer(value);
  const flags = AsnConvert.parse(value, KeyUsage).toNumber();
  return (Object.keys(keyUsageFlags) as KeyUsageName[]).filter(
    (name) => (flags & keyUsageFlags[name]) !== 0,
  );
};

export const decodeExtendedKeyUsage = (value: Uint8Array): string[] => {
  parseDer(value);
  return [...AsnConvert.parse(value, ExtendedKeyUsage)];
};

export const decodeKeyIdentifier = (value: Uint8Array): Buffer => {
  const element = parseDer(value);
  expectTag(element, TAG.octetString, "a KeyIdentifier");
  return element.value;
};

export const decodeAuthorityKeyIdentifier = (
  value: Uint8Array,
): AuthorityKeyIdentifierParts => {
  const root = parseDer(value);
  expectTag(root, TAG.sequence, "an AuthorityKeyIdentifier");
  const fields = children(root);
  const keyId = fields.find((field) => field.tag === 0x80);
  const issuer = fields.find((field) => field.tag === 0xa1);
  const serial = fields.find((field) => field.tag === 0x82);
  if (serial !== undefined && serial.value.length === 0) {
    throw new DerError("Empty authorityCertSerialNumber.");
  }
  return {
    keyIdentifier: keyId?.value,
    authorityCertIssuer:
      issuer === undefined
        ? undefined
        : children(issuer).map((name) => ({
            tag: name.tag,
            value: name.value,
          })),
    authorityCertSerialHex:
      serial === undefined
        ? undefined
        : canonicalSerialHex(serial.value.toString("hex")),
  };
};

export interface AuthorityKeyIdentifierParts {
  keyIdentifier?: Buffer;
  /** GeneralNames of authorityCertIssuer; a directoryName's `value` is the Name DER. */
  authorityCertIssuer?: { tag: number; value: Buffer }[];
  /** Canonical serial hex of authorityCertSerialNumber. */
  authorityCertSerialHex?: string;
}
