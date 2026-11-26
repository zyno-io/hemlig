import { createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import {
  bitString, bool, extension, explicit, octetString, oid, seq, set, smallInt, time, tlv, uint,
} from "./ez-der";
import { encodeSubject, parseCidr, type Subject } from "./ez-name";
import { keyIdentifier, OID, signatureAlgorithmForSpki, toPem } from "./ez-x509";

/** Test helpers: builds PKCS#10 requests like the server's Hemlig CSR, with switches to break them. Not used at runtime. */
export interface TestCsrOptions {
  readonly subject?: Subject;
  readonly curve?: "P-256" | "P-384";
  readonly rsaBits?: number;
  readonly ed25519?: boolean;
  readonly permitted?: { dns?: string[]; ip?: string[]; uri?: string[] };
  readonly excluded?: { dns?: string[]; ip?: string[]; uri?: string[] };
  readonly eku?: readonly string[];
  /** `undefined` means 0; `null` omits pathLen. */
  readonly pathLen?: number | null;
  readonly omitSki?: boolean;
  readonly omitKeyUsage?: boolean;
  readonly extra?: readonly Buffer[];
  readonly extraAttribute?: boolean;
  readonly badSignature?: boolean;
  readonly keyUsageNonCritical?: boolean;
  /** Replaces the NameConstraints extension value with these exact bytes. */
  readonly ncRaw?: Buffer;
}

export interface TestCsr {
  readonly der: Buffer;
  readonly pem: string;
  readonly spkiDer: Buffer;
  readonly subject: Subject;
  readonly privateKey: KeyObject;
}

const subtrees = (group: { dns?: string[]; ip?: string[]; uri?: string[] }): Buffer[] => [
  ...(group.dns ?? []).map((v) => seq(tlv(0x82, Buffer.from(v, "ascii")))),
  ...(group.uri ?? []).map((v) => seq(tlv(0x86, Buffer.from(v, "ascii")))),
  ...(group.ip ?? []).map((v) => {
    const cidr = parseCidr(v)!;
    return seq(tlv(0x87, Buffer.concat([cidr.address, cidr.mask])));
  }),
];

export const makeTestCsr = (options: TestCsrOptions = {}): TestCsr => {
  const subject = options.subject ?? { O: "Example Corp", CN: "Prod Issuing CA 1" };
  const pair = options.ed25519
    ? generateKeyPairSync("ed25519")
    : options.rsaBits
      ? generateKeyPairSync("rsa", { modulusLength: options.rsaBits })
      : generateKeyPairSync("ec", { namedCurve: options.curve ?? "P-256" });
  const spkiDer = pair.publicKey.export({ type: "spki", format: "der" });
  const permitted = options.permitted === undefined ? [] : subtrees(options.permitted);
  const excluded = options.excluded === undefined ? [] : subtrees(options.excluded);
  const extensions = [
    extension(OID.basicConstraints, true, seq(bool(true), ...(options.pathLen === null ? [] : [smallInt(options.pathLen ?? 0)]))),
    ...(options.omitKeyUsage ? [] : [extension(OID.keyUsage, !options.keyUsageNonCritical, bitString(Buffer.from([0x06]), 1))]),
    ...(options.ncRaw !== undefined
      ? [extension(OID.nameConstraints, true, options.ncRaw)]
      : permitted.length + excluded.length > 0
      ? [extension(OID.nameConstraints, true, seq(...(permitted.length ? [tlv(0xa0, ...permitted)] : []), ...(excluded.length ? [tlv(0xa1, ...excluded)] : [])))]
      : []),
    ...(options.eku && options.eku.length > 0 ? [extension(OID.extendedKeyUsage, false, seq(...options.eku.map((e) => oid(e))))] : []),
    ...(options.omitSki ? [] : [extension(OID.ski, false, octetString(keyIdentifier(spkiDer)))]),
    ...(options.extra ?? []),
  ];
  const info = seq(
    smallInt(0),
    encodeSubject(subject),
    spkiDer,
    tlv(
      0xa0,
      seq(oid(OID.extensionRequest), set(seq(...extensions))),
      ...(options.extraAttribute ? [seq(oid("1.2.840.113549.1.9.7"), set(tlv(0x0c, Buffer.alloc(2, 0x70))))] : []),
    ),
  );
  const algorithm = options.ed25519
    ? seq(oid(OID.ed25519))
    : options.rsaBits
      ? seq(oid(OID.sha256WithRsa), tlv(0x05))
      : seq(oid(options.curve === "P-384" ? OID.ecdsaSha384 : OID.ecdsaSha256));
  const signature = options.ed25519
    ? sign(null, info, pair.privateKey)
    : options.rsaBits
      ? sign("sha256", info, pair.privateKey)
      : sign(options.curve === "P-384" ? "sha384" : "sha256", info, { key: pair.privateKey, dsaEncoding: "der" });
  if (options.badSignature) signature[signature.length - 1] = (signature[signature.length - 1] as number) ^ 0xff;
  const der = seq(info, algorithm, bitString(signature));
  return { der, pem: toPem(der, "CERTIFICATE REQUEST"), spkiDer, subject, privateKey: pair.privateKey };
};


export interface BareRootOptions {
  readonly privateKey: KeyObject;
  readonly subject?: Subject;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  /** Extension TLVs (`extension(...)`) to include; none gives a v3 certificate without extensions (like ykman's). */
  readonly extensions?: readonly Buffer[];
  readonly serial?: Buffer;
  /** An empty `[3]` wrapper (malformed): for parser tests. */
  readonly emptyExtensionsWrapper?: boolean;
}

/** A self-signed v3 root with exactly the extensions given, for adoption tests (a ykman-style root has none). */
export const makeBareRoot = (options: BareRootOptions): { der: Buffer; pem: string; spkiDer: Buffer; subject: Subject } => {
  const subject = options.subject ?? { O: "Example Corp", CN: "Bare Root" };
  const spkiDer = createPublicKey(options.privateKey).export({ type: "spki", format: "der" });
  const algorithm = signatureAlgorithmForSpki(spkiDer);
  const name = encodeSubject(subject);
  const notBefore = options.notBefore ?? new Date(Math.floor(Date.now() / 1000) * 1000 - 3_600_000);
  const notAfter = options.notAfter ?? new Date(notBefore.getTime() + 3650 * 86_400_000);
  const exts = options.extensions ?? [];
  const tbs = seq(
    explicit(0, smallInt(2)),
    uint(options.serial ?? Buffer.concat([Buffer.from([0x01]), randomBytes(15)])),
    algorithm.algorithmIdentifier,
    name,
    seq(time(notBefore), time(notAfter)),
    name,
    spkiDer,
    ...(options.emptyExtensionsWrapper ? [tlv(0xa3)] : exts.length === 0 ? [] : [explicit(3, seq(...exts))]),
  );
  const signature =
    algorithm.keyType === "ec"
      ? sign(algorithm.hash, tbs, { key: options.privateKey, dsaEncoding: "der" })
      : sign(algorithm.hash, tbs, options.privateKey);
  const der = seq(tbs, algorithm.algorithmIdentifier, bitString(signature));
  return { der, pem: toPem(der, "CERTIFICATE"), spkiDer, subject };
};
