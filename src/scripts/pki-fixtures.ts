/**
 * Root, intermediate, CRL and key builders shared by the jest suites and the MiniStack scripts. Lives outside
 * `__fixtures__`, which the build excludes.
 */
import { generateKeyPairSync, sign } from "node:crypto";
import { caSignatureAlgorithmIdentifier, OID } from "../pki/asn1/algorithms";
import {
  assembleCertificate,
  buildCaTbs,
  buildTbsCertificate,
  parseCertificate,
  type ParsedCertificate,
} from "../pki/asn1/certificate";
import { assembleCrl } from "../pki/asn1/crl";
import {
  bitString,
  explicit,
  oid,
  seq,
  set,
  smallInteger,
  tlv,
  unsignedInteger,
  encodeTime,
  TAG,
} from "../pki/asn1/der";
import {
  authorityKeyIdentifierValue,
  basicConstraintsValue,
  crlNumberValue,
  EXT,
  extension,
  keyIdentifierFromSpki,
  keyIdentifierValue,
  keyUsageValue,
} from "../pki/asn1/extensions";
import { encodeSubjectAltName } from "../pki/asn1/names";
import { toPem } from "../pki/asn1/pem";
import { signWithPkcs8 } from "../pki/signer";
import { buildCaSubject } from "../pki/subject";
import type {
  CaSubject,
  NameConstraintSet,
  PkiKeyAlgorithm,
} from "../pki/types";
import { generateCaKeyPair } from "../pki/wrapped-keys";

export const hours = (count: number): number => count * 60 * 60 * 1000;
export const days = (count: number): number => count * 24 * hours(1);

export interface TestKey {
  readonly algorithm: PkiKeyAlgorithm;
  readonly pkcs8: Buffer;
  readonly spkiDer: Buffer;
  sign(data: Uint8Array): Buffer;
}

export const newKey = async (
  algorithm: PkiKeyAlgorithm = "ECDSA_P256",
): Promise<TestKey> => {
  const generated = await generateCaKeyPair(algorithm);
  return {
    algorithm,
    pkcs8: generated.privateKeyDer,
    spkiDer: generated.spkiDer,
    sign: (data) => signWithPkcs8(algorithm, generated.privateKeyDer, data),
  };
};

export interface TestCert {
  readonly cert: ParsedCertificate;
  readonly pem: string;
  readonly key: TestKey;
}

export const subjectDer = (subject: CaSubject | string): Buffer =>
  buildCaSubject(typeof subject === "string" ? { CN: subject } : subject).der;

export interface CertSpec {
  /** The issuing certificate; omit for a self-signed certificate. */
  readonly issuer?: TestCert;
  /** The subject's key. */
  readonly key: TestKey;
  readonly subject: Buffer;
  readonly extensions: readonly Buffer[];
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly serial?: Buffer;
  /** Overrides the signing key (to build a bad signature). */
  readonly signedBy?: TestKey;
}

export const makeCert = (spec: CertSpec): TestCert => {
  const signer = spec.signedBy ?? spec.issuer?.key ?? spec.key;
  const algorithm = caSignatureAlgorithmIdentifier(signer.algorithm);
  const tbs = buildTbsCertificate({
    serial: spec.serial ?? Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]),
    signatureAlgorithm: algorithm,
    issuerDer: spec.issuer?.cert.subjectDer ?? spec.subject,
    notBefore: spec.notBefore ?? new Date(Date.now() - hours(1)),
    notAfter: spec.notAfter ?? new Date(Date.now() + days(365)),
    subjectDer: spec.subject,
    spkiDer: spec.key.spkiDer,
    extensions: spec.extensions,
  });
  const der = assembleCertificate(tbs, algorithm, signer.sign(tbs));
  return {
    cert: parseCertificate(der),
    pem: toPem(der, "CERTIFICATE"),
    key: spec.key,
  };
};

export const skiExtension = (key: TestKey): Buffer =>
  extension(
    EXT.subjectKeyIdentifier,
    false,
    keyIdentifierValue(keyIdentifierFromSpki(key.spkiDer)),
  );

export const rootExtensions = (key: TestKey): Buffer[] => [
  extension(EXT.basicConstraints, true, basicConstraintsValue(true)),
  extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign", "cRLSign"])),
  skiExtension(key),
];

export interface RootOptions {
  readonly algorithm?: PkiKeyAlgorithm;
  readonly subject?: CaSubject | string;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly extensions?: (key: TestKey) => Buffer[];
}

export const makeRoot = async (
  options: RootOptions = {},
): Promise<TestCert> => {
  const key = await newKey(options.algorithm ?? "ECDSA_P384");
  return makeCert({
    key,
    subject: subjectDer(
      options.subject ?? { O: "Test Corp", CN: "Test Offline Root" },
    ),
    extensions: (options.extensions ?? rootExtensions)(key),
    notBefore: options.notBefore,
    notAfter: options.notAfter,
  });
};

export interface IntermediateOptions {
  readonly key?: TestKey;
  readonly subject?: CaSubject | string;
  readonly pathLen?: number;
  readonly nameConstraints?: NameConstraintSet;
  readonly extendedKeyUsage?: readonly string[];
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly serial?: Buffer;
}

/** A Hemlig-profile intermediate signed by `root`, built with the production `buildCaTbs`. */
export const makeIntermediate = async (
  root: TestCert,
  options: IntermediateOptions = {},
): Promise<TestCert> => {
  const key = options.key ?? (await newKey("ECDSA_P256"));
  const { tbs, signatureAlgorithm } = buildCaTbs({
    issuer: root.cert,
    serial: options.serial ?? Buffer.from([9, 8, 7, 6, 5, 4, 3, 2]),
    notBefore: options.notBefore ?? new Date(Date.now() - hours(1)),
    notAfter: options.notAfter ?? new Date(Date.now() + days(365)),
    subjectDer: subjectDer(
      options.subject ?? { O: "Test Corp", CN: "Test Issuing CA 1" },
    ),
    spkiDer: key.spkiDer,
    pathLen: options.pathLen ?? 0,
    nameConstraints: options.nameConstraints,
    extendedKeyUsage: options.extendedKeyUsage,
  });
  const der = assembleCertificate(tbs, signatureAlgorithm, root.key.sign(tbs));
  return { cert: parseCertificate(der), pem: toPem(der, "CERTIFICATE"), key };
};

export interface CrlSpec {
  readonly ca: TestCert;
  readonly thisUpdate?: Date;
  /** null omits nextUpdate. */
  readonly nextUpdate?: Date | null;
  /** null omits the CRL number extension. */
  readonly number?: bigint | Buffer | null;
  /** null omits the version (v1). */
  readonly version?: number | null;
  readonly entries?: readonly {
    serialHex: string;
    date?: Date;
    extensions?: readonly Buffer[];
  }[];
  readonly extraExtensions?: readonly Buffer[];
  readonly omitAki?: boolean;
  readonly akiBytes?: Buffer;
  readonly issuerDer?: Buffer;
  readonly signedBy?: TestKey;
  /** Flip a bit of the signature. */
  readonly corruptSignature?: boolean;
}

export const makeCrl = (spec: CrlSpec): Buffer => {
  const signer = spec.signedBy ?? spec.ca.key;
  const algorithm = caSignatureAlgorithmIdentifier(signer.algorithm);
  const thisUpdate = spec.thisUpdate ?? new Date(Date.now() - hours(1));
  const nextUpdate =
    spec.nextUpdate === undefined
      ? new Date(thisUpdate.getTime() + days(7))
      : spec.nextUpdate;
  const number = spec.number === undefined ? 1n : spec.number;
  const extensions = [
    ...(spec.omitAki === true
      ? []
      : [
          extension(
            EXT.authorityKeyIdentifier,
            false,
            authorityKeyIdentifierValue(
              spec.akiBytes ??
                spec.ca.cert.subjectKeyIdentifier ??
                Buffer.alloc(0),
            ),
          ),
        ]),
    ...(number === null
      ? []
      : [
          extension(
            EXT.crlNumber,
            false,
            typeof number === "bigint"
              ? crlNumberValue(number)
              : unsignedInteger(number),
          ),
        ]),
    ...(spec.extraExtensions ?? []),
  ];
  const entries = spec.entries ?? [];
  const tbs = seq(
    ...(spec.version === null ? [] : [smallInteger(spec.version ?? 1)]),
    algorithm,
    spec.issuerDer ?? spec.ca.cert.subjectDer,
    encodeTime(thisUpdate),
    ...(nextUpdate === null ? [] : [encodeTime(nextUpdate)]),
    ...(entries.length > 0
      ? [
          seq(
            ...entries.map((entry) =>
              seq(
                unsignedInteger(Buffer.from(entry.serialHex, "hex")),
                encodeTime(entry.date ?? thisUpdate),
                ...(entry.extensions === undefined
                  ? []
                  : [seq(...entry.extensions)]),
              ),
            ),
          ),
        ]
      : []),
    ...(extensions.length > 0 ? [explicit(0, seq(...extensions))] : []),
  );
  const signature = signer.sign(tbs);
  if (spec.corruptSignature === true) {
    signature[signature.length - 1] =
      (signature[signature.length - 1] as number) ^ 1;
  }
  return assembleCrl(tbs, algorithm, signature);
};

export const crlPem = (der: Uint8Array): string => toPem(der, "X509 CRL");

/** ENUMERATED-valued reason code extension with an arbitrary code (for removeFromCRL = 8). */
export const rawReasonExtension = (code: number): Buffer =>
  extension(EXT.reasonCode, false, tlv(TAG.enumerated, Buffer.from([code])));

/** A P-256 leaf CSR with a common name and optional DNS SANs, for the issuance suites. */
export const makeLeafCsr = (options: {
  commonName: string;
  dns?: readonly string[];
}): { pem: string; privateKeyPem: string } => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const extensions =
    options.dns === undefined || options.dns.length === 0
      ? []
      : [
          extension(
            EXT.subjectAltName,
            false,
            encodeSubjectAltName({ dns: options.dns }),
          ),
        ];
  const info = seq(
    smallInteger(0),
    subjectDer(options.commonName),
    publicKey.export({ type: "spki", format: "der" }),
    tlv(
      0xa0,
      ...(extensions.length === 0
        ? []
        : [seq(oid(EXT.extensionRequest), set(seq(...extensions)))]),
    ),
  );
  const signature = sign("sha256", info, {
    key: privateKey,
    dsaEncoding: "der",
  });
  return {
    pem: toPem(
      seq(info, seq(oid(OID.ecdsaSha256)), bitString(signature)),
      "CERTIFICATE REQUEST",
    ),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
};
