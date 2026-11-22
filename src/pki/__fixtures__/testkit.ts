import {
  constants,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { caSignatureAlgorithmIdentifier, OID } from "../asn1/algorithms";
import {
  assembleCertificate,
  buildCaTbs,
  buildTbsCertificate,
  parseCertificate,
  type ParsedCertificate,
} from "../asn1/certificate";
import { assembleCrl } from "../asn1/crl";
import {
  bitString,
  derNull,
  explicit,
  oid,
  seq,
  set,
  smallInteger,
  tlv,
  unsignedInteger,
  encodeTime,
  TAG,
} from "../asn1/der";
import {
  authorityKeyIdentifierValue,
  basicConstraintsValue,
  crlNumberValue,
  EXT,
  extension,
  keyIdentifierFromSpki,
  keyIdentifierValue,
  keyUsageValue,
} from "../asn1/extensions";
import { toPem } from "../asn1/pem";
import { signWithPkcs8 } from "../signer";
import { buildCaSubject } from "../subject";
import type { CaSubject, NameConstraintSet, PkiKeyAlgorithm } from "../types";
import { DecryptCommand, GenerateDataKeyCommand } from "@aws-sdk/client-kms";
import { generateCaKeyPair, type PkiKmsClient } from "../wrapped-keys";

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
}

/** A Hemlig-profile intermediate signed by `root`, built with the production `buildCaTbs`. */
export const makeIntermediate = async (
  root: TestCert,
  options: IntermediateOptions = {},
): Promise<TestCert> => {
  const key = options.key ?? (await newKey("ECDSA_P256"));
  const { tbs, signatureAlgorithm } = buildCaTbs({
    issuer: root.cert,
    serial: Buffer.from([9, 8, 7, 6, 5, 4, 3, 2]),
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

// ---------------------------------------------------------------------------------------------------------------------
// Golden files
// ---------------------------------------------------------------------------------------------------------------------

const fixtureDirectory = __dirname;

/**
 * Compares `data` with `__fixtures__/<name>`. A missing file, or `UPDATE_GOLDEN=1`, writes it instead, so a fixture
 * is regenerated by deleting it or by running the test with that variable set.
 */
export const expectGolden = (name: string, data: Uint8Array): void => {
  const path = join(fixtureDirectory, name);
  if (process.env.UPDATE_GOLDEN === "1" || !existsSync(path)) {
    writeFileSync(path, data);
    return;
  }
  expect(Buffer.from(data).toString("hex")).toBe(
    readFileSync(path).toString("hex"),
  );
};

export const readFixture = (name: string): Buffer =>
  readFileSync(join(fixtureDirectory, name));
export const hasFixture = (name: string): boolean =>
  existsSync(join(fixtureDirectory, name));
export const writeFixture = (name: string, data: Uint8Array): void =>
  writeFileSync(join(fixtureDirectory, name), data);

/** The fixed issuing CA and leaf SPKI behind the golden files. Created once and committed; see `expectGolden`. */
export const goldenFixtures = async (): Promise<{
  issuer: ParsedCertificate;
  leafSpki: Buffer;
}> => {
  if (!hasFixture("issuer.der")) {
    const root = await makeRoot();
    const intermediate = await makeIntermediate(root, {
      subject: { O: "Golden Corp", CN: "Golden Issuing CA 1" },
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2051-01-01T00:00:00Z"),
    });
    writeFixture("issuer.der", intermediate.cert.der);
    writeFixture("leaf-spki.der", (await newKey("ECDSA_P256")).spkiDer);
  }
  return {
    issuer: parseCertificate(readFixture("issuer.der")),
    leafSpki: readFixture("leaf-spki.der"),
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Leaf keys and CSRs
// ---------------------------------------------------------------------------------------------------------------------

export type LeafKeySpec =
  | {
      readonly type: "ec";
      readonly curve: "prime256v1" | "secp384r1" | "secp521r1" | "secp256k1";
    }
  | { readonly type: "rsa"; readonly bits: number; readonly exponent?: number }
  | { readonly type: "ed25519" };

export interface LeafKey {
  readonly spec: LeafKeySpec;
  readonly privateKey: KeyObject;
  readonly spkiDer: Buffer;
}

export const leafKey = (spec: LeafKeySpec): LeafKey => {
  const pair =
    spec.type === "ec"
      ? generateKeyPairSync("ec", { namedCurve: spec.curve })
      : spec.type === "rsa"
        ? generateKeyPairSync("rsa", {
            modulusLength: spec.bits,
            publicExponent: spec.exponent ?? 65537,
          })
        : generateKeyPairSync("ed25519");
  return {
    spec,
    privateKey: pair.privateKey,
    spkiDer: pair.publicKey.export({ type: "spki", format: "der" }),
  };
};

const sha256Params = (): Buffer => seq(oid(OID.sha256), derNull());

/** RSASSA-PSS-params for SHA-256, MGF1-SHA-256 and a 32-byte salt. */
const pssAlgorithm = (): Buffer =>
  seq(
    oid(OID.rsaPss),
    seq(
      explicit(0, sha256Params()),
      explicit(1, seq(oid(OID.mgf1), sha256Params())),
      explicit(2, smallInteger(32)),
    ),
  );

export interface CsrSpec {
  readonly key: LeafKey;
  readonly subject?: Buffer;
  /** Extensions placed in one extensionRequest attribute. */
  readonly extensions?: readonly Buffer[];
  /** Complete Attribute encodings, appended after (or replacing, with `onlyAttributes`) extensionRequest. */
  readonly attributes?: readonly Buffer[];
  readonly onlyAttributes?: boolean;
  readonly version?: number;
  /** Overrides the SPKI (for hand-crafted keys). */
  readonly spkiDer?: Buffer;
  readonly pss?: boolean;
  /** AlgorithmIdentifier override; the signature is still made with the key's natural algorithm. */
  readonly signatureAlgorithm?: Buffer;
  readonly corruptSignature?: boolean;
  readonly signedBy?: LeafKey;
}

export const extensionRequest = (extensions: readonly Buffer[]): Buffer =>
  seq(oid(EXT.extensionRequest), set(seq(...extensions)));

export const makeCsrDer = (spec: CsrSpec): Buffer => {
  const attributes = [
    ...(spec.onlyAttributes === true || spec.extensions === undefined
      ? []
      : [extensionRequest(spec.extensions)]),
    ...(spec.attributes ?? []),
  ];
  const info = seq(
    smallInteger(spec.version ?? 0),
    spec.subject ?? subjectDer({ CN: "csr.example.com" }),
    spec.spkiDer ?? spec.key.spkiDer,
    tlv(0xa0, ...attributes),
  );
  const signer = spec.signedBy ?? spec.key;
  let algorithm: Buffer;
  let signature: Buffer;
  if (signer.spec.type === "ec") {
    const digest =
      signer.spec.curve === "secp384r1"
        ? "sha384"
        : signer.spec.curve === "secp521r1"
          ? "sha512"
          : "sha256";
    algorithm = seq(
      oid(
        digest === "sha384"
          ? OID.ecdsaSha384
          : digest === "sha512"
            ? OID.ecdsaSha512
            : OID.ecdsaSha256,
      ),
    );
    signature = sign(digest, info, {
      key: signer.privateKey,
      dsaEncoding: "der",
    });
  } else if (signer.spec.type === "rsa" && spec.pss === true) {
    algorithm = pssAlgorithm();
    signature = sign("sha256", info, {
      key: signer.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
  } else if (signer.spec.type === "rsa") {
    algorithm = seq(oid(OID.sha256WithRsa), derNull());
    signature = sign("sha256", info, signer.privateKey);
  } else {
    algorithm = seq(oid(OID.ed25519));
    signature = sign(null, info, signer.privateKey);
  }
  if (spec.corruptSignature === true) {
    signature[signature.length - 1] =
      (signature[signature.length - 1] as number) ^ 1;
  }
  return seq(info, spec.signatureAlgorithm ?? algorithm, bitString(signature));
};

export const csrPem = (der: Uint8Array): string =>
  toPem(der, "CERTIFICATE REQUEST");

export { createPrivateKey, createPublicKey };

export const dataKey = Buffer.alloc(32, 0x42);

/** A KMS mock that hands out fresh copies of one data key, so zeroing is observable on the returned arrays. */
export const mockKms = (): {
  kms: PkiKmsClient;
  send: jest.Mock;
  handedOut: Uint8Array[];
} => {
  const handedOut: Uint8Array[] = [];
  const send = jest.fn(async (command: unknown) => {
    const plaintext = Uint8Array.from(dataKey);
    handedOut.push(plaintext);
    if (command instanceof GenerateDataKeyCommand) {
      return {
        Plaintext: plaintext,
        CiphertextBlob: Buffer.from("encrypted-data-key"),
      };
    }
    if (command instanceof DecryptCommand) {
      return { Plaintext: plaintext };
    }
    throw new Error("unexpected command");
  });
  return { kms: { send } as unknown as PkiKmsClient, send, handedOut };
};
