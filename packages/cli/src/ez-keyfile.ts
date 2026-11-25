import { createCipheriv, createPrivateKey, pbkdf2Sync, randomBytes, type KeyObject } from "node:crypto";
import { children, decodeOid, decodeSmallInt, DerError, parseDer, oid, octetString, seq, smallInt, nullValue, TAG, type Tlv } from "./ez-der";
import { EzError } from "./ez-error";
import { fromPem, toPem } from "./ez-x509";

/**
 * The encrypted PKCS#8 key file: PBES2 (PBKDF2-HMAC-SHA256, 1,000,000 iterations, AES-256-CBC) as an
 * `ENCRYPTED PRIVATE KEY` PEM. Built by hand because Node's own `cipher` export uses only 2,048 iterations. OpenSSL
 * reads the result (`openssl pkey -passin file:...`), so the manual recipe stays a fallback.
 */

export const KEY_FILE_ITERATIONS = 1_000_000;
export const MIN_PASSPHRASE_BYTES = 12;
export const MAX_PASSPHRASE_BYTES = 1024;

const OID_PBES2 = "1.2.840.113549.1.5.13";
const OID_PBKDF2 = "1.2.840.113549.1.5.12";
const OID_HMAC_SHA256 = "1.2.840.113549.2.9";
const OID_AES256_CBC = "2.16.840.1.101.3.4.1.42";

const toBuffer = (passphrase: Buffer | string): Buffer =>
  typeof passphrase === "string" ? Buffer.from(passphrase, "utf8") : passphrase;

/** Refuses passphrases outside 12-1024 bytes. */
export const assertPassphrasePolicy = (passphrase: Buffer | string): void => {
  const length = toBuffer(passphrase).length;
  if (length < MIN_PASSPHRASE_BYTES) {
    throw new EzError(2, "invalid_input", `The passphrase must be at least ${MIN_PASSPHRASE_BYTES} bytes.`);
  }
  if (length > MAX_PASSPHRASE_BYTES) {
    throw new EzError(2, "invalid_input", `The passphrase must be at most ${MAX_PASSPHRASE_BYTES} bytes.`);
  }
};

/** Encrypts a PKCS#8 DER private key. The input buffer is zeroed. */
export const encryptPkcs8 = (pkcs8Der: Buffer, passphrase: Buffer | string): string => {
  const secret = toBuffer(passphrase);
  let key: Buffer | undefined;
  try {
    assertPassphrasePolicy(secret);
    const salt = randomBytes(16);
    const iv = randomBytes(16);
    key = pbkdf2Sync(secret, salt, KEY_FILE_ITERATIONS, 32, "sha256");
    const cipher = createCipheriv("aes-256-cbc", key, iv);
    const encrypted = Buffer.concat([cipher.update(pkcs8Der), cipher.final()]);
    const der = seq(
      seq(
        oid(OID_PBES2),
        seq(
          seq(
            oid(OID_PBKDF2),
            seq(octetString(salt), smallInt(KEY_FILE_ITERATIONS), seq(oid(OID_HMAC_SHA256), nullValue())),
          ),
          seq(oid(OID_AES256_CBC), octetString(iv)),
        ),
      ),
      octetString(encrypted),
    );
    return toPem(der, "ENCRYPTED PRIVATE KEY");
  } finally {
    key?.fill(0);
    pkcs8Der.fill(0);
  }
};

export interface KeyFileInfo {
  readonly encrypted: boolean;
  readonly kdf?: { readonly name: "pbkdf2-hmac-sha256"; readonly iterations: number };
  readonly cipher?: "aes-256-cbc";
}

/** Reads the PBES2 parameters of an EZ key file without decrypting it. */
export const inspectKeyFile = (pem: string): KeyFileInfo => {
  if (!pem.includes("BEGIN ENCRYPTED PRIVATE KEY")) return { encrypted: pem.includes("ENCRYPTED") };
  try {
    const root = parseDer(fromPem(pem, "ENCRYPTED PRIVATE KEY"));
    const [algorithm] = children(root) as [Tlv];
    const [id, params] = children(algorithm) as [Tlv, Tlv];
    if (decodeOid(id) !== OID_PBES2) return { encrypted: true };
    const [kdfAlg, cipherAlg] = children(params) as [Tlv, Tlv];
    const [kdfId, kdfParams] = children(kdfAlg) as [Tlv, Tlv];
    const [cipherId] = children(cipherAlg) as [Tlv];
    if (decodeOid(kdfId) !== OID_PBKDF2) return { encrypted: true };
    const [, iterations, prf] = children(kdfParams) as [Tlv, Tlv, Tlv | undefined];
    const prfOid = prf?.tag === TAG.sequence ? decodeOid(children(prf)[0] as Tlv) : "1.2.840.113549.2.7";
    return {
      encrypted: true,
      kdf:
        prfOid === OID_HMAC_SHA256
          ? { name: "pbkdf2-hmac-sha256", iterations: decodeSmallInt(iterations) }
          : undefined,
      cipher: decodeOid(cipherId) === OID_AES256_CBC ? "aes-256-cbc" : undefined,
    };
  } catch (error) {
    if (error instanceof DerError || error instanceof EzError) {
      throw new EzError(2, "key_file_invalid", "The key file is not a valid encrypted PKCS#8 document.");
    }
    throw error;
  }
};

export interface ReadKey {
  readonly key: KeyObject;
  readonly encrypted: boolean;
}

/**
 * Reads a private key PEM: an EZ key file, an OpenSSL-written encrypted key (2,048-iteration PBES2 or the legacy
 * `Proc-Type` form) or an unencrypted key (callers should warn). A wrong passphrase exits 3 with `passphrase_invalid`.
 */
export const readPrivateKey = (pem: string, passphrase?: Buffer | string): ReadKey => {
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(pem)) {
    throw new EzError(2, "key_file_invalid", "The file does not contain a PEM private key.");
  }
  const encrypted = /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) || /Proc-Type:\s*4,ENCRYPTED/.test(pem);
  try {
    const key = createPrivateKey(
      encrypted ? { key: pem, format: "pem", passphrase: passphrase === undefined ? undefined : toBuffer(passphrase) } : { key: pem, format: "pem" },
    );
    return { key, encrypted };
  } catch {
    if (encrypted) throw new EzError(3, "passphrase_invalid", "The passphrase is wrong, or the key file is damaged.");
    throw new EzError(2, "key_file_invalid", "The private key could not be parsed.");
  }
};

/** Decrypts an EZ key file. Refuses an unencrypted key. */
export const decryptKeyFile = (pem: string, passphrase: Buffer | string): KeyObject => {
  const result = readPrivateKey(pem, passphrase);
  if (!result.encrypted) throw new EzError(2, "key_file_invalid", "The key file is not encrypted.");
  return result.key;
};
