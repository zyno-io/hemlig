import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPair,
  randomBytes,
} from "node:crypto";
import {
  DecryptCommand,
  GenerateDataKeyCommand,
  type KMSClient,
} from "@aws-sdk/client-kms";
import { ApiError, serviceUnavailable } from "../domain/errors";
import { stableJson } from "../util/encoding";
import type { PkiKeyAlgorithm, WrappedKey } from "./types";

/** KMS is injected so tests can mock it. Only `GenerateDataKey` and `Decrypt` are used. */
export type PkiKmsClient = Pick<KMSClient, "send">;

export interface CaKeyBinding {
  readonly caId: string;
  readonly environment: string;
}

export interface GeneratedCaKey {
  readonly algorithm: PkiKeyAlgorithm;
  /** Plaintext PKCS#8. The caller wraps it and zeroes it. */
  readonly privateKeyDer: Buffer;
  readonly spkiDer: Buffer;
  /** Lowercase hex SHA-256 of the SPKI DER. */
  readonly spkiSha256: string;
}

/** The KMS encryption context, also the AES-GCM AAD: `caId` and `environment` bind the blob to its CA. */
export const caEncryptionContext = (
  binding: CaKeyBinding,
): Record<string, string> => ({
  service: "hemlig",
  purpose: "pki-ca",
  caId: binding.caId,
  environment: binding.environment,
});

const aad = (binding: CaKeyBinding): Buffer =>
  Buffer.from(stableJson(caEncryptionContext(binding)), "utf8");

const generate = (
  algorithm: PkiKeyAlgorithm,
): Promise<{ privateKey: Buffer; publicKey: Buffer }> =>
  new Promise((resolve, reject) => {
    const encodings = {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    } as const;
    const done = (
      error: Error | null,
      publicKey: Buffer,
      privateKey: Buffer,
    ): void =>
      error === null ? resolve({ privateKey, publicKey }) : reject(error);
    switch (algorithm) {
      case "ECDSA_P256":
        generateKeyPair("ec", { namedCurve: "prime256v1", ...encodings }, done);
        break;
      case "ECDSA_P384":
        generateKeyPair("ec", { namedCurve: "secp384r1", ...encodings }, done);
        break;
      case "RSA_3072":
        generateKeyPair(
          "rsa",
          { modulusLength: 3072, publicExponent: 65537, ...encodings },
          done,
        );
        break;
      case "RSA_4096":
        generateKeyPair(
          "rsa",
          { modulusLength: 4096, publicExponent: 65537, ...encodings },
          done,
        );
        break;
      case "ED25519":
        generateKeyPair("ed25519", encodings, done);
        break;
    }
  });

/** Generates a CA key pair. The key never leaves the process unwrapped. */
export const generateCaKeyPair = async (
  algorithm: PkiKeyAlgorithm,
): Promise<GeneratedCaKey> => {
  const { privateKey, publicKey } = await generate(algorithm);
  return {
    algorithm,
    privateKeyDer: privateKey,
    spkiDer: publicKey,
    spkiSha256: createHash("sha256").update(publicKey).digest("hex"),
  };
};

/** `GenerateDataKey` under the pki-ca context, then AES-256-GCM with the context as AAD (the `IssuerKeyEnvelope` shape). */
export const wrapCaKey = async (
  kms: PkiKmsClient,
  kmsKeyId: string,
  privateKeyDer: Uint8Array,
  binding: CaKeyBinding,
): Promise<WrappedKey> => {
  const generated = await kms.send(
    new GenerateDataKeyCommand({
      KeyId: kmsKeyId,
      KeySpec: "AES_256",
      EncryptionContext: caEncryptionContext(binding),
    }),
  );
  if (
    generated.Plaintext === undefined ||
    generated.CiphertextBlob === undefined
  ) {
    throw serviceUnavailable("KMS did not return a CA data key.");
  }
  const key = Buffer.from(generated.Plaintext);
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad(binding));
    const ciphertext = Buffer.concat([
      cipher.update(privateKeyDer),
      cipher.final(),
    ]);
    return {
      algorithm: "AES-256-GCM",
      encryptedDataKey: Buffer.from(generated.CiphertextBlob).toString(
        "base64",
      ),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  } finally {
    key.fill(0);
    generated.Plaintext.fill(0);
  }
};

const keyUnavailable = (): ApiError =>
  new ApiError(
    409,
    "ca_key_unavailable",
    "The CA key is unavailable.",
    "ca_key_unavailable",
  );

/** KMS errors that mean the blob cannot be decrypted at all (as opposed to KMS being unavailable). */
const undecryptable = new Set([
  "InvalidCiphertextException",
  "IncorrectKeyException",
  "InvalidKeyUsageException",
]);

/** Decrypts a wrapped key to plaintext PKCS#8. The caller zeroes the returned buffer. */
export const unwrapCaKey = async (
  kms: PkiKmsClient,
  kmsKeyId: string,
  wrapped: WrappedKey,
  binding: CaKeyBinding,
): Promise<Buffer> => {
  if (wrapped.algorithm !== "AES-256-GCM") {
    throw keyUnavailable();
  }
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = (
      await kms.send(
        new DecryptCommand({
          KeyId: kmsKeyId,
          CiphertextBlob: Buffer.from(wrapped.encryptedDataKey, "base64"),
          EncryptionContext: caEncryptionContext(binding),
        }),
      )
    ).Plaintext;
  } catch (error) {
    if (error instanceof Error && undecryptable.has(error.name)) {
      throw keyUnavailable();
    }
    if (error instanceof Error && error.name === "AccessDeniedException") {
      throw new ApiError(
        503,
        "service_unavailable",
        "KMS could not decrypt the CA key.",
        "kms_access_denied",
      );
    }
    throw serviceUnavailable("KMS could not decrypt the CA key.");
  }
  if (plaintext === undefined) {
    throw serviceUnavailable("KMS did not return plaintext key material.");
  }
  const key = Buffer.from(plaintext);
  let update: Buffer | undefined;
  let last: Buffer | undefined;
  try {
    const tag = Buffer.from(wrapped.tag, "base64");
    if (tag.length !== 16) {
      throw new Error("The GCM tag must be 16 bytes.");
    }
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(wrapped.iv, "base64"),
      { authTagLength: 16 },
    );
    decipher.setAAD(aad(binding));
    decipher.setAuthTag(tag);
    update = decipher.update(Buffer.from(wrapped.ciphertext, "base64"));
    last = decipher.final();
    return Buffer.concat([update, last]);
  } catch {
    throw keyUnavailable();
  } finally {
    // Every intermediate plaintext copy goes, not just the one returned.
    update?.fill(0);
    last?.fill(0);
    key.fill(0);
    plaintext.fill(0);
  }
};
