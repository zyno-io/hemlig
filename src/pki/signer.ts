import { createPrivateKey, sign } from "node:crypto";
import {
  unwrapCaKey,
  type CaKeyBinding,
  type PkiKmsClient,
} from "./wrapped-keys";
import { ApiError } from "../domain/errors";
import type { PkiKeyAlgorithm, WrappedKey } from "./types";

/** Signs the to-be-signed bytes of a certificate, CRL or CSR with one CA key. */
export interface CaSigner {
  readonly algorithm: PkiKeyAlgorithm;
  sign(tbs: Uint8Array): Promise<Uint8Array>;
}

/**
 * Signs with a plaintext PKCS#8 key. ECDSA output is DER (`dsaEncoding: "der"`), Ed25519 output is the raw 64 bytes
 * (RFC 8410) and RSA is PKCS#1 v1.5 with SHA-256.
 */
export const signWithPkcs8 = (
  algorithm: PkiKeyAlgorithm,
  pkcs8Der: Buffer,
  data: Uint8Array,
): Buffer => {
  // Pass the caller's buffer straight through: a copy here would be a plaintext the caller cannot zero.
  const key = createPrivateKey({
    key: pkcs8Der,
    format: "der",
    type: "pkcs8",
  });
  switch (algorithm) {
    case "ECDSA_P256":
      return sign("sha256", data, { key, dsaEncoding: "der" });
    case "ECDSA_P384":
      return sign("sha384", data, { key, dsaEncoding: "der" });
    case "RSA_3072":
    case "RSA_4096":
      return sign("sha256", data, key);
    case "ED25519":
      return sign(null, data, key);
  }
};

export interface WrappedCaSignerOptions extends CaKeyBinding {
  readonly kms: PkiKmsClient;
  /** The application CMK. */
  readonly kmsKeyId: string;
  readonly algorithm: PkiKeyAlgorithm;
  readonly wrapped: WrappedKey;
}

/**
 * `kms:Decrypt` (purpose `pki-ca`), then `node:crypto.sign`, then the decrypted buffer is zeroed. Zeroing is best
 * effort: Node's `KeyObject` copy lives until garbage collection. Plaintext is never cached across calls.
 */
export class WrappedCaSigner implements CaSigner {
  public readonly algorithm: PkiKeyAlgorithm;

  public constructor(private readonly options: WrappedCaSignerOptions) {
    this.algorithm = options.algorithm;
  }

  public async sign(tbs: Uint8Array): Promise<Uint8Array> {
    const pkcs8 = await unwrapCaKey(
      this.options.kms,
      this.options.kmsKeyId,
      this.options.wrapped,
      {
        caId: this.options.caId,
        environment: this.options.environment,
      },
    );
    try {
      return signWithPkcs8(this.algorithm, pkcs8, tbs);
    } catch {
      throw new ApiError(
        409,
        "ca_key_unavailable",
        "The CA key is unavailable.",
        "ca_key_unavailable",
      );
    } finally {
      pkcs8.fill(0);
    }
  }
}
