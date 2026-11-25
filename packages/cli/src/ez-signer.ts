import { generateKeyPairSync, sign as cryptoSign, createPublicKey, type KeyObject } from "node:crypto";
import { children, DerError, decodeUint, parseDer, TAG, uint, seq } from "./ez-der";
import { EzError } from "./ez-error";
import {
  describeSpki,
  signatureAlgorithmForSpki,
  verifySignature,
  type EzKeyAlgorithm,
  type KeyInfo,
  type SignatureAlgorithm,
} from "./ez-x509";

/**
 * The signer interface. The root key may be a software key (here) or a YubiKey slot (later); both implement
 * `RootSigner`. Signing is batched: one device session and one PIN cover every signature in a command.
 */

/** One thing to sign. `description` is what an operator sees in a confirmation; `touch` events carry the `id`. */
export interface SignItem {
  /** Stable identifier within a batch, for example `certificate`, `crl`, `test`. */
  readonly id: string;
  /** Human-readable summary for confirmation prompts and touch notices. */
  readonly description: string;
  /** The exact bytes to sign (a TBS structure). */
  readonly data: Buffer;
}

export interface SignEvents {
  /** The device is waiting for a touch to sign this item (YubiKey signers call it). */
  readonly onTouch?: (item: SignItem) => void;
}

export interface RootSigner {
  /** `ECDSA_P384`, `RSA_3072`, and so on. */
  readonly keyAlgorithm: string;
  readonly signatureAlgorithm: SignatureAlgorithm;
  /** The public key the signer proves it holds (checked against the root certificate before any signature). */
  readonly spkiDer: Buffer;
  /**
   * Signs every item and returns the signatures in order: DER for ECDSA, PKCS#1 v1.5 for RSA. A hardware signer may
   * return raw r||s, which `signBatch` normalizes.
   */
  sign(items: readonly SignItem[], events?: SignEvents): Promise<Buffer[]>;
  close(): void | Promise<void>;
}

/**
 * Called with the full batch before the first signature. Throw to abort: the typed `confirm` step of the interactive
 * commands plugs in here, and an abort leaves no state behind because nothing has been signed yet.
 */
export type SignConfirmation = (items: readonly SignItem[]) => void | Promise<void>;

/** Converts a raw r||s ECDSA signature to DER; a DER signature passes through (validated). */
export const normalizeEcdsa = (signature: Buffer, coordinateLength: number): Buffer => {
  try {
    const root = parseDer(signature);
    const parts = root.tag === TAG.sequence ? children(root) : [];
    if (parts.length === 2 && parts.every((p) => p.tag === TAG.integer)) {
      decodeUint(parts[0]!);
      decodeUint(parts[1]!);
      return signature;
    }
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
  }
  if (signature.length === coordinateLength * 2) {
    return seq(uint(signature.subarray(0, coordinateLength)), uint(signature.subarray(coordinateLength)));
  }
  throw new EzError(7, "signature_self_check_failed", "The signer returned an unrecognized ECDSA signature encoding.");
};

/** Fails with exit 7 `signature_self_check_failed` unless `signature` verifies. */
export const verifyOrThrow = (spkiDer: Buffer, algorithmIdentifier: Buffer, data: Uint8Array, signature: Uint8Array): void => {
  if (!verifySignature(spkiDer, algorithmIdentifier, data, signature)) {
    throw new EzError(7, "signature_self_check_failed", "A signature did not verify under the root key; nothing was written.");
  }
};

/**
 * Confirms (if asked), signs the batch, normalizes ECDSA output and verifies every signature before returning it.
 * Every signer path goes through here, so no artifact is built from an unchecked signature.
 */
export const signBatch = async (
  signer: RootSigner,
  items: readonly SignItem[],
  options: { readonly confirm?: SignConfirmation; readonly events?: SignEvents } = {},
): Promise<Buffer[]> => {
  if (options.confirm !== undefined) await options.confirm(items);
  const raw = await signer.sign(items, options.events);
  if (raw.length !== items.length) {
    throw new EzError(7, "signature_self_check_failed", "The signer returned the wrong number of signatures.");
  }
  const info: KeyInfo = describeSpki(signer.spkiDer);
  return raw.map((signature, index) => {
    const item = items[index] as SignItem;
    const normalized =
      info.keyType === "ec" ? normalizeEcdsa(signature, info.coordinateLength as number) : signature;
    verifyOrThrow(signer.spkiDer, signer.signatureAlgorithm.algorithmIdentifier, item.data, normalized);
    return normalized;
  });
};

/** A software private key signer. */
export class SoftwareSigner implements RootSigner {
  public readonly spkiDer: Buffer;
  public readonly keyAlgorithm: string;
  public readonly signatureAlgorithm: SignatureAlgorithm;
  #key: KeyObject | undefined;

  public constructor(privateKey: KeyObject) {
    this.#key = privateKey;
    this.spkiDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    this.keyAlgorithm = describeSpki(this.spkiDer).algorithm;
    this.signatureAlgorithm = signatureAlgorithmForSpki(this.spkiDer);
  }

  public async sign(items: readonly SignItem[]): Promise<Buffer[]> {
    const key = this.#key;
    if (key === undefined) throw new EzError(7, "signer_closed", "The signer is closed.");
    const { hash, keyType } = this.signatureAlgorithm;
    return items.map((item) =>
      keyType === "ec"
        ? cryptoSign(hash, item.data, { key, dsaEncoding: "der" })
        : cryptoSign(hash, item.data, key),
    );
  }

  public close(): void {
    this.#key = undefined;
  }
}

export interface GeneratedKey {
  readonly privateKey: KeyObject;
  readonly spkiDer: Buffer;
  /** Plaintext PKCS#8; hand it to `encryptPkcs8`, which zeroes it. */
  exportPkcs8(): Buffer;
}

/** Generates a new root key in software. */
export const generateSoftwareKey = (algorithm: EzKeyAlgorithm): GeneratedKey => {
  const pair =
    algorithm === "ECDSA_P384"
      ? generateKeyPairSync("ec", { namedCurve: "P-384" })
      : algorithm === "ECDSA_P256"
        ? generateKeyPairSync("ec", { namedCurve: "P-256" })
        : algorithm === "RSA_3072"
          ? generateKeyPairSync("rsa", { modulusLength: 3072, publicExponent: 65537 })
          : algorithm === "RSA_4096"
            ? generateKeyPairSync("rsa", { modulusLength: 4096, publicExponent: 65537 })
            : undefined;
  if (pair === undefined) throw new EzError(2, "invalid_input", `Unsupported key algorithm ${String(algorithm)}.`);
  return {
    privateKey: pair.privateKey,
    spkiDer: pair.publicKey.export({ type: "spki", format: "der" }),
    exportPkcs8: () => pair.privateKey.export({ type: "pkcs8", format: "der" }),
  };
};
