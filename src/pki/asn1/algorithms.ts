import {
  createPublicKey,
  verify,
  constants,
  type KeyObject,
} from "node:crypto";
import type { LeafKeyAlgorithm, PkiKeyAlgorithm } from "../types";
import {
  children,
  decodeOid,
  decodeUnsignedInteger,
  derNull,
  expectTag,
  oid,
  parseDer,
  seq,
  TAG,
  type Tlv,
} from "./der";

export const OID = {
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsaPss: "1.2.840.113549.1.1.10",
  sha256WithRsa: "1.2.840.113549.1.1.11",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  mgf1: "1.2.840.113549.1.1.8",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  prime256v1: "1.2.840.10045.3.1.7",
  secp384r1: "1.3.132.0.34",
  secp521r1: "1.3.132.0.35",
  ed25519: "1.3.101.112",
} as const;

export class PublicKeyError extends Error {
  public constructor(
    public readonly reason:
      | "malformed_public_key"
      | "unsupported_key_algorithm"
      | "explicit_ec_parameters"
      | "unsupported_curve",
  ) {
    super(`Unsupported or malformed public key (${reason}).`);
  }
}

export interface AlgorithmIdentifierParts {
  readonly oid: string;
  /** Raw parameters element, when present. */
  readonly parameters?: Tlv;
  readonly raw: Buffer;
}

export const parseAlgorithmIdentifier = (
  element: Tlv,
): AlgorithmIdentifierParts => {
  expectTag(element, TAG.sequence, "an AlgorithmIdentifier");
  const [id, parameters, ...extra] = children(element);
  if (id === undefined || extra.length > 0) {
    throw new PublicKeyError("malformed_public_key");
  }
  return { oid: decodeOid(id), parameters, raw: element.raw };
};

interface SignatureAlgorithm {
  readonly oid: string;
  /** The signed digest, or null for Ed25519. */
  readonly digest: "sha256" | "sha384" | "sha512" | null;
  readonly key: "ec" | "rsa" | "ed25519";
  readonly nullParameters: boolean;
}

const signatureAlgorithms: Record<string, SignatureAlgorithm> = {
  [OID.ecdsaSha256]: {
    oid: OID.ecdsaSha256,
    digest: "sha256",
    key: "ec",
    nullParameters: false,
  },
  [OID.ecdsaSha384]: {
    oid: OID.ecdsaSha384,
    digest: "sha384",
    key: "ec",
    nullParameters: false,
  },
  [OID.ecdsaSha512]: {
    oid: OID.ecdsaSha512,
    digest: "sha512",
    key: "ec",
    nullParameters: false,
  },
  [OID.sha256WithRsa]: {
    oid: OID.sha256WithRsa,
    digest: "sha256",
    key: "rsa",
    nullParameters: true,
  },
  [OID.sha384WithRsa]: {
    oid: OID.sha384WithRsa,
    digest: "sha384",
    key: "rsa",
    nullParameters: true,
  },
  [OID.sha512WithRsa]: {
    oid: OID.sha512WithRsa,
    digest: "sha512",
    key: "rsa",
    nullParameters: true,
  },
  [OID.ed25519]: {
    oid: OID.ed25519,
    digest: null,
    key: "ed25519",
    nullParameters: false,
  },
};

/** The signature algorithm Hemlig uses for each CA key type (see "Key custody (WRAPPED)"). */
export const caSignatureAlgorithm = (
  algorithm: PkiKeyAlgorithm,
): SignatureAlgorithm => {
  switch (algorithm) {
    case "ECDSA_P256":
      return signatureAlgorithms[OID.ecdsaSha256] as SignatureAlgorithm;
    case "ECDSA_P384":
      return signatureAlgorithms[OID.ecdsaSha384] as SignatureAlgorithm;
    case "RSA_3072":
    case "RSA_4096":
      return signatureAlgorithms[OID.sha256WithRsa] as SignatureAlgorithm;
    case "ED25519":
      return signatureAlgorithms[OID.ed25519] as SignatureAlgorithm;
  }
};

/** DER AlgorithmIdentifier for a CA key's signature algorithm. */
export const caSignatureAlgorithmIdentifier = (
  algorithm: PkiKeyAlgorithm,
): Buffer => {
  const alg = caSignatureAlgorithm(algorithm);
  return alg.nullParameters ? seq(oid(alg.oid), derNull()) : seq(oid(alg.oid));
};

const hashOids: Record<string, "sha256" | "sha384" | "sha512"> = {
  [OID.sha256]: "sha256",
  [OID.sha384]: "sha384",
  [OID.sha512]: "sha512",
};

const hashLength = { sha256: 32, sha384: 48, sha512: 64 } as const;

const pssParameters = (
  parameters: Tlv | undefined,
): { digest: "sha256" | "sha384" | "sha512"; saltLength: number } => {
  if (parameters === undefined || parameters.tag !== TAG.sequence) {
    throw new Error("RSASSA-PSS parameters are required.");
  }
  let digest: "sha256" | "sha384" | "sha512" | undefined;
  let mgfDigest: "sha256" | "sha384" | "sha512" | undefined;
  let saltLength = 20;
  for (const field of children(parameters)) {
    const inner = children(field)[0];
    if (inner === undefined) {
      throw new Error("Malformed RSASSA-PSS parameters.");
    }
    if (field.tag === 0xa0) {
      digest = hashOids[parseAlgorithmIdentifier(inner).oid];
    } else if (field.tag === 0xa1) {
      const mgf = parseAlgorithmIdentifier(inner);
      if (mgf.oid !== OID.mgf1 || mgf.parameters === undefined) {
        throw new Error("Unsupported MGF.");
      }
      mgfDigest = hashOids[parseAlgorithmIdentifier(mgf.parameters).oid];
    } else if (field.tag === 0xa2) {
      saltLength = Number(
        BigInt("0x" + decodeUnsignedInteger(inner).toString("hex")),
      );
    } else if (field.tag !== 0xa3) {
      throw new Error("Malformed RSASSA-PSS parameters.");
    }
  }
  if (
    digest === undefined ||
    mgfDigest !== digest ||
    saltLength > hashLength[digest]
  ) {
    throw new Error("Unsupported RSASSA-PSS parameters.");
  }
  return { digest, saltLength };
};

export const spkiToKeyObject = (spkiDer: Uint8Array): KeyObject =>
  createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" });

/** True when `signature` is a valid signature over `data` by the key in `spkiDer` under `algorithm`. Never throws. */
export const verifySignature = (
  spkiDer: Uint8Array,
  algorithm: AlgorithmIdentifierParts,
  data: Uint8Array,
  signature: Uint8Array,
): boolean => {
  try {
    const key = spkiToKeyObject(spkiDer);
    if (algorithm.oid === OID.rsaPss) {
      if (key.asymmetricKeyType !== "rsa") {
        return false;
      }
      const { digest, saltLength } = pssParameters(algorithm.parameters);
      return verify(
        digest,
        data,
        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength },
        signature,
      );
    }
    const known = signatureAlgorithms[algorithm.oid];
    if (known === undefined || key.asymmetricKeyType !== known.key) {
      return false;
    }
    if (known.nullParameters) {
      if (
        algorithm.parameters === undefined ||
        algorithm.parameters.tag !== TAG.null
      ) {
        return false;
      }
    } else if (algorithm.parameters !== undefined) {
      return false;
    }
    if (known.key === "ec") {
      return verify(known.digest, data, { key, dsaEncoding: "der" }, signature);
    }
    return verify(known.digest, data, key, signature);
  } catch {
    return false;
  }
};

export type PublicKeyInfo =
  | {
      readonly kind: "rsa";
      readonly bits: number;
      readonly modulus: bigint;
      readonly exponent: bigint;
    }
  | { readonly kind: "ec"; readonly curve: "P-256" | "P-384" | "P-521" }
  | { readonly kind: "ed25519" };

const curves: Record<string, "P-256" | "P-384" | "P-521"> = {
  [OID.prime256v1]: "P-256",
  [OID.secp384r1]: "P-384",
  [OID.secp521r1]: "P-521",
};

const base64UrlToBigInt = (value: string): bigint =>
  BigInt("0x" + Buffer.from(value, "base64url").toString("hex"));

/** Classifies a SubjectPublicKeyInfo. Explicit EC parameters, unknown curves and unknown algorithms are refused. */
export const describePublicKey = (spkiDer: Uint8Array): PublicKeyInfo => {
  let algorithm: AlgorithmIdentifierParts;
  try {
    const spki = parseDer(spkiDer);
    const [algorithmElement, bits, ...extra] = children(spki);
    if (
      spki.tag !== TAG.sequence ||
      algorithmElement === undefined ||
      bits?.tag !== TAG.bitString ||
      extra.length > 0
    ) {
      throw new PublicKeyError("malformed_public_key");
    }
    algorithm = parseAlgorithmIdentifier(algorithmElement);
  } catch (error) {
    throw error instanceof PublicKeyError
      ? error
      : new PublicKeyError("malformed_public_key");
  }
  let key: KeyObject;
  const load = (): KeyObject => {
    // The SPKI must be the canonical encoding of the key it holds: no trailing bytes, no alternate forms.
    try {
      const loaded = spkiToKeyObject(spkiDer);
      const canonical = loaded.export({ type: "spki", format: "der" });
      if (!canonical.equals(Buffer.from(spkiDer))) {
        throw new Error("non-canonical SPKI");
      }
      return loaded;
    } catch {
      throw new PublicKeyError("malformed_public_key");
    }
  };
  switch (algorithm.oid) {
    case OID.rsaEncryption: {
      if (algorithm.parameters?.tag !== TAG.null) {
        throw new PublicKeyError("malformed_public_key");
      }
      key = load();
      const jwk = key.export({ format: "jwk" });
      if (jwk.n === undefined || jwk.e === undefined) {
        throw new PublicKeyError("malformed_public_key");
      }
      const modulus = base64UrlToBigInt(jwk.n);
      return {
        kind: "rsa",
        bits: modulus.toString(2).length,
        modulus,
        exponent: base64UrlToBigInt(jwk.e),
      };
    }
    case OID.ecPublicKey: {
      const parameters = algorithm.parameters;
      if (parameters?.tag === TAG.sequence) {
        throw new PublicKeyError("explicit_ec_parameters");
      }
      if (parameters?.tag !== TAG.oid) {
        throw new PublicKeyError("malformed_public_key");
      }
      const curve = curves[decodeOid(parameters)];
      if (curve === undefined) {
        throw new PublicKeyError("unsupported_curve");
      }
      load();
      return { kind: "ec", curve };
    }
    case OID.ed25519:
      if (algorithm.parameters !== undefined) {
        throw new PublicKeyError("malformed_public_key");
      }
      load();
      return { kind: "ed25519" };
    default:
      throw new PublicKeyError("unsupported_key_algorithm");
  }
};

/** The leaf key algorithm name, or undefined for sizes outside the allowed set (such as RSA 2560). */
export const leafKeyAlgorithm = (
  info: PublicKeyInfo,
): LeafKeyAlgorithm | undefined => {
  switch (info.kind) {
    case "ec":
      return info.curve === "P-256"
        ? "ECDSA_P256"
        : info.curve === "P-384"
          ? "ECDSA_P384"
          : "ECDSA_P521";
    case "ed25519":
      return "ED25519";
    case "rsa":
      return (
        {
          2048: "RSA_2048",
          3072: "RSA_3072",
          4096: "RSA_4096",
          8192: "RSA_8192",
        } as const
      )[info.bits as 2048 | 3072 | 4096 | 8192];
  }
};

/** The CA key algorithm of an SPKI, or undefined when it isn't one Hemlig offers for CA keys. */
export const pkiKeyAlgorithm = (
  info: PublicKeyInfo,
): PkiKeyAlgorithm | undefined => {
  const leaf = leafKeyAlgorithm(info);
  return leaf === "ECDSA_P256" ||
    leaf === "ECDSA_P384" ||
    leaf === "RSA_3072" ||
    leaf === "RSA_4096" ||
    leaf === "ED25519"
    ? leaf
    : undefined;
};
