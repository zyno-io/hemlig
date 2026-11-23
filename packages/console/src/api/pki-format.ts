import {
  pkiCaKind,
  pkiKeyAlgorithm,
  pkiLeafKeyAlgorithm,
  type PkiCaKind,
  type PkiKeyAlgorithm,
  type PkiLeafKeyAlgorithm,
  type PkiLeafRevocationReason,
} from "./pki-schemas";

/**
 * Shared PKI helpers: constants, durations, dates, and PEM inspection. None of
 * this parses ASN.1; the server is the validator. The checks here only keep an
 * obviously wrong or dangerous paste (above all a private key) from ever
 * leaving the browser.
 */

export const CA_KEY_ALGORITHMS: readonly PkiKeyAlgorithm[] = pkiKeyAlgorithm.options;
export const LEAF_KEY_ALGORITHMS: readonly PkiLeafKeyAlgorithm[] =
  pkiLeafKeyAlgorithm.options;
export const CA_KINDS: readonly PkiCaKind[] = pkiCaKind.options;

export const LEAF_REVOCATION_REASONS: readonly PkiLeafRevocationReason[] = [
  "unspecified",
  "keyCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
];

export const ED25519_WARNING =
  "Browsers don't accept Ed25519 chains, and some TLS stacks, libraries and hardware don't support them. Go, OpenSSL 1.1.1 and later, and rustls do. Test BoringSSL-based and JVM stacks (such as Envoy and Java) yourself. Prefer P-256 or P-384 unless every verifier is known.";

export const EXTERNAL_ROOT_RECOMMENDATION =
  "An external offline root is strongly recommended: this ROOT's key is WRAPPED and online, so a compromised PKI role can copy it, and local distrust only reaches relying parties that use Hemlig trust bundles.";

/** Mirrors `MAX_CA_PEM_BYTES` in src/pki/ca-model.ts. */
export const MAX_PEM_BYTES = 32_768;
/** Upper bound on a CRL, as PEM or base64 DER. */
export const MAX_CRL_CHARS = 720_000;

// ---------------------------------------------------------- Durations

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86_400 } as const;

/** `"90d"` becomes `7776000`. Only `s`, `m`, `h` and `d` are accepted. */
export const parseDuration = (text: string): number | undefined => {
  const match = /^(\d+)([smhd])$/.exec(text.trim());
  if (match === null) {
    return undefined;
  }
  const seconds = Number(match[1]) * UNIT_SECONDS[match[2] as keyof typeof UNIT_SECONDS];
  return Number.isSafeInteger(seconds) ? seconds : undefined;
};

/** The largest unit that divides `seconds` exactly, so it round-trips. */
export const formatDuration = (seconds: number): string => {
  for (const unit of ["d", "h", "m"] as const) {
    if (seconds !== 0 && seconds % UNIT_SECONDS[unit] === 0) {
      return `${seconds / UNIT_SECONDS[unit]}${unit}`;
    }
  }
  return `${seconds}s`;
};

// -------------------------------------------------------------- Dates

const pad = (value: number): string => String(value).padStart(2, "0");

/** A `datetime-local` value (local time) to an ISO instant. Empty or invalid is undefined. */
export const localInputToIso = (value: string): string | undefined => {
  if (value.trim() === "") {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
};

/** An ISO instant to a `datetime-local` value in local time. */
export const isoToLocalInput = (iso: string | undefined): string => {
  if (iso === undefined) {
    return "";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

/** Whole days from `now` until `iso`; negative once past. */
export const daysUntil = (iso: string, now: Date = new Date()): number =>
  Math.floor((new Date(iso).getTime() - now.getTime()) / 86_400_000);

// --------------------------------------------------------------- PEM

export type PemKind = "certificate" | "chain" | "csr" | "crl";

export interface PemInspection {
  /** True when any private key marker is present; the input must never be sent. */
  readonly privateKey: boolean;
  /** Number of PEM blocks found. */
  readonly blocks: number;
  /** Human-readable problems; empty when the text looks acceptable. */
  readonly problems: readonly string[];
}

const PRIVATE_KEY_MARKER = /PRIVATE KEY( BLOCK)?-----/;
const BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;
const BASE64_BODY = /^[A-Za-z0-9+/=\s]+$/;

const byteLength = (text: string): number => new TextEncoder().encode(text).length;

/**
 * Checks that DER bytes have the outer shape of a certificate, CSR or CRL:
 * a SEQUENCE with a consistent length whose first element is a SEQUENCE.
 * Private keys (PKCS#8, RSA, EC) start with an INTEGER instead.
 */
export const derShapeProblem = (bytes: Uint8Array): string | undefined => {
  const invalid = "Expected a DER certificate, CSR or CRL. It is not sent.";
  if (bytes.length < 4 || bytes[0] !== 0x30) {
    return invalid;
  }
  let offset = 2;
  let length = bytes[1] ?? 0;
  if (length >= 0x80) {
    const count = length - 0x80;
    if (count < 1 || count > 4 || bytes.length < 2 + count) {
      return invalid;
    }
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + (bytes[2 + index] ?? 0);
    }
    offset = 2 + count;
  }
  if (offset + length !== bytes.length || bytes[offset] !== 0x30) {
    return invalid;
  }
  return undefined;
};

const base64Bytes = (text: string): Uint8Array | undefined => {
  try {
    return Uint8Array.from(atob(text.replace(/\s+/g, "")), (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
};

export const inspectPem = (text: string, kind: PemKind): PemInspection => {
  const problems: string[] = [];
  const labels = [...text.matchAll(BLOCK)].map((match) => match[1] ?? "");
  const privateKey = PRIVATE_KEY_MARKER.test(text);
  if (privateKey) {
    problems.push("This looks like a private key. It is not sent.");
  }

  const wrongLabels = (allowed: readonly string[]): number =>
    labels.filter((label) => !allowed.includes(label)).length;

  switch (kind) {
    case "certificate": {
      if (labels.filter((label) => label === "CERTIFICATE").length !== 1 || labels.length !== 1) {
        problems.push("Expected exactly one CERTIFICATE block.");
      }
      break;
    }
    case "chain": {
      if (labels.filter((label) => label === "CERTIFICATE").length < 1) {
        problems.push("Expected at least one CERTIFICATE block.");
      } else if (wrongLabels(["CERTIFICATE"]) > 0) {
        problems.push("Only CERTIFICATE blocks are accepted in a chain.");
      }
      break;
    }
    case "csr": {
      // Any key type: deliberately not `inspectCsr`, which accepts RSA only.
      const csr = labels.filter(
        (label) => label === "CERTIFICATE REQUEST" || label === "NEW CERTIFICATE REQUEST",
      );
      if (csr.length !== 1 || labels.length !== 1) {
        problems.push("Expected exactly one CERTIFICATE REQUEST block.");
      }
      break;
    }
    case "crl": {
      if (labels.length === 0) {
        if (!BASE64_BODY.test(text) || text.trim() === "") {
          problems.push("Expected an X509 CRL PEM block or base64 DER.");
        } else {
          const bytes = base64Bytes(text);
          const problem = bytes === undefined ? undefined : derShapeProblem(bytes);
          if (problem !== undefined) {
            problems.push(problem);
          }
        }
      } else if (labels.length !== 1 || labels[0] !== "X509 CRL") {
        problems.push("Expected exactly one X509 CRL block.");
      }
      break;
    }
  }

  if (kind === "crl") {
    if (text.length > MAX_CRL_CHARS) {
      problems.push("The CRL is too large.");
    }
  } else if (byteLength(text) > MAX_PEM_BYTES) {
    problems.push("The PEM is larger than 32 KiB.");
  }
  return { privateKey, blocks: labels.length, problems };
};

/** Base64 bodies of every PEM block (or the raw base64), whitespace removed. */
const pemBodies = (text: string): string => {
  const bodies = [...text.matchAll(BLOCK)].map((match) =>
    match[0]
      .replace(/-----(BEGIN|END) [A-Z0-9 ]+-----/g, "")
      .replace(/\s+/g, ""),
  );
  return bodies.length > 0 ? bodies.join("|") : text.replace(/\s+/g, "");
};

/** Equal ignoring line endings, wrapping and surrounding whitespace. */
export const pemBodiesEqual = (a: string, b: string): boolean =>
  pemBodies(a) === pemBodies(b);

// ------------------------------------------------------------- Files

export type PemFileResult =
  | { readonly text: string; readonly problem?: undefined }
  | { readonly problem: string; readonly text?: undefined };

const readBytes = (file: Blob): Promise<Uint8Array> =>
  new Promise((resolve, reject) => {
    // FileReader rather than Blob.arrayBuffer(): jsdom may lack the latter.
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("The file could not be read."));
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.readAsArrayBuffer(file);
  });

const latin1 = (bytes: Uint8Array): string => {
  let out = "";
  for (let index = 0; index < bytes.length; index += 8192) {
    out += String.fromCharCode(...bytes.subarray(index, index + 8192));
  }
  return out;
};

const wrap64 = (base64: string): string => base64.replace(/(.{64})/g, "$1\n").trimEnd();

const DER_LABEL: Record<PemKind, string | undefined> = {
  certificate: "CERTIFICATE",
  chain: "CERTIFICATE",
  csr: "CERTIFICATE REQUEST",
  crl: undefined,
};

/**
 * Reads a file as PEM text, or as base64 for a DER CRL. The raw bytes are
 * scanned as latin1 for a private key marker first, so a DER-wrapped or
 * binary container is refused the same as a PEM one.
 */
export const fileToPemOrBase64 = async (
  file: Blob,
  kind: PemKind,
): Promise<PemFileResult> => {
  const limit = kind === "crl" ? Math.ceil((MAX_CRL_CHARS * 3) / 4) : MAX_PEM_BYTES;
  if (file.size > limit) {
    return { problem: "The file is too large." };
  }
  const bytes = await readBytes(file);
  const raw = latin1(bytes);
  if (PRIVATE_KEY_MARKER.test(raw)) {
    return { problem: "This file contains a private key. It is not sent." };
  }
  if (raw.includes("-----BEGIN ")) {
    return { text: new TextDecoder().decode(bytes) };
  }
  const shape = derShapeProblem(bytes);
  if (shape !== undefined) {
    return { problem: shape };
  }
  const base64 = btoa(raw);
  const label = DER_LABEL[kind];
  return {
    text:
      label === undefined
        ? base64
        : `-----BEGIN ${label}-----\n${wrap64(base64)}\n-----END ${label}-----\n`,
  };
};
