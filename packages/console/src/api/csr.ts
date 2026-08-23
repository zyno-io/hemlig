/**
 * Local pre-validation of a certificate signing request. Rejecting here saves
 * a round trip and, more importantly, a permanent audit object in a
 * Compliance-locked archive. The service re-validates everything.
 */
export const MAX_CSR_BYTES = 32 * 1024;

const pemBlock =
  /-----BEGIN CERTIFICATE REQUEST-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE REQUEST-----/;

export interface CsrProblem {
  readonly message: string;
}

export const inspectCsr = async (pem: string): Promise<CsrProblem | undefined> => {
  const trimmed = pem.trim();
  if (trimmed.length === 0) {
    return { message: "Paste or upload a PEM certificate signing request." };
  }
  if (new TextEncoder().encode(trimmed).length > MAX_CSR_BYTES) {
    return { message: "The request exceeds the 32 KiB limit." };
  }
  const matches = trimmed.match(new RegExp(pemBlock, "g"));
  if (matches === null || matches.length === 0) {
    return { message: "No BEGIN/END CERTIFICATE REQUEST block was found." };
  }
  if (matches.length > 1) {
    return { message: "Submit exactly one certificate signing request." };
  }
  const body = pemBlock.exec(trimmed)?.[1];
  if (body === undefined) {
    return { message: "The PEM block could not be read." };
  }
  let der: Uint8Array;
  try {
    const binary = atob(body.replace(/[\r\n]/g, ""));
    der = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return { message: "The PEM body is not valid base64." };
  }
  const bits = rsaModulusBits(der);
  if (bits === undefined) {
    return {
      message: "An RSA public key could not be read from the request.",
    };
  }
  if (bits < 2048) {
    return { message: `The RSA key is ${bits}-bit; 2048-bit or larger is required.` };
  }
  return undefined;
};

/**
 * Locates the RSA modulus inside the CSR's SubjectPublicKeyInfo without a full
 * ASN.1 parser: the rsaEncryption OID is followed by a BIT STRING wrapping an
 * RSAPublicKey SEQUENCE whose first INTEGER is the modulus.
 */
const rsaEncryptionOid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

const rsaModulusBits = (der: Uint8Array): number | undefined => {
  const oidAt = indexOfSequence(der, rsaEncryptionOid);
  if (oidAt === -1) {
    return undefined;
  }
  // Scan forward for the BIT STRING (0x03) that carries the key.
  for (let i = oidAt; i < der.length - 1; i += 1) {
    if (der[i] !== 0x03) {
      continue;
    }
    const header = readLength(der, i + 1);
    if (header === undefined) {
      continue;
    }
    // Skip the unused-bits octet, then expect SEQUENCE, then INTEGER.
    let cursor = header.next;
    if (der[cursor] !== 0x00) {
      continue;
    }
    cursor += 1;
    if (der[cursor] !== 0x30) {
      continue;
    }
    const sequence = readLength(der, cursor + 1);
    if (sequence === undefined) {
      continue;
    }
    cursor = sequence.next;
    if (der[cursor] !== 0x02) {
      continue;
    }
    const modulus = readLength(der, cursor + 1);
    if (modulus === undefined) {
      continue;
    }
    let length = modulus.length;
    // DER prefixes a leading zero byte to keep the integer positive.
    if (der[modulus.next] === 0x00) {
      length -= 1;
    }
    return length * 8;
  }
  return undefined;
};

const readLength = (
  der: Uint8Array,
  at: number,
): { readonly length: number; readonly next: number } | undefined => {
  const first = der[at];
  if (first === undefined) {
    return undefined;
  }
  if (first < 0x80) {
    return { length: first, next: at + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 4 || at + count >= der.length) {
    return undefined;
  }
  let length = 0;
  for (let i = 1; i <= count; i += 1) {
    length = (length << 8) | (der[at + i] ?? 0);
  }
  return { length, next: at + 1 + count };
};

const indexOfSequence = (haystack: Uint8Array, needle: readonly number[]): number => {
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
};
