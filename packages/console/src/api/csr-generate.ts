/**
 * In-browser RSA key pair + PKCS#10 CSR generator, for administrators who
 * would rather not shell out to openssl to enroll or rotate a consumer.
 *
 * Security posture (see CsrGeneratorModal.vue for the UI half of this):
 * the private key is generated with WebCrypto and exists only as the
 * CryptoKey and the PKCS#8 PEM string returned below. This module never
 * sends it anywhere, never writes it to any storage, and keeps no module
 * -level state — every call is self-contained so nothing here can leak a
 * key across calls or components. The caller owns clearing the returned PEM
 * from memory once the operator has saved it.
 *
 * Why this hand-rolls DER instead of a library: WebCrypto can generate and
 * sign, but it cannot emit a CSR — no design here avoids needing *some*
 * ASN.1 layer. @peculiar/x509 (plus @peculiar/asn1-csr, asn1-x509,
 * asn1-rsa, and several more transitive packages) or pkijs (six more
 * packages) would write it for us; node-forge is zero-dependency but pure
 * JS, so its RSA keygen takes visible seconds in a browser tab where
 * WebCrypto's is near-instant. All three were considered and rejected for
 * the same reason: this is the one code path in the console where an
 * administrator's browser ever holds a consumer's private key, and every
 * package sitting in that path is code that could read it. Zero
 * third-party code here is worth more than it would be anywhere else in
 * this app — and it costs nothing extra in cryptography either way, since
 * key generation and signing are native WebCrypto regardless of which way
 * this decision goes; a library would only replace this envelope-writing
 * code, never the crypto itself.
 *
 * The decisive argument is failure direction. A bug in an ASN.1 *parser*
 * is dangerous — malformed input can be coerced into a structure that
 * wrongly validates. A bug in a *writer* can only produce bytes that fail
 * to parse; there is no failure mode where a DER mistake here yields a
 * CSR that is weaker but still accepted. This output is checked twice:
 * csr-generate.test.ts verifies it with node-forge — the exact library
 * src/services/issuer.ts uses server-side — and the service re-verifies
 * everything again on submit.
 *
 * That is also why this being ~200 lines is the right size, not the first
 * slice of an open-ended job: the CSR is deliberately minimal — version 0,
 * a single CN RDN, the SPKI exported verbatim from WebCrypto, and empty
 * attributes. Hemlig assigns the consumer's SPIFFE URI SAN and clientAuth
 * EKU itself and ignores whatever subject a submitted CSR carries, so a
 * general-purpose ASN.1 writer is never needed. If the CSR ever has to
 * carry real extensions — SANs, key usage, challenge attributes —
 * hand-rolling stops being proportionate and @peculiar/x509 is the right
 * swap. Everything here sits behind the single generateCsr() export, so
 * that swap touches this one file and the existing tests carry over
 * unchanged.
 */

export type CsrKeySize = 2048 | 3072 | 4096;

export interface GeneratedCsr {
  readonly csrPem: string;
  readonly privateKeyPem: string; // PKCS#8, "BEGIN PRIVATE KEY"
  readonly publicKeyFingerprint: string; // SHA-256 hex of the SPKI DER, for display
}

// The service rejects anything smaller than 2048 bits (see src/api/csr.ts
// and the server-side check in src/services/issuer.ts); 3072 is a
// comfortable margin above that floor without 4096's multi-second keygen.
export const DEFAULT_CSR_KEY_SIZE: CsrKeySize = 3072;

// ---------------------------------------------------------------------------
// Minimal DER writer. Only the handful of universal types a CertificationRequest
// needs, plus the context-specific [0] tag for its (always empty) Attributes.
// ---------------------------------------------------------------------------

const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30, // constructed
  SET: 0x31, // constructed
} as const;

// Constructed, context-specific, tag number 0 — used for the CSR's
// `attributes [0] IMPLICIT SET OF Attribute`, which Hemlig ignores and this
// module always sends empty.
const CONTEXT_0_CONSTRUCTED = 0xa0;

// Every byte array this module produces is a fresh, non-shared buffer (built
// via `new Uint8Array(n)`, `Uint8Array.from(...)`, or `TextEncoder.encode`),
// never a view over someone else's buffer. Naming that as `Bytes` — instead
// of the bare `Uint8Array` alias, which defaults to the wider
// `Uint8Array<ArrayBufferLike>` — is what lets the final CSR bytes satisfy
// `BufferSource` when handed to crypto.subtle.sign below.
type Bytes = Uint8Array<ArrayBuffer>;

const concatBytes = (...parts: readonly Bytes[]): Bytes => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// DER definite-length encoding: short form under 128, otherwise a leading
// 0x80|byteCount followed by the big-endian length bytes.
const derLength = (length: number): number[] => {
  if (length < 0x80) {
    return [length];
  }
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return [0x80 | bytes.length, ...bytes];
};

// Generic tag/length/value framing. Every other helper below is a thin
// wrapper over this for one specific tag.
const tlv = (tag: number, content: Bytes): Bytes =>
  concatBytes(Uint8Array.from([tag, ...derLength(content.length)]), content);

const derSequence = (...children: readonly Bytes[]): Bytes => tlv(TAG.SEQUENCE, concatBytes(...children));

const derSet = (...children: readonly Bytes[]): Bytes => tlv(TAG.SET, concatBytes(...children));

// The CSR version field is always the literal INTEGER 0; this is not a
// general-purpose integer encoder.
const derVersionZero = (): Bytes => tlv(TAG.INTEGER, Uint8Array.from([0x00]));

// One "unused bits" octet (always 0 here — RSA signatures are whole bytes),
// then the raw content.
const derBitString = (content: Bytes): Bytes => tlv(TAG.BIT_STRING, concatBytes(Uint8Array.from([0x00]), content));

const derNull = (): Bytes => Uint8Array.from([0x05, 0x00]);

const derUtf8String = (value: string): Bytes => tlv(TAG.UTF8_STRING, new TextEncoder().encode(value));

// Base-128, most-significant-arc-first, with the first two arcs folded into
// one byte per X.690 8.19 — the standard OID encoding.
const derOid = (dotted: string): Bytes => {
  const arcs = dotted.split(".").map(Number);
  const [first, second, ...rest] = arcs;
  const bytes: number[] = [(first ?? 0) * 40 + (second ?? 0)];
  for (const arc of rest) {
    const group: number[] = [arc & 0x7f];
    let remaining = Math.floor(arc / 128);
    while (remaining > 0) {
      group.unshift((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    bytes.push(...group);
  }
  return tlv(TAG.OID, Uint8Array.from(bytes));
};

// commonName, from the X.520 attribute types arc.
const OID_COMMON_NAME = "2.5.4.3";
// sha256WithRSAEncryption, from the PKCS#1 arc. Matches the signature
// algorithm src/services/issuer.ts's forge-based verifier expects.
const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

const toHex = (bytes: Bytes): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const toBase64 = (bytes: Bytes): string => {
  // btoa wants a binary string; chunk the conversion so a large key never
  // risks a "too many arguments" spread limit (CSRs here are a few KB, so
  // this is one iteration in practice, but it costs nothing to be safe).
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
};

const pemWrap = (label: string, der: Bytes): string => {
  const base64 = toBase64(der);
  const lines: string[] = [];
  for (let offset = 0; offset < base64.length; offset += 64) {
    lines.push(base64.slice(offset, offset + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
};

/**
 * Generates an RSA key pair and a matching PKCS#10 CSR, entirely in the
 * browser. The subject is `CN=<commonName>` only, and it is cosmetic —
 * Hemlig assigns the consumer's SPIFFE URI SAN and clientAuth EKU itself and
 * ignores whatever subject a submitted CSR carries. Callers must not rely on
 * the subject for anything.
 */
export const generateCsr = async (input: {
  readonly commonName: string;
  readonly keySize: CsrKeySize;
}): Promise<GeneratedCsr> => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: input.keySize,
      publicExponent: Uint8Array.from([0x01, 0x00, 0x01]), // 65537
      hash: "SHA-256",
    },
    true, // extractable — required to export the key at all; see the module doc
    ["sign", "verify"],
  );

  // A SubjectPublicKeyInfo is already a complete DER structure once
  // exported; it is used verbatim below and never rebuilt by hand.
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));

  const subject = derSequence(derSet(derSequence(derOid(OID_COMMON_NAME), derUtf8String(input.commonName))));
  const attributes = tlv(CONTEXT_0_CONSTRUCTED, new Uint8Array(0)); // always empty; see the doc comment above
  const certificationRequestInfo = derSequence(derVersionZero(), subject, spki, attributes);

  // The signature covers the exact DER bytes of certificationRequestInfo,
  // tag and length included — not just its content.
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, certificationRequestInfo),
  );
  const signatureAlgorithm = derSequence(derOid(OID_SHA256_WITH_RSA), derNull());
  const certificationRequest = derSequence(certificationRequestInfo, signatureAlgorithm, derBitString(signature));

  const privateKeyDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  // Nothing else in this module holds a reference to keyPair.privateKey past
  // this point, and a CryptoKey cannot be zeroed directly — dropping every
  // reference is the most this function itself can do. The exported PEM
  // string is the caller's responsibility from here (see CsrGeneratorModal.vue).

  const fingerprint = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));

  return {
    csrPem: pemWrap("CERTIFICATE REQUEST", certificationRequest),
    privateKeyPem: pemWrap("PRIVATE KEY", privateKeyDer),
    publicKeyFingerprint: toHex(fingerprint),
  };
};
