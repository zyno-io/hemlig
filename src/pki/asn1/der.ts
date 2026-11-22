/**
 * Minimal strict DER reader and writer. The certificate, CRL and CSR helpers use it for the pieces that must stay
 * byte-exact (the issuer name, the to-be-signed structures) and for splitting structures before the typed
 * `@peculiar` schemas decode them.
 */

export class DerError extends Error {}

export interface Tlv {
  readonly tag: number;
  /** Content octets. */
  readonly value: Buffer;
  /** The complete encoding: tag, length and content. */
  readonly raw: Buffer;
  /** Offset just past this element in the buffer it was read from. */
  readonly end: number;
}

export const TAG = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  enumerated: 0x0a,
  utf8String: 0x0c,
  printableString: 0x13,
  ia5String: 0x16,
  utcTime: 0x17,
  generalizedTime: 0x18,
  sequence: 0x30,
  set: 0x31,
} as const;

export const readTlv = (input: Uint8Array, offset = 0): Tlv => {
  const buffer = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  if (offset + 2 > buffer.length) {
    throw new DerError("Truncated DER element.");
  }
  const tag = buffer[offset] as number;
  if ((tag & 0x1f) === 0x1f) {
    throw new DerError("Multi-byte DER tags are not supported.");
  }
  const first = buffer[offset + 1] as number;
  let length = first;
  let header = 2;
  if (first === 0x80) {
    throw new DerError("Indefinite lengths are not DER.");
  }
  if (first > 0x80) {
    const count = first & 0x7f;
    if (count > 4 || offset + 2 + count > buffer.length) {
      throw new DerError("Unsupported DER length.");
    }
    length = 0;
    for (let i = 0; i < count; i += 1) {
      length = length * 256 + (buffer[offset + 2 + i] as number);
    }
    if (length < 0x80 || (buffer[offset + 2] as number) === 0) {
      throw new DerError("Non-minimal DER length.");
    }
    header = 2 + count;
  }
  const end = offset + header + length;
  if (end > buffer.length) {
    throw new DerError("Truncated DER element.");
  }
  return {
    tag,
    value: buffer.subarray(offset + header, end),
    raw: buffer.subarray(offset, end),
    end,
  };
};

/** Parses exactly one element and rejects trailing bytes. */
export const parseDer = (input: Uint8Array): Tlv => {
  const element = readTlv(input);
  if (element.end !== input.byteLength) {
    throw new DerError("Trailing bytes after the DER element.");
  }
  return element;
};

export const children = (element: Tlv): Tlv[] => {
  const result: Tlv[] = [];
  let offset = 0;
  while (offset < element.value.length) {
    const child = readTlv(element.value, offset);
    result.push(child);
    offset = child.end;
  }
  return result;
};

export const expectTag = (
  element: Tlv | undefined,
  tag: number,
  what: string,
): Tlv => {
  if (element === undefined || element.tag !== tag) {
    throw new DerError(`Expected ${what}.`);
  }
  return element;
};

export const decodeOid = (element: Tlv): string => {
  expectTag(element, TAG.oid, "an OBJECT IDENTIFIER");
  const bytes = element.value;
  if (bytes.length === 0) {
    throw new DerError("Empty OBJECT IDENTIFIER.");
  }
  const arcs: number[] = [];
  let current = 0;
  let arcStart = true;
  for (const byte of bytes) {
    if (arcStart && byte === 0x80) {
      throw new DerError("Non-minimal OBJECT IDENTIFIER arc.");
    }
    arcStart = false;
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(current);
      current = 0;
      arcStart = true;
    }
  }
  if ((bytes[bytes.length - 1] as number) & 0x80) {
    throw new DerError("Truncated OBJECT IDENTIFIER.");
  }
  const [head = 0, ...rest] = arcs;
  const first = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [first, head - first * 40, ...rest].join(".");
};

/** Content octets of a non-negative INTEGER without the sign padding. */
export const decodeUnsignedInteger = (element: Tlv): Buffer => {
  expectTag(element, TAG.integer, "an INTEGER");
  const bytes = element.value;
  if (bytes.length === 0 || (bytes[0] as number) & 0x80) {
    throw new DerError("Expected a non-negative INTEGER.");
  }
  if (bytes.length > 1 && bytes[0] === 0 && !((bytes[1] as number) & 0x80)) {
    throw new DerError("Non-minimal INTEGER.");
  }
  return bytes[0] === 0 && bytes.length > 1 ? bytes.subarray(1) : bytes;
};

/**
 * The one canonical serial form: lowercase hex of the minimal positive INTEGER content, without the sign-padding 00
 * (a lone `00` stays). Throws unless the input is whole-byte lowercase hex.
 */
export const canonicalSerialHex = (hex: string): string => {
  if (!/^([0-9a-f]{2})+$/.test(hex)) {
    throw new DerError("Serial numbers are whole-byte lowercase hex.");
  }
  return hex.replace(/^(00)+(?=..)/, "");
};

/** Reads a small version INTEGER that must be one minimal byte from `allowed`. */
export const decodeVersion = (
  element: Tlv,
  allowed: readonly number[],
): number => {
  expectTag(element, TAG.integer, "a version");
  const value = element.value[0];
  if (
    element.value.length !== 1 ||
    value === undefined ||
    !allowed.includes(value)
  ) {
    throw new DerError("Unsupported version.");
  }
  return value;
};

const encodeLength = (length: number): Buffer => {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) {
    bytes.unshift(value % 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

export const tlv = (tag: number, ...parts: Uint8Array[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
};

export const seq = (...parts: Uint8Array[]): Buffer =>
  tlv(TAG.sequence, ...parts);
export const set = (...parts: Uint8Array[]): Buffer => tlv(TAG.set, ...parts);
export const octetString = (value: Uint8Array): Buffer =>
  tlv(TAG.octetString, value);
export const bitString = (value: Uint8Array): Buffer =>
  tlv(TAG.bitString, Buffer.from([0]), value);
export const boolTrue = (): Buffer => tlv(TAG.boolean, Buffer.from([0xff]));
export const derNull = (): Buffer => Buffer.from([TAG.null, 0]);
/** Constructed context-specific [n] EXPLICIT wrapper. */
export const explicit = (n: number, ...parts: Uint8Array[]): Buffer =>
  tlv(0xa0 | n, ...parts);

/** INTEGER from big-endian unsigned bytes. */
export const unsignedInteger = (bytes: Uint8Array): Buffer => {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  const trimmed = Buffer.from(bytes.subarray(start));
  const padded =
    trimmed.length === 0 || (trimmed[0] as number) & 0x80
      ? Buffer.concat([Buffer.from([0]), trimmed])
      : trimmed;
  return tlv(TAG.integer, padded);
};

export const smallInteger = (value: number): Buffer => {
  const bytes: number[] = [];
  for (let v = value; v > 0; v = Math.floor(v / 256)) {
    bytes.unshift(v % 256);
  }
  return unsignedInteger(Buffer.from(bytes.length === 0 ? [0] : bytes));
};

export const oid = (dotted: string): Buffer => {
  const arcs = dotted.split(".").map(Number);
  if (
    arcs.length < 2 ||
    arcs.some((arc) => !Number.isSafeInteger(arc) || arc < 0)
  ) {
    throw new DerError("Invalid OBJECT IDENTIFIER.");
  }
  const [first, second, ...rest] = arcs as [number, number, ...number[]];
  const body: number[] = [];
  for (const arc of [first * 40 + second, ...rest]) {
    const group = [arc % 128];
    for (
      let value = Math.floor(arc / 128);
      value > 0;
      value = Math.floor(value / 128)
    ) {
      group.unshift((value % 128) | 0x80);
    }
    body.push(...group);
  }
  return tlv(TAG.oid, Buffer.from(body));
};

const pad = (value: number, width: number): string =>
  String(value).padStart(width, "0");

/** UTCTime before 2050, GeneralizedTime from 2050 (RFC 5280 4.1.2.5). Sub-second precision is dropped. */
export const encodeTime = (date: Date): Buffer => {
  const year = date.getUTCFullYear();
  if (Number.isNaN(date.getTime()) || year < 1950 || year > 9999) {
    throw new DerError("The time is outside the encodable range.");
  }
  const rest =
    pad(date.getUTCMonth() + 1, 2) +
    pad(date.getUTCDate(), 2) +
    pad(date.getUTCHours(), 2) +
    pad(date.getUTCMinutes(), 2) +
    pad(date.getUTCSeconds(), 2) +
    "Z";
  return year < 2050
    ? tlv(TAG.utcTime, Buffer.from(pad(year % 100, 2) + rest, "ascii"))
    : tlv(TAG.generalizedTime, Buffer.from(pad(year, 4) + rest, "ascii"));
};

/** GeneralizedTime always (CRL entry invalidityDate). */
export const encodeGeneralizedTime = (date: Date): Buffer =>
  tlv(
    TAG.generalizedTime,
    Buffer.from(
      pad(date.getUTCFullYear(), 4) +
        pad(date.getUTCMonth() + 1, 2) +
        pad(date.getUTCDate(), 2) +
        pad(date.getUTCHours(), 2) +
        pad(date.getUTCMinutes(), 2) +
        pad(date.getUTCSeconds(), 2) +
        "Z",
      "ascii",
    ),
  );

export const decodeTime = (element: Tlv): Date => {
  const text = element.value.toString("ascii");
  let match: RegExpMatchArray | null;
  let year: number;
  if (element.tag === TAG.utcTime) {
    match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    year =
      match === null
        ? 0
        : Number(match[1]) >= 50
          ? 1900 + Number(match[1])
          : 2000 + Number(match[1]);
  } else if (element.tag === TAG.generalizedTime) {
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    year = match === null ? 0 : Number(match[1]);
  } else {
    throw new DerError("Expected a time.");
  }
  if (match === null) {
    throw new DerError("Malformed time.");
  }
  const [month, day, hour, minute, second] = match.slice(2).map(Number) as [
    number,
    number,
    number,
    number,
    number,
  ];
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new DerError("Malformed time.");
  }
  return date;
};
