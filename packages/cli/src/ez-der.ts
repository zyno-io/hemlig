import { EzError } from "./ez-error";

/** A small, independent DER writer and a strict reader. Written fresh for the CLI (MIT); shares no code with the server. */

export const TAG = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  enumerated: 0x0a,
  utf8: 0x0c,
  printable: 0x13,
  ia5: 0x16,
  utcTime: 0x17,
  generalizedTime: 0x18,
  sequence: 0x30,
  set: 0x31,
} as const;

// ---------------------------------------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------------------------------------

const lengthBytes = (length: number): Buffer => {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

export const tlv = (tag: number, ...parts: readonly Uint8Array[]): Buffer => {
  const value = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
};

export const seq = (...parts: readonly Uint8Array[]): Buffer =>
  tlv(TAG.sequence, ...parts);
export const set = (...parts: readonly Uint8Array[]): Buffer =>
  tlv(TAG.set, ...parts);
/** `[n] EXPLICIT` (constructed, context-specific). */
export const explicit = (n: number, ...parts: readonly Uint8Array[]): Buffer =>
  tlv(0xa0 | n, ...parts);
/** `[n] IMPLICIT` primitive (for example the keyIdentifier of an AKI). */
export const implicitPrimitive = (n: number, value: Uint8Array): Buffer =>
  tlv(0x80 | n, value);

export const oid = (dotted: string): Buffer => {
  const arcs = dotted.split(".").map((part) => {
    if (!/^\d+$/.test(part)) throw new Error(`Invalid OID ${dotted}.`);
    return Number(part);
  });
  if (arcs.length < 2 || (arcs[0] as number) > 2) {
    throw new Error(`Invalid OID ${dotted}.`);
  }
  const out: number[] = [];
  const subIds = [40 * (arcs[0] as number) + (arcs[1] as number), ...arcs.slice(2)];
  for (const arc of subIds) {
    const group = [arc % 128];
    for (let rest = Math.floor(arc / 128); rest > 0; rest = Math.floor(rest / 128)) {
      group.unshift(0x80 | (rest % 128));
    }
    out.push(...group);
  }
  return tlv(TAG.oid, Buffer.from(out));
};

/** Minimal, sign-padded INTEGER from big-endian unsigned magnitude bytes. */
export const uint = (magnitude: Uint8Array): Buffer => {
  let bytes = Buffer.from(magnitude);
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if (bytes.length === 0) bytes = Buffer.from([0]);
  if ((bytes[0] as number) & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(TAG.integer, bytes);
};

export const smallInt = (n: number): Buffer => {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("smallInt needs a non-negative safe integer.");
  const bytes: number[] = [];
  for (let rest = n; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest & 0xff);
  return uint(Buffer.from(bytes.length === 0 ? [0] : bytes));
};

export const bigUint = (n: bigint): Buffer => {
  if (n < 0n) throw new Error("bigUint needs a non-negative value.");
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return uint(Buffer.from(hex, "hex"));
};

export const enumerated = (n: number): Buffer =>
  tlv(TAG.enumerated, Buffer.from([n]));
export const bitString = (bytes: Uint8Array, unusedBits = 0): Buffer =>
  tlv(TAG.bitString, Buffer.from([unusedBits]), bytes);
export const octetString = (bytes: Uint8Array): Buffer => tlv(TAG.octetString, bytes);
export const bool = (value: boolean): Buffer =>
  tlv(TAG.boolean, Buffer.from([value ? 0xff : 0x00]));
export const nullValue = (): Buffer => tlv(TAG.null);
export const utf8 = (text: string): Buffer => tlv(TAG.utf8, Buffer.from(text, "utf8"));
export const printable = (text: string): Buffer => {
  if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(text)) {
    throw new Error("Not a PrintableString.");
  }
  return tlv(TAG.printable, Buffer.from(text, "ascii"));
};
export const ia5 = (text: string): Buffer => {
  if (!/^[\x00-\x7f]*$/.test(text)) throw new Error("Not an IA5String.");
  return tlv(TAG.ia5, Buffer.from(text, "ascii"));
};

/** UTCTime before 2050, GeneralizedTime from 2050; whole seconds, `Z`. */
export const time = (date: Date): Buffer => {
  const iso = date.toISOString();
  if (!/^\d{4}-/.test(iso)) throw new Error("Year out of range.");
  const stamp = `${iso.slice(0, 19).replace(/[-:T]/g, "")}Z`;
  return date.getUTCFullYear() < 2050
    ? tlv(TAG.utcTime, Buffer.from(stamp.slice(2), "ascii"))
    : tlv(TAG.generalizedTime, Buffer.from(stamp, "ascii"));
};

export const generalizedTime = (date: Date): Buffer =>
  tlv(
    TAG.generalizedTime,
    Buffer.from(`${date.toISOString().slice(0, 19).replace(/[-:T]/g, "")}Z`, "ascii"),
  );

/** One X.509 Extension; the critical flag is omitted when false (DER DEFAULT). */
export const extension = (
  extensionOid: string,
  critical: boolean,
  value: Uint8Array,
): Buffer =>
  seq(oid(extensionOid), ...(critical ? [bool(true)] : []), octetString(value));

// ---------------------------------------------------------------------------------------------------------------------
// Strict reader
// ---------------------------------------------------------------------------------------------------------------------

export class DerError extends EzError {
  public constructor(message: string) {
    super(2, "der_invalid", message);
  }
}

export interface Tlv {
  readonly tag: number;
  /** Complete encoding (header and value). */
  readonly raw: Buffer;
  readonly value: Buffer;
}

/**
 * Reads one TLV at `offset`. Refuses indefinite and non-minimal lengths, multi-byte tags and truncation. Slices share
 * the input buffer, so a nested `raw` is byte-identical to what was signed.
 */
export const readTlv = (input: Buffer, offset = 0): Tlv & { end: number } => {
  if (offset + 2 > input.length) throw new DerError("Truncated DER element.");
  const tag = input[offset] as number;
  if ((tag & 0x1f) === 0x1f) throw new DerError("Multi-byte DER tags are not supported.");
  const first = input[offset + 1] as number;
  let length: number;
  let headerLength = 2;
  if (first < 0x80) {
    length = first;
  } else {
    const count = first & 0x7f;
    if (count === 0) throw new DerError("Indefinite DER length.");
    if (count > 4) throw new DerError("DER length too large.");
    if (offset + 2 + count > input.length) throw new DerError("Truncated DER length.");
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + (input[offset + 2 + i] as number);
    }
    if ((input[offset + 2] as number) === 0 || length < 0x80) {
      throw new DerError("Non-minimal DER length.");
    }
    headerLength += count;
  }
  const end = offset + headerLength + length;
  if (end > input.length) throw new DerError("Truncated DER value.");
  return {
    tag,
    raw: input.subarray(offset, end),
    value: input.subarray(offset + headerLength, end),
    end,
  };
};

/** Parses exactly one TLV with nothing after it. */
export const parseDer = (input: Buffer): Tlv => {
  const element = readTlv(input, 0);
  if (element.end !== input.length) throw new DerError("Trailing bytes after the DER element.");
  return element;
};

export const children = (parent: Tlv): Tlv[] => {
  const out: Tlv[] = [];
  let offset = 0;
  while (offset < parent.value.length) {
    const child = readTlv(parent.value, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
};

export const expectTag = (element: Tlv | undefined, tag: number, what: string): Tlv => {
  if (element === undefined || element.tag !== tag) {
    throw new DerError(`Expected ${what}.`);
  }
  return element;
};

export const decodeOid = (element: Tlv): string => {
  expectTag(element, TAG.oid, "an OBJECT IDENTIFIER");
  const bytes = element.value;
  if (bytes.length === 0) throw new DerError("Empty OBJECT IDENTIFIER.");
  const arcs: number[] = [];
  let acc = 0;
  let started = false;
  for (const byte of bytes) {
    if (!started && byte === 0x80) throw new DerError("Non-minimal OID arc.");
    started = true;
    acc = acc * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(acc);
      acc = 0;
      started = false;
    }
  }
  if (started) throw new DerError("Truncated OBJECT IDENTIFIER.");
  const head = arcs[0] as number;
  const first = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [first, head - 40 * first, ...arcs.slice(1)].join(".");
};

/** The unsigned magnitude of a non-negative INTEGER (leading zero removed). */
export const decodeUint = (element: Tlv): Buffer => {
  expectTag(element, TAG.integer, "an INTEGER");
  const bytes = element.value;
  if (bytes.length === 0) throw new DerError("Empty INTEGER.");
  if ((bytes[0] as number) & 0x80) throw new DerError("Negative INTEGER.");
  if (bytes.length > 1 && bytes[0] === 0 && !((bytes[1] as number) & 0x80)) {
    throw new DerError("Non-minimal INTEGER.");
  }
  return bytes[0] === 0 && bytes.length > 1 ? bytes.subarray(1) : bytes;
};

export const decodeSmallInt = (element: Tlv): number => {
  const bytes = decodeUint(element);
  if (bytes.length > 6) throw new DerError("INTEGER too large.");
  return bytes.reduce((acc, byte) => acc * 256 + byte, 0);
};

export const decodeBool = (element: Tlv): boolean => {
  expectTag(element, TAG.boolean, "a BOOLEAN");
  if (element.value.length !== 1 || (element.value[0] !== 0 && element.value[0] !== 0xff)) {
    throw new DerError("Malformed BOOLEAN.");
  }
  return element.value[0] === 0xff;
};

/** The contents of a BIT STRING with no unused bits, or `unused` when allowed. */
export const decodeBitString = (
  element: Tlv,
): { bytes: Buffer; unusedBits: number } => {
  expectTag(element, TAG.bitString, "a BIT STRING");
  if (element.value.length < 1) throw new DerError("Empty BIT STRING.");
  const unusedBits = element.value[0] as number;
  if (unusedBits > 7 || (element.value.length === 1 && unusedBits !== 0)) {
    throw new DerError("Malformed BIT STRING.");
  }
  return { bytes: element.value.subarray(1), unusedBits };
};

export const decodeTime = (element: Tlv): Date => {
  const text = element.value.toString("ascii");
  let match: RegExpExecArray | null;
  if (element.tag === TAG.utcTime) {
    match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (match) {
      const yy = Number(match[1]);
      match[1] = String(yy >= 50 ? 1900 + yy : 2000 + yy);
    }
  } else if (element.tag === TAG.generalizedTime) {
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  } else {
    throw new DerError("Expected a time.");
  }
  if (!match) throw new DerError("Malformed time.");
  const [, y, mo, d, h, mi, s] = match.map(Number) as [number, number, number, number, number, number, number];
  const date = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  if (
    date.getUTCFullYear() !== y ||
    date.getUTCMonth() !== mo - 1 ||
    date.getUTCDate() !== d ||
    date.getUTCHours() !== h ||
    date.getUTCMinutes() !== mi ||
    date.getUTCSeconds() !== s
  ) {
    throw new DerError("Time out of range.");
  }
  return date;
};
