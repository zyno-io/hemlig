import { createHash } from "node:crypto";
import {
  children,
  decodeOid,
  DerError,
  oid,
  parseDer,
  printable,
  seq,
  set,
  TAG,
  utf8,
  type Tlv,
} from "./ez-der";
import { EzError } from "./ez-error";

/**
 * Subject names. EZ speaks the restricted form the Hemlig server enforces on every CA subject (see the PKI design,
 * "Subject names and the registry"): single-valued RDNs, printable ASCII 0x20-0x7e without leading, trailing or doubled
 * spaces, `C` as a two-letter PrintableString, the rest UTF8String, in the order C, ST, L, O, OU, CN.
 */

export const NAME_OID = {
  C: "2.5.4.6",
  ST: "2.5.4.8",
  L: "2.5.4.7",
  O: "2.5.4.10",
  OU: "2.5.4.11",
  CN: "2.5.4.3",
} as const;

export type NameAttributeType = keyof typeof NAME_OID;
export const NAME_ORDER: readonly NameAttributeType[] = ["C", "ST", "L", "O", "OU", "CN"];

export interface Subject {
  C?: string;
  ST?: string;
  L?: string;
  O?: string;
  OU?: string;
  CN: string;
}

const subjectInvalid = (message: string): never => {
  throw new EzError(2, "subject_invalid", message);
};

const assertValue = (type: string, value: string): void => {
  if (value.length === 0) subjectInvalid(`${type} is empty.`);
  if (!/^[\x20-\x7e]+$/.test(value)) subjectInvalid(`${type} must be printable ASCII.`);
  if (value.startsWith(" ") || value.endsWith(" ") || value.includes("  ")) {
    subjectInvalid(`${type} must not have leading, trailing or doubled spaces.`);
  }
};

/** Validates a subject object (not yet encoded). */
export const assertSubject = (subject: Subject): void => {
  for (const key of Object.keys(subject)) {
    if (!(NAME_ORDER as readonly string[]).includes(key)) {
      subjectInvalid(`Unsupported subject attribute ${key}.`);
    }
  }
  if (typeof subject.CN !== "string") subjectInvalid("The subject needs a CN.");
  for (const type of NAME_ORDER) {
    const value = subject[type];
    if (value === undefined) continue;
    assertValue(type, value);
    if (type === "C" && !/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(value)) {
      subjectInvalid("C must be a PrintableString.");
    }
  }
};

/** Parses `CN=Example Root,O=Example` (a backslash escapes a comma, an equals sign or a backslash). */
export const parseSubject = (text: string): Subject => {
  const parts: string[] = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (ch === "\\") {
      const next = text[i + 1];
      if (next === undefined) return subjectInvalid("Dangling backslash in the subject.");
      current += next;
      i += 1;
    } else if (ch === ",") {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  parts.push(current);
  const subject: Record<string, string> = {};
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq <= 0) return subjectInvalid(`Malformed subject component "${part}".`);
    const type = part.slice(0, eq).trim().toUpperCase();
    if (!(NAME_ORDER as readonly string[]).includes(type)) {
      return subjectInvalid(`Unsupported subject attribute ${type}.`);
    }
    if (subject[type] !== undefined) return subjectInvalid(`Duplicate subject attribute ${type}.`);
    subject[type] = part.slice(eq + 1).trim();
  }
  const result = subject as unknown as Subject;
  assertSubject(result);
  if (result.C !== undefined && !/^[A-Za-z]{2}$/.test(result.C)) {
    subjectInvalid("C must be a two-letter country code.");
  }
  return result;
};

export const encodeSubject = (subject: Subject): Buffer => {
  assertSubject(subject);
  return seq(
    ...NAME_ORDER.flatMap((type) => {
      const value = subject[type];
      if (value === undefined) return [];
      return [
        set(
          seq(
            oid(NAME_OID[type]),
            type === "C" ? printable(value) : utf8(value),
          ),
        ),
      ];
    }),
  );
};

/** `C=US, O=Example, CN=Example Root` in encoded order. */
export const formatSubject = (subject: Subject): string =>
  NAME_ORDER.flatMap((type) =>
    subject[type] === undefined
      ? []
      : [`${type}=${(subject[type] as string).replace(/[\\,=]/g, (c) => `\\${c}`)}`],
  ).join(", ");

export interface NameAttribute {
  readonly oid: string;
  readonly value: string;
}

export interface RestrictedName {
  readonly der: Buffer;
  readonly attributes: readonly NameAttribute[];
  /** Canonical comparison key: case and whitespace folded. */
  readonly key: string;
}

const canonicalKey = (attributes: readonly NameAttribute[]): string =>
  createHash("sha256")
    .update(
      JSON.stringify(
        attributes.map((a) => [a.oid, a.value.toLowerCase().replace(/\s+/g, " ")]),
      ),
    )
    .digest("hex");

const STRING_TAGS = new Set<number>([TAG.utf8, TAG.printable, TAG.ia5]);

/**
 * Decodes a DER Name and enforces the restricted form. `hemlig` limits the attributes to C, ST, L, O, OU and CN;
 * `external` accepts any string-typed attribute (for example DC), as the server does for an external root.
 */
export const assertRestrictedName = (
  der: Buffer,
  kind: "hemlig" | "external" = "external",
  code = "subject_invalid",
): RestrictedName => {
  const fail = (reason: string): never => {
    throw new EzError(2, code, `The name is not in the restricted form (${reason}).`);
  };
  let root: Tlv;
  try {
    root = parseDer(der);
  } catch (error) {
    if (error instanceof DerError) return fail("malformed_name");
    throw error;
  }
  if (root.tag !== TAG.sequence) return fail("malformed_name");
  let rdns: Tlv[];
  try {
    rdns = children(root);
  } catch {
    return fail("malformed_name");
  }
  if (rdns.length === 0) return fail("empty_name");
  const known = new Set<string>(Object.values(NAME_OID));
  const attributes = rdns.map((rdn): NameAttribute => {
    if (rdn.tag !== TAG.set) return fail("malformed_name");
    let atvs: Tlv[];
    try {
      atvs = children(rdn);
    } catch {
      return fail("malformed_name");
    }
    if (atvs.length !== 1) return fail("multi_valued_rdn");
    const atv = atvs[0] as Tlv;
    let parts: Tlv[];
    try {
      parts = atv.tag === TAG.sequence ? children(atv) : [];
    } catch {
      return fail("malformed_name");
    }
    const [type, value, ...extra] = parts;
    if (type === undefined || value === undefined || extra.length > 0) return fail("malformed_name");
    let typeOid: string;
    try {
      typeOid = decodeOid(type);
    } catch {
      return fail("malformed_name");
    }
    if (!STRING_TAGS.has(value.tag)) return fail("unsupported_string_type");
    const text = value.value.toString("latin1");
    if (text.length === 0) return fail("empty_value");
    if (!/^[\x20-\x7e]+$/.test(text)) return fail("non_ascii");
    if (text.startsWith(" ") || text.endsWith(" ") || text.includes("  ")) return fail("space_not_allowed");
    if (kind === "hemlig" && !known.has(typeOid)) return fail("attribute_not_allowed");
    return { oid: typeOid, value: text };
  });
  return { der: Buffer.from(der), attributes, key: canonicalKey(attributes) };
};

/** A subject object from a restricted Hemlig-form name (for display and state). */
export const subjectFromName = (name: RestrictedName): Subject => {
  const out: Record<string, string> = {};
  for (const attribute of name.attributes) {
    const type = NAME_ORDER.find((t) => NAME_OID[t] === attribute.oid);
    if (type !== undefined) out[type] = attribute.value;
  }
  return out as unknown as Subject;
};

export const describeName = (name: RestrictedName): string =>
  name.attributes
    .map((attribute) => {
      const type = NAME_ORDER.find((t) => NAME_OID[t] === attribute.oid) ?? attribute.oid;
      return `${type}=${attribute.value}`;
    })
    .join(", ");

/** Reserved by the server for the identity root. */
export const isIdentityRootName = (name: RestrictedName): boolean =>
  name.attributes.some(
    (attribute) =>
      attribute.oid === NAME_OID.CN && /^Hemlig .+ Issuing Root$/i.test(attribute.value),
  );

// ---------------------------------------------------------------------------------------------------------------------
// IP addresses and CIDR (for iPAddress name constraints)
// ---------------------------------------------------------------------------------------------------------------------

export const parseIp = (text: string): Buffer | undefined => {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) {
    const bytes = text.split(".").map(Number);
    return bytes.every((b) => b <= 255) && text.split(".").every((p) => p === "0" || !p.startsWith("0"))
      ? Buffer.from(bytes)
      : undefined;
  }
  if (!text.includes(":") || !/^[0-9a-fA-F:.]+$/.test(text)) return undefined;
  let head = text;
  let tail: string[] = [];
  let compressed = false;
  const gap = text.indexOf("::");
  if (gap >= 0) {
    if (text.indexOf("::", gap + 1) >= 0) return undefined;
    compressed = true;
    head = text.slice(0, gap);
    tail = text.slice(gap + 2) === "" ? [] : text.slice(gap + 2).split(":");
  }
  const front = head === "" ? [] : head.split(":");
  const expand = (groups: string[]): number[] | undefined => {
    const words: number[] = [];
    for (let i = 0; i < groups.length; i++) {
      const group = groups[i] as string;
      if (group.includes(".")) {
        const v4 = i === groups.length - 1 ? parseIp(group) : undefined;
        if (v4 === undefined || v4.length !== 4) return undefined;
        words.push(v4.readUInt16BE(0), v4.readUInt16BE(2));
      } else if (/^[0-9a-fA-F]{1,4}$/.test(group)) {
        words.push(parseInt(group, 16));
      } else {
        return undefined;
      }
    }
    return words;
  };
  const a = expand(front);
  const b = expand(tail);
  if (a === undefined || b === undefined) return undefined;
  const missing = 8 - a.length - b.length;
  if (compressed ? missing < 1 : missing !== 0) return undefined;
  const words = [...a, ...new Array<number>(compressed ? missing : 0).fill(0), ...b];
  const out = Buffer.alloc(16);
  words.forEach((word, i) => out.writeUInt16BE(word, i * 2));
  return out;
};

export const formatIp = (bytes: Buffer): string => {
  if (bytes.length === 4) return [...bytes].join(".");
  const words = Array.from({ length: 8 }, (_, i) => bytes.readUInt16BE(i * 2));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLength) [bestStart, bestLength] = [i, j - i];
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (bestLength < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
};

export const prefixMask = (prefix: number, length: number): Buffer => {
  const mask = Buffer.alloc(length);
  for (let i = 0; i < prefix; i++) mask[i >> 3] = (mask[i >> 3] as number) | (0x80 >> (i & 7));
  return mask;
};

/** `10.0.0.0/8` or `2001:db8::/32`: address and mask bytes (host bits cleared), or undefined when invalid. */
export const parseCidr = (
  text: string,
): { address: Buffer; mask: Buffer; prefix: number } | undefined => {
  const slash = text.indexOf("/");
  if (slash < 0) return undefined;
  const address = parseIp(text.slice(0, slash));
  const prefixText = text.slice(slash + 1);
  if (address === undefined || !/^\d{1,3}$/.test(prefixText)) return undefined;
  const prefix = Number(prefixText);
  if (prefix > address.length * 8) return undefined;
  const mask = prefixMask(prefix, address.length);
  return { address: Buffer.from(address.map((byte, i) => byte & (mask[i] as number))), mask, prefix };
};
