import { isIPv4, isIPv6 } from "node:net";
import type { NameConstraintEntry, NameConstraintSet } from "../types";
import {
  children,
  decodeOid,
  DerError,
  expectTag,
  oid,
  parseDer,
  seq,
  set,
  TAG,
  tlv,
  type Tlv,
} from "./der";

// ---------------------------------------------------------------------------------------------------------------------
// Distinguished names
// ---------------------------------------------------------------------------------------------------------------------

export type DirectoryStringKind = "printable" | "utf8" | "ia5";

export interface NameAttribute {
  readonly oid: string;
  /** Decoded text, or undefined when the value is not a PrintableString, UTF8String or IA5String. */
  readonly value?: string;
  readonly kind?: DirectoryStringKind;
}

const stringTags: Record<number, DirectoryStringKind> = {
  [TAG.printableString]: "printable",
  [TAG.utf8String]: "utf8",
  [TAG.ia5String]: "ia5",
};

const utf8Decoder = new TextDecoder("utf-8", {
  fatal: true,
  // Keep a leading U+FEFF so the printable-ASCII validator rejects it instead of it being silently dropped.
  ignoreBOM: true,
});

/** Splits a DER Name into RDNs of attributes. Throws DerError on malformed structure. */
export const decodeName = (der: Uint8Array): NameAttribute[][] => {
  const name = parseDer(der);
  expectTag(name, TAG.sequence, "a Name");
  return children(name).map((rdn) => {
    expectTag(rdn, TAG.set, "a RelativeDistinguishedName");
    const attributes = children(rdn);
    if (attributes.length === 0) {
      throw new DerError("Empty RelativeDistinguishedName.");
    }
    return attributes.map((attribute): NameAttribute => {
      expectTag(attribute, TAG.sequence, "an AttributeTypeAndValue");
      const [type, value, ...extra] = children(attribute);
      if (type === undefined || value === undefined || extra.length > 0) {
        throw new DerError("Malformed AttributeTypeAndValue.");
      }
      const kind = stringTags[value.tag];
      let text: string | undefined;
      if (kind !== undefined) {
        try {
          text = utf8Decoder.decode(value.value);
        } catch {
          text = undefined;
        }
      }
      return {
        oid: decodeOid(type),
        value: text,
        kind: text === undefined ? undefined : kind,
      };
    });
  });
};

/** Encodes a Name with one attribute per RDN, in the order given. */
export const encodeName = (
  attributes: readonly {
    oid: string;
    value: string;
    kind: DirectoryStringKind;
  }[],
): Buffer =>
  seq(
    ...attributes.map((attribute) =>
      set(
        seq(
          oid(attribute.oid),
          tlv(
            attribute.kind === "printable"
              ? TAG.printableString
              : attribute.kind === "utf8"
                ? TAG.utf8String
                : TAG.ia5String,
            Buffer.from(attribute.value, "utf8"),
          ),
        ),
      ),
    ),
  );

// ---------------------------------------------------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------------------------------------------------

export const ipToBytes = (text: string): Buffer => {
  if (isIPv4(text)) {
    return Buffer.from(text.split(".").map(Number));
  }
  if (!isIPv6(text) || text.includes("%")) {
    throw new Error("Invalid IP address.");
  }
  let value = text;
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(value);
  if (dotted?.[1] !== undefined) {
    const [a, b, c, d] = dotted[1].split(".").map(Number) as [
      number,
      number,
      number,
      number,
    ];
    value =
      value.slice(0, -dotted[1].length) +
      ((a << 8) | b).toString(16) +
      ":" +
      ((c << 8) | d).toString(16);
  }
  const [head = "", tail, ...extra] = value.split("::");
  if (extra.length > 0) {
    throw new Error("Invalid IP address.");
  }
  const left = head === "" ? [] : head.split(":");
  const right = tail === undefined || tail === "" ? [] : tail.split(":");
  const missing = 8 - left.length - right.length;
  const groups =
    tail === undefined
      ? left
      : [...left, ...Array<string>(missing).fill("0"), ...right];
  if (groups.length !== 8) {
    throw new Error("Invalid IP address.");
  }
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) =>
    bytes.writeUInt16BE(parseInt(group, 16), index * 2),
  );
  return bytes;
};

export const ipFromBytes = (bytes: Uint8Array): string => {
  if (bytes.length === 4) {
    return Array.from(bytes).join(".");
  }
  if (bytes.length !== 16) {
    throw new Error("Invalid IP address length.");
  }
  const buffer = Buffer.from(bytes);
  const groups = Array.from({ length: 8 }, (_, index) =>
    buffer.readUInt16BE(index * 2).toString(16),
  );
  // RFC 5952: compress the longest run of two or more zero groups.
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < 8;) {
    if (groups[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === "0") {
      end += 1;
    }
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestLength < 2) {
    return groups.join(":");
  }
  return `${groups.slice(0, bestStart).join(":")}::${groups.slice(bestStart + bestLength).join(":")}`;
};

const prefixToMask = (prefix: number, length: number): Buffer => {
  const mask = Buffer.alloc(length);
  for (let bit = 0; bit < prefix; bit += 1) {
    mask[bit >> 3] = (mask[bit >> 3] as number) | (0x80 >> (bit & 7));
  }
  return mask;
};

export interface IpNetwork {
  readonly address: Buffer;
  readonly prefix: number;
}

export const parseCidr = (text: string): IpNetwork => {
  const [address, prefixText, ...extra] = text.split("/");
  if (
    address === undefined ||
    prefixText === undefined ||
    extra.length > 0 ||
    !/^\d{1,3}$/.test(prefixText)
  ) {
    throw new Error("Invalid CIDR.");
  }
  const bytes = ipToBytes(address);
  const prefix = Number(prefixText);
  if (prefix > bytes.length * 8) {
    throw new Error("Invalid CIDR prefix.");
  }
  const mask = prefixToMask(prefix, bytes.length);
  return {
    address: Buffer.from(
      bytes.map((byte, index) => byte & (mask[index] as number)),
    ),
    prefix,
  };
};

export const formatCidr = (network: IpNetwork): string =>
  `${ipFromBytes(network.address)}/${network.prefix}`;

// ---------------------------------------------------------------------------------------------------------------------
// GeneralName, SubjectAltName and NameConstraints
// ---------------------------------------------------------------------------------------------------------------------

const GN = { email: 0x81, dns: 0x82, uri: 0x86, ip: 0x87 } as const;

const gnNames: Record<number, string> = {
  0xa0: "otherName",
  0x81: "rfc822Name",
  0x82: "dNSName",
  0xa3: "x400Address",
  0xa4: "directoryName",
  0xa5: "ediPartyName",
  0x86: "uniformResourceIdentifier",
  0x87: "iPAddress",
  0x88: "registeredID",
};

const ia5 = (element: Tlv): string => {
  if (element.value.some((byte) => byte > 0x7f)) {
    throw new DerError("Non-ASCII IA5String.");
  }
  return element.value.toString("ascii");
};

export interface SubjectAltNames {
  dns: string[];
  /** Canonical text (dotted IPv4, compressed IPv6). */
  ip: string[];
  uri: string[];
  email: string[];
  /** GeneralName types Hemlig does not issue (otherName, directoryName, registeredID, ...). */
  unsupported: string[];
}

export interface SubjectAltNameInput {
  dns?: readonly string[];
  ip?: readonly string[];
  uri?: readonly string[];
}

/** SubjectAltName extension value: dNSName, then iPAddress, then URI entries in the order given. */
export const encodeSubjectAltName = (names: SubjectAltNameInput): Buffer =>
  seq(
    ...(names.dns ?? []).map((value) =>
      tlv(GN.dns, Buffer.from(value, "ascii")),
    ),
    ...(names.ip ?? []).map((value) => tlv(GN.ip, ipToBytes(value))),
    ...(names.uri ?? []).map((value) =>
      tlv(GN.uri, Buffer.from(value, "ascii")),
    ),
  );

export const decodeSubjectAltName = (valueDer: Uint8Array): SubjectAltNames => {
  const root = parseDer(valueDer);
  expectTag(root, TAG.sequence, "a GeneralNames");
  const names: SubjectAltNames = {
    dns: [],
    ip: [],
    uri: [],
    email: [],
    unsupported: [],
  };
  for (const entry of children(root)) {
    switch (entry.tag) {
      case GN.dns:
        names.dns.push(ia5(entry));
        break;
      case GN.uri:
        names.uri.push(ia5(entry));
        break;
      case GN.email:
        names.email.push(ia5(entry));
        break;
      case GN.ip:
        names.ip.push(ipFromBytes(entry.value));
        break;
      default:
        names.unsupported.push(gnNames[entry.tag] ?? `tag${entry.tag}`);
    }
  }
  return names;
};

const subtree = (entry: NameConstraintEntry): Buffer => {
  switch (entry.type) {
    case "dns":
      return seq(tlv(GN.dns, Buffer.from(entry.value, "ascii")));
    case "uri":
      return seq(tlv(GN.uri, Buffer.from(entry.value, "ascii")));
    case "ip": {
      const network = parseCidr(entry.value);
      return seq(
        tlv(
          GN.ip,
          network.address,
          prefixToMask(network.prefix, network.address.length),
        ),
      );
    }
  }
};

/** NameConstraints extension value. */
export const encodeNameConstraints = (constraints: NameConstraintSet): Buffer =>
  seq(
    ...(constraints.permitted.length > 0
      ? [tlv(0xa0, ...constraints.permitted.map(subtree))]
      : []),
    ...(constraints.excluded.length > 0
      ? [tlv(0xa1, ...constraints.excluded.map(subtree))]
      : []),
  );

const decodeSubtrees = (
  container: Tlv,
  state: { unsupported: boolean },
): NameConstraintEntry[] => {
  const entries: NameConstraintEntry[] = [];
  for (const item of children(container)) {
    expectTag(item, TAG.sequence, "a GeneralSubtree");
    const [base, ...limits] = children(item);
    if (base === undefined) {
      throw new DerError("Empty GeneralSubtree.");
    }
    if (limits.length > 0) {
      // RFC 5280 4.2.1.10: minimum must be zero and maximum absent.
      throw new DerError(
        "GeneralSubtree minimum and maximum are not supported.",
      );
    }
    if (base.tag === GN.dns) {
      entries.push({ type: "dns", value: ia5(base) });
    } else if (base.tag === GN.uri) {
      entries.push({ type: "uri", value: ia5(base) });
    } else if (base.tag === GN.ip) {
      const half = base.value.length / 2;
      if (base.value.length !== 8 && base.value.length !== 32) {
        throw new DerError("Malformed iPAddress constraint.");
      }
      const address = base.value.subarray(0, half);
      const mask = base.value.subarray(half);
      let prefix = 0;
      while (
        prefix < half * 8 &&
        (mask[prefix >> 3] as number) & (0x80 >> (prefix & 7))
      ) {
        prefix += 1;
      }
      if (!prefixToMask(prefix, half).equals(mask)) {
        throw new DerError("Non-contiguous iPAddress mask.");
      }
      entries.push({
        type: "ip",
        value: formatCidr(parseCidr(`${ipFromBytes(address)}/${prefix}`)),
      });
    } else {
      // rfc822Name, directoryName, ...: Hemlig does not enforce these, so the caller must refuse them.
      state.unsupported = true;
    }
  }
  return entries;
};

export const decodeNameConstraints = (
  valueDer: Uint8Array,
): NameConstraintSet => decodeNameConstraintsDetailed(valueDer).constraints;

/** `unsupported` is true when any subtree has a GeneralName form other than dNSName, iPAddress or URI. */
export const decodeNameConstraintsDetailed = (
  valueDer: Uint8Array,
): { constraints: NameConstraintSet; unsupported: boolean } => {
  const state = { unsupported: false };
  const root = parseDer(valueDer);
  expectTag(root, TAG.sequence, "NameConstraints");
  const result: NameConstraintSet = { permitted: [], excluded: [] };
  for (const field of children(root)) {
    if (field.tag === 0xa0) {
      result.permitted = decodeSubtrees(field, state);
    } else if (field.tag === 0xa1) {
      result.excluded = decodeSubtrees(field, state);
    } else {
      throw new DerError("Malformed NameConstraints.");
    }
  }
  return { constraints: result, unsupported: state.unsupported };
};
