/**
 * Name normalization and rule matching for the PKI policy engine.
 *
 * Pure functions only. Normalizers return a NameResult instead of throwing so
 * the policy engine can turn a failure into a denial with a precise detail.
 */
import { domainToASCII, domainToUnicode } from "node:url";

export type NameResult<T> =
  { ok: true; value: T } | { ok: false; reason: string };

const good = <T>(value: T): NameResult<T> => ({ ok: true, value });
const bad = <T = never>(reason: string): NameResult<T> => ({
  ok: false,
  reason,
});

export const MAX_DNS_NAME_LENGTH = 253;
export const MAX_DNS_LABEL_LENGTH = 63;
export const MAX_URI_BYTES = 1024;

const ldhLabel = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const asciiOnly = /^[\x00-\x7f]*$/;

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

export interface DnsNormalizeOptions {
  /** Permit `*` as the whole leftmost label. */
  allowWildcard?: boolean;
}

export const isWildcardName = (name: string): boolean => name.startsWith("*.");

/** Lowercase ASCII, one trailing dot removed, LDH labels, A-label round trip. */
export const normalizeDnsName = (
  input: string,
  options: DnsNormalizeOptions = {},
): NameResult<string> => {
  if (typeof input !== "string") {
    return bad("dns name must be a string");
  }
  if (!asciiOnly.test(input)) {
    return bad(
      "dns name must be ASCII (U-labels are not accepted; use the A-label)",
    );
  }
  let name = input;
  if (name.endsWith(".")) {
    name = name.slice(0, -1);
  }
  name = name.toLowerCase();
  if (name.length === 0) {
    return bad("dns name is empty");
  }
  if (name.length > MAX_DNS_NAME_LENGTH) {
    return bad(`dns name exceeds ${MAX_DNS_NAME_LENGTH} bytes`);
  }
  const labels = name.split(".");
  for (let i = 0; i < labels.length; i += 1) {
    const label = labels[i] as string;
    if (label.length === 0) {
      return bad("dns name has an empty label");
    }
    if (label.length > MAX_DNS_LABEL_LENGTH) {
      return bad(`dns label exceeds ${MAX_DNS_LABEL_LENGTH} bytes`);
    }
    if (label === "*") {
      if (!options.allowWildcard) {
        return bad("wildcard is not allowed here");
      }
      if (i !== 0 || labels.length < 2) {
        return bad("wildcard must be the whole leftmost label with a base");
      }
      continue;
    }
    if (label.includes("_")) {
      return bad("dns label contains an underscore");
    }
    if (!ldhLabel.test(label)) {
      return bad("dns label is not letters, digits and hyphens");
    }
    if (label.startsWith("xn--")) {
      const unicode = domainToUnicode(label);
      if (
        unicode === "" ||
        unicode === label ||
        domainToASCII(unicode) !== label
      ) {
        return bad("dns label is not a valid A-label");
      }
    }
  }
  return good(name);
};

export type DnsRuleKind = "exact" | "single" | "deep";

/** A parsed DNS rule. `base` is the exact name, or the part after `*.` / `**.`. */
export interface DnsRule {
  kind: DnsRuleKind;
  base: string;
}

export const parseDnsRule = (text: string): NameResult<DnsRule> => {
  if (typeof text !== "string") {
    return bad("dns rule must be a string");
  }
  let kind: DnsRuleKind = "exact";
  let rest = text;
  if (text.startsWith("**.")) {
    kind = "deep";
    rest = text.slice(3);
  } else if (text.startsWith("*.")) {
    kind = "single";
    rest = text.slice(2);
  }
  const base = normalizeDnsName(rest);
  if (!base.ok) {
    return bad(`dns rule "${text}": ${base.reason}`);
  }
  if (kind !== "exact" && base.value.split(".").length < 2) {
    return bad(`dns rule "${text}": wildcard base needs at least two labels`);
  }
  return good({ kind, base: base.value });
};

export const dnsRuleToString = (rule: DnsRule): string =>
  rule.kind === "exact"
    ? rule.base
    : `${rule.kind === "single" ? "*" : "**"}.${rule.base}`;

const endsWithLabelBoundary = (name: string, base: string): boolean =>
  name.endsWith(`.${base}`);

/** Does the rule permit this concrete (non-wildcard) normalized name? */
export const dnsRuleMatches = (rule: DnsRule, name: string): boolean => {
  switch (rule.kind) {
    case "exact":
      return name === rule.base;
    case "single":
      return (
        endsWithLabelBoundary(name, rule.base) &&
        !name.slice(0, name.length - rule.base.length - 1).includes(".")
      );
    case "deep":
      return endsWithLabelBoundary(name, rule.base);
  }
};

/**
 * Does the rule permit every name the requested wildcard `*.<base>` can cover?
 * Only a rule that itself ranges over one label directly under `base` (the
 * same single wildcard) or over any depth at or above `base` can.
 */
export const dnsRuleCoversWildcard = (
  rule: DnsRule,
  wildcardBase: string,
): boolean => {
  switch (rule.kind) {
    case "exact":
      return false;
    case "single":
      return rule.base === wildcardBase;
    case "deep":
      return (
        wildcardBase === rule.base ||
        endsWithLabelBoundary(wildcardBase, rule.base)
      );
  }
};

/** Does the rule match at least one name the requested wildcard `*.<base>` can cover? */
export const dnsRuleIntersectsWildcard = (
  rule: DnsRule,
  wildcardBase: string,
): boolean => {
  switch (rule.kind) {
    case "exact":
      return (
        endsWithLabelBoundary(rule.base, wildcardBase) &&
        !rule.base
          .slice(0, rule.base.length - wildcardBase.length - 1)
          .includes(".")
      );
    case "single":
      return rule.base === wildcardBase;
    case "deep":
      return (
        wildcardBase === rule.base ||
        endsWithLabelBoundary(wildcardBase, rule.base)
      );
  }
};

export interface DnsRuleSet {
  allow: DnsRule[];
  deny: DnsRule[];
  allowWildcardNames: boolean;
}

export type RuleDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: "name_not_permitted" | "wildcard_not_permitted";
      detail: string;
    };

/** Evaluate one normalized DNS name (possibly `*.base`) against a rule set. Deny wins. */
export const evaluateDnsName = (
  name: string,
  rules: DnsRuleSet,
): RuleDecision => {
  const wildcard = isWildcardName(name);
  if (wildcard && !rules.allowWildcardNames) {
    return {
      allowed: false,
      reason: "wildcard_not_permitted",
      detail: `wildcard name ${name} is not permitted`,
    };
  }
  const base = wildcard ? name.slice(2) : name;
  const denied = rules.deny.some((rule) =>
    wildcard
      ? dnsRuleIntersectsWildcard(rule, base)
      : dnsRuleMatches(rule, name),
  );
  if (denied) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `dns name ${name} matches a deny rule`,
    };
  }
  const allowed = rules.allow.some((rule) =>
    wildcard ? dnsRuleCoversWildcard(rule, base) : dnsRuleMatches(rule, name),
  );
  if (!allowed) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `dns name ${name} matches no allow rule`,
    };
  }
  return { allowed: true };
};

// ---------------------------------------------------------------------------
// IP
// ---------------------------------------------------------------------------

export interface ParsedIp {
  family: 4 | 6;
  bytes: Uint8Array;
}

const parseIpv4 = (text: string): Uint8Array | undefined => {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) {
    return undefined;
  }
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const part = match[i + 1] as string;
    if (part.length > 1 && part.startsWith("0")) {
      return undefined;
    }
    const value = Number(part);
    if (value > 255) {
      return undefined;
    }
    bytes[i] = value;
  }
  return bytes;
};

const parseIpv6 = (text: string): Uint8Array | undefined => {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) {
    return undefined;
  }
  let source = text;
  if (source.includes(".")) {
    const lastColon = source.lastIndexOf(":");
    const v4 = parseIpv4(source.slice(lastColon + 1));
    if (!v4) {
      return undefined;
    }
    const hex = (a: number, b: number) => ((a << 8) | b).toString(16);
    source = `${source.slice(0, lastColon + 1)}${hex(v4[0] as number, v4[1] as number)}:${hex(v4[2] as number, v4[3] as number)}`;
  }
  const halves = source.split("::");
  if (halves.length > 2) {
    return undefined;
  }
  const split = (part: string): string[] =>
    part === "" ? [] : part.split(":");
  const head = split(halves[0] as string);
  const tail = halves.length === 2 ? split(halves[1] as string) : [];
  const groups = [...head, ...tail];
  if (!groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) {
    return undefined;
  }
  if (halves.length === 1 ? head.length !== 8 : groups.length > 7) {
    return undefined;
  }
  const full = [
    ...head,
    ...new Array<string>(8 - groups.length).fill("0"),
    ...tail,
  ];
  const bytes = new Uint8Array(16);
  full.forEach((group, index) => {
    const value = parseInt(group, 16);
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
};

const parseIpRaw = (text: string): ParsedIp | undefined => {
  const v4 = parseIpv4(text);
  if (v4) {
    return { family: 4, bytes: v4 };
  }
  const v6 = parseIpv6(text);
  return v6 ? { family: 6, bytes: v6 } : undefined;
};

const isMappedV6 = (ip: ParsedIp): boolean =>
  ip.family === 6 &&
  ip.bytes.subarray(0, 10).every((b) => b === 0) &&
  ip.bytes[10] === 0xff &&
  ip.bytes[11] === 0xff;

const unmap = (ip: ParsedIp): ParsedIp =>
  isMappedV6(ip) ? { family: 4, bytes: ip.bytes.slice(12) } : ip;

export const ipToString = (ip: ParsedIp): string => {
  if (ip.family === 4) {
    return Array.from(ip.bytes).join(".");
  }
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((ip.bytes[i] as number) << 8) | (ip.bytes[i + 1] as number));
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j += 1;
    }
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = (values: number[]) => values.map((v) => v.toString(16)).join(":");
  if (bestLength < 2) {
    return hex(groups);
  }
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLength))}`;
};

/** Byte-canonical IP: IPv4-mapped IPv6 becomes IPv4. `text` is the canonical text. */
export const normalizeIp = (
  input: string,
): NameResult<ParsedIp & { text: string }> => {
  if (typeof input !== "string") {
    return bad("ip address must be a string");
  }
  const raw = parseIpRaw(input);
  if (!raw) {
    return bad("not a valid IPv4 or IPv6 address");
  }
  const ip = unmap(raw);
  return good({ ...ip, text: ipToString(ip) });
};

export interface Cidr {
  family: 4 | 6;
  /** Network address with host bits zero. */
  bytes: Uint8Array;
  prefix: number;
}

const bitsEqual = (a: Uint8Array, b: Uint8Array, bits: number): boolean => {
  const whole = Math.floor(bits / 8);
  for (let i = 0; i < whole; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  const rest = bits % 8;
  if (rest === 0) {
    return true;
  }
  const mask = (0xff << (8 - rest)) & 0xff;
  return ((a[whole] as number) & mask) === ((b[whole] as number) & mask);
};

export interface CidrOptions {
  /**
   * Rule mode (default true): host bits must be zero and /0 is rejected. Pass
   * false for CA NameConstraints, which are masked and may be /0.
   */
  strict?: boolean;
  /**
   * Convert an IPv4-mapped IPv6 network to IPv4 (default true). CA constraints
   * pass false: verifiers compare address lengths, so a mapped constraint stays IPv6.
   */
  convertMapped?: boolean;
}

/**
 * Parse `addr/prefix` (or a bare address, meaning a single host). An IPv4-mapped
 * IPv6 network is converted to IPv4 when its prefix is at least 96.
 */
export const parseCidr = (
  text: string,
  options: CidrOptions = {},
): NameResult<Cidr> => {
  const strict = options.strict ?? true;
  if (typeof text !== "string") {
    return bad("cidr must be a string");
  }
  const slash = text.indexOf("/");
  const addressText = slash === -1 ? text : text.slice(0, slash);
  const raw = parseIpRaw(addressText);
  if (!raw) {
    return bad(`cidr "${text}": not a valid address`);
  }
  let prefix = raw.family === 4 ? 32 : 128;
  if (slash !== -1) {
    const prefixText = text.slice(slash + 1);
    if (!/^(0|[1-9]\d{0,2})$/.test(prefixText)) {
      return bad(`cidr "${text}": invalid prefix length`);
    }
    prefix = Number(prefixText);
  }
  let ip = raw;
  if (options.convertMapped !== false && isMappedV6(raw)) {
    if (prefix < 96) {
      return bad(
        `cidr "${text}": an IPv4-mapped network needs a prefix of at least 96`,
      );
    }
    ip = unmap(raw);
    prefix -= 96;
  }
  if (prefix > (ip.family === 4 ? 32 : 128)) {
    return bad(`cidr "${text}": prefix out of range`);
  }
  if (strict && prefix === 0) {
    return bad(`cidr "${text}": a /0 network is not allowed`);
  }
  const bytes = new Uint8Array(ip.bytes.length);
  for (let bit = 0; bit < prefix; bit += 1) {
    const index = bit >> 3;
    bytes[index] =
      (bytes[index] as number) |
      ((ip.bytes[index] as number) & (0x80 >> (bit % 8)));
  }
  if (strict && !bytes.every((b, i) => b === ip.bytes[i])) {
    return bad(`cidr "${text}": host bits are set`);
  }
  return good({ family: ip.family, bytes, prefix });
};

export const cidrToString = (cidr: Cidr): string =>
  `${ipToString(cidr)}/${cidr.prefix}`;

export const cidrContainsIp = (cidr: Cidr, ip: ParsedIp): boolean =>
  cidr.family === ip.family && bitsEqual(cidr.bytes, ip.bytes, cidr.prefix);

/** `inner` lies entirely within `outer`. */
export const cidrSubset = (inner: Cidr, outer: Cidr): boolean =>
  inner.family === outer.family &&
  inner.prefix >= outer.prefix &&
  bitsEqual(inner.bytes, outer.bytes, outer.prefix);

export const cidrsIntersect = (a: Cidr, b: Cidr): boolean =>
  cidrSubset(a, b) || cidrSubset(b, a);

export interface IpRuleSet {
  allow: Cidr[];
  deny: Cidr[];
}

export const evaluateIp = (
  ip: ParsedIp & { text: string },
  rules: IpRuleSet,
): RuleDecision => {
  if (rules.deny.some((cidr) => cidrContainsIp(cidr, ip))) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `ip ${ip.text} matches a deny rule`,
    };
  }
  if (!rules.allow.some((cidr) => cidrContainsIp(cidr, ip))) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `ip ${ip.text} matches no allow rule`,
    };
  }
  return { allowed: true };
};

// ---------------------------------------------------------------------------
// URI
// ---------------------------------------------------------------------------

export interface NormalizedUri {
  /** Canonical text: scheme://host[:port]path[?query]. */
  value: string;
  scheme: string;
  host: string;
  port: string;
  /** Normalized path ('' when absent on a non-special scheme). */
  path: string;
  query: string;
}

const specialSchemes = new Set(["http", "https", "ftp", "ws", "wss", "file"]);
const unreservedChar = /^[A-Za-z0-9\-._~]$/;

/** Decode unreserved percent-escapes, uppercase the rest. Dot segments are rejected afterwards. */
const normalizePercent = (path: string): NameResult<string> => {
  let out = "";
  for (let i = 0; i < path.length; i += 1) {
    const ch = path[i] as string;
    if (ch !== "%") {
      out += ch;
      continue;
    }
    const hex = path.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
      return bad("uri path has a malformed percent escape");
    }
    const code = parseInt(hex, 16);
    if (code < 0x20 || code === 0x7f) {
      return bad("uri path has an encoded control character");
    }
    const decoded = String.fromCharCode(code);
    out += unreservedChar.test(decoded) ? decoded : `%${hex.toUpperCase()}`;
    i += 2;
  }
  return good(out);
};

const pathSegments = (path: string): string[] =>
  path === "" ? [] : path.slice(1).split("/");

const checkSegments = (path: string): string | undefined => {
  for (const segment of pathSegments(path)) {
    if (segment === "." || segment === "..") {
      return "uri path has a dot segment";
    }
  }
  return undefined;
};

const hasControlOrSpace = (text: string): boolean =>
  /[\x00-\x20\x7f]/.test(text);

/** WHATWG parse; no userinfo or fragment; lowercase DNS host; normalized path. */
export const normalizeUri = (input: string): NameResult<NormalizedUri> => {
  if (typeof input !== "string") {
    return bad("uri must be a string");
  }
  if (Buffer.byteLength(input, "utf8") > MAX_URI_BYTES) {
    return bad(`uri exceeds ${MAX_URI_BYTES} bytes`);
  }
  if (!asciiOnly.test(input) || hasControlOrSpace(input)) {
    return bad("uri must be ASCII without whitespace or control characters");
  }
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(input);
  if (!authority) {
    return bad("uri must have a scheme and an authority (scheme://host)");
  }
  if (input.includes("#")) {
    return bad("uri must not have a fragment");
  }
  if ((authority[1] as string).includes("@")) {
    return bad("uri must not have userinfo");
  }
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return bad("uri does not parse");
  }
  if (url.username !== "" || url.password !== "") {
    return bad("uri must not have userinfo");
  }
  const scheme = url.protocol.slice(0, -1).toLowerCase();
  const hostText = url.hostname.toLowerCase();
  if (hostText.startsWith("[")) {
    return bad("uri IPv6 hosts are not supported");
  }
  if (hostText === "") {
    return bad("uri host is empty");
  }
  const host = normalizeDnsName(hostText);
  if (!host.ok) {
    return bad(`uri host: ${host.reason}`);
  }
  const path = normalizePercent(url.pathname);
  if (!path.ok) {
    return path;
  }
  const segmentProblem = checkSegments(path.value);
  if (segmentProblem) {
    return bad(segmentProblem);
  }
  const query = input.includes("?") ? url.search || "?" : "";
  const port = url.port;
  // WHATWG percent-encodes some characters (1 -> 3 bytes), so the limit applies to the built value.
  const value = `${scheme}://${host.value}${port ? `:${port}` : ""}${path.value}${query}`;
  if (Buffer.byteLength(value, "utf8") > MAX_URI_BYTES) {
    return bad(`uri exceeds ${MAX_URI_BYTES} bytes once normalized`);
  }
  return good({
    value,
    scheme,
    host: host.value,
    port,
    path: path.value,
    query,
  });
};

/** The reserved identity namespace `spiffe://hemlig/` (also the bare host). */
export const isReservedUri = (
  uri: Pick<NormalizedUri, "scheme" | "host">,
): boolean => uri.scheme === "spiffe" && uri.host === "hemlig";

export interface UriRule {
  scheme: string;
  host: DnsRule;
  /** Path segments; `*` one segment; `**` the rest (final entry only). */
  segments: string[];
}

export const parseUriRule = (text: string): NameResult<UriRule> => {
  if (typeof text !== "string") {
    return bad("uri rule must be a string");
  }
  if (!asciiOnly.test(text) || hasControlOrSpace(text) || /[?#@]/.test(text)) {
    return bad(
      `uri rule "${text}": query strings, fragments and userinfo are not allowed`,
    );
  }
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)(\/.*)?$/.exec(text);
  if (!match) {
    return bad(`uri rule "${text}": expected scheme://host[/path]`);
  }
  const scheme = (match[1] as string).toLowerCase();
  const hostText = match[2] as string;
  if (hostText.includes(":") || hostText.includes("[")) {
    return bad(`uri rule "${text}": ports and IP literals are not allowed`);
  }
  const host = parseDnsRule(hostText.toLowerCase());
  if (!host.ok) {
    return bad(`uri rule "${text}": ${host.reason}`);
  }
  let rawPath = match[3] ?? "";
  if (rawPath === "" && specialSchemes.has(scheme)) {
    rawPath = "/";
  }
  const segments: string[] = [];
  const raw = pathSegments(rawPath);
  for (let i = 0; i < raw.length; i += 1) {
    const segment = raw[i] as string;
    if (segment === "*" || segment === "**") {
      if (segment === "**" && i !== raw.length - 1) {
        return bad(
          `uri rule "${text}": ** is only allowed as the final segment`,
        );
      }
      segments.push(segment);
      continue;
    }
    if (segment.includes("*")) {
      return bad(`uri rule "${text}": * must be a whole path segment`);
    }
    const normalized = normalizePercent(segment);
    if (!normalized.ok) {
      return bad(`uri rule "${text}": ${normalized.reason}`);
    }
    if (normalized.value === "." || normalized.value === "..") {
      return bad(`uri rule "${text}": dot segments are not allowed`);
    }
    segments.push(normalized.value);
  }
  return good({ scheme, host: host.value, segments });
};

export const uriRuleIsReserved = (rule: UriRule): boolean =>
  rule.scheme === "spiffe" &&
  rule.host.kind === "exact" &&
  rule.host.base === "hemlig";

export const uriRuleMatches = (rule: UriRule, uri: NormalizedUri): boolean => {
  if (uri.scheme !== rule.scheme || uri.port !== "" || uri.query !== "") {
    return false;
  }
  if (!dnsRuleMatches(rule.host, uri.host)) {
    return false;
  }
  const request = pathSegments(uri.path);
  const last = rule.segments[rule.segments.length - 1];
  const deep = last === "**";
  const fixed = deep ? rule.segments.length - 1 : rule.segments.length;
  if (deep ? request.length <= fixed : request.length !== fixed) {
    return false;
  }
  for (let i = 0; i < request.length; i += 1) {
    const segment = request[i] as string;
    const pattern = i < fixed ? (rule.segments[i] as string) : "**";
    if (pattern === "*" || pattern === "**") {
      if (segment === "") {
        return false;
      }
    } else if (pattern !== segment) {
      return false;
    }
  }
  return true;
};

export interface UriRuleSet {
  allow: UriRule[];
  deny: UriRule[];
}

export const evaluateUri = (
  uri: NormalizedUri,
  rules: UriRuleSet,
): RuleDecision => {
  if (rules.deny.some((rule) => uriRuleMatches(rule, uri))) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `uri ${uri.value} matches a deny rule`,
    };
  }
  if (!rules.allow.some((rule) => uriRuleMatches(rule, uri))) {
    return {
      allowed: false,
      reason: "name_not_permitted",
      detail: `uri ${uri.value} matches no allow rule`,
    };
  }
  return { allowed: true };
};

// ---------------------------------------------------------------------------
// CA NameConstraints (RFC 5280 semantics, host based for URIs)
// ---------------------------------------------------------------------------

export interface NameConstraintSubtrees {
  /** `example.com` matches the name and its subdomains; `.example.com` only subdomains. */
  dns?: string[];
  /** CIDR strings such as `10.0.0.0/8`. */
  ip?: string[];
  /** Host constraints: `example.com` matches that host exactly; `.example.com` its subdomains. */
  uri?: string[];
}

export interface NameConstraintSet {
  permitted?: NameConstraintSubtrees;
  excluded?: NameConstraintSubtrees;
}

export type ConstraintType = "dns" | "ip" | "uri";

interface Subtree {
  base: string;
  self: boolean;
  sub: boolean;
  all: boolean;
}

const toSubtree = (
  text: string,
  type: "dns" | "uri",
  excluded = false,
): Subtree => {
  let base = text.toLowerCase();
  if (base.endsWith(".") && base.length > 1) {
    base = base.slice(0, -1);
  }
  if (base === "") {
    return { base, self: true, sub: true, all: type === "dns" };
  }
  if (base.startsWith(".")) {
    return { base: base.slice(1), self: false, sub: true, all: false };
  }
  // Excluded URI subtrees also cover subdomains (Go's reading), so Hemlig never issues what Go rejects.
  return { base, self: true, sub: type === "dns" || excluded, all: false };
};

const nameSubsetOfSubtree = (rule: DnsRule, tree: Subtree): boolean => {
  if (tree.all) {
    return true;
  }
  if (rule.kind === "exact") {
    return (
      (tree.self && rule.base === tree.base) ||
      (tree.sub && endsWithLabelBoundary(rule.base, tree.base))
    );
  }
  // Every name `label.base` (or deeper) is a proper subdomain of the tree base.
  return (
    tree.sub &&
    (rule.base === tree.base || endsWithLabelBoundary(rule.base, tree.base))
  );
};

const nameIntersectsSubtree = (rule: DnsRule, tree: Subtree): boolean => {
  if (nameSubsetOfSubtree(rule, tree)) {
    return true;
  }
  if (rule.kind === "exact") {
    return false;
  }
  if (rule.kind === "single") {
    return (
      tree.self &&
      endsWithLabelBoundary(tree.base, rule.base) &&
      !tree.base.slice(0, tree.base.length - rule.base.length - 1).includes(".")
    );
  }
  return (tree.self || tree.sub) && endsWithLabelBoundary(tree.base, rule.base);
};

export type RuleOverlap = "inside" | "partial" | "outside";

const classify = (
  restricted: boolean,
  permittedCover: boolean,
  permittedAny: boolean,
  excludedAll: boolean,
  excludedAny: boolean,
): RuleOverlap => {
  if ((restricted && !permittedAny) || excludedAll) {
    return "outside";
  }
  if ((!restricted || permittedCover) && !excludedAny) {
    return "inside";
  }
  return "partial";
};

/**
 * Parse CA IP constraints. Entries that do not parse never widen anything: a
 * permitted list still counts as restricted (an unparsable entry matches
 * nothing), and an unparsable excluded entry excludes everything.
 */
const toCidrs = (
  values: string[] | undefined,
  kind: "permitted" | "excluded",
): { cidrs: Cidr[]; total: number; invalid: boolean } => {
  const cidrs: Cidr[] = [];
  let invalid = false;
  for (const value of values ?? []) {
    const parsed = parseCidr(value, { strict: false, convertMapped: false });
    if (parsed.ok) {
      cidrs.push(parsed.value);
      // An IPv4-mapped excluded range also excludes its IPv4 form, so a
      // mapped exclusion never lets the equivalent 4-byte address through.
      // Permitted ranges stay IPv6-only (validators compare address lengths).
      if (kind === "excluded") {
        const converted = parseCidr(value, { strict: false });
        if (converted.ok && converted.value.family !== parsed.value.family) {
          cidrs.push(converted.value);
        }
      }
    } else {
      invalid = true;
    }
  }
  return { cidrs, total: (values ?? []).length, invalid };
};

/** Where a DNS rule (or a requested wildcard/name expressed as a rule) sits relative to the constraints. */
export const classifyDnsRule = (
  rule: DnsRule,
  constraints: NameConstraintSet | undefined,
  type: "dns" | "uri" = "dns",
): RuleOverlap => {
  const permitted = (constraints?.permitted?.[type] ?? []).map((t) =>
    toSubtree(t, type),
  );
  const excluded = (constraints?.excluded?.[type] ?? []).map((t) =>
    toSubtree(t, type, true),
  );
  return classify(
    permitted.length > 0,
    permitted.some((t) => nameSubsetOfSubtree(rule, t)),
    permitted.some((t) => nameIntersectsSubtree(rule, t)),
    excluded.some((t) => nameSubsetOfSubtree(rule, t)),
    excluded.some((t) => nameIntersectsSubtree(rule, t)),
  );
};

export const classifyCidr = (
  cidr: Cidr,
  constraints: NameConstraintSet | undefined,
): RuleOverlap => {
  const permitted = toCidrs(constraints?.permitted?.ip, "permitted");
  const excluded = toCidrs(constraints?.excluded?.ip, "excluded");
  return classify(
    permitted.total > 0,
    permitted.cidrs.some((p) => cidrSubset(cidr, p)),
    permitted.cidrs.some((p) => cidrsIntersect(cidr, p)),
    excluded.invalid || excluded.cidrs.some((e) => cidrSubset(cidr, e)),
    excluded.invalid || excluded.cidrs.some((e) => cidrsIntersect(cidr, e)),
  );
};

export type ConstraintCheck = { ok: true } | { ok: false; detail: string };

/**
 * Check a normalized value against CA NameConstraints. A requested wildcard
 * `*.base` is checked as the rule `*.base`, so every name it could cover must
 * be permitted and none excluded.
 */
export const checkNameConstraints = (
  type: ConstraintType,
  value: string,
  constraints: NameConstraintSet | undefined,
): ConstraintCheck => {
  // Parse first so an unparsable value is never waved through, constraints or not.
  const ip = type === "ip" ? normalizeIp(value) : undefined;
  const uri = type === "uri" ? normalizeUri(value) : undefined;
  if (ip && !ip.ok) {
    return { ok: false, detail: `ip ${value} is invalid` };
  }
  if (uri && !uri.ok) {
    return { ok: false, detail: `uri ${value} is invalid` };
  }
  if (!constraints) {
    return { ok: true };
  }
  let overlap: RuleOverlap;
  if (type === "ip") {
    if (!ip || !ip.ok) {
      return { ok: false, detail: `ip ${value} is invalid` };
    }
    const host: Cidr = {
      family: ip.value.family,
      bytes: ip.value.bytes,
      prefix: ip.value.family === 4 ? 32 : 128,
    };
    overlap = classifyCidr(host, constraints);
  } else {
    const host = uri ? (uri.ok ? uri.value.host : undefined) : value;
    if (host === undefined) {
      return { ok: false, detail: `uri ${value} is invalid` };
    }
    // RFC 5280 4.2.1.10: a URI whose host is an IP literal cannot satisfy a host constraint.
    const uriConstrained =
      (constraints.permitted?.uri?.length ?? 0) +
        (constraints.excluded?.uri?.length ?? 0) >
      0;
    if (uri && uriConstrained && parseIpv4(host)) {
      return {
        ok: false,
        detail: `uri ${value} has an IP-literal host, which URI name constraints do not allow`,
      };
    }
    const rule: DnsRule = isWildcardName(host)
      ? { kind: "single", base: host.slice(2) }
      : { kind: "exact", base: host };
    overlap = classifyDnsRule(rule, constraints, type);
  }
  return overlap === "inside"
    ? { ok: true }
    : {
        ok: false,
        detail: `${type} ${value} violates the CA name constraints`,
      };
};

// ---------------------------------------------------------------------------
// Reserved names
// ---------------------------------------------------------------------------

/** URIs are the only reserved namespace today (`spiffe://hemlig/`). */
export const isReservedName = (
  type: ConstraintType,
  value: string,
): boolean => {
  if (type !== "uri") {
    return false;
  }
  const parsed = normalizeUri(value);
  // Fail closed: a value that does not parse is treated as reserved.
  return !parsed.ok || isReservedUri(parsed.value);
};
