/**
 * Pure parts of IssuanceGrant write-time validation ("Validation at write
 * time"): structure, rule parsing, reserved names, size limits, forced values,
 * overlap with a CA's NameConstraints and lifetime/algorithm/EKU checks
 * against the CA policy. Consumer, CA status and environment checks need I/O
 * and live in the grant service.
 */
import { sha256Hex, stableJson } from "../util/encoding";
import {
  type Cidr,
  type DnsRule,
  type DnsRuleSet,
  type IpRuleSet,
  type NameConstraintSet,
  type UriRule,
  type UriRuleSet,
  checkNameConstraints,
  classifyCidr,
  classifyDnsRule,
  isReservedName,
  normalizeDnsName,
  normalizeIp,
  normalizeUri,
  parseCidr,
  parseDnsRule,
  parseUriRule,
  uriRuleIsReserved,
} from "./names";
import {
  DEFAULT_LEAF_KEY_ALGORITHMS,
  EXTENDED_KEY_USAGES,
  type ExtendedKeyUsageName,
  type GrantPolicy,
  KEY_USAGES,
  LEAF_KEY_ALGORITHMS,
  type LeafKeyAlgorithm,
  SUBJECT_ATTRIBUTES,
  type SanSet,
  type SubjectAttribute,
} from "./policy-types";

export const GRANT_POLICY_MAX_BYTES = 32 * 1024;
export const GRANT_MAX_NAME_RULES = 200;
export const GRANT_MAX_FORCED_SANS = 10;
export const GRANT_MAX_POLICY_OIDS = 10;
export const MAX_SANS = 100;
export const MIN_LEAF_LIFETIME_SECONDS = 300;
export const MAX_LEAF_LIFETIME_SECONDS = 397 * 86400;
export const DEFAULT_MIN_LIFETIME_SECONDS = 3600;
export const ANY_EXTENDED_KEY_USAGE = ["anyExtendedKeyUsage", "2.5.29.37.0"];
/** X.520 upper bound for O, OU and CN. */
export const MAX_SUBJECT_VALUE_LENGTH = 64;
/** RFC 5280 Appendix A.1 upper bounds: CN, O, OU 64; L, ST 128; C exactly 2. */
export const subjectValueLimit = (
  type: SubjectAttribute | "commonName",
): number =>
  type === "locality" || type === "state"
    ? 128
    : type === "country"
      ? 2
      : MAX_SUBJECT_VALUE_LENGTH;

export interface GrantIssue {
  code: string;
  path: string;
  message: string;
}

export interface GrantCaContext {
  leafKeyAlgorithms: LeafKeyAlgorithm[];
  maxLeafLifetimeSeconds: number;
  nameConstraints?: NameConstraintSet;
  extendedKeyUsages?: string[];
}

export interface GrantValidationContext {
  /** The CA the grant names. Omit to run only the CA-independent checks. */
  ca?: GrantCaContext;
}

/** A grant policy with every rule parsed. */
export interface CompiledGrantPolicy {
  policy: GrantPolicy;
  dns: DnsRuleSet;
  ip: IpRuleSet;
  uri: UriRuleSet;
  commonName: { mode: "san" | "forbid"; addToSans: boolean };
  maxSans: number;
  subjectAllow: Partial<Record<SubjectAttribute, string[]>>;
  forcedSans: SanSet;
  keyAlgorithms: LeafKeyAlgorithm[];
  minSeconds: number;
}

export interface GrantValidationResult {
  ok: boolean;
  policy?: GrantPolicy;
  compiled?: CompiledGrantPolicy;
  errors: GrantIssue[];
  warnings: GrantIssue[];
}

/** `sha256(stableJson(policy))`, stored and audited with the grant. */
export const policyDigest = (policy: unknown): string =>
  sha256Hex(stableJson(policy));

const oidPattern = /^[0-2](?:\.(?:0|[1-9]\d*))+$/;

/**
 * Glob subject value match: `*` matches any run of characters. Iterative with
 * a single backtrack point, so it runs in O(pattern x value) and cannot blow up.
 */
export const globMatches = (pattern: string, value: string): boolean => {
  let p = 0;
  let v = 0;
  let star = -1;
  let resume = 0;
  while (v < value.length) {
    if (p < pattern.length && pattern[p] === "*") {
      star = p;
      resume = v;
      p += 1;
    } else if (p < pattern.length && pattern[p] === value[v]) {
      p += 1;
      v += 1;
    } else if (star !== -1) {
      p = star + 1;
      resume += 1;
      v = resume;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === "*") {
    p += 1;
  }
  return p === pattern.length;
};

export const subjectGlobMatches = (
  patterns: string[],
  value: string,
): boolean => patterns.some((pattern) => globMatches(pattern, value));

export const validSubjectValue = (
  type: SubjectAttribute | "commonName",
  value: string,
): string | undefined => {
  if (value.length === 0) {
    return "is empty";
  }
  if (/[\x00-\x1f\x7f]/.test(value)) {
    return "contains control characters";
  }
  if (value !== value.trim()) {
    return "has leading or trailing whitespace";
  }
  if (type === "country") {
    return /^[A-Z]{2}$/.test(value)
      ? undefined
      : "must be a two-letter uppercase country code";
  }
  return value.length <= subjectValueLimit(type)
    ? undefined
    : `exceeds ${subjectValueLimit(type)} characters`;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

class Collector {
  public readonly errors: GrantIssue[] = [];
  public readonly warnings: GrantIssue[] = [];

  public error(code: string, path: string, message: string): void {
    this.errors.push({ code, path, message });
  }

  public warn(code: string, path: string, message: string): void {
    this.warnings.push({ code, path, message });
  }
}

const objectAt = (
  value: unknown,
  path: string,
  allowed: string[],
  out: Collector,
): Record<string, unknown> | undefined => {
  if (!isRecord(value)) {
    out.error("invalid_type", path, `${path} must be an object`);
    return undefined;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      out.error(
        "unknown_field",
        `${path}.${key}`,
        `${path}.${key} is not a recognized field`,
      );
    }
  }
  return value;
};

const stringsAt = (
  value: unknown,
  path: string,
  out: Collector,
): string[] | undefined => {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    out.error("invalid_type", path, `${path} must be an array of strings`);
    return undefined;
  }
  return value as string[];
};

const intAt = (
  value: unknown,
  path: string,
  min: number,
  max: number,
  out: Collector,
): number | undefined => {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  ) {
    out.error(
      "invalid_value",
      path,
      `${path} must be an integer from ${min} to ${max}`,
    );
    return undefined;
  }
  return value;
};

const enumsAt = <T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
  out: Collector,
): T[] | undefined => {
  const list = stringsAt(value, path, out);
  if (!list) {
    return undefined;
  }
  for (const item of list) {
    if (!allowed.includes(item as T)) {
      out.error(
        "unsupported_value",
        path,
        `${path} has unsupported value "${item}"`,
      );
    }
  }
  return list as T[];
};

const ruleLists = (
  value: unknown,
  path: string,
  extra: string[],
  out: Collector,
) => {
  const obj = objectAt(value, path, ["allow", "deny", ...extra], out);
  if (!obj) {
    return undefined;
  }
  const allow =
    obj.allow === undefined
      ? []
      : (stringsAt(obj.allow, `${path}.allow`, out) ?? []);
  const deny =
    obj.deny === undefined
      ? []
      : (stringsAt(obj.deny, `${path}.deny`, out) ?? []);
  return { obj, allow, deny };
};

/** Structure only: returns a typed policy, collecting issues. Unknown fields are errors. */
const readStructure = (
  input: unknown,
  out: Collector,
): GrantPolicy | undefined => {
  const root = objectAt(
    input,
    "policy",
    [
      "names",
      "subject",
      "keyAlgorithms",
      "keyUsages",
      "extendedKeyUsages",
      "lifetime",
      "forced",
      "quotas",
    ],
    out,
  );
  if (!root) {
    return undefined;
  }
  const names: GrantPolicy["names"] = {};
  if (root.names === undefined) {
    out.error("missing_field", "policy.names", "policy.names is required");
  } else {
    const n = objectAt(
      root.names,
      "policy.names",
      ["dns", "ip", "uri", "commonName", "maxSans"],
      out,
    );
    if (n) {
      if (n.dns !== undefined) {
        const lists = ruleLists(
          n.dns,
          "policy.names.dns",
          ["allowWildcardNames"],
          out,
        );
        if (lists) {
          const wildcard = lists.obj.allowWildcardNames;
          if (wildcard !== undefined && typeof wildcard !== "boolean") {
            out.error(
              "invalid_type",
              "policy.names.dns.allowWildcardNames",
              "allowWildcardNames must be a boolean",
            );
          }
          names.dns = {
            allow: lists.allow,
            deny: lists.deny,
            allowWildcardNames: wildcard === true,
          };
        }
      }
      if (n.ip !== undefined) {
        const lists = ruleLists(n.ip, "policy.names.ip", [], out);
        if (lists) {
          names.ip = { allow: lists.allow, deny: lists.deny };
        }
      }
      if (n.uri !== undefined) {
        const lists = ruleLists(n.uri, "policy.names.uri", [], out);
        if (lists) {
          names.uri = { allow: lists.allow, deny: lists.deny };
        }
      }
      if (n.commonName !== undefined) {
        const cn = objectAt(
          n.commonName,
          "policy.names.commonName",
          ["mode", "addToSans"],
          out,
        );
        if (cn) {
          if (
            cn.mode !== undefined &&
            cn.mode !== "san" &&
            cn.mode !== "forbid"
          ) {
            out.error(
              "invalid_value",
              "policy.names.commonName.mode",
              'mode must be "san" or "forbid"',
            );
          }
          if (cn.addToSans !== undefined && typeof cn.addToSans !== "boolean") {
            out.error(
              "invalid_type",
              "policy.names.commonName.addToSans",
              "addToSans must be a boolean",
            );
          }
          names.commonName = {
            ...(cn.mode === "san" || cn.mode === "forbid"
              ? { mode: cn.mode }
              : {}),
            ...(typeof cn.addToSans === "boolean"
              ? { addToSans: cn.addToSans }
              : {}),
          };
        }
      }
      if (n.maxSans !== undefined) {
        const max = intAt(n.maxSans, "policy.names.maxSans", 1, MAX_SANS, out);
        if (max !== undefined) {
          names.maxSans = max;
        }
      }
    }
  }

  let subject: GrantPolicy["subject"];
  if (root.subject !== undefined) {
    const s = objectAt(root.subject, "policy.subject", ["allow"], out);
    if (s) {
      subject = {};
      if (s.allow !== undefined) {
        const allow = objectAt(
          s.allow,
          "policy.subject.allow",
          [...SUBJECT_ATTRIBUTES],
          out,
        );
        if (allow) {
          subject.allow = {};
          for (const attribute of SUBJECT_ATTRIBUTES) {
            if (allow[attribute] === undefined) {
              continue;
            }
            const patterns = stringsAt(
              allow[attribute],
              `policy.subject.allow.${attribute}`,
              out,
            );
            if (patterns) {
              for (const pattern of patterns) {
                if (
                  pattern.length === 0 ||
                  pattern.length > subjectValueLimit(attribute) ||
                  /[\x00-\x1f\x7f]/.test(pattern)
                ) {
                  out.error(
                    "invalid_value",
                    `policy.subject.allow.${attribute}`,
                    `invalid pattern "${pattern}"`,
                  );
                }
              }
              subject.allow[attribute] = patterns;
            }
          }
        }
      }
    }
  }

  let keyAlgorithms: LeafKeyAlgorithm[] | undefined;
  if (root.keyAlgorithms !== undefined) {
    keyAlgorithms = enumsAt(
      root.keyAlgorithms,
      "policy.keyAlgorithms",
      LEAF_KEY_ALGORITHMS,
      out,
    );
  }
  let keyUsages: GrantPolicy["keyUsages"] = [];
  if (root.keyUsages === undefined) {
    out.error(
      "missing_field",
      "policy.keyUsages",
      "policy.keyUsages is required",
    );
  } else {
    keyUsages =
      enumsAt(root.keyUsages, "policy.keyUsages", KEY_USAGES, out) ?? [];
  }

  let ekus: GrantPolicy["extendedKeyUsages"] = { allow: [], default: [] };
  if (root.extendedKeyUsages === undefined) {
    out.error(
      "missing_field",
      "policy.extendedKeyUsages",
      "policy.extendedKeyUsages is required",
    );
  } else {
    const e = objectAt(
      root.extendedKeyUsages,
      "policy.extendedKeyUsages",
      ["allow", "default"],
      out,
    );
    if (e) {
      ekus = {
        allow:
          enumsAt(
            e.allow,
            "policy.extendedKeyUsages.allow",
            EXTENDED_KEY_USAGES,
            out,
          ) ?? [],
        default:
          enumsAt(
            e.default,
            "policy.extendedKeyUsages.default",
            EXTENDED_KEY_USAGES,
            out,
          ) ?? [],
      };
    }
  }

  let lifetime: GrantPolicy["lifetime"] = { defaultSeconds: 0, maxSeconds: 0 };
  if (root.lifetime === undefined) {
    out.error(
      "missing_field",
      "policy.lifetime",
      "policy.lifetime is required",
    );
  } else {
    const l = objectAt(
      root.lifetime,
      "policy.lifetime",
      ["defaultSeconds", "maxSeconds", "minSeconds"],
      out,
    );
    if (l) {
      const upper = Number.MAX_SAFE_INTEGER;
      const defaultSeconds = intAt(
        l.defaultSeconds,
        "policy.lifetime.defaultSeconds",
        1,
        upper,
        out,
      );
      const maxSeconds = intAt(
        l.maxSeconds,
        "policy.lifetime.maxSeconds",
        1,
        upper,
        out,
      );
      const minSeconds =
        l.minSeconds === undefined
          ? undefined
          : intAt(l.minSeconds, "policy.lifetime.minSeconds", 1, upper, out);
      lifetime = {
        defaultSeconds: defaultSeconds ?? 0,
        maxSeconds: maxSeconds ?? 0,
        ...(minSeconds !== undefined ? { minSeconds } : {}),
      };
    }
  }

  let forced: GrantPolicy["forced"];
  if (root.forced !== undefined) {
    const f = objectAt(
      root.forced,
      "policy.forced",
      ["subject", "sans", "certificatePolicies"],
      out,
    );
    if (f) {
      forced = {};
      if (f.subject !== undefined) {
        const fs = objectAt(
          f.subject,
          "policy.forced.subject",
          [...SUBJECT_ATTRIBUTES],
          out,
        );
        if (fs) {
          forced.subject = {};
          for (const attribute of SUBJECT_ATTRIBUTES) {
            const value = fs[attribute];
            if (value === undefined) {
              continue;
            }
            if (typeof value !== "string") {
              out.error(
                "invalid_type",
                `policy.forced.subject.${attribute}`,
                "forced subject values must be strings",
              );
              continue;
            }
            const problem = validSubjectValue(attribute, value);
            if (problem) {
              out.error(
                "invalid_value",
                `policy.forced.subject.${attribute}`,
                `value ${problem}`,
              );
            }
            forced.subject[attribute] = value;
          }
        }
      }
      if (f.sans !== undefined) {
        const fs = objectAt(
          f.sans,
          "policy.forced.sans",
          ["dns", "ip", "uri"],
          out,
        );
        if (fs) {
          forced.sans = {};
          for (const type of ["dns", "ip", "uri"] as const) {
            if (fs[type] !== undefined) {
              const list = stringsAt(
                fs[type],
                `policy.forced.sans.${type}`,
                out,
              );
              if (list) {
                forced.sans[type] = list;
              }
            }
          }
        }
      }
      if (f.certificatePolicies !== undefined) {
        const list = stringsAt(
          f.certificatePolicies,
          "policy.forced.certificatePolicies",
          out,
        );
        if (list) {
          forced.certificatePolicies = list;
        }
      }
    }
  }

  let quotas: GrantPolicy["quotas"];
  if (root.quotas !== undefined) {
    const q = objectAt(
      root.quotas,
      "policy.quotas",
      ["perHour", "perDay"],
      out,
    );
    if (q) {
      quotas = {};
      for (const key of ["perHour", "perDay"] as const) {
        if (q[key] !== undefined) {
          const value = intAt(
            q[key],
            `policy.quotas.${key}`,
            1,
            1_000_000,
            out,
          );
          if (value !== undefined) {
            quotas[key] = value;
          }
        }
      }
    }
  }

  return {
    names,
    ...(subject ? { subject } : {}),
    ...(keyAlgorithms ? { keyAlgorithms } : {}),
    keyUsages,
    extendedKeyUsages: ekus,
    lifetime,
    ...(forced ? { forced } : {}),
    ...(quotas ? { quotas } : {}),
  };
};

/** Parse rules and forced values into a CompiledGrantPolicy, collecting issues. */
const compile = (
  policy: GrantPolicy,
  ctx: GrantValidationContext,
  out: Collector,
): CompiledGrantPolicy => {
  const ca = ctx.ca;
  const parseList = <T>(
    list: string[] | undefined,
    path: string,
    parse: (
      text: string,
    ) => { ok: true; value: T } | { ok: false; reason: string },
  ): T[] => {
    const parsed: T[] = [];
    (list ?? []).forEach((text, index) => {
      const result = parse(text);
      if (result.ok) {
        parsed.push(result.value);
      } else {
        out.error("invalid_rule", `${path}[${index}]`, result.reason);
      }
    });
    return parsed;
  };

  // DNS
  const dns: DnsRuleSet = {
    allow: parseList(
      policy.names.dns?.allow,
      "policy.names.dns.allow",
      parseDnsRule,
    ),
    deny: parseList(
      policy.names.dns?.deny,
      "policy.names.dns.deny",
      parseDnsRule,
    ),
    allowWildcardNames: policy.names.dns?.allowWildcardNames === true,
  };
  // IP
  const ip: IpRuleSet = {
    allow: parseList<Cidr>(
      policy.names.ip?.allow,
      "policy.names.ip.allow",
      (t) => parseCidr(t),
    ),
    deny: parseList<Cidr>(policy.names.ip?.deny, "policy.names.ip.deny", (t) =>
      parseCidr(t),
    ),
  };
  // URI
  const uri: UriRuleSet = {
    allow: parseList(
      policy.names.uri?.allow,
      "policy.names.uri.allow",
      parseUriRule,
    ),
    deny: parseList(
      policy.names.uri?.deny,
      "policy.names.uri.deny",
      parseUriRule,
    ),
  };
  for (const [list, path] of [
    [uri.allow, "policy.names.uri.allow"],
    [uri.deny, "policy.names.uri.deny"],
  ] as const) {
    list.forEach((rule: UriRule) => {
      if (uriRuleIsReserved(rule)) {
        out.error(
          "reserved_name",
          path,
          "spiffe://hemlig/ is reserved and always denied",
        );
      }
    });
  }

  // Rule count
  const ruleCount =
    (policy.names.dns?.allow?.length ?? 0) +
    (policy.names.dns?.deny?.length ?? 0) +
    (policy.names.ip?.allow?.length ?? 0) +
    (policy.names.ip?.deny?.length ?? 0) +
    (policy.names.uri?.allow?.length ?? 0) +
    (policy.names.uri?.deny?.length ?? 0);
  if (ruleCount > GRANT_MAX_NAME_RULES) {
    out.error(
      "too_many_rules",
      "policy.names",
      `a grant may have at most ${GRANT_MAX_NAME_RULES} name rules (found ${ruleCount})`,
    );
  }

  // Overlap with the CA's NameConstraints (allow rules only; deny rules never widen access).
  if (ca?.nameConstraints) {
    const report = (
      overlap: "inside" | "partial" | "outside",
      path: string,
      text: string,
    ) => {
      if (overlap === "outside") {
        out.error(
          "rule_outside_ca_constraints",
          path,
          `rule "${text}" is entirely outside the CA name constraints`,
        );
      } else if (overlap === "partial") {
        out.warn(
          "rule_partially_outside_ca_constraints",
          path,
          `rule "${text}" partly overlaps the CA name constraints`,
        );
      }
    };
    policy.names.dns?.allow?.forEach((text, index) => {
      const rule = parseDnsRule(text);
      if (rule.ok) {
        report(
          classifyDnsRule(rule.value, ca.nameConstraints, "dns"),
          `policy.names.dns.allow[${index}]`,
          text,
        );
      }
    });
    policy.names.ip?.allow?.forEach((text, index) => {
      const cidr = parseCidr(text);
      if (cidr.ok) {
        report(
          classifyCidr(cidr.value, ca.nameConstraints),
          `policy.names.ip.allow[${index}]`,
          text,
        );
      }
    });
    policy.names.uri?.allow?.forEach((text, index) => {
      const rule = parseUriRule(text);
      if (rule.ok) {
        report(
          classifyDnsRule(rule.value.host, ca.nameConstraints, "uri"),
          `policy.names.uri.allow[${index}]`,
          text,
        );
      }
    });
  }

  // Subject globs
  const subjectAllow: Partial<Record<SubjectAttribute, string[]>> = {};
  for (const attribute of SUBJECT_ATTRIBUTES) {
    const patterns = policy.subject?.allow?.[attribute];
    if (patterns) {
      subjectAllow[attribute] = [...patterns];
    }
  }

  // Forced SANs
  const forcedSans: SanSet = { dns: [], ip: [], uri: [] };
  const forced = policy.forced?.sans ?? {};
  const forcedCount =
    (forced.dns?.length ?? 0) +
    (forced.ip?.length ?? 0) +
    (forced.uri?.length ?? 0);
  if (forcedCount > GRANT_MAX_FORCED_SANS) {
    out.error(
      "too_many_forced_sans",
      "policy.forced.sans",
      `at most ${GRANT_MAX_FORCED_SANS} forced SANs (found ${forcedCount})`,
    );
  }
  const addForced = (type: keyof SanSet, value: string, path: string) => {
    if (!forcedSans[type].includes(value)) {
      forcedSans[type].push(value);
    }
    if (isReservedName(type, value)) {
      out.error(
        "reserved_name",
        path,
        `forced SAN ${value} uses a reserved name`,
      );
    }
    if (ca?.nameConstraints) {
      const check = checkNameConstraints(type, value, ca.nameConstraints);
      if (!check.ok) {
        out.error("forced_san_violates_ca_constraints", path, check.detail);
      }
    }
  };
  (forced.dns ?? []).forEach((text, index) => {
    const result = normalizeDnsName(text);
    const path = `policy.forced.sans.dns[${index}]`;
    result.ok
      ? addForced("dns", result.value, path)
      : out.error("invalid_forced_san", path, result.reason);
  });
  (forced.ip ?? []).forEach((text, index) => {
    const result = normalizeIp(text);
    const path = `policy.forced.sans.ip[${index}]`;
    result.ok
      ? addForced("ip", result.value.text, path)
      : out.error("invalid_forced_san", path, result.reason);
  });
  (forced.uri ?? []).forEach((text, index) => {
    const result = normalizeUri(text);
    const path = `policy.forced.sans.uri[${index}]`;
    result.ok
      ? addForced("uri", result.value.value, path)
      : out.error("invalid_forced_san", path, result.reason);
  });
  const maxSans = Math.min(policy.names.maxSans ?? MAX_SANS, MAX_SANS);
  const forcedTotal =
    forcedSans.dns.length + forcedSans.ip.length + forcedSans.uri.length;
  if (forcedTotal > maxSans) {
    out.error(
      "forced_sans_exceed_max_sans",
      "policy.forced.sans",
      `forced SANs (${forcedTotal}) exceed maxSans (${maxSans})`,
    );
  }

  // Policy OIDs
  const oids = policy.forced?.certificatePolicies ?? [];
  if (oids.length > GRANT_MAX_POLICY_OIDS) {
    out.error(
      "too_many_policy_oids",
      "policy.forced.certificatePolicies",
      `at most ${GRANT_MAX_POLICY_OIDS} policy OIDs`,
    );
  }
  oids.forEach((oid, index) => {
    const arcs = oid.split(".");
    if (
      !oidPattern.test(oid) ||
      (Number(arcs[0]) < 2 && Number(arcs[1]) > 39)
    ) {
      out.error(
        "invalid_oid",
        `policy.forced.certificatePolicies[${index}]`,
        `"${oid}" is not a dotted OID`,
      );
    }
  });

  // Key algorithms against the CA's leaf policy
  const keyAlgorithms =
    policy.keyAlgorithms ??
    DEFAULT_LEAF_KEY_ALGORITHMS.filter(
      (algorithm) => !ca || ca.leafKeyAlgorithms.includes(algorithm),
    );
  if (ca && policy.keyAlgorithms) {
    for (const algorithm of policy.keyAlgorithms) {
      if (!ca.leafKeyAlgorithms.includes(algorithm)) {
        out.error(
          "key_algorithm_not_in_ca_policy",
          "policy.keyAlgorithms",
          `${algorithm} is not allowed by the CA leaf policy`,
        );
      }
    }
  }
  if (keyAlgorithms.length === 0) {
    out.error(
      "key_algorithm_not_in_ca_policy",
      "policy.keyAlgorithms",
      "no key algorithm is allowed by both the grant and the CA leaf policy",
    );
  }

  // EKU
  const { allow, default: defaults } = policy.extendedKeyUsages;
  if (defaults.length === 0) {
    out.error(
      "eku_default_required",
      "policy.extendedKeyUsages.default",
      "a leaf always carries an EKU, so a default is required",
    );
  }
  for (const eku of defaults) {
    if (!allow.includes(eku)) {
      out.error(
        "eku_default_not_allowed",
        "policy.extendedKeyUsages.default",
        `default ${eku} is not in allow`,
      );
    }
  }
  if (
    ca?.extendedKeyUsages &&
    !ca.extendedKeyUsages.some((e) => ANY_EXTENDED_KEY_USAGE.includes(e))
  ) {
    for (const eku of allow) {
      if (!ca.extendedKeyUsages.includes(eku)) {
        out.error(
          "eku_outside_ca_constraints",
          "policy.extendedKeyUsages.allow",
          `${eku} does not fit the CA EKU constraint`,
        );
      }
    }
  }

  // Lifetime: 300 <= min <= default <= max <= CA max <= 397 days
  const minSeconds = policy.lifetime.minSeconds ?? DEFAULT_MIN_LIFETIME_SECONDS;
  const { defaultSeconds, maxSeconds } = policy.lifetime;
  if (
    ca &&
    !(
      Number.isFinite(ca.maxLeafLifetimeSeconds) &&
      ca.maxLeafLifetimeSeconds > 0
    )
  ) {
    out.error(
      "ca_policy_invalid",
      "ca.maxLeafLifetimeSeconds",
      "the CA maximum lifetime is not a positive number",
    );
  }
  const caMax = ca
    ? Math.min(ca.maxLeafLifetimeSeconds, MAX_LEAF_LIFETIME_SECONDS)
    : MAX_LEAF_LIFETIME_SECONDS;
  if (minSeconds < MIN_LEAF_LIFETIME_SECONDS) {
    out.error(
      "lifetime_invalid",
      "policy.lifetime.minSeconds",
      `minSeconds must be at least ${MIN_LEAF_LIFETIME_SECONDS}`,
    );
  }
  if (defaultSeconds > 0 && maxSeconds > 0) {
    if (minSeconds > defaultSeconds) {
      out.error(
        "lifetime_invalid",
        "policy.lifetime",
        "minSeconds must not exceed defaultSeconds",
      );
    }
    if (defaultSeconds > maxSeconds) {
      out.error(
        "lifetime_invalid",
        "policy.lifetime",
        "defaultSeconds must not exceed maxSeconds",
      );
    }
    if (maxSeconds > MAX_LEAF_LIFETIME_SECONDS) {
      out.error(
        "lifetime_invalid",
        "policy.lifetime.maxSeconds",
        "maxSeconds must not exceed 397 days",
      );
    }
    if (ca && maxSeconds > caMax) {
      out.error(
        "lifetime_exceeds_ca_policy",
        "policy.lifetime.maxSeconds",
        `maxSeconds exceeds the CA maximum (${caMax})`,
      );
    }
  }

  return {
    policy,
    dns,
    ip,
    uri,
    commonName: {
      mode: policy.names.commonName?.mode ?? "san",
      addToSans: policy.names.commonName?.addToSans ?? true,
    },
    maxSans,
    subjectAllow,
    forcedSans,
    keyAlgorithms,
    minSeconds,
  };
};

/**
 * Validate an untrusted grant policy body. `errors` block the write;
 * `warnings` are reported and allowed. The size check runs first on the
 * canonical JSON (reason `policy_too_large`).
 */
export const validateGrantPolicy = (
  input: unknown,
  context: GrantValidationContext = {},
): GrantValidationResult => {
  const out = new Collector();
  let bytes: number;
  try {
    bytes = Buffer.byteLength(stableJson(input) ?? "", "utf8");
  } catch {
    out.error("invalid_type", "policy", "policy is not serializable JSON");
    return { ok: false, errors: out.errors, warnings: out.warnings };
  }
  if (bytes > GRANT_POLICY_MAX_BYTES) {
    out.error(
      "policy_too_large",
      "policy",
      `canonical policy JSON is ${bytes} bytes; the limit is ${GRANT_POLICY_MAX_BYTES}`,
    );
    return { ok: false, errors: out.errors, warnings: out.warnings };
  }
  const policy = readStructure(input, out);
  if (!policy || out.errors.length > 0) {
    return { ok: false, errors: out.errors, warnings: out.warnings };
  }
  const compiled = compile(policy, context, out);
  return {
    ok: out.errors.length === 0,
    ...(out.errors.length === 0 ? { policy, compiled } : {}),
    errors: out.errors,
    warnings: out.warnings,
  };
};

/** Compile a stored (previously validated) policy. Throws if it no longer parses. */
export const compileGrantPolicy = (
  policy: GrantPolicy,
): CompiledGrantPolicy => {
  const out = new Collector();
  const compiled = compile(policy, {}, out);
  if (out.errors.length > 0) {
    throw new Error(
      `stored grant policy is invalid: ${out.errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
    );
  }
  return compiled;
};

export type { ExtendedKeyUsageName };
