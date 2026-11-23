import {
  formatDuration,
  isoToLocalInput,
  localInputToIso,
  parseDuration,
} from "./pki-format";
import {
  pkiGrantPolicyStrict,
  type PkiCaDetail,
  type PkiGrantInput,
  type PkiGrantPolicyStrict,
  type PkiIssuanceGrant,
  type PkiLeafKeyAlgorithm,
} from "./pki-schemas";

/**
 * The grant editor's form model. A `PUT` replaces the whole grant, so the
 * mapping between a stored policy and this draft must be lossless:
 * `draftToRequest(draftFromGrant(g))` equals the stored policy plus its
 * envelope. The draft therefore remembers the policy it was loaded from
 * (`origin`) so that an optional key the server stored, such as `deny: []`, is
 * written back instead of being dropped.
 */

export const SUBJECT_KEYS = [
  "country",
  "state",
  "locality",
  "organization",
  "organizationalUnit",
] as const;
export type SubjectKey = (typeof SUBJECT_KEYS)[number];

export type KeyUsage = PkiGrantPolicyStrict["keyUsages"][number];
export type Eku = NonNullable<PkiGrantPolicyStrict["extendedKeyUsages"]["allow"]>[number];

export const KEY_USAGES: readonly KeyUsage[] = ["digitalSignature", "keyEncipherment"];
export const EKUS: readonly Eku[] = ["serverAuth", "clientAuth"];

export interface GrantDraft {
  name: string;
  caId: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  /** `datetime-local` value. */
  expiresAt: string;
  dnsAllow: string;
  dnsDeny: string;
  allowWildcardNames: boolean;
  ipAllow: string;
  ipDeny: string;
  uriAllow: string;
  uriDeny: string;
  /** Empty means the field is absent. */
  cnMode: "" | "san" | "forbid";
  addToSans: boolean;
  maxSans: string;
  subjectAllow: Record<SubjectKey, string>;
  keyAlgorithms: PkiLeafKeyAlgorithm[];
  keyUsages: KeyUsage[];
  ekuAllow: Eku[];
  ekuDefault: Eku[];
  lifetimeDefault: string;
  lifetimeMax: string;
  lifetimeMin: string;
  forcedSubject: Record<SubjectKey, string>;
  forcedDns: string;
  forcedIp: string;
  forcedUri: string;
  forcedPolicies: string;
  quotaPerHour: string;
  quotaPerDay: string;
  /** The stored policy this draft came from; undefined for a new grant. */
  origin?: PkiGrantPolicyStrict;
  /** The stored `expiresAt`, kept verbatim while the input is unchanged. */
  originExpiresAt?: string;
}

const blankSubject = (): Record<SubjectKey, string> => ({
  country: "",
  state: "",
  locality: "",
  organization: "",
  organizationalUnit: "",
});

/** The strict parse that decides whether this form may edit a grant. */
export const editableGrant = (
  grant: Pick<PkiIssuanceGrant, "policy">,
): PkiGrantPolicyStrict | undefined => {
  const parsed = pkiGrantPolicyStrict.safeParse(grant.policy);
  return parsed.success ? parsed.data : undefined;
};

export const emptyDraft = (ca?: Pick<PkiCaDetail, "caId" | "policy">): GrantDraft => {
  const max = ca === undefined ? 7_776_000 : Math.min(7_776_000, ca.policy.maxLeafLifetimeSeconds);
  return {
    name: "",
    caId: ca?.caId ?? "",
    displayName: "",
    status: "ACTIVE",
    expiresAt: "",
    dnsAllow: "",
    dnsDeny: "",
    allowWildcardNames: false,
    ipAllow: "",
    ipDeny: "",
    uriAllow: "",
    uriDeny: "",
    cnMode: "",
    addToSans: false,
    maxSans: "",
    subjectAllow: blankSubject(),
    keyAlgorithms: [],
    keyUsages: ["digitalSignature"],
    ekuAllow: ["serverAuth"],
    ekuDefault: ["serverAuth"],
    lifetimeDefault: formatDuration(max),
    lifetimeMax: formatDuration(max),
    lifetimeMin: "1h",
    forcedSubject: blankSubject(),
    forcedDns: "",
    forcedIp: "",
    forcedUri: "",
    forcedPolicies: "",
    quotaPerHour: "",
    quotaPerDay: "",
  };
};

const joinLines = (values: readonly string[] | undefined): string =>
  values === undefined ? "" : values.join("\n");

export const splitLines = (text: string): string[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");

/**
 * Builds a draft from a stored grant. Call `editableGrant` first: this takes
 * the strictly parsed policy, never the loose record.
 */
export const draftFromGrant = (
  grant: Pick<
    PkiIssuanceGrant,
    "name" | "caId" | "displayName" | "status" | "expiresAt"
  >,
  policy: PkiGrantPolicyStrict,
): GrantDraft => {
  const names = policy.names;
  const subjectAllow = blankSubject();
  const forcedSubject = blankSubject();
  for (const key of SUBJECT_KEYS) {
    subjectAllow[key] = joinLines(policy.subject?.allow?.[key]);
    forcedSubject[key] = policy.forced?.subject?.[key] ?? "";
  }
  return {
    name: grant.name,
    caId: grant.caId,
    displayName: grant.displayName ?? "",
    status: grant.status === "DISABLED" ? "DISABLED" : "ACTIVE",
    expiresAt: isoToLocalInput(grant.expiresAt),
    dnsAllow: joinLines(names.dns?.allow),
    dnsDeny: joinLines(names.dns?.deny),
    allowWildcardNames: names.dns?.allowWildcardNames ?? false,
    ipAllow: joinLines(names.ip?.allow),
    ipDeny: joinLines(names.ip?.deny),
    uriAllow: joinLines(names.uri?.allow),
    uriDeny: joinLines(names.uri?.deny),
    cnMode: names.commonName?.mode ?? "",
    addToSans: names.commonName?.addToSans ?? false,
    maxSans: names.maxSans === undefined ? "" : String(names.maxSans),
    subjectAllow,
    keyAlgorithms: [...(policy.keyAlgorithms ?? [])],
    keyUsages: [...policy.keyUsages],
    ekuAllow: [...(policy.extendedKeyUsages.allow ?? [])],
    ekuDefault: [...(policy.extendedKeyUsages.default ?? [])],
    lifetimeDefault: formatDuration(policy.lifetime.defaultSeconds),
    lifetimeMax: formatDuration(policy.lifetime.maxSeconds),
    lifetimeMin:
      policy.lifetime.minSeconds === undefined
        ? ""
        : formatDuration(policy.lifetime.minSeconds),
    forcedSubject,
    forcedDns: joinLines(policy.forced?.sans?.dns),
    forcedIp: joinLines(policy.forced?.sans?.ip),
    forcedUri: joinLines(policy.forced?.sans?.uri),
    forcedPolicies: joinLines(policy.forced?.certificatePolicies),
    quotaPerHour:
      policy.quotas?.perHour === undefined ? "" : String(policy.quotas.perHour),
    quotaPerDay:
      policy.quotas?.perDay === undefined ? "" : String(policy.quotas.perDay),
    origin: policy,
    ...(grant.expiresAt === undefined ? {} : { originExpiresAt: grant.expiresAt }),
  };
};

/** Drops undefined keys; returns undefined for an object with none and no reason to keep it. */
const compact = <T extends Record<string, unknown>>(
  value: T,
  keep: boolean,
): T | undefined => {
  const entries = Object.entries(value).filter(([, v]) => v !== undefined);
  if (entries.length === 0 && !keep) {
    return undefined;
  }
  return Object.fromEntries(entries) as T;
};

/** A list is written when it has entries or the stored policy had the key. */
const list = (text: string, stored: unknown): string[] | undefined => {
  const lines = splitLines(text);
  return lines.length > 0 || stored !== undefined ? lines : undefined;
};

const enumList = <T extends string>(values: readonly T[], stored: unknown): T[] | undefined =>
  values.length > 0 || stored !== undefined ? [...values] : undefined;

const flag = (value: boolean, stored: boolean | undefined): boolean | undefined =>
  value || stored !== undefined ? value : undefined;

const seconds = (text: string): number | undefined => {
  if (text.trim() === "") {
    return undefined;
  }
  return parseDuration(text) ?? Number.NaN;
};

const integer = (text: string): number | undefined => {
  if (text.trim() === "") {
    return undefined;
  }
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : Number.NaN;
};

const policyFields = (draft: GrantDraft): Omit<PkiGrantInput, "caId"> => {
  const origin = draft.origin;
  const names = origin?.names;

  const rules = (
    allow: string,
    deny: string,
    stored: { allow?: unknown; deny?: unknown } | undefined,
    extra: Record<string, unknown> = {},
  ): Record<string, unknown> | undefined =>
    compact(
      {
        allow: list(allow, stored?.allow),
        deny: list(deny, stored?.deny),
        ...extra,
      },
      stored !== undefined,
    );

  const dns = rules(draft.dnsAllow, draft.dnsDeny, names?.dns, {
    allowWildcardNames: flag(draft.allowWildcardNames, names?.dns?.allowWildcardNames),
  });
  const ip = rules(draft.ipAllow, draft.ipDeny, names?.ip);
  const uri = rules(draft.uriAllow, draft.uriDeny, names?.uri);
  const commonName = compact(
    {
      mode: draft.cnMode === "" ? undefined : draft.cnMode,
      addToSans: flag(draft.addToSans, names?.commonName?.addToSans),
    },
    names?.commonName !== undefined,
  );

  const subjectAllow = Object.fromEntries(
    SUBJECT_KEYS.map((key) => [
      key,
      list(draft.subjectAllow[key], origin?.subject?.allow?.[key]),
    ]),
  );
  const subject = compact(
    { allow: compact(subjectAllow, origin?.subject?.allow !== undefined) },
    origin?.subject !== undefined,
  );

  const forcedSubject = compact(
    Object.fromEntries(
      SUBJECT_KEYS.map((key) => [
        key,
        draft.forcedSubject[key].trim() === "" ? undefined : draft.forcedSubject[key].trim(),
      ]),
    ),
    origin?.forced?.subject !== undefined,
  );
  const forcedSans = compact(
    {
      dns: list(draft.forcedDns, origin?.forced?.sans?.dns),
      ip: list(draft.forcedIp, origin?.forced?.sans?.ip),
      uri: list(draft.forcedUri, origin?.forced?.sans?.uri),
    },
    origin?.forced?.sans !== undefined,
  );
  const forced = compact(
    {
      subject: forcedSubject,
      sans: forcedSans,
      certificatePolicies: list(draft.forcedPolicies, origin?.forced?.certificatePolicies),
    },
    origin?.forced !== undefined,
  );

  const quotas = compact(
    { perHour: integer(draft.quotaPerHour), perDay: integer(draft.quotaPerDay) },
    origin?.quotas !== undefined,
  );

  return {
    names: {
      ...(dns === undefined ? {} : { dns }),
      ...(ip === undefined ? {} : { ip }),
      ...(uri === undefined ? {} : { uri }),
      ...(commonName === undefined ? {} : { commonName }),
      ...(integer(draft.maxSans) === undefined ? {} : { maxSans: integer(draft.maxSans)! }),
    },
    ...(subject === undefined ? {} : { subject }),
    ...(enumList(draft.keyAlgorithms, origin?.keyAlgorithms) === undefined
      ? {}
      : { keyAlgorithms: enumList(draft.keyAlgorithms, origin?.keyAlgorithms)! }),
    keyUsages: [...draft.keyUsages],
    extendedKeyUsages: compact(
      {
        allow: enumList(draft.ekuAllow, origin?.extendedKeyUsages.allow),
        default: enumList(draft.ekuDefault, origin?.extendedKeyUsages.default),
      },
      true,
    )!,
    lifetime: compact(
      {
        defaultSeconds: seconds(draft.lifetimeDefault),
        maxSeconds: seconds(draft.lifetimeMax),
        minSeconds: seconds(draft.lifetimeMin),
      },
      true,
    ) as PkiGrantPolicyStrict["lifetime"],
    ...(forced === undefined ? {} : { forced }),
    ...(quotas === undefined ? {} : { quotas }),
  } as Omit<PkiGrantInput, "caId">;
};

/** The request body for a `PUT` or `?validateOnly` update. */
export const draftToRequest = (draft: GrantDraft): PkiGrantInput => {
  const displayName = draft.displayName.trim();
  // Keep the stored instant verbatim while the input still shows it.
  const expiresAt =
    draft.originExpiresAt !== undefined &&
    draft.expiresAt === isoToLocalInput(draft.originExpiresAt)
      ? draft.originExpiresAt
      : localInputToIso(draft.expiresAt);
  return {
    caId: draft.caId,
    // An omitted displayName clears it on PUT, which is what emptying means.
    ...(displayName === "" ? {} : { displayName }),
    status: draft.status,
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...policyFields(draft),
  };
};

export const draftToCreateRequest = (draft: GrantDraft): PkiGrantInput & { name: string } => ({
  name: draft.name.trim(),
  ...draftToRequest(draft),
});

/** Local problems that stop a submit before the server sees it. */
export const draftProblems = (draft: GrantDraft): string[] => {
  const problems: string[] = [];
  const duration = (label: string, text: string, required: boolean): void => {
    if (text.trim() === "") {
      if (required) {
        problems.push(`${label} is required.`);
      }
    } else if (parseDuration(text) === undefined) {
      problems.push(`${label} must look like 3600s, 90m, 24h or 90d.`);
    }
  };
  duration("Default lifetime", draft.lifetimeDefault, true);
  duration("Maximum lifetime", draft.lifetimeMax, true);
  duration("Minimum lifetime", draft.lifetimeMin, false);
  for (const [label, text] of [
    ["Maximum SANs", draft.maxSans],
    ["Quota per hour", draft.quotaPerHour],
    ["Quota per day", draft.quotaPerDay],
  ] as const) {
    if (text.trim() !== "" && integer(text) === undefined) {
      problems.push(`${label} must be a whole number.`);
    }
    if (text.trim() !== "" && Number.isNaN(integer(text))) {
      problems.push(`${label} must be a whole number.`);
    }
  }
  if (draft.expiresAt.trim() !== "" && localInputToIso(draft.expiresAt) === undefined) {
    problems.push("Expiry is not a valid date.");
  }
  if (draft.caId === "") {
    problems.push("Choose a CA.");
  }
  if (draft.keyUsages.length === 0) {
    problems.push("Select at least one key usage.");
  }
  return [...new Set(problems)];
};

/** Deterministic JSON (sorted keys), for comparing drafts and requests. */
export const stableJson = (value: unknown): string =>
  JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : v,
  );

/** The draft without its remembered origin, for dirty checks. */
export const draftSnapshot = (draft: GrantDraft): string => {
  const { origin: _origin, originExpiresAt: _origin2, ...rest } = draft;
  void _origin;
  void _origin2;
  return stableJson(rest);
};

export interface FieldIssue {
  /** A `GrantDraft` key, or `Key.sub` for the record fields. */
  readonly field: string;
  /** Zero-based line within a rule list, when the path indexes one. */
  readonly line?: number;
}

const FIELD_BY_PATH: readonly (readonly [RegExp, string])[] = [
  [/^names\.dns\.allow/, "dnsAllow"],
  [/^names\.dns\.deny/, "dnsDeny"],
  [/^names\.dns\.allowWildcardNames/, "allowWildcardNames"],
  [/^names\.ip\.allow/, "ipAllow"],
  [/^names\.ip\.deny/, "ipDeny"],
  [/^names\.uri\.allow/, "uriAllow"],
  [/^names\.uri\.deny/, "uriDeny"],
  [/^names\.commonName\.mode/, "cnMode"],
  [/^names\.commonName\.addToSans/, "addToSans"],
  [/^names\.maxSans/, "maxSans"],
  [/^subject\.allow\.(\w+)/, "subjectAllow."],
  [/^keyAlgorithms/, "keyAlgorithms"],
  [/^keyUsages/, "keyUsages"],
  [/^extendedKeyUsages\.allow/, "ekuAllow"],
  [/^extendedKeyUsages\.default/, "ekuDefault"],
  [/^lifetime\.defaultSeconds/, "lifetimeDefault"],
  [/^lifetime\.maxSeconds/, "lifetimeMax"],
  [/^lifetime\.minSeconds/, "lifetimeMin"],
  [/^forced\.subject\.(\w+)/, "forcedSubject."],
  [/^forced\.sans\.dns/, "forcedDns"],
  [/^forced\.sans\.ip/, "forcedIp"],
  [/^forced\.sans\.uri/, "forcedUri"],
  [/^forced\.certificatePolicies/, "forcedPolicies"],
  [/^quotas\.perHour/, "quotaPerHour"],
  [/^quotas\.perDay/, "quotaPerDay"],
];

/**
 * Maps a validation issue path such as `policy.names.dns.allow[1]` to the
 * form field and zero-based line it points at. Anything unrecognised is
 * `general`, so it is still shown rather than swallowed.
 */
export const issuePathToField = (path: string): FieldIssue => {
  const trimmed = path.replace(/^policy\./, "");
  const indexMatch = /\[(\d+)\]/.exec(trimmed);
  const line = indexMatch === null ? undefined : Number(indexMatch[1]);
  const withLine = (field: string): FieldIssue =>
    line === undefined ? { field } : { field, line };
  if (trimmed === "caId" || trimmed === "name" || trimmed === "displayName") {
    return { field: trimmed };
  }
  if (trimmed === "status" || trimmed === "expiresAt") {
    return { field: trimmed };
  }
  for (const [pattern, field] of FIELD_BY_PATH) {
    const match = pattern.exec(trimmed);
    if (match !== null) {
      return withLine(field.endsWith(".") ? `${field}${match[1]}` : field);
    }
  }
  return { field: "general" };
};
