import { displaySafe } from "./ez-x509";
import { renderHuman, shellQuote, type HumanResult, type Style } from "./output";

/**
 * Human results for every command except `pki ez` (which has its own in ez-output.ts). A command is described by a
 * small spec (which object to show, its facts, or the columns of its list) and rendered by one engine, so a command
 * without a spec still prints indented key/value text, never raw JSON. Every server-provided string goes through
 * `displaySafe`; `renderHuman` strips whatever is left. Secret payloads are never part of any result here.
 */

type Data = Record<string, any>;

/** What a command wrote: the JSON envelope's fields. */
export interface Envelope {
  readonly data: unknown;
  readonly etag?: string;
  readonly idempotencyKey?: string;
  readonly ifMatch?: string;
  readonly [other: string]: unknown;
}

export interface ResultContext {
  readonly now: Date;
}

const isRecord = (value: unknown): value is Data => typeof value === "object" && value !== null && !Array.isArray(value);
const safe = (value: unknown): string => displaySafe(String(value));
const plural = (n: number, word: string, many = `${word}s`): string => `${n} ${n === 1 ? word : many}`;

const pick = (root: unknown, path: string): unknown => {
  let at: unknown = root;
  for (const key of path.split(".")) {
    if (!isRecord(at)) return undefined;
    at = at[key];
  }
  return at;
};

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/** `2026-11-27 12:00 UTC` for an ISO timestamp; anything else is shown as given (escaped). */
export const whenText = (value: string): string => {
  const ms = ISO_TIME.test(value) ? Date.parse(value) : Number.NaN;
  return Number.isNaN(ms) ? safe(value) : `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
};

const dayText = (value: unknown): string | undefined => (typeof value === "string" ? whenText(value).slice(0, 10) : undefined);

/** How far `ms` is from now, in the largest sensible unit. */
export const relativeText = (ms: number): string => {
  const abs = Math.abs(ms);
  const unit =
    abs < 60_000 ? "less than a minute" : abs < 3_600_000 ? plural(Math.round(abs / 60_000), "minute") : abs < 172_800_000 ? plural(Math.round(abs / 3_600_000), "hour") : plural(Math.round(abs / 86_400_000), "day");
  return ms >= 0 ? `in ${unit}` : `${unit} ago`;
};

const pemSummary = (text: string): string => `PEM, ${plural(text.trim().split("\n").length, "line")} (not shown; --json prints it)`;

const scalar = (value: unknown): string | undefined => {
  if (typeof value === "string") return value.includes("-----BEGIN ") ? pemSummary(value) : ISO_TIME.test(value) ? whenText(value) : safe(value);
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  return undefined;
};

/** A value as one short line; undefined means "leave this fact out". Nested objects and arrays are summarized. */
export const formatValue = (value: unknown, depth = 0): string | undefined => {
  if (value === null || value === undefined) return undefined;
  const flat = scalar(value);
  if (flat !== undefined) return flat;
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    if (value.every((v) => scalar(v) !== undefined)) {
      const shown = value.slice(0, 6).map((v) => scalar(v) as string);
      return `${shown.join(", ")}${value.length > 6 ? ` (+${value.length - 6} more)` : ""}`;
    }
    return plural(value.length, "entry", "entries");
  }
  if (isRecord(value)) {
    const entries = Object.entries(value).filter(([key]) => key !== "payload");
    if (entries.length === 0) return "none";
    const parts = entries.map(([key, v]) => [key, depth < 1 ? formatValue(v, depth + 1) : scalar(v)] as const).filter(([, v]) => v !== undefined);
    const text = parts.slice(0, 5).map(([key, v]) => `${safe(key)}: ${v}`).join(", ");
    return `${text}${parts.length > 5 ? `, +${parts.length - 5} more` : ""}`;
  }
  return undefined;
};

type Picker = string | ((root: Data, envelope: Envelope) => unknown);
type FactDef = readonly [label: string, from: Picker];
type ColumnDef = readonly [header: string, from: Picker];

const value = (from: Picker, root: Data, envelope: Envelope): unknown => (typeof from === "string" ? pick(root, from) : from(root, envelope));

const factsOf = (root: Data, defs: readonly FactDef[], envelope: Envelope): [string, string][] =>
  defs.flatMap(([label, from]): [string, string][] => {
    const text = formatValue(value(from, root, envelope));
    return text === undefined ? [] : [[label, text]];
  });

interface Spec {
  /** Path of the object to show inside `data` (`ca` for a revoke receipt). */
  readonly root?: string;
  /** Mutations: `✓ headline`. Gets: a plain title. */
  readonly headline?: (root: Data, envelope: Envelope) => string;
  readonly mutation?: boolean;
  readonly facts?: readonly FactDef[];
  readonly list?: {
    readonly items: string;
    readonly noun: string;
    readonly columns: readonly ColumnDef[];
    readonly context?: (data: Data) => string;
  };
  readonly next?: (root: Data, envelope: Envelope) => string[];
  readonly custom?: (envelope: Envelope, context: ResultContext) => HumanResult;
}

// ---------------------------------------------------------------------------------------------------------------------
// Value pickers
// ---------------------------------------------------------------------------------------------------------------------

const tags = (root: Data): unknown => {
  const t = pick(root, "metadata.tags");
  return isRecord(t) && Object.keys(t).length > 0 ? t : undefined;
};
const access = (root: Data): unknown => {
  const acl = root.acl;
  if (!Array.isArray(acl)) return undefined;
  const ids = acl.map((g) => (isRecord(g) ? g.consumerId : undefined)).filter((id): id is string => typeof id === "string");
  return ids.length === 0 ? "no consumers" : `${plural(ids.length, "consumer")}: ${ids.slice(0, 5).map(safe).join(", ")}${ids.length > 5 ? ` (+${ids.length - 5} more)` : ""}`;
};
const range = (from: string, to: string) => (root: Data): unknown => {
  const a = dayText(root[from]);
  const b = dayText(root[to]);
  return a === undefined && b === undefined ? undefined : `${a ?? "?"} to ${b ?? "?"}`;
};
const shortHex = (text: unknown): string | undefined => (typeof text === "string" ? (text.length > 20 ? `${text.slice(0, 16)}...` : text) : undefined);
const sans = (root: Data): unknown => {
  const s = root.sans;
  if (!isRecord(s)) return undefined;
  const parts = Object.entries(s)
    .filter(([, names]) => Array.isArray(names) && names.length > 0)
    .map(([type, names]) => `${safe(type)} ${(names as string[]).map(safe).join(", ")}`);
  return parts.length === 0 ? undefined : parts.join("; ");
};
const crlText = (crl: unknown): unknown => {
  if (!isRecord(crl)) return undefined;
  const number = crl.number ?? crl.numberHex;
  return [number === undefined ? undefined : `#${safe(number)}`, typeof crl.state === "string" ? crl.state.toLowerCase() : undefined, dayText(crl.nextUpdate) === undefined ? undefined : `next update ${dayText(crl.nextUpdate)}`]
    .filter((p) => p !== undefined)
    .join(", ");
};
const warningTexts = (root: Data): string[] =>
  Array.isArray(root.warnings)
    ? root.warnings.flatMap((w): string[] => (isRecord(w) ? [safe(w.message ?? [w.code, w.path].filter((p) => p !== undefined).join(" "))] : typeof w === "string" ? [safe(w)] : []))
    : [];

// ---------------------------------------------------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------------------------------------------------

const SECRET_FACTS: readonly FactDef[] = [
  ["Secret ID", "secretId"],
  ["Environment", "environment"],
  ["State", "state"],
  ["Description", "metadata.description"],
  ["Path", "metadata.path"],
  ["Tags", tags],
  ["Access", access],
  ["Managed by agents", "agentManagedConsumerIds"],
  ["Payload keys", "payloadKeyCount"],
  ["Version", "controlVersionId"],
  ["Payload version", "payloadVersionId"],
  ["UID", "secretUid"],
];
const secretMutation = (headline: (root: Data) => string): Spec => ({
  mutation: true,
  headline,
  facts: SECRET_FACTS,
  next: (root) =>
    root.state === "PENDING_VALUE" ? [`Write the value: hemlig secret write-payload --environment ${safe(root.environment)} --secret-id ${safe(root.secretId)} --if-match current --input <file|->`] : [],
});

const CONSUMER_FACTS: readonly FactDef[] = [
  ["Consumer ID", "consumerId"],
  ["Environment", "environment"],
  ["Status", "status"],
  ["Subject URI", "subjectUri"],
  ["Active identities", "activeApiIdentityCount"],
  ["Root fingerprint", "rootFingerprint"],
  ["Created", "createdAt"],
  ["Created by", "createdBy"],
];

const CA_FACTS: readonly FactDef[] = [
  ["Name", "name"],
  ["Display name", "displayName"],
  ["CA ID", "caId"],
  ["Environment", "environment"],
  ["Kind", "kind"],
  ["Status", "status"],
  ["Key", (r) => (typeof r.keyAlgorithm === "string" ? `${r.keyAlgorithm}, ${String(r.keyState ?? "").toLowerCase()}` : undefined)],
  ["Subject", "subjectDn"],
  ["Serial", "serial"],
  ["Fingerprint", "fingerprint"],
  ["Valid", range("notBefore", "notAfter")],
  ["Parent", (r) => (isRecord(r.parent) ? `${safe(r.parent.type)} ${safe(r.parent.id)}` : undefined)],
  ["CRL", (r) => crlText(r.crl)],
  ["Root CRL", (r) => crlText(r.rootCrl)],
  ["Capacity", (r) => (isRecord(r.capacity) ? `${r.capacity.count ?? "?"} of ${r.capacity.capacity} certificates` : undefined)],
  ["CSR", "csrPem"],
  ["CSR file", "csrOut"],
  ["Version", "version"],
  ["Created", "createdAt"],
];
const caMutation = (verb: string): Spec => ({
  mutation: true,
  headline: (r) => `${verb}: ${safe(r.name ?? r.caId)}`,
  facts: CA_FACTS,
  next: (r) =>
    r.status === "PENDING_CERTIFICATE" && typeof r.caId === "string" && r.csrPem !== undefined
      ? [`Have the CSR signed by your root, then activate: hemlig pki ca activate ${safe(r.caId)} --certificate FILE --chain FILE`]
      : [],
});

const GRANT_FACTS: readonly FactDef[] = [
  ["Consumer", "consumerId"],
  ["Name", "name"],
  ["Display name", "displayName"],
  ["Environment", "environment"],
  ["CA ID", "caId"],
  ["Status", (r) => (r.expired === true ? `${String(r.status)} (expired)` : r.status)],
  ["Expires", "expiresAt"],
  ["Quotas", (r) => (isRecord(r.quotas) ? `${r.quotas.perHour} per hour, ${r.quotas.perDay} per day` : undefined)],
  ["Policy", "policy"],
  ["Version", "version"],
  ["Created", "createdAt"],
  ["Updated", "updatedAt"],
  ["UID", "uid"],
];
const grantMutation = (verb: string): Spec => ({
  mutation: true,
  headline: (r) => `${verb}: ${safe(r.consumerId)}/${safe(r.name)}`,
  facts: GRANT_FACTS,
});

const CERT_FACTS: readonly FactDef[] = [
  ["CA ID", "caId"],
  ["Serial", "serial"],
  ["Subject", "subject"],
  ["Status", "status"],
  ["Names", sans],
  ["Fingerprint", "fingerprint"],
  ["Key", "keyAlgorithm"],
  ["Valid", range("notBefore", "notAfter")],
  ["Issued", "issuedAt"],
  ["Grant", "issuanceGrant"],
  ["Lifetime clamped", (r) => (r.lifetimeClamped === true ? true : undefined)],
  ["Revocation", "revocation"],
  ["Certificate file", "out"],
  ["Chain file", "chainOut"],
  ["CA file", "caOut"],
];

const specs: Record<string, Spec> = {
  "secret read": { headline: (r) => `Secret ${safe(r.secretId)}`, facts: SECRET_FACTS },
  "secret create": secretMutation((r) => `Secret created: ${safe(r.secretId)}`),
  "secret update": secretMutation((r) => `Secret updated: ${safe(r.secretId)}`),
  "secret write-payload": secretMutation((r) => `Payload written: ${safe(r.secretId)}${r.payloadKeyCount === undefined ? "" : ` (${plural(Number(r.payloadKeyCount), "key")})`}`),
  "secret archive": secretMutation((r) => `Secret archived: ${safe(r.secretId)}`),

  "consumer list": {
    list: {
      items: "consumers",
      noun: "consumer",
      columns: [["CONSUMER ID", "consumerId"], ["STATUS", "status"], ["ENVIRONMENT", "environment"], ["CREATED", (r) => dayText(r.createdAt)]],
    },
  },
  "consumer get": { headline: (r) => `Consumer ${safe(r.consumerId)}`, facts: CONSUMER_FACTS },
  "consumer identities": {
    list: {
      items: "apiIdentities",
      noun: "API identity",
      columns: [["FINGERPRINT", (r) => shortHex(r.apiFingerprint)], ["KIND", "kind"], ["STATUS", "status"], ["VALID UNTIL", (r) => dayText(r.notAfter)]],
      context: (d) => ` of consumer ${safe(d.consumerId)}`,
    },
  },
  "consumer revoke-identity": {
    mutation: true,
    headline: (r) => `API identity revoked: ${safe(shortHex(r.apiFingerprint))}`,
    facts: [["Consumer ID", "consumerId"], ["Environment", "environment"], ["Fingerprint", "apiFingerprint"], ["Status", "status"], ["Root fingerprint", "rootFingerprint"]],
  },

  "pki ca list": {
    list: {
      items: "cas",
      noun: "CA",
      columns: [["NAME", "name"], ["CA ID", "caId"], ["KIND", "kind"], ["STATUS", "status"], ["KEY", "keyAlgorithm"], ["EXPIRES", (r) => dayText(r.notAfter)]],
    },
  },
  "pki ca get": { headline: (r) => `CA ${safe(r.name ?? r.caId)}`, facts: CA_FACTS },
  "pki ca create": caMutation("CA created"),
  "pki ca activate": caMutation("CA activated"),
  "pki ca update": caMutation("CA updated"),
  "pki ca retire": caMutation("CA retired"),
  "pki ca destroy-key": caMutation("CA key destroyed"),
  "pki ca delete": caMutation("CA deleted"),
  "pki ca revoke": {
    root: "ca",
    mutation: true,
    headline: (r, e) => (pick(e.data, "changed") === false ? `CA was already revoked: ${safe(r.name ?? r.caId)}` : `CA revoked: ${safe(r.name ?? r.caId)}`),
    facts: [
      ...CA_FACTS,
      ["CRL entry", (_r, e) => pick(e.data, "crlEntry")],
      ["CRL published", (_r, e) => pick(e.data, "crlPublished")],
      ["CRL number", (_r, e) => pick(e.data, "crlNumber")],
      ["Revoked CAs", (_r, e) => pick(e.data, "revokedCaIds")],
      ["Complete", (_r, e) => pick(e.data, "complete")],
    ],
    next: (_r, e) =>
      pick(e.data, "complete") === false && typeof e.idempotencyKey === "string"
        ? [`Not every child CA is revoked yet: run the same command again with --idempotency-key ${safe(e.idempotencyKey)}`]
        : [],
  },
  "pki ca crl publish": {
    mutation: true,
    headline: (r) => `CRL published for ${safe(r.caId)}`,
    facts: [["CA ID", "caId"], ["CRL", (r) => crlText(r.crl)], ["This update", "crl.thisUpdate"], ["Entries", "crl.entryCount"], ["Pending revocations", "crl.pendingRevocations"]],
  },
  "pki ca crl get": {
    headline: (r) => (r.notModified === true ? `CRL not modified: ${safe(r.id)}` : `CRL saved: ${safe(r.path)}`),
    mutation: true,
    facts: [["Issuer", "id"], ["File", "path"], ["Size", (r) => (typeof r.bytes === "number" ? `${r.bytes} bytes` : undefined)], ["SHA-256", "sha256"], ["ETag", "etag"]],
  },

  "pki external-ca list": {
    list: {
      items: "externalCas",
      noun: "external CA",
      columns: [["EXT ID", "extId"], ["SUBJECT", "subjectDn"], ["EXPIRES", (r) => dayText(r.notAfter)], ["CRL", "crlState"]],
    },
  },
  "pki external-ca get": {
    headline: (r) => `External CA ${safe(r.extId)}`,
    facts: [
      ["Ext ID", "extId"], ["Subject", "subjectDn"], ["Fingerprint", "fingerprint"], ["Expires", "notAfter"], ["CRL state", "crlState"],
      ["CRL", (r) => (isRecord(r.crl) ? `#${safe(r.crl.numberHex)}, next update ${dayText(r.crl.nextUpdate) ?? "?"}` : undefined)],
      ["Environments", "environments"], ["Dependents", "dependents"], ["Version", "version"], ["Created", "createdAt"],
    ],
  },
  "pki external-ca upload-crl": {
    mutation: true,
    headline: (r) => (r.changed === false ? `CRL already current for ${safe(r.extId)}` : `CRL uploaded for ${safe(r.extId)}`),
    facts: [["Ext ID", "extId"], ["CRL", (r) => (isRecord(r.crl) ? `#${safe(r.crl.numberHex)}, next update ${dayText(r.crl.nextUpdate) ?? "?"}` : undefined)], ["Revoked CAs", "revokedCaIds"]],
  },

  "pki grant list": {
    list: {
      items: "grants",
      noun: "issuance grant",
      columns: [["CONSUMER", "consumerId"], ["NAME", "name"], ["CA ID", "caId"], ["STATUS", (r) => (r.expired === true ? `${String(r.status)} (expired)` : r.status)], ["EXPIRES", (r) => dayText(r.expiresAt)]],
    },
  },
  "pki grant get": { headline: (r) => `Issuance grant ${safe(r.consumerId)}/${safe(r.name)}`, facts: GRANT_FACTS },
  "pki grant create": grantMutation("Issuance grant created"),
  "pki grant update": grantMutation("Issuance grant updated"),
  "pki grant delete": grantMutation("Issuance grant deleted"),

  "pki cert list": {
    list: {
      items: "certificates",
      noun: "certificate",
      columns: [["SERIAL", "serial"], ["SUBJECT", "subject"], ["STATUS", "status"], ["EXPIRES", (r) => dayText(r.notAfter)], ["CA ID", "caId"]],
    },
  },
  "pki cert get": { headline: (r) => `Certificate ${safe(r.serial)}`, facts: CERT_FACTS },
  "pki cert issue": {
    mutation: true,
    headline: (r) => `Certificate issued: serial ${safe(r.serial)}`,
    facts: CERT_FACTS,
  },
  "pki cert revoke": {
    root: "certificate",
    mutation: true,
    headline: (r, e) => (pick(e.data, "changed") === false ? `Certificate was already revoked: serial ${safe(r.serial)}` : `Certificate revoked: serial ${safe(r.serial)}`),
    facts: [
      ...CERT_FACTS,
      ["CRL entry", (_r, e) => pick(e.data, "crlEntry")],
      ["CRL published", (_r, e) => pick(e.data, "crlPublished")],
      ["CRL number", (_r, e) => pick(e.data, "crlNumber")],
    ],
  },
  "pki consumer revoke-certificates": {
    mutation: true,
    headline: (r) => `Revoked ${plural(Number(r.revoked ?? 0), "certificate")} of consumer ${safe(r.consumerId)}`,
    facts: [["Consumer ID", "consumerId"], ["Grant", "issuanceGrant"], ["Revoked", "revoked"], ["Already revoked", "alreadyRevoked"], ["CAs", "caIds"], ["Complete", "complete"], ["Requests", "attempts"]],
  },
  "pki grant evaluate": { custom: (e) => evaluateResult(e) },
  "pki grant migrate": { custom: (e) => migrateResult(e) },
};

// ---------------------------------------------------------------------------------------------------------------------
// Custom results
// ---------------------------------------------------------------------------------------------------------------------

const evaluateResult = (envelope: Envelope): HumanResult => {
  const data = (envelope.data ?? {}) as Data;
  const allowed = data.decision === "allow";
  const denial = isRecord(data.denial) ? data.denial : undefined;
  return {
    headline: allowed ? "Allowed: the grant would issue this request" : `Denied: ${safe(denial?.reason ?? "the grant would refuse this request")}`,
    mark: allowed ? "ok" : "warn",
    facts: [
      ...(denial?.detail === undefined ? [] : ([["Detail", safe(denial.detail)]] as [string, string][])),
      ...(denial?.deniedName === undefined ? [] : ([["Denied name", `${safe(denial.deniedNameType ?? "name")} ${safe(denial.deniedName)}`]] as [string, string][])),
    ],
    table: Array.isArray(data.trace)
      ? { head: ["STEP", "CHECK", "OUTCOME"], rows: data.trace.filter(isRecord).map((t) => [safe(t.step), safe(t.name), safe(t.outcome)]) }
      : undefined,
  };
};

const migrateResult = (envelope: Envelope): HumanResult => {
  const data = (envelope.data ?? {}) as Data;
  const results = Array.isArray(data.results) ? data.results.filter(isRecord) : [];
  const count = (...outcomes: string[]): number => results.filter((r) => outcomes.includes(String(r.outcome))).length;
  const bad = count("invalid", "failed");
  const dry = data.dryRun === true;
  const moved = count(dry ? "valid" : "migrated");
  const detail = (r: Data): string => typeof r.reason === "string" ? safe(r.reason) : (Array.isArray(r.errors) && isRecord(r.errors[0]) ? safe(r.errors[0].message ?? r.errors[0].code ?? "") : "");
  return {
    headline: `${dry ? "Dry run: " : ""}${plural(moved, "grant")} ${dry ? "would move" : "moved"} from ${safe(data.from)} to ${safe(data.to)}`,
    mark: bad > 0 ? "warn" : "ok",
    facts: [["Not migrated", String(bad)], ["Skipped", String(count("skipped"))], ["Left on the old CA", String(data.remainingListed ?? 0)]],
    table:
      results.length === 0
        ? undefined
        : { head: ["CONSUMER", "NAME", "OUTCOME", "DETAIL"], rows: results.map((r) => [safe(r.consumerId ?? ""), safe(r.name ?? ""), safe(r.outcome ?? ""), detail(r)]) },
    warnings: data.listedTruncated === true || data.remainingTruncated === true ? ["The listing was truncated; run the command again to continue."] : [],
  };
};

/** `grant create|update --validate-only`: nothing was written. */
const validationResult = (data: Data): HumanResult => {
  const issues = (list: unknown): string[][] =>
    Array.isArray(list) ? list.filter(isRecord).map((i) => [safe(i.code ?? ""), safe(i.path ?? ""), safe(i.message ?? "")]) : [];
  const errors = issues(data.errors);
  const warnings = issues(data.warnings);
  return {
    headline: data.valid ? "Grant is valid (validate-only: nothing was written)" : `Grant is invalid: ${plural(errors.length, "error")} (nothing was written)`,
    mark: data.valid ? "ok" : "warn",
    table: errors.length === 0 ? undefined : { head: ["CODE", "PATH", "MESSAGE"], rows: errors },
    warnings: warnings.map((w) => w.filter((p) => p !== "").join(" ")),
    facts: data.policyDigest === undefined ? [] : [["Policy digest", safe(data.policyDigest)]],
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------------------------------------------------

const PREFERRED = ["name", "id", "caId", "consumerId", "serial", "status", "kind", "environment", "state", "notAfter", "expiresAt", "createdAt"];

/** Columns for a list nobody described: the first few scalar fields, preferring names, IDs and status. */
const autoTable = (items: readonly Data[]): { head: string[]; rows: string[][] } => {
  const first = items[0] ?? {};
  const keys = Object.keys(first).filter((k) => scalar(first[k]) !== undefined);
  const ranked = [...keys].sort((a, b) => (PREFERRED.indexOf(a) < 0 ? 99 : PREFERRED.indexOf(a)) - (PREFERRED.indexOf(b) < 0 ? 99 : PREFERRED.indexOf(b)));
  const chosen = ranked.slice(0, 5);
  return { head: chosen.map((k) => safe(k).toUpperCase()), rows: items.map((item) => chosen.map((k) => formatValue(item[k]) ?? "")) };
};

const upperFirst = (text: string): string => text.charAt(0).toUpperCase() + text.slice(1);

/** Key/value lines for data without a spec; nested objects are indented one level. The secret payload is never shown. */
const flatten = (data: Data, prefix = "", depth = 0): [string, string][] => {
  const out: [string, string][] = [];
  for (const [key, entry] of Object.entries(data)) {
    const label = prefix === "" ? safe(key) : `${prefix}.${safe(key)}`;
    if (key === "payload") {
      out.push([label, "(hidden)"]);
    } else if (isRecord(entry) && depth < 1 && Object.keys(entry).length > 0) {
      out.push(...flatten(entry, label, depth + 1));
    } else {
      const text = formatValue(entry);
      if (text !== undefined) out.push([label, text]);
    }
  }
  return out;
};

const arrayProperty = (data: Data): string | undefined => {
  const names = Object.keys(data).filter((k) => Array.isArray(data[k]) && (data[k] as unknown[]).length > 0 && (data[k] as unknown[]).every(isRecord));
  return names.length === 1 ? names[0] : undefined;
};

const pageNote = (data: Data): string[] =>
  typeof data.nextCursor === "string" && data.nextCursor !== "" ? [`More results: pass --cursor ${shellQuote(data.nextCursor)} for the next page.`] : [];

const listResult = (data: Data, list: NonNullable<Spec["list"]>, envelope: Envelope): HumanResult => {
  const items = Array.isArray(data[list.items]) ? (data[list.items] as unknown[]).filter(isRecord) : [];
  const more = pageNote(data);
  if (items.length === 0) return { headline: `No ${list.noun}s found${list.context?.(data) ?? ""}`, mark: "none", notes: more };
  return {
    headline: `${plural(items.length, list.noun)}${list.context?.(data) ?? ""}${more.length > 0 ? " on this page" : ""}`,
    mark: "none",
    table: { head: list.columns.map(([h]) => h), rows: items.map((item) => list.columns.map(([, from]) => formatValue(value(from, item, envelope)) ?? "")) },
    notes: more,
  };
};

/** The human result for a command's envelope. */
export const humanResult = (command: string, envelope: Envelope, context: ResultContext): HumanResult => {
  const spec = specs[command];
  if (spec?.custom !== undefined) return spec.custom(envelope, context);
  const data: unknown = envelope.data;
  if (command.startsWith("pki grant ") && isRecord(data) && typeof data.valid === "boolean" && Array.isArray(data.errors)) return validationResult(data);
  if (!isRecord(data)) return { headline: `Done: ${safe(command)}`, mark: "ok", facts: data === undefined ? [] : [["Result", formatValue(data) ?? ""]] };
  if (spec?.list !== undefined) return listResult(data, spec.list, envelope);
  const root = spec?.root === undefined ? data : (pick(data, spec.root) as Data | undefined);
  if (!isRecord(root)) return { headline: `Done: ${safe(command)}`, facts: flatten(data) };
  if (spec === undefined) {
    // No renderer for this command: a list if the data holds exactly one array of records, else indented key/value text.
    const items = arrayProperty(data);
    if (items !== undefined) {
      const table = autoTable(data[items] as Data[]);
      return { headline: plural((data[items] as unknown[]).length, items.replace(/s$/, "")), mark: "none", table, notes: pageNote(data) };
    }
    return { headline: upperFirst(safe(command)), mark: "none", facts: flatten(data) };
  }
  const facts = factsOf(root, spec.facts ?? [], envelope);
  if (spec.mutation === true && typeof envelope.idempotencyKey === "string") facts.push(["Idempotency key", safe(envelope.idempotencyKey)]);
  const hasPem = Object.entries(root).some(([key, v]) => key.endsWith("Pem") && typeof v === "string");
  return {
    headline: spec.headline?.(root, envelope) ?? upperFirst(safe(command)),
    mark: spec.mutation === true ? "ok" : "none",
    facts,
    notes: hasPem ? ["PEM text is not shown on a terminal: save it with an --out option, or add --json to print it."] : [],
    warnings: warningTexts(root),
    next: spec.next?.(root, envelope) ?? [],
  };
};

export const renderResult = (command: string, envelope: Envelope, context: ResultContext, style: Style): string => renderHuman(humanResult(command, envelope, context), style);

// ---------------------------------------------------------------------------------------------------------------------
// login and logout
// ---------------------------------------------------------------------------------------------------------------------

export const loginResult = (adminUrl: string, expiresAt: string, now: Date): HumanResult => {
  const left = Date.parse(expiresAt) - now.getTime();
  return {
    headline: `Logged in to ${safe(adminUrl)}`,
    facts: [["Expires", `${whenText(expiresAt)}${Number.isNaN(left) ? "" : ` (${relativeText(left)})`}`]],
  };
};

export const logoutResult = (): HumanResult => ({ headline: "Logged out", facts: [["Cached login", "removed"]] });
