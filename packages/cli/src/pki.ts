import { createHash, randomUUID } from "node:crypto";
import {
  open,
  readFile,
  rename,
  unlink,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  HemligClient,
  HemligError,
  type BinaryResult,
  type PkiCaDetail,
  type PkiCaKind,
  type PkiCaPolicyInput,
  type PkiCaRevocationReason,
  type PkiRevokeCaRequest,
  type PkiCaSubject,
  type PkiAdminIssueCertificateRequest,
  type PkiCertificateStatus,
  type PkiCreateCaRequest,
  type PkiEvaluateRequest,
  type PkiIssuanceGrant,
  type PkiIssuanceGrantInput,
  type PkiRevocationReason,
  type PkiKeyAlgorithm,
  type PkiLeafKeyAlgorithm,
  type PkiNameSubtrees,
  type PkiRequestedConstraints,
} from "@zyno-io/hemlig-client";
import { defaultConfigDir } from "./login";
import {
  CliError,
  createTransport,
  parseTimeoutMs,
  resolveAdminSession,
  resolveIdempotencyKey,
  usage,
  type CliDependencies,
} from "./common";
import { emitHelp, tableHelpPage } from "./help";
import { renderResult } from "./human";
import { emitResult, reportFailureFor, resolveMode } from "./output";

const CA_KEY_ALGORITHMS = [
  "ECDSA_P256",
  "ECDSA_P384",
  "RSA_3072",
  "RSA_4096",
  "ED25519",
] as const;
const LEAF_KEY_ALGORITHMS = [
  "ECDSA_P256",
  "ECDSA_P384",
  "ECDSA_P521",
  "ED25519",
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "RSA_8192",
] as const;
const EKUS = ["serverAuth", "clientAuth"] as const;
const CA_UUID_PATTERN =
  /^ca-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXT_ID_PATTERN = /^ext-[0-9a-f]{40}$/;
const ENVIRONMENT_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const MAX_LIST_PAGES = 10;
const MAX_PEM_FILE_BYTES = 32768;
const MAX_CRL_FILE_BYTES = 1048576;
const MAX_GRANT_FILE_BYTES = 65536;
const MAX_MIGRATE_PAGES = 50;
const MAX_REVOKE_ATTEMPTS = 20;
const CONSUMER_ID_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;
const SERIAL_PATTERN = /^[0-9a-f]{2,40}$/;
const REVOCATION_REASONS = [
  "unspecified",
  "keyCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
] as const;
const CA_REVOCATION_REASONS = [
  "unspecified",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
] as const;
const CA_KINDS = ["EXTERNAL_INTERMEDIATE", "ROOT", "INTERMEDIATE"] as const;
const EXTERNAL_ROOT_WARNING =
  "An external offline root is strongly recommended: this ROOT's key is WRAPPED and online, so a compromised PKI role can copy it, and local distrust only reaches relying parties that use Hemlig trust bundles.";
const CERTIFICATE_STATUSES = ["ISSUED", "REVOKED", "EXPIRED"] as const;

const POLICY_FLAGS = [
  "max-leaf-lifetime",
  "leaf-key-algorithm",
  "capacity",
  "issuance-per-hour",
  "crl-validity",
];
const CONSTRAINT_FLAGS = [
  "permit-dns",
  "exclude-dns",
  "permit-ip",
  "exclude-ip",
  "permit-uri",
  "exclude-uri",
];

interface CommandSpec {
  readonly positionals: readonly [number, number];
  readonly mutation: boolean;
  readonly flags: readonly string[];
}

const commandSpecs: Record<string, CommandSpec> = {
  "ca list": {
    positionals: [0, 0],
    mutation: false,
    flags: ["environment", "cursor"],
  },
  "ca get": { positionals: [1, 1], mutation: false, flags: ["environment"] },
  "ca create": {
    positionals: [0, 0],
    mutation: true,
    flags: [
      "environment",
      "name",
      "key-algorithm",
      "subject",
      ...CONSTRAINT_FLAGS,
      "eku",
      ...POLICY_FLAGS,
      "display-name",
      "rollover-from",
      "csr-out",
      "kind",
      "parent",
      "validity",
    ],
  },
  "ca revoke": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment", "reason", "invalidity-date"],
  },
  "ca activate": {
    positionals: [1, 1],
    mutation: true,
    flags: [
      "environment",
      "certificate",
      "chain",
      "root-crl",
      "accept-broader-constraints",
    ],
  },
  "ca update": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment", "if-match", ...POLICY_FLAGS, "display-name"],
  },
  "ca retire": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment"],
  },
  "ca destroy-key": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment"],
  },
  "ca delete": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment", "if-match"],
  },
  "ca crl publish": {
    positionals: [1, 1],
    mutation: true,
    flags: ["environment"],
  },
  "ca crl get": {
    positionals: [1, 1],
    mutation: false,
    flags: ["environment", "out", "format", "if-none-match"],
  },
  "grant list": {
    positionals: [0, 1],
    mutation: false,
    flags: ["environment", "ca", "include-deleted", "cursor"],
  },
  "grant get": { positionals: [2, 2], mutation: false, flags: [] },
  "grant create": {
    positionals: [2, 2],
    mutation: true,
    flags: ["environment", "file", "ca", "validate-only"],
  },
  "grant update": {
    positionals: [2, 2],
    mutation: true,
    flags: ["environment", "file", "ca", "if-match", "validate-only"],
  },
  "grant delete": {
    positionals: [2, 2],
    mutation: true,
    flags: ["if-match"],
  },
  "grant evaluate": {
    positionals: [2, 2],
    mutation: false,
    flags: [
      "csr",
      "dns",
      "ip",
      "uri",
      "cn",
      "key-algorithm",
      "duration",
      "usage",
    ],
  },
  "grant migrate": {
    positionals: [0, 0],
    mutation: false,
    flags: ["environment", "from", "to", "dry-run"],
  },
  "cert list": {
    positionals: [0, 1],
    mutation: false,
    flags: [
      "environment",
      "consumer",
      "status",
      "expiring-before",
      "grant",
      "include-expired",
      "cursor",
    ],
  },
  "cert get": {
    positionals: [2, 2],
    mutation: false,
    flags: ["environment", "out"],
  },
  "cert issue": {
    positionals: [1, 1],
    mutation: true,
    flags: [
      "environment",
      "csr",
      "use-csr-names",
      "dns",
      "ip",
      "uri",
      "subject",
      "duration",
      "usage",
      "out",
      "chain-out",
      "ca-out",
    ],
  },
  "cert revoke": {
    positionals: [2, 2],
    mutation: true,
    flags: ["environment", "reason", "invalidity-date"],
  },
  "consumer revoke-certificates": {
    positionals: [1, 1],
    mutation: true,
    flags: ["grant", "reason"],
  },
  "external-ca list": {
    positionals: [0, 0],
    mutation: false,
    flags: ["cursor"],
  },
  "external-ca get": { positionals: [1, 1], mutation: false, flags: [] },
  "external-ca upload-crl": {
    positionals: [0, 1],
    mutation: true,
    flags: ["environment", "crl", "for-ca"],
  },
};

export const pkiHelp = {
  usage:
    "hemlig pki ca <list|get|create|activate|update|retire|revoke|destroy-key|delete> | hemlig pki ca crl <publish|get> | hemlig pki external-ca <list|get|upload-crl> | hemlig pki grant <list|get|create|update|delete|evaluate|migrate> | hemlig pki cert <list|get|issue|revoke> | hemlig pki consumer revoke-certificates | hemlig pki ez <generate-ca|sign-cert|activate|revoke-cert|renew-crl|upload-crl|status>",
  commands: {
    "ca list": "--environment [--cursor]",
    "ca get <ca>": "[--environment] (needed only when <ca> is a name)",
    "ca create":
      "--environment --name --key-algorithm --subject 'CN=..,O=..' [--permit-dns|--exclude-dns|--permit-ip|--exclude-ip|--permit-uri|--exclude-uri]... [--eku serverAuth|clientAuth]... [--max-leaf-lifetime 90d] [--leaf-key-algorithm A]... [--capacity N] [--issuance-per-hour N] [--crl-validity 7d] [--display-name S] [--rollover-from <ca>] [--csr-out FILE] [--kind EXTERNAL_INTERMEDIATE|ROOT|INTERMEDIATE] [--parent <ca>] [--validity 365d] [--idempotency-key]",
    "ca activate <ca>":
      "--certificate FILE --chain FILE [--root-crl FILE] [--accept-broader-constraints]",
    "ca update <ca>":
      "--if-match ETAG|current, policy flags and/or --display-name",
    "ca retire <ca>": "[--idempotency-key]",
    "ca revoke <ca>":
      "[--reason R] [--invalidity-date ISO] [--idempotency-key]; an INTERMEDIATE goes on its root's CRL; a ROOT is distrusted locally with its children",
    "ca destroy-key <ca>": "[--idempotency-key]",
    "ca delete <ca>": "--if-match ETAG|current",
    "ca crl publish <ca>": "[--idempotency-key]",
    "ca crl get <ca|ext-id>":
      "--out FILE [--format der|pem] [--if-none-match ETAG]",
    "external-ca list": "[--cursor]",
    "external-ca get <ext-id>": "",
    "external-ca upload-crl (<ext-id> | --for-ca <ca>)":
      "--crl FILE [--idempotency-key]",
    "grant list (<consumer> | --ca <ca>)": "[--include-deleted] [--cursor]",
    "grant get <consumer> <name>": "",
    "grant create <consumer> <name>":
      "--file FILE [--ca <ca>] [--validate-only] [--idempotency-key]",
    "grant update <consumer> <name>":
      "--file FILE [--ca <ca>] --if-match ETAG|current [--validate-only] [--idempotency-key]",
    "grant delete <consumer> <name>":
      "--if-match ETAG|current [--idempotency-key]",
    "grant evaluate <consumer> <name>":
      "(--csr FILE | --key-algorithm A [--dns N]... [--ip N]... [--uri N]... [--cn N]) [--duration 1h] [--usage U]...",
    "grant migrate":
      "--from <ca> --to <ca> [--dry-run]; re-points every grant of the old CA, exit 5 if any grant is invalid or failed",
    "cert list (<ca> | --consumer <id>)":
      "[--status ISSUED|REVOKED|EXPIRED] [--expiring-before ISO|duration] [--grant N] [--include-expired] [--cursor]",
    "cert get <ca> <serial>": "[--out FILE] (writes the certificate PEM)",
    "cert issue <ca>":
      "--csr FILE (--use-csr-names | [--dns N]... [--ip N]... [--uri N]... [--subject 'CN=..,O=..']) [--duration 1h] [--usage U]... [--out FILE] [--chain-out FILE] [--ca-out FILE] [--idempotency-key]",
    "cert revoke <ca> <serial>":
      "[--reason R] [--invalidity-date ISO] [--idempotency-key]",
    "consumer revoke-certificates <consumer>":
      "[--grant N] [--reason R] [--idempotency-key]; repeats with the same key until complete",
  },
  "ez <command>":
    "Offline-root automation: hemlig pki ez --help. Creates and operates the offline root that signs EXTERNAL_INTERMEDIATE CAs.",
  references:
    "A <ca> is a ca-<uuid> ID, or a name resolved in --environment (HEMLIG_ENVIRONMENT).",
  files:
    "Certificates, chains and CRLs may be PEM or DER. Private keys are never printed.",
  durations: "An integer of seconds, or an integer with s, m, h or d.",
};

type PkiValues = Record<string, string | boolean | string[] | undefined>;

const multipleFlags = new Set([
  ...CONSTRAINT_FLAGS,
  "eku",
  "leaf-key-algorithm",
  "dns",
  "ip",
  "uri",
  "usage",
]);
const stringFlags = [
  "admin-url",
  "token-file",
  "timeout-ms",
  "environment",
  "cursor",
  "name",
  "key-algorithm",
  "subject",
  ...CONSTRAINT_FLAGS,
  "eku",
  "max-leaf-lifetime",
  "leaf-key-algorithm",
  "capacity",
  "issuance-per-hour",
  "crl-validity",
  "display-name",
  "rollover-from",
  "csr-out",
  "kind",
  "parent",
  "validity",
  "idempotency-key",
  "certificate",
  "chain",
  "root-crl",
  "if-match",
  "out",
  "format",
  "if-none-match",
  "crl",
  "for-ca",
  "file",
  "ca",
  "csr",
  "dns",
  "ip",
  "uri",
  "usage",
  "cn",
  "duration",
  "from",
  "to",
  "consumer",
  "status",
  "expiring-before",
  "grant",
  "reason",
  "invalidity-date",
  "chain-out",
  "ca-out",
];

/** Index of the first positional argument, skipping the values of value-taking flags; -1 if there is none. */
export function pkiFirstPositional(args: readonly string[]): number {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) return index;
    if (!arg.includes("=") && stringFlags.includes(arg.slice(2))) index += 1;
  }
  return -1;
}

const parseOptions = (
  args: readonly string[],
): {
  values: PkiValues;
  positionals: string[];
  seen: Set<string>;
} => {
  const options: Record<
    string,
    { type: "string" | "boolean"; multiple?: boolean }
  > = {
    help: { type: "boolean" },
    json: { type: "boolean" },
    "accept-broader-constraints": { type: "boolean" },
    "validate-only": { type: "boolean" },
    "dry-run": { type: "boolean" },
    "include-deleted": { type: "boolean" },
    "include-expired": { type: "boolean" },
    "use-csr-names": { type: "boolean" },
  };
  for (const name of stringFlags) {
    options[name] = multipleFlags.has(name)
      ? { type: "string", multiple: true }
      : { type: "string" };
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: [...args],
      allowPositionals: true,
      strict: true,
      tokens: true,
      options,
    });
  } catch {
    usage(
      "Invalid arguments. Run hemlig pki --help for the JSON command reference.",
    );
  }
  const seen = new Set<string>();
  for (const token of parsed.tokens) {
    if (token.kind !== "option") continue;
    if (!multipleFlags.has(token.name) && seen.has(token.name))
      usage("An option was supplied more than once.");
    seen.add(token.name);
  }
  // --json only picks the output format; it is no option of any command.
  seen.delete("json");
  return {
    values: parsed.values as PkiValues,
    positionals: parsed.positionals,
    seen,
  };
};

const str = (values: PkiValues, name: string): string | undefined => {
  const value = values[name];
  return typeof value === "string" ? value : undefined;
};

const list = (values: PkiValues, name: string): string[] => {
  const value = values[name];
  return Array.isArray(value) ? value : [];
};

/** Parses an integer of seconds, or an integer with an s, m, h or d suffix. */
export function parseDuration(name: string, value: string): number {
  const match = /^(\d+)([smhd])?$/.exec(value);
  if (!match)
    return usage(
      `--${name} must be an integer of seconds, or an integer with an s, m, h or d suffix.`,
    );
  const unit = { s: 1, m: 60, h: 3600, d: 86400 }[match[2] ?? "s"]!;
  const seconds = Number(match[1]) * unit;
  if (!Number.isSafeInteger(seconds) || seconds < 1)
    usage(`--${name} must be a positive duration.`);
  return seconds;
}

function parseCount(name: string, value: string): number {
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)))
    usage(`--${name} must be a non-negative integer.`);
  return Number(value);
}

const subjectKeys: Record<string, keyof PkiCaSubject> = {
  CN: "commonName",
  O: "organization",
  OU: "organizationalUnit",
  C: "country",
  L: "locality",
  ST: "state",
};

/** Parses `CN=Example CA, O=Example, C=US` into the API subject object. */
export function parseSubject(text: string): PkiCaSubject {
  const subject = parseSubjectAttributes(text);
  if (subject.commonName === undefined)
    return usage("--subject requires a CN.");
  return subject as PkiCaSubject;
}

/** Like `parseSubject`, but a CN is optional (administrator issuance). */
export function parseSubjectAttributes(text: string): Partial<PkiCaSubject> {
  const subject: Partial<Record<keyof PkiCaSubject, string>> = {};
  const hint =
    "--subject must be comma-separated KEY=value pairs using C, ST, L, O, OU and CN (a literal comma in a value is written \\,).";
  for (const part of text.split(/(?<!\\),/)) {
    const match = /^\s*([A-Za-z][A-Za-z0-9.-]*)\s*=(.*)$/s.exec(part);
    if (!match) return usage(hint);
    const key = match[1]!.toUpperCase();
    const value = match[2]!.trim().replace(/\\,/g, ",");
    const field = subjectKeys[key];
    if (field === undefined)
      return usage(`--subject attribute ${match[1]} is not supported. ${hint}`);
    if (value === "") return usage(`--subject ${key} has an empty value.`);
    if (subject[field] !== undefined)
      return usage(`--subject repeats the ${key} attribute.`);
    subject[field] = value;
  }
  return subject;
}

/** Increments the trailing integer of a name, keeping zero padding. */
export function incrementTrailingInteger(value: string): string | undefined {
  const match = /^(.*?)(\d+)$/.exec(value);
  if (!match) return undefined;
  const digits = match[2]!;
  const next = String(BigInt(digits) + 1n);
  return `${match[1]}${next.padStart(digits.length, "0")}`;
}

export function isCaId(value: string): boolean {
  return CA_UUID_PATTERN.test(value);
}

export function derToPem(der: Uint8Array, label: string): string {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

const isPem = (bytes: Uint8Array): boolean =>
  Buffer.from(bytes).toString("latin1").trimStart().startsWith("-----BEGIN");

async function readFileBytes(
  path: string,
  limit: number,
  what: string,
): Promise<Buffer> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch {
    throw new CliError(9, "input_io_error", `Cannot read the ${what} file.`);
  }
  if (bytes.length === 0 || bytes.length > limit)
    return usage(`The ${what} file is empty or exceeds ${limit} bytes.`);
  return bytes;
}

/** A PEM file is sent as text; DER certificates are wrapped as PEM. */
async function readCertificateFile(
  path: string,
  what: string,
): Promise<string> {
  const bytes = await readFileBytes(path, MAX_PEM_FILE_BYTES, what);
  return isPem(bytes) ? bytes.toString("utf8") : derToPem(bytes, "CERTIFICATE");
}

/** A PEM CRL is sent as text; a DER CRL is sent as base64. */
async function readCrlFile(path: string, what: string): Promise<string> {
  const bytes = await readFileBytes(path, MAX_CRL_FILE_BYTES, what);
  return isPem(bytes) ? bytes.toString("utf8") : bytes.toString("base64");
}

const strongEtag = (value: string, flag = "if-match"): string => {
  const raw =
    value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
  if (
    !raw ||
    raw === "*" ||
    raw.startsWith("W/") ||
    !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(raw)
  )
    usage(
      `--${flag} must be a strong ETag${flag === "if-match" ? " or current" : ""}; wildcard and weak ETags are forbidden.`,
    );
  return raw;
};

function constraintsFrom(
  values: PkiValues,
): PkiRequestedConstraints | undefined {
  const side = (prefix: "permit" | "exclude"): PkiNameSubtrees | undefined => {
    const subtrees: { dns?: string[]; ip?: string[]; uri?: string[] } = {};
    for (const kind of ["dns", "ip", "uri"] as const) {
      const entries = list(values, `${prefix}-${kind}`);
      if (entries.some((entry) => entry === ""))
        usage(`--${prefix}-${kind} must not be empty.`);
      if (entries.length > 0) subtrees[kind] = entries;
    }
    return Object.keys(subtrees).length === 0 ? undefined : subtrees;
  };
  const permitted = side("permit");
  const excluded = side("exclude");
  const ekus = list(values, "eku");
  for (const eku of ekus)
    if (!(EKUS as readonly string[]).includes(eku))
      usage("--eku must be serverAuth or clientAuth.");
  const result: {
    nameConstraints?: {
      permitted?: PkiNameSubtrees;
      excluded?: PkiNameSubtrees;
    };
    extendedKeyUsages?: ("serverAuth" | "clientAuth")[];
  } = {};
  if (permitted !== undefined || excluded !== undefined)
    result.nameConstraints = {
      ...(permitted === undefined ? {} : { permitted }),
      ...(excluded === undefined ? {} : { excluded }),
    };
  if (ekus.length > 0)
    result.extendedKeyUsages = ekus as ("serverAuth" | "clientAuth")[];
  return Object.keys(result).length === 0 ? undefined : result;
}

function policyFrom(values: PkiValues): PkiCaPolicyInput {
  const policy: {
    -readonly [K in keyof PkiCaPolicyInput]: PkiCaPolicyInput[K];
  } = {};
  const lifetime = str(values, "max-leaf-lifetime");
  if (lifetime !== undefined)
    policy.maxLeafLifetimeSeconds = parseDuration(
      "max-leaf-lifetime",
      lifetime,
    );
  const algorithms = list(values, "leaf-key-algorithm");
  for (const algorithm of algorithms)
    if (!(LEAF_KEY_ALGORITHMS as readonly string[]).includes(algorithm))
      usage("--leaf-key-algorithm is not a supported algorithm.");
  if (algorithms.length > 0)
    policy.leafKeyAlgorithms = algorithms as PkiLeafKeyAlgorithm[];
  const capacity = str(values, "capacity");
  if (capacity !== undefined)
    policy.capacity = parseCount("capacity", capacity);
  const rate = str(values, "issuance-per-hour");
  if (rate !== undefined)
    policy.issuancePerHour = parseCount("issuance-per-hour", rate);
  const validity = str(values, "crl-validity");
  if (validity !== undefined)
    policy.crlValiditySeconds = parseDuration("crl-validity", validity);
  return policy;
}

const policyOf = (ca: PkiCaDetail): PkiCaPolicyInput => ({
  // A ROOT issues no leaves, and the server refuses leaf fields on it.
  ...(ca.kind === "ROOT"
    ? {}
    : {
        maxLeafLifetimeSeconds: ca.policy.maxLeafLifetimeSeconds,
        leafKeyAlgorithms: ca.policy.leafKeyAlgorithms,
      }),
  capacity: ca.policy.capacity,
  issuancePerHour: ca.policy.issuancePerHour,
  crlValiditySeconds: ca.policy.crlValiditySeconds,
});

export async function resolveCa(
  client: HemligClient,
  token: string,
  reference: string,
  environment: string | undefined,
): Promise<string> {
  if (isCaId(reference)) return reference;
  if (environment === undefined)
    return usage(
      "Supply --environment or HEMLIG_ENVIRONMENT to resolve a CA name.",
    );
  let cursor: string | undefined;
  for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
    const result = await client.listPkiCas(token, { environment, cursor });
    const match = result.cas.find((ca) => ca.name === reference);
    if (match !== undefined) {
      // The ID is printed and used in requests: a server-supplied value that is not a CA ID is never trusted.
      if (!isCaId(match.caId)) throw new CliError(7, "invalid_response", "The server returned a malformed CA ID.");
      return match.caId;
    }
    cursor = result.nextCursor;
    if (cursor === undefined) break;
  }
  throw new CliError(
    4,
    "not_found",
    "No CA with that name was found in the environment.",
  );
}

/** Claims output files with `wx` before any request, so nothing is clobbered. */
async function claimOutputs(
  paths: Record<string, string | undefined>,
  placeholders: string[],
  claimedHandles: FileHandle[],
): Promise<Map<string, FileHandle>> {
  const handles = new Map<string, FileHandle>();
  for (const [key, path] of Object.entries(paths)) {
    if (path === undefined) continue;
    try {
      const handle = await open(path, "wx");
      handles.set(key, handle);
      claimedHandles.push(handle);
      placeholders.push(path);
    } catch {
      for (const handle of handles.values())
        await handle.close().catch(() => undefined);
      for (const claimed of placeholders.splice(0))
        await unlink(claimed).catch(() => undefined);
      throw new CliError(
        9,
        "output_io_error",
        "Cannot create an output file; it may already exist.",
      );
    }
  }
  return handles;
}

async function writeClaimed(
  handle: FileHandle,
  content: string,
): Promise<void> {
  try {
    await handle.writeFile(content);
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function crlFileContent(
  bytes: Uint8Array,
  format: "der" | "pem",
): Buffer | string {
  return format === "der" ? Buffer.from(bytes) : derToPem(bytes, "X509 CRL");
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function consumerOperand(value: string | undefined, what = "consumer"): string {
  if (value === undefined || !CONSUMER_ID_PATTERN.test(value))
    return usage(`Supply a valid ${what} ID.`);
  return value;
}

function nameOperand(value: string | undefined): string {
  if (value === undefined || !CONSUMER_ID_PATTERN.test(value))
    return usage("Supply a valid grant name.");
  return value;
}

function reasonFlag(
  values: PkiValues,
  invalidityDate: string | undefined,
): PkiRevocationReason | undefined {
  const reason = str(values, "reason");
  if (
    reason !== undefined &&
    !(REVOCATION_REASONS as readonly string[]).includes(reason)
  )
    usage(`--reason must be one of ${REVOCATION_REASONS.join(", ")}.`);
  if (invalidityDate !== undefined && reason !== "keyCompromise")
    usage("--invalidity-date requires --reason keyCompromise.");
  return reason as PkiRevocationReason | undefined;
}

function caReasonFlag(
  values: PkiValues,
  invalidityDate: string | undefined,
): PkiCaRevocationReason | undefined {
  const reason = str(values, "reason");
  if (
    reason !== undefined &&
    !(CA_REVOCATION_REASONS as readonly string[]).includes(reason)
  )
    usage(`--reason must be one of ${CA_REVOCATION_REASONS.join(", ")}.`);
  if (invalidityDate !== undefined && reason !== "caCompromise")
    usage("--invalidity-date requires --reason caCompromise.");
  return reason as PkiCaRevocationReason | undefined;
}

/** Local kind rules shared by `ca create`, checked again once a rollover base supplies the kind. */
function checkCreateKind(
  kind: PkiCaKind,
  flags: {
    readonly parent: string | undefined;
    readonly validity: string | undefined;
    readonly csrOut: string | undefined;
    readonly policy: PkiCaPolicyInput;
  },
  parentKnown: boolean,
): void {
  if (kind !== "INTERMEDIATE" && flags.parent !== undefined)
    usage("--parent is only valid with --kind INTERMEDIATE.");
  if (kind === "INTERMEDIATE" && !parentKnown)
    usage("An INTERMEDIATE CA needs --parent <root>.");
  if (kind === "EXTERNAL_INTERMEDIATE" && flags.validity !== undefined)
    usage("--validity is only valid with --kind ROOT or INTERMEDIATE.");
  if (kind !== "EXTERNAL_INTERMEDIATE" && flags.csrOut !== undefined)
    usage("--csr-out is only valid with --kind EXTERNAL_INTERMEDIATE.");
  if (
    kind === "ROOT" &&
    (flags.policy.maxLeafLifetimeSeconds !== undefined ||
      flags.policy.leafKeyAlgorithms !== undefined)
  )
    usage(
      "A ROOT CA issues no leaves; omit --max-leaf-lifetime and --leaf-key-algorithm.",
    );
}

/** Reads the grant JSON file: policy fields plus optional caId, displayName, expiresAt, status and name. */
async function readGrantFile(
  path: string,
  expectedName: string,
): Promise<Record<string, unknown>> {
  const bytes = await readFileBytes(path, MAX_GRANT_FILE_BYTES, "grant");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return usage("The grant file is not valid JSON.");
  }
  if (!isRecord(parsed)) return usage("The grant file must be a JSON object.");
  if (parsed.name !== undefined && parsed.name !== expectedName)
    usage("The grant file name does not match the <name> operand.");
  if (parsed.caId !== undefined && typeof parsed.caId !== "string")
    usage("The grant file caId must be a string.");
  return parsed;
}

/** A PEM CSR is sent as text; DER is wrapped. A private key is never sent. */
async function readCsrFile(path: string): Promise<string> {
  let bytes = await readFileBytes(path, MAX_PEM_FILE_BYTES, "CSR");
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    bytes = bytes.subarray(3);
  // Scan the whole file: keys may follow "Bag Attributes" or other leading text.
  if (/PRIVATE KEY-----/.test(bytes.toString("latin1")))
    usage("The --csr file contains a private key; supply a CSR.");
  if (isPem(bytes)) {
    const text = bytes.toString("utf8");
    if (!/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(text))
      usage("The --csr file is not a certificate request.");
    return text;
  }
  // DER: SEQUENCE { SEQUENCE (certificationRequestInfo), ... }. A key starts with an INTEGER.
  const lengthBytes =
    bytes[1] !== undefined && bytes[1] >= 0x80 ? 1 + (bytes[1] & 0x7f) : 1;
  if (bytes[0] !== 0x30 || bytes[1 + lengthBytes] !== 0x30)
    usage("The --csr file is not a certificate request.");
  return derToPem(bytes, "CERTIFICATE REQUEST");
}

function sansFrom(values: PkiValues): PkiAdminIssueCertificateRequest["sans"] {
  const sans: { dns?: string[]; ip?: string[]; uri?: string[] } = {};
  for (const kind of ["dns", "ip", "uri"] as const) {
    const entries = list(values, kind);
    if (entries.some((entry) => entry === ""))
      usage(`--${kind} must not be empty.`);
    if (entries.length > 0) sans[kind] = entries;
  }
  return Object.keys(sans).length === 0 ? undefined : sans;
}

function usagesFrom(values: PkiValues): string[] | undefined {
  const usages = list(values, "usage");
  if (usages.length > 16 || usages.some((u) => u === "" || u.length > 64))
    usage("--usage accepts at most 16 values of 1 to 64 characters.");
  return usages.length === 0 ? undefined : usages;
}

/** An ISO timestamp, or a duration counted forward from now. */
function parseWhen(
  name: string,
  value: string,
  nowMs: number,
  direction: 1 | -1 = 1,
): string {
  if (/^\d+[smhd]?$/.test(value))
    return new Date(
      nowMs + direction * parseDuration(name, value) * 1000,
    ).toISOString();
  const time = Date.parse(value);
  if (!/^\d{4}-\d{2}-\d{2}/.test(value) || Number.isNaN(time))
    return usage(`--${name} must be an ISO 8601 timestamp or a duration.`);
  return new Date(time).toISOString();
}

/** The policy fields of a stored grant plus the PUT envelope, re-pointed at `caId`. */
function grantPutBody(
  grant: PkiIssuanceGrant,
  caId: string,
): PkiIssuanceGrantInput {
  return {
    ...grant.policy,
    caId,
    ...(grant.status === "ACTIVE" || grant.status === "DISABLED"
      ? { status: grant.status }
      : {}),
    ...(grant.displayName === undefined
      ? {}
      : { displayName: grant.displayName }),
    ...(grant.expiresAt === undefined ? {} : { expiresAt: grant.expiresAt }),
  };
}

interface MigrateResult {
  consumerId: string;
  name: string;
  uid?: string;
  outcome: "migrated" | "valid" | "invalid" | "skipped" | "failed";
  reason?: string;
  errors?: unknown[];
  warnings?: unknown[];
}

/** A request error as receipt data; remote messages are never echoed. */
function errorEntry(error: unknown): Record<string, string | number | boolean> {
  if (error instanceof HemligError) {
    const entry: Record<string, string | number | boolean> = {
      status: error.status,
      code: error.code ?? `http_${error.status}`,
    };
    for (const [key, value] of Object.entries(error.details ?? {}))
      if (entry[key] === undefined) entry[key] = value;
    return entry;
  }
  return { code: "transport_error" };
}

const migrationKey = (
  from: string,
  to: string,
  consumerId: string,
  name: string,
  version: string,
): string =>
  `migrate-${createHash("sha256")
    .update(JSON.stringify([from, to, consumerId, name, version]))
    .digest("hex")
    .slice(0, 32)}`;

async function listGrantsOfCa(
  client: HemligClient,
  token: string,
  caId: string,
): Promise<{ grants: { consumerId: string; name: string }[]; more: boolean }> {
  const grants: { consumerId: string; name: string }[] = [];
  let cursor: string | undefined;
  const seen = new Set<string>();
  for (let page = 0; page < MAX_MIGRATE_PAGES; page += 1) {
    const result = await client.listCaIssuanceGrants(token, caId, { cursor });
    for (const grant of result.grants)
      grants.push({ consumerId: grant.consumerId, name: grant.name });
    cursor = result.nextCursor;
    if (cursor === undefined) return { grants, more: false };
    if (seen.has(cursor)) break;
    seen.add(cursor);
  }
  return { grants, more: true };
}

/** Runs `hemlig pki ...` (the arguments after `pki`). */
export async function runPkiCli(
  args: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> {
  const env = dependencies.env ?? process.env;
  const stdout =
    dependencies.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr =
    dependencies.stderr ?? ((text: string) => process.stderr.write(text));
  const now = dependencies.now ?? Date.now;
  const configDir = dependencies.configDir ?? defaultConfigDir(env);
  const mode = resolveMode(dependencies, args, env);
  let idempotencyKey: string | undefined;
  let ifMatch: string | undefined;
  let mutationAttempted = false;
  let csrPlaceholder: string | undefined;
  const placeholders: string[] = [];
  const claimedHandles: FileHandle[] = [];
  try {
    const { values, positionals, seen } = parseOptions(args);
    if (values.help === true) {
      await emitHelp(mode, stdout, pkiHelp, () =>
        tableHelpPage(pkiHelp, {
          prefix: "hemlig pki",
          path: positionals,
          summary: "Certificate authorities, issuance grants and certificates.",
          sharedOptions: ["admin-url", "token-file", "timeout-ms"],
        }),
      );
      return 0;
    }
    const group = positionals[0];
    const sub = positionals[1];
    let name: string;
    let operands: string[];
    if (group === "ca" && sub === "crl") {
      name = `ca crl ${positionals[2]}`;
      operands = positionals.slice(3);
    } else {
      name = `${group} ${sub}`;
      operands = positionals.slice(2);
    }
    const spec = commandSpecs[name];
    if (
      spec === undefined ||
      operands.length < spec.positionals[0] ||
      operands.length > spec.positionals[1]
    )
      return usage(
        "Expected hemlig pki <ca|external-ca|grant|cert|consumer> <command>. Run hemlig pki --help.",
      );
    const allowed = new Set([
      "admin-url",
      "token-file",
      "timeout-ms",
      ...spec.flags,
    ]);
    if (spec.mutation) allowed.add("idempotency-key");
    for (const flag of seen)
      if (!allowed.has(flag))
        usage("An option is not supported by this command.");

    const timeoutMs = parseTimeoutMs(str(values, "timeout-ms"));
    const isExtCommand =
      name === "external-ca get" || name === "external-ca upload-crl";
    const extOperand = isExtCommand ? operands[0] : undefined;
    if (extOperand !== undefined && !EXT_ID_PATTERN.test(extOperand))
      usage("Supply a valid ext-<40 hex> external CA ID.");
    const rolloverFrom = str(values, "rollover-from");
    const forCa = str(values, "for-ca");
    const references: string[] = [];
    const caOperand =
      group === "ca" ||
      name === "cert list" ||
      name === "cert get" ||
      name === "cert issue" ||
      name === "cert revoke";
    if (caOperand && !isExtCommand && operands[0] !== undefined) {
      const isExtTarget =
        name === "ca crl get" && EXT_ID_PATTERN.test(operands[0]);
      if (!isExtTarget) references.push(operands[0]);
    }
    if (rolloverFrom !== undefined) references.push(rolloverFrom);
    const parentFlag = name === "ca create" ? str(values, "parent") : undefined;
    if (parentFlag !== undefined) references.push(parentFlag);
    if (forCa !== undefined) references.push(forCa);
    const caFlag = str(values, "ca");
    const fromFlag = str(values, "from");
    const toFlag = str(values, "to");
    for (const flagged of [caFlag, fromFlag, toFlag])
      if (flagged !== undefined) references.push(flagged);
    const flagEnvironment = str(values, "environment");
    const needsEnvironment =
      ((name === "ca list" || name === "ca create") &&
        rolloverFrom === undefined) ||
      references.some((reference) => !isCaId(reference));
    if (
      flagEnvironment !== undefined &&
      !ENVIRONMENT_PATTERN.test(flagEnvironment)
    )
      usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
    let environment = flagEnvironment ?? env.HEMLIG_ENVIRONMENT;
    if (environment !== undefined && !ENVIRONMENT_PATTERN.test(environment)) {
      if (needsEnvironment)
        usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
      environment = undefined;
    }
    if (
      (name === "ca list" || name === "ca create") &&
      environment === undefined &&
      rolloverFrom === undefined
    )
      usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
    if (
      references.some((reference) => !isCaId(reference)) &&
      environment === undefined
    )
      usage("Supply --environment or HEMLIG_ENVIRONMENT to resolve a CA name.");
    const cursor = str(values, "cursor");
    if (cursor !== undefined && (!cursor || cursor.length > 2048))
      usage("--cursor must be a nextCursor value from the previous page.");

    // Command-specific local validation and file reads happen before any network call.
    const createFlags = () => ({
      subject: str(values, "subject"),
      subjectParsed:
        str(values, "subject") === undefined
          ? undefined
          : parseSubject(str(values, "subject")!),
      constraints: constraintsFrom(values),
      policy: policyFrom(values),
      keyAlgorithm: str(values, "key-algorithm"),
      name: str(values, "name"),
      displayName: str(values, "display-name"),
    });
    let create: ReturnType<typeof createFlags> | undefined;
    let createKind: PkiCaKind | undefined;
    let createValiditySeconds: number | undefined;
    let caRevokeBody: PkiRevokeCaRequest = {};
    let certificatePem: string | undefined;
    let chainPem: string | undefined;
    let rootCrl: string | undefined;
    let crlUpload: string | undefined;
    let updateFlags: ReturnType<typeof createFlags> | undefined;
    let crlOut: string | undefined;
    let crlFormat: "der" | "pem" = "der";
    if (name === "ca create") {
      create = createFlags();
      if (
        create.keyAlgorithm !== undefined &&
        !(CA_KEY_ALGORITHMS as readonly string[]).includes(create.keyAlgorithm)
      )
        usage("--key-algorithm is not a supported CA key algorithm.");
      const kindFlag = str(values, "kind");
      if (
        kindFlag !== undefined &&
        !(CA_KINDS as readonly string[]).includes(kindFlag)
      )
        usage(`--kind must be one of ${CA_KINDS.join(", ")}.`);
      createKind = kindFlag as PkiCaKind | undefined;
      const validityFlag = str(values, "validity");
      if (validityFlag !== undefined)
        createValiditySeconds = parseDuration("validity", validityFlag);
      // With --rollover-from and no --kind the kind comes from the base CA, checked after reading it.
      if (createKind !== undefined || rolloverFrom === undefined)
        checkCreateKind(
          createKind ?? "EXTERNAL_INTERMEDIATE",
          {
            parent: parentFlag,
            validity: validityFlag,
            csrOut: str(values, "csr-out"),
            policy: create.policy,
          },
          parentFlag !== undefined || rolloverFrom !== undefined,
        );
      if (rolloverFrom === undefined) {
        if (!create.name) usage("Supply --name.");
        if (!create.keyAlgorithm) usage("Supply --key-algorithm.");
        if (!create.subjectParsed) usage("Supply --subject.");
      }
    } else if (name === "ca revoke") {
      const when = str(values, "invalidity-date");
      const reason = caReasonFlag(values, when);
      caRevokeBody = {
        ...(reason === undefined ? {} : { reason }),
        ...(when === undefined
          ? {}
          : { invalidityDate: parseWhen("invalidity-date", when, now(), -1) }),
      };
    } else if (name === "ca activate") {
      const certificate = str(values, "certificate");
      const chain = str(values, "chain");
      if (!certificate || !chain) usage("Supply --certificate and --chain.");
      certificatePem = await readCertificateFile(certificate, "certificate");
      chainPem = await readCertificateFile(chain, "chain");
      const rootCrlPath = str(values, "root-crl");
      if (rootCrlPath !== undefined)
        rootCrl = await readCrlFile(rootCrlPath, "root CRL");
    } else if (name === "ca update") {
      updateFlags = createFlags();
      if (
        Object.keys(updateFlags.policy).length === 0 &&
        updateFlags.displayName === undefined
      )
        usage("Supply at least one policy flag or --display-name.");
    } else if (name === "external-ca upload-crl") {
      const crlPath = str(values, "crl");
      if (!crlPath) usage("Supply --crl <file>.");
      if ((extOperand === undefined) === (forCa === undefined))
        usage("Supply exactly one of <ext-id> or --for-ca <ca>.");
      crlUpload = await readCrlFile(crlPath, "CRL");
    } else if (name === "ca crl get") {
      crlOut = str(values, "out");
      if (!crlOut) usage("Supply --out <file>.");
      const format = str(values, "format") ?? "der";
      if (format !== "der" && format !== "pem")
        usage("--format must be der or pem.");
      crlFormat = format;
      const ifNoneMatch = str(values, "if-none-match");
      if (ifNoneMatch !== undefined) strongEtag(ifNoneMatch, "if-none-match");
    }
    // Grant, certificate and consumer commands: validate operands, flags and files locally first.
    const validateOnly = values["validate-only"] === true;
    const dryRun = values["dry-run"] === true;
    let grantConsumer: string | undefined;
    let grantName: string | undefined;
    let grantFile: Record<string, unknown> | undefined;
    let evaluateBody: PkiEvaluateRequest | undefined;
    let issueBody: PkiAdminIssueCertificateRequest | undefined;
    let revokeBody: {
      reason?: PkiRevocationReason;
      invalidityDate?: string;
      issuanceGrant?: string;
    } = {};
    let certOut: Record<"out" | "chain-out" | "ca-out", string | undefined> = {
      out: undefined,
      "chain-out": undefined,
      "ca-out": undefined,
    };
    let certSerial: string | undefined;
    let certList:
      | {
          consumer?: string;
          status?: PkiCertificateStatus;
          expiringBefore?: string;
          grant?: string;
          includeExpired: boolean;
        }
      | undefined;
    if (name.startsWith("grant ") && name !== "grant migrate") {
      if (name === "grant list") {
        if ((operands[0] === undefined) === (caFlag === undefined))
          usage("Supply exactly one of <consumer> or --ca <ca>.");
        if (operands[0] !== undefined)
          grantConsumer = consumerOperand(operands[0]);
        if (values["include-deleted"] === true && caFlag !== undefined)
          usage("--include-deleted applies to <consumer> listings only.");
      } else {
        grantConsumer = consumerOperand(operands[0]);
        grantName = nameOperand(operands[1]);
      }
      if (name === "grant create" || name === "grant update") {
        const file = str(values, "file");
        if (!file) usage("Supply --file <grant.json>.");
        grantFile = await readGrantFile(file!, grantName!);
        if (caFlag === undefined && grantFile.caId === undefined)
          usage("Supply --ca or a caId in the grant file.");
        if (validateOnly && str(values, "idempotency-key") !== undefined)
          usage("--validate-only writes nothing and takes no idempotency key.");
      }
      if (name === "grant evaluate") {
        const csr = str(values, "csr");
        const sans = sansFrom(values);
        const cn = str(values, "cn");
        const keyAlgorithm = str(values, "key-algorithm");
        const duration = str(values, "duration");
        if (
          keyAlgorithm !== undefined &&
          !(LEAF_KEY_ALGORITHMS as readonly string[]).includes(keyAlgorithm)
        )
          usage("--key-algorithm is not a supported algorithm.");
        if (csr !== undefined) {
          if (
            sans !== undefined ||
            cn !== undefined ||
            keyAlgorithm !== undefined
          )
            usage(
              "--csr cannot be combined with --dns, --ip, --uri, --cn or --key-algorithm.",
            );
        } else if (keyAlgorithm === undefined) {
          usage("Supply --csr, or --key-algorithm with names.");
        } else if (sans === undefined && cn === undefined) {
          usage("Supply at least one of --dns, --ip, --uri or --cn.");
        }
        const usages = usagesFrom(values);
        evaluateBody = {
          ...(csr === undefined
            ? {
                keyAlgorithm: keyAlgorithm as PkiLeafKeyAlgorithm,
                ...(sans === undefined ? {} : { sans }),
                ...(cn === undefined ? {} : { commonName: cn }),
              }
            : { certificateSigningRequestPem: await readCsrFile(csr) }),
          ...(duration === undefined
            ? {}
            : { durationSeconds: parseDuration("duration", duration) }),
          ...(usages === undefined ? {} : { usages }),
        };
      }
    } else if (name === "grant migrate") {
      if (!fromFlag || !toFlag) usage("Supply --from <ca> and --to <ca>.");
    } else if (name === "cert list") {
      const consumerFlag = str(values, "consumer");
      if ((operands[0] === undefined) === (consumerFlag === undefined))
        usage("Supply exactly one of <ca> or --consumer <id>.");
      const status = str(values, "status");
      if (
        status !== undefined &&
        !(CERTIFICATE_STATUSES as readonly string[]).includes(status)
      )
        usage(`--status must be one of ${CERTIFICATE_STATUSES.join(", ")}.`);
      const expiring = str(values, "expiring-before");
      const grant = str(values, "grant");
      const includeExpired = values["include-expired"] === true;
      if (consumerFlag !== undefined) {
        consumerOperand(consumerFlag);
        if (status !== undefined || expiring !== undefined)
          usage("--status and --expiring-before apply to <ca> listings only.");
        if (grant !== undefined) nameOperand(grant);
      } else if (grant !== undefined || includeExpired) {
        usage(
          "--grant and --include-expired apply to --consumer listings only.",
        );
      }
      certList = {
        ...(consumerFlag === undefined ? {} : { consumer: consumerFlag }),
        ...(status === undefined
          ? {}
          : { status: status as PkiCertificateStatus }),
        ...(expiring === undefined
          ? {}
          : { expiringBefore: parseWhen("expiring-before", expiring, now()) }),
        ...(grant === undefined ? {} : { grant }),
        includeExpired,
      };
    } else if (name === "cert get" || name === "cert revoke") {
      certSerial = operands[1]?.toLowerCase();
      if (certSerial === undefined || !SERIAL_PATTERN.test(certSerial))
        usage("Supply a valid hexadecimal certificate serial.");
      if (name === "cert get") {
        certOut = { ...certOut, out: str(values, "out") };
      } else {
        const when = str(values, "invalidity-date");
        const reason = reasonFlag(values, when);
        revokeBody = {
          ...(reason === undefined ? {} : { reason }),
          ...(when === undefined
            ? {}
            : {
                invalidityDate: parseWhen("invalidity-date", when, now(), -1),
              }),
        };
      }
    } else if (name === "cert issue") {
      const csr = str(values, "csr");
      if (!csr) usage("Supply --csr <file>.");
      const sans = sansFrom(values);
      const subjectText = str(values, "subject");
      const subject =
        subjectText === undefined
          ? undefined
          : parseSubjectAttributes(subjectText);
      const useCsrNames = values["use-csr-names"] === true;
      if (useCsrNames && (sans !== undefined || subject !== undefined))
        usage(
          "--use-csr-names cannot be combined with --dns, --ip, --uri or --subject.",
        );
      if (!useCsrNames && sans === undefined && subject === undefined)
        usage(
          "Supply --use-csr-names, or names with --dns, --ip, --uri or --subject.",
        );
      const duration = str(values, "duration");
      const usages = usagesFrom(values);
      certOut = {
        out: str(values, "out"),
        "chain-out": str(values, "chain-out"),
        "ca-out": str(values, "ca-out"),
      };
      const outPaths = Object.values(certOut).filter(
        (path): path is string => path !== undefined,
      );
      if (new Set(outPaths).size !== outPaths.length)
        usage("--out, --chain-out and --ca-out must be different files.");
      issueBody = {
        certificateSigningRequestPem: await readCsrFile(csr!),
        ...(useCsrNames ? { useCsrNames: true } : {}),
        ...(sans === undefined ? {} : { sans }),
        ...(subject === undefined ? {} : { subject }),
        ...(duration === undefined
          ? {}
          : { durationSeconds: parseDuration("duration", duration) }),
        ...(usages === undefined ? {} : { usages }),
      };
    } else if (name === "consumer revoke-certificates") {
      consumerOperand(operands[0]);
      const grant = str(values, "grant");
      if (grant !== undefined) nameOperand(grant);
      const reason = reasonFlag(values, undefined);
      revokeBody = {
        ...(reason === undefined ? {} : { reason }),
        ...(grant === undefined ? {} : { issuanceGrant: grant }),
      };
    }
    const ifMatchFlag = str(values, "if-match");
    if (
      (name === "ca update" ||
        name === "ca delete" ||
        name === "grant update" ||
        name === "grant delete") &&
      !ifMatchFlag
    )
      usage(
        "Supply --if-match with a known ETag, or current to fetch it once.",
      );
    if (ifMatchFlag !== undefined && ifMatchFlag !== "current")
      ifMatch = strongEtag(ifMatchFlag);

    const { origin, token } = await resolveAdminSession(
      {
        "admin-url": str(values, "admin-url"),
        "token-file": str(values, "token-file"),
      },
      env,
      { configDir, now },
    );
    if (spec.mutation && !validateOnly)
      idempotencyKey = resolveIdempotencyKey(str(values, "idempotency-key"));
    const client = new HemligClient(
      origin,
      createTransport(dependencies, timeoutMs),
    );
    const ca = (reference: string) =>
      resolveCa(client, token, reference, environment);
    const receipt = async (
      data: unknown,
      etag?: string,
      extra: Record<string, unknown> = {},
    ): Promise<number> => {
      const envelope = { data, etag, idempotencyKey, ifMatch, ...extra };
      await emitResult(mode, stdout, envelope, (style) =>
        renderResult(`pki ${name}`, envelope, { now: new Date(now()) }, style),
      );
      return 0;
    };
    const versionOf = (detail: PkiCaDetail): string => {
      if (typeof detail.version !== "string" || detail.version === "")
        throw new CliError(
          7,
          "invalid_response",
          "Administrator API returned an invalid CA response.",
        );
      return detail.version;
    };

    switch (name) {
      case "ca list":
        return receipt(
          await client.listPkiCas(token, { environment: environment!, cursor }),
        );
      case "ca get": {
        const detail = await client.getPkiCa(token, await ca(operands[0]!));
        return receipt(detail, detail.version);
      }
      case "grant list": {
        if (caFlag !== undefined)
          return receipt(
            await client.listCaIssuanceGrants(token, await ca(caFlag), {
              cursor,
            }),
          );
        return receipt(
          await client.listAdminIssuanceGrants(token, grantConsumer!, {
            includeDeleted: values["include-deleted"] === true,
            cursor,
          }),
        );
      }
      case "grant get": {
        const grant = await client.getAdminIssuanceGrant(
          token,
          grantConsumer!,
          grantName!,
        );
        return receipt(grant, grant.version);
      }
      case "grant create":
      case "grant update": {
        const file = grantFile!;
        const { name: _name, caId: fileCa, ...policyFields } = file;
        const resolvedFlag =
          caFlag === undefined ? undefined : await ca(caFlag);
        const resolvedFile =
          typeof fileCa === "string" ? await ca(fileCa) : undefined;
        if (
          resolvedFlag !== undefined &&
          resolvedFile !== undefined &&
          resolvedFlag !== resolvedFile
        )
          usage("--ca and the grant file caId name different CAs.");
        const caId = (resolvedFlag ?? resolvedFile)!;
        const input = {
          ...policyFields,
          caId,
        } as unknown as PkiIssuanceGrantInput;
        if (name === "grant create") {
          const body = { ...input, name: grantName! };
          if (validateOnly) {
            const result = await client.validateIssuanceGrantCreate(
              token,
              grantConsumer!,
              body,
            );
            await receipt(result);
            return result.valid === false ? 5 : 0;
          }
          mutationAttempted = true;
          const created = await client.createIssuanceGrant(
            token,
            grantConsumer!,
            body,
            idempotencyKey!,
          );
          return receipt(created, created.version);
        }
        if (ifMatchFlag === "current")
          ifMatch = (
            await client.getAdminIssuanceGrant(
              token,
              grantConsumer!,
              grantName!,
            )
          ).version;
        if (validateOnly) {
          const result = await client.validateIssuanceGrantUpdate(
            token,
            grantConsumer!,
            grantName!,
            ifMatch!,
            input,
          );
          await receipt(result);
          return result.valid === false ? 5 : 0;
        }
        mutationAttempted = true;
        const updated = await client.updateIssuanceGrant(
          token,
          grantConsumer!,
          grantName!,
          ifMatch!,
          input,
          idempotencyKey!,
        );
        return receipt(updated, updated.version);
      }
      case "grant delete": {
        if (ifMatchFlag === "current")
          ifMatch = (
            await client.getAdminIssuanceGrant(
              token,
              grantConsumer!,
              grantName!,
            )
          ).version;
        mutationAttempted = true;
        const deleted = await client.deleteIssuanceGrant(
          token,
          grantConsumer!,
          grantName!,
          ifMatch!,
          idempotencyKey!,
        );
        return receipt(deleted, deleted.version);
      }
      case "grant evaluate":
        return receipt(
          await client.evaluateIssuanceGrant(
            token,
            grantConsumer!,
            grantName!,
            evaluateBody!,
          ),
        );
      case "grant migrate": {
        const fromId = await ca(fromFlag!);
        const toId = await ca(toFlag!);
        if (fromId === toId) usage("--from and --to must be different CAs.");
        const { grants: listed, more } = await listGrantsOfCa(
          client,
          token,
          fromId,
        );
        const results: MigrateResult[] = [];
        for (const { consumerId, name: grantNameOf } of listed) {
          const result: MigrateResult = {
            consumerId,
            name: grantNameOf,
            outcome: "failed",
          };
          results.push(result);
          let current: PkiIssuanceGrant;
          try {
            current = await client.getAdminIssuanceGrant(
              token,
              consumerId,
              grantNameOf,
            );
          } catch (error) {
            if (
              error instanceof HemligError &&
              (error.status === 401 || error.status === 403)
            )
              throw error;
            result.errors = [errorEntry(error)];
            continue;
          }
          result.uid = current.uid;
          if (current.status === "DELETED" || current.caId !== fromId) {
            result.outcome = "skipped";
            continue;
          }
          if (current.expired === true) {
            // The server rejects a past expiresAt, so an expired grant cannot move.
            result.outcome = "skipped";
            result.reason = "expired";
            continue;
          }
          const body = grantPutBody(current, toId);
          try {
            if (dryRun) {
              const check = await client.validateIssuanceGrantUpdate(
                token,
                consumerId,
                grantNameOf,
                current.version,
                body,
              );
              result.outcome = check.valid ? "valid" : "invalid";
              if (check.errors.length > 0) result.errors = [...check.errors];
              if (check.warnings.length > 0)
                result.warnings = [...check.warnings];
            } else {
              mutationAttempted = true;
              const moved = await client.updateIssuanceGrant(
                token,
                consumerId,
                grantNameOf,
                current.version,
                body,
                migrationKey(
                  fromId,
                  toId,
                  consumerId,
                  grantNameOf,
                  current.version,
                ),
              );
              result.outcome = "migrated";
              if (moved.warnings !== undefined && moved.warnings.length > 0)
                result.warnings = [...moved.warnings];
            }
          } catch (error) {
            if (
              error instanceof HemligError &&
              (error.status === 401 || error.status === 403)
            )
              throw error;
            result.outcome =
              error instanceof HemligError && error.status === 400
                ? "invalid"
                : "failed";
            result.errors = [errorEntry(error)];
          }
        }
        const remaining = await listGrantsOfCa(client, token, fromId);
        await receipt({
          from: fromId,
          to: toId,
          dryRun,
          results,
          listedTruncated: more,
          remainingListed: remaining.grants.length,
          remainingTruncated: remaining.more,
        });
        return more ||
          results.some((r) => r.outcome === "invalid" || r.outcome === "failed")
          ? 5
          : 0;
      }
      case "cert list": {
        const list = certList!;
        if (list.consumer !== undefined)
          return receipt(
            await client.listConsumerPkiCertificates(token, list.consumer, {
              issuanceGrant: list.grant,
              includeExpired: list.includeExpired,
              cursor,
            }),
          );
        return receipt(
          await client.listPkiCertificates(token, await ca(operands[0]!), {
            status: list.status,
            expiringBefore: list.expiringBefore,
            cursor,
          }),
        );
      }
      case "cert get": {
        const caId = await ca(operands[0]!);
        const outPath = certOut.out;
        const handles = await claimOutputs(
          { certificate: outPath },
          placeholders,
          claimedHandles,
        );
        const detail = await client.getPkiCertificate(token, caId, certSerial!);
        if (outPath === undefined) return receipt(detail);
        placeholders.length = 0;
        await writeClaimed(handles.get("certificate")!, detail.certificatePem);
        const { certificatePem: _pem, ...rest } = detail;
        return receipt({ ...rest, out: outPath });
      }
      case "cert issue": {
        const caId = await ca(operands[0]!);
        const handles = await claimOutputs(
          {
            certificate: certOut.out,
            chain: certOut["chain-out"],
            ca: certOut["ca-out"],
          },
          placeholders,
          claimedHandles,
        );
        mutationAttempted = true;
        const issued = await client.issuePkiCertificate(
          token,
          caId,
          issueBody!,
          idempotencyKey!,
        );
        if (handles.size === 0) return receipt(issued);
        const pems = {
          certificate: issued.certificatePem,
          chain: issued.chainPem,
          ca: issued.caPem,
        };
        const outPaths: Record<string, string | undefined> = {
          certificate: certOut.out,
          chain: certOut["chain-out"],
          ca: certOut["ca-out"],
        };
        const complete = new Set<string>();
        try {
          for (const [key, handle] of handles) {
            await writeClaimed(handle, pems[key as keyof typeof pems]);
            complete.add(key);
          }
        } catch {
          // Never leave a truncated or empty file behind.
          for (const [key, path] of Object.entries(outPaths))
            if (path !== undefined && !complete.has(key))
              await unlink(path).catch(() => undefined);
          placeholders.length = 0;
          throw new CliError(
            9,
            "output_io_error",
            `The certificate was issued (caId ${issued.caId}, serial ${issued.serial}) but an output file could not be written; incomplete files were removed. Rerun the same command with the same --idempotency-key and new output paths to replay it, or read it with \`hemlig pki cert get\`.`,
          );
        }
        placeholders.length = 0;
        const { certificatePem, chainPem, caPem, ...rest } = issued;
        return receipt({
          ...rest,
          ...(certOut.out === undefined
            ? { certificatePem }
            : { out: certOut.out }),
          ...(certOut["chain-out"] === undefined
            ? { chainPem }
            : { chainOut: certOut["chain-out"] }),
          ...(certOut["ca-out"] === undefined
            ? { caPem }
            : { caOut: certOut["ca-out"] }),
        });
      }
      case "cert revoke": {
        const caId = await ca(operands[0]!);
        mutationAttempted = true;
        return receipt(
          await client.revokePkiCertificate(
            token,
            caId,
            certSerial!,
            revokeBody,
            idempotencyKey!,
          ),
        );
      }
      case "consumer revoke-certificates": {
        mutationAttempted = true;
        let attempts = 0;
        let revokedTotal = 0;
        let result;
        do {
          result = await client.revokeConsumerPkiCertificates(
            token,
            operands[0]!,
            revokeBody,
            idempotencyKey!,
          );
          attempts += 1;
          revokedTotal += result.revoked ?? 0;
        } while (result.complete === false && attempts < MAX_REVOKE_ATTEMPTS);
        if (result.complete === false)
          throw new CliError(
            7,
            "revoke_incomplete",
            `Revocation was still incomplete after ${MAX_REVOKE_ATTEMPTS} attempts; repeat the command with the same --idempotency-key.`,
          );
        return receipt({ ...result, revoked: revokedTotal, attempts });
      }
      case "external-ca list":
        return receipt(await client.listExternalCas(token, { cursor }));
      case "external-ca get":
        return receipt(await client.getExternalCa(token, extOperand!));
      case "ca create": {
        const flags = create!;
        let base: PkiCaDetail | undefined;
        if (rolloverFrom !== undefined)
          base = await client.getPkiCa(token, await ca(rolloverFrom));
        let requestName = flags.name;
        let subject = flags.subjectParsed;
        if (base !== undefined) {
          if (requestName === undefined) {
            requestName = incrementTrailingInteger(base.name);
            if (requestName === undefined)
              usage(
                "The CA name has no trailing integer to increment; supply --name.",
              );
          }
          if (subject === undefined) {
            const next = incrementTrailingInteger(base.subject.commonName);
            if (next === undefined)
              usage(
                "The CA subject CN has no trailing integer to increment; supply --subject.",
              );
            subject = { ...base.subject, commonName: next };
          }
        }
        const kind: PkiCaKind =
          createKind ?? base?.kind ?? "EXTERNAL_INTERMEDIATE";
        const parentCaId =
          parentFlag !== undefined
            ? await ca(parentFlag)
            : kind === "INTERMEDIATE"
              ? base?.parentCaId
              : undefined;
        if (base !== undefined)
          checkCreateKind(
            kind,
            {
              parent: parentFlag,
              validity: str(values, "validity"),
              csrOut: str(values, "csr-out"),
              policy: flags.policy,
            },
            parentCaId !== undefined,
          );
        const keyAlgorithm = (flags.keyAlgorithm ??
          base?.key.algorithm) as PkiKeyAlgorithm;
        const { maxLeafLifetimeSeconds, leafKeyAlgorithms, ...baseNoLeaf } =
          base === undefined ? ({} as PkiCaPolicyInput) : policyOf(base);
        const policy: PkiCaPolicyInput = {
          ...baseNoLeaf,
          ...(kind === "ROOT"
            ? {}
            : {
                ...(maxLeafLifetimeSeconds === undefined
                  ? {}
                  : { maxLeafLifetimeSeconds }),
                ...(leafKeyAlgorithms === undefined
                  ? {}
                  : { leafKeyAlgorithms }),
              }),
          ...flags.policy,
        };
        const constraints =
          flags.constraints === undefined
            ? base?.requestedConstraints
            : {
                ...(flags.constraints.nameConstraints === undefined &&
                base?.requestedConstraints?.nameConstraints !== undefined
                  ? {
                      nameConstraints:
                        base.requestedConstraints.nameConstraints,
                    }
                  : {}),
                ...(flags.constraints.extendedKeyUsages === undefined &&
                base?.requestedConstraints?.extendedKeyUsages !== undefined
                  ? {
                      extendedKeyUsages:
                        base.requestedConstraints.extendedKeyUsages,
                    }
                  : {}),
                ...flags.constraints,
              };
        const request: PkiCreateCaRequest = {
          environment:
            str(values, "environment") ?? base?.environment ?? environment!,
          name: requestName!,
          kind,
          ...(parentCaId === undefined ? {} : { parentCaId }),
          ...(createValiditySeconds === undefined
            ? {}
            : { validitySeconds: createValiditySeconds }),
          keyAlgorithm,
          subject: subject!,
          ...(constraints === undefined || Object.keys(constraints).length === 0
            ? {}
            : { requestedConstraints: constraints }),
          ...(Object.keys(policy).length === 0 ? {} : { policy }),
          ...(flags.displayName === undefined
            ? {}
            : { displayName: flags.displayName }),
        };
        const csrOut = str(values, "csr-out");
        let csrHandle: FileHandle | undefined;
        if (csrOut !== undefined) {
          // Claim the path first so an existing file fails before the CA exists.
          try {
            csrHandle = await open(csrOut, "wx");
            csrPlaceholder = csrOut;
          } catch {
            throw new CliError(
              9,
              "output_io_error",
              "Cannot create the --csr-out file; it may already exist.",
            );
          }
        }
        mutationAttempted = true;
        let created: Awaited<ReturnType<HemligClient["createPkiCa"]>>;
        try {
          created = await client.createPkiCa(token, request, idempotencyKey!);
        } catch (error) {
          await csrHandle?.close().catch(() => undefined);
          throw error;
        }
        for (const warning of created.warnings ?? [])
          await stderr(`warning: ${warning.message}\n`);
        if (
          keyAlgorithm === "ED25519" &&
          !(created.warnings ?? []).some(
            (warning) => warning.code === "ed25519_compatibility",
          )
        )
          await stderr(
            "warning: Ed25519 CA keys are not supported by every TLS stack; verify client compatibility.\n",
          );
        if (
          kind === "ROOT" &&
          !(created.warnings ?? []).some(
            (warning) => warning.code === "external_root_recommended",
          )
        )
          await stderr(`warning: ${EXTERNAL_ROOT_WARNING}\n`);
        if (csrOut === undefined) return receipt(created, created.version);
        try {
          if (created.csrPem === undefined)
            throw new Error("The server returned no CSR.");
          await csrHandle!.writeFile(created.csrPem);
        } catch {
          throw new CliError(
            9,
            "output_io_error",
            "The CA was created but the CSR file could not be written. Read the CSR with `hemlig pki ca get`, or replay this command with the same --idempotency-key.",
          );
        } finally {
          await csrHandle!.close().catch(() => undefined);
        }
        csrPlaceholder = undefined;
        const { csrPem: _omitted, ...rest } = created;
        return receipt({ ...rest, csrOut }, created.version);
      }
      case "ca activate": {
        const caId = await ca(operands[0]!);
        mutationAttempted = true;
        const detail = await client.activatePkiCa(
          token,
          caId,
          {
            certificatePem: certificatePem!,
            chainPem: chainPem!,
            ...(rootCrl === undefined ? {} : { rootCrl }),
            ...(values["accept-broader-constraints"] === true
              ? { acceptBroaderConstraints: true }
              : {}),
          },
          idempotencyKey!,
        );
        return receipt(detail, detail.version);
      }
      case "ca update": {
        const caId = await ca(operands[0]!);
        const current = await client.getPkiCa(token, caId);
        if (ifMatchFlag === "current") ifMatch = versionOf(current);
        const flags = updateFlags!;
        if (
          current.kind === "ROOT" &&
          (flags.policy.maxLeafLifetimeSeconds !== undefined ||
            flags.policy.leafKeyAlgorithms !== undefined)
        )
          usage(
            "A ROOT CA issues no leaves; omit --max-leaf-lifetime and --leaf-key-algorithm.",
          );
        const displayName = flags.displayName ?? current.displayName;
        mutationAttempted = true;
        const detail = await client.updatePkiCa(
          token,
          caId,
          ifMatch!,
          {
            ...(displayName === undefined ? {} : { displayName }),
            policy: { ...policyOf(current), ...flags.policy },
          },
          idempotencyKey!,
        );
        return receipt(detail, detail.version);
      }
      case "ca revoke": {
        const caId = await ca(operands[0]!);
        mutationAttempted = true;
        const result = await client.revokePkiCa(
          token,
          caId,
          caRevokeBody,
          idempotencyKey!,
        );
        return receipt(result, result.ca.version);
      }
      case "ca delete": {
        const caId = await ca(operands[0]!);
        if (ifMatchFlag === "current")
          ifMatch = versionOf(await client.getPkiCa(token, caId));
        mutationAttempted = true;
        const detail = await client.deletePkiCa(
          token,
          caId,
          ifMatch!,
          idempotencyKey!,
        );
        return receipt(detail, detail.version);
      }
      case "ca retire":
      case "ca destroy-key": {
        const caId = await ca(operands[0]!);
        mutationAttempted = true;
        const detail =
          name === "ca retire"
            ? await client.retirePkiCa(token, caId, idempotencyKey!)
            : await client.destroyPkiCaKey(token, caId, idempotencyKey!);
        return receipt(detail, detail.version);
      }
      case "ca crl publish": {
        const caId = await ca(operands[0]!);
        mutationAttempted = true;
        return receipt(
          await client.publishPkiCrl(token, caId, idempotencyKey!),
        );
      }
      case "ca crl get": {
        const target = operands[0]!;
        const issuerId = EXT_ID_PATTERN.test(target)
          ? target
          : await ca(target);
        const ifNoneMatch = str(values, "if-none-match");
        const result: BinaryResult = await client.getAdminCrl(
          token,
          issuerId,
          ifNoneMatch === undefined
            ? undefined
            : strongEtag(ifNoneMatch, "if-none-match"),
        );
        if (result.status === 304)
          return receipt({
            id: issuerId,
            etag: result.etag,
            path: crlOut,
            notModified: true,
          });
        const sha256 = createHash("sha256").update(result.bytes).digest("hex");
        const typeOk = (result.contentType ?? "")
          .trim()
          .toLowerCase()
          .startsWith("application/pkix-crl");
        if (
          !(typeOk || result.bytes[0] === 0x30) ||
          (result.etag !== undefined && result.etag !== sha256)
        )
          throw new CliError(
            7,
            "invalid_response",
            "Administrator API returned a CRL that failed verification.",
          );
        const content = crlFileContent(result.bytes, crlFormat);
        const temporary = `${crlOut}.tmp-${randomUUID()}`;
        try {
          await writeFile(temporary, content, { flag: "wx" });
          await rename(temporary, crlOut!);
        } catch {
          await unlink(temporary).catch(() => undefined);
          throw new CliError(
            9,
            "output_io_error",
            "Cannot write the CRL file.",
          );
        }
        return receipt({
          id: issuerId,
          bytes: Buffer.byteLength(content),
          sha256,
          etag: result.etag,
          path: crlOut,
          notModified: false,
        });
      }
      case "external-ca upload-crl": {
        let extId = extOperand;
        if (extId === undefined) {
          const detail = await client.getPkiCa(token, await ca(forCa!));
          if (detail.parent?.type !== "external")
            throw new CliError(
              5,
              "conflict",
              "The CA has no external parent yet; activate it first.",
            );
          extId = detail.parent.id;
        }
        mutationAttempted = true;
        return receipt(
          await client.uploadExternalCaCrl(
            token,
            extId,
            crlUpload!,
            idempotencyKey!,
          ),
        );
      }
    }
    return usage("Run hemlig pki --help.");
  } catch (error) {
    for (const handle of claimedHandles)
      await handle.close().catch(() => undefined);
    for (const path of placeholders) await unlink(path).catch(() => undefined);
    if (csrPlaceholder !== undefined) {
      // Nothing was created: remove the empty placeholder claimed for --csr-out.
      await unlink(csrPlaceholder).catch(() => undefined);
    }
    return reportFailureFor(
      mode,
      error,
      { group: "pki", idempotencyKey, ifMatch, mutationAttempted },
      stderr,
    );
  }
}
