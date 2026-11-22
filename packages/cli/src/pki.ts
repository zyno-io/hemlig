import { createHash } from "node:crypto";
import { open, readFile, unlink, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  HemligClient,
  type BinaryResult,
  type PkiCaDetail,
  type PkiCaPolicyInput,
  type PkiCaSubject,
  type PkiCreateCaRequest,
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
  reportFailure,
  resolveAdminSession,
  resolveIdempotencyKey,
  usage,
  type CliDependencies,
} from "./common";

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
    ],
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
    "hemlig pki ca <list|get|create|activate|update|retire|destroy-key|delete> | hemlig pki ca crl <publish|get> | hemlig pki external-ca <list|get|upload-crl>",
  commands: {
    "ca list": "--environment [--cursor]",
    "ca get <ca>": "[--environment] (needed only when <ca> is a name)",
    "ca create":
      "--environment --name --key-algorithm --subject 'CN=..,O=..' [--permit-dns|--exclude-dns|--permit-ip|--exclude-ip|--permit-uri|--exclude-uri]... [--eku serverAuth|clientAuth]... [--max-leaf-lifetime 90d] [--leaf-key-algorithm A]... [--capacity N] [--issuance-per-hour N] [--crl-validity 7d] [--display-name S] [--rollover-from <ca>] [--csr-out FILE] [--idempotency-key]",
    "ca activate <ca>":
      "--certificate FILE --chain FILE [--root-crl FILE] [--accept-broader-constraints]",
    "ca update <ca>":
      "--if-match ETAG|current, policy flags and/or --display-name",
    "ca retire <ca>": "[--idempotency-key]",
    "ca destroy-key <ca>": "[--idempotency-key]",
    "ca delete <ca>": "--if-match ETAG|current",
    "ca crl publish <ca>": "[--idempotency-key]",
    "ca crl get <ca|ext-id>":
      "--out FILE [--format der|pem] [--if-none-match ETAG]",
    "external-ca list": "[--cursor]",
    "external-ca get <ext-id>": "",
    "external-ca upload-crl (<ext-id> | --for-ca <ca>)":
      "--crl FILE [--idempotency-key]",
  },
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
];

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
    "accept-broader-constraints": { type: "boolean" },
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
  const subject: Partial<Record<keyof PkiCaSubject, string>> = {};
  for (const part of text.split(/,(?=\s*(?:C|ST|L|O|OU|CN)=)/)) {
    const trimmed = part.trim();
    const equals = trimmed.indexOf("=");
    const key = equals < 0 ? "" : trimmed.slice(0, equals).trim();
    const value = equals < 0 ? "" : trimmed.slice(equals + 1).trim();
    const field = subjectKeys[key];
    if (field === undefined || value === "")
      return usage(
        "--subject must be comma-separated KEY=value pairs using C, ST, L, O, OU and CN.",
      );
    if (subject[field] !== undefined)
      return usage(`--subject repeats the ${key} attribute.`);
    subject[field] = value;
  }
  if (subject.commonName === undefined)
    return usage("--subject requires a CN.");
  return subject as PkiCaSubject;
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

const strongEtag = (value: string): string => {
  const raw =
    value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
  if (
    !raw ||
    raw === "*" ||
    raw.startsWith("W/") ||
    !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(raw)
  )
    usage(
      "--if-match must be a strong ETag or current; wildcard and weak ETags are forbidden.",
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
  maxLeafLifetimeSeconds: ca.policy.maxLeafLifetimeSeconds,
  leafKeyAlgorithms: ca.policy.leafKeyAlgorithms,
  capacity: ca.policy.capacity,
  issuancePerHour: ca.policy.issuancePerHour,
  crlValiditySeconds: ca.policy.crlValiditySeconds,
});

async function resolveCa(
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
    if (match !== undefined) return match.caId;
    cursor = result.nextCursor;
    if (cursor === undefined) break;
  }
  throw new CliError(
    4,
    "not_found",
    "No CA with that name was found in the environment.",
  );
}

function crlFileContent(
  bytes: Uint8Array,
  format: "der" | "pem",
): Buffer | string {
  return format === "der" ? Buffer.from(bytes) : derToPem(bytes, "X509 CRL");
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
  let idempotencyKey: string | undefined;
  let ifMatch: string | undefined;
  let mutationAttempted = false;
  let csrPlaceholder: string | undefined;
  try {
    const { values, positionals, seen } = parseOptions(args);
    if (values.help === true) {
      await stdout(`${JSON.stringify(pkiHelp)}\n`);
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
        "Expected hemlig pki ca <command> or hemlig pki external-ca <command>. Run hemlig pki --help.",
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
    const requestedEnvironment =
      str(values, "environment") ?? env.HEMLIG_ENVIRONMENT;
    if (
      requestedEnvironment !== undefined &&
      !ENVIRONMENT_PATTERN.test(requestedEnvironment)
    )
      usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
    const environment = requestedEnvironment;
    const isExtCommand =
      name === "external-ca get" || name === "external-ca upload-crl";
    const extOperand = isExtCommand ? operands[0] : undefined;
    if (extOperand !== undefined && !EXT_ID_PATTERN.test(extOperand))
      usage("Supply a valid ext-<40 hex> external CA ID.");
    const rolloverFrom = str(values, "rollover-from");
    const forCa = str(values, "for-ca");
    const references: string[] = [];
    if (!isExtCommand && operands[0] !== undefined) {
      const isExtTarget =
        name === "ca crl get" && EXT_ID_PATTERN.test(operands[0]);
      if (!isExtTarget) references.push(operands[0]);
    }
    if (rolloverFrom !== undefined) references.push(rolloverFrom);
    if (forCa !== undefined) references.push(forCa);
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
      if (rolloverFrom === undefined) {
        if (!create.name) usage("Supply --name.");
        if (!create.keyAlgorithm) usage("Supply --key-algorithm.");
        if (!create.subjectParsed) usage("Supply --subject.");
      }
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
      if (ifNoneMatch !== undefined) strongEtag(ifNoneMatch);
    }
    const ifMatchFlag = str(values, "if-match");
    if ((name === "ca update" || name === "ca delete") && !ifMatchFlag)
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
    if (spec.mutation)
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
      await stdout(
        `${JSON.stringify({ data, etag, idempotencyKey, ifMatch, ...extra })}\n`,
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
        const keyAlgorithm = (flags.keyAlgorithm ??
          base?.key.algorithm) as PkiKeyAlgorithm;
        const policy = {
          ...(base === undefined ? {} : policyOf(base)),
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
          kind: "EXTERNAL_INTERMEDIATE",
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
        if (csrOut !== undefined) {
          // Claim the path first so an existing file fails before the CA exists.
          try {
            await (await open(csrOut, "wx")).close();
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
        const created = await client.createPkiCa(
          token,
          request,
          idempotencyKey!,
        );
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
        if (csrOut === undefined) return receipt(created, created.version);
        try {
          await writeFile(csrOut, created.csrPem, { flag: "w" });
        } catch {
          throw new CliError(
            9,
            "output_io_error",
            "Cannot write the CSR file.",
          );
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
          ifNoneMatch === undefined ? undefined : strongEtag(ifNoneMatch),
        );
        if (result.status === 304)
          return receipt({
            id: issuerId,
            etag: result.etag,
            path: crlOut,
            notModified: true,
          });
        const content = crlFileContent(result.bytes, crlFormat);
        try {
          await writeFile(crlOut!, content);
        } catch {
          throw new CliError(
            9,
            "output_io_error",
            "Cannot write the CRL file.",
          );
        }
        return receipt({
          id: issuerId,
          bytes: Buffer.byteLength(content),
          sha256: createHash("sha256").update(result.bytes).digest("hex"),
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
    if (csrPlaceholder !== undefined) {
      // Nothing was created: remove the empty placeholder claimed for --csr-out.
      await unlink(csrPlaceholder).catch(() => undefined);
    }
    return reportFailure(
      error,
      { group: "pki", idempotencyKey, ifMatch, mutationAttempted },
      stderr,
    );
  }
}
