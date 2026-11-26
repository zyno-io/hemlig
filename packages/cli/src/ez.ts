import { randomBytes } from "node:crypto";
import { hostname as osHostname } from "node:os";
import { promises as fs, openSync } from "node:fs";
import { ReadStream as TtyReadStream } from "node:tty";
import { isAbsolute, normalize, resolve, dirname, join, basename, sep } from "node:path";
import { parseArgs } from "node:util";
import type { PkiCaDetail, PkiCaSubject } from "@zyno-io/hemlig-client";
import { CliError, reportFailure, parseTimeoutMs, usage, type CliDependencies } from "./common";
import {
  crlEntriesOf,
  gateRootProfile,
  importedIssuedEntries,
  isEncryptedKeyPem,
  KEY_FILE_ALGORITHM_WARNINGS,
  assertCrlFromRoot,
  mergeRevocations,
  nextThisUpdate,
  parseCrlSource,
  parseOpenSslCrlNumber,
  parseOpenSslIndex,
  planCrl,
  planReissue,
  readSourceKey,
  recordsFromCrl,
  recordsFromIndex,
  revokedEntriesOf,
  subjectOfRoot,
  type IndexRow,
  type RevocationRecord,
  type RevocationSource,
} from "./ez-adopt";
import { EzError } from "./ez-error";
import { acquireLock, createImmutable, exists, type LockHandle } from "./ez-fs";
import { firstFormError, runForm, type FormField } from "./ez-form";
import { prepareCrl, prepareIntermediate, prepareRoot, signPrepared, type IssuedCertificate, type IssuedCrl, type Prepared } from "./ez-issue";
import { decryptKeyFile, encryptPkcs8, KEY_FILE_ITERATIONS } from "./ez-keyfile";
import { assertRestrictedName, describeName, encodeSubject, formatSubject, isIdentityRootName, parseSubject, type Subject } from "./ez-name";
import {
  activateWithCertificate,
  assertClockSkew,
  downloadRootCrl,
  fetchCa,
  findExternalRoot,
  openSession,
  assertCarriesServerRevocations,
  fetchServerCrl,
  fetchServerView,
  serverViewOf,
  uploadRootCrl,
  type OnlineSession,
} from "./ez-online";
import { assertCrlValidityDays, EZ_DEFAULTS, parseDuration } from "./ez-profile";
import { consumeConfirmation, Prompter, type Confirmation } from "./ez-prompt";
import { renderAddYubiKeyReview, renderAdoptReview, renderCrlReview, renderRevokeReview, renderSignReview, rootLabel } from "./ez-review";
import { generateSoftwareKey, SoftwareSigner, signBatch, type RootSigner, type SignItem } from "./ez-signer";
import {
  assertKeyTypeSupported,
  chooseRecordedDevice,
  parseSerial,
  parseSlot,
  pivKeyType,
  TOUCH_POLICIES,
  touchNotice,
  YkmanClient,
  YubiKeySigner,
  type TouchPolicy,
} from "./ez-yubikey";
import { acknowledgeWrites, DeviceHandle, renderYubiKeyReview, type YkIo } from "./ez-yubikey-flow";
import {
  compareWithServer,
  DEFAULT_STATE_FILE,
  EzStore,
  initialArtifacts,
  initialState,
  resolveRecordedPath,
  type EzState,
  type IssuedEntry,
  type SignReservation,
  type StoreOptions,
} from "./ez-state";
import {
  computeIntermediateValidity,
  DAY_MS,
  decodeCsrInput,
  CRL_REASON_NAMES,
  describeSpki,
  EZ_KEY_ALGORITHMS,
  fromPem,
  keyIdentifier,
  NEW_REVOCATION_REASONS,
  OID,
  parseBasicConstraints,
  parseCertificate,
  parseCrl,
  randomSerial,
  serialHex,
  sha256Hex,
  toPem,
  validateCsr,
  validateRootCertificate,
  verifyCertificateSignature,
  verifyCrlSignature,
  type CrlReasonName,
  type EzKeyAlgorithm,
  type IntermediateValidity,
  type ParsedCertificate,
  type ParsedCrl,
  type ValidatedCsr,
} from "./ez-x509";
import { resolveCa, isCaId } from "./pki";
import { humanFromReceipt, warningText, makeStyle, renderHuman, renderHumanError, type ErrorInfo } from "./ez-output";
import type { TerminalInput } from "./tty";

export const ezHelp = {
  usage: "hemlig pki ez <generate-ca|adopt-ca|import-key|add-yubikey|sign-cert|activate|revoke-cert|renew-crl|upload-crl|status> [options]",
  commands: {
    "generate-ca":
      "[--subject 'CN=..,O=..'] [--key-algorithm ECDSA_P384|ECDSA_P256|RSA_3072|RSA_4096] [--validity 20y] [--intermediate-validity 730d] [--crl-validity 180d] [--path-len N] [--key-file F] [--cert-file F] [--crl-file F] [--passphrase-stdin] [--yes]; creates a root, CRL #1 and the state file. Opens a settings form on a terminal. YubiKey: --yubikey [--yubikey-serial N] [--second-yubikey-serial N] [--slot 9c] [--touch-policy always|cached|never] [--overwrite-slot 9c] [--no-slot-certificate] [--protect-management-key] [--pin-stdin] [--allow-last-pin-attempt] imports a software-generated key (encrypted backup file kept) into the YubiKey; add --on-device --accept-no-backup to generate on the YubiKey with no backup and no recovery.",
    "adopt-ca":
      "(--openssl-dir DIR | --cert F --key F | --yubikey [--cert F]) [--crl F] [--openssl-index F] [--openssl-crlnumber F] [--crl-number N] [--no-prior-revocations] [--reissue-root-certificate [--validity D]] [--offline] [--crl-validity D] [--intermediate-validity D] [--key-file F] [--cert-file F] [--crl-file F] [--passphrase-stdin]; brings an existing offline root into Hemlig. Needs a revocation source (--crl, an index.txt, or the server's root CRL) or --no-prior-revocations, and a CRL number source (or --crl-number N, at least the last CRL number the root ever issued). Software roots: the key is re-encrypted into --dir under a new passphrase (with --passphrase-stdin: the source key's passphrase first, if it is encrypted, then the new one) and the source files are never changed. --openssl-dir reads root.pem, private/root.key, index.txt, crlnumber and root.crl.pem. YubiKey: --yubikey [--yubikey-serial N] [--slot 9c] [--pin-stdin] [--allow-last-pin-attempt] reads the slot read-only and signs with it; nothing is written to the device unless --store-certificate-in-slot. Input files are relative to the current directory. Shows a review and asks you to type confirm. Online by default (reads the server's root CRL); --offline skips the server.",
    "add-yubikey":
      "[--yubikey-serial N] [--pin-stdin] [--allow-last-pin-attempt] [--json]; records another YubiKey that already holds this root's key (a YubiKey root only; for a software root use import-key). Read-only on the device: it checks the recorded slot holds the root's key, shows a review, asks you to type confirm and signs one test challenge. Nothing is written to either device.",
    "import-key":
      "[--yubikey-serial N] [--slot 9c] [--touch-policy always|cached|never] [--overwrite-slot 9c] [--no-slot-certificate] [--protect-management-key] [--passphrase-stdin] [--pin-stdin] [--allow-last-pin-attempt]; decrypts the root's backup key file and imports it into a (another) YubiKey, then records the device.",
    "sign-cert <ca>":
      "--environment ENV [--validity 730d] [--crl-validity D] [--renew-before 45d] [--key F] [--csr F] [--passphrase-stdin] [--yes]; online: fetches the pending CA's CSR, shows it, asks you to type confirm, signs, syncs the root CRL and activates.",
    "sign-cert <ca> --offline":
      "--csr F [--expect-spki-sha256 HEX] [--out F] [--chain-out F] [--crl-out F] [--environment ENV] [--validity D] [--key F]; no network; writes the certificate (and optional chain and CRL copies) to carry to an online machine.",
    "activate <ca>": "--environment ENV --certificate F --chain F [--crl F]; online: uploads the root CRL, then activates. Needs no state and no key.",
    "revoke-cert (<ca> | --serial HEX | --cert FILE)":
      "--reason R [--invalidity-date ISO] [--offline --crl-out F] [--key F] [--passphrase-stdin]; shows what is revoked, asks you to type confirm, signs a new CRL and uploads it.",
    "renew-crl": "[--if-due] [--renew-before 45d] [--crl-validity D] [--expect-ext-id ext-..] [--offline --crl-out F] [--key F] [--passphrase-stdin]; signs a new root CRL and uploads it.",
    "upload-crl": "[--expect-ext-id ext-..]; uploads the current root CRL (retry path, or another deployment). Stateless: --crl F --root-cert F verifies a carried CRL under the root, refuses one that drops a revocation the server lists or is not newer, then uploads it (no state directory needed).",
    status: "[--offline]; local state, deployments and a server comparison.",
  },
  common:
    "--json (print the JSON receipt on stdout even on a terminal; piped output is always JSON), --dir DIR (default: the current directory; relative file flags are relative to it), --state-file NAME (default hemlig-ez.json), --break-stale-lock. Online commands also take --admin-url, --token-file and --timeout-ms.",
  prompts:
    "Passphrases and YubiKey PINs are typed at the terminal (twice for a new key) or read from a pipe with --passphrase-stdin and --pin-stdin (passphrase first). sign-cert and revoke-cert always ask you to type confirm at a terminal; --yes skips only the settings form.",
};

// ---------------------------------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------------------------------

const BOOLEAN_FLAGS = [
  "help",
  "yes",
  "offline",
  "passphrase-stdin",
  "break-stale-lock",
  "if-due",
  "yubikey",
  "on-device",
  "accept-no-backup",
  "protect-management-key",
  "no-slot-certificate",
  "allow-last-pin-attempt",
  "pin-stdin",
  "json",
  "no-prior-revocations",
  "reissue-root-certificate",
  "store-certificate-in-slot",
] as const;
const STRING_FLAGS = [
  "yubikey-serial",
  "second-yubikey-serial",
  "slot",
  "touch-policy",
  "overwrite-slot",
  "dir",
  "state-file",
  "subject",
  "key-algorithm",
  "validity",
  "intermediate-validity",
  "crl-validity",
  "renew-before",
  "path-len",
  "key-file",
  "cert-file",
  "crl-file",
  "environment",
  "csr",
  "expect-spki-sha256",
  "out",
  "chain-out",
  "crl-out",
  "key",
  "certificate",
  "chain",
  "crl",
  "reason",
  "invalidity-date",
  "serial",
  "expect-ext-id",
  "admin-url",
  "token-file",
  "timeout-ms",
  "cert",
  "openssl-dir",
  "root-cert",
  "openssl-index",
  "openssl-crlnumber",
  "crl-number",
] as const;

const ONLINE = ["admin-url", "token-file", "timeout-ms"];
const STATE = ["dir", "state-file", "break-stale-lock"];
const SECRET = ["passphrase-stdin"];
const YUBIKEY_USE = ["pin-stdin", "yubikey-serial", "allow-last-pin-attempt"];
const YUBIKEY_WRITE = [...YUBIKEY_USE, "slot", "touch-policy", "overwrite-slot", "no-slot-certificate", "protect-management-key"];

interface CommandSpec {
  readonly operands: readonly [number, number];
  readonly flags: readonly string[];
}

const COMMANDS: Record<string, CommandSpec> = {
  "generate-ca": {
    operands: [0, 0],
    flags: [...STATE, ...SECRET, ...YUBIKEY_WRITE, "yubikey", "on-device", "accept-no-backup", "second-yubikey-serial", "yes", "subject", "key-algorithm", "validity", "intermediate-validity", "crl-validity", "path-len", "key-file", "cert-file", "crl-file"],
  },
  "adopt-ca": {
    operands: [0, 0],
    flags: [
      ...STATE, ...SECRET, ...YUBIKEY_USE, ...ONLINE,
      "offline", "yubikey", "slot", "store-certificate-in-slot", "cert", "key", "crl", "openssl-dir", "openssl-index", "openssl-crlnumber", "crl-number",
      "no-prior-revocations", "reissue-root-certificate", "validity", "crl-validity", "intermediate-validity", "key-file", "cert-file", "crl-file",
    ],
  },
  "add-yubikey": { operands: [0, 0], flags: [...STATE, ...YUBIKEY_USE] },
  "import-key": { operands: [0, 0], flags: [...STATE, ...SECRET, ...YUBIKEY_WRITE] },
  "sign-cert": {
    operands: [1, 1],
    flags: [...STATE, ...SECRET, ...YUBIKEY_USE, ...ONLINE, "yes", "offline", "environment", "csr", "expect-spki-sha256", "out", "chain-out", "crl-out", "validity", "crl-validity", "renew-before", "key"],
  },
  activate: { operands: [1, 1], flags: [...ONLINE, "environment", "certificate", "chain", "crl"] },
  "revoke-cert": {
    operands: [0, 1],
    flags: [...STATE, ...SECRET, ...YUBIKEY_USE, ...ONLINE, "offline", "environment", "reason", "invalidity-date", "serial", "cert", "crl-out", "crl-validity", "expect-ext-id", "key"],
  },
  "renew-crl": {
    operands: [0, 0],
    flags: [...STATE, ...SECRET, ...YUBIKEY_USE, ...ONLINE, "offline", "if-due", "renew-before", "crl-validity", "expect-ext-id", "crl-out", "key"],
  },
  "upload-crl": { operands: [0, 0], flags: [...STATE, ...ONLINE, "expect-ext-id", "crl", "root-cert"] },
  status: { operands: [0, 0], flags: [...STATE, ...ONLINE, "offline"] },
};

type Values = Record<string, string | boolean | undefined>;

interface Parsed {
  readonly command: string;
  readonly operands: string[];
  readonly values: Values;
}

const parseEzArgs = (args: readonly string[]): Parsed | "help" => {
  const options: Record<string, { type: "string" | "boolean" }> = {};
  for (const name of BOOLEAN_FLAGS) options[name] = { type: "boolean" };
  for (const name of STRING_FLAGS) options[name] = { type: "string" };
  let parsed;
  try {
    parsed = parseArgs({ args: [...args], allowPositionals: true, strict: true, tokens: true, options });
  } catch {
    return usage("Invalid arguments. Run hemlig pki ez --help.");
  }
  const seen = new Set<string>();
  for (const token of parsed.tokens) {
    if (token.kind !== "option") continue;
    if (seen.has(token.name)) usage("An option was supplied more than once.");
    seen.add(token.name);
  }
  const [command, ...operands] = parsed.positionals;
  if (parsed.values.help === true && command === undefined) return "help";
  if (command === undefined) return usage("Expected hemlig pki ez <command>. Run hemlig pki ez --help.");
  const spec = COMMANDS[command];
  if (spec === undefined) return usage("Unknown pki ez command. Run hemlig pki ez --help.");
  if (parsed.values.help === true) return "help";
  if (operands.length < spec.operands[0] || operands.length > spec.operands[1]) usage(`Wrong number of operands for ${command}. Run hemlig pki ez --help.`);
  const allowed = new Set([...spec.flags, "json"]);
  for (const flag of seen) if (!allowed.has(flag)) usage(`--${flag} is not supported by ${command}.`);
  return { command, operands, values: parsed.values as Values };
};

// ---------------------------------------------------------------------------------------------------------------------
// Context and small helpers
// ---------------------------------------------------------------------------------------------------------------------

interface Progress {
  readonly completed: string[];
  readonly files: Record<string, string>;
  /** Set when a plain rerun would be wrong; replaces the rerun hint in the error envelope. */
  recovery?: string;
}

interface Ctx {
  readonly command: string;
  readonly operands: readonly string[];
  readonly values: Values;
  readonly dependencies: CliDependencies;
  readonly env: NodeJS.ProcessEnv;
  readonly clock: () => Date;
  readonly prompter: Prompter;
  readonly progress: Progress;
  readonly say: (text: string) => Promise<void>;
  /** Like `say`, but only when the result is printed as JSON: on a terminal the human result replaces it. */
  readonly summary: (text: string) => Promise<void>;
  readonly color: boolean;
  /** The ykman client (created on first use; `HEMLIG_YKMAN` names the executable). */
  readonly ykman: () => YkmanClient;
}

interface Receipt {
  readonly data: Record<string, unknown>;
  readonly next?: readonly string[];
}

const str = (values: Values, name: string): string | undefined => {
  const value = values[name];
  return typeof value === "string" ? value : undefined;
};
const flag = (values: Values, name: string): boolean => values[name] === true;

const checked = (fn: (value: string) => unknown) =>
  Object.assign(
    (value: string): string | undefined => {
      try {
        fn(value);
        return undefined;
      } catch (error) {
        if (error instanceof EzError || error instanceof CliError) return error.message;
        throw error;
      }
    },
    { throws: fn },
  );

const shellArg = (value: string): string => (/^[A-Za-z0-9._/:=@%+-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`);

const directoryOf = (values: Values): string => resolve(str(values, "dir") ?? process.cwd());
const withinDir = (dir: string, path: string): string => (isAbsolute(path) ? normalize(path) : resolve(dir, path));
/** How a path is recorded in the state: relative inside `dir`, or absolute when it points elsewhere. */
const recordedPath = (dir: string, path: string): string => {
  if (path.length === 0 || path.includes("\0")) throw new EzError(2, "invalid_input", "A file name is empty or malformed.");
  if (isAbsolute(path)) return normalize(path);
  const relative = normalize(path);
  return relative === ".." || relative.startsWith(`..${"/"}`) || relative.startsWith("..\\") ? resolve(dir, path) : relative;
};

const storeOptions = (ctx: Ctx, dir: string): StoreOptions => {
  const stateFile = str(ctx.values, "state-file");
  if (stateFile !== undefined && !/^[A-Za-z0-9._-]+$/.test(stateFile)) usage("--state-file must be a plain file name inside --dir.");
  return {
    dir,
    stateFile: stateFile ?? DEFAULT_STATE_FILE,
    command: `pki ez ${ctx.command}`,
    breakStaleLock: flag(ctx.values, "break-stale-lock"),
    now: ctx.clock,
    fault: ctx.dependencies.ezFault,
  };
};

const readBounded = async (path: string, limit: number, what: string, allowEmpty = false): Promise<Buffer> => {
  let bytes: Buffer;
  try {
    bytes = await fs.readFile(path);
  } catch {
    throw new EzError(9, "input_io_error", `Cannot read the ${what} (${path}).`);
  }
  if ((bytes.length === 0 && !allowEmpty) || bytes.length > limit) throw new EzError(2, "invalid_input", `The ${what} is empty or larger than ${limit} bytes.`);
  return bytes;
};

const environmentOf = (ctx: Ctx, required: boolean): string | undefined => {
  const value = str(ctx.values, "environment") ?? ctx.env.HEMLIG_ENVIRONMENT;
  if (value === undefined) {
    if (required) usage("Supply --environment or HEMLIG_ENVIRONMENT.");
    return undefined;
  }
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(value)) usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
  return value;
};

const days = (text: string, what: string): number => {
  try {
    return parseDuration(text);
  } catch (error) {
    if (error instanceof EzError) throw new EzError(2, "invalid_input", `${what}: ${error.message}`);
    throw error;
  }
};

const crlDays = (text: string): number => assertCrlValidityDays(days(text, "CRL validity"));

const subjectOf = (record: PkiCaSubject): Subject => ({
  CN: record.commonName,
  ...(record.organization === undefined ? {} : { O: record.organization }),
  ...(record.organizationalUnit === undefined ? {} : { OU: record.organizationalUnit }),
  ...(record.country === undefined ? {} : { C: record.country }),
  ...(record.locality === undefined ? {} : { L: record.locality }),
  ...(record.state === undefined ? {} : { ST: record.state }),
});

const colorWanted = (env: NodeJS.ProcessEnv, interactive: boolean): boolean =>
  interactive && env.NO_COLOR === undefined && env.TERM !== "dumb";

/** Writes a file that leaves the machine. An identical existing file is fine (a rerun); a different one is never overwritten. */
const writeOutput = async (path: string, data: Buffer, mode = 0o644): Promise<void> => {
  await fs.mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    await createImmutable(path, data, mode);
  } catch (error) {
    if (error instanceof EzError && error.code === "already_exists") {
      const existing = await fs.readFile(path).catch(() => undefined);
      if (existing !== undefined && existing.equals(data)) return;
      throw new EzError(5, "already_exists", `${path} already exists with different content; nothing was overwritten.`, { files: [path] });
    }
    throw error;
  }
};

const pemOf = (der: Buffer, label: string): string => toPem(der, label);

// ---------------------------------------------------------------------------------------------------------------------
// Settings form helpers
// ---------------------------------------------------------------------------------------------------------------------

/** The form runs only on a terminal and without --yes; the typed confirm is never skipped. */
const formWanted = (ctx: Ctx): boolean => ctx.prompter.interactive && !flag(ctx.values, "yes");

const terminalColumns = (): number => {
  const columns = process.stderr.columns;
  return typeof columns === "number" && columns >= 40 ? columns : 80;
};

const runSettingsForm = async (ctx: Ctx, title: string, fields: FormField[]): Promise<Record<string, string>> => {
  if (!formWanted(ctx)) {
    const error = firstFormError(fields);
    if (error !== undefined) {
      // Re-run the failing check so the error keeps its own code (for example subject_invalid).
      for (const field of fields) {
        if (field.value !== "" || field.optional !== true) field.validate?.throws?.(field.value);
      }
      usage(error);
    }
    return Object.fromEntries(fields.map((f) => [f.id, f.value]));
  }
  return runForm({ title, fields, prompter: ctx.prompter, color: ctx.color, columns: terminalColumns() });
};

// ---------------------------------------------------------------------------------------------------------------------
// Signing core shared by sign-cert, renew-crl and revoke-cert
// ---------------------------------------------------------------------------------------------------------------------

const ykIo = (ctx: Ctx): YkIo => ({
  prompter: ctx.prompter,
  say: ctx.say,
  client: ctx.ykman(),
  pinFromStdin: flag(ctx.values, "pin-stdin"),
  allowLastPinAttempt: flag(ctx.values, "allow-last-pin-attempt"),
});

/** The YubiKey that holds this root's key, checked read-only and with its PIN already verified (so a typo changes nothing). */
const unlockYubiKey = async (ctx: Ctx, store: EzStore): Promise<YubiKeySigner> => {
  const record = store.state.key.yubikey as NonNullable<typeof store.state.key.yubikey>;
  if (str(ctx.values, "key") !== undefined) usage("--key applies only to a software key; this root's key is on a YubiKey.");
  const io = ykIo(ctx);
  const flagged = str(ctx.values, "yubikey-serial");
  const serial = await chooseRecordedDevice(io.client, record.devices.map((d) => d.serial), flagged === undefined ? undefined : parseSerial(flagged));
  const device = await DeviceHandle.open(io, { serial, slot: record.slot, write: false, overwrite: false, allowLastPinAttempt: io.allowLastPinAttempt });
  if (device.target.info.key === null) {
    throw new EzError(5, "slot_empty", `Slot ${record.slot} of YubiKey ${serial} holds no key.`);
  }
  store.assertSigner(device.target.info.key.spkiDer);
  const signer = device.signer(device.target.info.key.spkiDer);
  try {
    await signer.verifyPin();
  } catch (error) {
    signer.close();
    throw error;
  }
  return signer;
};

const unlockSigner = async (ctx: Ctx, store: EzStore): Promise<RootSigner> => {
  if (store.state.key.storage === "yubikey") return unlockYubiKey(ctx, store);
  const override = str(ctx.values, "key");
  const path = override === undefined ? store.keyFilePath : withinDir(store.dir, override);
  if (path === undefined) {
    throw new EzError(2, "key_storage_unsupported", "This root has no key file to sign with.");
  }
  const pem = await readBounded(path, 65536, "key file");
  const passphrase = await ctx.prompter.passphrase({ create: false, fromStdin: flag(ctx.values, "passphrase-stdin") });
  try {
    const signer = new SoftwareSigner(decryptKeyFile(pem.toString("utf8"), passphrase));
    store.assertSigner(signer.spkiDer);
    return signer;
  } finally {
    passphrase.fill(0);
  }
};

interface IssuePlan {
  readonly cert?: { readonly reservation: SignReservation; readonly csr: ValidatedCsr; readonly serial: Buffer; readonly validity: IntermediateValidity };
  readonly crl?: { readonly validityDays: number };
}

interface IssueResult {
  readonly certificate?: { readonly der: Buffer; readonly entry: IssuedEntry; readonly resumed: boolean };
  readonly crl?: { readonly der: Buffer; readonly parsed: ParsedCrl; readonly number: number };
}

/** Reserves, signs as one batch (gated by the typed confirm having happened) and commits. */
const unlistedRevocations = (store: EzStore): string[] => store.state.revoked.filter((r) => r.listedInCrl === null).map((r) => r.serial);

/** Only revoke-cert (which shows its own review and asks for `confirm`) may sign a CRL that still has to list a revocation. */
const assertNoPendingRevocation = (store: EzStore): void => {
  const pending = unlistedRevocations(store);
  if (pending.length > 0) {
    throw new EzError(5, "revocation_pending", "A revocation is recorded but not yet in a signed CRL. Rerun revoke-cert for it, which shows the review and asks you to type confirm.", {
      serials: pending,
    });
  }
};

/**
 * Reserves and signs as one batch. A batch that signs a certificate, or a CRL that newly lists a revocation, needs the
 * `Confirmation` that only `Prompter.confirm` can mint.
 */
const issue = async (ctx: Ctx, store: EzStore, signer: RootSigner, plan: IssuePlan, confirmation?: Confirmation): Promise<IssueResult> => {
  const now = ctx.clock();
  const root = store.rootCertificate;
  const began = await store.begin({ sign: plan.cert?.reservation, crl: plan.crl !== undefined });
  const resumed = plan.cert === undefined ? undefined : began.resumed;
  const items: Prepared<unknown>[] = [];
  let certAt = -1;
  let crlAt = -1;
  if (plan.cert !== undefined && resumed === undefined) {
    certAt = items.length;
    items.push(prepareIntermediate(signer, root, plan.cert.csr, { now, serial: plan.cert.serial, validity: plan.cert.validity }) as Prepared<unknown>);
  }
  if (plan.crl !== undefined) {
    if (began.crl === undefined) throw new EzError(7, "internal_error", "The CRL reservation is missing.");
    crlAt = items.length;
    items.push(
      prepareCrl(signer, root, {
        number: began.crl.number,
        thisUpdate: began.crl.thisUpdate,
        validityDays: plan.crl.validityDays,
        entries: store.revocationEntries(),
      }) as Prepared<unknown>,
    );
  }
  let finished: unknown[] = [];
  try {
    const signatures = await signBatch(signer, items.map((p) => p.item), {
      events: { onTouch: (item) => void ctx.say(touchNotice(signer instanceof YubiKeySigner ? signer.serial : 0, item)) },
      confirm: () => {
        // The review and the typed confirm happened before anything was reserved; this makes it impossible to sign without them.
        const gated = certAt >= 0 || unlistedRevocations(store).length > 0;
        // Single use, and only for the operation it was typed for: a certificate is "sign", a revoking CRL is "revoke".
        if (gated && !consumeConfirmation(confirmation, certAt >= 0 ? "sign" : "revoke")) {
          throw new EzError(2, "confirmation_declined", "Signing was attempted without the typed confirmation.");
        }
      },
    });
    finished = items.map((p, i) => p.finish(signatures[i] as Buffer));
  } catch (error) {
    if (plan.cert !== undefined && resumed === undefined) await store.abandon(serialHex(plan.cert.serial)).catch(() => undefined);
    throw error;
  }
  const out: { certificate?: IssueResult["certificate"]; crl?: IssueResult["crl"] } = {};
  if (plan.cert !== undefined) {
    if (resumed !== undefined) {
      const der = await store.readIssuedCertificate(resumed);
      if (der === undefined) throw new EzError(5, "state_conflict", "The signed certificate file is missing.", { reason: "issued_missing" });
      out.certificate = { der, entry: resumed, resumed: true };
    } else {
      const certificate = finished[certAt] as IssuedCertificate;
      const entry = await store.commitSigned(serialHex(plan.cert.serial), certificate.der);
      ctx.progress.completed.push("certificate-signed");
      out.certificate = { der: certificate.der, entry, resumed: false };
    }
  }
  if (plan.crl !== undefined && began.crl !== undefined) {
    const crl = finished[crlAt] as IssuedCrl;
    await store.commitCrl(began.crl.number, crl.der);
    ctx.progress.completed.push("crl-signed");
    out.crl = { der: crl.der, parsed: crl.crl, number: began.crl.number };
  }
  return out;
};

// ---------------------------------------------------------------------------------------------------------------------
// Root CRL sync (online)
// ---------------------------------------------------------------------------------------------------------------------

interface CrlSync {
  readonly registered: boolean;
  readonly extId?: string;
  readonly uploaded: boolean;
  readonly changed?: boolean;
  readonly revokedCaIds?: readonly string[];
}

/** Pushes the current local CRL to a registered root when the server's copy differs. The server is never ahead here (checkServer). */
const syncRootCrl = async (session: OnlineSession, store: EzStore, ext: Awaited<ReturnType<typeof findExternalRoot>>, ctx: Ctx): Promise<CrlSync> => {
  if (ext === undefined) return { registered: false, uploaded: false };
  const current = await store.readCurrentCrl();
  if (current === undefined) throw new EzError(5, "state_conflict", "There is no current CRL to upload.", { reason: "crl_missing" });
  const number = Number(current.number);
  if (ext.crl?.sha256 === current.sha256) {
    await store.recordUpload(session.origin.origin, ext.extId, number);
    return { registered: true, extId: ext.extId, uploaded: false, changed: false };
  }
  const response = await uploadRootCrl(session, ext.extId, { pem: pemOf(current.der, "X509 CRL"), sha256: current.sha256 });
  ctx.progress.completed.push("crl-uploaded");
  await store.recordUpload(session.origin.origin, ext.extId, number);
  return { registered: true, extId: ext.extId, uploaded: true, changed: response.changed, revokedCaIds: response.revokedCaIds };
};

const checkExpectedExt = (expected: string | undefined, ext: { extId: string } | undefined): void => {
  if (expected === undefined) return;
  if (!/^ext-[0-9a-f]{40}$/.test(expected)) usage("--expect-ext-id must be an ext-<40 hex> ID.");
  if (ext?.extId !== expected) {
    throw new EzError(5, "root_mismatch", `The server's external root is ${ext?.extId ?? "not registered"}, not ${expected}; this is not the deployment you meant.`);
  }
};

const sessionOf = async (ctx: Ctx): Promise<OnlineSession> =>
  openSession(
    { "admin-url": str(ctx.values, "admin-url"), "token-file": str(ctx.values, "token-file") },
    ctx.dependencies,
    parseTimeoutMs(str(ctx.values, "timeout-ms")),
  );

const crlSummary = (crl: ParsedCrl | undefined): Record<string, unknown> | undefined =>
  crl === undefined ? undefined : { number: Number(crl.number), thisUpdate: crl.thisUpdate.toISOString(), nextUpdate: crl.nextUpdate?.toISOString(), entries: crl.entries.length, sha256: crl.sha256 };

// ---------------------------------------------------------------------------------------------------------------------
// generate-ca
// ---------------------------------------------------------------------------------------------------------------------

const checkSubjectText = (text: string): void => {
  const subject = parseSubject(text);
  const name = assertRestrictedName(encodeSubject(subject), "external");
  if (isIdentityRootName(name)) throw new EzError(2, "subject_invalid", "That subject is reserved for Hemlig's own identity root.");
};

const YUBIKEY_ONLY_FLAGS = ["yubikey-serial", "second-yubikey-serial", "slot", "touch-policy", "overwrite-slot", "no-slot-certificate", "protect-management-key", "pin-stdin", "allow-last-pin-attempt"];

const generateCa = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  if (flag(v, "on-device") && !flag(v, "yubikey")) usage("--on-device needs --yubikey.");
  if (flag(v, "on-device") && !flag(v, "accept-no-backup")) {
    usage("--on-device generates a key that can never be exported or recovered; add --accept-no-backup to say you understand (you will also be asked to type it).");
  }
  if (flag(v, "accept-no-backup") && !flag(v, "on-device")) usage("--accept-no-backup applies only with --on-device.");
  const initialStorage = flag(v, "yubikey") ? (flag(v, "on-device") ? "yubikey-on-device" : "yubikey") : "software";
  const fields: FormField[] = [
    { id: "dir", label: "Directory", kind: "text", value: directoryOf(v), hint: "state, certificates and CRLs are written here", validate: checked((x) => x.length > 0 || usage("empty")) },
    { id: "subject", label: "Root subject", kind: "text", value: str(v, "subject") ?? "", hint: "for example CN=Example Root CA,O=Example Corp", validate: checked(checkSubjectText) },
    { id: "storage", label: "Key storage", kind: "choice", value: initialStorage, choices: ["software", "yubikey", "yubikey-on-device"], hint: "yubikey = backup key file + import (recommended); yubikey-on-device = NO backup" },
    { id: "keyAlgorithm", label: "Key algorithm", kind: "choice", value: str(v, "key-algorithm") ?? EZ_DEFAULTS.keyAlgorithm, choices: EZ_KEY_ALGORITHMS },
    { id: "keyFile", label: "Key file", kind: "text", value: str(v, "key-file") ?? "root.key.pem", hint: "the encrypted key or backup; relative to the directory", validate: checked((x) => recordedPath("/", x)) },
    { id: "yubikeySerial", label: "YubiKey serial", kind: "text", optional: true, value: str(v, "yubikey-serial") ?? "", hint: "YubiKey storage; needed when several are connected", validate: checked((x) => parseSerial(x)) },
    { id: "secondSerial", label: "Second YubiKey", kind: "text", optional: true, value: str(v, "second-yubikey-serial") ?? "", hint: "optional second copy (imported key only)", validate: checked((x) => parseSerial(x, "--second-yubikey-serial")) },
    { id: "slot", label: "YubiKey slot", kind: "text", value: str(v, "slot") ?? EZ_DEFAULTS.slot, hint: "PIN policy is always", validate: checked(parseSlot) },
    { id: "touchPolicy", label: "Touch policy", kind: "choice", value: str(v, "touch-policy") ?? EZ_DEFAULTS.touchPolicy, choices: TOUCH_POLICIES },
    { id: "certFile", label: "Certificate file", kind: "text", value: str(v, "cert-file") ?? "root.pem", validate: checked((x) => recordedPath("/", x)) },
    { id: "crlFile", label: "CRL copy", kind: "text", value: str(v, "crl-file") ?? "root.crl.pem", validate: checked((x) => recordedPath("/", x)) },
    { id: "rootValidity", label: "Root validity", kind: "text", value: str(v, "validity") ?? `${EZ_DEFAULTS.rootValidityDays}d`, hint: "20y = 7300 days", validate: checked((x) => days(x, "Root validity")) },
    { id: "intermediateValidity", label: "Intermediate validity", kind: "text", value: str(v, "intermediate-validity") ?? `${EZ_DEFAULTS.intermediateValidityDays}d`, hint: "default for sign-cert", validate: checked((x) => days(x, "Intermediate validity")) },
    { id: "crlValidity", label: "CRL validity", kind: "text", value: str(v, "crl-validity") ?? `${EZ_DEFAULTS.crlValidityDays}d`, hint: "60d to 400d", validate: checked(crlDays) },
    { id: "renewWindow", label: "CRL renewal window", kind: "readonly", value: `${EZ_DEFAULTS.crlRenewBeforeDays}d`, hint: "renewed when fewer days remain (--renew-before)" },
    { id: "pathLen", label: "Path length limit", kind: "text", optional: true, value: str(v, "path-len") ?? "", hint: "blank = none; - clears", validate: checked((x) => pathLength(x)) },
    { id: "kdf", label: "Key protection", kind: "readonly", value: `PBKDF2-HMAC-SHA256 x ${KEY_FILE_ITERATIONS.toLocaleString("en-US")}, AES-256-CBC` },
  ];
  const settings = await runSettingsForm(ctx, "hemlig pki ez generate-ca: new offline root", fields);
  const dir = resolve(settings.dir as string);
  const subject = parseSubject(settings.subject as string);
  checkSubjectText(settings.subject as string);
  const algorithm = settings.keyAlgorithm as EzKeyAlgorithm;
  const storage = settings.storage as string;
  const useYubiKey = storage !== "software";
  const onDevice = storage === "yubikey-on-device";
  if (onDevice && !flag(v, "accept-no-backup")) {
    usage("Generating the key on the YubiKey (no backup, no recovery) needs --accept-no-backup, and you will also be asked to type it.");
  }
  if (!useYubiKey) {
    for (const name of YUBIKEY_ONLY_FLAGS) if (v[name] !== undefined) usage(`--${name} applies only with --yubikey.`);
    if (flag(v, "yubikey") || flag(v, "on-device")) usage("--yubikey conflicts with the key storage chosen.");
  }
  const rootDays = days(settings.rootValidity as string, "Root validity");
  const intermediateDays = days(settings.intermediateValidity as string, "Intermediate validity");
  const crlValidity = crlDays(settings.crlValidity as string);
  const pathLen = pathLength(settings.pathLen as string);
  const keyFile = recordedPath(dir, settings.keyFile as string);
  const certFile = recordedPath(dir, settings.certFile as string);
  const crlFile = recordedPath(dir, settings.crlFile as string);
  if (new Set(onDevice ? [certFile, crlFile] : [keyFile, certFile, crlFile]).size !== (onDevice ? 2 : 3)) usage("The key, certificate and CRL files must be different files.");

  const baseOptions: StoreOptions = { ...storeOptions({ ...ctx, values: { ...v, dir } }, dir) };
  // The directory lock is taken before anything is written to a device or to disk, so a second run cannot interleave.
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const lock: LockHandle = await acquireLock(dir, { command: baseOptions.command, hostname: osHostname(), now: ctx.clock, breakStale: baseOptions.breakStaleLock });
  let lockPassed = false;
  try {
  const options: StoreOptions = { ...baseOptions, lock };
  const statePath = join(dir, options.stateFile as string);
  const targets = [statePath, ...(onDevice ? [] : [withinDir(dir, keyFile)]), withinDir(dir, certFile), withinDir(dir, crlFile), join(dir, "crls", "000001.crl.pem")];
  const present: string[] = [];
  for (const target of targets) if (await exists(target)) present.push(target);
  if (present.length > 0) {
    throw new EzError(5, "already_exists", `Refusing to overwrite existing files: ${present.join(", ")}. Nothing was changed.`, { files: present });
  }

  // YubiKey preflight: read-only checks and the review, before any prompt for a secret.
  const io = useYubiKey ? ykIo(ctx) : undefined;
  const handles: DeviceHandle[] = [];
  const slot = useYubiKey ? parseSlot(settings.slot as string) : EZ_DEFAULTS.slot;
  const touchPolicy = settings.touchPolicy as TouchPolicy;
  const keyType = useYubiKey ? pivKeyType(algorithm) : "";
  const slotCertificate = !flag(v, "no-slot-certificate");
  const overwriteFlag = str(v, "overwrite-slot");
  if (overwriteFlag !== undefined && parseSlot(overwriteFlag) !== slot) usage(`--overwrite-slot must name the chosen slot (${slot}).`);
  const overwrite = overwriteFlag !== undefined;
  if (useYubiKey && io !== undefined) {
    const secondText = settings.secondSerial as string;
    if (onDevice && secondText !== "") usage("--second-yubikey-serial applies only to an imported key (a key generated on a YubiKey cannot be copied).");
    const serialText = settings.yubikeySerial as string;
    for (const text of secondText === "" ? [serialText] : [serialText, secondText]) {
      const handle = await DeviceHandle.open(io, {
        serial: text === "" ? undefined : parseSerial(text),
        slot,
        write: true,
        overwrite,
        keyType,
        allowLastPinAttempt: io.allowLastPinAttempt,
      });
      if (handles.some((h) => h.serial === handle.serial)) usage("The two YubiKeys must be different devices.");
      handles.push(handle);
    }
    if (flag(v, "protect-management-key") && handles.some((h) => h.target.management !== "default")) {
      usage("--protect-management-key applies only to a YubiKey that still has the factory management key.");
    }
    const review = { action: onDevice ? ("generate" as const) : ("import" as const), keyType, touchPolicy, backupFile: onDevice ? undefined : withinDir(dir, keyFile), slotCertificate, overwrite };
    await ctx.say(renderYubiKeyReview(handles, review));
    await acknowledgeWrites(io, handles, review);
    if (flag(v, "protect-management-key")) for (const handle of handles) await handle.acknowledgeProtect();
  }

  const now = ctx.clock();
  const created: { signer: RootSigner; key?: ReturnType<typeof generateSoftwareKey> } = { signer: undefined as never };
  const rootTouch = { onTouch: (item: SignItem) => void ctx.say(touchNotice(handles[0]?.serial ?? 0, item)) };
  let keyPem: string | undefined;
  let yubikeySigner: YubiKeySigner | undefined;
  let testSigners: YubiKeySigner[] = [];
  let backupPassphrase: Buffer | undefined;
  const protectedSerials: number[] = [];
  const writtenSerials: number[] = [];
  try {
    if (!onDevice) {
      const passphrase = await ctx.prompter.passphrase({ create: true, fromStdin: flag(v, "passphrase-stdin") });
      const key = generateSoftwareKey(algorithm);
      created.key = key;
      created.signer = new SoftwareSigner(key.privateKey);
      try {
        keyPem = encryptPkcs8(key.exportPkcs8(), passphrase);
      } catch (error) {
        passphrase.fill(0);
        throw error;
      }
      // An imported key keeps the passphrase until the backup has been read back and decrypted (before any device write).
      if (useYubiKey) backupPassphrase = passphrase;
      else passphrase.fill(0);
    }
    if (useYubiKey) {
      // Every PIN is read and checked before anything is changed on any device, so a typo changes nothing.
      for (const handle of handles) await handle.verifyPin();
      for (const handle of handles) {
        if (flag(v, "protect-management-key")) {
          await handle.protectManagementKey();
          protectedSerials.push(handle.serial);
          ctx.progress.completed.push(`management-key-protected:${handle.serial}`);
        }
        await handle.checkManagement();
      }
    }
    if (onDevice) {
      const handle = handles[0] as DeviceHandle;
      const management = await handle.management();
      const spki = await (io as YkIo).client.generate({ serial: handle.serial, slot, keyType, touchPolicy, overwrite, management: management.spec, pin: management.pin });
      ctx.progress.completed.push("yubikey-key-generated");
      await handle.assertHolds(spki);
      yubikeySigner = handle.signer(spki);
      created.signer = yubikeySigner;
    }
    const signer = created.signer;
    const [root] = await signPrepared(signer, [prepareRoot(signer, { subject, now, validityDays: rootDays, pathLen })] as const, { events: rootTouch });
    const [crl] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: now, validityDays: crlValidity, entries: [] })] as const, { events: rootTouch });
    const slotWarnings: string[] = [];

    if (useYubiKey && !onDevice && created.key !== undefined) {
      // Backup first, then the devices: the key never exists only on a device.
      const keyPath = withinDir(dir, keyFile);
      await fs.mkdir(dirname(keyPath), { recursive: true, mode: 0o700 });
      await createImmutable(keyPath, Buffer.from(keyPem as string), 0o600);
      ctx.progress.files.key = keyPath;
      ctx.progress.completed.push("backup-written");
      await ctx.dependencies.afterBackupWritten?.(keyPath);
      // The backup must be the file that was meant and must restore this root's key before any device is written.
      const onDisk = await fs.readFile(keyPath);
      if (!onDisk.equals(Buffer.from(keyPem as string))) {
        throw new EzError(9, "backup_verify_failed", "The backup key file on disk is not what was written; no YubiKey was touched.");
      }
      const restored = new SoftwareSigner(decryptKeyFile(onDisk.toString("utf8"), backupPassphrase as Buffer));
      const restoredSpki = restored.spkiDer;
      restored.close();
      if (!restoredSpki.equals(root.certificate.spkiDer)) {
        throw new EzError(9, "backup_verify_failed", "The backup key file does not restore this root's key; no YubiKey was touched.");
      }
      backupPassphrase?.fill(0);
      backupPassphrase = undefined;
      for (const handle of handles) {
        const management = await handle.management();
        const pkcs8 = created.key.exportPkcs8();
        try {
          await (io as YkIo).client.putKey({ serial: handle.serial, slot, touchPolicy, overwrite, management: management.spec, pin: management.pin, keyDer: pkcs8 });
        } finally {
          pkcs8.fill(0);
        }
        writtenSerials.push(handle.serial);
        ctx.progress.completed.push(`yubikey-imported:${handle.serial}`);
        await handle.assertHolds(root.certificate.spkiDer);
      }
      yubikeySigner = handles[0]?.signer(root.certificate.spkiDer);
      testSigners = handles.slice(1).map((h) => h.signer(root.certificate.spkiDer));
    }

    const state = initialState({
      origin: "generated",
      subject: subject as unknown as Record<string, string>,
      subjectDn: formatSubject(subject),
      root: root.certificate,
      keyAlgorithm: algorithm,
      pathLen: pathLen ?? null,
      key: useYubiKey
        ? {
            storage: "yubikey",
            file: onDevice ? null : keyFile,
            kdf: onDevice ? null : { name: "pbkdf2-hmac-sha256", iterations: KEY_FILE_ITERATIONS },
            yubikey: {
              slot,
              keyType,
              generatedOnDevice: onDevice,
              pinPolicy: "always",
              touchPolicy,
              devices: handles.map((h) => ({ serial: h.serial, firmware: h.target.info.device.firmware, fips: h.target.info.device.fips, addedAt: now.toISOString() })),
            },
          }
        : { storage: "software", file: keyFile, kdf: { name: "pbkdf2-hmac-sha256", iterations: KEY_FILE_ITERATIONS }, yubikey: null },
      crl: crl.crl,
      certificateFile: certFile,
      crlCopyFile: crlFile,
      defaults: { intermediateValidityDays: intermediateDays, crlValidityDays: crlValidity },
      now,
    });
    lockPassed = true;
    const store = await EzStore.create(options, state, initialArtifacts(state, { rootDer: root.der, crlDer: crl.der, ...(useYubiKey ? {} : { keyFilePem: keyPem }) }));
    try {
      ctx.progress.completed.push("root-created");
      const files = {
        state: statePath,
        ...(onDevice ? {} : { key: withinDir(dir, keyFile) }),
        certificate: withinDir(dir, certFile),
        crl: withinDir(dir, crlFile),
      };
      Object.assign(ctx.progress.files, files);
      await ctx.summary(
        [
          "",
          `Root created: ${formatSubject(subject)}`,
          `  SHA-256 fingerprint  ${root.certificate.fingerprint}`,
          ...(onDevice
            ? [`  Key                  on YubiKey ${handles[0]?.serial ?? ""}, slot ${slot} (generated on the device; NO backup exists)`]
            : [`  Key file             ${(files as { key: string }).key}  (encrypted; back it up and remember the passphrase)`]),
          ...(useYubiKey && !onDevice ? [`  YubiKey              ${handles.map((h) => h.serial).join(", ")}, slot ${slot}`] : []),
          `  Certificate          ${files.certificate}`,
          "",
        ].join("\n"),
      );
      if (useYubiKey && slotCertificate && io !== undefined) {
        for (const handle of handles) {
          try {
            const management = await handle.management();
            await io.client.putCertificate({ serial: handle.serial, slot, overwrite: handle.target.occupied, management: management.spec, pin: management.pin, certificateDer: root.der });
            ctx.progress.completed.push(`slot-certificate:${handle.serial}`);
          } catch (error) {
            slotWarnings.push(`slot_certificate_failed:${handle.serial}`);
            await ctx.say(`The root was created, but its certificate could not be stored in slot ${slot} of YubiKey ${handle.serial} (${error instanceof EzError ? error.message : "unknown error"}). It is in ${files.certificate}.\n`);
          }
        }
      }
      if (useYubiKey && !onDevice && yubikeySigner !== undefined) {
        // A real signature with the stored key proves the import end to end (PIN, and a touch if the policy asks for it).
        try {
          for (const tester of [yubikeySigner, ...testSigners]) {
            await signBatch(tester, [{ id: "test", description: "a test challenge (nothing is issued)", data: randomBytes(32) }], { events: { onTouch: (item) => void ctx.say(touchNotice(tester.serial, item)) } });
          }
          ctx.progress.completed.push("test-signature");
        } catch (error) {
          await ctx.say("The root was created and the key imported, but the test signature failed. The state is valid; try renew-crl to retry signing.\n");
          throw error;
        }
      }
      return {
        data: {
          command: "generate-ca",
          dir,
          root: {
            subject: formatSubject(subject),
            fingerprint: root.certificate.fingerprint,
            spkiSha256: root.certificate.spkiSha256,
            serial: root.certificate.serialHex,
            notBefore: root.certificate.notBefore.toISOString(),
            notAfter: root.certificate.notAfter.toISOString(),
            keyAlgorithm: algorithm,
            extIdHint: state.root.extIdHint,
          },
          crl: { number: 1, nextUpdate: (crl.crl.nextUpdate as Date).toISOString() },
          key: useYubiKey
            ? { storage: "yubikey", slot, keyType, generatedOnDevice: onDevice, touchPolicy, serials: handles.map((h) => h.serial), managementKeyProtected: protectedSerials, backupFile: onDevice ? null : (files as { key: string }).key }
            : { storage: "software" },
          files,
          defaults: state.defaults,
          ...(slotWarnings.length === 0 ? {} : { warnings: slotWarnings }),
        },
        next: [
          onDevice
            ? "There is NO backup of this root key: protect the YubiKey and its PIN and PUK."
            : `Back up ${(files as { key: string }).key} somewhere safe, apart from the passphrase.`,
          "hemlig pki ca create --kind EXTERNAL_INTERMEDIATE ... (then) hemlig pki ez sign-cert <ca-id> --environment <env>",
        ],
      };
    } finally {
      await store.close();
    }
  } catch (error) {
    if (ctx.progress.completed.includes("backup-written") && !ctx.progress.completed.includes("root-created")) {
      ctx.progress.recovery = [
        `No state file was written and nothing was published. The backup key file ${ctx.progress.files.key ?? ""} exists.`,
        writtenSerials.length === 0 ? "No YubiKey was written." : `YubiKey(s) already written: ${writtenSerials.join(", ")} (slot ${slot}).`,
        `Delete ${dir} and rerun generate-ca${writtenSerials.length === 0 ? "" : ` with --overwrite-slot ${slot}`}; do not reuse this backup.`,
      ].join(" ");
    }
    throw error;
  } finally {
    backupPassphrase?.fill(0);
    created.signer?.close();
    yubikeySigner?.close();
    for (const tester of testSigners) tester.close();
    for (const handle of handles) handle.close();
  }
  } finally {
    if (!lockPassed) await lock.release();
  }
};

/** `import-key`: puts the backup key into a (another) YubiKey. */
const importKey = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const dir = directoryOf(v);
  const store = await EzStore.open(storeOptions(ctx, dir));
  const handles: DeviceHandle[] = [];
  const protectedSerials: number[] = [];
  try {
    const state = store.state;
    const record = state.key.yubikey;
    if (state.key.file === null) {
      throw new EzError(5, "key_not_exportable", "This root's key was generated on a YubiKey and has no backup file; it cannot be copied to another device.");
    }
    const slot = record?.slot ?? parseSlot(str(v, "slot") ?? EZ_DEFAULTS.slot);
    if (record !== null && str(v, "slot") !== undefined && parseSlot(str(v, "slot") as string) !== record.slot) usage(`This root's YubiKey slot is ${record.slot}.`);
    const touchPolicy = (record?.touchPolicy ?? str(v, "touch-policy") ?? EZ_DEFAULTS.touchPolicy) as TouchPolicy;
    if (!TOUCH_POLICIES.includes(touchPolicy)) usage(`--touch-policy must be one of ${TOUCH_POLICIES.join(", ")}.`);
    if (record !== null && str(v, "touch-policy") !== undefined && str(v, "touch-policy") !== record.touchPolicy) usage(`This root's touch policy is ${record.touchPolicy}.`);
    const overwriteFlag = str(v, "overwrite-slot");
    if (overwriteFlag !== undefined && parseSlot(overwriteFlag) !== slot) usage(`--overwrite-slot must name the chosen slot (${slot}).`);
    const overwrite = overwriteFlag !== undefined;
    const io = ykIo(ctx);
    const keyType = pivKeyType(state.root.keyAlgorithm);
    const serialText = str(v, "yubikey-serial");
    const handle = await DeviceHandle.open(io, { serial: serialText === undefined ? undefined : parseSerial(serialText), slot, write: true, overwrite, keyType, allowLastPinAttempt: io.allowLastPinAttempt });
    handles.push(handle);
    assertKeyTypeSupported(handle.target.info.device.firmware, keyType);
    if (flag(v, "protect-management-key") && handle.target.management !== "default") usage("--protect-management-key applies only to a YubiKey that still has the factory management key.");
    const slotCertificate = !flag(v, "no-slot-certificate");
    const review = { action: "import" as const, keyType, touchPolicy, backupFile: store.keyFilePath, slotCertificate, overwrite };
    await ctx.say(renderYubiKeyReview(handles, review));
    await acknowledgeWrites(io, handles, review);
    if (flag(v, "protect-management-key")) await handle.acknowledgeProtect();

    const keyPath = store.keyFilePath as string;
    const pem = await readBounded(keyPath, 65536, "key file");
    const passphrase = await ctx.prompter.passphrase({ create: false, fromStdin: flag(v, "passphrase-stdin") });
    let privateKey;
    try {
      privateKey = decryptKeyFile(pem.toString("utf8"), passphrase);
    } finally {
      passphrase.fill(0);
    }
    const software = new SoftwareSigner(privateKey);
    store.assertSigner(software.spkiDer);
    software.close();
    const signer = handle.signer(store.rootCertificate.spkiDer);
    try {
      await handle.verifyPin();
      if (flag(v, "protect-management-key")) {
        await handle.protectManagementKey();
        protectedSerials.push(handle.serial);
        ctx.progress.completed.push(`management-key-protected:${handle.serial}`);
      }
      await handle.checkManagement();
      const management = await handle.management();
      const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
      try {
        await io.client.putKey({ serial: handle.serial, slot, touchPolicy, overwrite, management: management.spec, pin: management.pin, keyDer: pkcs8 });
      } finally {
        pkcs8.fill(0);
      }
      ctx.progress.completed.push(`yubikey-imported:${handle.serial}`);
      await handle.assertHolds(store.rootCertificate.spkiDer);
      await store.recordYubiKey({
        slot,
        keyType,
        generatedOnDevice: false,
        pinPolicy: "always",
        touchPolicy,
        device: { serial: handle.serial, firmware: handle.target.info.device.firmware, fips: handle.target.info.device.fips },
      });
      ctx.progress.completed.push("state-updated");
      const warnings: string[] = [];
      if (slotCertificate) {
        try {
          await io.client.putCertificate({ serial: handle.serial, slot, overwrite: handle.target.occupied, management: management.spec, pin: management.pin, certificateDer: store.rootCertificate.der });
        } catch (error) {
          warnings.push(`slot_certificate_failed:${handle.serial}`);
          await ctx.say(`The key was imported, but the root certificate could not be stored in the slot (${error instanceof EzError ? error.message : "unknown error"}).\n`);
        }
      }
      await signBatch(signer, [{ id: "test", description: "a test challenge (nothing is issued)", data: randomBytes(32) }], {
        events: { onTouch: (item) => void ctx.say(touchNotice(handle.serial, item)) },
      });
      ctx.progress.completed.push("test-signature");
      return {
        data: {
          command: "import-key",
          root: { fingerprint: store.rootCertificate.fingerprint },
          yubikey: { serial: handle.serial, firmware: handle.target.info.device.firmware, slot, keyType, touchPolicy, managementKeyProtected: protectedSerials.includes(handle.serial) },
          ...(warnings.length === 0 ? {} : { warnings }),
        },
        next: [state.key.storage === "software" ? "Signing now uses the YubiKey; the key file is kept as the backup." : "Add this YubiKey's serial to your records."],
      };
    } finally {
      signer.close();
    }
  } finally {
    for (const handle of handles) handle.close();
    await store.close();
  }
};

/**
 * `add-yubikey`: records another YubiKey that already holds this root's key (imported there outside Hemlig). Read-only on
 * the device (`info`, then one test signature); the state gains the device only after the typed confirm and a verified signature.
 */
const addYubiKey = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const store = await EzStore.open(storeOptions(ctx, directoryOf(v)));
  let handle: DeviceHandle | undefined;
  let signer: YubiKeySigner | undefined;
  try {
    const state = store.state;
    const record = state.key.yubikey;
    if (state.key.storage !== "yubikey" || record === null) {
      throw new EzError(2, "key_storage_unsupported", "This root's key is a software key. To put it on a YubiKey use import-key; add-yubikey records a second YubiKey for a root that already lives on one.");
    }
    const recorded = record.devices.map((d) => d.serial);
    const flagged = str(v, "yubikey-serial") === undefined ? undefined : parseSerial(str(v, "yubikey-serial") as string);
    const alreadyRecorded = (serial: number): EzError =>
      new EzError(5, "yubikey_already_recorded", `YubiKey ${serial} is already recorded for this root (recorded: ${recorded.join(", ")}); nothing changed.`);
    if (flagged !== undefined && recorded.includes(flagged)) throw alreadyRecorded(flagged);
    const io = ykIo(ctx);
    handle = await DeviceHandle.open(io, { serial: flagged, slot: record.slot, write: false, overwrite: false, allowLastPinAttempt: io.allowLastPinAttempt });
    if (recorded.includes(handle.serial)) throw alreadyRecorded(handle.serial);
    const key = handle.target.info.key;
    if (key === null) throw new EzError(5, "slot_empty", `Slot ${record.slot} of YubiKey ${handle.serial} holds no key. The key must be in slot ${record.slot}, the root's recorded slot.`);
    const root = store.rootCertificate;
    if (key.keyType !== record.keyType || !key.spkiDer.equals(root.spkiDer)) {
      throw new EzError(
        5,
        "key_mismatch",
        `Slot ${record.slot} of YubiKey ${handle.serial} does not hold this root's key (${key.keyType}, SPKI SHA-256 ${sha256Hex(key.spkiDer)}; the root's key is ${record.keyType}, SPKI SHA-256 ${root.spkiSha256}). Nothing changed.`,
        { slotSpkiSha256: sha256Hex(key.spkiDer), rootSpkiSha256: root.spkiSha256 },
      );
    }
    const warnings: string[] = [];
    const slotCertificate = handle.target.info.certificateDer;
    if (slotCertificate === null) warnings.push("slot_certificate_missing");
    else if (!slotCertificate.equals(root.der)) warnings.push("slot_certificate_not_root");
    await ctx.prompter.requireConfirmTerminal("record");
    await ctx.say(
      renderAddYubiKeyReview({
        root: rootLabel(root),
        device: handle.target.info.device,
        slot: record.slot,
        keyType: key.keyType,
        pinPolicy: key.pinPolicy,
        touchPolicy: key.touchPolicy,
        recorded,
        warnings: warnings.map((w) => warningText(w)),
      }),
    );
    const confirmation = await ctx.prompter.confirm("record");
    const serial = handle.serial;
    signer = handle.signer(root.spkiDer);
    // The test signature is verified under the root's key by signBatch; only then is the device recorded.
    await signBatch(signer, [{ id: "test", description: "a test challenge (nothing is issued)", data: randomBytes(32) }], {
      events: { onTouch: (item) => void ctx.say(touchNotice(serial, item)) },
      confirm: () => {
        if (!consumeConfirmation(confirmation, "record")) throw new EzError(2, "confirmation_declined", "Signing was attempted without the typed confirmation.");
      },
    });
    ctx.progress.completed.push("test-signature");
    await store.recordYubiKey({
      slot: record.slot,
      keyType: record.keyType,
      generatedOnDevice: record.generatedOnDevice,
      pinPolicy: record.pinPolicy,
      touchPolicy: record.touchPolicy,
      device: { serial, firmware: handle.target.info.device.firmware, fips: handle.target.info.device.fips },
    });
    return {
      data: {
        command: "add-yubikey",
        root: { fingerprint: root.fingerprint },
        yubikey: { serial, firmware: handle.target.info.device.firmware, slot: record.slot, keyType: record.keyType, pinPolicy: key.pinPolicy, touchPolicy: key.touchPolicy },
        devices: store.state.key.yubikey?.devices.map((d) => d.serial) ?? [],
        warnings,
      },
      next: ["Either YubiKey can now sign. Connect only one at a time, or pass --yubikey-serial N."],
    };
  } finally {
    signer?.close();
    handle?.close();
    await store.close();
  }
};

const pathLength = (text: string): number | undefined => {
  if (text === "") return undefined;
  const value = Number(text);
  if (!/^\d+$/.test(text) || !Number.isSafeInteger(value) || value < 1) {
    throw new EzError(2, "invalid_input", "The path length limit must be a whole number of at least 1 (or blank for none).");
  }
  return value;
};

// ---------------------------------------------------------------------------------------------------------------------
// sign-cert
// ---------------------------------------------------------------------------------------------------------------------

const checkOnlineCa = (ca: PkiCaDetail, environment: string): void => {
  if (ca.environment !== environment) {
    throw new EzError(5, "environment_mismatch", `That CA is in environment ${ca.environment}, not ${environment}.`);
  }
  if (ca.kind !== "EXTERNAL_INTERMEDIATE") {
    throw new EzError(5, "ca_not_external", "Only an EXTERNAL_INTERMEDIATE CA is signed by an offline root.");
  }
};

const signCert = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const offline = flag(v, "offline");
  const reference = ctx.operands[0] as string;
  const dir = directoryOf(v);
  if (offline && !isCaId(reference)) usage("Offline, <ca> must be the ca-<uuid> ID (a name needs the server).");
  const environmentFlag = environmentOf(ctx, !offline);
  const environment = environmentFlag ?? "";
  const expectedSpki = str(v, "expect-spki-sha256")?.toLowerCase();
  if (expectedSpki !== undefined && !/^[0-9a-f]{64}$/.test(expectedSpki)) usage("--expect-spki-sha256 must be 64 hex characters.");
  if (!offline) {
    for (const name of ["out", "chain-out", "crl-out", "expect-spki-sha256"]) {
      if (v[name] !== undefined) usage(`--${name} applies only with --offline.`);
    }
  } else if (str(v, "csr") === undefined) usage("--offline needs --csr FILE.");

  const store = await EzStore.open(storeOptions(ctx, dir));
  try {
    assertNoPendingRevocation(store);
    const state = store.state;
    const root = store.rootCertificate;
    const session = offline ? undefined : await sessionOf(ctx);
    let caId = reference;
    let csr: ValidatedCsr;
    let source: string;
    let ca: PkiCaDetail | undefined;
    if (session !== undefined) {
      caId = isCaId(reference) ? reference : await resolveCa(session.client, session.token, reference, environment);
      ca = await fetchCa(session, caId);
      checkOnlineCa(ca, environment);
      const ours = state.issued.find((e) => e.caId === caId && (e.status === "signed" || e.status === "activated"));
      if (ca.status === "ACTIVE") {
        if (ours !== undefined && ours.fingerprint === ca.fingerprint) {
          await store.markActivated(ours.serial);
          return { data: { command: "sign-cert", caId, environment, serial: ours.serial, fingerprint: ours.fingerprint, activated: true, alreadyActive: true, ca: { status: ca.status, version: ca.version } } };
        }
        throw new EzError(5, "ca_activated_elsewhere", "That CA is already active with a certificate this root state did not issue.");
      }
      if (ca.status !== "PENDING_CERTIFICATE" || ca.csrPem === undefined) {
        throw new EzError(5, "ca_not_pending", `That CA is ${ca.status}, not waiting for a certificate.`);
      }
      csr = validateCsr(ca.csrPem, {
        spkiSha256: ca.key.spkiSha256,
        subject: subjectOf(ca.subject),
        nameConstraints: ca.requestedConstraints?.nameConstraints ?? null,
        extendedKeyUsages: ca.requestedConstraints?.extendedKeyUsages ?? null,
        rootSubjectDer: root.subjectDer,
      });
      const csrFile = str(v, "csr");
      if (csrFile !== undefined) {
        const given = decodeCsrInput(await readBounded(withinDir(dir, csrFile), 32768, "CSR file"));
        if (!given.equals(csr.der)) throw new EzError(5, "csr_key_mismatch", "The --csr file is not the CSR the server holds for this CA.");
      }
      source = `Hemlig server ${session.origin.origin}`;
    } else {
      const file = withinDir(dir, str(v, "csr") as string);
      csr = validateCsr(decodeCsrInput(await readBounded(file, 32768, "CSR file")), { spkiSha256: expectedSpki, rootSubjectDer: root.subjectDer });
      source = `file ${file}`;
    }
    const conflict = state.issued.find((e) => e.caId === caId && e.status !== "abandoned" && e.csrSha256 !== csr.sha256);
    if (conflict !== undefined) {
      throw new EzError(5, "issued_conflict", `A certificate (serial ${conflict.serial}) was already issued for ${caId} from a different CSR.`, { serial: conflict.serial });
    }
    const prior = state.issued.find((e) => e.caId === caId && e.csrSha256 === csr.sha256 && (e.status === "signed" || e.status === "activated"));

    // Root registration and the server cross-checks come before any prompt.
    let ext: Awaited<ReturnType<typeof findExternalRoot>> = undefined;
    if (session !== undefined) {
      ext = await findExternalRoot(session, state.root);
      // The first server response carries its clock; check it before anything is signed or uploaded.
      assertClockSkew(session, ctx.clock());
      await store.checkServer(await fetchServerView(session, ext, store.rootCertificate));
    }

    const outputs = {
      out: withinDir(dir, str(v, "out") ?? `${caId}.cert.pem`),
      chain: str(v, "chain-out") === undefined ? undefined : withinDir(dir, str(v, "chain-out") as string),
      crl: str(v, "crl-out") === undefined ? undefined : withinDir(dir, str(v, "crl-out") as string),
    };
    if (offline && prior === undefined) {
      // Like writeOutput: an existing file that already holds exactly what would be written (the root, the current CRL) is fine.
      const rootPem = Buffer.from(pemOf(root.der, "CERTIFICATE"));
      const wanted = new Map<string, Buffer | undefined>([
        [outputs.out, undefined],
        ...(outputs.chain === undefined ? [] : [[outputs.chain, rootPem] as const]),
      ]);
      // --crl-out is decided below, once it is known whether this run renews the CRL.
      for (const path of [outputs.out, outputs.chain]) {
        if (path === undefined || !(await exists(path))) continue;
        const expected = wanted.get(path);
        const existing = expected === undefined ? undefined : await fs.readFile(path).catch(() => undefined);
        if (expected === undefined || existing === undefined || !existing.equals(expected)) {
          throw new EzError(5, "already_exists", `${path} already exists; nothing was overwritten.`, { files: [path] });
        }
      }
    }

    const keyDefault = store.keyFilePath ?? "";
    const settings = await runSettingsForm(ctx, `hemlig pki ez sign-cert: ${caId}`, [
      { id: "ca", label: "CA ID", kind: "readonly", value: caId },
      { id: "environment", label: "Environment", kind: "readonly", value: environment === "" ? "(not given)" : environment },
      { id: "subject", label: "Subject", kind: "readonly", value: describeName(csr.subject) },
      { id: "root", label: "Root", kind: "readonly", value: rootLabel(root).subjectDn },
      { id: "validity", label: "Intermediate validity", kind: "text", value: str(v, "validity") ?? `${state.defaults.intermediateValidityDays}d`, hint: "clamped to the root's end", validate: checked((x) => days(x, "Validity")) },
      { id: "crlValidity", label: "CRL validity", kind: "text", value: str(v, "crl-validity") ?? `${state.defaults.crlValidityDays}d`, hint: "if the CRL is renewed", validate: checked(crlDays) },
      { id: "renewBefore", label: "CRL renewal window", kind: "text", value: str(v, "renew-before") ?? `${EZ_DEFAULTS.crlRenewBeforeDays}d`, hint: "renew when fewer days remain", validate: checked((x) => days(x, "Renewal window")) },
      state.key.storage === "yubikey"
        ? { id: "key", label: "Root key", kind: "readonly" as const, value: `YubiKey slot ${state.key.yubikey?.slot ?? ""} (serial ${(state.key.yubikey?.devices ?? []).map((d) => d.serial).join(", ")})` }
        : { id: "key", label: "Root key file", kind: "text" as const, value: str(v, "key") ?? keyDefault, validate: checked((x) => x.length > 0 || usage("empty")) },
      ...(offline ? [{ id: "out", label: "Certificate output", kind: "text" as const, value: outputs.out, validate: checked((x) => x.length > 0 || usage("empty")) }] : []),
    ]);
    const finalValues: Values = state.key.storage === "yubikey" ? { ...v } : { ...v, key: settings.key };
    const certPath = offline ? withinDir(dir, settings.out as string) : outputs.out;
    const now = ctx.clock();
    const validityDays = days(settings.validity as string, "Validity");
    const crlValidity = crlDays(settings.crlValidity as string);
    const renewBefore = days(settings.renewBefore as string, "Renewal window");
    const validity = computeIntermediateValidity({ now, days: validityDays, root, minimumDays: EZ_DEFAULTS.intermediateMinimumDays });
    const serialBytes = randomSerial();
    const serial = serialHex(serialBytes);
    const needCert = prior === undefined;
    const needCrl = store.crlDue(renewBefore, now);
    if (offline && prior === undefined && outputs.crl !== undefined && (await exists(outputs.crl))) {
      // A renewed CRL is written to --crl-out after signing, so an existing file is acceptable only where it cannot clash: the
      // state's own CRL copy (rewritten with the renewed CRL) when renewing, or a file already holding the current CRL.
      const current = await store.readCurrentCrl();
      const existing = await fs.readFile(outputs.crl).catch(() => undefined);
      const identical = current !== undefined && existing !== undefined && existing.equals(Buffer.from(pemOf(current.der, "X509 CRL")));
      const isCopy = outputs.crl === withinDir(dir, state.crl.copyFile);
      if (needCrl ? !isCopy : !identical) {
        throw new EzError(5, "already_exists", `${outputs.crl} already exists${needCrl ? " and the root CRL is renewed in this run" : ""}; nothing was signed or overwritten.`, { files: [outputs.crl] });
      }
    }
    const crlPreview = needCrl ? { number: state.crl.lastNumber + 1, nextUpdate: new Date(store.nextCrlThisUpdate(now).getTime() + crlValidity * DAY_MS) } : undefined;

    let confirmation: Confirmation | undefined;
    if (needCert || needCrl) {
      await ctx.prompter.requireConfirmTerminal("sign");
      await ctx.say(
        needCert
          ? renderSignReview({ caId, environment: environment === "" ? "(not given)" : environment, source, csr, serial, notBefore: validity.notBefore, notAfter: validity.notAfter, root: rootLabel(root), crl: crlPreview, expectedSpki: expectedSpki !== undefined || !offline })
          : renderCrlReview({ root: rootLabel(root), crl: crlPreview as { number: number; nextUpdate: Date }, why: `the certificate for ${caId} is already signed (serial ${prior.serial}); the root CRL is due` }),
      );
      confirmation = await ctx.prompter.confirm("sign");
    }
    let issued: IssueResult = {};
    if (needCert || needCrl) {
      const signer = await unlockSigner({ ...ctx, values: finalValues }, store);
      try {
        issued = await issue(
          ctx,
          store,
          signer,
          {
            cert: {
              reservation: {
                serial,
                caId,
                environment: offline ? (environment === "" ? null : environment) : (ca?.environment ?? environment),
                adminOrigin: session?.origin.origin ?? null,
                subjectDn: describeName(csr.subject),
                subjectKey: csr.subject.key,
                csrSha256: csr.sha256,
                spkiSha256: csr.spkiSha256,
                notBefore: validity.notBefore,
                notAfter: validity.notAfter,
              },
              csr,
              serial: serialBytes,
              validity,
            },
            ...(needCrl ? { crl: { validityDays: crlValidity } } : {}),
          },
          confirmation,
        );
      } finally {
        signer.close();
      }
    } else {
      issued = { certificate: await resumeCertificate(store, prior) };
    }
    const certificate = issued.certificate as NonNullable<IssueResult["certificate"]>;
    const certParsed = parseCertificate(certificate.der);
    const rootPem = pemOf(root.der, "CERTIFICATE");
    const certPem = pemOf(certificate.der, "CERTIFICATE");
    const common = {
      command: "sign-cert",
      caId,
      environment: environment === "" ? null : environment,
      serial: certParsed.serialHex,
      fingerprint: certParsed.fingerprint,
      notBefore: certParsed.notBefore.toISOString(),
      notAfter: certParsed.notAfter.toISOString(),
      recovered: certificate.resumed,
    };
    const warnings = [...csr.warnings];
    const currentCrl = await store.readCurrentCrl();

    if (session === undefined) {
      await writeOutput(certPath, Buffer.from(certPem));
      ctx.progress.files.certificate = certPath;
      if (outputs.chain !== undefined) await writeOutput(outputs.chain, Buffer.from(rootPem));
      if (outputs.crl !== undefined && currentCrl !== undefined) await writeOutput(outputs.crl, Buffer.from(pemOf(currentCrl.der, "X509 CRL")));
      const chainFile = outputs.chain ?? withinDir(dir, state.root.certificateFile);
      const crlFile = outputs.crl ?? withinDir(dir, state.crl.copyFile);
      return {
        data: {
          ...common,
          certificateFile: certPath,
          chainFile,
          crlFile,
          root: { fingerprint: root.fingerprint },
          crl: { ...crlSummary(currentCrl), renewed: issued.crl !== undefined },
          activated: false,
          warnings,
        },
        next: [
          `Carry ${[certPath, chainFile, crlFile].join(", ")} to a machine that can reach the server, then:`,
          `hemlig pki ez activate ${caId} --environment ${environment === "" ? "<environment>" : environment} --certificate ${shellArg(certPath)} --chain ${shellArg(chainFile)} --crl ${shellArg(crlFile)}`,
        ],
      };
    }

    // Online: sync the root CRL, then activate (with the CRL only when the root is new to the server).
    let sync = await syncRootCrl(session, store, ext, ctx);
    const activation = await activateWithCertificate(session, {
      caId,
      certificatePem: certPem,
      chainPem: rootPem,
      certificateFingerprint: certParsed.fingerprint,
      ...(sync.registered || currentCrl === undefined ? {} : { rootCrlPem: pemOf(currentCrl.der, "X509 CRL") }),
    });
    ctx.progress.completed.push("activated");
    await store.markActivated(certParsed.serialHex);
    let extId = sync.extId;
    if (!sync.registered) {
      extId = activation.detail.parent?.type === "external" ? activation.detail.parent.id : state.root.extIdHint;
      if (currentCrl !== undefined) await store.recordUpload(session.origin.origin, extId, Number(currentCrl.number));
      sync = { registered: true, extId, uploaded: true, changed: true };
    }
    return {
      data: {
        ...common,
        certificateFile: join(store.dir, "issued", `${certParsed.serialHex}.pem`),
        root: { extId, fingerprint: root.fingerprint },
        crl: { ...crlSummary(currentCrl), renewed: issued.crl !== undefined, uploaded: sync.uploaded, changed: sync.changed },
        activated: true,
        alreadyActive: activation.alreadyActive,
        ca: { status: activation.detail.status, version: activation.detail.version },
        warnings,
      },
    };
  } finally {
    await store.close();
  }
};

const resumeCertificate = async (store: EzStore, entry: IssuedEntry): Promise<NonNullable<IssueResult["certificate"]>> => {
  const der = await store.readIssuedCertificate(entry);
  if (der === undefined) throw new EzError(5, "state_conflict", "The signed certificate file is missing.", { reason: "issued_missing" });
  return { der, entry, resumed: true };
};

// ---------------------------------------------------------------------------------------------------------------------
// activate (stateless)
// ---------------------------------------------------------------------------------------------------------------------

const activateCommand = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const dir = process.cwd();
  const certificateFile = str(v, "certificate");
  const chainFile = str(v, "chain");
  if (certificateFile === undefined || chainFile === undefined) usage("Supply --certificate and --chain.");
  const environment = environmentOf(ctx, true) as string;
  const certificate = parseCertificate(certificateBytes(await readBounded(withinDir(dir, certificateFile as string), 32768, "certificate file")));
  const root = parseCertificate(certificateBytes(await readBounded(withinDir(dir, chainFile as string), 32768, "chain file")));
  const rootCheck = validateRootCertificate(root.der);
  if (rootCheck.reasons.length > 0) {
    throw new EzError(5, "root_profile_invalid", `The chain file's root is not acceptable (${rootCheck.reasons.join(", ")}).`, { reasons: rootCheck.reasons });
  }
  if (!certificate.issuerDer.equals(root.subjectDer) || !verifyCertificateSignature(certificate, root.spkiDer)) {
    throw new EzError(5, "certificate_invalid", "The certificate is not signed by the root in the chain file.");
  }
  let crl: ParsedCrl | undefined;
  const crlFile = str(v, "crl");
  if (crlFile !== undefined) {
    const bytes = await readBounded(withinDir(dir, crlFile), 1048576, "CRL file");
    crl = parseCrl(bytes.toString("latin1").includes("-----BEGIN") ? fromPem(bytes.toString("latin1"), "X509 CRL") : bytes);
    if (!crl.issuerDer.equals(root.subjectDer) || !verifyCrlSignature(crl, root.spkiDer)) {
      throw new EzError(5, "crl_invalid", "The CRL is not signed by the root in the chain file.");
    }
    if (crl.entries.some((e) => e.serial === certificate.serialHex)) {
      throw new EzError(5, "crl_invalid", "The root CRL already lists this certificate as revoked.");
    }
  }
  const session = await sessionOf(ctx);
  const caId = isCaId(ctx.operands[0] as string) ? (ctx.operands[0] as string) : await resolveCa(session.client, session.token, ctx.operands[0] as string, environment);
  const ca = await fetchCa(session, caId);
  checkOnlineCa(ca, environment);
  if (ca.key.spkiSha256 !== certificate.spkiSha256) {
    throw new EzError(5, "csr_key_mismatch", "The certificate's key is not the CA key Hemlig holds.");
  }
  if (ca.status === "ACTIVE" && ca.fingerprint === certificate.fingerprint) {
    return { data: { command: "activate", caId, environment, fingerprint: certificate.fingerprint, activated: true, alreadyActive: true, ca: { status: ca.status, version: ca.version } } };
  }
  if (ca.status !== "PENDING_CERTIFICATE") throw new EzError(5, "ca_not_pending", `That CA is ${ca.status}, not waiting for a certificate.`);
  const ext = await findExternalRoot(session, { spkiSha256: root.spkiSha256, fingerprint: root.fingerprint });
  // The first server response carries its clock; check it before anything is signed or uploaded.
  assertClockSkew(session, ctx.clock());
  let uploaded = false;
  let changed: boolean | undefined;
  let skipped: string | undefined;
  if (ext !== undefined && crl !== undefined) {
    const server = ext.crl;
    const serverNumber = server === undefined ? -1n : BigInt(`0x${server.numberHex}`);
    const ours = crl.number ?? 0n;
    if (server?.sha256 === crl.sha256) skipped = "the server already has this CRL";
    else if (ours < serverNumber) skipped = "the server's root CRL is newer than the one supplied";
    else if (ours === serverNumber) throw new EzError(5, "state_forked", "The server's root CRL has the same number as the supplied one but different content: two copies of this root are signing.");
    else {
      // Never upload a CRL that drops a revocation the server already lists.
      assertCarriesServerRevocations(crl, await fetchServerCrl(session, ext, root));
      const response = await uploadRootCrl(session, ext.extId, { pem: pemOf(crl.der, "X509 CRL"), sha256: crl.sha256 });
      uploaded = true;
      changed = response.changed;
      ctx.progress.completed.push("crl-uploaded");
    }
  }
  const warnings: string[] = [];
  if (ext === undefined && crl === undefined) warnings.push("no_root_crl");
  const activation = await activateWithCertificate(session, {
    caId,
    certificatePem: pemOf(certificate.der, "CERTIFICATE"),
    chainPem: pemOf(root.der, "CERTIFICATE"),
    certificateFingerprint: certificate.fingerprint,
    ...(ext === undefined && crl !== undefined ? { rootCrlPem: pemOf(crl.der, "X509 CRL") } : {}),
  });
  return {
    data: {
      command: "activate",
      caId,
      environment,
      serial: certificate.serialHex,
      fingerprint: certificate.fingerprint,
      root: { extId: ext?.extId ?? `ext-${root.spkiSha256.slice(0, 40)}`, fingerprint: root.fingerprint },
      crl: crl === undefined ? undefined : { number: Number(crl.number), uploaded: uploaded || ext === undefined, changed, ...(skipped === undefined ? {} : { skipped }) },
      activated: true,
      alreadyActive: activation.alreadyActive,
      ca: { status: activation.detail.status, version: activation.detail.version },
      warnings,
    },
  };
};

/** A certificate file may be PEM or DER; a chain file holds the root (the first certificate). */
const certificateBytes = (bytes: Buffer): Buffer => {
  const text = bytes.toString("latin1");
  return text.includes("-----BEGIN") ? fromPem(text, "CERTIFICATE") : bytes;
};

// ---------------------------------------------------------------------------------------------------------------------
// revoke-cert
// ---------------------------------------------------------------------------------------------------------------------

const safeSubjectDn = (cert: ParsedCertificate): string => {
  try {
    return describeName(assertRestrictedName(cert.subjectDer, "external"));
  } catch {
    return "(unreadable subject)";
  }
};

/** A certificate this root issued: its issuer, signature and AKI are the root's, and it is not the root itself. */
const assertIssuedByRoot = (cert: ParsedCertificate, root: ParsedCertificate): ParsedCertificate => {
  if (cert.fingerprint === root.fingerprint || cert.spkiDer.equals(root.spkiDer)) {
    throw new EzError(5, "certificate_invalid", "That is the root certificate (or one with the root's key), not a certificate the root issued.");
  }
  if (!cert.issuerDer.equals(root.subjectDer) || !verifyCertificateSignature(cert, root.spkiDer)) {
    throw new EzError(5, "certificate_invalid", "That certificate was not issued by this root (its issuer or signature does not verify under the root's key).");
  }
  if (root.subjectKeyIdentifier === undefined || cert.authorityKeyIdentifier === undefined || !cert.authorityKeyIdentifier.equals(root.subjectKeyIdentifier)) {
    throw new EzError(5, "certificate_invalid", "That certificate's authority key identifier is not this root's subject key identifier.");
  }
  return cert;
};

const revokeCert = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const offline = flag(v, "offline");
  const reference = ctx.operands[0];
  const serialFlag = str(v, "serial");
  const certFile = str(v, "cert");
  if ([reference, serialFlag, certFile].filter((x) => x !== undefined).length !== 1) usage("Supply exactly one of <ca>, --serial HEX or --cert FILE.");
  const reason = str(v, "reason") as CrlReasonName | undefined;
  if (reason === undefined) usage("--reason is required (there is no default).");
  // certificateHold and aACompromise can only be repeated for a serial an adoption imported with that reason (checked below).
  if (!CRL_REASON_NAMES.includes(reason as CrlReasonName)) usage(`--reason must be one of ${NEW_REVOCATION_REASONS.join(", ")}.`);
  const invalidityText = str(v, "invalidity-date");
  const invalidityDate = invalidityText === undefined ? undefined : new Date(invalidityText);
  if (invalidityDate !== undefined && Number.isNaN(invalidityDate.getTime())) usage("--invalidity-date must be an ISO-8601 time.");
  if (offline && str(v, "crl-out") === undefined) usage("--offline needs --crl-out FILE.");
  if (!offline && str(v, "crl-out") !== undefined) usage("--crl-out applies only with --offline.");
  if (reference !== undefined && !isCaId(reference) && offline) usage("Offline, <ca> must be the ca-<uuid> ID.");
  const dir = directoryOf(v);
  const store = await EzStore.open(storeOptions(ctx, dir));
  try {
    const state = store.state;
    const root = store.rootCertificate;
    const session = offline ? undefined : await sessionOf(ctx);
    let caId: string | null = null;
    if (reference !== undefined) {
      caId = isCaId(reference) ? reference : await resolveCa((session as OnlineSession).client, (session as OnlineSession).token, reference, environmentOf(ctx, true) as string);
    }
    const live = (e: IssuedEntry): boolean => e.status === "signed" || e.status === "activated" || e.status === "imported";
    // A certificate the state never recorded (an adopted root's earlier intermediates): taken from --cert, or from the server
    // for a CA. It must verify under this root; it is recorded only after the typed confirm.
    let outside: { der: Buffer; caId: string | null; environment: string | null; adminOrigin: string | null } | undefined;
    let target: IssuedEntry[];
    if (certFile !== undefined) {
      const der = certificateBytes(await readBounded(withinDir(dir, certFile), 32768, "certificate file"));
      const cert = assertIssuedByRoot(parseCertificate(der), root);
      target = state.issued.filter((e) => e.serial === cert.serialHex);
      if (target.length === 0) outside = { der: cert.der, caId: null, environment: null, adminOrigin: null };
    } else {
      target = caId !== null ? state.issued.filter((e) => e.caId === caId && live(e)) : state.issued.filter((e) => e.serial === EzStore.canonicalSerial(serialFlag as string));
      if (target.length === 0 && caId !== null && session !== undefined) {
        const ca = await fetchCa(session, caId);
        if (ca.certificatePem !== undefined) {
          const cert = assertIssuedByRoot(parseCertificate(fromPem(ca.certificatePem, "CERTIFICATE")), root);
          // The server must not be able to attach a certificate this state already knows to a different CA.
          const known = state.issued.find((e) => e.serial === cert.serialHex);
          if (known !== undefined && (known.caId !== caId || (known.fingerprint !== null && known.fingerprint !== cert.fingerprint))) {
            throw new EzError(5, "state_conflict", `The server's certificate for ${caId} has serial ${cert.serialHex}, which this state already records for ${known.caId ?? "no CA"}; nothing was revoked.`, { reason: "serial_other_ca", serial: cert.serialHex });
          }
          outside = { der: cert.der, caId, environment: ca.environment, adminOrigin: session.origin.origin };
        }
      }
    }
    const certSource = certFile !== undefined ? `file ${withinDir(dir, certFile)}` : outside !== undefined && session !== undefined ? `server ${session.origin.origin}` : undefined;
    if (outside !== undefined) {
      const cert = parseCertificate(outside.der);
      target = [
        {
          serial: cert.serialHex,
          caId: outside.caId,
          environment: outside.environment,
          adminOrigin: outside.adminOrigin,
          subjectDn: safeSubjectDn(cert),
          subjectKey: "",
          csrSha256: null,
          spkiSha256: cert.spkiSha256,
          certificateFile: null,
          fingerprint: cert.fingerprint,
          notBefore: cert.notBefore.toISOString(),
          notAfter: cert.notAfter.toISOString(),
          status: "imported",
          signedAt: null,
          activatedAt: null,
        },
      ];
    }
    if (target.length !== 1) {
      throw new EzError(2, "unknown_serial", target.length === 0 ? "This root state has no such issued certificate. For a certificate issued before adoption, pass it with --cert FILE (online, a CA ID also works when the server holds its certificate)." : "More than one certificate matches; revoke by --serial.", {});
    }
    const entry = target[0] as IssuedEntry;
    const already = state.revoked.find((r) => r.serial === entry.serial);
    if (already === undefined && !NEW_REVOCATION_REASONS.includes(reason as CrlReasonName)) usage(`--reason must be one of ${NEW_REVOCATION_REASONS.join(", ")}.`);
    if (already !== undefined) {
      // The signed CRL carries what is recorded; a different reason or date would be shown but never signed.
      const recordedDate = already.invalidityDate === null ? undefined : Date.parse(already.invalidityDate);
      const askedDate = invalidityDate === undefined ? undefined : Math.floor(invalidityDate.getTime() / 1000) * 1000;
      if (already.reason !== reason || (askedDate !== undefined && askedDate !== recordedDate)) {
        const imported = !NEW_REVOCATION_REASONS.includes(already.reason);
        throw new EzError(5, "revocation_conflict", `Serial ${entry.serial} is already recorded as revoked (reason ${already.reason}${already.invalidityDate === null ? "" : `, invalidity date ${already.invalidityDate}`}); rerun with those values${imported ? ` (--reason ${already.reason} is accepted here only to match the imported revocation; it cannot be given for a new one)` : ""}.`, {
          reason: already.reason,
          invalidityDate: already.invalidityDate,
        });
      }
    }
    const unlisted = already !== undefined && already.listedInCrl === null;
    const renewBefore = EZ_DEFAULTS.crlRenewBeforeDays;
    const needSign = already === undefined || unlisted || store.crlDue(renewBefore);
    let ext: Awaited<ReturnType<typeof findExternalRoot>> = undefined;
    if (session !== undefined) {
      ext = await findExternalRoot(session, state.root);
      // The first server response carries its clock; check it before anything is signed or uploaded.
      assertClockSkew(session, ctx.clock());
      await store.checkServer(await fetchServerView(session, ext, store.rootCertificate));
      checkExpectedExt(str(v, "expect-ext-id"), ext);
    }
    const crlValidity = str(v, "crl-validity") === undefined ? state.defaults.crlValidityDays : crlDays(str(v, "crl-validity") as string);
    const now = ctx.clock();
    let issuedCrl: IssueResult["crl"];
    if (needSign) {
      await ctx.prompter.requireConfirmTerminal("revoke");
      await ctx.say(
        renderRevokeReview({
          caId: entry.caId,
          environment: entry.environment,
          subjectDn: entry.subjectDn,
          serial: entry.serial,
          reason: already?.reason ?? (reason as CrlReasonName),
          invalidityDate: already === undefined ? invalidityDate : already.invalidityDate === null ? undefined : new Date(already.invalidityDate),
          alsoListed: unlistedRevocations(store).filter((serial) => serial !== entry.serial),
          root: rootLabel(root),
          crl: { number: state.crl.lastNumber + 1, nextUpdate: new Date(store.nextCrlThisUpdate(now).getTime() + crlValidity * DAY_MS) },
          alreadyRevoked: already !== undefined,
          ...(certSource === undefined ? {} : { certificateSource: certSource, certificateFingerprint: entry.fingerprint ?? undefined }),
        }),
      );
      const confirmation = await ctx.prompter.confirm("revoke");
      const signer = await unlockSigner(ctx, store);
      try {
        if (outside !== undefined) await store.importIssued({ ...outside });
        // A serial already recorded (for example imported with certificateHold) is signed as recorded.
        if (already === undefined) await store.addRevocation({ serial: entry.serial, caId: entry.caId, reason: reason as CrlReasonName, invalidityDate });
        ctx.progress.completed.push("revocation-recorded");
        issuedCrl = (await issue(ctx, store, signer, { crl: { validityDays: crlValidity } }, confirmation)).crl;
      } finally {
        signer.close();
      }
    }
    const currentCrl = await store.readCurrentCrl();
    const data: Record<string, unknown> = {
      command: "revoke-cert",
      caId: entry.caId,
      serial: entry.serial,
      reason: state.revoked.find((r) => r.serial === entry.serial)?.reason ?? reason,
      crl: { ...crlSummary(currentCrl), renewed: issuedCrl !== undefined },
    };
    if (session === undefined) {
      const crlOut = withinDir(dir, str(v, "crl-out") as string);
      if (currentCrl !== undefined) await writeOutput(crlOut, Buffer.from(pemOf(currentCrl.der, "X509 CRL")));
      ctx.progress.files.crl = crlOut;
      return { data: { ...data, crlFile: crlOut }, next: [`On an online machine: hemlig pki ez upload-crl --crl ${shellArg(crlOut)} --root-cert ${shellArg(withinDir(dir, state.root.certificateFile))}`] };
    }
    if (ext === undefined) {
      if (entry.caId !== null) {
        throw new EzError(5, "revocation_not_applied", "The signed CRL was not uploaded: the server you are logged in to does not know this root, so the CA is not revoked there.", {
          caId: entry.caId,
          issuedBy: entry.adminOrigin ?? "",
          session: session.origin.origin,
          originDiffers: entry.adminOrigin !== null && entry.adminOrigin !== session.origin.origin,
        });
      }
      return { data: { ...data, uploaded: false, warnings: ["root_not_registered"] } };
    }
    const sync = await syncRootCrl(session, store, ext, ctx);
    let applied = sync.revokedCaIds?.includes(entry.caId ?? "") === true;
    if (!applied && entry.caId !== null) applied = (await fetchCa(session, entry.caId)).status === "REVOKED";
    if (entry.caId !== null && !applied) {
      throw new EzError(5, "revocation_not_applied", "The root CRL was uploaded but the server does not show the CA as revoked.", { caId: entry.caId });
    }
    return { data: { ...data, root: { extId: sync.extId }, uploaded: sync.uploaded, changed: sync.changed, revoked: entry.caId === null ? undefined : true, revokedCaIds: sync.revokedCaIds } };
  } finally {
    await store.close();
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// renew-crl and upload-crl
// ---------------------------------------------------------------------------------------------------------------------

const renewCrl = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const offline = flag(v, "offline");
  if (offline && str(v, "crl-out") === undefined) usage("--offline needs --crl-out FILE.");
  if (!offline && str(v, "crl-out") !== undefined) usage("--crl-out applies only with --offline.");
  const dir = directoryOf(v);
  const store = await EzStore.open(storeOptions(ctx, dir));
  try {
    assertNoPendingRevocation(store);
    const state = store.state;
    const session = offline ? undefined : await sessionOf(ctx);
    let ext: Awaited<ReturnType<typeof findExternalRoot>> = undefined;
    if (session !== undefined) {
      ext = await findExternalRoot(session, state.root);
      // The first server response carries its clock; check it before anything is signed or uploaded.
      assertClockSkew(session, ctx.clock());
      await store.checkServer(await fetchServerView(session, ext, store.rootCertificate));
      checkExpectedExt(str(v, "expect-ext-id"), ext);
    }
    const now = ctx.clock();
    const renewBefore = str(v, "renew-before") === undefined ? EZ_DEFAULTS.crlRenewBeforeDays : days(str(v, "renew-before") as string, "Renewal window");
    const crlValidity = str(v, "crl-validity") === undefined ? state.defaults.crlValidityDays : crlDays(str(v, "crl-validity") as string);
    const renew = !flag(v, "if-due") || store.crlDue(renewBefore, now);
    let renewed: IssueResult["crl"];
    if (renew) {
      const signer = await unlockSigner(ctx, store);
      try {
        renewed = (await issue(ctx, store, signer, { crl: { validityDays: crlValidity } })).crl;
      } finally {
        signer.close();
      }
    }
    const currentCrl = await store.readCurrentCrl();
    const data: Record<string, unknown> = { command: "renew-crl", renewed: renewed !== undefined, crl: crlSummary(currentCrl) };
    if (session === undefined) {
      const crlOut = withinDir(dir, str(v, "crl-out") as string);
      if (currentCrl !== undefined) await writeOutput(crlOut, Buffer.from(pemOf(currentCrl.der, "X509 CRL")));
      ctx.progress.files.crl = crlOut;
      return { data: { ...data, crlFile: crlOut }, next: [`On an online machine: hemlig pki ez upload-crl --crl ${shellArg(crlOut)} --root-cert ${shellArg(withinDir(dir, state.root.certificateFile))}`] };
    }
    const sync = await syncRootCrl(session, store, ext, ctx);
    return {
      data: { ...data, uploaded: sync.uploaded, changed: sync.changed, root: { registered: sync.registered, extId: sync.extId }, ...(sync.registered ? {} : { warnings: ["root_not_registered"] }) },
    };
  } finally {
    await store.close();
  }
};

/** `upload-crl --crl F --root-cert F`: no state. Verifies the CRL under the root, then the same server checks as a stateful upload. */
const uploadCrlStateless = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const crlFile = str(v, "crl");
  const rootFile = str(v, "root-cert");
  if (crlFile === undefined || rootFile === undefined) usage("A stateless upload needs both --crl FILE and --root-cert FILE.");
  for (const name of ["dir", "state-file", "break-stale-lock"]) if (v[name] !== undefined) usage(`--${name} applies only to an upload from the state directory (omit --crl and --root-cert).`);
  const root = parseCertificate(certificateBytes(await readBounded(resolve(rootFile as string), 32768, "root certificate file")));
  const rootCheck = validateRootCertificate(root.der);
  if (rootCheck.reasons.length > 0) throw new EzError(5, "root_profile_invalid", `The root certificate is not acceptable (${rootCheck.reasons.join(", ")}).`, { reasons: rootCheck.reasons });
  const bytes = await readBounded(resolve(crlFile as string), 4_194_304, "CRL file");
  const crl = parseCrl(bytes.toString("latin1").includes("-----BEGIN") ? fromPem(bytes.toString("latin1"), "X509 CRL") : bytes);
  assertCrlFromRoot(crl, root, "The CRL");
  const session = await sessionOf(ctx);
  const ext = await findExternalRoot(session, { spkiSha256: root.spkiSha256, fingerprint: root.fingerprint });
  // The first server response carries its clock; check it before anything is signed or uploaded.
  assertClockSkew(session, ctx.clock());
  if (ext === undefined) throw new EzError(4, "not_found", "The server does not know this root yet; it is registered when the first CA under it is activated.");
  checkExpectedExt(str(v, "expect-ext-id"), ext);
  const summary = { number: Number(crl.number), sha256: crl.sha256 };
  if (ext.crl?.sha256 === crl.sha256) {
    return { data: { command: "upload-crl", root: { extId: ext.extId }, crl: summary, uploaded: false, changed: false } };
  }
  if (ext.crl !== undefined) {
    const serverNumber = BigInt(`0x${ext.crl.numberHex}`);
    const ours = crl.number ?? 0n;
    if (ours < serverNumber) throw new EzError(5, "state_behind_server", "The server's root CRL is newer than this one; nothing was uploaded.", { serverNumber: serverNumber.toString(), number: ours.toString() });
    if (ours === serverNumber) throw new EzError(5, "state_forked", "The server's root CRL has the same number but different content: two copies of this root are signing.", { number: ours.toString() });
    assertCarriesServerRevocations(crl, await fetchServerCrl(session, ext, root));
  }
  const response = await uploadRootCrl(session, ext.extId, { pem: pemOf(crl.der, "X509 CRL"), sha256: crl.sha256 });
  return { data: { command: "upload-crl", root: { extId: ext.extId }, crl: summary, uploaded: true, changed: response.changed, revokedCaIds: response.revokedCaIds } };
};

const uploadCrl = async (ctx: Ctx): Promise<Receipt> => {
  if (str(ctx.values, "crl") !== undefined || str(ctx.values, "root-cert") !== undefined) return uploadCrlStateless(ctx);
  const store = await EzStore.open(storeOptions(ctx, directoryOf(ctx.values)));
  try {
    const session = await sessionOf(ctx);
    const ext = await findExternalRoot(session, store.state.root);
    // The first server response carries its clock; check it before anything is signed or uploaded.
    assertClockSkew(session, ctx.clock());
    if (ext === undefined) throw new EzError(4, "not_found", "The server does not know this root yet; it is registered when the first CA under it is activated.");
    await store.checkServer(await fetchServerView(session, ext, store.rootCertificate));
    checkExpectedExt(str(ctx.values, "expect-ext-id"), ext);
    const sync = await syncRootCrl(session, store, ext, ctx);
    return { data: { command: "upload-crl", root: { extId: sync.extId }, crl: crlSummary(await store.readCurrentCrl()), uploaded: sync.uploaded, changed: sync.changed, revokedCaIds: sync.revokedCaIds } };
  } finally {
    await store.close();
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------------------------------------------------

const statusRoot = async (dir: string, state: EzState): Promise<ParsedCertificate> => {
  const bytes = await readBounded(resolveRecordedPath(dir, state.root.certificateFile, true), 65536, "root certificate file");
  return parseCertificate(fromPem(bytes.toString("latin1"), "CERTIFICATE"));
};

const status = async (ctx: Ctx): Promise<Receipt> => {
  const dir = directoryOf(ctx.values);
  const stateFile = str(ctx.values, "state-file") ?? DEFAULT_STATE_FILE;
  if (!(await exists(join(dir, stateFile)))) {
    throw new EzError(5, "state_missing", `${join(dir, stateFile)} does not exist. Run generate-ca first.`);
  }
  const state: EzState = await EzStore.peek(dir, stateFile);
  const now = ctx.clock();
  const current = state.crl.current;
  const crlDaysLeft = current === null ? null : Math.floor((Date.parse(current.nextUpdate) - now.getTime()) / DAY_MS);
  const live = state.issued.filter((e) => e.status !== "abandoned");
  const data: Record<string, unknown> = {
    command: "status",
    dir,
    root: {
      subject: state.root.subjectDn,
      origin: state.root.origin,
      fingerprint: state.root.fingerprint,
      spkiSha256: state.root.spkiSha256,
      keyAlgorithm: state.root.keyAlgorithm,
      notAfter: state.root.notAfter,
      extIdHint: state.root.extIdHint,
    },
    key: { storage: state.key.storage, file: state.key.file },
    crl: current === null ? null : { number: current.number, nextUpdate: current.nextUpdate, daysLeft: crlDaysLeft, due: (crlDaysLeft !== null && crlDaysLeft < EZ_DEFAULTS.crlRenewBeforeDays) || state.revoked.some((r) => r.listedInCrl === null) },
    issued: live.map((e) => ({ serial: e.serial, caId: e.caId, environment: e.environment, status: e.status, notAfter: e.notAfter })),
    revoked: state.revoked.map((r) => ({ serial: r.serial, caId: r.caId, reason: r.reason, listedInCrl: r.listedInCrl })),
    deployments: state.deployments,
    deploymentsBehind: state.deployments.filter((d) => d.lastUploadedCrlNumber < (current?.number ?? 0)).map((d) => d.adminOrigin),
    pending: state.pending,
    lastSignedAt: state.lastSignedAt,
  };
  if (flag(ctx.values, "offline")) return { data: { ...data, server: { checked: false } } };
  try {
    const session = await sessionOf(ctx);
    const ext = await findExternalRoot(session, state.root);
    let relation = ext === undefined ? "not_registered" : "in_sync";
    try {
      compareWithServer(state, await fetchServerView(session, ext, await statusRoot(dir, state)));
      if (ext?.crl !== undefined && current !== null && ext.crl.sha256 !== current.sha256) relation = "server_behind_local";
    } catch (error) {
      if (!(error instanceof EzError)) throw error;
      relation = error.code;
    }
    return { data: { ...data, server: { checked: true, origin: session.origin.origin, extId: ext?.extId, crlNumberHex: ext?.crl?.numberHex, relation } } };
  } catch (error) {
    // `status` reports instead of failing when the server cannot be reached or no login is cached.
    const code = error instanceof EzError || error instanceof CliError ? error.code : "server_unreachable";
    return { data: { ...data, server: { checked: false, reason: code } } };
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// adopt-ca
// ---------------------------------------------------------------------------------------------------------------------

const wholeNumber = (text: string, name: string): bigint => {
  if (!/^\d{1,40}$/.test(text)) usage(`${name} must be a whole number.`);
  return BigInt(text);
};

const pathLenOf = (cert: ParsedCertificate): number | null => {
  const bc = cert.extensions.find((e) => e.oid === OID.basicConstraints);
  const pathLen = bc === undefined ? undefined : parseBasicConstraints(bc.value).pathLen;
  return pathLen !== undefined && pathLen >= 1 ? pathLen : null;
};

/** realpath of the nearest existing ancestor, with the rest appended (the path itself may not exist yet). */
const realPathOf = async (path: string): Promise<string> => {
  const tail: string[] = [];
  let current = resolve(path);
  for (;;) {
    try {
      return join(await fs.realpath(current), ...tail);
    } catch {
      const parent = dirname(current);
      if (parent === current) return resolve(path);
      tail.unshift(basename(current));
      current = parent;
    }
  }
};

const crlFileNameOf = (number: bigint): string => `crls/${String(number).padStart(6, "0")}.crl.pem`;

/** `adopt-ca`: brings an existing root (an OpenSSL recipe, key and certificate files, or a YubiKey slot) under EZ management. */
const adoptCa = async (ctx: Ctx): Promise<Receipt> => {
  const v = ctx.values;
  const useYubiKey = flag(v, "yubikey");
  const opensslDir = str(v, "openssl-dir");
  const certFlag = str(v, "cert");
  const keyFlag = str(v, "key");
  const reissue = flag(v, "reissue-root-certificate");
  const offline = flag(v, "offline");
  const storeInSlot = flag(v, "store-certificate-in-slot");

  // -- 1. Flags (no side effects) ------------------------------------------------------------------------------------
  if (useYubiKey && opensslDir !== undefined) usage("--yubikey and --openssl-dir are different sources; choose one.");
  if (opensslDir !== undefined && (certFlag !== undefined || keyFlag !== undefined)) usage("--openssl-dir supplies the certificate and key; do not add --cert or --key.");
  if (!useYubiKey && opensslDir === undefined && (certFlag === undefined || keyFlag === undefined)) {
    usage("Choose what to adopt: --openssl-dir DIR, --cert F --key F, or --yubikey [--cert F].");
  }
  if (useYubiKey && keyFlag !== undefined) usage("--key applies to a software root; this root's key is in the YubiKey.");
  if (!useYubiKey) {
    for (const name of ["yubikey-serial", "slot", "pin-stdin", "allow-last-pin-attempt", "store-certificate-in-slot"]) {
      if (v[name] !== undefined) usage(`--${name} applies only with --yubikey.`);
    }
  } else {
    for (const name of ["passphrase-stdin", "key-file"]) if (v[name] !== undefined) usage(`--${name} applies only to a software root.`);
  }
  if (flag(v, "no-prior-revocations") && (v.crl !== undefined || v["openssl-index"] !== undefined || opensslDir !== undefined)) {
    usage("--no-prior-revocations contradicts the CRL or index.txt you supplied; drop one of them.");
  }
  if (str(v, "validity") !== undefined && !reissue) usage("--validity applies only with --reissue-root-certificate.");
  if (offline) {
    for (const name of ["admin-url", "token-file", "timeout-ms"]) if (v[name] !== undefined) usage(`--${name} cannot be combined with --offline.`);
  }
  const flagNumber = str(v, "crl-number") === undefined ? undefined : wholeNumber(str(v, "crl-number") as string, "--crl-number");
  const reissueDays = str(v, "validity") === undefined ? undefined : days(str(v, "validity") as string, "Validity");
  const crlValidity = str(v, "crl-validity") === undefined ? EZ_DEFAULTS.crlValidityDays : crlDays(str(v, "crl-validity") as string);
  const intermediateDays = str(v, "intermediate-validity") === undefined ? EZ_DEFAULTS.intermediateValidityDays : days(str(v, "intermediate-validity") as string, "Intermediate validity");
  const dir = directoryOf(v);
  const now = ctx.clock();
  const keyFile = recordedPath(dir, str(v, "key-file") ?? "root.key.pem");
  const certFile = recordedPath(dir, str(v, "cert-file") ?? "root.pem");
  const crlFile = recordedPath(dir, str(v, "crl-file") ?? "root.crl.pem");
  const names = useYubiKey ? [certFile, crlFile] : [keyFile, certFile, crlFile];
  if (new Set(names).size !== names.length) usage("The key, certificate and CRL files must be different files.");

  // -- 2. Read and verify everything that does not need the target directory (still no side effects) --------------------
  // Input files are relative to the current directory; only the output names are relative to --dir.
  const input = (path: string): string => resolve(path);
  const recipe = opensslDir === undefined ? undefined : resolve(opensslDir);
  const optionalFile = async (path: string): Promise<string | undefined> => ((await exists(path)) ? path : undefined);
  const uniq = (paths: (string | undefined)[]): string[] => [...new Set(paths.filter((p): p is string => p !== undefined))];
  const crlPaths = uniq([recipe === undefined ? undefined : await optionalFile(join(recipe, "root.crl.pem")), str(v, "crl") === undefined ? undefined : input(str(v, "crl") as string)]);
  const indexPaths = uniq([recipe === undefined ? undefined : join(recipe, "index.txt"), str(v, "openssl-index") === undefined ? undefined : input(str(v, "openssl-index") as string)]);
  const numberPaths = uniq([recipe === undefined ? undefined : await optionalFile(join(recipe, "crlnumber")), str(v, "openssl-crlnumber") === undefined ? undefined : input(str(v, "openssl-crlnumber") as string)]);

  const io = useYubiKey ? ykIo(ctx) : undefined;
  let handle: DeviceHandle | undefined;
  let lockPassed = false;
  let createdDir = false;
  let lock: LockHandle | undefined;
  try {
    let slot = EZ_DEFAULTS.slot as string;
    let certDer: Buffer | undefined;
    let slotKeySpki: Buffer | undefined;
    let slotCertDer: Buffer | null = null;
    const warnings: string[] = [];
    if (useYubiKey && io !== undefined) {
      slot = parseSlot(str(v, "slot") ?? EZ_DEFAULTS.slot);
      const serialText = str(v, "yubikey-serial");
      handle = await DeviceHandle.open(io, { serial: serialText === undefined ? undefined : parseSerial(serialText), slot, write: false, overwrite: false, allowLastPinAttempt: io.allowLastPinAttempt });
      const slotKey = handle.target.info.key;
      if (slotKey === null) throw new EzError(5, "slot_empty", `Slot ${slot} of YubiKey ${handle.serial} holds no key; there is nothing to adopt.`);
      slotKeySpki = slotKey.spkiDer;
      slotCertDer = handle.target.info.certificateDer;
      if (certFlag !== undefined) {
        certDer = certificateBytes(await readBounded(input(certFlag), 65536, "root certificate file"));
        if (slotCertDer !== null && !slotCertDer.equals(certDer)) warnings.push("slot_certificate_differs");
      } else if (slotCertDer !== null) {
        certDer = slotCertDer;
      } else {
        throw new EzError(2, "root_certificate_required", `Slot ${slot} of YubiKey ${handle.serial} holds no certificate; pass the root certificate with --cert F.`);
      }
    } else {
      const certPath = recipe === undefined ? input(certFlag as string) : join(recipe, "root.pem");
      certDer = certificateBytes(await readBounded(certPath, 65536, "root certificate file"));
    }
    const validation = validateRootCertificate(certDer, { now, minimumRemainingDays: EZ_DEFAULTS.adoptMinimumRemainingDays });
    const cert = validation.certificate;
    if (slotKeySpki !== undefined && !cert.spkiDer.equals(slotKeySpki)) {
      throw new EzError(5, "key_mismatch", `The certificate's public key is not the key in slot ${slot} of YubiKey ${handle?.serial ?? ""}; nothing was adopted.`);
    }
    gateRootProfile(validation.reasons, reissue);
    const keyInfo = describeSpki(cert.spkiDer);
    if (keyInfo.keyType === "rsa" && Number(keyInfo.algorithm.slice(4)) < 2048) {
      throw new EzError(2, "key_too_weak", "An RSA root key must be at least 2048 bits.");
    }
    warnings.push(...KEY_FILE_ALGORITHM_WARNINGS(keyInfo.algorithm));
    const reissuePlan = reissue ? planReissue(cert, reissueDays, now) : undefined;
    const finalSki = reissuePlan?.subjectKeyIdentifier ?? cert.subjectKeyIdentifier ?? keyIdentifier(cert.spkiDer);
    const issuerView = { ...cert, subjectKeyIdentifier: finalSki } as ParsedCertificate & { readonly subjectKeyIdentifier: Buffer };

    // The source key (software roots): read now, decrypted after the review decisions that need no secret.
    let keyPem: string | undefined;
    let encryptedSource = false;
    if (!useYubiKey) {
      const keyPath = recipe === undefined ? input(keyFlag as string) : join(recipe, "private", "root.key");
      keyPem = (await readBounded(keyPath, 65536, "key file")).toString("utf8");
      if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(keyPem)) throw new EzError(2, "key_file_invalid", "The key file does not contain a PEM private key.");
      encryptedSource = isEncryptedKeyPem(keyPem);
    }

    // Prior CRLs and revocations. Every CRL must verify under the root.
    const crls: { source: "server" | "crl-file"; crl: ParsedCrl }[] = [];
    for (const path of crlPaths) {
      const crl = parseCrlSource(await readBounded(path, 4_194_304, "CRL file"), (text) => fromPem(text, "X509 CRL"));
      assertCrlFromRoot(crl, cert, `The CRL ${path}`);
      crls.push({ source: "crl-file", crl });
    }
    crls.sort((a, b) => (b.crl.number ?? 0n) > (a.crl.number ?? 0n) ? 1 : -1);
    const rows: IndexRow[] = [];
    for (const path of indexPaths) rows.push(...parseOpenSslIndex((await readBounded(path, 33_554_432, "index.txt file", true)).toString("utf8")));
    let crlnumberFile: bigint | undefined;
    for (const path of numberPaths) {
      const last = parseOpenSslCrlNumber((await readBounded(path, 4096, "crlnumber file")).toString("utf8")) - 1n;
      if (crlnumberFile === undefined || last > crlnumberFile) crlnumberFile = last;
    }

    // The server: for a registered root, its stored root CRL is a revocation and number source.
    let session: OnlineSession | undefined;
    let ext: Awaited<ReturnType<typeof findExternalRoot>> = undefined;
    let serverCrl: ParsedCrl | undefined;
    if (!offline) {
      session = await sessionOf(ctx);
      ext = await findExternalRoot(session, { spkiSha256: cert.spkiSha256, fingerprint: cert.fingerprint });
      // The first server response carries its clock; check it before anything is signed or uploaded.
      assertClockSkew(session, now);
      if (ext !== undefined && reissuePlan !== undefined) {
        throw new EzError(5, "root_mismatch", "The server already knows this root; a re-issued certificate would change its fingerprint and no longer match the registered root.", { extId: ext.extId });
      }
      if (ext?.crl !== undefined) {
        const bytes = await downloadRootCrl(session, ext.extId);
        if (sha256Hex(bytes) !== ext.crl.sha256) throw new EzError(7, "invalid_response", "The server's root CRL does not match its record.");
        serverCrl = parseCrl(bytes);
        assertCrlFromRoot(serverCrl, cert, "The server's root CRL");
        crls.unshift({ source: "server", crl: serverCrl });
      }
    }
    const revocationSources: RevocationSource[] = [
      ...(serverCrl === undefined ? [] : ["server" as const]),
      ...(crls.some((c) => c.source === "crl-file") ? ["crl-file" as const] : []),
      ...(indexPaths.length === 0 ? [] : ["openssl-index" as const]),
    ];
    if (revocationSources.length === 0 && !flag(v, "no-prior-revocations")) {
      throw new EzError(2, "revocation_source_required", "No source of prior revocations: pass --crl FILE, --openssl-index FILE (or --openssl-dir), log in so the server's root CRL can be read, or --no-prior-revocations if this root has never revoked anything. A next CRL that omitted earlier revocations would un-revoke them for relying parties.");
    }
    const records: RevocationRecord[] = mergeRevocations([
      ...crls.map((c) => recordsFromCrl(c.crl, c.source)),
      recordsFromIndex(rows),
    ]);
    const plan = planCrl({ flag: flagNumber, crlnumberFile, crls }, { now, renewBeforeDays: EZ_DEFAULTS.crlRenewBeforeDays, root: issuerView, records });
    if (plan.raisedByServer) {
      warnings.push("crl_number_raised_by_server");
      await ctx.say(`The server's root CRL number is higher than the one you gave; the next CRL number was raised to follow it.\n`);
    }
    const currentNumber = plan.adopted === undefined ? plan.lastNumber + 1n : plan.lastNumber;
    const newThisUpdate = plan.adopted === undefined ? nextThisUpdate(now, plan.newestThisUpdate) : undefined;
    const newNextUpdate = newThisUpdate === undefined ? undefined : new Date(newThisUpdate.getTime() + crlValidity * DAY_MS);

    // Targets: never overwrite anything.
    const statePath = join(dir, str(v, "state-file") ?? DEFAULT_STATE_FILE);
    const targets = [statePath, withinDir(dir, certFile), withinDir(dir, crlFile), join(dir, crlFileNameOf(currentNumber)), ...(useYubiKey ? [] : [withinDir(dir, keyFile)]), ...(reissuePlan === undefined ? [] : [join(dir, "root.original.pem")])];
    // Adoption writes only into --dir: it must not overlap the recipe directory, and no output may be an input file.
    const refuseSourceOverlap = async (): Promise<void> => {
      const realDir = await realPathOf(dir);
      if (recipe !== undefined) {
        const realRecipe = await realPathOf(recipe);
        if (realDir === realRecipe || realDir.startsWith(realRecipe + sep)) {
          throw new EzError(2, "invalid_input", `--dir (${dir}) is the OpenSSL directory or inside it; adopt-ca writes crls/, the state and more, and never writes into a source. Choose another --dir.`);
        }
      }
      const inputs = new Set<string>();
      for (const path of [certFlag, keyFlag, str(v, "crl"), str(v, "openssl-index"), str(v, "openssl-crlnumber"), ...crlPaths, ...indexPaths, ...numberPaths, ...(recipe === undefined ? [] : [join(recipe, "root.pem"), join(recipe, "private", "root.key")])]) {
        if (path !== undefined) inputs.add(await realPathOf(input(path)));
      }
      for (const target of targets) {
        if (inputs.has(await realPathOf(target))) throw new EzError(2, "invalid_input", `The output ${target} is also an input file; adopt-ca never modifies a source.`);
      }
    };
    const refuseExisting = async (): Promise<void> => {
      const present: string[] = [];
      for (const target of targets) if (await exists(target)) present.push(target);
      if (present.length > 0) {
        throw new EzError(5, "already_exists", `Refusing to overwrite existing files: ${present.join(", ")}. Nothing was changed. If a previous adopt-ca was interrupted (there is no ${DEFAULT_STATE_FILE}), remove only the files it wrote there and rerun; your sources and the device were not changed.`, { files: present });
      }
    };
    await refuseSourceOverlap();
    await refuseExisting();
    // A certificate that already is the slot's needs no device write.
    const storeDeviceCertificate = storeInSlot && (reissuePlan !== undefined || slotCertDer === null || !slotCertDer.equals(cert.der));
    // Everything that could refuse has run; from here on the operator must be able to type the confirmation.
    await ctx.prompter.requireConfirmTerminal("adopt");

    // -- 3. The directory, the lock, then secrets --------------------------------------------------------------------
    createdDir = !(await exists(dir));
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const baseOptions = storeOptions({ ...ctx, values: { ...v, dir } }, dir);
    lock = await acquireLock(dir, { command: baseOptions.command, hostname: osHostname(), now: ctx.clock, breakStale: baseOptions.breakStaleLock });
    await refuseExisting();

    let signer: RootSigner;
    let sourceKey: ReturnType<typeof readSourceKey>["key"] | undefined;
    if (useYubiKey && handle !== undefined) {
      signer = handle.signer(cert.spkiDer);
      warnings.push("no_key_backup");
    } else {
      let existing: Buffer | undefined;
      if (encryptedSource) existing = await ctx.prompter.passphrase({ create: false, fromStdin: flag(v, "passphrase-stdin"), label: "Source key passphrase: " });
      try {
        sourceKey = readSourceKey(keyPem as string, existing).key;
      } finally {
        existing?.fill(0);
      }
      if (!encryptedSource) {
        warnings.push("key_unencrypted");
        await ctx.say("WARNING: the source key file is NOT encrypted. Hemlig re-encrypts a copy under your new passphrase, but the original stays unprotected until you delete it.\n");
      }
      signer = new SoftwareSigner(sourceKey);
      if (!signer.spkiDer.equals(cert.spkiDer)) {
        signer.close();
        throw new EzError(5, "key_mismatch", "The private key does not belong to the certificate's public key; nothing was adopted.");
      }
    }

    try {
      // -- 4. Review and the typed confirm ---------------------------------------------------------------------------
      const sourceLabel = useYubiKey ? `YubiKey ${handle?.serial ?? ""}, slot ${slot} (firmware ${handle?.target.info.device.firmware ?? ""})` : recipe !== undefined ? `OpenSSL directory ${recipe}` : `files ${input(certFlag as string)} and ${input(keyFlag as string)}`;
      const adoptedCrl = plan.adopted?.crl;
      await ctx.say(
        renderAdoptReview({
          source: sourceLabel,
          subjectDn: describeName(assertRestrictedName(cert.subjectDer, "external")),
          fingerprint: cert.fingerprint,
          serial: cert.serialHex,
          notBefore: cert.notBefore,
          notAfter: cert.notAfter,
          key: keyInfo.algorithm,
          spkiSha256: cert.spkiSha256,
          storage: useYubiKey ? `YubiKey (no backup held by Hemlig), PIN and touch as the slot is set` : `software key file ${withinDir(dir, keyFile)} (re-encrypted)`,
          crl: {
            lastNumber: plan.lastNumber,
            sources: plan.sources,
            signNumber: plan.adopted === undefined ? Number(currentNumber) : undefined,
            nextUpdate: (adoptedCrl?.nextUpdate ?? newNextUpdate) as Date,
            adopted: plan.adopted !== undefined,
          },
          revocations: { count: records.length, sources: revocationSources.length === 0 ? ["none declared"] : revocationSources },
          importedIssued: new Set(rows.map((r) => r.serial)).size,
          ...(reissuePlan === undefined ? {} : { reissue: { serial: serialHex(reissuePlan.serial), notAfter: reissuePlan.notAfter, keepsSki: reissuePlan.subjectKeyIdentifier !== undefined, keptFile: withinDir(dir, "root.original.pem"), pathLen: reissuePlan.pathLen, droppedPathLen: reissuePlan.droppedPathLen } }),
          ...(useYubiKey ? { slotCertificate: storeDeviceCertificate } : {}),
          warnings: warnings.map((w) => adoptWarningText(w)),
        }),
      );
      const confirmation = await ctx.prompter.confirm("adopt");
      if (storeDeviceCertificate && handle !== undefined && io !== undefined) {
        await io.prompter.acknowledge(String(handle.serial), `Type the serial number ${handle.serial} to store the certificate in slot ${slot} of that YubiKey${slotCertDer === null ? "" : " (replacing the one there)"}: `);
      }

      // -- 5. Unlock, prepare and sign one batch -----------------------------------------------------------------------
      let newKeyPem: string | undefined;
      if (signer instanceof YubiKeySigner) {
        await signer.verifyPin();
        if (storeDeviceCertificate && handle !== undefined) await handle.checkManagement();
      } else {
        const fresh = await ctx.prompter.passphrase({ create: true, fromStdin: flag(v, "passphrase-stdin"), label: "New passphrase for the Hemlig key file (12+ characters): " });
        try {
          newKeyPem = encryptPkcs8((sourceKey as NonNullable<typeof sourceKey>).export({ type: "pkcs8", format: "der" }), fresh);
          const check = new SoftwareSigner(decryptKeyFile(newKeyPem, fresh));
          const same = check.spkiDer.equals(cert.spkiDer);
          check.close();
          if (!same) throw new EzError(7, "internal_error", "The re-encrypted key does not restore this root's key; nothing was written.");
        } finally {
          fresh.fill(0);
        }
      }
      const test: SignItem = { id: "test", description: "a test challenge (nothing is issued)", data: randomBytes(32) };
      const rootPrep = reissuePlan === undefined ? undefined : prepareRoot(signer, { subject: reissuePlan.subjectDer, now, serial: reissuePlan.serial, notAfter: reissuePlan.notAfter, pathLen: reissuePlan.pathLen, subjectKeyIdentifier: reissuePlan.subjectKeyIdentifier });
      const crlPrep =
        plan.adopted !== undefined || newThisUpdate === undefined
          ? undefined
          : prepareCrl(signer, issuerView, { number: currentNumber, thisUpdate: newThisUpdate, validityDays: crlValidity, entries: crlEntriesOf(records) });
      const items = [test, ...(rootPrep === undefined ? [] : [rootPrep.item]), ...(crlPrep === undefined ? [] : [crlPrep.item])];
      const signatures = await signBatch(signer, items, {
        events: { onTouch: (item) => void ctx.say(touchNotice(handle?.serial ?? 0, item)) },
        confirm: () => {
          if (!consumeConfirmation(confirmation, "adopt")) throw new EzError(2, "confirmation_declined", "Signing was attempted without the typed confirmation.");
        },
      });
      let cursor = 1;
      const reissued = rootPrep === undefined ? undefined : rootPrep.finish(signatures[cursor++] as Buffer);
      const newCrl = crlPrep === undefined ? undefined : crlPrep.finish(signatures[cursor++] as Buffer);
      const finalRoot = reissued?.certificate ?? cert;
      if (reissued !== undefined && (!finalRoot.subjectDer.equals(cert.subjectDer) || !finalRoot.spkiDer.equals(cert.spkiDer))) {
        throw new EzError(7, "signature_self_check_failed", "The re-issued root does not keep the original subject and key; nothing was written.");
      }
      const currentCrl = (newCrl?.crl ?? plan.adopted?.crl) as ParsedCrl;

      // -- 6. State and files (the state file last; nothing is overwritten) --------------------------------------------
      const subject = subjectOfRoot(finalRoot);
      const state = initialState({
        origin: "adopted",
        subject: subject as unknown as Record<string, string>,
        subjectDn: formatSubject(subject),
        root: finalRoot,
        keyAlgorithm: keyInfo.algorithm,
        pathLen: pathLenOf(finalRoot),
        key:
          useYubiKey && handle !== undefined
            ? {
                storage: "yubikey",
                file: null,
                kdf: null,
                yubikey: {
                  slot,
                  keyType: handle.target.info.key?.keyType ?? "",
                  generatedOnDevice: handle.target.info.key?.generated ?? false,
                  pinPolicy: handle.target.info.key?.pinPolicy ?? "always",
                  touchPolicy: handle.target.info.key?.touchPolicy ?? "always",
                  devices: [{ serial: handle.serial, firmware: handle.target.info.device.firmware, fips: handle.target.info.device.fips, addedAt: now.toISOString() }],
                },
              }
            : { storage: "software", file: keyFile, kdf: { name: "pbkdf2-hmac-sha256", iterations: KEY_FILE_ITERATIONS }, yubikey: null },
        crl: currentCrl,
        certificateFile: certFile,
        crlCopyFile: crlFile,
        defaults: { intermediateValidityDays: intermediateDays, crlValidityDays: crlValidity },
        adoption: {
          source: useYubiKey ? "yubikey" : recipe !== undefined ? "openssl-dir" : "files",
          adoptedAt: now.toISOString(),
          crlNumberSource: [...plan.sources],
          revocationSource: revocationSources.length === 0 ? ["none-declared"] : [...revocationSources],
        },
        reissuedFrom: reissued === undefined ? null : { fingerprint: cert.fingerprint, file: "root.original.pem" },
        now,
      });
      state.revoked = revokedEntriesOf(records, Number(currentNumber));
      state.issued = importedIssuedEntries(rows, finalRoot);
      if (plan.newestThisUpdate !== undefined && plan.newestThisUpdate.getTime() > Date.parse(state.crl.lastThisUpdate)) {
        state.crl.lastThisUpdate = plan.newestThisUpdate.toISOString();
      }
      const artifacts = [
        ...initialArtifacts(state, { rootDer: finalRoot.der, crlDer: currentCrl.der, ...(newKeyPem === undefined ? {} : { keyFilePem: newKeyPem }) }),
        ...(reissued === undefined ? [] : [{ path: "root.original.pem", data: Buffer.from(toPem(cert.der, "CERTIFICATE")), mode: 0o644 }]),
      ];
      lockPassed = true;
      const store = await EzStore.create({ ...baseOptions, lock }, state, artifacts);
      try {
        ctx.progress.completed.push("root-adopted");
        const files: Record<string, string> = {
          state: statePath,
          ...(useYubiKey ? {} : { key: withinDir(dir, keyFile) }),
          certificate: withinDir(dir, certFile),
          crl: withinDir(dir, crlFile),
          ...(reissued === undefined ? {} : { originalCertificate: join(dir, "root.original.pem") }),
        };
        Object.assign(ctx.progress.files, files);
        if (session !== undefined && ext?.crl !== undefined && ext.crl.sha256 === currentCrl.sha256) {
          await store.recordUpload(session.origin.origin, ext.extId, Number(currentCrl.number));
        }
        await ctx.summary(["", `Root adopted: ${formatSubject(subject)}`, `  SHA-256 fingerprint  ${finalRoot.fingerprint}`, `  CRL number           ${currentCrl.number}`, ""].join("\n"));
        if (!useYubiKey) {
          const originals = [recipe === undefined ? input(keyFlag as string) : join(recipe, "private", "root.key")];
          await ctx.summary(`NOTE: the original key file(s) remain: ${originals.join(", ")}. ${encryptedSource ? "OpenSSL's -aes256 protects them with only a few thousand PBKDF2 iterations" : "They are NOT encrypted"}; secure or delete them once you have backed up ${files.key}.\n`);
        } else {
          await ctx.summary("NOTE: Hemlig holds no backup of this YubiKey's key. If the device is lost or locked, this root is gone.\n");
        }
        if (storeDeviceCertificate && handle !== undefined && io !== undefined) {
          try {
            const management = await handle.management();
            await io.client.putCertificate({ serial: handle.serial, slot, overwrite: slotCertDer !== null, management: management.spec, pin: management.pin, certificateDer: finalRoot.der });
            ctx.progress.completed.push(`slot-certificate:${handle.serial}`);
          } catch (error) {
            warnings.push(`slot_certificate_failed:${handle.serial}`);
            await ctx.say(`The root was adopted, but its certificate could not be stored in slot ${slot} (${error instanceof EzError ? error.message : "unknown error"}). It is in ${files.certificate}.\n`);
          }
        }
        const registered = ext !== undefined;
        return {
          data: {
            command: "adopt-ca",
            dir,
            source: state.adoption?.source,
            root: {
              subject: formatSubject(subject),
              fingerprint: finalRoot.fingerprint,
              spkiSha256: finalRoot.spkiSha256,
              serial: finalRoot.serialHex,
              notBefore: finalRoot.notBefore.toISOString(),
              notAfter: finalRoot.notAfter.toISOString(),
              keyAlgorithm: keyInfo.algorithm,
              extIdHint: state.root.extIdHint,
              reissued: reissued !== undefined,
              ...(reissued === undefined ? {} : { originalFingerprint: cert.fingerprint, fingerprintChanged: true }),
            },
            crl: { number: Number(currentCrl.number), nextUpdate: (currentCrl.nextUpdate as Date).toISOString(), signed: newCrl !== undefined, adopted: newCrl === undefined, lastNumber: Number(plan.lastNumber), numberSources: plan.sources },
            revocations: { count: records.length, sources: state.adoption?.revocationSource },
            issuedImported: state.issued.length,
            key: useYubiKey ? { storage: "yubikey", slot, serial: handle?.serial, keyType: state.key.yubikey?.keyType, touchPolicy: state.key.yubikey?.touchPolicy } : { storage: "software", file: files.key },
            files,
            defaults: state.defaults,
            ...(registered ? { server: { registered: true, extId: ext?.extId } } : {}),
            warnings,
          },
          next: [
            ...(useYubiKey ? ["Hemlig holds no backup of this YubiKey's key."] : [`Back up ${files.key}, then secure or delete the original key file(s).`]),
            ...(reissued === undefined ? [] : [`The root fingerprint changed (was ${cert.fingerprint}); redistribute ${files.certificate} to anything that pins the certificate.`]),
            ...(registered && newCrl !== undefined ? ["hemlig pki ez upload-crl"] : []),
            "hemlig pki ez sign-cert <ca-id> --environment <env>",
          ],
        };
      } finally {
        await store.close();
      }
    } finally {
      signer.close();
    }
  } finally {
    handle?.close();
    if (!lockPassed) {
      await lock?.release();
      if (createdDir) await fs.rmdir(dir).catch(() => undefined);
    }
  }
};

const ADOPT_WARNINGS: Record<string, string> = {
  key_unencrypted: "the source key file is not encrypted",
  no_key_backup: "Hemlig holds no backup of this YubiKey's key; if the device is lost or locked the root is gone",
  slot_certificate_differs: "the slot holds a different certificate than --cert; the one from --cert is adopted",
  crl_number_raised_by_server: "the server's CRL number raised the next number",
  root_key_rsa_2048: "RSA-2048 is a weak size for a root key",
};
const adoptWarningText = (code: string): string => ADOPT_WARNINGS[code] ?? code;

// ---------------------------------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------------------------------

const openControllingTerminal = async (): Promise<TerminalInput | undefined> => {
  try {
    return new TtyReadStream(openSync("/dev/tty", "r")) as unknown as TerminalInput;
  } catch {
    return undefined;
  }
};

/** Runs `hemlig pki ez ...` (the arguments after `ez`). */
export async function runEzCli(args: readonly string[], dependencies: CliDependencies = {}): Promise<number> {
  const env = dependencies.env ?? process.env;
  const stdout = dependencies.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = dependencies.stderr ?? ((text: string) => process.stderr.write(text));
  const nowMs = dependencies.now ?? Date.now;
  // Terminals get a human result; pipes, redirects and --json keep the JSON envelope. Injected writers are not terminals
  // unless a test says so.
  const stdoutTty = dependencies.stdoutIsTTY ?? (dependencies.stdout === undefined && process.stdout.isTTY === true);
  const stderrTty = dependencies.stderrIsTTY ?? (dependencies.stderr === undefined && process.stderr.isTTY === true);
  const jsonRequested = args.includes("--json");
  const human = stdoutTty && !jsonRequested;
  const progress: Progress = { completed: [], files: {} };
  let ykmanClient: YkmanClient | undefined;
  try {
    const parsed = parseEzArgs(args);
    if (parsed === "help") {
      await stdout(`${JSON.stringify(ezHelp)}\n`);
      return 0;
    }
    const prompter = new Prompter({
      stdin: (dependencies.stdin ?? process.stdin) as TerminalInput,
      write: async (text) => {
        await stderr(text);
      },
      confirmArmMs: dependencies.confirmArmMs,
      openTerminal: (dependencies.openTerminal as (() => Promise<TerminalInput | undefined>) | undefined) ?? openControllingTerminal,
    });
    const ctx: Ctx = {
      command: parsed.command,
      operands: parsed.operands,
      values: parsed.values,
      dependencies,
      env,
      clock: () => new Date(nowMs()),
      prompter,
      progress,
      say: async (text) => {
        await stderr(text);
      },
      summary: async (text) => {
        if (!human) await stderr(text);
      },
      color: colorWanted(env, prompter.interactive),
      ykman: () => (ykmanClient ??= new YkmanClient({ path: env.HEMLIG_YKMAN })),
    };
    const handlers: Record<string, (ctx: Ctx) => Promise<Receipt>> = {
      "generate-ca": generateCa,
      "adopt-ca": adoptCa,
      "import-key": importKey,
      "add-yubikey": addYubiKey,
      "sign-cert": signCert,
      activate: activateCommand,
      "revoke-cert": revokeCert,
      "renew-crl": renewCrl,
      "upload-crl": uploadCrl,
      status,
    };
    const receipt = await (handlers[parsed.command] as (ctx: Ctx) => Promise<Receipt>)(ctx);
    if (human) {
      const result = humanFromReceipt(receipt.data, receipt.next ?? [], {
        command: parsed.command,
        dir: parsed.command === "activate" ? process.cwd() : directoryOf(parsed.values),
        cwd: process.cwd(),
        now: ctx.clock(),
        environment: str(parsed.values, "environment") ?? env.HEMLIG_ENVIRONMENT,
      });
      await stdout(renderHuman(result, makeStyle(colorWanted(env, true))));
      return 0;
    }
    await stdout(`${JSON.stringify({ data: receipt.data, ...(receipt.next === undefined ? {} : { next: receipt.next }) })}\n`);
    return 0;
  } catch (error) {
    const failure = {
      group: "pki",
      mutationAttempted: false,
      ...(progress.completed.length === 0
        ? {}
        : {
            ez: {
              completed: progress.completed,
              files: progress.files,
              ...(progress.recovery === undefined ? { rerun: `hemlig pki ez ${args.map(shellArg).join(" ")}` } : { recovery: progress.recovery }),
            },
          }),
    };
    if (!stderrTty || jsonRequested) return reportFailure(error, failure, stderr);
    // A terminal: the same exit code and the same classification, printed for a person.
    let envelope = "";
    const code = await reportFailure(error, failure, (text) => {
      envelope += text;
    });
    try {
      const parsedError = JSON.parse(envelope.trim().split("\n").pop() as string) as { error: ErrorInfo & { ez?: ErrorInfo["ez"] }; ez?: ErrorInfo["ez"] };
      await stderr(renderHumanError({ ...parsedError.error, ez: parsedError.ez ?? parsedError.error.ez }, makeStyle(colorWanted(env, true))));
    } catch {
      await stderr(envelope);
    }
    return code;
  }
}
