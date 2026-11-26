import { sep } from "node:path";
import { displaySafe } from "./ez-x509";

/**
 * Human-readable results and errors for `hemlig pki ez`. On a terminal a command prints a short result (a headline,
 * a few aligned facts, warnings and numbered next steps) instead of the JSON receipt; piped output and `--json` keep
 * the JSON envelope. Every value that did not come from this file's own constants goes through `displaySafe`.
 */

export interface Style {
  readonly bold: (text: string) => string;
  readonly dim: (text: string) => string;
  readonly green: (text: string) => string;
  readonly yellow: (text: string) => string;
  readonly red: (text: string) => string;
}

export const makeStyle = (color: boolean): Style => {
  const wrap = (open: string, close: string) => (text: string): string => (color ? `\x1b[${open}m${text}\x1b[${close}m` : text);
  return { bold: wrap("1", "22"), dim: wrap("2", "22"), green: wrap("32", "39"), yellow: wrap("33", "39"), red: wrap("31", "39") };
};

export interface HumanResult {
  /** The one-line result; `mark` picks the symbol (default a check mark). */
  readonly headline: string;
  readonly mark?: "ok" | "warn" | "none";
  readonly facts?: readonly (readonly [string, string])[];
  /** Extra preformatted lines (the status dashboard's table), shown after the facts. */
  readonly body?: readonly string[];
  readonly warnings?: readonly string[];
  /** Numbered steps; a step may hold several lines (the second and later are indented under the number). */
  readonly next?: readonly string[];
}

const indent = (text: string, by: string): string => text.split("\n").map((line, i) => (i === 0 ? line : `${by}${line}`)).join("\n");

/**
 * Last line of defense for terminal output: values from servers and files are already `displaySafe` where they enter a
 * result, and this strips any control, C1 or bidirectional-override character that is left (keeping newlines).
 */
const backstop = (text: string): string =>
  text.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);

export const renderHuman = (result: HumanResult, style: Style): string => {
  const safe = backstop;
  const mark = result.mark ?? "ok";
  const out: string[] = [];
  out.push(`${mark === "ok" ? `${style.green("✓")} ` : mark === "warn" ? `${style.yellow("!")} ` : ""}${style.bold(safe(result.headline))}`);
  const facts = result.facts ?? [];
  if (facts.length > 0) {
    const width = Math.max(...facts.map(([label]) => label.length));
    out.push("", ...facts.map(([label, value]) => `  ${style.dim(label.padEnd(width))}  ${safe(value)}`));
  }
  if ((result.body ?? []).length > 0) out.push("", ...(result.body as string[]).map((line) => `  ${safe(line)}`));
  if ((result.warnings ?? []).length > 0) out.push("", ...(result.warnings as string[]).map((w) => `${style.yellow("!")} ${safe(w)}`));
  if ((result.next ?? []).length > 0) {
    out.push("", style.bold("Next steps"));
    (result.next as string[]).forEach((step, i) => out.push(`  ${i + 1}. ${indent(safe(step), "     ")}`));
  }
  return `${out.join("\n")}\n`;
};

// ---------------------------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------------------------

/** Hints for conditions with an obvious next move; the code stays in the output for scripts and support. */
const ERROR_HINTS: Record<string, string> = {
  passphrase_invalid: "Check the passphrase for the key file and try again.",
  pin_invalid: "The PIN is never retried automatically. Check it, and mind the attempts left, before running the command again.",
  already_exists: "Nothing was overwritten. Choose another --dir, or remove the files only if you know they are leftovers.",
  state_locked: "Another hemlig pki ez command is running in this directory. If it crashed, run again with --break-stale-lock.",
  state_behind_server: "The server knows a newer root CRL than this state. Restore the latest copy of this directory before signing anything.",
  state_forked: "Two copies of this root are signing. Keep one active copy of the directory.",
  clock_skew: "Fix this machine's clock and run the command again.",
  terminal_required: "This step needs a person at a terminal; it cannot run unattended.",
  confirmation_declined: "Nothing was signed and nothing changed.",
  revocation_source_required: "Pass --crl FILE, --openssl-index FILE, or --no-prior-revocations if this root never revoked anything.",
  crl_number_required: "Pass --crl-number N, at least the number of the last CRL this root ever issued.",
  root_profile_invalid: "Reissuing a root certificate with --reissue-root-certificate fixes missing CA extensions only.",
  yubikey_multiple: "Pass --yubikey-serial N to choose a device.",
  yubikey_already_recorded: "That YubiKey is already one of this root's recorded devices; nothing changed.",
  tool_missing: "Install YubiKey Manager (ykman 5.5 or later), or set HEMLIG_YKMAN to its absolute path.",
  unknown_serial: "Pass the certificate itself with --cert FILE if the root issued it before it was adopted.",
};

export interface ErrorInfo {
  readonly exitCode: number;
  readonly code: string;
  readonly message: string;
  /** What had already happened when the command failed, from the JSON envelope's `ez` object. */
  readonly ez?: { readonly completed?: readonly string[]; readonly rerun?: string; readonly recovery?: string };
}

export const renderHumanError = (error: ErrorInfo, style: Style): string => {
  const safe = backstop;
  const lines = [`${style.red("✗")} ${style.bold(safe(error.message))}`, `  ${style.dim(`(${safe(error.code)}, exit ${error.exitCode})`)}`];
  const hint = ERROR_HINTS[error.code];
  if (hint !== undefined) lines.push(`  ${safe(hint)}`);
  if (error.ez?.completed !== undefined && error.ez.completed.length > 0) lines.push(`  Done before the failure: ${safe(error.ez.completed.join(", "))}.`);
  if (error.ez?.recovery !== undefined) lines.push(`  ${safe(error.ez.recovery)}`);
  else if (error.ez?.rerun !== undefined) lines.push(`  To retry: ${safe(error.ez.rerun)}`);
  return `${lines.join("\n")}\n`;
};

// ---------------------------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------------------------

type Data = Record<string, any>;

export interface HumanContext {
  readonly command: string;
  /** The working directory of the state (or the current directory). */
  readonly dir: string;
  readonly cwd: string;
  readonly now: Date;
  readonly environment?: string;
}

export const shellQuote = (value: string): string => (/^[A-Za-z0-9._/:=@%+-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`);

const shortFingerprint = (fingerprint: string): string => (fingerprint.length > 16 ? `${fingerprint.slice(0, 8)}…${fingerprint.slice(-4)}` : fingerprint);
/** Plain words for the source codes the JSON carries. */
export const sourceWord = (code: string): string =>
  ({ "none-declared": "none declared", "crl-file": "CRL file", "openssl-index": "index.txt", server: "server CRL", flag: "--crl-number", "openssl-crlnumber": "crlnumber file" })[code] ?? displaySafe(code);

const day = (iso: unknown): string => (typeof iso === "string" ? iso.slice(0, 10) : "unknown");
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/** A path inside `dir` is shown relative to it; anything else in full. */
export const relativeTo = (dir: string, path: unknown): string => {
  if (typeof path !== "string") return "";
  return displaySafe(path.startsWith(`${dir}${sep}`) ? path.slice(dir.length + 1) : path);
};

const WARNING_TEXT: Record<string, string> = {
  key_unencrypted: "The source key file is not encrypted.",
  no_key_backup: "Hemlig holds no backup of this key. If the YubiKey is lost or locked, this root is gone.",
  slot_certificate_differs: "The slot holds a different certificate than --cert; the one from --cert was adopted.",
  crl_number_raised_by_server: "The server's root CRL number was higher than the one you gave, so the next number follows the server's.",
  root_key_rsa_2048: "RSA-2048 is a weak size for a root key.",
  csr_unbound: "The CSR was not pinned to the CA's key (no --expect-spki-sha256).",
  csr_unconstrained: "The CA has no name constraints: it may issue for any name.",
  root_not_registered: "The server you are logged in to does not know this root yet (it is registered when the first CA under it is activated).",
  slot_certificate_missing: "The slot holds no certificate. That does not affect signing; the root certificate is in the directory.",
  slot_certificate_not_root: "The certificate in the slot is not this root's certificate. That does not affect signing.",
  no_root_crl: "No root CRL was supplied or registered.",
};

export const warningText = (code: string): string => {
  const slot = /^slot_certificate_failed:(\d+)$/.exec(code);
  if (slot !== null) return `The root certificate could not be stored in the slot of YubiKey ${slot[1]}; it is in the certificate file.`;
  return WARNING_TEXT[code] ?? code;
};

const warningsOf = (data: Data): string[] => (Array.isArray(data.warnings) ? (data.warnings as string[]).map((w) => displaySafe(warningText(w))) : []);

const crlFact = (crl: Data | null | undefined, now: Date): string => {
  if (crl === null || crl === undefined || crl.number === undefined) return "none";
  const left = typeof crl.nextUpdate === "string" ? Math.floor((Date.parse(crl.nextUpdate) - now.getTime()) / 86_400_000) : undefined;
  return `#${crl.number}, next update ${day(crl.nextUpdate)}${left === undefined ? "" : ` (${plural(left, "day")} left)`}`;
};

const keyFact = (key: Data | undefined, dir: string): string => {
  if (key === undefined) return "";
  if (key.storage === "yubikey") {
    const serials = Array.isArray(key.serials) ? key.serials.join(", ") : key.serial;
    return `YubiKey ${serials}, slot ${displaySafe(String(key.slot))}${key.generatedOnDevice === true ? " (generated on the device, no backup)" : ""}`;
  }
  return `software key file ${key.file === undefined ? "" : relativeTo(dir, key.file)}`.trim();
};

/** The command prefix with this run's `--dir` filled in (omitted when it is the current directory). */
const cmd = (ctx: HumanContext, sub: string, rest = ""): string =>
  `hemlig pki ez ${sub}${rest === "" ? "" : ` ${rest}`}${ctx.dir === ctx.cwd ? "" : ` --dir ${shellQuote(ctx.dir)}`}`;

const backupStep = (ctx: HumanContext): string => `Back up ${ctx.dir} (for example, commit it to a private git repo).`;
const signStep = (ctx: HumanContext): string =>
  `Create an intermediate CA in Hemlig (console PKI tab, or \`hemlig pki ca create --kind EXTERNAL_INTERMEDIATE …\`), then sign it:\n${cmd(ctx, "sign-cert", `<ca-id> --environment ${ctx.environment ?? "<env>"}`)}`;

export const humanFromReceipt = (data: Data, nextHints: readonly string[], ctx: HumanContext): HumanResult => {
  const warnings = warningsOf(data);
  switch (data.command ?? ctx.command) {
    case "generate-ca": {
      const root = data.root as Data;
      const key = data.key as Data;
      const dirFacts: [string, string][] = [["Directory", ctx.dir]];
      return {
        headline: `Root created: ${displaySafe(String(root.subject))}`,
        facts: [
          ["Fingerprint", `${shortFingerprint(root.fingerprint)} (SHA-256)`],
          ["Key", `${displaySafe(String(root.keyAlgorithm))}, ${keyFact({ ...key, file: (data.files as Data).key }, ctx.dir)}`],
          ["Valid", `${day(root.notBefore)} to ${day(root.notAfter)}`],
          ["CRL", crlFact(data.crl, ctx.now)],
          ...dirFacts,
          ["Files", Object.values(data.files as Data).map((f) => relativeTo(ctx.dir, f)).join(", ")],
        ],
        warnings: [...(key.generatedOnDevice === true ? ["The key was generated on the YubiKey: Hemlig holds no backup, and a lost or locked device means a new root."] : []), ...warnings],
        next: [
          key.generatedOnDevice === true ? backupStep(ctx) : `Back up ${ctx.dir}, including ${relativeTo(ctx.dir, (data.files as Data).key ?? "the key file")}, somewhere safe, apart from the passphrase.`,
          signStep(ctx),
        ],
      };
    }
    case "adopt-ca": {
      const root = data.root as Data;
      const crl = data.crl as Data;
      const key = data.key as Data;
      const sources = (data.revocations as Data).sources as string[] | undefined;
      const reissued = root.reissued === true;
      const server = data.server as Data | undefined;
      return {
        headline: `Root adopted: ${displaySafe(String(root.subject))}`,
        facts: [
          ["Fingerprint", `${shortFingerprint(root.fingerprint)} (SHA-256)`],
          ["CRL", `${crlFact(crl, ctx.now)}${crl.signed === true ? ", signed now" : ", the supplied CRL stays current"}`],
          ["Revocations", `${(data.revocations as Data).count} carried over${sources === undefined ? "" : ` (${sources.map(sourceWord).join(", ")})`}`],
          ["Key", keyFact(key, ctx.dir)],
          ...(reissued ? ([["Original", `${relativeTo(ctx.dir, (data.files as Data).originalCertificate)} (kept)`]] as [string, string][]) : []),
          ["Directory", ctx.dir],
        ],
        warnings: [
          ...(reissued ? [`The root certificate was reissued: its fingerprint changed (was ${shortFingerprint(root.originalFingerprint)}). Redistribute ${relativeTo(ctx.dir, (data.files as Data).certificate)} to anything that pins it.`] : []),
          ...warnings,
          ...(key.storage === "software" ? ["The original key file(s) remain where they were. Secure or delete them once the new copy is backed up."] : []),
        ],
        next: [
          backupStep(ctx),
          signStep(ctx),
          ...(server?.registered === true && crl.signed === true ? [`The server holds an older root CRL; upload the new one:\n${cmd(ctx, "upload-crl")}`] : []),
        ],
      };
    }
    case "import-key": {
      const yk = data.yubikey as Data;
      return {
        headline: `Root key imported into YubiKey ${yk.serial}`,
        facts: [
          ["Fingerprint", `${shortFingerprint((data.root as Data).fingerprint)} (SHA-256)`],
          ["Key", `${displaySafe(String(yk.keyType))}, slot ${displaySafe(String(yk.slot))}, touch ${displaySafe(String(yk.touchPolicy))}`],
          ["Firmware", String(yk.firmware)],
          ["Directory", ctx.dir],
        ],
        warnings,
        next: [`Record YubiKey ${Number(yk.serial)} with your other root-key custody records.`, `Check it signs: ${cmd(ctx, "renew-crl", `--offline --crl-out root.crl.pem --yubikey-serial ${yk.serial}`)}`],
      };
    }
    case "add-yubikey": {
      const yk = data.yubikey as Data;
      const serial = Number(yk.serial);
      return {
        headline: `YubiKey ${serial} recorded as another holder of the root key`,
        facts: [
          ["Fingerprint", `${shortFingerprint(String((data.root as Data).fingerprint))} (SHA-256)`],
          ["YubiKey", `${serial}, firmware ${displaySafe(String(yk.firmware))}`],
          ["Slot", `${displaySafe(String(yk.slot))}, ${displaySafe(String(yk.keyType))}, touch ${displaySafe(String(yk.touchPolicy))}`],
          ["Recorded", (data.devices as number[]).join(", ")],
          ["Directory", ctx.dir],
        ],
        warnings,
        next: [
          `Either YubiKey can now sign. Connect only one at a time, or pass --yubikey-serial N (for example ${cmd(ctx, "renew-crl", `--if-due --yubikey-serial ${serial}`)}).`,
          backupStep(ctx),
        ],
      };
    }
    case "sign-cert": {
      const crl = data.crl as Data | undefined;
      const activated = data.activated === true;
      const root = data.root as Data | undefined;
      const facts: [string, string][] = [
        ["CA ID", displaySafe(String(data.caId))],
        ...(data.environment === null || data.environment === undefined ? [] : ([["Environment", displaySafe(String(data.environment))]] as [string, string][])),
        ...(data.serial === undefined ? [] : ([["Serial", String(data.serial)]] as [string, string][])),
        ...(data.notAfter === undefined ? [] : ([["Valid until", day(data.notAfter)]] as [string, string][])),
        ...(data.fingerprint === undefined ? [] : ([["Fingerprint", `${shortFingerprint(String(data.fingerprint))} (SHA-256)`]] as [string, string][])),
        ...(crl === undefined ? [] : ([["Root CRL", `${crlFact(crl, ctx.now)}${crl.renewed === true ? ", renewed" : ""}${crl.uploaded === true ? ", uploaded" : ""}`]] as [string, string][])),
        ["Directory", ctx.dir],
      ];
      if (!activated) {
        const files: [string, string][] = [["Certificate", relativeTo(ctx.dir, data.certificateFile)], ["Root", relativeTo(ctx.dir, data.chainFile)], ["CRL", relativeTo(ctx.dir, data.crlFile)]];
        return {
          headline: `Certificate signed for ${displaySafe(String(data.caId))} (not activated yet)`,
          facts: [...facts, ...files],
          warnings,
          next: [`Carry the certificate, the root and the CRL to a machine that can reach Hemlig and activate:\n${nextHints.find((h) => h.startsWith("hemlig pki ez activate")) ?? "hemlig pki ez activate <ca-id> --environment <env> --certificate FILE --chain FILE --crl FILE"}`],
        };
      }
      return {
        headline: data.alreadyActive === true ? `CA ${displaySafe(String(data.caId))} was already active` : `Certificate signed and CA activated: ${displaySafe(String(data.caId))}`,
        facts: root?.extId === undefined ? facts : [...facts.slice(0, -1), ["Root ID", displaySafe(String(root.extId))], facts[facts.length - 1] as [string, string]],
        warnings: [...(data.recovered === true ? ["Reused the certificate signed by an earlier run; nothing was signed twice."] : []), ...warnings],
        next: [`Keep the root CRL fresh: it must be uploaded before ${crl === undefined ? "its next update" : day(crl.nextUpdate)}.\n${cmd(ctx, "renew-crl", "--if-due")}`, backupStep(ctx)],
      };
    }
    case "activate":
      return {
        headline: data.alreadyActive === true ? `CA ${displaySafe(String(data.caId))} was already active` : `CA activated: ${displaySafe(String(data.caId))}`,
        facts: [
          ["CA ID", displaySafe(String(data.caId))],
          ["Environment", displaySafe(String(data.environment))],
          ["Serial", String(data.serial)],
          ["Fingerprint", `${shortFingerprint(String(data.fingerprint))} (SHA-256)`],
          ["Root ID", displaySafe(String((data.root as Data).extId))],
          ...(data.crl === undefined ? [] : ([["Root CRL", `#${(data.crl as Data).number}${(data.crl as Data).uploaded === true ? ", uploaded" : (data.crl as Data).skipped !== undefined ? `, not uploaded (${displaySafe(String((data.crl as Data).skipped))})` : ""}`]] as [string, string][])),
        ],
        warnings,
        next: [`Keep the root CRL fresh on the root machine: hemlig pki ez renew-crl --if-due`],
      };
    case "revoke-cert": {
      const crl = data.crl as Data | undefined;
      const online = data.uploaded !== undefined;
      return {
        headline: `Revoked ${displaySafe(String(data.caId ?? `serial ${data.serial}`))}: ${displaySafe(String(data.reason))}`,
        facts: [
          ...(data.caId === null || data.caId === undefined ? [] : ([["CA ID", displaySafe(String(data.caId))]] as [string, string][])),
          ["Serial", String(data.serial)],
          ["Reason", displaySafe(String(data.reason))],
          ["Root CRL", `${crlFact(crl, ctx.now)}${crl?.renewed === true ? ", signed now" : ""}${data.uploaded === true ? ", uploaded" : ""}`],
          ...(data.revoked === true ? ([["Server", "shows the CA as revoked"]] as [string, string][]) : []),
          ...(data.crlFile === undefined ? [] : ([["CRL file", relativeTo(ctx.dir, data.crlFile)]] as [string, string][])),
          ["Directory", ctx.dir],
        ],
        warnings,
        next: online ? [backupStep(ctx)] : [`On a machine that can reach Hemlig, upload the CRL (it refuses one that would drop a revocation):\n${nextHints[0]?.replace(/^On an online machine: /, "") ?? "hemlig pki ez upload-crl --crl FILE --root-cert FILE"}`, backupStep(ctx)],
      };
    }
    case "renew-crl": {
      const crl = data.crl as Data | undefined;
      const offline = data.crlFile !== undefined;
      return {
        headline: data.renewed === true ? `Root CRL renewed: #${crl?.number}` : `Root CRL is current: #${crl?.number}`,
        mark: "ok",
        facts: [
          ["Root CRL", crlFact(crl, ctx.now)],
          ...(data.uploaded === undefined ? [] : ([["Server", data.uploaded === true ? "uploaded" : "already up to date"]] as [string, string][])),
          ...((data.root as Data | undefined)?.extId === undefined ? [] : ([["Root ID", displaySafe(String((data.root as Data).extId))]] as [string, string][])),
          ...(offline ? ([["CRL file", relativeTo(ctx.dir, data.crlFile)]] as [string, string][]) : []),
          ["Directory", ctx.dir],
        ],
        warnings,
        next: offline
          ? [`On a machine that can reach Hemlig, upload it:\n${nextHints[0]?.replace(/^On an online machine: /, "") ?? "hemlig pki ez upload-crl --crl FILE --root-cert FILE"}`, backupStep(ctx)]
          : [`Run again before ${day(crl?.nextUpdate)} (or on a schedule): ${cmd(ctx, "renew-crl", "--if-due")}`, backupStep(ctx)],
      };
    }
    case "upload-crl": {
      const crl = data.crl as Data | undefined;
      return {
        headline: data.uploaded === true ? `Root CRL #${crl?.number} uploaded` : `Root CRL #${crl?.number} is already on the server`,
        facts: [
          ["Root ID", displaySafe(String((data.root as Data | undefined)?.extId ?? ""))],
          ["Root CRL", crl?.nextUpdate === undefined ? `#${crl?.number}` : crlFact(crl, ctx.now)],
          ...(Array.isArray(data.revokedCaIds) && data.revokedCaIds.length > 0 ? ([["Revoked CAs", displaySafe((data.revokedCaIds as string[]).join(", "))]] as [string, string][]) : []),
        ],
        warnings,
      };
    }
    case "status":
      return statusResult(data, ctx);
    default:
      return { headline: String(data.command ?? ctx.command), warnings };
  }
};

const statusResult = (data: Data, ctx: HumanContext): HumanResult => {
  const root = data.root as Data;
  const crl = data.crl as Data | null;
  const issued = (data.issued as Data[]) ?? [];
  const revoked = (data.revoked as Data[]) ?? [];
  const server = data.server as Data | undefined;
  const behind = (data.deploymentsBehind as string[]) ?? [];
  const warnings: string[] = [];
  if (crl?.due === true) warnings.push(`The root CRL is due for renewal (${plural(Number(crl.daysLeft), "day")} left).`);
  if (crl === null) warnings.push("There is no current CRL.");
  if (data.pending !== null && data.pending !== undefined) warnings.push("An operation is pending; the next command will recover it.");
  for (const origin of behind) warnings.push(`${displaySafe(origin)} holds an older root CRL than the current one.`);
  const relation = server?.relation as string | undefined;
  if (relation !== undefined && relation !== "in_sync" && relation !== "not_registered") warnings.push(`The server comparison says: ${displaySafe(relation)}.`);
  const active = issued.filter((e) => e.status === "activated").length;
  const sOrigin = displaySafe(String(server?.origin ?? ""));
  const serverFact =
    server === undefined || server.checked !== true
      ? `not checked${server?.reason === undefined ? "" : ` (${displaySafe(String(server.reason))})`}`
      : relation === "in_sync"
        ? `in sync with ${sOrigin} (${displaySafe(String(server.extId))})`
        : relation === "not_registered"
          ? `${sOrigin} does not know this root yet`
          : `${sOrigin}: ${displaySafe(String(relation))}`;
  return {
    headline: displaySafe(String(root.subject)),
    mark: warnings.length === 0 ? "ok" : "warn",
    facts: [
      ["Origin", `${displaySafe(String(root.origin))}, ${displaySafe(String(root.keyAlgorithm))}, valid until ${day(root.notAfter)}`],
      ["Fingerprint", `${shortFingerprint(String(root.fingerprint))} (SHA-256)`],
      ["Key", (data.key as Data).storage === "yubikey" ? "YubiKey" : `software key file ${relativeTo(ctx.dir, (data.key as Data).file)}`],
      ["CRL", crl === null ? "none" : `${crlFact(crl, ctx.now)}${crl.due === true ? " — renewal due" : ""}`],
      ["Issued", `${plural(issued.length, "certificate")}${issued.length === 0 ? "" : `, ${active} active`}`],
      ["Revoked", String(revoked.length)],
      ["Server", serverFact],
      ["Directory", ctx.dir],
    ],
    warnings,
    next: crl?.due === true || crl === null ? [`Renew the root CRL:\n${cmd(ctx, "renew-crl")}`] : undefined,
  };
};
