/**
 * Terminal rendering primitives: styles, escaping, the result renderer and the error renderer. Pure (no client, no I/O),
 * and named ez- so that the EZ library's import boundary holds; every command's human output is built on it.
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

export const colorWanted = (env: NodeJS.ProcessEnv, interactive: boolean): boolean =>
  interactive && env.NO_COLOR === undefined && env.TERM !== "dumb";

// ---------------------------------------------------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------------------------------------------------

/**
 * Last line of defense for terminal output: values from servers and files are already `displaySafe` where they enter a
 * result, and this strips any control, C1 or bidirectional-override character that is left (keeping newlines).
 */
export const backstop = (text: string): string =>
  text.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, (c) => {
    const code = c.charCodeAt(0);
    return code < 256 ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
  });

/** For a value that must stay on one line: the same, and a newline is escaped too. */
export const oneLine = (text: string): string => backstop(text).replace(/\n/g, "\\x0a");

export const indent = (text: string, by: string): string => text.split("\n").map((line, i) => (i === 0 ? line : `${by}${line}`)).join("\n");

/** Greedy word wrap; a word longer than the width stays whole. */
export const wrapText = (text: string, width: number): string[] => {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/).filter((w) => w !== "")) {
    if (line !== "" && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else line = line === "" ? word : `${line} ${word}`;
  }
  if (line !== "") lines.push(line);
  return lines.length === 0 ? [""] : lines;
};

export const shellQuote = (value: string): string => (/^[A-Za-z0-9._/:=@%+-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`);

// ---------------------------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------------------------

export interface HumanResult {
  /** The one-line result; `mark` picks the symbol (default a check mark). */
  readonly headline: string;
  readonly mark?: "ok" | "warn" | "none";
  readonly facts?: readonly (readonly [string, string])[];
  /** Extra preformatted lines (the status dashboard's table), shown after the facts. */
  readonly body?: readonly string[];
  /** An aligned table (lists), shown after the facts. */
  readonly table?: { readonly head: readonly string[]; readonly rows: readonly (readonly string[])[] };
  /** Dim lines after the table (a paging hint). */
  readonly notes?: readonly string[];
  readonly warnings?: readonly string[];
  /** Numbered steps; a step may hold several lines (the second and later are indented under the number). */
  readonly next?: readonly string[];
}

const MAX_CELL = 56;
const cell = (text: string): string => {
  const safe = oneLine(text);
  return safe.length > MAX_CELL ? `${safe.slice(0, MAX_CELL - 1)}…` : safe;
};

export const renderHuman = (result: HumanResult, style: Style): string => {
  const safe = oneLine;
  const mark = result.mark ?? "ok";
  const out: string[] = [];
  out.push(`${mark === "ok" ? `${style.green("✓")} ` : mark === "warn" ? `${style.yellow("!")} ` : ""}${style.bold(safe(result.headline))}`);
  const facts = result.facts ?? [];
  if (facts.length > 0) {
    const width = Math.max(...facts.map(([label]) => label.length));
    out.push("", ...facts.map(([label, value]) => `  ${style.dim(label.padEnd(width))}  ${safe(value)}`));
  }
  if ((result.body ?? []).length > 0) out.push("", ...(result.body as string[]).map((line) => `  ${safe(line)}`));
  if (result.table !== undefined && result.table.rows.length > 0) {
    const head = result.table.head;
    const rows = result.table.rows.map((row) => row.map(cell));
    const widths = head.map((h, i) => Math.max(h.length, ...rows.map((row) => (row[i] ?? "").length)));
    const line = (cells: readonly string[]): string => cells.map((c, i) => (i === cells.length - 1 ? c : c.padEnd(widths[i] as number))).join("  ").trimEnd();
    out.push("", `  ${style.dim(line(head))}`, ...rows.map((row) => `  ${line(row)}`));
  }
  if ((result.notes ?? []).length > 0) out.push("", ...(result.notes as string[]).map((n) => `  ${style.dim(safe(n))}`));
  if ((result.warnings ?? []).length > 0) out.push("", ...(result.warnings as string[]).map((w) => `${style.yellow("!")} ${safe(w)}`));
  if ((result.next ?? []).length > 0) {
    out.push("", style.bold("Next steps"));
    (result.next as string[]).forEach((step, i) => out.push(`  ${i + 1}. ${indent(backstop(step), "     ")}`));
  }
  return `${out.join("\n")}\n`;
};

// ---------------------------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------------------------

/** Hints for the codes every command can raise; the code stays in the output for scripts and support. */
export const CLI_ERROR_HINTS: Record<string, string> = {
  invalid_input: "Run hemlig --help, or hemlig <command> --help, for the options of a command.",
  unauthorized: "The token was rejected. Run `hemlig login`, or check the token source you passed.",
  forbidden: "This account may not do that in this environment.",
  login_expired: "Run `hemlig login` to sign in again.",
  login_mismatch: "Run `hemlig login` for the API you are addressing, or pass --token-file.",
  login_timeout: "Run `hemlig login` again and finish the sign-in in the browser before it times out.",
  precondition_failed: "Someone changed it first. Read the current version, then run the command again with its --if-match.",
  conflict: "Nothing was retried. Check the current state before running the command again.",
  transport_error: "Check --admin-url and the network connection. A mutation may already have completed: read the resource before repeating it.",
  service_error: "A mutation may already have completed: read the resource before repeating it.",
};

export interface ErrorInfo {
  readonly exitCode: number;
  readonly code: string;
  readonly message: string;
  readonly details?: Record<string, unknown>;
  readonly status?: number;
  readonly apiCode?: string;
  readonly apiDetails?: unknown;
  /** Mutations only: whether the request was `not_sent`, `rejected` or of `unknown` outcome. */
  readonly outcome?: string;
  readonly idempotencyKey?: string;
  /** What had already happened when the command failed, from the JSON envelope's `ez` object. */
  readonly ez?: { readonly completed?: readonly string[]; readonly files?: Readonly<Record<string, string>>; readonly rerun?: string; readonly recovery?: string };
}

export interface ErrorOptions {
  /** Facts of a partly completed run that are not in the JSON envelope (the new root's fingerprint). */
  readonly fingerprint?: string;
  /** The flag (`--out`, `--crl-out`, ...) that names this output file, when it is one. */
  readonly flagFor?: (file: string) => string | undefined;
  /** Hints by error code; defaults to the CLI-wide ones. */
  readonly hints?: Readonly<Record<string, string>>;
}

const compact = (value: unknown): string => oneLine(typeof value === "string" ? value : (JSON.stringify(value) ?? String(value))).slice(0, 400);

const OUTCOME_TEXT: Record<string, string> = {
  not_sent: "The request was not sent; nothing changed.",
  rejected: "The server rejected the request; nothing changed.",
  unknown: "The request was sent and its outcome is unknown: read the resource before repeating it.",
};

export const renderError = (error: ErrorInfo, style: Style, options: ErrorOptions = {}): string => {
  const hints = options.hints ?? CLI_ERROR_HINTS;
  const lines = [`${style.red("✗")} ${style.bold(oneLine(error.message))}`, `  ${style.dim(`(${oneLine(error.code)}, exit ${error.exitCode})`)}`];
  const files = Array.isArray(error.details?.files) ? (error.details?.files as unknown[]) : [];
  const outputFlag = error.code === "already_exists" && files.length === 1 ? options.flagFor?.(String(files[0])) : undefined;
  const hint = outputFlag !== undefined ? hints.already_exists_output?.replace("that output", `${outputFlag} (${compact(files[0])})`) : hints[error.code];
  if (hint !== undefined) lines.push(`  ${oneLine(hint)}`);
  // Everything the JSON envelope would say, compactly: a person fixing a failed mutation needs the same facts a script gets.
  for (const [key, value] of Object.entries(error.details ?? {})) lines.push(`  ${oneLine(key)}: ${compact(value)}`);
  if (error.status !== undefined) lines.push(`  HTTP status: ${compact(error.status)}`);
  if (error.apiCode !== undefined) lines.push(`  API code: ${compact(error.apiCode)}`);
  if (error.apiDetails !== undefined) lines.push(`  API details: ${compact(error.apiDetails)}`);
  if (error.outcome !== undefined) lines.push(`  ${oneLine(OUTCOME_TEXT[error.outcome] ?? error.outcome)}`);
  if (error.idempotencyKey !== undefined && error.outcome === "unknown") lines.push(`  Idempotency key: ${compact(error.idempotencyKey)} (pass it again to replay safely)`);
  if (error.ez?.completed !== undefined && error.ez.completed.length > 0) lines.push(`  Done before the failure: ${compact(error.ez.completed.join(", "))}.`);
  if (options.fingerprint !== undefined) lines.push(`  Root fingerprint: ${compact(options.fingerprint)} (SHA-256)`);
  for (const [name, file] of Object.entries(error.ez?.files ?? {})) lines.push(`  File ${oneLine(name)}: ${compact(file)}`);
  if (error.ez?.recovery !== undefined) lines.push(`  ${oneLine(error.ez.recovery)}`);
  else if (error.ez?.rerun !== undefined) lines.push(`  To retry: ${oneLine(error.ez.rerun)}`);
  return `${lines.join("\n")}\n`;
};

