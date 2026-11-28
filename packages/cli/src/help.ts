import { backstop, makeStyle, wrapText, type OutputMode, type Style } from "./output";

/**
 * Help on a terminal. The JSON help (usage plus commands) stays what it was for pipes and `--json`; on a terminal the
 * same objects are rendered as plain text, so the two cannot drift: usage strings are split into one alternative per
 * line, command synopses become aligned option lists, and per-command help comes from the same table.
 */

/** Option descriptions shared by the JSON help (`hemlig --help`) and the terminal help of every command. */
export const optionHelp = {
  "--console-url": "Console HTTPS origin for login; defaults to HEMLIG_CONSOLE_URL.",
  "--no-browser": "login only: print the URL instead of opening a browser.",
  "--no-localhost":
    "login only: no local callback listener; copy the login code shown by the console and paste it into the terminal. Default when SSH_CONNECTION or SSH_TTY is set.",
  "--localhost": "login only: use the 127.0.0.1 callback listener even in an SSH session. Cannot be combined with --no-localhost.",
  "--admin-url":
    "Administrator origin; defaults to HEMLIG_ADMIN_URL, then the API recorded by hemlig login when the cached login is the token source.",
  "--environment": "Logical environment; defaults to HEMLIG_ENVIRONMENT. Not used by consumer get, identities or revoke-identity.",
  "--token-file":
    "OIDC bearer token file; defaults to HEMLIG_ADMIN_TOKEN_FILE, then HEMLIG_ADMIN_TOKEN, then the token cached by hemlig login.",
  "--consumer-id": "Consumer ID, for hemlig consumer get|identities|revoke-identity.",
  "--fingerprint":
    "revoke-identity only: full 64-hex SHA-256 or a unique prefix of at least 12 hex characters, resolved against the consumer's identities.",
  "--cursor": "consumer list|identities: nextCursor from the previous page; one page is returned per call.",
  "--secret-id": "Reusable secret ID for active records.",
  "--secret-uid": "Immutable UID for archived records (read only).",
  "--input": "JSON file, or - for stdin. Required for create, update, write-payload.",
  "--if-match": "Known controlVersionId/strong ETag, or current to fetch it once. Required for update, write-payload, archive.",
  "--idempotency-key":
    "Durable operation key (secret mutations and consumer revoke-identity); defaults to a newly minted UUID for each mutation.",
  "--timeout-ms": "Per-request timeout (1–300000 milliseconds); default 30000.",
};

/** Terminal-only: `--json` is accepted everywhere but is not part of the JSON help shape. */
const JSON_OPTION = "Print the JSON envelope instead of text. Output is JSON anyway when stdout is not a terminal.";

const PLACEHOLDERS: Record<string, string> = {
  "--console-url": "<url>",
  "--admin-url": "<url>",
  "--environment": "<env>",
  "--token-file": "<file>",
  "--consumer-id": "<id>",
  "--fingerprint": "<hex>",
  "--cursor": "<cursor>",
  "--secret-id": "<id>",
  "--secret-uid": "<uid>",
  "--input": "<file|->",
  "--if-match": "<etag|current>",
  "--idempotency-key": "<key>",
  "--timeout-ms": "<ms>",
};

const WIDTH = 88;

export interface HelpSection {
  readonly title: string;
  /** Aligned rows: a term and its description. */
  readonly rows?: readonly (readonly [string, string])[];
  /** Plain paragraphs. */
  readonly text?: readonly string[];
  /** Verbatim lines (alternatives of a usage string). */
  readonly lines?: readonly string[];
}

export interface HelpPage {
  /** One-line description under the title. */
  readonly summary?: string;
  readonly sections: readonly HelpSection[];
}

const KEY_MAX = 34;

const definitions = (rows: readonly (readonly [string, string])[]): string[] => {
  const width = Math.min(KEY_MAX, Math.max(...rows.map(([k]) => k.length)));
  const out: string[] = [];
  for (const [key, description] of rows) {
    const descLines = description === "" ? [] : wrapText(description, WIDTH - 4 - width);
    if (key.length > width) {
      out.push(key);
      for (const l of descLines) out.push(`${" ".repeat(width + 2)}${l}`);
    } else if (descLines.length === 0) out.push(key);
    else {
      out.push(`${key.padEnd(width)}  ${descLines[0]}`);
      for (const l of descLines.slice(1)) out.push(`${" ".repeat(width + 2)}${l}`);
    }
  }
  return out;
};

export const renderHelpPage = (page: HelpPage, style: Style): string => {
  // Content is escaped before it is styled, so the escape codes of the style itself survive.
  const out: string[] = [];
  if (page.summary !== undefined) out.push(...wrapText(backstop(page.summary), WIDTH), "");
  for (const section of page.sections) {
    out.push(style.bold(section.title));
    for (const p of section.text ?? []) out.push(...wrapText(backstop(p), WIDTH - 2).map((l) => `  ${l}`));
    for (const l of section.lines ?? []) out.push(...wrapText(backstop(l), WIDTH - 4).map((w, i) => `${i === 0 ? "  " : "      "}${w}`));
    if (section.rows !== undefined && section.rows.length > 0) out.push(...definitions(section.rows.map(([k, v]) => [backstop(k), backstop(v)] as const)).map((l) => `  ${l}`));
    out.push("");
  }
  while (out[out.length - 1] === "") out.pop();
  return `${out.join("\n")}\n`;
};

/** Writes the help page: text on a terminal, `json` (the unchanged JSON help line) otherwise. */
export const emitHelp = async (
  mode: OutputMode,
  stdout: (text: string) => unknown,
  jsonHelp: unknown,
  page: () => HelpPage,
): Promise<void> => {
  if (mode.human) {
    let text: string | undefined;
    try {
      text = renderHelpPage(page(), makeStyle(mode.color));
    } catch {
      text = undefined;
    }
    if (text !== undefined) {
      await stdout(text);
      return;
    }
  }
  await stdout(`${JSON.stringify(jsonHelp)}\n`);
};

/** The alternatives of a usage string, one per line. */
export const usageLines = (usage: string): string[] => usage.split(" | ").map((l) => l.trim());

// ---------------------------------------------------------------------------------------------------------------------
// Synopsis parsing (pki and pki ez command tables)
// ---------------------------------------------------------------------------------------------------------------------

interface SynopsisItem {
  readonly syntax: string;
  readonly need: "required" | "optional" | "one of";
}

/** Splits at top-level whitespace and at a top-level semicolon (the rest is prose). */
const synopsisTokens = (text: string): { tokens: string[]; prose: string } => {
  const tokens: string[] = [];
  let current = "";
  let depth = 0;
  let quote = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i] as string;
    if (c === "'") quote = !quote;
    if (!quote) {
      if (c === "[" || c === "(") depth += 1;
      if (c === "]" || c === ")") depth = Math.max(0, depth - 1);
      if (c === ";" && depth === 0) {
        if (current !== "") tokens.push(current);
        return { tokens, prose: text.slice(i + 1).trim() };
      }
      if (/\s/.test(c) && depth === 0) {
        if (current !== "") tokens.push(current);
        current = "";
        continue;
      }
    }
    current += c;
  }
  if (current !== "") tokens.push(current);
  return { tokens, prose: "" };
};

export const parseSynopsis = (text: string): { items: SynopsisItem[]; notes: string[] } => {
  const { tokens, prose } = synopsisTokens(text);
  const items: SynopsisItem[] = [];
  const notes: string[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i] as string;
    const repeat = token.endsWith("...");
    const body = repeat ? token.slice(0, -3) : token;
    if (body.startsWith("[") && body.endsWith("]")) items.push({ syntax: `${body.slice(1, -1)}${repeat ? " (repeatable)" : ""}`, need: "optional" });
    else if (body.startsWith("(") && body.endsWith(")")) {
      const inner = body.slice(1, -1);
      if (inner.includes("--")) items.push({ syntax: inner, need: "one of" });
      else notes.push(inner);
    } else if (body.startsWith("--")) {
      const parts = [body];
      while (i + 1 < tokens.length && !/^(--|\[|\()/.test(tokens[i + 1] as string)) {
        i += 1;
        parts.push(tokens[i] as string);
      }
      items.push({ syntax: `${parts.join(" ")}${repeat ? " (repeatable)" : ""}`, need: "required" });
    }
  }
  if (prose !== "") notes.push(prose.charAt(0).toUpperCase() + prose.slice(1));
  return { items, notes };
};

const NEED_TEXT = { required: "required", optional: "optional", "one of": "required, one of" } as const;

interface TableEntry {
  readonly key: string;
  readonly path: readonly string[];
  readonly operands: string;
  readonly synopsis: string;
}

/** `ca get <ca>` becomes the path `ca get` and the operands `<ca>`. */
const tableEntry = (key: string, synopsis: string): TableEntry => {
  const words = key.split(" ");
  const path: string[] = [];
  let at = 0;
  while (at < words.length && /^[a-z][a-z0-9-]*$/.test(words[at] as string)) {
    path.push(words[at] as string);
    at += 1;
  }
  // A flag-like word (`--offline`) after the operands belongs to the operands text.
  return { key, path, operands: words.slice(at).join(" "), synopsis };
};

export interface TableHelp {
  readonly usage: string;
  readonly commands: Readonly<Record<string, string>>;
  readonly [other: string]: unknown;
}

const humanTitle = (key: string): string => {
  const spaced = key.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/-/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
};

/** Common options of a table-driven group (pki, pki ez). `names` are option names without the dashes. */
const sharedOptionRows = (names: readonly string[]): [string, string][] => [
  ...names.flatMap((n): [string, string][] => {
    const flag = `--${n}`;
    const text = (optionHelp as Record<string, string>)[flag];
    return text === undefined ? [] : [[`${flag} ${PLACEHOLDERS[flag] ?? ""}`.trim(), text]];
  }),
  ["--json", JSON_OPTION],
];

export interface TableHelpOptions {
  /** `hemlig pki` or `hemlig pki ez`. */
  readonly prefix: string;
  /** What the user typed after the prefix, flags removed. */
  readonly path: readonly string[];
  readonly summary: string;
  readonly sharedOptions: readonly string[];
}

/** Help for a table-driven group: the whole group, a sub-group (`ca`, `ca crl`) or one command. */
export const tableHelpPage = (help: TableHelp, options: TableHelpOptions): HelpPage => {
  const entries = Object.entries(help.commands).map(([key, synopsis]) => tableEntry(key, synopsis));
  // Operand values after the command (`ca get ca-1`) are not part of the path: keep the longest prefix some command has.
  let asked = options.path;
  while (asked.length > 0 && !entries.some((e) => asked.every((word, i) => e.path[i] === word))) asked = asked.slice(0, -1);
  const matches = entries.filter((e) => asked.length > 0 && asked.every((word, i) => e.path[i] === word));
  const exact = matches.filter((e) => e.path.length === asked.length);
  const extras = Object.entries(help).filter(([key, value]) => key !== "usage" && key !== "commands" && typeof value === "string") as [string, string][];
  const notes: HelpSection[] = extras
    .filter(([key]) => !key.includes("<"))
    .map(([key, value]) => ({ title: key === "common" ? "Every command" : humanTitle(key), text: [value] }));
  const shared: HelpSection = { title: "Common options", rows: sharedOptionRows(options.sharedOptions) };

  if (exact.length > 0) {
    // One command (ez has two forms of sign-cert, so there may be several entries).
    const sections: HelpSection[] = [];
    sections.push({
      title: "Usage",
      lines: exact.map((e) => `${options.prefix} ${e.path.join(" ")}${e.operands === "" ? "" : ` ${e.operands}`}${parseSynopsis(e.synopsis).items.length > 0 ? " [options]" : ""}`),
    });
    for (const e of exact) {
      const parsed = parseSynopsis(e.synopsis);
      const label = exact.length > 1 ? `Options of ${options.prefix} ${e.key}` : "Options";
      if (parsed.items.length > 0) sections.push({ title: label, rows: parsed.items.map((i) => [i.syntax, NEED_TEXT[i.need]] as [string, string]) });
      if (parsed.notes.length > 0) sections.push({ title: "Notes", text: parsed.notes });
    }
    sections.push(shared);
    return { sections };
  }

  const group = matches.length > 0 ? matches : entries;
  const heading = matches.length > 0 ? `${options.prefix} ${asked.join(" ")}` : options.prefix;
  const usage = usageLines(help.usage).filter((l) => matches.length === 0 || l.startsWith(heading));
  const rows: [string, string][] = group.map((e) => {
    // The options part of the synopsis (the prose after the semicolon is on the command's own page).
    const head = (e.synopsis.split(";")[0] as string).trim();
    return [e.key, head.length > 100 ? `${options.prefix} ${e.path.join(" ")} --help` : head];
  });
  for (const [key, value] of extras) if (key.includes("<") && matches.length === 0) rows.push([key, value]);
  return {
    summary: matches.length === 0 ? options.summary : undefined,
    sections: [
      { title: "Usage", lines: usage.length > 0 ? usage : [help.usage] },
      { title: "Commands", rows },
      ...(matches.length === 0 ? notes : []),
      shared,
    ],
  };
};

/** The first non-flag arguments: the path the user typed before `--help`. */
export const helpPath = (args: readonly string[], valueFlags: ReadonlySet<string>): string[] => {
  const path: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    if (arg.startsWith("-")) {
      if (!arg.includes("=") && valueFlags.has(arg)) i += 1;
      continue;
    }
    path.push(arg);
  }
  return path;
};

// ---------------------------------------------------------------------------------------------------------------------
// The top-level hemlig command (secret, consumer, login, logout, idempotency-key)
// ---------------------------------------------------------------------------------------------------------------------

export interface IndexHelpJson {
  readonly usage: string;
  readonly commands: readonly string[];
  readonly consumerCommands: Readonly<Record<string, string>>;
  readonly topLevelCommands: Readonly<Record<string, string>>;
  readonly options: Readonly<Record<string, string>>;
  readonly output: string;
  readonly exitCodes: Readonly<Record<string, string>>;
}

export interface IndexHelpContext {
  readonly help: IndexHelpJson;
  /** What `hemlig secret <command>` does (the JSON help lists only the names). */
  readonly secretCommands: Readonly<Record<string, string>>;
  /** Option names (no dashes) a command accepts, from the same table that validates them. */
  readonly optionsOf: (group: "secret" | "consumer", command: string) => readonly string[];
  /** Option names (no dashes) a command needs before it can run. */
  readonly requiredOf: (group: "secret" | "consumer", command: string) => readonly string[];
  readonly loginOptions: readonly string[];
}

const optionRows = (names: readonly string[], help: IndexHelpJson): [string, string][] => {
  // Keep the order of the JSON help's options table.
  const order = Object.keys(help.options);
  const flags = names.map((n) => `--${n}`).sort((a, b) => order.indexOf(a) - order.indexOf(b));
  return [
    ...flags.map((flag): [string, string] => [`${flag} ${PLACEHOLDERS[flag] ?? ""}`.trim(), help.options[flag] ?? ""]),
    ["--json", JSON_OPTION],
  ];
};

export const indexHelpPage = (path: readonly string[], context: IndexHelpContext): HelpPage => {
  const { help } = context;
  const exitRows = Object.entries(help.exitCodes) as [string, string][];
  const [group, command] = path;
  const terminalOutput = "On a terminal, results and errors print as text; exit codes never change. Piped or with --json:";

  if (group === "secret" || group === "consumer") {
    const table: Readonly<Record<string, string>> = group === "secret" ? context.secretCommands : help.consumerCommands;
    if (command !== undefined && command in table) {
      const names = context.optionsOf(group, command);
      const required = new Set(context.requiredOf(group, command));
      const synopsis = [...required].map((n) => `--${n} ${PLACEHOLDERS[`--${n}`] ?? ""}`.trim()).join(" ");
      return {
        summary: table[command],
        sections: [
          { title: "Usage", lines: [`hemlig ${group} ${command}${synopsis === "" ? "" : ` ${synopsis}`}${names.length > required.size ? " [options]" : ""}`] },
          { title: "Options", rows: optionRows(names, help) },
        ],
      };
    }
    const commands = Object.keys(table);
    return {
      sections: [
        { title: "Usage", lines: [`hemlig ${group} <${commands.join("|")}> [options]`] },
        { title: "Commands", rows: commands.map((c) => [c, table[c] as string] as [string, string]) },
        { title: "Run for the options of one command", lines: [`hemlig ${group} <command> --help`] },
      ],
    };
  }
  if (group === "login" || group === "logout" || group === "idempotency-key") {
    return {
      summary: help.topLevelCommands[group],
      sections: [
        { title: "Usage", lines: [group === "login" ? "hemlig login [options]" : `hemlig ${group}`] },
        ...(group === "login" ? [{ title: "Options", rows: optionRows(context.loginOptions, help) }] : []),
      ],
    };
  }
  return {
    summary: "Hemlig administrator CLI: secrets, consumers and PKI.",
    sections: [
      { title: "Usage", lines: usageLines(help.usage) },
      {
        title: "Commands",
        rows: [
          ["secret <command>", `${help.commands.join(", ")}. Run hemlig secret --help.`],
          ["consumer <command>", `${Object.keys(help.consumerCommands).join(", ")}. Run hemlig consumer --help.`],
          ["pki <group> <command>", "Certificate authorities, issuance grants and certificates. Run hemlig pki --help."],
          ...Object.entries(help.topLevelCommands).map(([k, v]): [string, string] => [k, v]),
        ],
      },
      { title: "Options", rows: optionRows(Object.keys(help.options).map((k) => k.slice(2)), help) },
      { title: "Output", text: [`${terminalOutput} ${help.output.charAt(0).toLowerCase()}${help.output.slice(1)}`] },
      { title: "Exit codes", rows: exitRows },
    ],
  };
};
