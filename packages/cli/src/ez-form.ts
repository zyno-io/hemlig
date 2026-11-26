import { EzError } from "./ez-error";
import { displaySafe } from "./ez-x509";
import type { Prompter } from "./ez-prompt";

/**
 * The settings form: a numbered list the operator can review and edit before `generate-ca` and `sign-cert`. It is a
 * plain line loop (no cursor movement, no full-screen mode), so it works over SSH, in small terminals and in tmux.
 * Flags pre-fill it; `--yes` and a non-terminal stdin skip it.
 */

export interface FormField {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  /** `choice` accepts one of `choices` (by name or number); `readonly` is shown but cannot be edited. */
  readonly kind: "text" | "choice" | "readonly";
  readonly choices?: readonly string[];
  /** Shown beside the value. */
  readonly hint?: string;
  /** Returns an error message, or undefined when the value is acceptable. Empty values are validated too. */
  readonly validate?: ((value: string) => string | undefined) & {
    /** The same check, throwing the original error (used when the form is skipped, so the error keeps its code). */
    readonly throws?: (value: string) => unknown;
  };
  /** An empty value is acceptable (blank means "none"). */
  readonly optional?: boolean;
}

export interface FormOptions {
  readonly title: string;
  readonly fields: readonly FormField[];
  readonly prompter: Prompter;
  /** Terminal width used to keep the list readable (default 80). */
  readonly columns?: number;
  readonly color?: boolean;
  /** Edit rounds before giving up (a safety valve for runaway input). */
  readonly maxRounds?: number;
}

const bold = (color: boolean, text: string): string => (color ? `\x1b[1m${text}\x1b[0m` : text);
const dim = (color: boolean, text: string): string => (color ? `\x1b[2m${text}\x1b[0m` : text);

const shown = (field: FormField): string => {
  const value = displaySafe(field.value);
  return value === "" ? "(none)" : value;
};

export const renderForm = (title: string, fields: readonly FormField[], columns: number, color: boolean): string => {
  const width = Math.max(...fields.map((f) => f.label.length));
  const lines = [`\n${bold(color, displaySafe(title))}`, dim(color, "Review the settings. Enter a number to edit it, or press Enter to accept.")];
  let index = 0;
  for (const field of fields) {
    const number = field.kind === "readonly" ? " -" : `${String((index += 1))}`.padStart(2);
    const hint = field.hint === undefined ? "" : `  ${dim(color, field.hint)}`;
    const choices = field.kind === "choice" && field.choices !== undefined ? `  ${dim(color, `[${field.choices.join(" | ")}]`)}` : "";
    const line = `${number}) ${field.label.padEnd(width)}  ${shown(field)}${choices}${hint}`;
    // A long value wraps under the label column instead of running off a small terminal.
    lines.push(line.length <= columns ? line : `${number}) ${field.label}\n      ${shown(field)}${choices}${hint}`);
  }
  return `${lines.join("\n")}\n`;
};

/** The first message of any field that fails validation, or undefined. */
export const firstFormError = (fields: readonly FormField[]): string | undefined => {
  for (const field of fields) {
    if (field.kind === "readonly") continue;
    if (field.kind === "choice" && !(field.choices ?? []).includes(field.value)) {
      return `${field.label}: choose one of ${(field.choices ?? []).join(", ")}.`;
    }
    if (field.value === "" && field.optional !== true) return `${field.label} is required.`;
    const error = field.value === "" && field.optional === true ? undefined : field.validate?.(field.value);
    if (error !== undefined) return `${field.label}: ${error}`;
  }
  return undefined;
};

const resolveChoice = (field: FormField, answer: string): string | undefined => {
  const choices = field.choices ?? [];
  const byNumber = /^\d+$/.test(answer) ? choices[Number(answer) - 1] : undefined;
  return byNumber ?? choices.find((c) => c.toLowerCase() === answer.toLowerCase());
};

/** Runs the form and returns the final values by field id. Throws if the terminal is cancelled (^C or EOF). */
export const runForm = async (options: FormOptions): Promise<Record<string, string>> => {
  const { prompter } = options;
  const color = options.color ?? false;
  const columns = options.columns ?? 80;
  const values = new Map(options.fields.map((f) => [f.id, f.value]));
  const current = (): FormField[] => options.fields.map((f) => ({ ...f, value: values.get(f.id) as string }));
  for (let round = 0; round < (options.maxRounds ?? 500); round += 1) {
    const fields = current();
    await prompter.print(renderForm(options.title, fields, columns, color));
    const editable = fields.filter((f) => f.kind !== "readonly");
    const answer = (await prompter.text("Edit # (Enter to accept): ")).trim();
    if (answer === "") {
      const error = firstFormError(fields);
      if (error === undefined) return Object.fromEntries(values);
      await prompter.print(`${error}\n`);
      continue;
    }
    const field = /^\d+$/.test(answer) ? editable[Number(answer) - 1] : undefined;
    if (field === undefined) {
      await prompter.print(`Enter a number from 1 to ${editable.length}, or press Enter to accept.\n`);
      continue;
    }
    const prompt =
      field.kind === "choice"
        ? `${field.label} (${(field.choices ?? []).map((c, i) => `${i + 1}=${c}`).join(", ")}) [${field.value}]: `
        : `${field.label} [${field.value === "" ? "none" : field.value}] (Enter keeps it${field.optional === true ? ", - clears it" : ""}): `;
    const raw = (await prompter.text(prompt)).trim();
    if (raw === "") continue;
    const next = field.kind === "choice" ? resolveChoice(field, raw) : field.optional === true && raw === "-" ? "" : raw;
    if (next === undefined) {
      await prompter.print(`Choose one of: ${(field.choices ?? []).join(", ")}.\n`);
      continue;
    }
    const error = next === "" && field.optional === true ? undefined : field.validate?.(next);
    if (error !== undefined) {
      await prompter.print(`${error}\n`);
      continue;
    }
    values.set(field.id, next);
  }
  throw new EzError(2, "invalid_input", "The settings form did not finish.");
};
