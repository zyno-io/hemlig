import { displaySafe } from "./ez-x509";
import { colorWanted, makeStyle, renderError, type ErrorInfo, type Style } from "./ez-render";
import { reportFailure, type CliDependencies, type FailureContext } from "./common";

export * from "./ez-render";

/**
 * Output mode and writers shared by every `hemlig` command. On a terminal a command prints a human result or error
 * (see ez-render.ts); piped output and `--json` keep the JSON envelope byte for byte.
 */

// ---------------------------------------------------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------------------------------------------------

export interface OutputMode {
  /** Results (and help) go to stdout: human only on a terminal without --json. */
  readonly human: boolean;
  /** Errors go to stderr: human only when stderr is a terminal and --json is absent. */
  readonly errorHuman: boolean;
  readonly color: boolean;
}

/** Injected writers are not terminals unless a test says so; otherwise the real streams are asked. */
export const resolveMode = (dependencies: CliDependencies, args: readonly string[], env: NodeJS.ProcessEnv): OutputMode => {
  const stdoutTty = dependencies.stdoutIsTTY ?? (dependencies.stdout === undefined && process.stdout.isTTY === true);
  const stderrTty = dependencies.stderrIsTTY ?? (dependencies.stderr === undefined && process.stderr.isTTY === true);
  const json = args.includes("--json");
  return { human: stdoutTty && !json, errorHuman: stderrTty && !json, color: colorWanted(env, true) };
};

/**
 * Writes a result: the human rendering on a terminal, the JSON envelope otherwise. A renderer bug must never change
 * the exit code or hide the result, so a throwing renderer falls back to the envelope.
 */
export const emitResult = async (
  mode: OutputMode,
  stdout: (text: string) => unknown,
  envelope: unknown,
  render: (style: Style) => string,
): Promise<void> => {
  if (mode.human) {
    let text: string | undefined;
    try {
      text = render(makeStyle(mode.color));
    } catch {
      text = undefined;
    }
    if (text !== undefined) {
      await stdout(text);
      return;
    }
  }
  await stdout(`${JSON.stringify(envelope)}\n`);
};

/**
 * Reports a failure: the JSON envelope on stderr unless stderr is a terminal and --json is absent, in which case the
 * same classification (and exit code) is printed for a person. A renderer bug keeps the plain envelope.
 */
export const reportFailureFor = async (
  mode: OutputMode,
  error: unknown,
  context: FailureContext,
  stderr: (text: string) => unknown,
  render: (info: ErrorInfo, style: Style) => string = (info, style) => renderError(info, style),
): Promise<number> => {
  if (!mode.errorHuman) return reportFailure(error, context, stderr);
  let envelope = "";
  const code = await reportFailure(error, context, (text) => {
    envelope += text;
  });
  let text = envelope;
  try {
    const parsed = JSON.parse(envelope.trim().split("\n").pop() as string) as { error: ErrorInfo; idempotencyKey?: string; ez?: ErrorInfo["ez"] };
    text = render({ ...parsed.error, ez: parsed.ez ?? parsed.error.ez, idempotencyKey: parsed.idempotencyKey }, makeStyle(mode.color));
  } catch {
    // keep the plain envelope
  }
  try {
    await stderr(text);
  } catch {
    // A closed or failing stderr cannot carry the message; the exit code is the same as for the JSON envelope.
    return 9;
  }
  return code;
};

export { displaySafe };
