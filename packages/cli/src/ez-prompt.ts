import { timingSafeEqual } from "node:crypto";
import { EzError } from "./ez-error";
import { assertPassphrasePolicy, MAX_PASSPHRASE_BYTES } from "./ez-keyfile";
import { isTerminal, readTerminalLine, type TerminalInput } from "./tty";

/**
 * Terminal interaction for `hemlig pki ez`. Everything a human reads or types goes through stderr and the terminal,
 * so stdout stays one JSON receipt. Secrets are read without echo; the typed `confirm` is read from the keyboard
 * only (never from a pipe) and has no bypass.
 */

export const CONFIRM_WORD = "confirm";
const MAX_LINE_BYTES = 4096;

export interface PrompterOptions {
  readonly stdin: TerminalInput;
  /** Prompt and review output (stderr). */
  readonly write: (text: string) => void | Promise<void>;
  /** Opens the controlling terminal when stdin is a pipe; used only for the typed `confirm`. */
  readonly openTerminal?: () => Promise<TerminalInput | undefined>;
}

const cancelled = (): EzError => new EzError(9, "prompt_cancelled", "The prompt was cancelled.");
const tooLarge = (): EzError => new EzError(2, "invalid_input", "That input is too long.");

export class Prompter {
  readonly #stdin: TerminalInput;
  readonly #write: PrompterOptions["write"];
  readonly #openTerminal: PrompterOptions["openTerminal"];
  #pipeIterator: AsyncIterator<string | Uint8Array> | undefined;
  #pipeBuffer = "";
  #pipeEnded = false;

  public constructor(options: PrompterOptions) {
    this.#stdin = options.stdin;
    this.#write = options.write;
    this.#openTerminal = options.openTerminal;
  }

  /** True when stdin is a terminal: the form and the secret prompts are available. */
  public get interactive(): boolean {
    return isTerminal(this.#stdin);
  }

  public async print(text: string): Promise<void> {
    await this.#write(text);
  }

  async #terminalLine(input: TerminalInput, label: string, secret: boolean, maxBytes = MAX_LINE_BYTES): Promise<Buffer> {
    await this.#write(label);
    try {
      return await readTerminalLine(input, {
        maxBytes,
        cancelled,
        tooLarge,
        allowPipe: false,
        notTerminal: () => new EzError(2, "terminal_required", "This input needs a terminal."),
        ...(secret ? {} : { echo: (text: string) => void this.#write(text) }),
      });
    } finally {
      await this.#write("\n");
    }
  }

  /** A secret from the terminal, no echo. Without a terminal it exits 2 `terminal_required`. */
  public async secret(label: string, maxBytes = MAX_PASSPHRASE_BYTES): Promise<Buffer> {
    if (!this.interactive) {
      throw new EzError(2, "terminal_required", "A secret is read from the terminal; pass --passphrase-stdin to read it from a pipe.");
    }
    return this.#terminalLine(this.#stdin, label, true, maxBytes);
  }

  /** One echoed line from the terminal (the settings form). */
  public async text(label: string): Promise<string> {
    if (!this.interactive) throw new EzError(2, "terminal_required", "This input needs a terminal.");
    const bytes = await this.#terminalLine(this.#stdin, label, false);
    try {
      return bytes.toString("utf8");
    } finally {
      bytes.fill(0);
    }
  }

  /** The next line of piped stdin (`--passphrase-stdin`). Never used on a terminal. */
  public async pipeLine(maxBytes = MAX_PASSPHRASE_BYTES + 2): Promise<Buffer> {
    if (this.interactive) {
      throw new EzError(2, "invalid_input", "--passphrase-stdin reads a pipe; stdin is a terminal. Omit the flag to be prompted.");
    }
    const input = this.#stdin;
    this.#pipeIterator ??= typeof input.iterator === "function" ? input.iterator({ destroyOnReturn: false }) : input[Symbol.asyncIterator]();
    for (;;) {
      const end = this.#pipeBuffer.search(/[\r\n]/);
      if (end >= 0) {
        const line = this.#pipeBuffer.slice(0, end);
        this.#pipeBuffer = this.#pipeBuffer.slice(this.#pipeBuffer[end] === "\r" && this.#pipeBuffer[end + 1] === "\n" ? end + 2 : end + 1);
        return Buffer.from(line, "utf8");
      }
      if (Buffer.byteLength(this.#pipeBuffer) > maxBytes) throw tooLarge();
      if (this.#pipeEnded) {
        const rest = this.#pipeBuffer;
        this.#pipeBuffer = "";
        if (rest === "") throw new EzError(2, "invalid_input", "Stdin ended before the passphrase was read.");
        return Buffer.from(rest, "utf8");
      }
      const next = await this.#pipeIterator.next();
      if (next.done === true) this.#pipeEnded = true;
      else this.#pipeBuffer += typeof next.value === "string" ? next.value : Buffer.from(next.value).toString("utf8");
    }
  }

  /**
   * The root key passphrase. `fromStdin` reads the first line of a pipe; otherwise the terminal is prompted, twice for a
   * new key (a mismatch exits 2 `passphrase_mismatch`; the policy is applied before the second prompt). The caller
   * zeroes the returned buffer.
   */
  public async passphrase(options: { readonly create: boolean; readonly fromStdin: boolean; readonly label?: string }): Promise<Buffer> {
    if (options.fromStdin) {
      const line = await this.pipeLine();
      try {
        if (options.create) assertPassphrasePolicy(line);
      } catch (error) {
        line.fill(0);
        throw error;
      }
      return line;
    }
    const first = await this.secret(options.label ?? (options.create ? "New root key passphrase (12+ characters): " : "Root key passphrase: "));
    if (!options.create) return first;
    try {
      assertPassphrasePolicy(first);
      const second = await this.secret("Repeat the passphrase: ");
      const same = first.length === second.length && timingSafeEqual(first, second);
      second.fill(0);
      if (!same) throw new EzError(2, "passphrase_mismatch", "The two passphrases differ.");
      return first;
    } catch (error) {
      first.fill(0);
      throw error;
    }
  }

  async #confirmInput(): Promise<{ input: TerminalInput | undefined; opened: boolean }> {
    if (isTerminal(this.#stdin)) return { input: this.#stdin, opened: false };
    const input = await this.#openTerminal?.();
    return { input: input !== undefined && isTerminal(input) ? input : undefined, opened: input !== undefined };
  }

  /** Fails with `terminal_required` now, before any review is shown, when a typed confirm could not be read later. */
  public async requireConfirmTerminal(action: string): Promise<void> {
    const { input, opened } = await this.#confirmInput();
    if (opened) (input ?? undefined)?.destroy?.();
    if (input === undefined) {
      throw new EzError(
        2,
        "terminal_required",
        `${action} needs the operator to type "${CONFIRM_WORD}" at a terminal; there is no unattended mode and --yes does not skip it.`,
      );
    }
  }

  /**
   * The typed confirmation: the caller has printed the review; the operator must type exactly `confirm` at the keyboard.
   * Anything else exits 2 `confirmation_declined`; ^C or EOF exits 9 `prompt_cancelled`. With stdin piped it uses the
   * controlling terminal, and with none it exits 2 `terminal_required`: signing and revoking are never unattended.
   */
  public async confirm(action: string): Promise<void> {
    const { input, opened } = await this.#confirmInput();
    if (input === undefined) {
      throw new EzError(
        2,
        "terminal_required",
        `${action} needs the operator to type "${CONFIRM_WORD}" at a terminal; there is no unattended mode and --yes does not skip it.`,
      );
    }
    try {
      const typed = await this.#terminalLine(input, `Type "${CONFIRM_WORD}" to ${action}; anything else aborts: `, false, 64);
      if (typed.toString("utf8") !== CONFIRM_WORD) {
        throw new EzError(2, "confirmation_declined", `Not confirmed; nothing was ${action === "revoke" ? "revoked" : "signed"} and no state changed.`);
      }
    } finally {
      if (opened) input.destroy?.();
    }
  }
}
