/**
 * Line reader for terminals and pipes, shared by `hemlig login --no-localhost` (a pasted code) and `hemlig pki ez`
 * (passphrases, PINs, the typed `confirm`). On a terminal it runs in raw mode with no echo, because canonical mode
 * truncates a line at 1024 bytes on macOS. Secrets come back as a `Buffer` that the caller zeroes after use.
 */

/** Input stream; process.stdin satisfies it. */
export interface TerminalInput extends AsyncIterable<string | Uint8Array> {
  readonly isTTY?: boolean;
  setRawMode?(mode: boolean): unknown;
  pause?(): unknown;
  resume?(): unknown;
  /** Called when a read is abandoned (timeout) so the process can exit. */
  destroy?(): unknown;
  /** Node streams: an iterator that leaves the stream open when the read ends, so it can be read again. */
  iterator?(options: { destroyOnReturn: boolean }): AsyncIterator<string | Uint8Array>;
  /** Node streams: pushes bytes read past the end of the line back for the next reader. */
  unshift?(chunk: Buffer): unknown;
}

const BRACKETED_PASTE = ["\x1b[200~", "\x1b[201~"];

export interface TerminalLineOptions {
  /** Longest accepted line in bytes. */
  readonly maxBytes: number;
  /** Error thrown on ^C, on ^D with nothing typed, and on EOF at a terminal. */
  readonly cancelled: () => Error;
  readonly tooLarge: () => Error;
  readonly signal?: AbortSignal;
  /** Without a terminal, take the first line of the stream (default). When false, a non-terminal input is refused via `notTerminal`. */
  readonly allowPipe?: boolean;
  readonly notTerminal?: () => Error;
  /**
   * Called with each accepted character, and with `\b \b` when one is erased, so a prompt that is not secret can show
   * what is typed (raw mode echoes nothing). Absent for secrets.
   */
  readonly echo?: (text: string) => void;
  /**
   * Terminal reads only: bytes that arrive in the same chunk after the Enter key are dropped instead of pushed back, so
   * typeahead or a paste can never become the answer to a later prompt.
   */
  readonly discardLeftover?: boolean;
  /**
   * Terminal reads only: the read arms once input has been quiet for this many milliseconds. Anything received before
   * that is dropped, and each such chunk restarts the wait, so buffered or still-arriving typeahead is never the answer.
   */
  readonly armMs?: number;
}

export const isTerminal = (input: TerminalInput): boolean =>
  input.isTTY === true && typeof input.setRawMode === "function";

/** Reads one line as bytes. */
export async function readTerminalLine(input: TerminalInput, options: TerminalLineOptions): Promise<Buffer> {
  const raw = isTerminal(input);
  if (!raw && options.allowPipe === false) {
    throw (options.notTerminal ?? options.cancelled)();
  }
  const { signal } = options;
  // A Node stream must not be destroyed when one line has been read: passphrase prompts read twice, and stdin may carry more.
  const iterator = typeof input.iterator === "function" ? input.iterator({ destroyOnReturn: false }) : input[Symbol.asyncIterator]();
  let leftover = "";
  const decoder = new TextDecoder();
  // Rejects when the caller aborts (timeout), so a stalled stdin cannot outlive it.
  const aborted = new Promise<never>((_, reject) => {
    if (signal?.aborted) reject(signal.reason);
    signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
  });
  aborted.catch(() => {});
  // One entry per typed character, so backspace removes a whole code point.
  const typed: Buffer[] = [];
  let size = 0;
  const finish = (): Buffer => {
    const out = Buffer.concat(typed);
    for (const part of typed) part.fill(0);
    return out;
  };
  const push = (text: string): void => {
    const bytes = Buffer.from(text, "utf8");
    typed.push(bytes);
    size += bytes.length;
    if (size > options.maxBytes) {
      for (const part of typed) part.fill(0);
      throw options.tooLarge();
    }
  };
  let carry = "";
  const armMs = options.armMs ?? 0;
  let armedAt = Date.now() + armMs;
  if (raw) input.setRawMode!(true);
  try {
    for (;;) {
      const next = await Promise.race([iterator.next(), aborted]);
      if (next.done) {
        if (raw && size === 0) throw options.cancelled();
        return finish();
      }
      const chunk = next.value;
      if (raw && Date.now() < armedAt) {
        // Not armed yet: this input was typed ahead. Drop it and wait for the line to go quiet.
        armedAt = Date.now() + armMs;
        continue;
      }
      let text = carry + (typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true }));
      carry = "";
      if (!raw) {
        const end = text.search(/[\r\n]/);
        push(end < 0 ? text : text.slice(0, end));
        if (end >= 0) {
          leftover = text.slice(text[end] === "\r" && text[end + 1] === "\n" ? end + 2 : end + 1);
          return finish();
        }
        continue;
      }
      for (const marker of BRACKETED_PASTE) text = text.split(marker).join("");
      // Hold back a possible start of a marker split across chunks.
      for (let n = Math.min(text.length, 5); n > 0; n--) {
        const tail = text.slice(-n);
        if (BRACKETED_PASTE.some((m) => m.startsWith(tail))) {
          carry = tail;
          text = text.slice(0, -n);
          break;
        }
      }
      const chars = [...text];
      for (const [position, ch] of chars.entries()) {
        const point = ch.codePointAt(0)!;
        if (point === 0x03) throw options.cancelled();
        if (point === 0x04) {
          if (size === 0) throw options.cancelled();
        } else if (ch === "\r" || ch === "\n") {
          const rest = chars.slice(position + 1);
          if (ch === "\r" && rest[0] === "\n") rest.shift();
          leftover = rest.join("");
          return finish();
        } else if (point === 0x7f || point === 0x08) {
          const last = typed.pop();
          if (last !== undefined) {
            size -= last.length;
            last.fill(0);
            options.echo?.("\b \b");
          }
        } else if (point >= 0x20) {
          push(ch);
          options.echo?.(ch);
        }
      }
    }
  } finally {
    if (raw) input.setRawMode!(false);
    if (leftover !== "" && !(raw && options.discardLeftover === true) && typeof input.unshift === "function") input.unshift(Buffer.from(leftover, "utf8"));
    input.pause?.();
    void Promise.resolve(iterator.return?.()).catch(() => {});
    // An abandoned read leaves the stream open; closing it lets the process exit.
    if (signal?.aborted) input.destroy?.();
  }
}
