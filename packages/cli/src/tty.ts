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
  const iterator = input[Symbol.asyncIterator]();
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
  if (raw) input.setRawMode!(true);
  try {
    for (;;) {
      const next = await Promise.race([iterator.next(), aborted]);
      if (next.done) {
        if (raw && size === 0) throw options.cancelled();
        return finish();
      }
      const chunk = next.value;
      let text = carry + (typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true }));
      carry = "";
      if (!raw) {
        const end = text.search(/[\r\n]/);
        push(end < 0 ? text : text.slice(0, end));
        if (end >= 0) return finish();
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
      for (const ch of text) {
        const point = ch.codePointAt(0)!;
        if (point === 0x03) throw options.cancelled();
        if (point === 0x04) {
          if (size === 0) throw options.cancelled();
        } else if (ch === "\r" || ch === "\n") {
          return finish();
        } else if (point === 0x7f || point === 0x08) {
          const last = typed.pop();
          if (last !== undefined) {
            size -= last.length;
            last.fill(0);
          }
        } else if (point >= 0x20) {
          push(ch);
        }
      }
    }
  } finally {
    if (raw) input.setRawMode!(false);
    input.pause?.();
    void Promise.resolve(iterator.return?.()).catch(() => {});
    // An abandoned read leaves the stream open; closing it lets the process exit.
    if (signal?.aborted) input.destroy?.();
  }
}
