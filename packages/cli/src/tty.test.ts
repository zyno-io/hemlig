import assert from "node:assert/strict";
import test from "node:test";
import { readTerminalLine, type TerminalInput } from "./tty";

const input = (chunks: (string | Uint8Array)[], tty = false): TerminalInput & { raw: boolean[] } => {
  const raw: boolean[] = [];
  return {
    raw,
    isTTY: tty,
    setRawMode: tty ? (mode: boolean) => void raw.push(mode) : undefined,
    async *[Symbol.asyncIterator]() {
      yield* chunks;
    },
  };
};
const options = { maxBytes: 16, cancelled: () => new Error("cancelled"), tooLarge: () => new Error("large") };

test("pipe: first line as bytes", async () => {
  assert.equal((await readTerminalLine(input(["pass", "word\nrest"]), options)).toString(), "password");
  assert.equal((await readTerminalLine(input([Buffer.from("héllo\r\n")]), options)).toString(), "héllo");
});

test("terminal: raw mode on and off, backspace by code point, ^D with input ignored, paste markers removed", async () => {
  const term = input(["ab\x7fé\x7f\x7fc\x04d\x1b[200~ef\x1b[201~\r"], true);
  assert.equal((await readTerminalLine(term, options)).toString(), "cdef");
  assert.deepEqual(term.raw, [true, false]);
});

test("terminal: ^C, ^D on empty and EOF cancel; oversize is refused; pipes can be refused", async () => {
  await assert.rejects(readTerminalLine(input(["ab\x03"], true), options), /cancelled/);
  await assert.rejects(readTerminalLine(input(["\x04"], true), options), /cancelled/);
  await assert.rejects(readTerminalLine(input([], true), options), /cancelled/);
  await assert.rejects(readTerminalLine(input(["x".repeat(17)], true), options), /large/);
  await assert.rejects(readTerminalLine(input(["x".repeat(17)]), options), /large/);
  await assert.rejects(readTerminalLine(input(["x\n"]), { ...options, allowPipe: false, notTerminal: () => new Error("terminal_required") }), /terminal_required/);
});

test("terminal: echo reports typed characters and erasures, never for a secret read", async () => {
  const echoed: string[] = [];
  const term = input(["ab\x7fc\r"], true);
  assert.equal((await readTerminalLine(term, { ...options, echo: (t) => void echoed.push(t) })).toString(), "ac");
  assert.deepEqual(echoed, ["a", "b", "\b \b", "c"]);
  // without an echo callback nothing is reported (the secret path)
  assert.equal((await readTerminalLine(input(["secret\r"], true), options)).toString(), "secret");
});
