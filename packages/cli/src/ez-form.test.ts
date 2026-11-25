import assert from "node:assert/strict";
import test from "node:test";
import { EzError } from "./ez-error";
import { FakeTerminal, pipeInput } from "./ez-fake";
import { firstFormError, renderForm, runForm, type FormField } from "./ez-form";
import { Prompter } from "./ez-prompt";

const fields = (): FormField[] => [
  { id: "ro", label: "Fixed", kind: "readonly", value: "never edited" },
  { id: "name", label: "Name", kind: "text", value: "abc", validate: (v) => (/^[a-z]+$/.test(v) ? undefined : "letters only") },
  { id: "algo", label: "Algorithm", kind: "choice", value: "A", choices: ["A", "B", "C"] },
  { id: "note", label: "Note", kind: "text", value: "", optional: true },
];

const harness = (...keys: string[]) => {
  const output: string[] = [];
  const term = new FakeTerminal(keys.join(""));
  const prompter = new Prompter({ stdin: term, write: (t) => void output.push(t) });
  return { term, prompter, text: () => output.join("") };
};

test("renderForm numbers editable rows, marks read-only rows and shows choices", () => {
  const text = renderForm("Title", fields(), 80, false);
  assert.match(text, / -\) Fixed +never edited/);
  assert.match(text, / 1\) Name +abc/);
  assert.match(text, / 2\) Algorithm +A +\[A \| B \| C\]/);
  assert.match(text, /3\) Note +\(none\)/);
  assert.match(renderForm("T", fields(), 80, true), /\x1b\[1mT\x1b\[0m/);
  // a narrow terminal wraps the value under the label
  assert.match(renderForm("T", [{ id: "x", label: "Long", kind: "text", value: "v".repeat(60) }], 40, false), /1\) Long\n {6}v+/);
  // hostile values are escaped
  assert.match(renderForm("T", [{ id: "x", label: "X", kind: "text", value: "a\x1b[2Jb" }], 80, false), /a\\x1b\[2Jb/);
});

test("accepting immediately returns the initial values", async () => {
  const h = harness("\r");
  assert.deepEqual(await runForm({ title: "T", fields: fields(), prompter: h.prompter }), { ro: "never edited", name: "abc", algo: "A", note: "" });
  assert.equal(h.term.rawModes.length, 2);
});

test("editing text, choices by number and name, clearing optional values, and rejected input", async () => {
  const h = harness("1\r", "xyz\r", "2\r", "3\r", "3\r", "hello\r", "3\r", "-\r", "2\r", "b\r", "\r");
  const result = await runForm({ title: "T", fields: fields(), prompter: h.prompter });
  assert.deepEqual(result, { ro: "never edited", name: "xyz", algo: "B", note: "" });
  const bad = harness("1\r", "ABC\r", "2\r", "Z\r", "9\r", "x\r", "1\r", "\r", "\r");
  const kept = await runForm({ title: "T", fields: fields(), prompter: bad.prompter });
  assert.equal(kept.name, "abc");
  assert.equal(kept.algo, "A");
  assert.match(bad.text(), /letters only/);
  assert.match(bad.text(), /Choose one of: A, B, C/);
  assert.match(bad.text(), /Enter a number from 1 to 3/);
});

test("a form with an invalid required value cannot be accepted until it is fixed", async () => {
  const start = fields();
  start[1] = { ...(start[1] as FormField), value: "" };
  assert.match(firstFormError(start) ?? "", /Name is required/);
  const h = harness("\r", "1\r", "fixed\r", "\r");
  assert.equal((await runForm({ title: "T", fields: start, prompter: h.prompter })).name, "fixed");
  assert.match(h.text(), /Name is required/);
});

test("typed text is echoed, backspace erases, and EOF or Ctrl-C cancels without a result", async () => {
  const h = harness("1\r", "ab\x7fc\r", "\r");
  await runForm({ title: "T", fields: fields(), prompter: h.prompter });
  assert.match(h.text(), /a\x08 \x08|ab\x08 \x08c/);
  for (const keys of [[""], ["1\r", "x\x03"]]) {
    const c = harness(...keys);
    await assert.rejects(runForm({ title: "T", fields: fields(), prompter: c.prompter }), (e) => e instanceof EzError && e.code === "prompt_cancelled");
  }
});

test("the form needs a terminal", async () => {
  const prompter = new Prompter({ stdin: pipeInput("\n"), write: () => {} });
  assert.equal(prompter.interactive, false);
  await assert.rejects(runForm({ title: "T", fields: fields(), prompter }), (e) => e instanceof EzError && e.code === "terminal_required");
});

test("prompter: secrets are never echoed, pipe lines are read one at a time, confirm needs a terminal", async () => {
  const out: string[] = [];
  const term = new FakeTerminal("secret passphrase\r");
  const prompter = new Prompter({ stdin: term, write: (t) => void out.push(t) });
  assert.equal((await prompter.secret("Pass: ")).toString(), "secret passphrase");
  assert.equal(out.join("").includes("secret"), false);
  const pipe = new Prompter({ stdin: pipeInput("first line\r\nsecond\nthird"), write: () => {} });
  assert.equal((await pipe.pipeLine()).toString(), "first line");
  assert.equal((await pipe.pipeLine()).toString(), "second");
  assert.equal((await pipe.pipeLine()).toString(), "third");
  await assert.rejects(pipe.pipeLine(), /Stdin ended/);
  await assert.rejects(pipe.secret("x"), (e) => e instanceof EzError && e.code === "terminal_required");
  await assert.rejects(pipe.confirm("sign"), (e) => e instanceof EzError && e.code === "terminal_required");
  await assert.rejects(new Prompter({ stdin: term, write: () => {} }).pipeLine(), (e) => e instanceof EzError && e.code === "invalid_input");
});

test("prompter: new passphrases are checked against the policy, then confirmed", async () => {
  const mk = (...keys: string[]) => new Prompter({ stdin: new FakeTerminal(keys.join("")), write: () => {} });
  assert.equal((await mk("a long enough passphrase\r", "a long enough passphrase\r").passphrase({ create: true, fromStdin: false })).toString(), "a long enough passphrase");
  await assert.rejects(mk("short\r", "short\r").passphrase({ create: true, fromStdin: false }), (e) => e instanceof EzError && e.code === "invalid_input");
  await assert.rejects(mk("a long enough passphrase\r", "a long enough passphrasX\r").passphrase({ create: true, fromStdin: false }), (e) => e instanceof EzError && e.code === "passphrase_mismatch");
  const piped = new Prompter({ stdin: pipeInput("a long enough passphrase\n"), write: () => {} });
  assert.equal((await piped.passphrase({ create: true, fromStdin: true })).toString(), "a long enough passphrase");
  await assert.rejects(new Prompter({ stdin: pipeInput("short\n"), write: () => {} }).passphrase({ create: true, fromStdin: true }), (e) => e instanceof EzError && e.code === "invalid_input");
});
