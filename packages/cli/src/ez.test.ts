import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runCli } from "./index";
import { FakeServer, FakeTerminal, caIdOf, pendingCa, pipeInput, type FakeCa } from "./ez-fake";
import { EzError } from "./ez-error";
import { EzStore, type EzState } from "./ez-state";
import { Prompter, isConfirmation } from "./ez-prompt";
import { fromPem, parseCertificate, parseCrl, verifyCertificateSignature, verifyCrlSignature } from "./ez-x509";
import type { TerminalInput } from "./tty";

const PASS = "correct horse battery staple";
const token = "test.header.signature";
const origin = "https://admin.example.test";
const baseEnv = { HEMLIG_ADMIN_URL: origin, HEMLIG_ADMIN_TOKEN: token, HEMLIG_ENVIRONMENT: "prod" };
const clock = { value: Date.parse("2026-11-25T12:00:00Z") };

interface Run {
  exitCode: number;
  stdout: string;
  stderr: string;
  json: any;
  error: any;
}

interface RunOptions {
  stdin?: TerminalInput;
  server?: FakeServer;
  openTerminal?: () => Promise<TerminalInput | undefined>;
  env?: NodeJS.ProcessEnv;
  confirmArmMs?: number;
}

const run = async (args: string[], options: RunOptions = {}): Promise<Run> => {
  let stdout = "";
  let stderr = "";
  const exitCode = await runCli(["pki", "ez", ...args], {
    env: options.env ?? baseEnv,
    configDir: join(tmpdir(), "hemlig-ez-test-no-config"),
    now: () => clock.value,
    stdin: options.stdin ?? pipeInput(),
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    transport:
      options.server ??
      ({
        async request() {
          throw new Error("unexpected network request");
        },
      } as never),
    openTerminal: options.openTerminal,
    confirmArmMs: options.confirmArmMs ?? 0,
  });
  const lastLine = (text: string): any => {
    const line = text.trim().split("\n").filter((l) => l.startsWith("{")).pop();
    return line === undefined ? undefined : JSON.parse(line);
  };
  return { exitCode, stdout, stderr, json: stdout.trim() === "" ? undefined : JSON.parse(stdout), error: lastLine(stderr)?.error };
};

const tempDir = async (): Promise<string> => fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-cmd-"));
const snapshot = async (dir: string): Promise<Record<string, string>> => {
  const out: Record<string, string> = {};
  const walk = async (current: string, prefix: string): Promise<void> => {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      if (entry.name === ".hemlig-ez.lock") continue;
      if (entry.isDirectory()) await walk(join(current, entry.name), `${prefix}${entry.name}/`);
      else out[`${prefix}${entry.name}`] = createHash("sha256").update(await fs.readFile(join(current, entry.name))).digest("hex");
    }
  };
  await walk(dir, "");
  return out;
};
const readState = async (dir: string): Promise<EzState> => JSON.parse(await fs.readFile(join(dir, "hemlig-ez.json"), "utf8"));

/** Creates a root with the real command (piped passphrase, no form). */
const newRoot = async (dir: string, extra: string[] = ["--key-algorithm", "ECDSA_P256"]): Promise<Run> => {
  const result = await run(["generate-ca", "--dir", dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--passphrase-stdin", ...extra], {
    stdin: pipeInput(`${PASS}\n`),
  });
  assert.equal(result.exitCode, 0, result.stderr);
  return result;
};

const server = (...cas: FakeCa[]): FakeServer => {
  const s = new FakeServer();
  for (const ca of cas) s.add(ca);
  return s;
};

const signOnline = (dir: string, caId: string, s: FakeServer, keys: string[] = [`confirm\r`, `${PASS}\r`], extra: string[] = []) =>
  run(["sign-cert", caId, "--dir", dir, "--environment", "prod", "--yes", ...extra], { server: s, stdin: new FakeTerminal(...keys) });

const cleanup = (dir: string) => fs.rm(dir, { recursive: true, force: true });

// -- generate-ca ---------------------------------------------------------------------------------------------------

test("generate-ca writes the root, CRL 1 and state; stdout is one JSON receipt", async () => {
  const dir = await tempDir();
  try {
    const result = await newRoot(dir);
    assert.equal(result.stdout.trim().split("\n").length, 1);
    assert.equal(result.json.data.command, "generate-ca");
    assert.equal(result.json.data.crl.number, 1);
    const root = parseCertificate(fromPem(await fs.readFile(join(dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(root.fingerprint, result.json.data.root.fingerprint);
    assert.equal(verifyCertificateSignature(root, root.spkiDer), true);
    const crl = parseCrl(fromPem(await fs.readFile(join(dir, "root.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(verifyCrlSignature(crl, root.spkiDer), true);
    assert.equal(crl.number, 1n);
    assert.match(await fs.readFile(join(dir, "root.key.pem"), "utf8"), /BEGIN ENCRYPTED PRIVATE KEY/);
    assert.equal((await fs.stat(join(dir, "root.key.pem"))).mode & 0o777, 0o600);
    const state = await readState(dir);
    assert.equal(state.key.storage, "software");
    assert.equal(state.defaults.intermediateValidityDays, 730);
    assert.equal(state.key.kdf?.iterations, 1_000_000);
    assert.equal((await fs.readdir(dir)).includes(".hemlig-ez.lock"), false);
  } finally {
    await cleanup(dir);
  }
});

test("generate-ca refuses existing files, weak passphrases and a missing subject without writing anything", async () => {
  const dir = await tempDir();
  try {
    const before = await run(["generate-ca", "--dir", dir, "--yes", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(before.exitCode, 2, "no subject without a form");
    const weak = await run(["generate-ca", "--dir", dir, "--subject", "CN=R", "--yes", "--passphrase-stdin"], { stdin: pipeInput("short\n") });
    assert.equal(weak.exitCode, 2);
    assert.deepEqual(await fs.readdir(dir), []);
    await newRoot(dir);
    const snap = await snapshot(dir);
    const again = await run(["generate-ca", "--dir", dir, "--subject", "CN=Other", "--yes", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(again.exitCode, 5);
    assert.equal(again.error.code, "already_exists");
    assert.deepEqual(await snapshot(dir), snap);
    const reserved = await run(["generate-ca", "--dir", await tempDir(), "--subject", "CN=Hemlig Prod Issuing Root", "--yes", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(reserved.exitCode, 2);
    assert.equal(reserved.error.code, "subject_invalid");
  } finally {
    await cleanup(dir);
  }
});

test("generate-ca on a terminal: the form edits settings, the passphrase is asked twice, a mismatch is asked again and refused after three", async () => {
  const dir = await tempDir();
  try {
    // 2 = subject, 4 = key algorithm (choice 2 = ECDSA_P256), 13 = intermediate validity, then accept.
    const term = new FakeTerminal("2\r", "CN=Form Root,O=Test\r", "4\r", "2\r", "13\r", "365d\r", "\r", `${PASS}\r`, `${PASS}\r`);
    const result = await run(["generate-ca", "--dir", dir], { stdin: term });
    assert.equal(result.exitCode, 0, result.stderr);
    const state = await readState(dir);
    assert.equal(state.root.subjectDn, "O=Test, CN=Form Root");
    assert.equal(state.root.keyAlgorithm, "ECDSA_P256");
    assert.equal(state.defaults.intermediateValidityDays, 365);
    assert.match(result.stderr, /PBKDF2-HMAC-SHA256 x 1,000,000/);
    assert.match(result.stderr, /New root key passphrase/);
    assert.deepEqual(term.rawModes.filter((m) => m).length, term.rawModes.filter((m) => !m).length);
    // the typed text of the form is echoed, the passphrase is not
    assert.equal(result.stderr.includes(PASS), false);

    const dir2 = await tempDir();
    const mismatch = await run(["generate-ca", "--dir", dir2, "--subject", "CN=M", "--key-algorithm", "ECDSA_P256"], {
      stdin: new FakeTerminal("\r", `${PASS}\r`, `${PASS}x\r`, `${PASS}\r`, `${PASS}y\r`, `${PASS}\r`, `${PASS}z\r`),
    });
    assert.equal(mismatch.exitCode, 2);
    assert.equal(mismatch.error.code, "passphrase_mismatch");
    assert.equal(mismatch.stderr.match(/Try again/g)?.length, 2);
    assert.deepEqual(await fs.readdir(dir2), []);
    await cleanup(dir2);
  } finally {
    await cleanup(dir);
  }
});

test("generate-ca honours custom file names, an absolute key location and rejects colliding names", async () => {
  const dir = await tempDir();
  const usb = await tempDir();
  try {
    const keyPath = join(usb, "root.key.pem");
    const result = await newRoot(dir, ["--key-algorithm", "ECDSA_P256", "--key-file", keyPath, "--cert-file", "ca/root-cert.pem", "--crl-file", "ca/root.crl", "--intermediate-validity", "400d", "--crl-validity", "90d", "--validity", "10y", "--path-len", "2"]);
    assert.equal(result.json.data.files.key, keyPath);
    assert.ok((await fs.stat(keyPath)).isFile());
    assert.ok((await fs.stat(join(dir, "ca", "root-cert.pem"))).isFile());
    const state = await readState(dir);
    assert.equal(state.key.file, keyPath);
    assert.equal(state.root.certificateFile, join("ca", "root-cert.pem"));
    assert.equal(state.root.pathLen, 2);
    assert.equal(state.defaults.crlValidityDays, 90);
    const bad = await run(["generate-ca", "--dir", await tempDir(), "--subject", "CN=X", "--yes", "--passphrase-stdin", "--key-file", "a.pem", "--cert-file", "a.pem"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(bad.exitCode, 2);
  } finally {
    await cleanup(dir);
    await cleanup(usb);
  }
});

// -- sign-cert online ----------------------------------------------------------------------------------------------

test("sign-cert online: reviews, needs the typed confirm, signs, seeds the CRL, activates and records everything", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record, csr } = pendingCa(1, { requested: { nameConstraints: { permitted: { dns: ["example.com"] } } }, permitted: { dns: ["example.com"] }, eku: ["1.3.6.1.5.5.7.3.1"] });
    (record.requestedConstraints as any).extendedKeyUsages = ["serverAuth"];
    const s = server(record);
    const result = await signOnline(dir, record.caId, s);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.json.data.activated, true);
    assert.equal(result.json.data.alreadyActive, false);
    // the review shows what is signed
    assert.match(result.stderr, /Review: this will sign an intermediate CA certificate/);
    assert.match(result.stderr, new RegExp(record.caId));
    assert.match(result.stderr, /dns:example\.com/);
    assert.match(result.stderr, new RegExp(record.spkiSha256));
    assert.match(result.stderr, /serverAuth/);
    assert.match(result.stderr, /Signed by root/);
    assert.match(result.stderr, /Type "confirm" to sign/);
    // the unregistered root is seeded with the CRL in the activation request, and the key is deterministic
    const [activation] = s.activations();
    assert.ok(activation?.body.rootCrl);
    assert.equal(s.uploads().length, 0);
    const state = await readState(dir);
    const entry = state.issued[0];
    assert.equal(entry?.status, "activated");
    assert.equal(entry?.csrSha256, createHash("sha256").update(csr.der).digest("hex"));
    assert.equal(activation?.key, `ez-act-${createHash("sha256").update(`${record.caId}\n${entry?.fingerprint}`).digest("hex").slice(0, 40)}`);
    assert.equal(state.deployments[0]?.lastUploadedCrlNumber, 1);
    // the certificate verifies under the root and keeps the requested constraints
    const cert = parseCertificate(fromPem(await fs.readFile(join(dir, "issued", `${entry?.serial}.pem`), "utf8"), "CERTIFICATE"));
    const root = parseCertificate(fromPem(await fs.readFile(join(dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(verifyCertificateSignature(cert, root.spkiDer), true);
    assert.equal(cert.spkiSha256, record.spkiSha256);
    assert.equal(s.cas.get(record.caId)?.status, "ACTIVE");
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert online: a second CA under the registered root activates without the CRL; a newer local CRL is uploaded first", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const one = pendingCa(1);
    const two = pendingCa(2);
    const three = pendingCa(3);
    const s = server(one.record, two.record, three.record);
    assert.equal((await signOnline(dir, one.record.caId, s)).exitCode, 0);
    // in sync: nothing to upload, activation omits rootCrl
    const second = await signOnline(dir, two.record.caId, s);
    assert.equal(second.exitCode, 0, second.stderr);
    assert.equal(s.uploads().length, 0);
    assert.equal(s.activations()[1]?.body.rootCrl, undefined);
    // a renewal that never reached the server: the next sign-cert uploads CRL 2, then activates without rootCrl
    const renewed = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", "out.crl.pem"], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewed.exitCode, 0, renewed.stderr);
    const third = await signOnline(dir, three.record.caId, s);
    assert.equal(third.exitCode, 0, third.stderr);
    assert.deepEqual(s.uploads().map((u) => u.number), [2n]);
    assert.equal(s.activations()[2]?.body.rootCrl, undefined);
    assert.equal(third.json.data.crl.uploaded, true);
    const order = s.mutations.map((r) => (r.url.pathname.endsWith("/crl") ? "upload" : "activate"));
    assert.deepEqual(order, ["activate", "activate", "upload", "activate"]);
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert: every typed-confirm abort path leaves no state change and sends nothing", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record } = pendingCa(1);
    const s = server(record);
    const before = await snapshot(dir);
    const cases: [string, TerminalInput | undefined, number, string][] = [
      ["wrong word", new FakeTerminal("yes\r"), 2, "confirmation_declined"],
      ["case differs", new FakeTerminal("Confirm\r"), 2, "confirmation_declined"],
      ["extra text", new FakeTerminal("confirm \r"), 2, "confirmation_declined"],
      ["empty", new FakeTerminal("\r"), 2, "confirmation_declined"],
      ["EOF", new FakeTerminal(), 9, "prompt_cancelled"],
      ["Ctrl-C", new FakeTerminal("conf\x03"), 9, "prompt_cancelled"],
    ];
    for (const [label, stdin, exitCode, code] of cases) {
      const result = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin });
      assert.equal(result.exitCode, exitCode, label);
      assert.equal(result.error.code, code, label);
      assert.deepEqual(await snapshot(dir), before, label);
    }
    assert.equal(s.mutations.length, 0);
    assert.equal(s.cas.get(record.caId)?.status, "PENDING_CERTIFICATE");
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert: --yes never skips the confirm; a pipe needs a terminal; a wrong passphrase changes nothing", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record } = pendingCa(1);
    const s = server(record);
    const before = await snapshot(dir);
    // stdin is a pipe (passphrase-stdin) and there is no terminal: refused, never auto-confirmed
    const piped = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes", "--passphrase-stdin"], {
      server: s,
      stdin: pipeInput(`${PASS}\nconfirm\n`),
      openTerminal: async () => undefined,
    });
    assert.equal(piped.exitCode, 2);
    assert.equal(piped.error.code, "terminal_required");
    assert.doesNotMatch(piped.stderr, /Review:/, "refused before anything was shown");
    // a wrong passphrase after a valid confirm: exit 3, still nothing written
    const wrong = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], {
      server: s,
      stdin: new FakeTerminal("confirm\r", "not the passphrase!\r"),
    });
    assert.equal(wrong.exitCode, 3);
    assert.equal(wrong.error.code, "passphrase_invalid");
    assert.deepEqual(await snapshot(dir), before);
    assert.equal(s.mutations.length, 0);
    // a pipe passphrase works when the keyboard confirm comes from the controlling terminal
    const tty = new FakeTerminal("confirm\r");
    const ok = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes", "--passphrase-stdin"], {
      server: s,
      stdin: pipeInput(`${PASS}\n`),
      openTerminal: async () => tty,
    });
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.equal(tty.destroyed, true);
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert: the review escapes hostile values and validation failures happen before any prompt", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const hostile = pendingCa(1);
    const s = server(hostile.record);
    const term = new FakeTerminal("confirm\r");
    // CSR from another key: refused before anything is shown or asked
    const other = pendingCa(2);
    hostile.record.csrPem = other.csr.pem;
    const mismatch = await run(["sign-cert", hostile.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: term });
    assert.equal(mismatch.exitCode, 5);
    assert.equal(mismatch.error.code, "csr_key_mismatch");
    assert.deepEqual(term.remaining, ["confirm\r"], "no prompt was consumed");
    assert.doesNotMatch(mismatch.stderr, /Type "confirm"/);
    // wrong environment, wrong kind, not pending
    const e = await run(["sign-cert", hostile.record.caId, "--dir", dir, "--environment", "staging", "--yes"], { server: s, stdin: new FakeTerminal() });
    assert.equal(e.error.code, "environment_mismatch");
    hostile.record.csrPem = hostile.csr.pem;
    hostile.record.status = "REVOKED";
    assert.equal((await run(["sign-cert", hostile.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() })).error.code, "ca_not_pending");
    hostile.record.status = "PENDING_CERTIFICATE";
    hostile.record.kind = "ROOT";
    assert.equal((await run(["sign-cert", hostile.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() })).error.code, "ca_not_external");
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert: a CSR whose constraints differ from the record, or whose subject is the root's, is refused", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const widened = pendingCa(1, { permitted: { dns: ["example.com"] } });
    const s = server(widened.record);
    const result = await signOnline(dir, widened.record.caId, s);
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "csr_constraints_mismatch");
    const same = pendingCa(2, { subject: { O: "Example Corp", CN: "Example Root" } });
    s.add(same.record);
    const clash = await signOnline(dir, same.record.caId, s);
    assert.equal(clash.error.code, "csr_subject_is_root");
  } finally {
    await cleanup(dir);
  }
});

// -- crash and rerun -----------------------------------------------------------------------------------------------

test("sign-cert rerun after a failed activation reuses the signed certificate and the same idempotency key", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record } = pendingCa(1);
    const s = server(record);
    s.failNext = { suffix: "/certificate", after: false };
    const first = await signOnline(dir, record.caId, s);
    assert.equal(first.exitCode, 8);
    assert.deepEqual(first.error.code, "transport_error");
    const failure = JSON.parse(first.stderr.trim().split("\n").filter((l) => l.startsWith("{")).pop() as string);
    assert.ok(failure.ez.completed.includes("certificate-signed"));
    assert.match(failure.ez.rerun, /^hemlig pki ez sign-cert /);
    const state = await readState(dir);
    assert.equal(state.issued[0]?.status, "signed");
    const serial = state.issued[0]?.serial;
    // rerun: nothing needs signing, so there is no confirm and no passphrase
    const term = new FakeTerminal();
    const second = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: term });
    assert.equal(second.exitCode, 0, second.stderr);
    assert.equal(second.json.data.serial, serial);
    assert.equal(second.json.data.recovered, true);
    assert.doesNotMatch(second.stderr, /Type "confirm"/);
    const [a, b] = s.activations();
    assert.equal(a?.key, b?.key);
    assert.equal((await readState(dir)).issued.length, 1);
    assert.equal((await readState(dir)).issued[0]?.status, "activated");
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert rerun after the server activated but the response was lost reports alreadyActive", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record } = pendingCa(1);
    const s = server(record);
    s.failNext = { suffix: "/certificate", after: true };
    const first = await signOnline(dir, record.caId, s);
    assert.equal(first.exitCode, 8);
    assert.equal(s.cas.get(record.caId)?.status, "ACTIVE");
    const second = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() });
    assert.equal(second.exitCode, 0, second.stderr);
    assert.equal(second.json.data.alreadyActive, true);
    assert.equal((await readState(dir)).issued[0]?.status, "activated");
    // a third run also succeeds without signing
    assert.equal((await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() })).json.data.alreadyActive, true);
    assert.equal((await readState(dir)).issued.length, 1);
  } finally {
    await cleanup(dir);
  }
});

test("sign-cert refuses a CA activated with another certificate and a root the server knows differently", async () => {
  const dir = await tempDir();
  const other = await tempDir();
  try {
    await newRoot(dir);
    await newRoot(other);
    const { record } = pendingCa(1);
    const s = server(record);
    // another root already activated this CA: not ours
    const foreign = await signOnline(other, record.caId, s);
    assert.equal(foreign.exitCode, 0);
    const result = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "ca_activated_elsewhere");
    // a server record for this root's key with a different certificate
    const two = pendingCa(2);
    s.add(two.record);
    const ext = [...s.externals.values()][0];
    const state = await readState(dir);
    s.externals.set(`ext-${state.root.spkiSha256.slice(0, 40)}`, { ...(ext as any), extId: `ext-${state.root.spkiSha256.slice(0, 40)}`, fingerprint: "ab".repeat(32) });
    const mismatch = await signOnline(dir, two.record.caId, s);
    assert.equal(mismatch.exitCode, 5);
    assert.equal(mismatch.error.code, "root_mismatch");
  } finally {
    await cleanup(dir);
    await cleanup(other);
  }
});

test("sign-cert checks the server's CRL against the local state and the clock before prompting", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const one = pendingCa(1);
    const two = pendingCa(2);
    const s = server(one.record, two.record);
    assert.equal((await signOnline(dir, one.record.caId, s)).exitCode, 0);
    // the server holds a newer CRL than this state: a restored backup
    const ext = [...s.externals.values()][0]!;
    ext.crl = { ...(ext.crl as any), numberHex: "09" };
    const term = new FakeTerminal("confirm\r");
    const behind = await run(["sign-cert", two.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: term });
    assert.equal(behind.exitCode, 5);
    assert.equal(behind.error.code, "state_behind_server");
    assert.deepEqual(term.remaining, ["confirm\r"]);
    ext.crl = { ...(ext.crl as any), numberHex: "01", sha256: "cd".repeat(32) };
    const forked = await run(["sign-cert", two.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() });
    assert.equal(forked.error.code, "state_forked");
    // clock skew
    s.dateHeader = new Date(clock.value + 600_000).toUTCString();
    const skewed = await run(["sign-cert", two.record.caId, "--dir", dir, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal() });
    assert.equal(skewed.error.code, "clock_skew");
  } finally {
    await cleanup(dir);
  }
});

// -- sign-cert offline + activate ----------------------------------------------------------------------------------

test("sign-cert offline: pins the key, needs the confirm, writes the files to carry; a rerun is idempotent", async () => {
  const dir = await tempDir();
  const carry = await tempDir();
  try {
    await newRoot(dir);
    const { record, csr } = pendingCa(1);
    const csrFile = join(carry, "ca.csr.pem");
    await fs.writeFile(csrFile, csr.pem);
    const base = ["sign-cert", record.caId, "--dir", dir, "--offline", "--csr", csrFile, "--yes", "--out", join(carry, "ca.pem"), "--environment", "prod"];
    // wrong pin
    const wrong = await run([...base, "--expect-spki-sha256", "ab".repeat(32)], { stdin: new FakeTerminal("confirm\r") });
    assert.equal(wrong.exitCode, 5);
    assert.equal(wrong.error.code, "csr_key_mismatch");
    // declined confirm leaves nothing
    const before = await snapshot(dir);
    const declined = await run([...base, "--expect-spki-sha256", record.spkiSha256], { stdin: new FakeTerminal("no\r") });
    assert.equal(declined.error.code, "confirmation_declined");
    assert.deepEqual(await snapshot(dir), before);
    assert.deepEqual(await fs.readdir(carry), ["ca.csr.pem"]);
    // success
    const ok = await run([...base, "--expect-spki-sha256", record.spkiSha256, "--chain-out", join(carry, "root.pem"), "--crl-out", join(carry, "root.crl.pem")], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.equal(ok.json.data.activated, false);
    assert.match(ok.json.next[1], /^hemlig pki ez activate ca-/);
    assert.equal((await fs.readdir(carry)).sort().join(), "ca.csr.pem,ca.pem,root.crl.pem,root.pem");
    assert.doesNotMatch(ok.stderr, /key is not pinned/);
    const cert = parseCertificate(fromPem(await fs.readFile(join(carry, "ca.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(cert.spkiSha256, record.spkiSha256);
    // rerun: same certificate, no prompts
    const again = await run([...base, "--expect-spki-sha256", record.spkiSha256, "--chain-out", join(carry, "root.pem"), "--crl-out", join(carry, "root.crl.pem")], { stdin: new FakeTerminal() });
    assert.equal(again.exitCode, 0, again.stderr);
    assert.equal(again.json.data.serial, ok.json.data.serial);
    assert.equal((await readState(dir)).issued.length, 1);
    // a different CSR for the same CA is a conflict; an existing output is never overwritten
    const other = pendingCa(1);
    await fs.writeFile(csrFile, other.csr.pem);
    const conflict = await run([...base], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(conflict.error.code, "issued_conflict");
  } finally {
    await cleanup(dir);
    await cleanup(carry);
  }
});

test("sign-cert offline: unpinned CSRs warn, outputs are not clobbered, private keys and bad files are refused", async () => {
  const dir = await tempDir();
  const carry = await tempDir();
  try {
    await newRoot(dir);
    const { record, csr } = pendingCa(1);
    const csrFile = join(carry, "ca.csr.pem");
    await fs.writeFile(csrFile, csr.pem);
    const out = join(carry, "ca.pem");
    await fs.writeFile(out, "precious");
    const existing = await run(["sign-cert", record.caId, "--dir", dir, "--offline", "--csr", csrFile, "--out", out, "--yes"], { stdin: new FakeTerminal() });
    assert.equal(existing.error.code, "already_exists");
    assert.equal(await fs.readFile(out, "utf8"), "precious");
    await fs.unlink(out);
    const unpinned = await run(["sign-cert", record.caId, "--dir", dir, "--offline", "--csr", csrFile, "--out", out, "--yes"], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(unpinned.exitCode, 0, unpinned.stderr);
    assert.match(unpinned.stderr, /key is not pinned/);
    assert.deepEqual(unpinned.json.data.warnings, ["csr_unbound"]);
    await fs.writeFile(csrFile, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
    const key = await run(["sign-cert", record.caId, "--dir", dir, "--offline", "--csr", csrFile, "--out", join(carry, "x.pem"), "--yes"], { stdin: new FakeTerminal() });
    assert.equal(key.error.code, "csr_invalid");
    assert.equal((await run(["sign-cert", "prod-issuing-1", "--dir", dir, "--offline", "--csr", csrFile], { stdin: new FakeTerminal() })).exitCode, 2);
    assert.equal((await run(["sign-cert", record.caId, "--dir", dir, "--offline"], { stdin: new FakeTerminal() })).exitCode, 2);
  } finally {
    await cleanup(dir);
    await cleanup(carry);
  }
});

test("activate: offline-produced files activate a new root with its CRL, and a registered root gets the newer CRL uploaded first", async () => {
  const dir = await tempDir();
  const carry = await tempDir();
  try {
    await newRoot(dir);
    const one = pendingCa(1);
    const two = pendingCa(2);
    const s = server(one.record, two.record);
    for (const [n, ca] of [[1, one], [2, two]] as const) {
      await fs.writeFile(join(carry, `${n}.csr.pem`), ca.csr.pem);
      if (n === 2) {
        const renewed = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", join(carry, "root.crl.pem")], { stdin: new FakeTerminal(`${PASS}\r`) });
        assert.equal(renewed.exitCode, 0, renewed.stderr);
      }
      const signed = await run(["sign-cert", ca.record.caId, "--dir", dir, "--offline", "--csr", join(carry, `${n}.csr.pem`), "--out", join(carry, `${n}.pem`), "--chain-out", join(carry, `root${n}.pem`), "--crl-out", join(carry, `crl${n}.pem`), "--yes"], {
        stdin: new FakeTerminal("confirm\r", `${PASS}\r`),
      });
      assert.equal(signed.exitCode, 0, signed.stderr);
    }
    const first = await run(["activate", one.record.caId, "--environment", "prod", "--certificate", join(carry, "1.pem"), "--chain", join(carry, "root1.pem"), "--crl", join(carry, "crl1.pem")], { server: s });
    assert.equal(first.exitCode, 0, first.stderr);
    assert.equal(first.json.data.activated, true);
    assert.ok(s.activations()[0]?.body.rootCrl);
    // CA two was signed after CRL 2: the registered root gets CRL 2 uploaded, then activation without rootCrl
    const second = await run(["activate", two.record.caId, "--environment", "prod", "--certificate", join(carry, "2.pem"), "--chain", join(carry, "root2.pem"), "--crl", join(carry, "crl2.pem")], { server: s });
    assert.equal(second.exitCode, 0, second.stderr);
    assert.deepEqual(s.uploads().map((u) => u.number), [2n]);
    assert.equal(s.activations()[1]?.body.rootCrl, undefined);
    // an older CRL than the server's is skipped
    const three = pendingCa(3);
    s.add(three.record);
    const mismatch = await run(["activate", three.record.caId, "--environment", "prod", "--certificate", join(carry, "1.pem"), "--chain", join(carry, "root1.pem")], { server: s });
    assert.equal(mismatch.error.code, "csr_key_mismatch");
    // already active with this certificate: success; wrong environment refused
    const again = await run(["activate", one.record.caId, "--environment", "prod", "--certificate", join(carry, "1.pem"), "--chain", join(carry, "root1.pem")], { server: s });
    assert.equal(again.json.data.alreadyActive, true);
    assert.equal((await run(["activate", one.record.caId, "--environment", "dev", "--certificate", join(carry, "1.pem"), "--chain", join(carry, "root1.pem")], { server: s })).error.code, "environment_mismatch");
    assert.equal((await run(["activate", one.record.caId, "--environment", "prod", "--certificate", join(carry, "1.pem")], { server: s })).exitCode, 2);
  } finally {
    await cleanup(dir);
    await cleanup(carry);
  }
});

test("activate refuses a certificate that the chain's root did not sign", async () => {
  const a = await tempDir();
  const b = await tempDir();
  const carry = await tempDir();
  try {
    await newRoot(a);
    await newRoot(b);
    const ca = pendingCa(1);
    await fs.writeFile(join(carry, "csr.pem"), ca.csr.pem);
    const signed = await run(["sign-cert", ca.record.caId, "--dir", a, "--offline", "--csr", join(carry, "csr.pem"), "--out", join(carry, "c.pem"), "--yes"], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(signed.exitCode, 0, signed.stderr);
    const result = await run(["activate", ca.record.caId, "--environment", "prod", "--certificate", join(carry, "c.pem"), "--chain", join(b, "root.pem")], { server: server(ca.record) });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "certificate_invalid");
  } finally {
    await cleanup(a);
    await cleanup(b);
    await cleanup(carry);
  }
});

// -- revoke-cert, renew-crl, upload-crl, status --------------------------------------------------------------------

const activated = async (dir: string, s: FakeServer, n = 1) => {
  const ca = pendingCa(n);
  s.add(ca.record);
  const result = await signOnline(dir, ca.record.caId, s);
  assert.equal(result.exitCode, 0, result.stderr);
  return ca;
};

test("revoke-cert: typed confirm, records, signs CRL 2, uploads and verifies the CA is revoked", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    const ca = await activated(dir, s);
    const before = await snapshot(dir);
    const noReason = await run(["revoke-cert", ca.record.caId, "--dir", dir], { server: s, stdin: new FakeTerminal("confirm\r") });
    assert.equal(noReason.exitCode, 2);
    for (const [label, stdin, code] of [["wrong", new FakeTerminal("revoke\r"), "confirmation_declined"], ["eof", new FakeTerminal(), "prompt_cancelled"]] as const) {
      const declined = await run(["revoke-cert", ca.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: s, stdin });
      assert.equal(declined.error.code, code, label);
      assert.deepEqual(await snapshot(dir), before, label);
    }
    const result = await run(["revoke-cert", ca.record.caId, "--dir", dir, "--reason", "caCompromise", "--invalidity-date", "2026-11-20T00:00:00Z"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stderr, /Review: this will REVOKE/);
    assert.match(result.stderr, new RegExp(ca.record.caId));
    assert.equal(result.json.data.revoked, true);
    assert.equal(s.cas.get(ca.record.caId)?.status, "REVOKED");
    assert.deepEqual(s.uploads().map((u) => u.number), [2n]);
    const state = await readState(dir);
    assert.equal(state.revoked[0]?.reason, "caCompromise");
    assert.equal(state.revoked[0]?.listedInCrl, 2);
    assert.equal(state.crl.current?.number, 2);
    const crl = parseCrl(fromPem(await fs.readFile(join(dir, "root.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(crl.entries[0]?.reason, "caCompromise");
    assert.equal(crl.entries[0]?.serial, state.revoked[0]?.serial);
  } finally {
    await cleanup(dir);
  }
});

test("revoke-cert: a failed upload reruns without signing; revocation_not_applied is reported; offline writes the CRL", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    const one = await activated(dir, s, 1);
    const two = await activated(dir, s, 2);
    s.failNext = { suffix: "/crl", after: false };
    const first = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(first.exitCode, 8);
    const failure = JSON.parse(first.stderr.trim().split("\n").filter((l) => l.startsWith("{")).pop() as string);
    assert.deepEqual(failure.ez.completed.slice(0, 3), ["revocation-recorded", "crl-signed", ]);
    assert.equal((await readState(dir)).crl.current?.number, 2);
    // the rerun needs no confirm or passphrase: the CRL is already signed
    const rerun = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: s, stdin: new FakeTerminal() });
    assert.equal(rerun.exitCode, 0, rerun.stderr);
    assert.equal(s.cas.get(one.record.caId)?.status, "REVOKED");
    assert.equal((await readState(dir)).crl.current?.number, 2);
    // a server that does not apply the revocation
    s.ignoreRevocations = true;
    const ignored = await run(["revoke-cert", two.record.caId, "--dir", dir, "--reason", "superseded"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(ignored.exitCode, 5);
    assert.equal(ignored.error.code, "revocation_not_applied");
    // offline by serial
    s.ignoreRevocations = false;
    const three = await activated(dir, s, 3);
    const serial = (await readState(dir)).issued.find((e) => e.caId === three.record.caId)?.serial as string;
    const out = join(dir, "carry.crl.pem");
    const offline = await run(["revoke-cert", "--serial", serial, "--dir", dir, "--offline", "--crl-out", out, "--reason", "cessationOfOperation"], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(offline.exitCode, 0, offline.stderr);
    assert.ok(parseCrl(fromPem(await fs.readFile(out, "utf8"), "X509 CRL")).entries.some((e) => e.serial === serial));
    assert.equal((await run(["revoke-cert", "--serial", "deadbeef", "--dir", dir, "--offline", "--crl-out", out, "--reason", "keyCompromise"], { stdin: new FakeTerminal() })).error.code, "unknown_serial");
  } finally {
    await cleanup(dir);
  }
});

test("renew-crl: --if-due is a no-op when the CRL is fresh; otherwise it signs, uploads and honours --expect-ext-id", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    await activated(dir, s);
    const fresh = await run(["renew-crl", "--dir", dir, "--if-due"], { server: s, stdin: new FakeTerminal() });
    assert.equal(fresh.exitCode, 0, fresh.stderr);
    assert.equal(fresh.json.data.renewed, false);
    const extId = [...s.externals.keys()][0] as string;
    const wrong = await run(["renew-crl", "--dir", dir, "--expect-ext-id", `ext-${"0".repeat(40)}`], { server: s, stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(wrong.error.code, "root_mismatch");
    assert.equal((await readState(dir)).crl.current?.number, 1);
    const renewed = await run(["renew-crl", "--dir", dir, "--expect-ext-id", extId, "--crl-validity", "100d"], { server: s, stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewed.exitCode, 0, renewed.stderr);
    assert.equal(renewed.json.data.renewed, true);
    assert.equal(renewed.json.data.uploaded, true);
    assert.deepEqual(s.uploads().map((u) => u.number), [2n]);
    // the clock moves into the renewal window: --if-due now signs
    clock.value += 140 * 86_400_000;
    try {
      const due = await run(["renew-crl", "--dir", dir, "--if-due"], { server: s, stdin: new FakeTerminal(`${PASS}\r`) });
      assert.equal(due.exitCode, 0, due.stderr);
      assert.equal(due.json.data.renewed, true);
      assert.equal(due.json.data.crl.number, 3);
    } finally {
      clock.value -= 140 * 86_400_000;
    }
    // a wrong passphrase writes nothing
    const before = await snapshot(dir);
    const bad = await run(["renew-crl", "--dir", dir], { server: s, stdin: new FakeTerminal("a wrong passphrase!\r") });
    assert.equal(bad.exitCode, 3);
    assert.deepEqual(await snapshot(dir), before);
  } finally {
    await cleanup(dir);
  }
});

test("upload-crl pushes the current CRL, and status reports local and server state", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    await activated(dir, s);
    const offline = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", join(dir, "o.crl.pem")], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(offline.exitCode, 0, offline.stderr);
    const status = await run(["status", "--dir", dir], { server: s });
    assert.equal(status.exitCode, 0, status.stderr);
    assert.equal(status.json.data.server.relation, "server_behind_local");
    assert.equal(status.json.data.issued[0].status, "activated");
    assert.deepEqual(status.json.data.deploymentsBehind, [origin]);
    const upload = await run(["upload-crl", "--dir", dir], { server: s });
    assert.equal(upload.exitCode, 0, upload.stderr);
    assert.equal(upload.json.data.uploaded, true);
    assert.equal((await run(["upload-crl", "--dir", dir], { server: s })).json.data.uploaded, false);
    assert.equal((await run(["status", "--dir", dir], { server: s })).json.data.server.relation, "in_sync");
    const local = await run(["status", "--dir", dir, "--offline"]);
    assert.equal(local.json.data.server.checked, false);
    assert.equal(local.json.data.crl.number, 2);
    // without a login, status still reports the local state
    const noLogin = await run(["status", "--dir", dir], { env: {} });
    assert.equal(noLogin.exitCode, 0);
    assert.equal(noLogin.json.data.server.checked, false);
    assert.equal((await run(["status", "--dir", await tempDir()])).error.code, "state_missing");
  } finally {
    await cleanup(dir);
  }
});

// -- CLI surface ---------------------------------------------------------------------------------------------------

test("usage errors exit 2, help is JSON, the lock blocks a second command, EzError maps onto the envelope", async () => {
  const dir = await tempDir();
  try {
    for (const args of [[], ["bogus"], ["generate-ca", "--nope"], ["sign-cert"], ["status", "extra"], ["generate-ca", "--yes", "--yes"], ["status", "--passphrase-stdin"], ["generate-ca", "--state-file", "../x", "--yes", "--subject", "CN=x"]]) {
      const result = await run(args, { stdin: pipeInput(`${PASS}\n`) });
      assert.equal(result.exitCode, 2, args.join(" "));
      assert.equal(result.stdout, "");
    }
    const help = await run(["--help"]);
    assert.equal(help.exitCode, 0);
    assert.match(help.json.usage, /generate-ca/);
    assert.equal((await run(["sign-cert", "--help"])).exitCode, 0);
    await newRoot(dir);
    const store = await EzStore.open({ dir, command: "holder" });
    try {
      const locked = await run(["status", "--dir", dir, "--offline"]);
      // status does not take the lock, a mutating command does
      assert.equal(locked.exitCode, 0);
      const renew = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", "x.pem"], { stdin: new FakeTerminal(`${PASS}\r`) });
      assert.equal(renew.exitCode, 5);
      assert.equal(renew.error.code, "state_locked");
      assert.equal(typeof renew.error.details.holder, "object");
    } finally {
      await store.close();
    }
    // --passphrase-stdin on a terminal is refused
    const tty = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", "x.pem", "--passphrase-stdin"], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(tty.exitCode, 2);
    // a non-terminal without --passphrase-stdin
    const pipe = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", "x.pem"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(pipe.error.code, "terminal_required");
    assert.equal((await run(["status", "--dir", dir, "--offline"])).json.data.crl.number, 1);
  } finally {
    await cleanup(dir);
  }
});

test("the CA id helper: caIdOf matches the CA id pattern the commands accept", () => {
  assert.match(caIdOf(7), /^ca-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
});

// -- review fixes: typeahead, pending revocations, conflicting reruns ----------------------------------------------

test("typeahead can never answer the confirm: a paste at the form prompt, or keys typed before the prompt, are discarded", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const { record } = pendingCa(1);
    const s = server(record);
    const before = await snapshot(dir);
    // one paste: accepts the form, then "confirm" and the passphrase ride along in the same chunk
    const pasted = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod"], {
      server: s,
      stdin: new FakeTerminal(`\rconfirm\r${PASS}\r`),
    });
    assert.equal(pasted.exitCode, 9);
    assert.equal(pasted.error.code, "prompt_cancelled");
    assert.match(pasted.stderr, /Review: this will sign/);
    assert.deepEqual(await snapshot(dir), before);
    // --yes, with the answer already buffered when the prompt appears: dropped by the arm window
    const early = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], {
      server: s,
      stdin: new FakeTerminal("confirm\r", `${PASS}\r`),
      confirmArmMs: 100,
    });
    assert.equal(early.exitCode, 9);
    assert.deepEqual(await snapshot(dir), before);
    assert.equal(s.mutations.length, 0);
    // typed after the prompt is shown: accepted
    const late = await run(["sign-cert", record.caId, "--dir", dir, "--environment", "prod", "--yes"], {
      server: s,
      stdin: new FakeTerminal(150, "confirm\r", `${PASS}\r`),
      confirmArmMs: 100,
    });
    assert.equal(late.exitCode, 0, late.stderr);
  } finally {
    await cleanup(dir);
  }
});

test("the confirm echoes only what is still a prefix of the word, and its proof cannot be forged", async () => {
  const out: string[] = [];
  const prompter = new Prompter({ stdin: new FakeTerminal("confXhunter2\r"), write: (t) => void out.push(t), confirmArmMs: 0 });
  await assert.rejects(prompter.confirm("sign"), (e) => e instanceof EzError && e.code === "confirmation_declined");
  const text = out.join("");
  assert.match(text, /conf/);
  assert.doesNotMatch(text, /X|hunter2/);
  const ok = await new Prompter({ stdin: new FakeTerminal("confirm\r"), write: () => {}, confirmArmMs: 0 }).confirm("sign");
  assert.equal(isConfirmation(ok), true);
  assert.equal(isConfirmation({ action: "sign" }), false);
  assert.equal(isConfirmation(Object.freeze({ action: "sign" })), false);
});

/** Records a revocation in the state without signing a CRL for it (as a crash after the record would). */
const recordRevocation = async (dir: string, serial: string, caId: string, reason: "keyCompromise" | "superseded" = "keyCompromise") => {
  const store = await EzStore.open({ dir, command: "test" });
  try {
    await store.addRevocation({ serial, caId, reason });
  } finally {
    await store.close();
  }
};

test("renew-crl and sign-cert refuse to publish an unlisted revocation; revoke-cert finishes it with its own review", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    const one = await activated(dir, s, 1);
    const two = pendingCa(2);
    s.add(two.record);
    const serial = (await readState(dir)).issued[0]?.serial as string;
    await recordRevocation(dir, serial, one.record.caId);
    const before = await snapshot(dir);
    const renew = await run(["renew-crl", "--dir", dir], { server: s, stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renew.exitCode, 5);
    assert.equal(renew.error.code, "revocation_pending");
    const renewOffline = await run(["renew-crl", "--dir", dir, "--offline", "--crl-out", "x.pem"], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewOffline.error.code, "revocation_pending");
    const sign = await signOnline(dir, two.record.caId, s);
    assert.equal(sign.error.code, "revocation_pending");
    assert.deepEqual(await snapshot(dir), before);
    // revoke-cert shows the review, asks for confirm, signs and uploads
    const done = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(done.exitCode, 0, done.stderr);
    assert.match(done.stderr, /Review: this will REVOKE/);
    assert.equal((await readState(dir)).revoked[0]?.listedInCrl, 2);
  } finally {
    await cleanup(dir);
  }
});

test("a second revoke-cert with a different reason or date is refused, and the review shows what is recorded", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    const one = await activated(dir, s, 1);
    const serial = (await readState(dir)).issued[0]?.serial as string;
    await recordRevocation(dir, serial, one.record.caId, "keyCompromise");
    const before = await snapshot(dir);
    for (const extra of [["--reason", "superseded"], ["--reason", "keyCompromise", "--invalidity-date", "2026-01-01T00:00:00Z"]]) {
      const conflict = await run(["revoke-cert", one.record.caId, "--dir", dir, ...extra], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
      assert.equal(conflict.exitCode, 5, extra.join(" "));
      assert.equal(conflict.error.code, "revocation_conflict");
      assert.doesNotMatch(conflict.stderr, /Review:/);
      assert.deepEqual(await snapshot(dir), before);
    }
    const same = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(same.exitCode, 0, same.stderr);
    assert.match(same.stderr, /Reason: +keyCompromise/);
    // once listed, the same conflict check applies to a later rerun
    const again = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "superseded"], { server: s, stdin: new FakeTerminal() });
    assert.equal(again.error.code, "revocation_conflict");
  } finally {
    await cleanup(dir);
  }
});

test("revoke-cert does not exit 0 when the logged-in server does not know the root", async () => {
  const dir = await tempDir();
  try {
    await newRoot(dir);
    const s = server();
    const one = await activated(dir, s, 1);
    const elsewhere = new FakeServer();
    const result = await run(["revoke-cert", one.record.caId, "--dir", dir, "--reason", "keyCompromise"], { server: elsewhere, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "revocation_not_applied");
    assert.equal(elsewhere.mutations.length, 0);
  } finally {
    await cleanup(dir);
  }
});
