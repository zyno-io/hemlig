import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { acquireLock } from "./ez-fs";
import { runCli } from "./index";
import { bitString, bool, extension, octetString, seq } from "./ez-der";
import { FakeServer, FakeTerminal, pendingCa, pipeInput, type FakeCa } from "./ez-fake";
import { humanFromReceipt, makeStyle, renderHuman, renderHumanError } from "./ez-output";
import { SoftwareSigner } from "./ez-signer";
import { makeBareRoot } from "./ez-testkit";
import { keyIdentifier, OID } from "./ez-x509";
import type { TerminalInput } from "./tty";

const PASS = "correct horse battery staple";
const clock = { value: Date.now() };
FakeServer.clock = () => clock.value;
// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[/;

interface Run {
  exitCode: number;
  stdout: string;
  stderr: string;
}

interface Options {
  stdin?: TerminalInput;
  server?: FakeServer;
  stdoutTty?: boolean;
  stderrTty?: boolean;
  env?: NodeJS.ProcessEnv;
}

const run = async (args: string[], options: Options = {}): Promise<Run> => {
  let stdout = "";
  let stderr = "";
  clock.value = Date.now();
  const exitCode = await runCli(["pki", "ez", ...args], {
    env: { HEMLIG_ADMIN_URL: "https://admin.example.test", HEMLIG_ADMIN_TOKEN: "test.header.signature", HEMLIG_ENVIRONMENT: "prod", ...options.env },
    configDir: join(tmpdir(), "hemlig-ez-output-no-config"),
    now: () => clock.value,
    stdin: options.stdin ?? pipeInput(),
    stdout: (t) => {
      stdout += t;
    },
    stderr: (t) => {
      stderr += t;
    },
    stdoutIsTTY: options.stdoutTty ?? false,
    stderrIsTTY: options.stderrTty ?? false,
    transport: options.server ?? ({ async request() { throw new Error("unexpected network request"); } } as never),
    confirmArmMs: 0,
  });
  return { exitCode, stdout, stderr };
};

const tty = (options: Options = {}): Options => ({ stdoutTty: true, stderrTty: true, env: { NO_COLOR: "1" }, ...options });
const tempDir = (): Promise<string> => fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-out-"));
const server = (...cas: FakeCa[]): FakeServer => {
  const s = new FakeServer();
  for (const ca of cas) s.add(ca);
  return s;
};

/** A bare root and key in files, adopted into `<dir>/out` with the human output captured. */
const adopt = async (dir: string, options: Options = tty()) => {
  const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const signer = new SoftwareSigner(key);
  const bare = makeBareRoot({
    privateKey: key,
    subject: { O: "Example Corp", CN: "Output Root" },
    notAfter: new Date(Date.now() + 3000 * 86_400_000),
    extensions: [extension(OID.basicConstraints, true, seq(bool(true))), extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)), extension(OID.ski, false, octetString(keyIdentifier(signer.spkiDer)))],
  });
  await fs.writeFile(join(dir, "root.pem"), bare.pem);
  await fs.writeFile(join(dir, "key.pem"), key.export({ type: "pkcs8", format: "pem" }));
  const out = join(dir, "CA");
  const result = await run(["adopt-ca", "--dir", out, "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--no-prior-revocations", "--crl-number", "1", "--offline"], {
    ...options,
    stdin: new FakeTerminal("confirm\r", `${PASS}\r`, `${PASS}\r`),
  });
  return { out, result };
};

test("adopt-ca on a terminal prints a headline, aligned facts, warnings and numbered next steps, and no JSON", async () => {
  const dir = await tempDir();
  try {
    const { out, result } = await adopt(dir);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stdout, /^✓ Root adopted: O=Example Corp, CN=Output Root\n/);
    assert.match(result.stdout, /\n {2}Fingerprint {2,}[0-9a-f]{64} \(SHA-256\)\n/);
    assert.match(result.stdout, /\n {2}CRL {2,}#2, next update \d{4}-\d{2}-\d{2} \(\d+ days left\), signed now\n/);
    assert.match(result.stdout, new RegExp(`\\n {2}Directory {2,}${out.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n`));
    assert.match(result.stdout, /\n {2}Revocations {2,}0 carried over \(none declared\)\n/);
    assert.match(result.stdout, /\n! The original key file\(s\) remain: \S+key\.pem\. They are NOT encrypted\./);
    assert.match(result.stdout, /\nNext steps\n {2}1\. Back up .*CA \(for example, commit it to a private git repo\)\.\n {2}2\. Create an intermediate CA in Hemlig/);
    assert.match(result.stdout, new RegExp(`\\n {5}hemlig pki ez sign-cert <ca-id> --environment prod --dir ${out.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n`));
    assert.doesNotMatch(result.stdout, /\{"data"/);
    assert.doesNotMatch(result.stdout + result.stderr, /\bEZ\b/);
    assert.doesNotMatch(result.stdout, ANSI);
    // The review and the typed prompt still go to stderr; the old duplicate summary does not.
    assert.match(result.stderr, /ADOPT an existing root into Hemlig/);
    assert.doesNotMatch(result.stderr, /Root adopted:/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("without a terminal, or with --json, stdout is the unchanged JSON envelope and the human summary stays on stderr", async () => {
  const dir = await tempDir();
  try {
    const piped = await adopt(dir, { stdoutTty: false, stderrTty: false });
    assert.equal(piped.result.exitCode, 0);
    const envelope = JSON.parse(piped.result.stdout) as { data: Record<string, any>; next: string[] };
    assert.equal(piped.result.stdout.trim().split("\n").length, 1);
    assert.equal(envelope.data.command, "adopt-ca");
    assert.ok(envelope.next.every((n) => !/\bEZ\b/.test(n)));
    assert.match(piped.result.stderr, /Root adopted: /);
    assert.match(piped.result.stderr, /NOTE: the original key file\(s\) remain/);
    // --json on a terminal: the same envelope (the field names are the same), the summary on stderr
    const dir2 = await tempDir();
    const key = dir2;
    void key;
    const second = await run(["status", "--dir", piped.out, "--offline", "--json"], tty());
    assert.equal(JSON.parse(second.stdout).data.command, "status");
    assert.doesNotMatch(second.stdout, /✓/);
    await fs.rm(dir2, { recursive: true, force: true });
    const plain = await run(["status", "--dir", piped.out, "--offline"], { stdoutTty: false });
    assert.equal(JSON.parse(plain.stdout).data.command, "status");
    // --json is accepted by every command's parser
    const usage = await run(["renew-crl", "--json", "--offline"]);
    assert.equal(usage.exitCode, 2, "renew-crl --offline still needs --crl-out");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("NO_COLOR keeps a terminal result plain, and without it the result is colored", async () => {
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const plain = await run(["status", "--dir", out, "--offline"], tty({ env: { NO_COLOR: "1" } }));
    assert.doesNotMatch(plain.stdout, ANSI);
    const dumb = await run(["status", "--dir", out, "--offline"], tty({ env: { TERM: "dumb" } }));
    assert.doesNotMatch(dumb.stdout, ANSI);
    const colored = await run(["status", "--dir", out, "--offline"], { stdoutTty: true, stderrTty: true, env: { TERM: "xterm-256color" } });
    assert.match(colored.stdout, ANSI);
    assert.match(colored.stdout.replace(/\x1b\[[0-9;]*m/g, ""), /Output Root/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("status reads as a dashboard; renew-crl, sign-cert (online and offline), activate, revoke-cert and upload-crl each print a result with next steps", async () => {
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const ca = pendingCa(1);
    const s = server(ca.record);
    const keys = (): FakeTerminal => new FakeTerminal("confirm\r", `${PASS}\r`);

    const signed = await run(["sign-cert", ca.record.caId, "--dir", out, "--environment", "prod", "--yes"], { ...tty(), server: s, stdin: keys() });
    assert.equal(signed.exitCode, 0, signed.stderr);
    assert.match(signed.stdout, new RegExp(`^✓ Certificate signed and CA activated: ${ca.record.caId}\\n`));
    assert.match(signed.stdout, /\n {2}CA ID {2,}ca-/);
    assert.match(signed.stdout, /\n {2}Root CRL {2,}#2, next update/);
    assert.match(signed.stdout, /\nNext steps\n {2}1\. Keep the root CRL fresh: .*\n {5}hemlig pki ez renew-crl --if-due --dir /);
    assert.doesNotMatch(signed.stdout, /\{"data"/);

    const status = await run(["status", "--dir", out], { ...tty(), server: s });
    assert.equal(status.exitCode, 0, status.stderr);
    assert.match(status.stdout, /^✓ O=Example Corp, CN=Output Root\n/);
    for (const label of ["Origin", "Fingerprint", "Key", "CRL", "Issued", "Revoked", "Server", "Directory"]) assert.match(status.stdout, new RegExp(`\\n {2}${label} {2,}\\S`));
    assert.match(status.stdout, /Issued {2,}1 certificate, 1 active/);
    assert.match(status.stdout, /Server {2,}in sync with https:\/\/admin\.example\.test/);
    assert.ok(status.stdout.split("\n").length < 16, "a compact dashboard");

    const renewed = await run(["renew-crl", "--dir", out], { ...tty(), server: s, stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewed.exitCode, 0, renewed.stderr);
    assert.match(renewed.stdout, /^✓ Root CRL renewed: #3\n/);
    assert.match(renewed.stdout, /Server {2,}uploaded/);
    const current = await run(["renew-crl", "--dir", out, "--if-due"], { ...tty(), server: s, stdin: new FakeTerminal(`${PASS}\r`) });
    assert.match(current.stdout, /^✓ Root CRL is current: #3\n/);
    const offlineRenew = await run(["renew-crl", "--dir", out, "--offline", "--crl-out", "carry.crl.pem"], { ...tty(), stdin: new FakeTerminal(`${PASS}\r`) });
    assert.match(offlineRenew.stdout, /^✓ Root CRL renewed: #4\n/);
    assert.match(offlineRenew.stdout, /1\. On a machine that can reach Hemlig, upload it:\n {5}hemlig pki ez upload-crl --crl .*carry\.crl\.pem --root-cert /);

    const uploaded = await run(["upload-crl", "--dir", out], { ...tty(), server: s });
    assert.equal(uploaded.exitCode, 0, uploaded.stderr);
    assert.match(uploaded.stdout, /^✓ Root CRL #4 uploaded\n/);
    const again = await run(["upload-crl", "--dir", out], { ...tty(), server: s });
    assert.match(again.stdout, /^✓ Root CRL #4 is already on the server\n/);

    const revoked = await run(["revoke-cert", ca.record.caId, "--dir", out, "--reason", "caCompromise"], { ...tty(), server: s, stdin: keys() });
    assert.equal(revoked.exitCode, 0, revoked.stderr);
    assert.match(revoked.stdout, new RegExp(`^✓ Revoked ${ca.record.caId}: caCompromise\\n`));
    assert.match(revoked.stdout, /Server {2,}shows the CA as revoked/);

    // sign-cert offline, then activate it
    const ca2 = pendingCa(2);
    s.add(ca2.record);
    const csr = join(dir, "ca2.csr.pem");
    await fs.writeFile(csr, ca2.csr.pem);
    const off = await run(["sign-cert", ca2.record.caId, "--dir", out, "--offline", "--csr", csr, "--expect-spki-sha256", ca2.record.spkiSha256, "--out", join(dir, "ca2.pem"), "--chain-out", join(dir, "chain.pem"), "--crl-out", join(dir, "c.crl.pem"), "--yes"], { ...tty(), stdin: keys() });
    assert.equal(off.exitCode, 0, off.stderr);
    assert.match(off.stdout, new RegExp(`^✓ Certificate signed for ${ca2.record.caId} \\(not activated yet\\)\\n`));
    assert.match(off.stdout, /Next steps\n {2}1\. Carry the certificate, the root and the CRL to a machine that can reach Hemlig and activate:\n {5}hemlig pki ez activate /);
    const activated = await run(["activate", ca2.record.caId, "--environment", "prod", "--certificate", join(dir, "ca2.pem"), "--chain", join(dir, "chain.pem"), "--crl", join(dir, "c.crl.pem")], { ...tty(), server: s });
    assert.equal(activated.exitCode, 0, activated.stderr);
    assert.match(activated.stdout, new RegExp(`^✓ CA activated: ${ca2.record.caId}\\n`));
    assert.match(activated.stdout, /\n {2}Root CRL {2,}#/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("generate-ca on a terminal prints the root, its files and the steps after it", async () => {
  const dir = await tempDir();
  try {
    const result = await run(["generate-ca", "--dir", join(dir, "new"), "--subject", "CN=Fresh Root,O=Example Corp", "--yes", "--key-algorithm", "ECDSA_P256"], { ...tty(), stdin: new FakeTerminal(`${PASS}\r`, `${PASS}\r`) });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stdout, /^✓ Root created: O=Example Corp, CN=Fresh Root\n/);
    assert.match(result.stdout, /\n {2}Files {2,}hemlig-ez\.json, root\.key\.pem, root\.pem, root\.crl\.pem\n/);
    assert.match(result.stdout, /\n {2}Key {2,}ECDSA_P256, software key file root\.key\.pem\n/);
    assert.match(result.stdout, /Next steps\n {2}1\. Back up .*new, including root\.key\.pem/);
    assert.doesNotMatch(result.stdout, /\{"data"/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("import-key and warnings render from their receipts", () => {
  const style = makeStyle(false);
  const result = humanFromReceipt(
    { command: "import-key", root: { fingerprint: "ab".repeat(32) }, yubikey: { serial: 11111111, firmware: "5.7.4", slot: "9c", keyType: "ECCP384", touchPolicy: "always" }, warnings: ["slot_certificate_failed:11111111"] },
    [],
    { command: "import-key", dir: "/ca", cwd: "/elsewhere", now: new Date() },
  );
  const text = renderHuman(result, style);
  assert.match(text, /^✓ Root key imported into YubiKey 11111111\n/);
  assert.match(text, /\n {2}Fingerprint {2,}(ab){32} \(SHA-256\)\n/);
  assert.match(text, /Key {2,}ECCP384, slot 9c, touch always/);
  assert.match(text, /\n! The root certificate could not be stored in the slot of YubiKey 11111111/);
  assert.doesNotMatch(text, /renew-crl|Check it signs/, "a step that would commit a new CRL number is not suggested");
  const withHint = renderHuman(humanFromReceipt({ command: "import-key", root: { fingerprint: "ab".repeat(32) }, yubikey: { serial: 11111111, firmware: "5.7.4", slot: "9c", keyType: "ECCP384", touchPolicy: "always" } }, ["Signing now uses the YubiKey; the key file is kept as the backup."], { command: "import-key", dir: "/ca", cwd: "/", now: new Date() }), style);
  assert.match(withHint, /1\. Signing now uses the YubiKey; the key file is kept as the backup\./);
});

test("untrusted values cannot inject terminal escapes into a result or an error", () => {
  const style = makeStyle(false);
  const text = renderHuman(
    humanFromReceipt({ command: "activate", caId: "ca-\x1b[2J", environment: "prod\x07", serial: "01", fingerprint: "ab".repeat(32), root: { extId: "ext-x" }, activated: true }, [], { command: "activate", dir: "/", cwd: "/", now: new Date() }),
    style,
  );
  assert.equal(/[\x00-\x08\x0b-\x1f\x7f]/.test(text), false);
  const error = renderHumanError({ exitCode: 2, code: "invalid_input", message: "bad \x1b[31m input" }, style);
  assert.equal(error.includes("\x1b"), false);
});

test("a terminal error is a short human message with the code and exit code; JSON and piped stderr keep the envelope", async () => {
  const dir = await tempDir();
  try {
    const args = ["generate-ca", "--dir", join(dir, "x"), "--subject", "CN=R", "--yes", "--passphrase-stdin"];
    const human = await run(args, { ...tty(), stdin: pipeInput("short\n") });
    assert.equal(human.exitCode, 2);
    assert.equal(human.stderr.trimEnd(), "✗ The passphrase must be at least 12 bytes.\n  (invalid_input, exit 2)");
    assert.equal(human.stdout, "");
    const json = await run([...args, "--json"], { ...tty(), stdin: pipeInput("short\n") });
    assert.equal(json.exitCode, 2);
    assert.deepEqual(JSON.parse(json.stderr), { error: { exitCode: 2, code: "invalid_input", message: "The passphrase must be at least 12 bytes." } });
    const piped = await run(args, { stdoutTty: true, stderrTty: false, stdin: pipeInput("short\n") });
    assert.deepEqual(JSON.parse(piped.stderr), { error: { exitCode: 2, code: "invalid_input", message: "The passphrase must be at least 12 bytes." } });
    // a hint where one exists, and the retry line after partial progress
    const usage = await run(["status", "--dir", join(dir, "none")], tty());
    assert.equal(usage.exitCode, 5);
    assert.match(usage.stderr, /^✗ .*does not exist/);
    assert.match(usage.stderr, /\(state_missing, exit 5\)/);
    const hint = renderHumanError({ exitCode: 3, code: "passphrase_invalid", message: "The passphrase is wrong, or the key file is damaged.", ez: { completed: ["certificate-signed"], rerun: "hemlig pki ez sign-cert ca-1" } }, makeStyle(false));
    assert.match(hint, /\n {2}Check the passphrase for the key file and try again\.\n/);
    assert.match(hint, /Done before the failure: certificate-signed\./);
    assert.match(hint, /To retry: hemlig pki ez sign-cert ca-1\n$/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// -- review findings ---------------------------------------------------------------------------------------------------

const havePty = ((): boolean => {
  const probe = spawnSync("python3", ["-c", "import pty,os; m,s=pty.openpty(); os.close(m); os.close(s)"], { encoding: "utf8" });
  return probe.status === 0;
})();

const PTY_RUNNER = `
import os, pty, subprocess, sys
master, slave = pty.openpty()
env = dict(os.environ, NO_COLOR="1")
proc = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=env)
os.close(slave)
out = b""
while True:
    try:
        chunk = os.read(master, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
proc.wait()
sys.stdout.write(out.decode("utf8", "replace").replace("\\r\\n", "\\n"))
sys.exit(proc.returncode)
`;

test("the real binary prints the human result under a pty and the JSON envelope when piped", { skip: !havePty && "no pty available" }, async () => {
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const main = join(__dirname, "main.js");
    const base = ["pki", "ez", "status", "--dir", out, "--offline"];
    const real = spawnSync("python3", ["-c", PTY_RUNNER, process.execPath, main, ...base], { encoding: "utf8" });
    assert.equal(real.status, 0, real.stdout + real.stderr);
    assert.match(real.stdout, /^✓ O=Example Corp, CN=Output Root\n/);
    assert.match(real.stdout, /\n {2}Fingerprint {2,}[0-9a-f]{64} \(SHA-256\)\n/);
    assert.doesNotMatch(real.stdout, /\{"data"/);
    const failing = spawnSync("python3", ["-c", PTY_RUNNER, process.execPath, main, "pki", "ez", "status", "--dir", join(dir, "missing"), "--offline"], { encoding: "utf8" });
    assert.equal(failing.status, 5);
    assert.match(failing.stdout, /^✗ .*does not exist[^\n]*\n {2}\(state_missing, exit 5\)/);
    const piped = spawnSync(process.execPath, [main, ...base], { encoding: "utf8" });
    assert.equal(piped.status, 0);
    assert.equal(JSON.parse(piped.stdout).data.command, "status");
    const withJson = spawnSync("python3", ["-c", PTY_RUNNER, process.execPath, main, ...base, "--json"], { encoding: "utf8" });
    assert.equal(JSON.parse(withJson.stdout.trim()).data.command, "status");
    const pipedError = spawnSync(process.execPath, [main, "pki", "ez", "status", "--dir", join(dir, "missing"), "--offline"], { encoding: "utf8" });
    assert.equal(pipedError.status, 5);
    assert.equal(JSON.parse(pipedError.stderr).error.code, "state_missing");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("re-running activate on an already-active CA prints a result (no crash), and a renderer failure falls back to the JSON receipt with the real exit code", async () => {
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const ca = pendingCa(1);
    const s = server(ca.record);
    const csr = join(dir, "ca.csr.pem");
    await fs.writeFile(csr, ca.csr.pem);
    const files = [join(dir, "c.pem"), join(dir, "chain.pem"), join(dir, "c.crl.pem")];
    assert.equal((await run(["sign-cert", ca.record.caId, "--dir", out, "--offline", "--csr", csr, "--out", files[0] as string, "--chain-out", files[1] as string, "--crl-out", files[2] as string, "--yes"], { ...tty(), stdin: new FakeTerminal("confirm\r", `${PASS}\r`) })).exitCode, 0);
    const args = ["activate", ca.record.caId, "--environment", "prod", "--certificate", files[0] as string, "--chain", files[1] as string, "--crl", files[2] as string];
    assert.equal((await run(args, { ...tty(), server: s })).exitCode, 0);
    const again = await run(args, { ...tty(), server: s });
    assert.equal(again.exitCode, 0, again.stderr);
    assert.match(again.stdout, new RegExp(`^✓ CA ${ca.record.caId} was already active\\n`));
    // a renderer exception: JSON on stdout, exit 0
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const output = require("./ez-output") as { humanFromReceipt: unknown };
    const original = output.humanFromReceipt;
    output.humanFromReceipt = () => {
      throw new TypeError("renderer bug");
    };
    try {
      const broken = await run(args, { ...tty(), server: s });
      assert.equal(broken.exitCode, 0);
      assert.equal(JSON.parse(broken.stdout).data.command, "activate");
    } finally {
      output.humanFromReceipt = original;
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("generate-ca whose form changes the directory reports and suggests the directory it used", async () => {
  const dir = await tempDir();
  try {
    const chosen = join(dir, "chosen");
    const result = await run(["generate-ca", "--dir", join(dir, "typed"), "--subject", "CN=Moved Root,O=Example Corp", "--key-algorithm", "ECDSA_P256"], {
      ...tty(),
      stdin: new FakeTerminal("1\r", `${chosen}\r`, "\r", `${PASS}\r`, `${PASS}\r`),
    });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`\\n {2}Directory {2,}${chosen.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n`));
    assert.match(result.stdout, new RegExp(`--dir ${chosen.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n`));
    assert.equal(result.stdout.includes("typed"), false);
    assert.ok((await fs.stat(join(chosen, "hemlig-ez.json"))).isFile());
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a terminal error carries the details a person needs: details, API fields, files, lock holder, serials, fingerprint, and the output flag for already_exists", async () => {
  const text = renderHumanError(
    { exitCode: 5, code: "revocation_not_applied", message: "The signed CRL was not uploaded.", details: { caId: "ca-1", issuedBy: "https://a.example", session: "https://b.example", originDiffers: true }, status: 409, apiCode: "conflict", apiDetails: { reason: "ca_not_pending" }, ez: { completed: ["revocation-recorded"], files: { crl: "/ca/root.crl.pem" }, rerun: "hemlig pki ez revoke-cert x" } },
    makeStyle(false),
    { fingerprint: "ab".repeat(32) },
  );
  for (const expected of ["caId: ca-1", "issuedBy: https://a.example", "session: https://b.example", "originDiffers: true", "HTTP status: 409", "API code: conflict", 'API details: {"reason":"ca_not_pending"}', "File crl: /ca/root.crl.pem", `Root fingerprint: ${"ab".repeat(32)} (SHA-256)`, "Done before the failure: revocation-recorded.", "To retry: hemlig pki ez revoke-cert x"]) {
    assert.ok(text.includes(expected), `${expected}\n${text}`);
  }
  assert.ok(renderHumanError({ exitCode: 5, code: "revocation_pending", message: "m", details: { serials: ["0a0b"] } }, makeStyle(false)).includes('serials: ["0a0b"]'));

  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    // the lock holder
    const lock = await acquireLock(out, { command: "pki ez test", hostname: "elsewhere", now: () => new Date() });
    try {
      const locked = await run(["renew-crl", "--dir", out, "--offline", "--crl-out", join(dir, "l.crl.pem")], { ...tty(), stdin: new FakeTerminal(`${PASS}\r`) });
      assert.equal(locked.exitCode, 5);
      assert.match(locked.stderr, /\(state_locked, exit 5\)/);
      assert.match(locked.stderr, /holder: \{.*"hostname":"elsewhere"/);
      assert.match(locked.stderr, /lockFile: /);
    } finally {
      await lock.release();
    }
    // already_exists names the output flag
    const ca = pendingCa(1);
    const csr = join(dir, "ca.csr.pem");
    await fs.writeFile(csr, ca.csr.pem);
    await fs.writeFile(join(dir, "taken.pem"), "x");
    const exists = await run(["sign-cert", ca.record.caId, "--dir", out, "--offline", "--csr", csr, "--out", join(dir, "taken.pem"), "--yes"], { ...tty(), stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(exists.exitCode, 5);
    assert.match(exists.stderr, /Choose another name for --out \(.*taken\.pem\)/);
    assert.doesNotMatch(exists.stderr, /Choose another --dir/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("status with a recorded but unlisted revocation points to revoke-cert, not renew-crl; renew-crl says when the root is not registered", async () => {
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const statePath = join(out, "hemlig-ez.json");
    const state = JSON.parse(await fs.readFile(statePath, "utf8"));
    state.revoked.push({ serial: "0a0b", caId: null, reason: "keyCompromise", revokedAt: new Date().toISOString(), invalidityDate: null, imported: false, listedInCrl: null });
    await fs.writeFile(statePath, JSON.stringify(state));
    const status = await run(["status", "--dir", out, "--offline"], tty());
    assert.equal(status.exitCode, 0, status.stderr);
    assert.match(status.stdout, /\n! 1 revocation recorded but not yet in a signed CRL \(serial 0a0b\)/);
    assert.match(status.stdout, /hemlig pki ez revoke-cert --serial 0a0b --reason keyCompromise --dir /);
    assert.doesNotMatch(status.stdout, /Renew the root CRL/);
    state.revoked.pop();
    await fs.writeFile(statePath, JSON.stringify(state));
    const unregistered = await run(["renew-crl", "--dir", out], { ...tty(), server: server(), stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(unregistered.exitCode, 0, unregistered.stderr);
    assert.match(unregistered.stdout, /\n {2}Server {2,}not registered with Hemlig yet/);
    assert.doesNotMatch(unregistered.stdout, /already up to date/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("line separators, bidi marks and newlines in server-supplied values cannot forge a line in a terminal error or result", async () => {
  const error = renderHumanError({ exitCode: 5, code: "x\ny", message: "a\nb\u2028c\u2029d\u200ee\u200ff\u061cg" }, makeStyle(false));
  assert.equal(error.split("\n").length, 3, "the message and the code stay on their own single lines");
  assert.equal(/[\u2028\u2029\u200e\u200f\u061c]/.test(error), false);
  const text = renderHuman({ headline: "h\u2028i", facts: [["K", "v\nforged"]], warnings: ["w\u200fx\nforged"] }, makeStyle(false));
  assert.equal(/[\u2028\u200f]/.test(text), false);
  assert.equal(text.split("\n").filter((l) => l.includes("forged")).length, 2);
  const dir = await tempDir();
  try {
    const { out } = await adopt(dir);
    const ca = pendingCa(1);
    (ca.record as { environment: string }).environment = "pr\nod\u2028";
    const result = await run(["sign-cert", ca.record.caId, "--dir", out, "--environment", "prod", "--yes"], { ...tty(), server: server(ca.record), stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(result.exitCode, 5);
    assert.match(result.stderr, /^✗ That CA is in environment pr\\x0aod\\x2028, not prod\.\n {2}\(environment_mismatch, exit 5\)/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the full fingerprint is shown for generate-ca, adopt-ca, import-key and status, and the PBKDF2 note is in the adopt result", () => {
  const style = makeStyle(false);
  const fp = "cd".repeat(32);
  const adopted = renderHuman(
    humanFromReceipt(
      { command: "adopt-ca", root: { subject: "CN=R", fingerprint: fp }, crl: { number: 1, nextUpdate: "2027-01-01T00:00:00.000Z", signed: true }, revocations: { count: 0, sources: ["none-declared"] }, key: { storage: "software", file: "/ca/root.key.pem" }, files: { key: "/ca/root.key.pem", certificate: "/ca/root.pem" } },
      [],
      { command: "adopt-ca", dir: "/ca", cwd: "/", now: new Date("2026-12-01T00:00:00Z") },
      { originalKeys: ["/src/private/root.key"], sourceEncrypted: true },
    ),
    style,
  );
  assert.ok(adopted.includes(`${fp} (SHA-256)`));
  assert.match(adopted, /! The original key file\(s\) remain: \/src\/private\/root\.key\. OpenSSL's -aes256 protects them with only a few thousand PBKDF2 iterations/);
  const generated = renderHuman(humanFromReceipt({ command: "generate-ca", root: { subject: "CN=R", fingerprint: fp, keyAlgorithm: "ECDSA_P256", notBefore: "2026-01-01", notAfter: "2046-01-01" }, key: { storage: "software" }, crl: { number: 1, nextUpdate: "2027-01-01T00:00:00.000Z" }, files: { key: "/ca/root.key.pem" } }, [], { command: "generate-ca", dir: "/ca", cwd: "/", now: new Date("2026-12-01T00:00:00Z") }), style);
  assert.ok(generated.includes(`${fp} (SHA-256)`));
});

test("a failing stderr on the error path exits 9 instead of an unhandled rejection", async () => {
  let stderrCalls = 0;
  const exitCode = await runCli(["pki", "ez", "status", "--dir", join(tmpdir(), "does-not-exist-ez-out")], {
    env: {},
    stdin: pipeInput(),
    stdout: async () => undefined,
    stderr: async () => {
      stderrCalls += 1;
      throw Object.assign(new Error("write EIO"), { code: "EIO" });
    },
    stdoutIsTTY: true,
    stderrIsTTY: true,
  });
  assert.equal(exitCode, 9);
  assert.ok(stderrCalls >= 1);
});
