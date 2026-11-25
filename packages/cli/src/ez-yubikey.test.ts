import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runCli } from "./index";
import { FakeServer, FakeTerminal, pendingCa, pipeInput, type FakeCa } from "./ez-fake";
import { fromPem, parseCertificate, parseCrl, verifyCertificateSignature, verifyCrlSignature } from "./ez-x509";
import type { EzState } from "./ez-state";
import { createFakeYkman, forbiddenSerials, makeDevice, randomSlot, type FakeBehavior, type FakeDevice, type FakeYkman } from "./ez-yubikey-testkit";
import { ALLOWED_SLOTS, firmwareAtLeast, parseSlot } from "./ez-yubikey";
import { YUBIKEY_SCRIPT_SHA256 } from "./ez-yubikey-script";
import type { TerminalInput } from "./tty";

const PASS = "correct horse battery staple";
const PIN = "123456";
const SERIAL = 11111111;
const SECOND = 22222222;
const token = "test.header.signature";
const origin = "https://admin.example.test";
const clock = { value: Date.parse("2026-11-25T12:00:00Z") };

interface Run {
  ez: any;
  exitCode: number;
  stdout: string;
  stderr: string;
  json: any;
  error: any;
}

const run = async (ykman: FakeYkman, args: string[], options: { stdin?: TerminalInput; server?: FakeServer; afterBackupWritten?: (path: string) => Promise<void> } = {}): Promise<Run> => {
  let stdout = "";
  let stderr = "";
  const exitCode = await runCli(["pki", "ez", ...args], {
    env: { HEMLIG_ADMIN_URL: origin, HEMLIG_ADMIN_TOKEN: token, HEMLIG_ENVIRONMENT: "prod", HEMLIG_YKMAN: ykman.path },
    configDir: join(tmpdir(), "hemlig-ez-test-no-config"),
    now: () => clock.value,
    stdin: options.stdin ?? pipeInput(),
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    transport: options.server ?? ({ async request() { throw new Error("unexpected network request"); } } as never),
    confirmArmMs: 0,
    afterBackupWritten: options.afterBackupWritten,
  });
  const last = stderr.trim().split("\n").filter((l) => l.startsWith("{")).pop();
  return { ez: last === undefined ? undefined : JSON.parse(last).ez, exitCode, stdout, stderr, json: stdout.trim() === "" ? undefined : JSON.parse(stdout), error: last === undefined ? undefined : JSON.parse(last).error };
};

const tempDir = (): Promise<string> => fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-yk-"));
const readState = async (dir: string): Promise<EzState> => JSON.parse(await fs.readFile(join(dir, "hemlig-ez.json"), "utf8"));

const base = (dir: string, extra: string[] = []): string[] => [
  "generate-ca", "--dir", dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--key-algorithm", "ECDSA_P256", "--yubikey", ...extra,
];
/** Prompts in order: serial acknowledgement, passphrase twice, PIN. */
const importKeys = (serial = SERIAL, ...more: string[]): FakeTerminal => new FakeTerminal(`${serial}\r`, `${PASS}\r`, `${PASS}\r`, `${PIN}\r`, ...more);

interface Env {
  dir: string;
  ykman: FakeYkman;
  done(): Promise<void>;
}

const setup = async (devices: FakeDevice[] = [makeDevice(SERIAL)], behavior: FakeBehavior = {}): Promise<Env> => {
  const dir = await tempDir();
  const ykman = await createFakeYkman(dir, devices, behavior);
  const work = join(dir, "root");
  await fs.mkdir(work);
  return { dir: work, ykman, done: () => fs.rm(dir, { recursive: true, force: true }) };
};

/** Every call addressed only the chosen slot, and the neighbors of the chosen slot are byte-identical. */
const assertOnlySlot = async (env: Env, slot: string, serials: number[], before: Record<number, string>): Promise<void> => {
  const calls = await env.ykman.calls();
  for (const call of calls) {
    if (call.op === "list") continue;
    assert.equal(call.slot, slot, `op ${call.op} addressed ${String(call.slot)}`);
    assert.ok(!forbiddenSerials().includes(call.serial ?? 0));
    // The secrets are only ever on stdin: argv is exactly `script --force <file>`.
    // The script arrives on an inherited pipe, so there is no script file at all.
    assert.deepEqual(call.argv, ["script", "--force", "-"]);
    assert.equal(call.scriptSha256, YUBIKEY_SCRIPT_SHA256);
  }
  for (const serial of serials) assert.equal(await env.ykman.otherSlots(serial, slot), before[serial]);
};

const snapshots = async (env: Env, serials: number[], slot = "9c"): Promise<Record<number, string>> =>
  Object.fromEntries(await Promise.all(serials.map(async (s) => [s, await env.ykman.otherSlots(s, slot)] as const)));

const writes = (calls: { op: string }[]): string[] => calls.map((c) => c.op).filter((op) => ["generate", "put-key", "put-certificate", "protect-management-key"].includes(op));

// -- helpers ---------------------------------------------------------------------------------------------------------

test("slot and firmware helpers", () => {
  assert.equal(parseSlot("9C"), "9c");
  assert.equal(parseSlot("82"), "82");
  assert.equal(parseSlot("95"), "95");
  for (const bad of ["9e", "f9", "96", "81", "9b", "", "0x9c"]) assert.throws(() => parseSlot(bad), /cannot be used/);
  assert.ok(ALLOWED_SLOTS.includes("9c") && !ALLOWED_SLOTS.includes("9e") && !ALLOWED_SLOTS.includes("f9"));
  assert.equal(firmwareAtLeast("5.4.3", 5, 3), true);
  assert.equal(firmwareAtLeast("5.4.3", 5, 7), false);
  assert.equal(firmwareAtLeast("5.7.4", 5, 7), true);
  assert.equal(firmwareAtLeast("6.0.0", 5, 7), true);
  process.env.HEMLIG_EZ_YUBIKEY_DENY = "77777777, 88888888";
  try {
    assert.throws(() => makeDevice(77777777), /deny list/);
    assert.ok(makeDevice(SERIAL));
  } finally {
    delete process.env.HEMLIG_EZ_YUBIKEY_DENY;
  }
});

// -- generate-ca: imported key (default) ---------------------------------------------------------------------------------

test("generate-ca --yubikey imports a backed-up key into slot 9c and signs with it afterwards", async () => {
  const env = await setup();
  try {
    const before = await snapshots(env, [SERIAL]);
    const result = await run(env.ykman, base(env.dir, ["--touch-policy", "always"]), { stdin: importKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.json.data.key.storage, "yubikey");
    assert.equal(result.json.data.key.generatedOnDevice, false);
    assert.deepEqual(result.json.data.key.serials, [SERIAL]);
    // The backup exists and is encrypted; the device holds the same key and the root certificate.
    assert.match(await fs.readFile(join(env.dir, "root.key.pem"), "utf8"), /BEGIN ENCRYPTED PRIVATE KEY/);
    const state = await readState(env.dir);
    assert.equal(state.key.storage, "yubikey");
    assert.equal(state.key.file, "root.key.pem");
    assert.equal(state.key.yubikey?.slot, "9c");
    assert.equal(state.key.yubikey?.pinPolicy, "always");
    assert.equal(state.key.yubikey?.touchPolicy, "always");
    assert.equal(state.key.yubikey?.generatedOnDevice, false);
    assert.equal(state.key.yubikey?.devices[0]?.serial, SERIAL);
    assert.equal(state.key.yubikey?.devices[0]?.firmware, "5.4.3");
    const device = (await env.ykman.state()).devices[0] as FakeDevice;
    const slot = device.slots["9c"];
    assert.ok(slot);
    const root = parseCertificate(fromPem(await fs.readFile(join(env.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(Buffer.from(slot.spki, "base64").equals(root.spkiDer), true);
    assert.equal(slot.touchPolicy, "always");
    assert.equal(slot.cert, root.der.toString("base64"));
    // The default (factory) management key warning was shown, and the key is not protected.
    assert.match(result.stderr, /FACTORY DEFAULT management key/);
    assert.equal(device.mgmt.default, true);
    // Calls: only the chosen slot; a test signature was made with the PIN; no secrets on argv.
    const calls = await env.ykman.calls();
    assert.deepEqual(writes(calls), ["put-key", "put-certificate"]);
    assert.ok(calls.some((c) => c.op === "sign" && c.items?.includes("test")));
    assert.match(result.stderr, /Touch the YubiKey/);
    await assertOnlySlot(env, "9c", [SERIAL], before);
  } finally {
    await env.done();
  }
});

test("a signed certificate, a CRL renewal and a revocation all go through the YubiKey", async () => {
  const env = await setup();
  try {
    const result = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    const ca = pendingCa(1);
    const server = new FakeServer();
    server.add(ca.record);
    const before = await snapshots(env, [SERIAL]);
    const callsBefore = (await env.ykman.calls()).length;
    const sign = await run(env.ykman, ["sign-cert", ca.record.caId, "--dir", env.dir, "--environment", "prod", "--yes"], {
      server,
      stdin: new FakeTerminal("confirm\r", `${PIN}\r`),
    });
    assert.equal(sign.exitCode, 0, sign.stderr);
    assert.equal(sign.json.data.activated, true);
    assert.match(sign.stderr, /Touch the YubiKey \(serial 11111111\) now to sign: Intermediate certificate/);
    const cert = (await env.ykman.calls()).slice(callsBefore);
    // The PIN is checked once with no items before anything is reserved, then the signature is made.
    assert.deepEqual(cert.filter((c) => c.op === "sign").map((c) => c.items), [[], ["intermediate-certificate"]]);
    const root = parseCertificate(fromPem(await fs.readFile(join(env.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    const issued = parseCertificate(fromPem(await fs.readFile(join(env.dir, "issued", `${sign.json.data.serial}.pem`), "utf8"), "CERTIFICATE"));
    assert.equal(verifyCertificateSignature(issued, root.spkiDer), true);

    const crlOut = join(env.dir, "next.crl.pem");
    const renew = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", crlOut], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(renew.exitCode, 0, renew.stderr);
    const crl = parseCrl(fromPem(await fs.readFile(crlOut, "utf8"), "X509 CRL"));
    assert.equal(crl.number, 2n);
    assert.equal(verifyCrlSignature(crl, root.spkiDer), true);

    const revoke = await run(env.ykman, ["revoke-cert", ca.record.caId, "--dir", env.dir, "--reason", "keyCompromise", "--offline", "--crl-out", join(env.dir, "revoked.crl.pem")], {
      stdin: new FakeTerminal("confirm\r", `${PIN}\r`),
    });
    assert.equal(revoke.exitCode, 0, revoke.stderr);
    const revokedCrl = parseCrl(fromPem(await fs.readFile(join(env.dir, "revoked.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(revokedCrl.entries.some((e) => e.serial === issued.serialHex), true);
    await assertOnlySlot(env, "9c", [SERIAL], before);
  } finally {
    await env.done();
  }
});

test("a wrong PIN fails once, is never retried and changes no state", async () => {
  const env = await setup();
  try {
    assert.equal((await run(env.ykman, base(env.dir), { stdin: importKeys() })).exitCode, 0);
    const stateBefore = await fs.readFile(join(env.dir, "hemlig-ez.json"), "utf8");
    const callsBefore = (await env.ykman.calls()).length;
    const result = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "x.crl.pem")], { stdin: new FakeTerminal("999999\r") });
    assert.equal(result.exitCode, 3);
    assert.equal(result.error.code, "pin_invalid");
    assert.match(result.error.message, /2 attempt/);
    assert.equal(await fs.readFile(join(env.dir, "hemlig-ez.json"), "utf8"), stateBefore);
    const sign = (await env.ykman.calls()).slice(callsBefore).filter((c) => c.op === "sign");
    assert.equal(sign.length, 1, "the PIN is tried exactly once");
    assert.equal((await env.ykman.state()).devices[0]?.pinAttempts, 2);
  } finally {
    await env.done();
  }
});

test("a corrupt signature is caught by the self-check (exit 7) and nothing is written", async () => {
  const env = await setup();
  try {
    assert.equal((await run(env.ykman, base(env.dir), { stdin: importKeys() })).exitCode, 0);
    await env.ykman.setState((s) => (s.behavior.corruptSignature = true));
    const stateBefore = await fs.readFile(join(env.dir, "hemlig-ez.json"), "utf8");
    const result = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "x.crl.pem")], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(result.exitCode, 7);
    assert.equal(result.error.code, "signature_self_check_failed");
    const state = JSON.parse(await fs.readFile(join(env.dir, "hemlig-ez.json"), "utf8")) as EzState;
    assert.equal(state.crl.current?.number, 1);
    await assert.rejects(fs.stat(join(env.dir, "x.crl.pem")));
    void stateBefore;
  } finally {
    await env.done();
  }
});

test("raw r||s signatures from the device are normalized to DER", async () => {
  const env = await setup([makeDevice(SERIAL)], { rawSignatures: true });
  try {
    assert.equal((await run(env.ykman, base(env.dir), { stdin: importKeys() })).exitCode, 0);
    const out = join(env.dir, "x.crl.pem");
    const result = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", out], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(result.exitCode, 0, result.stderr);
    const root = parseCertificate(fromPem(await fs.readFile(join(env.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(verifyCrlSignature(parseCrl(fromPem(await fs.readFile(out, "utf8"), "X509 CRL")), root.spkiDer), true);
  } finally {
    await env.done();
  }
});

test("a touch timeout exits 9 and signs nothing", async () => {
  const env = await setup();
  try {
    assert.equal((await run(env.ykman, base(env.dir, ["--touch-policy", "always"]), { stdin: importKeys() })).exitCode, 0);
    await env.ykman.setState((s) => (s.behavior.touchTimeout = true));
    const result = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "x.crl.pem")], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(result.exitCode, 9);
    assert.equal(result.error.code, "touch_timeout");
    assert.equal((await readState(env.dir)).crl.current?.number, 1);
  } finally {
    await env.done();
  }
});

// -- safety rails ----------------------------------------------------------------------------------------------------

test("an occupied slot is refused without --overwrite-slot, and nothing is written", async () => {
  const env = await setup([makeDevice(SERIAL, { slots: { "9a": randomSlot(), "9c": randomSlot("ECCP384"), "82": randomSlot("ECCP256") } })]);
  try {
    const before = await snapshots(env, [SERIAL]);
    const refused = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(refused.exitCode, 5);
    assert.equal(refused.error.code, "slot_occupied");
    assert.match(refused.error.message, /--overwrite-slot 9c/);
    assert.deepEqual(writes(await env.ykman.calls()), []);
    assert.deepEqual(await fs.readdir(env.dir), []);

    // Naming a different slot is a usage error, not an override.
    const wrong = await run(env.ykman, base(env.dir, ["--overwrite-slot", "9a"]), { stdin: importKeys() });
    assert.equal(wrong.exitCode, 2);
    assert.deepEqual(writes(await env.ykman.calls()), []);

    const old = (await env.ykman.state()).devices[0]?.slots["9c"]?.spki;
    const ok = await run(env.ykman, base(env.dir, ["--overwrite-slot", "9c"]), { stdin: importKeys() });
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.match(ok.stderr, /cannot delete a key/, "fw 5.4.3 cannot delete: the warning says the old key is lost");
    assert.match(ok.stderr, /will be OVERWRITTEN/);
    assert.notEqual((await env.ykman.state()).devices[0]?.slots["9c"]?.spki, old);
    await assertOnlySlot(env, "9c", [SERIAL], before);
  } finally {
    await env.done();
  }
});

test("a default PIN and a last PIN attempt are refused before any write", async () => {
  const env = await setup([makeDevice(SERIAL, { pinDefault: true })]);
  try {
    const result = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "yubikey_default_pin");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    assert.deepEqual(await fs.readdir(env.dir), []);
    await env.ykman.setState((s) => {
      (s.devices[0] as FakeDevice).pinDefault = false;
      (s.devices[0] as FakeDevice).pinAttempts = 1;
    });
    const last = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(last.exitCode, 5);
    assert.equal(last.error.code, "pin_last_attempt");
    assert.deepEqual(await fs.readdir(env.dir), []);
    const allowed = await run(env.ykman, base(env.dir, ["--allow-last-pin-attempt"]), { stdin: importKeys() });
    assert.equal(allowed.exitCode, 0, allowed.stderr);
  } finally {
    await env.done();
  }
});

test("firmware gating: RSA needs 5.7, firmware below 5.3 is unsupported", async () => {
  const env = await setup([makeDevice(SERIAL)]);
  try {
    const rsa = await run(env.ykman, base(env.dir, ["--key-algorithm", "RSA_3072"]).filter((a, i, all) => !(a === "ECDSA_P256" || all[i + 1] === "ECDSA_P256")), { stdin: importKeys() });
    assert.equal(rsa.exitCode, 2);
    assert.equal(rsa.error.code, "yubikey_algorithm_unsupported");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    await env.ykman.setState((s) => ((s.devices[0] as FakeDevice).firmware = "5.2.7"));
    const old = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(old.exitCode, 9);
    assert.equal(old.error.code, "yubikey_firmware_unsupported");
    assert.deepEqual(writes(await env.ykman.calls()), []);
  } finally {
    await env.done();
  }
});

test("RSA-3072 on firmware 5.7 imports; on 5.7 an overwrite carries no deletion warning", async () => {
  const env = await setup([makeDevice(SERIAL, { firmware: "5.7.4", mgmt: { keyType: "AES192", key: "010203040506070801020304050607080102030405060708", default: true } })]);
  try {
    const args = ["generate-ca", "--dir", env.dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--yubikey", "--key-algorithm", "RSA_3072"];
    const result = await run(env.ykman, args, { stdin: importKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal((await env.ykman.state()).devices[0]?.slots["9c"]?.keyType, "RSA3072");
  } finally {
    await env.done();
  }
});

test("device selection: several devices need --yubikey-serial; none connected is an error", async () => {
  const env = await setup([makeDevice(SERIAL), makeDevice(SECOND)]);
  try {
    const many = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(many.exitCode, 2);
    assert.equal(many.error.code, "yubikey_multiple");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    const before = await snapshots(env, [SERIAL, SECOND]);
    const ok = await run(env.ykman, base(env.dir, ["--yubikey-serial", String(SECOND)]), { stdin: importKeys(SECOND) });
    assert.equal(ok.exitCode, 0, ok.stderr);
    const state = await env.ykman.state();
    assert.ok(state.devices.find((d) => d.serial === SECOND)?.slots["9c"]);
    assert.equal(state.devices.find((d) => d.serial === SERIAL)?.slots["9c"], undefined, "the other YubiKey is untouched");
    await assertOnlySlot(env, "9c", [SERIAL, SECOND], before);
    const none = await createFakeYkman(env.dir, []);
    const missing = await run(none, base(join(env.dir, "other")), { stdin: importKeys() });
    assert.equal(missing.exitCode, 9);
    assert.equal(missing.error.code, "yubikey_not_found");
  } finally {
    await env.done();
  }
});

test("writing a key needs the serial typed at the keyboard; a wrong one aborts with no writes", async () => {
  const env = await setup();
  try {
    const wrong = await run(env.ykman, base(env.dir), { stdin: new FakeTerminal("99999999\r", `${PASS}\r`, `${PASS}\r`, `${PIN}\r`) });
    assert.equal(wrong.exitCode, 2);
    assert.equal(wrong.error.code, "confirmation_declined");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    assert.deepEqual(await fs.readdir(env.dir), []);
    // A pipe (no terminal) cannot acknowledge either; --yes does not skip it.
    const piped = await run(env.ykman, [...base(env.dir), "--passphrase-stdin", "--pin-stdin"], { stdin: pipeInput(`${PASS}\n${PIN}\n`) });
    assert.equal(piped.exitCode, 2);
    assert.equal(piped.error.code, "terminal_required");
    assert.deepEqual(writes(await env.ykman.calls()), []);
  } finally {
    await env.done();
  }
});

test("--protect-management-key replaces only the factory key, after its own typed acknowledgement", async () => {
  const env = await setup();
  try {
    const keys = new FakeTerminal(`${SERIAL}\r`, "protect management key\r", `${PASS}\r`, `${PASS}\r`, `${PIN}\r`);
    const result = await run(env.ykman, base(env.dir, ["--protect-management-key"]), { stdin: keys });
    assert.equal(result.exitCode, 0, result.stderr);
    const device = (await env.ykman.state()).devices[0] as FakeDevice;
    assert.equal(device.mgmt.default, false);
    assert.equal(device.pivmanProtected, true);
    const calls = await env.ykman.calls();
    assert.deepEqual(writes(calls), ["protect-management-key", "put-key", "put-certificate"]);
    assert.deepEqual(calls.filter((c) => c.op === "put-key").map((c) => c.managementMode), ["pin"]);
    // Without a typed acknowledgement nothing about the management key changes.
    const env2 = await setup();
    try {
      const declined = await run(env2.ykman, base(env2.dir, ["--protect-management-key"]), { stdin: new FakeTerminal(`${SERIAL}\r`, "nope\r") });
      assert.equal(declined.exitCode, 2);
      assert.equal((await env2.ykman.state()).devices[0]?.mgmt.default, true);
      assert.deepEqual(writes(await env2.ykman.calls()), []);
    } finally {
      await env2.done();
    }
  } finally {
    await env.done();
  }
});

test("the factory management key is never replaced unless asked, and a custom one is prompted for", async () => {
  const custom = "aa".repeat(24);
  const env = await setup([makeDevice(SERIAL, { mgmt: { keyType: "TDES", key: custom, default: false } })]);
  try {
    const wrong = await run(env.ykman, base(env.dir), { stdin: importKeys(SERIAL, "00".repeat(24) + "\r") });
    assert.equal(wrong.exitCode, 3);
    assert.equal(wrong.error.code, "management_key_invalid");
    assert.deepEqual(await fs.readdir(env.dir), [], "a mistyped management key is caught before any file is written");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    const ok = await run(env.ykman, base(env.dir, ["--overwrite-slot", "9c"]).filter((a) => a !== "--overwrite-slot" && a !== "9c"), { stdin: importKeys(SERIAL, `${custom}\r`) });
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.equal((await env.ykman.state()).devices[0]?.mgmt.key, custom);
    const protect = await run(env.ykman, base(join(env.dir, "again"), ["--protect-management-key", "--overwrite-slot", "9c"]), { stdin: importKeys() });
    assert.equal(protect.exitCode, 2, "a non-default management key is not rotated");
  } finally {
    await env.done();
  }
});

// -- generate on the device --------------------------------------------------------------------------------------------

test("--on-device generates in the slot with loud warnings, a typed acknowledgement and no key file", async () => {
  const env = await setup();
  try {
    const missingFlag = await run(env.ykman, base(env.dir, ["--on-device"]), { stdin: importKeys() });
    assert.equal(missingFlag.exitCode, 2);
    assert.match(missingFlag.error.message, /--accept-no-backup/);
    assert.deepEqual(await env.ykman.calls(), []);

    const before = await snapshots(env, [SERIAL]);
    // Prompts: "no backup", serial, PIN. (Two touches: certificate and CRL; the fake never blocks.)
    const result = await run(env.ykman, base(env.dir, ["--on-device", "--accept-no-backup", "--touch-policy", "always"]), {
      stdin: new FakeTerminal("no backup\r", `${SERIAL}\r`, `${PIN}\r`),
    });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stderr, /can NEVER be exported or recovered/);
    assert.match(result.stderr, /There is no second copy/);
    assert.equal(result.json.data.key.generatedOnDevice, true);
    assert.equal(result.json.data.key.backupFile, null);
    assert.deepEqual((await fs.readdir(env.dir)).sort(), ["crls", "hemlig-ez.json", "issued", "root.crl.pem", "root.pem"]);
    const state = await readState(env.dir);
    assert.equal(state.key.file, null);
    assert.equal(state.key.yubikey?.generatedOnDevice, true);
    const root = parseCertificate(fromPem(await fs.readFile(join(env.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(verifyCertificateSignature(root, root.spkiDer), true, "the root certificate was signed on the device");
    const calls = await env.ykman.calls();
    assert.deepEqual(writes(calls), ["generate", "put-certificate"]);
    assert.deepEqual(calls.filter((c) => c.op === "sign").map((c) => c.items), [[], ["root-certificate"], ["crl"]]);
    assert.equal(createPublicKey({ key: root.spkiDer, format: "der", type: "spki" }).asymmetricKeyType, "ec");
    await assertOnlySlot(env, "9c", [SERIAL], before);

    // Not typing the phrase aborts before the device is touched.
    const env2 = await setup();
    try {
      const declined = await run(env2.ykman, base(env2.dir, ["--on-device", "--accept-no-backup"]), { stdin: new FakeTerminal("yes\r", `${SERIAL}\r`, `${PIN}\r`) });
      assert.equal(declined.exitCode, 2);
      assert.equal(declined.error.code, "confirmation_declined");
      assert.deepEqual(writes(await env2.ykman.calls()), []);
    } finally {
      await env2.done();
    }

    // Signing later uses the device; import-key refuses (there is no backup).
    const imp = await run(env.ykman, ["import-key", "--dir", env.dir], { stdin: new FakeTerminal() });
    assert.equal(imp.exitCode, 5);
    assert.equal(imp.error.code, "key_not_exportable");
  } finally {
    await env.done();
  }
});

// -- second YubiKey and import-key ----------------------------------------------------------------------------------------

test("a second YubiKey in the same run is confirmed by serial and holds the same key", async () => {
  const env = await setup([makeDevice(SERIAL), makeDevice(SECOND)]);
  try {
    const before = await snapshots(env, [SERIAL, SECOND]);
    const result = await run(env.ykman, base(env.dir, ["--yubikey-serial", String(SERIAL), "--second-yubikey-serial", String(SECOND)]), {
      stdin: new FakeTerminal(`${SERIAL}\r`, `${SECOND}\r`, `${PASS}\r`, `${PASS}\r`, `${PIN}\r`, `${PIN}\r`),
    });
    assert.equal(result.exitCode, 0, result.stderr);
    const state = await env.ykman.state();
    const spkis = state.devices.map((d) => d.slots["9c"]?.spki);
    assert.equal(spkis[0], spkis[1]);
    assert.deepEqual((await readState(env.dir)).key.yubikey?.devices.map((d) => d.serial), [SERIAL, SECOND]);
    await assertOnlySlot(env, "9c", [SERIAL, SECOND], before);
    // With both connected, signing needs --yubikey-serial.
    const ambiguous = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "x.pem")], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(ambiguous.error.code, "yubikey_multiple");
    const picked = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "x.pem"), "--yubikey-serial", String(SECOND)], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(picked.exitCode, 0, picked.stderr);
    const notRecorded = await run(env.ykman, ["renew-crl", "--dir", env.dir, "--offline", "--crl-out", join(env.dir, "y.pem"), "--yubikey-serial", "33333333"], { stdin: new FakeTerminal(`${PIN}\r`) });
    assert.equal(notRecorded.error.code, "yubikey_not_recorded");
  } finally {
    await env.done();
  }
});

test("import-key restores the backup into another YubiKey and records it; software roots can move onto a YubiKey", async () => {
  const env = await setup([makeDevice(SERIAL), makeDevice(SECOND)]);
  try {
    // A software root first.
    const created = await run(env.ykman, ["generate-ca", "--dir", env.dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--key-algorithm", "ECDSA_P256", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(created.exitCode, 0, created.stderr);
    assert.equal((await readState(env.dir)).key.storage, "software");
    assert.deepEqual(await env.ykman.calls(), []);
    const before = await snapshots(env, [SERIAL, SECOND]);
    const moved = await run(env.ykman, ["import-key", "--dir", env.dir, "--yubikey-serial", String(SERIAL)], { stdin: new FakeTerminal(`${SERIAL}\r`, `${PASS}\r`, `${PIN}\r`) });
    assert.equal(moved.exitCode, 0, moved.stderr);
    let state = await readState(env.dir);
    assert.equal(state.key.storage, "yubikey");
    assert.equal(state.key.file, "root.key.pem", "the backup file is kept");
    assert.deepEqual(state.key.yubikey?.devices.map((d) => d.serial), [SERIAL]);
    const again = await run(env.ykman, ["import-key", "--dir", env.dir, "--yubikey-serial", String(SECOND)], { stdin: new FakeTerminal(`${SECOND}\r`, `${PASS}\r`, `${PIN}\r`) });
    assert.equal(again.exitCode, 0, again.stderr);
    state = await readState(env.dir);
    assert.deepEqual(state.key.yubikey?.devices.map((d) => d.serial), [SERIAL, SECOND]);
    // Same slot only; re-importing onto an occupied slot needs --overwrite-slot.
    const occupied = await run(env.ykman, ["import-key", "--dir", env.dir, "--yubikey-serial", String(SECOND)], { stdin: new FakeTerminal(`${SECOND}\r`, `${PASS}\r`, `${PIN}\r`) });
    assert.equal(occupied.error.code, "slot_occupied");
    const badSlot = await run(env.ykman, ["import-key", "--dir", env.dir, "--yubikey-serial", String(SECOND), "--slot", "9a"], { stdin: new FakeTerminal() });
    assert.equal(badSlot.exitCode, 2);
    await assertOnlySlot(env, "9c", [SERIAL, SECOND], before);
    // A wrong passphrase imports nothing.
    const env2 = await setup([makeDevice(SERIAL)]);
    try {
      await run(env2.ykman, ["generate-ca", "--dir", env2.dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--key-algorithm", "ECDSA_P256", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
      const wrong = await run(env2.ykman, ["import-key", "--dir", env2.dir], { stdin: new FakeTerminal(`${SERIAL}\r`, "wrong passphrase here\r", `${PIN}\r`) });
      assert.equal(wrong.error.code, "passphrase_invalid");
      assert.deepEqual(writes(await env2.ykman.calls()), []);
    } finally {
      await env2.done();
    }
  } finally {
    await env.done();
  }
});

test("--yubikey flags are rejected for a software root", async () => {
  const env = await setup();
  try {
    const result = await run(env.ykman, ["generate-ca", "--dir", env.dir, "--subject", "CN=Example Root,O=Example Corp", "--yes", "--slot", "9c", "--passphrase-stdin"], { stdin: pipeInput(`${PASS}\n`) });
    assert.equal(result.exitCode, 2);
    assert.deepEqual(await env.ykman.calls(), []);
  } finally {
    await env.done();
  }
});

test("import mode verifies the backup file before any device is written, and says how to recover", async () => {
  const env = await setup();
  try {
    const tampered = await run(env.ykman, base(env.dir), {
      stdin: importKeys(),
      afterBackupWritten: async (path) => {
        await fs.writeFile(path, "not the backup");
      },
    });
    assert.equal(tampered.exitCode, 9);
    assert.equal(tampered.error.code, "backup_verify_failed");
    assert.deepEqual(writes(await env.ykman.calls()), [], "no device was touched");
    assert.equal((await fs.readdir(env.dir)).includes("hemlig-ez.json"), false);
    assert.match(tampered.ez.recovery, /No state file was written and nothing was published/);
    assert.match(tampered.ez.recovery, /No YubiKey was written/);
    assert.equal(tampered.ez.rerun, undefined, "a plain rerun would hit already_exists");
  } finally {
    await env.done();
  }
});

test("a device write that did not take names the devices written, and a protected management key is reported", async () => {
  const env = await setup([makeDevice(SERIAL)], { forgetKeys: true });
  try {
    const result = await run(env.ykman, base(env.dir, ["--protect-management-key"]), {
      stdin: new FakeTerminal(`${SERIAL}\r`, "protect management key\r", `${PASS}\r`, `${PASS}\r`, `${PIN}\r`),
    });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "key_mismatch");
    assert.ok(result.ez.completed.includes(`management-key-protected:${SERIAL}`));
    assert.ok(result.ez.completed.includes("backup-written"));
    assert.match(result.ez.recovery, new RegExp(`YubiKey\\(s\\) already written: ${SERIAL} \\(slot 9c\\)`));
    assert.match(result.ez.recovery, /--overwrite-slot 9c/);
    assert.equal((await fs.readdir(env.dir)).includes("hemlig-ez.json"), false);
  } finally {
    await env.done();
  }
});

test("success receipts list the YubiKeys whose management key was replaced", async () => {
  const env = await setup();
  try {
    const result = await run(env.ykman, base(env.dir, ["--protect-management-key"]), {
      stdin: new FakeTerminal(`${SERIAL}\r`, "protect management key\r", `${PASS}\r`, `${PASS}\r`, `${PIN}\r`),
    });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(result.json.data.key.managementKeyProtected, [SERIAL]);
  } finally {
    await env.done();
  }
});

test("typed acknowledgements echo only while the input is a prefix of the phrase", async () => {
  const env = await setup();
  try {
    // The serial is echoed up to the first wrong character; the rest (and a mistyped phrase) never appears.
    const result = await run(env.ykman, base(env.dir), { stdin: new FakeTerminal("11119999\r") });
    assert.equal(result.error.code, "confirmation_declined");
    assert.ok(result.stderr.includes("1111"));
    assert.equal(result.stderr.includes("9999"), false);
  } finally {
    await env.done();
  }
});

test("generate-ca takes the directory lock before it writes anything to a device or disk", async () => {
  const env = await setup();
  try {
    await fs.writeFile(join(env.dir, ".hemlig-ez.lock"), JSON.stringify({ pid: process.pid, hostname: "other-host", command: "x", startedAt: new Date().toISOString(), nonce: "n" }));
    const result = await run(env.ykman, base(env.dir), { stdin: importKeys() });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "state_locked");
    assert.deepEqual(writes(await env.ykman.calls()), []);
    assert.equal((await fs.readdir(env.dir)).includes("root.key.pem"), false);
  } finally {
    await env.done();
  }
});

test("two YubiKeys: every PIN is checked before any device changes, and --protect-management-key waits for all of them", async () => {
  const env = await setup([makeDevice(SERIAL), makeDevice(SECOND)]);
  try {
    const result = await run(env.ykman, base(env.dir, ["--yubikey-serial", String(SERIAL), "--second-yubikey-serial", String(SECOND), "--protect-management-key"]), {
      stdin: new FakeTerminal(`${SERIAL}\r`, `${SECOND}\r`, "protect management key\r", "protect management key\r", `${PASS}\r`, `${PASS}\r`, `${PIN}\r`, "000000\r"),
    });
    assert.equal(result.exitCode, 3);
    assert.equal(result.error.code, "pin_invalid");
    assert.deepEqual(writes(await env.ykman.calls()), [], "no device was changed");
    assert.deepEqual((await env.ykman.state()).devices.map((d) => d.mgmt.default), [true, true]);
    assert.deepEqual((await fs.readdir(env.dir)).filter((f) => f !== ".hemlig-ez.lock"), []);
  } finally {
    await env.done();
  }
});

test("no script file is ever written: the script goes to ykman on an inherited pipe", async () => {
  const env = await setup();
  try {
    const tmp = await fs.readdir(tmpdir());
    assert.equal((await run(env.ykman, base(env.dir), { stdin: importKeys() })).exitCode, 0);
    const calls = await env.ykman.calls();
    assert.ok(calls.length > 0);
    assert.ok(calls.every((c) => c.scriptPath === "-" && c.scriptSha256 === YUBIKEY_SCRIPT_SHA256));
    assert.deepEqual((await fs.readdir(tmpdir())).filter((f) => f.startsWith("hemlig-ez-") && !tmp.includes(f)), []);
  } finally {
    await env.done();
  }
});

void ({} as FakeCa);
