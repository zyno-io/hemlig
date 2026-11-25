import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { KeyObject } from "node:crypto";
import { PassThrough } from "node:stream";
import test from "node:test";
import { EzError } from "./ez-error";
import { acquireLock, LOCK_FILE } from "./ez-fs";
import { prepareCrl, prepareIntermediate, prepareRoot, signPrepared } from "./ez-issue";
import { encryptPkcs8 } from "./ez-keyfile";
import { formatSubject } from "./ez-name";
import { SoftwareSigner, generateSoftwareKey } from "./ez-signer";
import { EzStore, compareWithServer, initialArtifacts, initialState, type EzState, type StoreOptions } from "./ez-state";
import { makeTestCsr } from "./ez-testkit";
import { parseCrl, fromPem, validateCsr } from "./ez-x509";
import { readTerminalLine, type TerminalInput } from "./tty";

let clock = new Date("2026-11-25T12:00:00Z");
const subject = { O: "Example Corp", CN: "Hardening Root" };
const code = (p: Promise<unknown>, expected: string, reason?: string) =>
  assert.rejects(p, (e) => e instanceof EzError && e.code === expected && (reason === undefined || (e.details as { reason?: string } | undefined)?.reason === reason), `expected ${expected}${reason ? `/${reason}` : ""}`);

interface F { dir: string; privateKey: KeyObject; signer: SoftwareSigner; options: StoreOptions; store: EzStore; state: ReturnType<typeof initialState>; rootDer: Buffer; crlDer: Buffer }

const fixture = async (name: string, extra: Partial<StoreOptions> = {}): Promise<F> => {
  clock = new Date("2026-11-25T12:00:00Z");
  const dir = await fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), `ez-hard-${name}-`));
  const key = generateSoftwareKey("ECDSA_P256");
  const signer = new SoftwareSigner(key.privateKey);
  const [root] = await signPrepared(signer, [prepareRoot(signer, { subject, now: clock })] as const);
  const [crl] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: clock, entries: [] })] as const);
  const state = initialState({
    origin: "generated", subject, subjectDn: formatSubject(subject), root: root.certificate, keyAlgorithm: "ECDSA_P256",
    key: { storage: "software", file: "root.key.pem", kdf: { name: "pbkdf2-hmac-sha256", iterations: 1_000_000 }, yubikey: null },
    crl: crl.crl, now: clock,
  });
  const options: StoreOptions = { dir, command: "test", now: () => clock, hostname: "h1", ...extra };
  const store = await EzStore.create(options, state, initialArtifacts(state, { rootDer: root.der, crlDer: crl.der, keyFilePem: "KEYFILE" }));
  return { dir, privateKey: key.privateKey, signer, options, store, state, rootDer: root.der, crlDer: crl.der };
};
const done = async (f: F) => { await f.store.close().catch(() => undefined); await fs.rm(f.dir, { recursive: true, force: true }); };
const tick = () => { clock = new Date(clock.getTime() + 60_000); };
const crlFor = async (f: F, number: number, thisUpdate: Date, entries = f.store.revocationEntries()) =>
  (await signPrepared(f.signer, [prepareCrl(f.signer, f.store.rootCertificate, { number, thisUpdate, entries })] as const))[0];
const reserve = (serial: string, caId: string, csr = validateCsr(makeTestCsr().der)) => ({
  csr, sign: { serial, caId, environment: "prod", adminOrigin: null, subjectDn: `CN=${caId}`, csrSha256: csr.sha256, spkiSha256: csr.spkiSha256, notBefore: clock, notAfter: new Date(clock.getTime() + 400 * 86_400_000) },
});

// -- 2: commitCrl must be exactly the reserved CRL ----------------------------------------------------------------------

test("commitCrl: refuses a CRL that omits a revocation, was never reserved, or is not newer (p2 A, B)", async () => {
  const f = await fixture("crl");
  try {
    await f.store.addRevocation({ serial: "01aa", caId: "ca-1", reason: "keyCompromise" });
    tick();
    const r2 = (await f.store.begin({ crl: true })).crl!;
    await f.store.commitCrl(r2.number, (await crlFor(f, r2.number, r2.thisUpdate)).der);
    tick();
    const r3 = (await f.store.begin({ crl: true })).crl!;
    // A1: #3 without the revoked serial would un-revoke it.
    await code(f.store.commitCrl(r3.number, (await crlFor(f, r3.number, r3.thisUpdate, [])).der), "state_conflict", "crl_missing_revocation");
    assert.equal(f.store.state.crl.current!.number, 2);
    // A2: a number that was never reserved.
    await code(f.store.commitCrl(9, (await crlFor(f, 9, new Date(r3.thisUpdate.getTime()))).der), "state_conflict", "crl_not_reserved");
    // The right one still works afterwards.
    await f.store.commitCrl(r3.number, (await crlFor(f, r3.number, r3.thisUpdate)).der);
    assert.equal(f.store.state.crl.current!.number, 3);
    assert.deepEqual(f.store.state.revoked.map((r) => r.listedInCrl), [2]);
    await f.store.close();
    await (await EzStore.open(f.options)).close();
  } finally {
    await done(f);
  }
});

test("commitCrl: a burned number committed later cannot regress the current CRL (p2 B)", async () => {
  const f = await fixture("burned");
  try {
    tick();
    const r2 = (await f.store.begin({ crl: true })).crl!;
    const late2 = await crlFor(f, r2.number, r2.thisUpdate);
    await f.store.close();
    const s = await EzStore.open(f.options); // burns 2
    tick();
    const r3 = (await s.begin({ crl: true })).crl!;
    f.store = s;
    await s.commitCrl(r3.number, (await crlFor(f, r3.number, r3.thisUpdate)).der);
    await code(s.commitCrl(2, late2.der), "state_conflict", "crl_not_reserved");
    assert.equal(s.state.crl.current!.number, 3);
    await s.close();
    await (await EzStore.open(f.options)).close();
  } finally {
    await done(f);
  }
});

test("commitCrl: thisUpdate must be the reserved one, and a refusal leaves the directory openable (p2 C)", async () => {
  const f = await fixture("thisupdate");
  try {
    tick();
    const r = (await f.store.begin({ crl: true })).crl!;
    const shifted = await crlFor(f, r.number, new Date(r.thisUpdate.getTime() + 5000), []);
    await code(f.store.commitCrl(r.number, shifted.der), "state_conflict", "crl_this_update");
    await f.store.close();
    const s = await EzStore.open(f.options); // burns the number; no brick
    assert.equal(s.state.crl.current!.number, 1);
    await s.close();
  } finally {
    await done(f);
  }
});

test("recovery refuses a rolled-forward CRL that omits a revocation, and open detects a current CRL missing a listed revocation", async () => {
  let armed = false;
  const f = await fixture("recover", { fault: (s) => { if (armed && s === "commitCrl:file") throw new Error("crash"); } });
  try {
    await f.store.addRevocation({ serial: "01aa", caId: null, reason: "superseded" });
    tick();
    const r = (await f.store.begin({ crl: true })).crl!;
    armed = true;
    await assert.rejects(f.store.commitCrl(r.number, (await crlFor(f, r.number, r.thisUpdate)).der), /crash/);
    armed = false;
    await f.store.close();
    // Swap the leftover file for a CRL without the revocation: recovery must not adopt it.
    const file = join(f.dir, "crls/000002.crl.pem");
    const bad = await crlFor(f, 2, r.thisUpdate, []);
    await fs.writeFile(file, bad.pem);
    await code(EzStore.open(f.options), "state_conflict", "crl_missing_revocation");
    await fs.rm(file);
    const s = await EzStore.open(f.options);
    assert.equal(s.state.crl.current!.number, 1);
    // Now mark the revocation as listed in a CRL that does not carry it: open detects it.
    await s.close();
    const raw = JSON.parse(await fs.readFile(join(f.dir, "hemlig-ez.json"), "utf8")) as EzState;
    raw.revoked[0]!.listedInCrl = 1;
    await fs.writeFile(join(f.dir, "hemlig-ez.json"), JSON.stringify(raw));
    await code(EzStore.open(f.options), "state_conflict", "crl_missing_revocation");
  } finally {
    await done(f);
  }
});

// -- 3, 8b: serials -----------------------------------------------------------------------------------------------------

test("serials are canonicalized: odd length and leading zeros dedupe (p4)", async () => {
  const f = await fixture("serial");
  try {
    assert.deepEqual(await f.store.addRevocation({ serial: "1aa", caId: null, reason: "keyCompromise" }), { added: true });
    assert.deepEqual(await f.store.addRevocation({ serial: "01aa", caId: null, reason: "keyCompromise" }), { added: false });
    assert.deepEqual(await f.store.addRevocation({ serial: "0001AA", caId: null, reason: "keyCompromise" }), { added: false });
    assert.deepEqual(f.store.state.revoked.map((r) => r.serial), ["01aa"]);
    for (const bad of ["", "0", "00", "xyz", "0x1"]) {
      await code(f.store.addRevocation({ serial: bad, caId: null, reason: "keyCompromise" }), "invalid_input");
    }
    tick();
    const r = (await f.store.begin({ crl: true })).crl!;
    await f.store.commitCrl(r.number, (await crlFor(f, r.number, r.thisUpdate)).der);
    assert.equal(parseCrl(fromPem(await fs.readFile(join(f.dir, "root.crl.pem"), "utf8"), "X509 CRL")).entries.length, 1);
  } finally {
    await done(f);
  }
});

test("begin refuses a serial that any entry (even abandoned) or a revocation already uses (p2 D)", async () => {
  const f = await fixture("reuse");
  try {
    await f.store.begin({ sign: reserve("01aa", "ca-1").sign });
    await f.store.abandon("01aa");
    await code(f.store.begin({ sign: reserve("01aa", "ca-2").sign }), "state_conflict", "serial_reused");
    await code(f.store.begin({ sign: reserve("1aa", "ca-2").sign }), "state_conflict", "serial_reused");
    await f.store.addRevocation({ serial: "02bb", caId: null, reason: "superseded" });
    await code(f.store.begin({ sign: reserve("02bb", "ca-2").sign }), "state_conflict", "serial_reused");
    await f.store.close();
    await (await EzStore.open(f.options)).close();
  } finally {
    await done(f);
  }
});

test("begin refuses a live certificate with the same subject and a different key, unless that one is revoked", async () => {
  const f = await fixture("subject");
  try {
    const a = reserve("01aa", "ca-1");
    await f.store.begin({ sign: a.sign });
    const [issued] = await signPrepared(f.signer, [prepareIntermediate(f.signer, f.store.rootCertificate, a.csr, { now: clock, serial: Buffer.from([1, 0xaa]) })] as const);
    await f.store.commitSigned("01aa", issued.der);
    const b = reserve("02bb", "ca-2");
    await code(f.store.begin({ sign: { ...b.sign, subjectDn: a.sign.subjectDn } }), "issued_conflict");
    await f.store.addRevocation({ serial: "01aa", caId: "ca-1", reason: "superseded" });
    await f.store.begin({ sign: { ...b.sign, subjectDn: a.sign.subjectDn } });
  } finally {
    await done(f);
  }
});

// -- 5: create ---------------------------------------------------------------------------------------------------------

test("create under another state-file name lists the existing files and advises nothing destructive (p2 G)", async () => {
  const f = await fixture("create");
  try {
    await f.store.close();
    await assert.rejects(
      EzStore.create({ ...f.options, stateFile: "second.json" }, f.state, initialArtifacts(f.state, { rootDer: f.rootDer, crlDer: f.crlDer, keyFilePem: "OTHER" })),
      (e) => e instanceof EzError && e.code === "already_exists" && /root\.key\.pem/.test(e.message) && !/delete|remove/i.test(e.message) && (e.details as { files: string[] }).files.length >= 3,
    );
    assert.equal(await fs.readFile(join(f.dir, "root.key.pem"), "utf8"), "KEYFILE");
    assert.equal((await fs.readdir(f.dir)).includes("second.json"), false);
    assert.equal((await fs.readdir(f.dir)).includes(LOCK_FILE), false);
  } finally {
    await done(f);
  }
});

// -- 7: hard crash ----------------------------------------------------------------------------------------------------

const crashChild = (f: F, csrDer: Buffer, crashStep: string): void => {
  const script = `
    const { EzStore } = require(${JSON.stringify(join(__dirname, "ez-state.js"))});
    const { validateCsr } = require(${JSON.stringify(join(__dirname, "ez-x509.js"))});
    const { prepareIntermediate, signPrepared } = require(${JSON.stringify(join(__dirname, "ez-issue.js"))});
    const { SoftwareSigner } = require(${JSON.stringify(join(__dirname, "ez-signer.js"))});
    const { createPrivateKey } = require("node:crypto");
    (async () => {
      const at = new Date(${JSON.stringify(clock.toISOString())});
      let armed = false;
      const store = await EzStore.open({ dir: ${JSON.stringify(f.dir)}, command: "child", hostname: "h1", now: () => at,
        fault: (s) => { if (armed && s === ${JSON.stringify(crashStep)}) process.exit(137); } });
      const c = validateCsr(Buffer.from(${JSON.stringify(csrDer.toString("base64"))}, "base64"));
      const signer = new SoftwareSigner(createPrivateKey(process.env.EZ_KEY));
      await store.begin({ sign: { serial: "01aa", caId: "ca-1", environment: null, adminOrigin: null, subjectDn: "CN=ca-1",
        csrSha256: c.sha256, spkiSha256: c.spkiSha256, notBefore: at, notAfter: new Date(at.getTime() + 400 * 86400000) } });
      const [issued] = await signPrepared(signer, [prepareIntermediate(signer, store.rootCertificate, c, { now: at, serial: Buffer.from([1, 0xaa]) })]);
      armed = true;
      await store.commitSigned("01aa", issued.der);
      process.exit(0);
    })().catch((e) => { console.error(e); process.exit(1); });`;
  const result = spawnSync(process.execPath, ["-e", script], {
    env: { ...process.env, EZ_KEY: f.privateKey.export({ type: "pkcs8", format: "pem" }) as string },
    encoding: "utf8",
  });
  assert.equal(result.status, 137, result.stderr);
};

test("a hard crash (process exit, no finally) between the temp write and the link rolls the signed certificate forward (p3 E)", async () => {
  const f = await fixture("hardcrash");
  try {
    await f.store.close();
    crashChild(f, makeTestCsr().der, "immutable:temp-written");
    const temps = (await fs.readdir(join(f.dir, "issued"))).filter((n) => n.endsWith(".tmp"));
    assert.equal(temps.length, 1, "the crash left the signed certificate as a temp file");
    assert.equal((JSON.parse(await fs.readFile(join(f.dir, "hemlig-ez.json"), "utf8")) as EzState).issued[0]!.status, "signing");
    await fs.unlink(join(f.dir, LOCK_FILE)); // the dead process's lock
    const s = await EzStore.open(f.options);
    assert.equal(s.state.issued[0]!.status, "signed");
    assert.deepEqual(await fs.readdir(join(f.dir, "issued")), ["01aa.pem"], "temp swept, final in place");
    assert.equal(s.state.pending, null);
    await s.close();
  } finally {
    await done(f);
  }
});

test("a hard crash after a partial or foreign temp file: the entry is abandoned and every stale temp is swept", async () => {
  const f = await fixture("sweep");
  try {
    await f.store.begin({ sign: reserve("01aa", "ca-1").sign });
    await f.store.close();
    await fs.writeFile(join(f.dir, "issued", ".01aa.pem.0123456789ab.tmp"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    await fs.writeFile(join(f.dir, "crls", ".000002.crl.pem.0123456789ab.tmp"), "x");
    await fs.writeFile(join(f.dir, ".hemlig-ez.json.0123456789ab.tmp"), "x");
    const s = await EzStore.open(f.options);
    assert.equal(s.state.issued[0]!.status, "abandoned");
    assert.deepEqual(await fs.readdir(join(f.dir, "issued")), []);
    assert.deepEqual(await fs.readdir(join(f.dir, "crls")), ["000001.crl.pem"]);
    assert.equal((await fs.readdir(f.dir)).filter((n) => n.endsWith(".tmp")).length, 0);
    await s.close();
  } finally {
    await done(f);
  }
});

// -- 8: low items -----------------------------------------------------------------------------------------------------

test("encryptPkcs8 zeroes the plaintext even when the passphrase policy refuses (p3 L)", () => {
  const pkcs8 = generateSoftwareKey("ECDSA_P256").exportPkcs8();
  assert.throws(() => encryptPkcs8(pkcs8, "short"), EzError);
  assert.ok(pkcs8.every((b) => b === 0));
});

test("the strict schema ignores keys inherited from Object.prototype (p2 H)", async () => {
  const f = await fixture("proto");
  try {
    await f.store.close();
    const raw = JSON.parse(await fs.readFile(join(f.dir, "hemlig-ez.json"), "utf8")) as Record<string, unknown>;
    for (const key of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
      await fs.writeFile(join(f.dir, "hemlig-ez.json"), JSON.stringify(raw).replace(/^\{/, `{${JSON.stringify(key)}:1,`));
      await code(EzStore.open(f.options), "state_corrupt");
    }
  } finally {
    await done(f);
  }
});

test("compareWithServer: malformed numbers are invalid_response; a server CRL revoking unknown serials is behind; an older server CRL must match our file (p2 I)", async () => {
  const f = await fixture("server");
  try {
    tick();
    for (let i = 0; i < 2; i++) {
      const r = (await f.store.begin({ crl: true })).crl!;
      await f.store.commitCrl(r.number, (await crlFor(f, r.number, r.thisUpdate)).der);
      tick();
    }
    const s = f.store.state;
    const sync = (server: Parameters<typeof compareWithServer>[1]) => { try { compareWithServer(s, server); return "ok"; } catch (e) { return (e as EzError).code; } };
    assert.equal(sync({ crl: { numberHex: "", sha256: "a".repeat(64) } }), "invalid_response");
    assert.equal(sync({ crl: { numberHex: "zz", sha256: "a".repeat(64) } }), "invalid_response");
    assert.equal(sync({ crl: { numberHex: "3", sha256: "xyz" } }), "invalid_response");
    assert.equal(sync({ crl: { numberHex: "1".repeat(41), sha256: "a".repeat(64) } }), "invalid_response");
    assert.equal(sync({ crl: { numberHex: "3", sha256: s.crl.current!.sha256.toUpperCase(), serials: [] } }), "ok");
    assert.equal(sync({ crl: { numberHex: "3", sha256: s.crl.current!.sha256, serials: ["0ff"] } }), "state_behind_server");
    // Older server CRL: its hash must be the one we signed under that number.
    const first = fromPem(await fs.readFile(join(f.dir, "crls/000001.crl.pem"), "utf8"), "X509 CRL");
    const firstSha = (await import("node:crypto")).createHash("sha256").update(first).digest("hex");
    await f.store.checkServer({ crl: { numberHex: "1", sha256: firstSha } });
    await code(f.store.checkServer({ crl: { numberHex: "1", sha256: "b".repeat(64) } }), "state_forked");
    await code(f.store.checkServer({ crl: { numberHex: "2", sha256: "b".repeat(64) } }), "state_forked");
  } finally {
    await done(f);
  }
});

test("stale-lock breaking is serialized: two breakers cannot both win, and a replaced holder is never stolen", async () => {
  const dir = await fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-lockrace-"));
  try {
    const dead = await acquireLock(dir, { command: "old", hostname: "h1", pid: 424242 });
    void dead;
    const attempts = await Promise.allSettled(
      Array.from({ length: 6 }, (_, i) => acquireLock(dir, { command: `breaker-${i}`, hostname: "h1", breakStale: true, isAlive: (pid) => pid !== 424242 })),
    );
    const winners = attempts.filter((a) => a.status === "fulfilled");
    assert.equal(winners.length, 1, "exactly one breaker holds the lock");
    for (const a of attempts) {
      if (a.status === "rejected") assert.ok(a.reason instanceof EzError && a.reason.code === "state_locked");
    }
    assert.deepEqual((await fs.readdir(dir)).sort(), [LOCK_FILE]);
    // The winner is live; a later breaker must not steal it.
    await assert.rejects(acquireLock(dir, { command: "late", hostname: "h1", breakStale: true, isAlive: () => true }), (e) => e instanceof EzError && e.code === "state_locked");
    await (winners[0] as PromiseFulfilledResult<{ release(): Promise<void> }>).value.release();
    assert.deepEqual(await fs.readdir(dir), []);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// -- 6: tty reuse -------------------------------------------------------------------------------------------------------

const options = { maxBytes: 64, cancelled: () => new Error("cancelled"), tooLarge: () => new Error("large") };
const stream = (tty: boolean): PassThrough & TerminalInput => {
  const s = new PassThrough() as PassThrough & { isTTY?: boolean; setRawMode?: (m: boolean) => unknown };
  if (tty) {
    s.isTTY = true;
    s.setRawMode = () => s;
  }
  return s as PassThrough & TerminalInput;
};

for (const tty of [true, false]) {
  test(`readTerminalLine twice on one real stream (${tty ? "terminal" : "pipe"}): not destroyed, no bytes lost (p3 M)`, async () => {
    const s = stream(tty);
    const end = tty ? "\r" : "\n";
    s.write(`first${end}second${end}third`);
    assert.equal((await readTerminalLine(s, options)).toString(), "first");
    assert.equal((s as PassThrough).destroyed, false);
    assert.equal((await readTerminalLine(s, options)).toString(), "second");
    // later bytes arrive separately
    setTimeout(() => s.write(`${end}`), 10);
    assert.equal((await readTerminalLine(s, options)).toString(), "third");
  });

  test(`readTerminalLine reads a line that arrives after the first read (${tty ? "terminal" : "pipe"})`, async () => {
    const s = stream(tty);
    const end = tty ? "\r" : "\n";
    setTimeout(() => s.write(`one${end}`), 5);
    assert.equal((await readTerminalLine(s, options)).toString(), "one");
    setTimeout(() => s.write(`two${end}`), 5);
    assert.equal((await readTerminalLine(s, options)).toString(), "two");
    assert.equal((s as PassThrough).destroyed, false);
  });
}

test("readTerminalLine: CRLF is one line break", async () => {
  const s = stream(false);
  s.write("a\r\nb\r\n");
  assert.equal((await readTerminalLine(s, options)).toString(), "a");
  assert.equal((await readTerminalLine(s, options)).toString(), "b");
});
