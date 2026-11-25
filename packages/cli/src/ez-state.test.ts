import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EzError } from "./ez-error";
import { acquireLock, createImmutable, writeAtomic, LOCK_FILE } from "./ez-fs";
import { prepareCrl, prepareIntermediate, prepareRoot, signPrepared } from "./ez-issue";
import { encodeSubject, formatSubject } from "./ez-name";
import { SoftwareSigner, generateSoftwareKey } from "./ez-signer";
import {
  EzStore, compareWithServer, initialArtifacts, initialState, resolveRecordedPath, type EzState, type StoreOptions,
} from "./ez-state";
import { makeTestCsr } from "./ez-testkit";
import { toPem, validateCsr } from "./ez-x509";

const day = 86_400_000;
let clock = new Date("2026-11-25T12:00:00Z");
const now = () => clock;
const subject = { O: "Example Corp", CN: "Example EZ Root CA 1" };

const tempDir = async (): Promise<string> => fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-state-"));
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

interface Fixture {
  dir: string;
  signer: SoftwareSigner;
  options: StoreOptions;
  store: EzStore;
}

const fixture = async (extra: Partial<StoreOptions> = {}): Promise<Fixture> => {
  clock = new Date("2026-11-25T12:00:00Z");
  const dir = await tempDir();
  const key = generateSoftwareKey("ECDSA_P256");
  const signer = new SoftwareSigner(key.privateKey);
  const [root] = await signPrepared(signer, [prepareRoot(signer, { subject, now: clock })] as const);
  const [crl] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: clock, entries: [] })] as const);
  const state = initialState({
    origin: "generated", subject, subjectDn: formatSubject(subject), root: root.certificate, keyAlgorithm: "ECDSA_P256",
    key: { storage: "software", file: "root.key.pem", kdf: { name: "pbkdf2-hmac-sha256", iterations: 1_000_000 }, yubikey: null },
    crl: crl.crl, now: clock,
  });
  const options: StoreOptions = { dir, command: "test", now, hostname: "h1", ...extra };
  const store = await EzStore.create(options, state, initialArtifacts(state, { rootDer: root.der, crlDer: crl.der, keyFilePem: "KEYFILE" }));
  return { dir, signer, options, store };
};

const cleanup = (f: Fixture) => fs.rm(f.dir, { recursive: true, force: true });
const readState = async (dir: string): Promise<EzState> => JSON.parse(await fs.readFile(join(dir, "hemlig-ez.json"), "utf8"));
const writeState = (dir: string, state: unknown) => fs.writeFile(join(dir, "hemlig-ez.json"), JSON.stringify(state));
const rejects = (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e) => e instanceof EzError && e.code === code, `expected ${code}`);

const reservation = (f: Fixture, csrDer: Buffer, caId: string | null = "ca-1", serial = "01aa") => {
  const csr = validateCsr(csrDer);
  return { csr, sign: {
    serial, caId, environment: "prod", adminOrigin: "https://admin.example.com", subjectDn: `CN=${caId ?? "none"}`, subjectKey: createHash("sha256").update(caId ?? "none").digest("hex"), csrSha256: csr.sha256,
    spkiSha256: csr.spkiSha256, notBefore: new Date(clock.getTime() - 3_600_000), notAfter: new Date(clock.getTime() + 730 * day),
  } };
};

/** One full sign cycle through the store. */
const signIntermediate = async (f: Fixture, csrDer: Buffer, serial = "01aa", caId: string | null = "ca-1") => {
  const { csr, sign } = reservation(f, csrDer, caId, serial);
  const began = await f.store.begin({ sign });
  if (began.resumed) return { entry: began.resumed, resumed: true };
  const [issued] = await signPrepared(f.signer, [prepareIntermediate(f.signer, f.store.rootCertificate, csr, { now: clock, serial: Buffer.from(serial.length % 2 ? `0${serial}` : serial, "hex") })] as const);
  return { entry: await f.store.commitSigned(serial, issued.der), resumed: false, issued };
};

const signCrl = async (f: Fixture, number: number, thisUpdate: Date) => {
  const [crl] = await signPrepared(f.signer, [prepareCrl(f.signer, f.store.rootCertificate, { number, thisUpdate, entries: f.store.revocationEntries() })] as const);
  return crl;
};

// -- files and locks -----------------------------------------------------------------------------------------------

test("create: files, modes, no temp leftovers; reopen loads the same state", async () => {
  const f = await fixture();
  try {
    const names = (await fs.readdir(f.dir)).sort();
    assert.deepEqual(names, [".hemlig-ez.lock", "crls", "hemlig-ez.json", "issued", "root.crl.pem", "root.key.pem", "root.pem"]);
    assert.deepEqual(await fs.readdir(join(f.dir, "crls")), ["000001.crl.pem"]);
    assert.equal((await fs.stat(join(f.dir, "hemlig-ez.json"))).mode & 0o777, 0o600);
    assert.equal((await fs.stat(join(f.dir, "root.key.pem"))).mode & 0o777, 0o600);
    assert.equal(f.store.state.revision, 1);
    await f.store.close();
    assert.equal((await fs.readdir(f.dir)).includes(LOCK_FILE), false);
    const again = await EzStore.open(f.options);
    assert.equal(again.state.root.fingerprint, f.store.state.root.fingerprint);
    await again.close();
  } finally {
    await cleanup(f);
  }
});

test("create never overwrites: any existing target is already_exists and is listed", async () => {
  const f = await fixture();
  try {
    await f.store.close();
    const state = await readState(f.dir);
    const { revision: _r, updatedAt: _u, format: _f, version: _v, ...initial } = state;
    await rejects(EzStore.create(f.options, initial, []), "already_exists");
    await fs.rm(join(f.dir, "hemlig-ez.json"));
    await assert.rejects(
      EzStore.create(f.options, initial, [{ path: "root.pem", data: Buffer.from("x") }]),
      (e) => e instanceof EzError && e.code === "already_exists" && /root\.pem/.test(e.message) && !/delete/i.test(e.message),
    );
    assert.equal(await fs.readFile(join(f.dir, "root.pem"), "utf8").then((t) => t.startsWith("-----BEGIN CERTIFICATE")), true, "nothing overwritten");
  } finally {
    await cleanup(f);
  }
});

test("createImmutable is no-clobber, including the no-hard-link fallback", async () => {
  const dir = await tempDir();
  try {
    const path = join(dir, "a.pem");
    await createImmutable(path, Buffer.from("one"));
    await rejects(createImmutable(path, Buffer.from("two")), "already_exists");
    assert.equal(await fs.readFile(path, "utf8"), "one");
    const original = fs.link;
    (fs as { link: unknown }).link = async () => { throw Object.assign(new Error("no links"), { code: "EPERM" }); };
    try {
      const other = join(dir, "b.pem");
      await createImmutable(other, Buffer.from("three"));
      await rejects(createImmutable(other, Buffer.from("four")), "already_exists");
      assert.equal(await fs.readFile(other, "utf8"), "three");
    } finally {
      (fs as { link: unknown }).link = original;
    }
    assert.deepEqual((await fs.readdir(dir)).sort(), ["a.pem", "b.pem"]);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("writeAtomic: a crash before the rename leaves the old content and no temp file", async () => {
  const dir = await tempDir();
  try {
    const path = join(dir, "s.json");
    await writeAtomic(path, Buffer.from("old"));
    await assert.rejects(writeAtomic(path, Buffer.from("new"), 0o600, { fault: (s) => { if (s === "atomic:temp-written") throw new Error("crash"); } }), /crash/);
    assert.equal(await fs.readFile(path, "utf8"), "old");
    assert.deepEqual(await fs.readdir(dir), ["s.json"]);
    await writeAtomic(path, Buffer.from("new"));
    assert.equal(await fs.readFile(path, "utf8"), "new");
    assert.deepEqual(await fs.readdir(dir), ["s.json"]);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("lock: contention reports the holder; release is nonce-checked; stale locks break only on this host with a dead pid", async () => {
  const dir = await tempDir();
  try {
    const a = await acquireLock(dir, { command: "sign-cert", hostname: "h1", pid: 111 });
    await assert.rejects(acquireLock(dir, { command: "renew-crl", hostname: "h1" }), (e) => {
      return e instanceof EzError && e.code === "state_locked" && (e.details as { holder: { command: string; pid: number } }).holder.command === "sign-cert";
    });
    // alive holder: not broken even with the flag
    await rejects(acquireLock(dir, { command: "x", hostname: "h1", breakStale: true, isAlive: () => true }), "state_locked");
    // other host: not broken
    await rejects(acquireLock(dir, { command: "x", hostname: "h2", breakStale: true, isAlive: () => false }), "state_locked");
    // dead pid on this host without the flag: still locked
    await rejects(acquireLock(dir, { command: "x", hostname: "h1", isAlive: () => false }), "state_locked");
    const b = await acquireLock(dir, { command: "x", hostname: "h1", breakStale: true, isAlive: () => false });
    // the old holder releasing must not delete the new holder's lock
    await a.release();
    await rejects(acquireLock(dir, { command: "y", hostname: "h1" }), "state_locked");
    await b.release();
    assert.deepEqual(await fs.readdir(dir), []);
    (await acquireLock(dir, { command: "z", hostname: "h1" })).release();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a second open while the first holds the lock is state_locked", async () => {
  const f = await fixture();
  try {
    await rejects(EzStore.open(f.options), "state_locked");
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

// -- sign flow and the CRL state machine -----------------------------------------------------------------------------

test("sign flow: reserve, commit, activate; the certificate verifies under the root", async () => {
  const f = await fixture();
  try {
    const csr = makeTestCsr();
    const { entry } = await signIntermediate(f, csr.der);
    assert.equal(entry.status, "signed");
    assert.equal(f.store.state.pending, null);
    assert.equal(f.store.state.issued.length, 1);
    const der = await f.store.readIssuedCertificate(entry);
    assert.equal(sha(der!), entry.fingerprint);
    await f.store.markActivated("01aa");
    assert.equal(f.store.state.issued[0]!.status, "activated");
    assert.ok(f.store.state.issued[0]!.activatedAt);
    // the same CSR again resumes; nothing new is reserved or signed
    const again = await signIntermediate(f, csr.der, "02bb");
    assert.equal(again.resumed, true);
    assert.equal(f.store.state.issued.length, 1);
    // a different CSR for the same CA is a conflict
    await rejects(f.store.begin({ sign: reservation(f, makeTestCsr().der, "ca-1", "03cc").sign }), "issued_conflict");
    // a reused serial is refused
    await rejects(f.store.begin({ sign: reservation(f, makeTestCsr().der, "ca-2", "01aa").sign }), "state_conflict");
    // a commit must be the certificate that was reserved
    const other = reservation(f, makeTestCsr().der, "ca-3", "04dd");
    await f.store.begin({ sign: other.sign });
    const [wrong] = await signPrepared(f.signer, [prepareIntermediate(f.signer, f.store.rootCertificate, validateCsr(makeTestCsr().der), { now: clock })] as const);
    await rejects(f.store.commitSigned("04dd", wrong.der), "state_conflict");
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

test("CRL numbers are strictly monotonic and thisUpdate strictly increases even with a frozen clock", async () => {
  const f = await fixture();
  try {
    const seen: [number, string][] = [];
    for (let i = 0; i < 4; i++) {
      const { crl } = await f.store.begin({ crl: true });
      seen.push([crl!.number, crl!.thisUpdate.toISOString()]);
      await f.store.commitCrl(crl!.number, (await signCrl(f, crl!.number, crl!.thisUpdate)).der);
    }
    assert.deepEqual(seen.map((s) => s[0]), [2, 3, 4, 5]);
    for (let i = 1; i < seen.length; i++) assert.ok(seen[i]![1] > seen[i - 1]![1]);
    assert.equal(f.store.state.crl.current!.number, 5);
    assert.equal(f.store.state.crl.lastNumber, 5);
    assert.deepEqual((await fs.readdir(join(f.dir, "crls"))).sort(), ["000001.crl.pem", "000002.crl.pem", "000003.crl.pem", "000004.crl.pem", "000005.crl.pem"]);
    assert.equal(await fs.readFile(join(f.dir, "root.crl.pem"), "utf8"), await fs.readFile(join(f.dir, "crls/000005.crl.pem"), "utf8"));
    assert.equal(f.store.crlDue(45, clock), false);
    assert.equal(f.store.crlDue(45, new Date(clock.getTime() + 140 * day)), true);
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

test("clock guards: an old clock cannot sign (I6, I7)", async () => {
  const f = await fixture();
  try {
    const { crl } = await f.store.begin({ crl: true });
    await f.store.commitCrl(crl!.number, (await signCrl(f, crl!.number, crl!.thisUpdate)).der);
    clock = new Date(clock.getTime() - 3600_000);
    await rejects(f.store.begin({ crl: true }), "clock_regressed");
    clock = new Date(clock.getTime() + 3600_000 + 1000);
    await f.store.begin({ crl: true });
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

test("revocations: idempotent, grow only, reason rules, and CRL entries must be on the list", async () => {
  const f = await fixture();
  try {
    assert.deepEqual(await f.store.addRevocation({ serial: "01aa", caId: "ca-1", reason: "keyCompromise" }), { added: true });
    assert.deepEqual(await f.store.addRevocation({ serial: "00" + "01aa", caId: "ca-1", reason: "superseded" }), { added: false });
    await assert.rejects(f.store.addRevocation({ serial: "02", caId: null, reason: "certificateHold" }), (e) => e instanceof EzError && e.code === "invalid_input");
    await assert.rejects(f.store.addRevocation({ serial: "02", caId: null, reason: "keyCompromise", invalidityDate: new Date(clock.getTime() + day) }), EzError);
    assert.equal(f.store.state.revoked.length, 1);
    const { crl } = await f.store.begin({ crl: true });
    const good = await signCrl(f, crl!.number, crl!.thisUpdate);
    assert.deepEqual(good.crl.entries.map((e) => [e.serial, e.reason]), [["01aa", "keyCompromise"]]);
    // a CRL that lists a serial the state does not know about is refused
    const [rogue] = await signPrepared(f.signer, [prepareCrl(f.signer, f.store.rootCertificate, { number: crl!.number, thisUpdate: crl!.thisUpdate, entries: [{ serial: "99", revokedAt: clock }] })] as const);
    await rejects(f.store.commitCrl(crl!.number, rogue.der), "state_conflict");
    await f.store.commitCrl(crl!.number, good.der);
    assert.equal(f.store.state.crl.current!.number, crl!.number);
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

// -- crash recovery (every row of section 6.4) -------------------------------------------------------------------------

const crashAt = async (step: string, run: (f: Fixture) => Promise<void>): Promise<Fixture> => {
  let armed = false;
  const f = await fixture({ fault: (s) => { if (armed && s === step) throw new Error(`crash at ${s}`); } });
  armed = true;
  await assert.rejects(run(f), new RegExp(`crash at ${step}`));
  armed = false;
  await f.store.close(); // the process died: its lock goes away
  return f;
};

test("crash: sign, after the journal entry and before the certificate -> abandoned on the next run", async () => {
  const csr = makeTestCsr();
  const f = await crashAt("begin:persisted", async (f) => void (await f.store.begin({ sign: reservation(f, csr.der).sign })));
  try {
    assert.equal((await readState(f.dir)).issued[0]!.status, "signing");
    const store = await EzStore.open(f.options);
    assert.equal(store.state.issued[0]!.status, "abandoned");
    assert.equal(store.state.pending, null);
    // the same CSR can be signed again afterwards, with a new serial
    const f2 = { ...f, store };
    const again = await signIntermediate(f2, csr.der, "01bb");
    assert.equal(again.entry.status, "signed");
    await store.close();
  } finally {
    await cleanup(f);
  }
});

test("crash: sign, after the certificate file and before the state update -> rolled forward to signed", async () => {
  const csr = makeTestCsr();
  const f = await crashAt("commitSigned:file", async (f) => void (await signIntermediate(f, csr.der)));
  try {
    assert.equal((await readState(f.dir)).issued[0]!.status, "signing");
    assert.ok((await fs.readdir(join(f.dir, "issued"))).includes("01aa.pem"));
    const store = await EzStore.open(f.options);
    assert.equal(store.state.issued[0]!.status, "signed");
    assert.equal(store.state.issued[0]!.fingerprint, sha(fromFile(await fs.readFile(join(f.dir, "issued/01aa.pem"), "utf8"))));
    assert.equal(store.state.pending, null);
    // rerun reuses the signed certificate instead of signing twice
    const again = await signIntermediate({ ...f, store }, csr.der, "02bb");
    assert.equal(again.resumed, true);
    await store.close();
  } finally {
    await cleanup(f);
  }
});

const fromFile = (pem: string): Buffer => Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");

test("crash: sign, a state write that never renamed -> the old state stands and no temp file remains", async () => {
  const csr = makeTestCsr();
  const f = await crashAt("atomic:temp-written", async (f) => void (await f.store.begin({ sign: reservation(f, csr.der).sign })));
  try {
    const state = await readState(f.dir);
    assert.equal(state.issued.length, 0);
    assert.equal(state.revision, 1);
    assert.equal((await fs.readdir(f.dir)).filter((n) => n.endsWith(".tmp")).length, 0);
    await (await EzStore.open(f.options)).close();
  } finally {
    await cleanup(f);
  }
});

test("crash: CRL, after allocating N and before the file -> N is burned, the next CRL is N+1", async () => {
  const f = await crashAt("begin:persisted", async (f) => void (await f.store.begin({ crl: true })));
  try {
    const store = await EzStore.open(f.options);
    assert.equal(store.state.crl.lastNumber, 2);
    assert.equal(store.state.crl.current!.number, 1);
    assert.equal(store.state.pending, null);
    const { crl } = await store.begin({ crl: true });
    assert.equal(crl!.number, 3);
    await store.close();
  } finally {
    await cleanup(f);
  }
});

for (const step of ["commitCrl:file", "commitCrl:copy"]) {
  test(`crash: CRL at ${step} -> the verified CRL is adopted and the copy healed`, async () => {
    const f = await crashAt(step, async (f) => {
      const { crl } = await f.store.begin({ crl: true });
      await f.store.commitCrl(crl!.number, (await signCrl(f, crl!.number, crl!.thisUpdate)).der);
    });
    try {
      const store = await EzStore.open(f.options);
      assert.equal(store.state.crl.current!.number, 2);
      assert.equal(store.state.pending, null);
      assert.equal(await fs.readFile(join(f.dir, "root.crl.pem"), "utf8"), await fs.readFile(join(f.dir, "crls/000002.crl.pem"), "utf8"));
      await store.close();
    } finally {
      await cleanup(f);
    }
  });
}

test("crash: combined sign and CRL batch recovers both halves independently", async () => {
  const csr = makeTestCsr();
  const f = await crashAt("commitSigned:file", async (f) => {
    const { sign } = reservation(f, csr.der);
    const { crl } = await f.store.begin({ sign, crl: true });
    const [issued] = await signPrepared(f.signer, [prepareIntermediate(f.signer, f.store.rootCertificate, validateCsr(csr.der), { now: clock, serial: Buffer.from([1, 0xaa]) })] as const);
    await f.store.commitSigned("01aa", issued.der); // crashes writing the certificate state
    void crl;
  });
  try {
    const store = await EzStore.open(f.options);
    assert.equal(store.state.issued[0]!.status, "signed");
    assert.equal(store.state.pending, null);
    assert.equal(store.state.crl.lastNumber, 2, "the CRL number stays burned");
    assert.equal(store.state.crl.current!.number, 1);
    await store.close();
  } finally {
    await cleanup(f);
  }
});

// -- invariants ----------------------------------------------------------------------------------------------------------

const expectConflict = async (f: Fixture, reason: string) => {
  await assert.rejects(EzStore.open(f.options), (e) => e instanceof EzError && e.code === "state_conflict" && (e.details as { reason: string }).reason === reason, `expected ${reason}`);
  assert.equal((await fs.readdir(f.dir)).includes(LOCK_FILE), false, "lock released after a failed open");
};

test("invariants: rollback, forked or tampered files, shrunk revocations", async () => {
  const f = await fixture();
  try {
    await f.store.addRevocation({ serial: "01aa", caId: null, reason: "keyCompromise" });
    const { crl } = await f.store.begin({ crl: true });
    await f.store.commitCrl(crl!.number, (await signCrl(f, crl!.number, crl!.thisUpdate)).der);
    await f.store.close();
    const good = await readState(f.dir);

    await writeState(f.dir, { ...good, crl: { ...good.crl, lastNumber: 1 } });
    await expectConflict(f, "crl_number_rollback");

    await writeState(f.dir, { ...good, revoked: [] });
    await expectConflict(f, "revoked_shrunk");

    await writeState(f.dir, { ...good, crl: { ...good.crl, current: { ...good.crl.current!, sha256: "0".repeat(64) } } });
    await expectConflict(f, "crl_tampered");

    await writeState(f.dir, good);
    const root = await fs.readFile(join(f.dir, "root.pem"));
    const text = root.toString();
    await fs.writeFile(join(f.dir, "root.pem"), `${text.slice(0, 100)}${text[100] === "A" ? "B" : "A"}${text.slice(101)}`);
    await expectConflict(f, "root_tampered");
    await fs.writeFile(join(f.dir, "root.pem"), root);

    const crlFile = join(f.dir, "crls/000002.crl.pem");
    const original = await fs.readFile(crlFile);
    await fs.rm(crlFile);
    await expectConflict(f, "crl_missing");
    await fs.writeFile(crlFile, original);

    await (await EzStore.open(f.options)).close();
  } finally {
    await cleanup(f);
  }
});

test("invariants: a missing or altered issued certificate is a conflict", async () => {
  const f = await fixture();
  try {
    await signIntermediate(f, makeTestCsr().der);
    await f.store.close();
    const file = join(f.dir, "issued/01aa.pem");
    const original = await fs.readFile(file);
    await fs.writeFile(file, toPem(Buffer.from("not the cert"), "CERTIFICATE"));
    await expectConflict(f, "issued_tampered");
    await fs.rm(file);
    await expectConflict(f, "issued_missing");
    await fs.writeFile(file, original);
    await (await EzStore.open(f.options)).close();
  } finally {
    await cleanup(f);
  }
});

test("state file: unknown keys, bad JSON, wrong version and path traversal are state_corrupt", async () => {
  const f = await fixture();
  try {
    await f.store.close();
    const good = await readState(f.dir);
    const corrupt = async (state: unknown) => {
      await writeState(f.dir, state);
      await assert.rejects(EzStore.open(f.options), (e) => e instanceof EzError && e.code === "state_corrupt" && e.exitCode === 9);
    };
    await corrupt({ ...good, surprise: 1 });
    await corrupt({ ...good, version: 2 });
    await corrupt({ ...good, root: { ...good.root, extra: true } });
    await corrupt({ ...good, crl: { ...good.crl, current: { ...good.crl.current!, file: "../outside.crl.pem" } } });
    await corrupt({ ...good, crl: { ...good.crl, current: { ...good.crl.current!, file: "/etc/passwd" } } });
    await corrupt({ ...good, root: { ...good.root, certificateFile: "../root.pem" } });
    await corrupt({ ...good, key: { ...good.key, file: null } });
    await corrupt({ ...good, revoked: [{ serial: "ZZ" }] });
    await fs.writeFile(join(f.dir, "hemlig-ez.json"), "{ not json");
    await assert.rejects(EzStore.open(f.options), (e) => e instanceof EzError && e.code === "state_corrupt");
    await fs.rm(join(f.dir, "hemlig-ez.json"));
    await rejects(EzStore.open(f.options), "state_missing");
    await writeState(f.dir, good);
    await (await EzStore.open(f.options)).close();
  } finally {
    await cleanup(f);
  }
});

test("resolveRecordedPath: relative inside the directory; absolute only where allowed", () => {
  assert.equal(resolveRecordedPath("/d", "crls/000001.crl.pem", false), "/d/crls/000001.crl.pem");
  assert.equal(resolveRecordedPath("/d", "/mnt/usb/root.key.pem", true), "/mnt/usb/root.key.pem");
  for (const bad of ["../x", "a/../b", "/abs", "a//b", "C:/x", ""]) {
    assert.throws(() => resolveRecordedPath("/d", bad, false), (e) => e instanceof EzError && e.code === "state_corrupt", bad);
  }
  assert.throws(() => resolveRecordedPath("/d", "../x", true), EzError);
});

test("signer must hold the root key (I5)", async () => {
  const f = await fixture();
  try {
    f.store.assertSigner(f.signer.spkiDer);
    assert.throws(() => f.store.assertSigner(new SoftwareSigner(generateSoftwareKey("ECDSA_P256").privateKey).spkiDer), (e) => e instanceof EzError && e.code === "key_mismatch");
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

// -- online cross-check and deployments ------------------------------------------------------------------------------------

test("compareWithServer: behind, forked and root mismatch", async () => {
  const f = await fixture();
  try {
    const s = f.store.state;
    const cur = s.crl.current!;
    compareWithServer(s, {});
    compareWithServer(s, { fingerprint: s.root.fingerprint, crl: { numberHex: "1".padStart(40, "0"), sha256: cur.sha256 } });
    const code = (server: Parameters<typeof compareWithServer>[1]) => { try { compareWithServer(s, server); } catch (e) { return (e as EzError).code; } return undefined; };
    assert.equal(code({ fingerprint: "a".repeat(64) }), "root_mismatch");
    assert.equal(code({ crl: { numberHex: "2".padStart(40, "0"), sha256: "b".repeat(64) } }), "state_behind_server");
    assert.equal(code({ crl: { numberHex: "1".padStart(40, "0"), sha256: "b".repeat(64) } }), "state_forked");
    assert.equal(code({ crl: { numberHex: "0".padStart(40, "0"), sha256: "b".repeat(64) } }), undefined, "an older server CRL is handled by the caller");
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

test("deployments: uploads are recorded and behind-ness is derived from the current CRL", async () => {
  const f = await fixture();
  try {
    await f.store.recordUpload("https://a.example", "ext-1", 1);
    await f.store.recordUpload("https://b.example", "ext-2", 1);
    assert.deepEqual(f.store.deploymentsBehind(), []);
    const { crl } = await f.store.begin({ crl: true });
    await f.store.commitCrl(crl!.number, (await signCrl(f, crl!.number, crl!.thisUpdate)).der);
    await f.store.recordUpload("https://a.example", "ext-1", 2);
    await f.store.recordUpload("https://a.example", "ext-1", 1);
    assert.deepEqual(f.store.deploymentsBehind().map((d) => d.adminOrigin), ["https://b.example"]);
    assert.equal(f.store.state.deployments.find((d) => d.adminOrigin === "https://a.example")!.lastUploadedCrlNumber, 2);
  } finally {
    await f.store.close();
    await cleanup(f);
  }
});

test("fixture subject encoding stays restricted", () => {
  assert.ok(encodeSubject(subject).length > 0);
});
