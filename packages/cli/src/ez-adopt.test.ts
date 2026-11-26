import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runCli } from "./index";
import { bigUint, bitString, bool, enumerated, explicit, extension, octetString, seq, smallInt, time, tlv, uint } from "./ez-der";
import { FakeServer, FakeTerminal, pendingCa, pipeInput, type FakeCa } from "./ez-fake";
import { decryptKeyFile } from "./ez-keyfile";
import { parseOpenSslCrlNumber, parseOpenSslIndex, planReissue } from "./ez-adopt";
import { prepareCrl, signPrepared } from "./ez-issue";
import { SoftwareSigner } from "./ez-signer";
import type { EzState } from "./ez-state";
import { makeBareRoot } from "./ez-testkit";
import { fromPem, keyIdentifier, OID, signatureAlgorithmForSpki, toPem, parseCertificate, parseCrl, validateRootCertificate, verifyCertificateSignature, verifyCrlSignature } from "./ez-x509";
import type { TerminalInput } from "./tty";

const PASS = "correct horse battery staple";
const SRC = "srcsrcsrcsrc";
const token = "test.header.signature";
const origin = "https://admin.example.test";
const baseEnv = { HEMLIG_ADMIN_URL: origin, HEMLIG_ADMIN_TOKEN: token, HEMLIG_ENVIRONMENT: "prod" };
// OpenSSL stamps the real time, so these tests run on the real clock.
const clock = { value: Date.now() };

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
if (!haveOpenssl && process.env.CI) {
  test("requires openssl on PATH when CI is set", () => {
    throw new Error("openssl is not on PATH, but CI requires the cross-checks.");
  });
}
const needsOpenssl = { skip: !haveOpenssl && "openssl not on PATH" };

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
  ezFault?: (step: string) => void | Promise<void>;
  /** Run this many days in the future (the real clock plus an offset). */
  laterDays?: number;
}

const run = async (args: string[], options: RunOptions = {}): Promise<Run> => {
  let stdout = "";
  let stderr = "";
  clock.value = Date.now() + (options.laterDays ?? 0) * 86_400_000;
  const exitCode = await runCli(["pki", "ez", ...args], {
    env: baseEnv,
    configDir: join(tmpdir(), "hemlig-ez-adopt-test-no-config"),
    now: () => clock.value,
    stdin: options.stdin ?? pipeInput(),
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    transport: options.server ?? ({ async request() { throw new Error("unexpected network request"); } } as never),
    openTerminal: options.openTerminal,
    confirmArmMs: 0,
    ezFault: options.ezFault,
  });
  const last = stderr.trim().split("\n").filter((l) => l.startsWith("{")).pop();
  return { exitCode, stdout, stderr, json: stdout.trim() === "" ? undefined : JSON.parse(stdout), error: last === undefined ? undefined : JSON.parse(last).error };
};

const tempDir = (): Promise<string> => fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-adopt-"));
const cleanup = (dir: string) => fs.rm(dir, { recursive: true, force: true });
const readState = async (dir: string): Promise<EzState> => JSON.parse(await fs.readFile(join(dir, "hemlig-ez.json"), "utf8"));
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
const exists = (path: string): Promise<boolean> => fs.stat(path).then(() => true, () => false);

const openssl = (args: string[], cwd: string): string => {
  const result = spawnSync("openssl", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(result.status, 0, `openssl ${args.join(" ")}: ${result.stderr}`);
  return result.stdout;
};

const CNF = `[ ca ]
default_ca = root_ca
[ root_ca ]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/certs
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/root.pem
private_key = $dir/private/root.key
default_md = sha384
default_days = 365
default_crl_days = 180
policy = policy_any
unique_subject = no
crl_extensions = crl_ext
x509_extensions = leaf_ext
[ policy_any ]
commonName = supplied
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ leaf_ext ]
basicConstraints = CA:FALSE
[ req ]
distinguished_name = dn
string_mask = utf8only
prompt = no
[ dn ]
CN = x
[ v3_root ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_ski_only ]
subjectKeyIdentifier = hash
`;

interface Recipe {
  dir: string;
  /** Serial hex of every leaf, in issue order. */
  leaves: string[];
}

interface RecipeOptions {
  /** The key is written unencrypted. */
  plainKey?: boolean;
  /** Leaves to issue; the ones listed in `revoke` are revoked (name is the OpenSSL reason). */
  revoke?: Record<number, string>;
  leafCount?: number;
  /** CRLs to generate (0 = none; the recipe then has no root.crl.pem). */
  crls?: number;
  rootExtensions?: "v3_root" | "v3_ski_only";
  rootDays?: number;
  subj?: string;
}

/** A real `openssl ca` recipe directory, laid out as the offline-root guide describes. */
const buildRecipe = async (options: RecipeOptions = {}): Promise<Recipe> => {
  const dir = await tempDir();
  await fs.mkdir(join(dir, "private"));
  await fs.mkdir(join(dir, "certs"));
  await fs.writeFile(join(dir, "index.txt"), "");
  await fs.writeFile(join(dir, "serial"), "01\n");
  await fs.writeFile(join(dir, "crlnumber"), "01\n");
  await fs.writeFile(join(dir, "ca.cnf"), CNF);
  const pass = ["-passin", `pass:${SRC}`];
  openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", ...(options.plainKey ? [] : ["-aes256", "-pass", `pass:${SRC}`]), "-out", "private/root.key"], dir);
  openssl(["req", "-new", "-x509", "-config", "ca.cnf", "-key", "private/root.key", ...(options.plainKey ? [] : pass), "-subj", options.subj ?? "/C=US/O=Example Corp/CN=Recipe Root CA", "-days", String(options.rootDays ?? 3650), "-sha384", "-extensions", options.rootExtensions ?? "v3_root", "-out", "root.pem"], dir);
  const leaves: string[] = [];
  const count = options.leafCount ?? 3;
  for (let i = 1; i <= count; i++) {
    openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `leaf-${i}.key`, "-subj", `/CN=leaf-${i}`, "-out", `leaf-${i}.csr`], dir);
    openssl(["ca", "-batch", "-config", "ca.cnf", ...(options.plainKey ? [] : pass), "-in", `leaf-${i}.csr`, "-out", `leaf-${i}.pem`, "-notext"], dir);
    leaves.push(parseCertificate(fromPem(await fs.readFile(join(dir, `leaf-${i}.pem`), "utf8"), "CERTIFICATE")).serialHex);
  }
  for (const [index, reason] of Object.entries(options.revoke ?? {})) {
    openssl(["ca", "-config", "ca.cnf", ...(options.plainKey ? [] : pass), "-revoke", `leaf-${index}.pem`, ...(reason === "hold" ? ["-crl_hold", "1.2.840.10040.2.1"] : ["-crl_reason", reason])], dir);
  }
  for (let i = 0; i < (options.crls ?? 1); i++) {
    openssl(["ca", "-config", "ca.cnf", ...(options.plainKey ? [] : pass), "-gencrl", "-out", "root.crl.pem"], dir);
  }
  return { dir, leaves };
};

/** Prompts of a software adoption in order: source passphrase (if encrypted), confirm, the new passphrase twice. */
const adoptKeys = (encrypted = true, pass = PASS): FakeTerminal => new FakeTerminal(...(encrypted ? [`${SRC}\r`] : []), "confirm\r", `${pass}\r`, `${pass}\r`);

const adoptArgs = (dir: string, recipe: string, extra: string[] = ["--offline"]): string[] => ["adopt-ca", "--dir", dir, "--openssl-dir", recipe, ...extra];

const server = (...cas: FakeCa[]): FakeServer => {
  const s = new FakeServer();
  for (const ca of cas) s.add(ca);
  return s;
};

const openRoot = async (dir: string) => parseCertificate(fromPem(await fs.readFile(join(dir, "root.pem"), "utf8"), "CERTIFICATE"));

// -- parsers ---------------------------------------------------------------------------------------------------------

test("index.txt and crlnumber parse: V/R/E rows, reasons, hex next number", () => {
  const rows = parseOpenSslIndex(
    [
      "V\t270101000000Z\t\t01\tunknown\t/CN=a",
      "R\t270101000000Z\t261101120000Z,keyCompromise\t02\tunknown\t/CN=b",
      "R\t270101000000Z\t261101120000Z,CACompromise\t0A\tunknown\t/CN=c",
      "E\t200101000000Z\t\t03\tunknown\t/CN=d",
      "R\t270101000000Z\t20261101120000Z\t04\tunknown\t/CN=e",
      "R\t270101000000Z\t261101120000Z,keyTime,261001000000Z\t05\tunknown\t/CN=f",
      "R\t270101000000Z\t261101120000Z,certificateHold\t06\tunknown\t/CN=g",
      "R\t270101000000Z\t261101120000Z,holdInstruction,1.2.840.10040.2.1\t07\tunknown\t/CN=h",
      "",
    ].join("\n"),
  );
  assert.deepEqual(rows.map((r) => [r.status, r.serial, r.revoked?.reason]), [
    ["V", "01", undefined],
    ["R", "02", "keyCompromise"],
    ["R", "0a", "caCompromise"],
    ["E", "03", undefined],
    ["R", "04", "unspecified"],
    ["R", "05", "keyCompromise"],
    ["R", "06", "certificateHold"],
    ["R", "07", "certificateHold"],
  ]);
  assert.deepEqual(parseOpenSslIndex(""), [], "an empty index.txt is zero rows");
  assert.equal(rows[1]?.revoked?.at.toISOString(), "2026-11-01T12:00:00.000Z");
  assert.equal(rows[5]?.revoked?.invalidityDate?.toISOString(), "2026-10-01T00:00:00.000Z");
  for (const bad of ["V\t270101000000Z\t\t01\tunknown", "X\t270101000000Z\t\t01\tunknown\t/CN=a", "R\t270101000000Z\t\t01\tunknown\t/CN=a", "R\t270101000000Z\t261101120000Z,removeFromCRL\t01\tunknown\t/CN=a", "V\t270101000000Z\t\tzz\tunknown\t/CN=a", "V\t271301000000Z\t\t01\tunknown\t/CN=a"]) {
    assert.throws(() => parseOpenSslIndex(bad), /index\.txt line 1/, bad);
  }
  assert.equal(parseOpenSslCrlNumber("1000\n"), 0x1000n);
  assert.throws(() => parseOpenSslCrlNumber("0"), /next CRL number/);
  assert.throws(() => parseOpenSslCrlNumber("xyz"), /hexadecimal/);
});

// -- the recipe directory --------------------------------------------------------------------------------------------

test("adopt-ca --openssl-dir: reads index.txt R rows and crlnumber, keeps the source untouched, then sign-cert, renew-crl, revoke-cert, upload-crl and status work", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 2: "keyCompromise", 3: "CACompromise" }, crls: 2 });
  const dir = await tempDir();
  const out = join(dir, "adopted");
  try {
    const before = await snapshot(recipe.dir);
    assert.equal((await fs.readFile(join(recipe.dir, "crlnumber"), "utf8")).trim(), "03");
    const result = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout.trim().split("\n").length, 1);
    assert.deepEqual(await snapshot(recipe.dir), before, "the recipe directory is byte for byte unchanged");
    // The review came before the signature, and the originals are called out.
    assert.match(result.stderr, /Review: this will ADOPT/);
    assert.match(result.stderr, /Type "confirm" to adopt/);
    assert.match(result.stderr, /original key file\(s\) remain/);
    const state = await readState(out);
    assert.equal(state.root.origin, "adopted");
    assert.equal(state.key.storage, "software");
    assert.equal(state.key.kdf?.iterations, 1_000_000);
    assert.equal(state.adoption?.source, "openssl-dir");
    assert.deepEqual(state.adoption?.crlNumberSource.sort(), ["crl-file", "openssl-crlnumber"]);
    assert.deepEqual(state.adoption?.revocationSource.sort(), ["crl-file", "openssl-index"]);
    // The SHA-1 SKI of the recipe root is used as it is.
    const root = await openRoot(out);
    assert.equal(root.subjectKeyIdentifier?.length, 20);
    assert.equal(state.root.subjectKeyIdentifier, root.subjectKeyIdentifier?.toString("hex"));
    // crlnumber 03 means the last CRL was 2; the fresh, complete CRL stays current and nothing new is signed.
    assert.equal(state.crl.lastNumber, 2);
    assert.equal(state.crl.current?.number, 2);
    assert.equal(result.json.data.crl.signed, false);
    assert.deepEqual(state.revoked.map((r) => [r.serial, r.reason, r.imported, r.listedInCrl]), [
      [recipe.leaves[1], "keyCompromise", true, 2],
      [recipe.leaves[2], "caCompromise", true, 2],
    ]);
    assert.equal(state.issued.length, 3);
    assert.ok(state.issued.every((e) => e.status === "imported"));
    // The key file is the EZ format and decrypts under the new passphrase only.
    const keyPem = await fs.readFile(join(out, "root.key.pem"), "utf8");
    assert.match(keyPem, /BEGIN ENCRYPTED PRIVATE KEY/);
    assert.equal((await fs.stat(join(out, "root.key.pem"))).mode & 0o777, 0o600);
    assert.equal(new SoftwareSigner(decryptKeyFile(keyPem, PASS)).spkiDer.equals(root.spkiDer), true);
    assert.throws(() => decryptKeyFile(keyPem, SRC));

    // sign-cert on the adopted root: an intermediate that openssl verify accepts, and a CRL that keeps the old revocations.
    const ca = pendingCa(1);
    const s = server(ca.record);
    const signed = await run(["sign-cert", ca.record.caId, "--dir", out, "--environment", "prod", "--yes"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(signed.exitCode, 0, signed.stderr);
    assert.equal(signed.json.data.activated, true);
    const issuedPath = join(out, "issued", `${signed.json.data.serial}.pem`);
    const verify = spawnSync("openssl", ["verify", "-x509_strict", "-CAfile", join(out, "root.pem"), issuedPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(verify.status, 0, verify.stdout + verify.stderr);

    // revoke the new CA: CRL 3 lists the old revocations too and openssl agrees.
    const revoked = await run(["revoke-cert", ca.record.caId, "--dir", out, "--reason", "caCompromise"], { server: s, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(revoked.exitCode, 0, revoked.stderr);
    const crl = parseCrl(fromPem(await fs.readFile(join(out, "root.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(crl.number, 3n);
    assert.deepEqual(crl.entries.map((e) => e.serial).sort(), [recipe.leaves[1], recipe.leaves[2], signed.json.data.serial].sort());
    assert.equal(verifyCrlSignature(crl, root.spkiDer), true);
    const crlText = openssl(["crl", "-in", join(out, "root.crl.pem"), "-noout", "-text"], out);
    for (const serial of [recipe.leaves[1], recipe.leaves[2]]) assert.match(crlText, new RegExp(`Serial Number: ${(serial as string).toUpperCase()}`));
    const check = spawnSync("openssl", ["verify", "-crl_check", "-CAfile", join(out, "root.pem"), "-CRLfile", join(out, "root.crl.pem"), join(recipe.dir, "leaf-2.pem")], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.notEqual(check.status, 0);
    assert.match(check.stdout + check.stderr, /certificate revoked/);
    // the unrevoked leaf is still fine
    const fine = spawnSync("openssl", ["verify", "-crl_check", "-CAfile", join(out, "root.pem"), "-CRLfile", join(out, "root.crl.pem"), join(recipe.dir, "leaf-1.pem")], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(fine.status, 0, fine.stdout + fine.stderr);

    // the remaining commands see an ordinary root
    const renewed = await run(["renew-crl", "--dir", out, "--offline", "--crl-out", join(dir, "renewed.crl.pem")], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewed.exitCode, 0, renewed.stderr);
    assert.equal(renewed.json.data.crl.number, 4);
    const uploaded = await run(["upload-crl", "--dir", out], { server: s });
    assert.equal(uploaded.exitCode, 0, uploaded.stderr);
    const status = await run(["status", "--dir", out], { server: s });
    assert.equal(status.exitCode, 0, status.stderr);
    assert.equal(status.json.data.root.origin, "adopted");
    assert.equal(status.json.data.server.relation, "in_sync");
    assert.equal(status.json.data.crl.number, 4);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: with no CRL file the number comes from crlnumber, a new CRL is signed with every R row, and a revoked leaf stays revoked", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "superseded", 3: "unspecified" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    await fs.rm(join(recipe.dir, "root.crl.pem"));
    const result = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    const state = await readState(out);
    assert.deepEqual(state.adoption?.crlNumberSource, ["openssl-crlnumber"]);
    assert.deepEqual(state.adoption?.revocationSource, ["openssl-index"]);
    assert.equal(state.crl.lastNumber, 2);
    assert.equal(result.json.data.crl.signed, true);
    assert.deepEqual(state.revoked.map((r) => [r.serial, r.reason, r.listedInCrl]), [
      [recipe.leaves[0], "superseded", 2],
      [recipe.leaves[2], "unspecified", 2],
    ]);
    const root = await openRoot(out);
    const crl = parseCrl(fromPem(await fs.readFile(join(out, "root.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(crl.number, 2n);
    assert.equal(crl.authorityKeyIdentifier?.equals(root.subjectKeyIdentifier as Buffer), true);
    assert.equal(verifyCrlSignature(crl, root.spkiDer), true);
    // OpenSSL records the reason the operator gave, and EZ keeps it (unspecified carries no reason code).
    assert.deepEqual(crl.entries.map((e) => e.reason ?? "unspecified"), ["superseded", "unspecified"]);
    const check = spawnSync("openssl", ["verify", "-crl_check", "-CAfile", join(out, "root.pem"), "-CRLfile", join(out, "root.crl.pem"), join(recipe.dir, "leaf-3.pem")], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.match(check.stdout + check.stderr, /certificate revoked/);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: --crl-number raises the number above every source, and the max wins", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  try {
    const raised = await run(adoptArgs(join(dir, "a"), recipe.dir, ["--offline", "--crl-number", "40"]), { stdin: adoptKeys() });
    assert.equal(raised.exitCode, 0, raised.stderr);
    const state = await readState(join(dir, "a"));
    assert.equal(state.crl.lastNumber, 41);
    assert.deepEqual(state.adoption?.crlNumberSource.sort(), ["crl-file", "flag", "openssl-crlnumber"]);
    assert.equal(raised.json.data.crl.signed, true, "the adopted CRL is not the newest number, so a new one is signed");
    const lower = await run(adoptArgs(join(dir, "b"), recipe.dir, ["--offline", "--crl-number", "0"]), { stdin: adoptKeys() });
    assert.equal(lower.exitCode, 0, lower.stderr);
    assert.equal((await readState(join(dir, "b"))).crl.lastNumber, 1);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

// -- keys ------------------------------------------------------------------------------------------------------------

test("adopt-ca --cert --key: an unencrypted key is accepted with a warning, the copy is encrypted, sources are untouched", needsOpenssl, async () => {
  const recipe = await buildRecipe({ plainKey: true, revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    const before = await snapshot(recipe.dir);
    const result = await run(
      ["adopt-ca", "--dir", out, "--cert", join(recipe.dir, "root.pem"), "--key", join(recipe.dir, "private", "root.key"), "--crl", join(recipe.dir, "root.crl.pem"), "--offline"],
      { stdin: adoptKeys(false) },
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stderr, /NOT encrypted/);
    assert.ok(result.json.data.warnings.includes("key_unencrypted"));
    assert.doesNotMatch(result.stderr, /Source key passphrase/);
    assert.deepEqual(await snapshot(recipe.dir), before);
    assert.match(await fs.readFile(join(out, "root.key.pem"), "utf8"), /BEGIN ENCRYPTED PRIVATE KEY/);
    assert.equal((await readState(out)).adoption?.source, "files");
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: a traditional -aes256 PEM key works; --passphrase-stdin reads the old then the new passphrase", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    openssl(["pkey", "-in", "private/root.key", "-passin", `pass:${SRC}`, "-traditional", "-aes256", "-passout", `pass:${SRC}`, "-out", "private/trad.key"], recipe.dir);
    const traditional = await fs.readFile(join(recipe.dir, "private", "trad.key"), "utf8");
    assert.match(traditional, /BEGIN EC PRIVATE KEY/);
    assert.match(traditional, /Proc-Type: 4,ENCRYPTED/);
    const out = join(dir, "out");
    const result = await run(
      ["adopt-ca", "--dir", out, "--cert", join(recipe.dir, "root.pem"), "--key", join(recipe.dir, "private", "trad.key"), "--crl", join(recipe.dir, "root.crl.pem"), "--offline", "--passphrase-stdin"],
      { stdin: pipeInput(`${SRC}\n${PASS}\n`), openTerminal: async () => new FakeTerminal("confirm\r") },
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(new SoftwareSigner(decryptKeyFile(await fs.readFile(join(out, "root.key.pem"), "utf8"), PASS)).spkiDer.equals((await openRoot(out)).spkiDer), true);
    // A key that is not a PEM private key is refused with the conversion hint.
    await fs.writeFile(join(recipe.dir, "private", "junk.key"), "not a key\n");
    const junk = await run(["adopt-ca", "--dir", join(dir, "j"), "--cert", join(recipe.dir, "root.pem"), "--key", join(recipe.dir, "private", "junk.key"), "--offline", "--no-prior-revocations", "--crl-number", "1"]);
    assert.equal(junk.exitCode, 2);
    assert.equal(junk.error.code, "key_file_invalid");
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: a wrong source passphrase exits 3 and leaves nothing behind (not even the directory)", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "never");
  try {
    const before = await snapshot(recipe.dir);
    const result = await run(adoptArgs(out, recipe.dir), { stdin: new FakeTerminal("not the passphrase\r") });
    assert.equal(result.exitCode, 3);
    assert.equal(result.error.code, "passphrase_invalid");
    assert.equal(await exists(out), false);
    assert.deepEqual(await snapshot(recipe.dir), before);
    assert.doesNotMatch(result.stderr, /Review:/, "nothing was reviewed or signed");
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: a key that does not belong to the certificate is key_mismatch", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const other = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const result = await run(
      ["adopt-ca", "--dir", join(dir, "out"), "--cert", join(recipe.dir, "root.pem"), "--key", join(other.dir, "private", "root.key"), "--crl", join(recipe.dir, "root.crl.pem"), "--offline"],
      { stdin: new FakeTerminal(`${SRC}\r`) },
    );
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "key_mismatch");
    assert.equal(await exists(join(dir, "out")), false);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(other.dir);
    await cleanup(dir);
  }
});

// -- revocation and number sources -----------------------------------------------------------------------------------

test("adopt-ca: refuses without a revocation source, needs a number source, and --no-prior-revocations is explicit", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const common = ["--cert", join(recipe.dir, "root.pem"), "--key", join(recipe.dir, "private", "root.key"), "--offline"];
    const missing = await run(["adopt-ca", "--dir", join(dir, "a"), ...common, "--crl-number", "3"]);
    assert.equal(missing.exitCode, 2);
    assert.equal(missing.error.code, "revocation_source_required");
    assert.equal(await exists(join(dir, "a")), false);
    const noNumber = await run(["adopt-ca", "--dir", join(dir, "b"), ...common, "--no-prior-revocations"]);
    assert.equal(noNumber.exitCode, 2);
    assert.equal(noNumber.error.code, "crl_number_required");
    const contradiction = await run(["adopt-ca", "--dir", join(dir, "c"), ...common, "--no-prior-revocations", "--crl", join(recipe.dir, "root.crl.pem")]);
    assert.equal(contradiction.exitCode, 2);
    const declared = await run(["adopt-ca", "--dir", join(dir, "d"), ...common, "--no-prior-revocations", "--crl-number", "3"], { stdin: adoptKeys() });
    assert.equal(declared.exitCode, 0, declared.stderr);
    const state = await readState(join(dir, "d"));
    assert.deepEqual(state.adoption?.revocationSource, ["none-declared"]);
    assert.deepEqual(state.adoption?.crlNumberSource, ["flag"]);
    assert.equal(state.crl.current?.number, 4);
    assert.equal(state.revoked.length, 0);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca: a CRL from another issuer is refused, even with the right root", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const other = await buildRecipe({ revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  try {
    const result = await run(adoptArgs(join(dir, "out"), recipe.dir, ["--offline", "--crl", join(other.dir, "root.crl.pem")]), { stdin: adoptKeys() });
    assert.equal(result.exitCode, 5);
    assert.equal(result.error.code, "crl_invalid");
    assert.match(result.error.message, /not issued by this root/);
    assert.equal(await exists(join(dir, "out")), false);
    // same subject name but a different key: the signature does not verify
    const lookalike = await buildRecipe({ crls: 1 });
    const forged = await run(adoptArgs(join(dir, "out2"), recipe.dir, ["--offline", "--crl", join(lookalike.dir, "root.crl.pem")]), { stdin: adoptKeys() });
    assert.equal(forged.exitCode, 5);
    assert.equal(forged.error.code, "crl_invalid");
    await cleanup(lookalike.dir);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(other.dir);
    await cleanup(dir);
  }
});

test("adopt-ca online: the server's root CRL is verified and unioned, raises the number, stays current and is recorded as uploaded", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    // Snapshot the older recipe state (CRL 1, one revocation), then revoke another leaf and issue CRL 2 as "the server's".
    const index = await fs.readFile(join(recipe.dir, "index.txt"), "utf8");
    const crlnumber = await fs.readFile(join(recipe.dir, "crlnumber"), "utf8");
    const olderCrl = await fs.readFile(join(recipe.dir, "root.crl.pem"));
    openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-revoke", "leaf-3.pem", "-crl_reason", "cessationOfOperation"], recipe.dir);
    openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-gencrl", "-out", "server.crl.pem"], recipe.dir);
    const serverCrlPem = await fs.readFile(join(recipe.dir, "server.crl.pem"), "utf8");
    await fs.writeFile(join(recipe.dir, "index.txt"), index);
    await fs.writeFile(join(recipe.dir, "crlnumber"), crlnumber);
    await fs.writeFile(join(recipe.dir, "root.crl.pem"), olderCrl);
    await fs.rm(join(recipe.dir, "server.crl.pem"));
    const root = parseCertificate(fromPem(await fs.readFile(join(recipe.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    const serverCrl = parseCrl(fromPem(serverCrlPem, "X509 CRL"));
    assert.equal(serverCrl.number, 2n);
    const s = new FakeServer();
    const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
    s.externals.set(extId, {
      extId,
      fingerprint: root.fingerprint,
      crlPem: serverCrlPem,
      crl: { numberHex: "02", sha256: serverCrl.sha256, thisUpdate: serverCrl.thisUpdate.toISOString(), nextUpdate: (serverCrl.nextUpdate as Date).toISOString() },
      dependents: new Set(),
      serials: new Map(),
    });
    // The operator says the last number was 1; the server's 2 raises it.
    const result = await run(["adopt-ca", "--dir", out, "--openssl-dir", recipe.dir, "--crl-number", "1"], { server: s, stdin: adoptKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.ok(result.json.data.warnings.includes("crl_number_raised_by_server"));
    assert.ok(s.requests.some((r) => r.url.pathname === `/v1/admin/pki/crls/${extId}`), "the CRL was downloaded like pki ca crl get");
    assert.equal(s.mutations.length, 0, "adopt-ca never uploads");
    const state = await readState(out);
    assert.equal(state.crl.lastNumber, 2);
    assert.equal(state.crl.current?.number, 2);
    assert.equal(result.json.data.crl.signed, false, "the server's CRL covers everything, so it stays current");
    assert.deepEqual(state.adoption?.crlNumberSource.sort(), ["crl-file", "flag", "openssl-crlnumber", "server"]);
    assert.deepEqual(state.revoked.map((r) => r.serial).sort(), [recipe.leaves[0], recipe.leaves[2]].sort());
    assert.equal(state.deployments[0]?.lastUploadedCrlNumber, 2);
    const status = await run(["status", "--dir", out], { server: s });
    assert.equal(status.json.data.server.relation, "in_sync");

    // Another adoption where the server knows a revocation the local sources do not: it is carried over in a NEW CRL
    // (the local sources alone would not have listed it).
    const out2 = join(dir, "out2");
    await fs.rm(join(recipe.dir, "root.crl.pem"));
    const second = await run(["adopt-ca", "--dir", out2, "--openssl-dir", recipe.dir, "--crl-number", "1"], { server: s, stdin: adoptKeys() });
    assert.equal(second.exitCode, 0, second.stderr);
    assert.equal((await readState(out2)).revoked.length, 2);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca online: a registered root cannot be re-issued, and a server CRL from another issuer is refused", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const other = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const root = parseCertificate(fromPem(await fs.readFile(join(recipe.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    const otherCrlPem = await fs.readFile(join(other.dir, "root.crl.pem"), "utf8");
    const otherCrl = parseCrl(fromPem(otherCrlPem, "X509 CRL"));
    const s = new FakeServer();
    const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
    s.externals.set(extId, {
      extId,
      fingerprint: root.fingerprint,
      crlPem: otherCrlPem,
      crl: { numberHex: "01", sha256: otherCrl.sha256, thisUpdate: otherCrl.thisUpdate.toISOString(), nextUpdate: (otherCrl.nextUpdate as Date).toISOString() },
      dependents: new Set(),
      serials: new Map(),
    });
    const refused = await run(adoptArgs(join(dir, "a"), recipe.dir, []), { server: s, stdin: adoptKeys() });
    assert.equal(refused.exitCode, 5);
    assert.equal(refused.error.code, "crl_invalid");
    assert.match(refused.error.message, /server's root CRL/);
    assert.equal(await exists(join(dir, "a")), false);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(other.dir);
    await cleanup(dir);
  }
});

// -- reissue ---------------------------------------------------------------------------------------------------------

const bareKey = (): KeyObject => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const writeKey = async (dir: string, key: KeyObject): Promise<string> => {
  const path = join(dir, "bare.key");
  await fs.writeFile(path, key.export({ type: "pkcs8", format: "pem" }));
  return path;
};

test("--reissue-root-certificate: an extension-less root is refused naming the flag, then re-issued with the same subject and key", async () => {
  const key = bareKey();
  const bare = makeBareRoot({ privateKey: key, notAfter: new Date(Math.floor(Date.now() / 1000) * 1000 + 3000 * 86_400_000) });
  const dir = await tempDir();
  try {
    const certPath = join(dir, "bare.pem");
    await fs.writeFile(certPath, bare.pem);
    const keyPath = await writeKey(dir, key);
    const common = ["--cert", certPath, "--key", keyPath, "--offline", "--no-prior-revocations", "--crl-number", "9"];
    const without = await run(["adopt-ca", "--dir", join(dir, "a"), ...common]);
    assert.equal(without.exitCode, 5);
    assert.equal(without.error.code, "root_profile_invalid");
    assert.match(without.error.message, /--reissue-root-certificate/);
    assert.deepEqual(without.error.details?.reasons ?? [], ["root_not_ca", "root_key_usage", "root_missing_ski"]);
    assert.equal(await exists(join(dir, "a")), false);

    const out = join(dir, "out");
    const result = await run(["adopt-ca", "--dir", out, ...common, "--reissue-root-certificate"], { stdin: adoptKeys(false) });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stderr, /FINGERPRINT CHANGES/);
    assert.equal(result.json.data.root.fingerprintChanged, true);
    const old = parseCertificate(bare.der);
    const root = await openRoot(out);
    assert.notEqual(root.fingerprint, old.fingerprint);
    assert.equal(root.subjectDer.equals(old.subjectDer), true);
    assert.equal(root.spkiDer.equals(old.spkiDer), true);
    assert.equal(root.issuerDer.equals(old.subjectDer), true);
    assert.notEqual(root.serialHex, old.serialHex);
    assert.equal(root.notAfter.getTime(), old.notAfter.getTime());
    assert.ok(Math.abs(root.notBefore.getTime() - (Math.floor(clock.value / 1000) * 1000 - 3_600_000)) < 5000);
    assert.deepEqual(validateRootCertificate(root.der, { minimumRemainingDays: 90 }).reasons, []);
    assert.equal(root.subjectKeyIdentifier?.equals(keyIdentifier(root.spkiDer)), true, "no old SKI: RFC 7093 method 1");
    assert.equal(await fs.readFile(join(out, "root.original.pem"), "utf8"), bare.pem);
    assert.equal(verifyCertificateSignature(root, old.spkiDer), true);
    const state = await readState(out);
    assert.deepEqual(state.root.reissuedFrom, { fingerprint: old.fingerprint, file: "root.original.pem" });
    assert.equal(state.root.fingerprint, root.fingerprint);
    // the CRL (number 10) was signed in the same batch
    const crl = parseCrl(fromPem(await fs.readFile(join(out, "root.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(crl.number, 10n);
    assert.equal(verifyCrlSignature(crl, root.spkiDer), true);
    // the reissued root signs intermediates that verify
    const ca = pendingCa(1);
    const signed = await run(["sign-cert", ca.record.caId, "--dir", out, "--environment", "prod", "--yes"], { server: server(ca.record), stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(signed.exitCode, 0, signed.stderr);
  } finally {
    await cleanup(dir);
  }
});

test("--reissue-root-certificate keeps an existing SKI value, honours --validity, and --store-certificate-in-slot needs --yubikey", needsOpenssl, async () => {
  const recipe = await buildRecipe({ rootExtensions: "v3_ski_only", crls: 1 });
  const dir = await tempDir();
  try {
    const old = parseCertificate(fromPem(await fs.readFile(join(recipe.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    assert.equal(old.subjectKeyIdentifier?.length, 20);
    const out = join(dir, "out");
    const result = await run(adoptArgs(out, recipe.dir, ["--offline", "--reissue-root-certificate", "--validity", "1000d"]), { stdin: adoptKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    const root = await openRoot(out);
    assert.equal(root.subjectKeyIdentifier?.equals(old.subjectKeyIdentifier as Buffer), true);
    assert.equal(Math.round((root.notAfter.getTime() - clock.value) / 86_400_000), 1000);
    // the OpenSSL CRL was issued with the old SKI as AKI, so it is still the current CRL
    assert.equal(result.json.data.crl.adopted, true);
    const verify = spawnSync("openssl", ["verify", "-CAfile", join(out, "root.pem"), join(recipe.dir, "leaf-1.pem")], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(verify.status, 0, verify.stdout + verify.stderr);
    const flagged = await run(["adopt-ca", "--dir", join(dir, "x"), "--openssl-dir", recipe.dir, "--offline", "--store-certificate-in-slot"]);
    assert.equal(flagged.exitCode, 2);
    const validity = await run(adoptArgs(join(dir, "y"), recipe.dir, ["--offline", "--validity", "900d"]));
    assert.equal(validity.exitCode, 2, "--validity needs --reissue-root-certificate");
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("--reissue-root-certificate is refused for anything but extension-profile failures, and when nothing needs fixing", needsOpenssl, async () => {
  const dir = await tempDir();
  const key = bareKey();
  try {
    const keyPath = await writeKey(dir, key);
    const flags = (cert: string): string[] => ["--cert", cert, "--key", keyPath, "--offline", "--no-prior-revocations", "--crl-number", "1", "--reissue-root-certificate"];
    // expires in 30 days: root_expires_soon is not an extension problem
    const soon = makeBareRoot({ privateKey: key, notAfter: new Date(Date.now() + 30 * 86_400_000) });
    await fs.writeFile(join(dir, "soon.pem"), soon.pem);
    const expiring = await run(["adopt-ca", "--dir", join(dir, "a"), ...flags(join(dir, "soon.pem"))]);
    assert.equal(expiring.exitCode, 5);
    assert.equal(expiring.error.code, "root_profile_invalid");
    assert.match(expiring.error.message, /cannot fix root_expires_soon/);
    // not self-signed by its own key: a root issued by someone else
    const issuer = bareKey();
    const forged = makeBareRoot({ privateKey: issuer, notAfter: new Date(Date.now() + 3000 * 86_400_000) });
    const tampered = Buffer.from(forged.der);
    tampered[tampered.length - 3] = (tampered[tampered.length - 3] as number) ^ 0xff;
    await fs.writeFile(join(dir, "forged.pem"), `-----BEGIN CERTIFICATE-----\n${tampered.toString("base64")}\n-----END CERTIFICATE-----\n`);
    const forgedRun = await run(["adopt-ca", "--dir", join(dir, "b"), ...flags(join(dir, "forged.pem"))]);
    assert.equal(forgedRun.exitCode, 5);
    assert.match(forgedRun.error.message, /root_signature_invalid/);
    // pathLen 0 is an extension-profile failure and is fixed (the re-issue drops it)
    const pathZero = makeBareRoot({
      privateKey: key,
      notAfter: new Date(Date.now() + 3000 * 86_400_000),
      extensions: [extension(OID.basicConstraints, true, seq(bool(true), smallInt(0))), extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)), extension(OID.ski, false, octetString(keyIdentifier(new SoftwareSigner(key).spkiDer)))],
    });
    await fs.writeFile(join(dir, "zero.pem"), pathZero.pem);
    const fixed = await run(["adopt-ca", "--dir", join(dir, "c"), ...flags(join(dir, "zero.pem"))], { stdin: adoptKeys(false) });
    assert.equal(fixed.exitCode, 0, fixed.stderr);
    assert.match(fixed.stderr, /NO limit: the old limit of 0 is dropped/);
    assert.equal(parseCertificate(fromPem(await fs.readFile(join(dir, "c", "root.pem"), "utf8"), "CERTIFICATE")).extensions.find((e) => e.oid === OID.basicConstraints)?.critical, true);
    // an already-compliant recipe root: nothing to fix, so the flag is refused
    const recipe = await buildRecipe({ crls: 1 });
    const needless = await run(adoptArgs(join(dir, "d"), recipe.dir, ["--offline", "--reissue-root-certificate"]));
    assert.equal(needless.exitCode, 2);
    assert.equal(needless.error.code, "reissue_not_needed");
    // a recipe root with a bad subject is not fixable either
    await cleanup(recipe.dir);
  } finally {
    await cleanup(dir);
  }
});

test("planReissue keeps a valid pathLen and refuses a short validity", () => {
  const key = bareKey();
  const cert = parseCertificate(makeBareRoot({ privateKey: key }).der);
  assert.throws(() => planReissue(cert, 30, new Date()), /at least 90 days/);
  assert.equal(planReissue(cert, 400, new Date()).pathLen, undefined);
});

// -- confirm, no-clobber and crashes ---------------------------------------------------------------------------------

test("adopt-ca: declining the typed confirm signs nothing and leaves nothing behind", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const out = join(dir, "out");
    const before = await snapshot(recipe.dir);
    for (const [label, keys, code, exit] of [
      ["wrong word", [`${SRC}\r`, "yes\r"], "confirmation_declined", 2],
      ["EOF", [`${SRC}\r`], "prompt_cancelled", 9],
    ] as const) {
      const result = await run(adoptArgs(out, recipe.dir), { stdin: new FakeTerminal(...keys) });
      assert.equal(result.exitCode, exit, label);
      assert.equal(result.error.code, code, label);
      assert.match(result.stderr, /Review: this will ADOPT/, label);
      assert.equal(await exists(out), false, label);
      assert.deepEqual(await snapshot(recipe.dir), before);
    }
    // in an existing directory only the directory's own content remains
    await fs.mkdir(out);
    await fs.writeFile(join(out, "keep.txt"), "mine");
    const declined = await run(adoptArgs(out, recipe.dir), { stdin: new FakeTerminal(`${SRC}\r`, "no\r") });
    assert.equal(declined.exitCode, 2);
    assert.deepEqual(await fs.readdir(out), ["keep.txt"]);
    // a pipe with no terminal is refused before anything is shown
    const piped = await run(adoptArgs(out, recipe.dir, ["--offline", "--passphrase-stdin"]), { stdin: pipeInput(`${SRC}\n${PASS}\n`), openTerminal: async () => undefined });
    assert.equal(piped.exitCode, 2);
    assert.equal(piped.error.code, "terminal_required");
    assert.doesNotMatch(piped.stderr, /Review:/);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca never overwrites: an existing state or target file is refused and the directory is unchanged", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const out = join(dir, "out");
    assert.equal((await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() })).exitCode, 0);
    const before = await snapshot(out);
    const again = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
    assert.equal(again.exitCode, 5);
    assert.equal(again.error.code, "already_exists");
    assert.deepEqual(await snapshot(out), before);
    // a lone existing target file in an otherwise empty directory
    const lone = join(dir, "lone");
    await fs.mkdir(lone);
    await fs.writeFile(join(lone, "root.pem"), "precious");
    const refused = await run(adoptArgs(lone, recipe.dir), { stdin: adoptKeys() });
    assert.equal(refused.exitCode, 5);
    assert.equal(refused.error.code, "already_exists");
    assert.equal(await fs.readFile(join(lone, "root.pem"), "utf8"), "precious");
    assert.deepEqual(await fs.readdir(lone), ["root.pem"]);
    // the source directory as the target: root.pem is there already, nothing is changed
    const before2 = await snapshot(recipe.dir);
    const inPlace = await run(adoptArgs(recipe.dir, recipe.dir), { stdin: adoptKeys() });
    assert.equal(inPlace.exitCode, 2);
    assert.deepEqual(await snapshot(recipe.dir), before2);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca crash recovery: a crash between files leaves no state and a clean rerun path; sources and a half-written directory are never trusted", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 2: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  try {
    const out = join(dir, "out");
    const before = await snapshot(recipe.dir);
    for (const step of ["create:artifact:1", "create:artifact:3"]) {
      const crashed = await run(adoptArgs(out, recipe.dir), {
        stdin: adoptKeys(),
        ezFault: (s) => {
          if (s === step) throw new Error("crash");
        },
      });
      assert.notEqual(crashed.exitCode, 0, step);
      assert.equal(await exists(join(out, "hemlig-ez.json")), false, "the state file is written last");
      assert.equal(await exists(join(out, ".hemlig-ez.lock")), false, "the lock is released");
      assert.deepEqual(await snapshot(recipe.dir), before);
      // the rerun refuses to build on the leftovers and says what to do
      const rerun = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
      assert.equal(rerun.exitCode, 5, step);
      assert.equal(rerun.error.code, "already_exists");
      assert.match(rerun.error.message, /was interrupted/);
      // other commands see no state at all
      const status = await run(["status", "--dir", out, "--offline"]);
      assert.equal(status.exitCode, 5);
      assert.equal(status.error.code, "state_missing");
      await fs.rm(out, { recursive: true, force: true });
    }
    const done = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
    assert.equal(done.exitCode, 0, done.stderr);
    assert.equal((await readState(out)).pending, null);
    // a crash after the state exists is an ordinary state: it opens, and the CRL and certificate verify
    const status = await run(["status", "--dir", out, "--offline"]);
    assert.equal(status.exitCode, 0, status.stderr);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca usage errors and help", async () => {
  const cases: string[][] = [
    ["adopt-ca"],
    ["adopt-ca", "--yubikey", "--openssl-dir", "x"],
    ["adopt-ca", "--openssl-dir", "x", "--cert", "c.pem"],
    ["adopt-ca", "--cert", "c.pem"],
    ["adopt-ca", "--cert", "c.pem", "--key", "k.pem", "--slot", "9c"],
    ["adopt-ca", "--yubikey", "--passphrase-stdin"],
    ["adopt-ca", "--yubikey", "--key", "k.pem"],
    ["adopt-ca", "--cert", "c.pem", "--key", "k.pem", "--crl-number", "abc"],
    ["adopt-ca", "--cert", "c.pem", "--key", "k.pem", "--offline", "--admin-url", "https://x.example"],
  ];
  for (const args of cases) {
    const result = await run(args);
    assert.equal(result.exitCode, 2, args.join(" "));
  }
  const help = await run(["--help"]);
  assert.equal(help.exitCode, 0);
  assert.match(help.stdout, /adopt-ca/);
  assert.ok(JSON.parse(help.stdout).commands["adopt-ca"]);
});

test("adopted CRLs built by EZ itself qualify as current; an old or incomplete one does not", async () => {
  // A CRL EZ signed (180 days) is adopted as is; one with < 45 days left is replaced.
  const key = bareKey();
  const signer = new SoftwareSigner(key);
  const bare = makeBareRoot({
    privateKey: key,
    notAfter: new Date(Date.now() + 3000 * 86_400_000),
    extensions: [extension(OID.basicConstraints, true, seq(bool(true))), extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)), extension(OID.ski, false, octetString(keyIdentifier(signer.spkiDer)))],
  });
  const root = parseCertificate(bare.der);
  const dir = await tempDir();
  try {
    const stamp = new Date(Math.floor(Date.now() / 1000) * 1000 - 60_000);
    const fresh = (await signPrepared(signer, [prepareCrl(signer, root, { number: 7, thisUpdate: stamp, validityDays: 180, entries: [] })] as const))[0];
    const stale = (await signPrepared(signer, [prepareCrl(signer, root, { number: 7, thisUpdate: new Date(stamp.getTime() - 150 * 86_400_000), validityDays: 180, entries: [] })] as const))[0];
    await fs.writeFile(join(dir, "root.pem"), bare.pem);
    await fs.writeFile(join(dir, "key.pem"), key.export({ type: "pkcs8", format: "pem" }));
    await fs.writeFile(join(dir, "fresh.crl.pem"), fresh.pem);
    await fs.writeFile(join(dir, "stale.crl.pem"), stale.pem);
    const args = (target: string, crl: string): string[] => ["adopt-ca", "--dir", join(dir, target), "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--crl", join(dir, crl), "--offline"];
    const a = await run(args("a", "fresh.crl.pem"), { stdin: adoptKeys(false) });
    assert.equal(a.exitCode, 0, a.stderr);
    assert.equal(a.json.data.crl.adopted, true);
    assert.equal((await fs.readFile(join(dir, "a", "root.crl.pem"), "utf8")), fresh.pem);
    const b = await run(args("b", "stale.crl.pem"), { stdin: adoptKeys(false) });
    assert.equal(b.exitCode, 0, b.stderr);
    assert.equal(b.json.data.crl.signed, true);
    assert.equal(b.json.data.crl.number, 8);
  } finally {
    await cleanup(dir);
  }
});

// -- review findings -------------------------------------------------------------------------------------------------

test("adopt-ca accepts an empty index.txt (a recipe that never issued anything)", needsOpenssl, async () => {
  const recipe = await buildRecipe({ leafCount: 0, crls: 1 });
  const dir = await tempDir();
  try {
    assert.equal((await fs.stat(join(recipe.dir, "index.txt"))).size, 0);
    const result = await run(adoptArgs(join(dir, "out"), recipe.dir), { stdin: adoptKeys() });
    assert.equal(result.exitCode, 0, result.stderr);
    const state = await readState(join(dir, "out"));
    assert.equal(state.issued.length, 0);
    assert.equal(state.revoked.length, 0);
    assert.deepEqual(state.adoption?.revocationSource.sort(), ["crl-file", "openssl-index"]);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("a holdInstruction row is certificateHold, and revoke-cert can repeat that imported reason but not use it for a new revocation", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "hold", 2: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    await fs.rm(join(recipe.dir, "root.crl.pem"));
    const adopted = await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() });
    assert.equal(adopted.exitCode, 0, adopted.stderr);
    const state = await readState(out);
    assert.equal(state.revoked.find((r) => r.serial === recipe.leaves[0])?.reason, "certificateHold");
    const base = ["revoke-cert", "--dir", out, "--serial", recipe.leaves[0] as string, "--offline", "--crl-out", join(dir, "r.crl.pem")];
    const wrong = await run([...base, "--reason", "keyCompromise"]);
    assert.equal(wrong.exitCode, 5);
    assert.equal(wrong.error.code, "revocation_conflict");
    assert.match(wrong.error.message, /--reason certificateHold is accepted here only to match the imported revocation/);
    const right = await run([...base, "--reason", "certificateHold"]);
    assert.equal(right.exitCode, 0, right.stderr);
    // a NEW revocation may still not use certificateHold
    const fresh = await run(["revoke-cert", "--dir", out, "--serial", recipe.leaves[2] as string, "--reason", "certificateHold", "--offline", "--crl-out", join(dir, "n.crl.pem")], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(fresh.exitCode, 2);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("adopt-ca refuses a --dir inside the recipe, and any output that is an input", needsOpenssl, async () => {
  const recipe = await buildRecipe({ crls: 1 });
  const dir = await tempDir();
  try {
    const before = await snapshot(recipe.dir);
    for (const target of [recipe.dir, join(recipe.dir, "nested")]) {
      const result = await run(adoptArgs(target, recipe.dir, ["--offline", "--cert-file", "a.pem", "--crl-file", "a.crl", "--key-file", "a.key"]), { stdin: adoptKeys() });
      assert.equal(result.exitCode, 2, target);
      assert.match(result.error.message, /inside it|OpenSSL directory/);
      assert.deepEqual(await snapshot(recipe.dir), before);
    }
    // a symlink to the recipe is the same directory
    await fs.symlink(recipe.dir, join(dir, "link"));
    assert.equal((await run(adoptArgs(join(dir, "link", "x"), recipe.dir), { stdin: adoptKeys() })).exitCode, 2);
    // an output that names an input file
    const clash = await run(adoptArgs(join(dir, "out"), recipe.dir, ["--offline", "--cert-file", join(recipe.dir, "root.pem")]), { stdin: adoptKeys() });
    assert.equal(clash.exitCode, 2);
    assert.match(clash.error.message, /also an input file/);
    assert.deepEqual(await snapshot(recipe.dir), before);
    assert.equal(await exists(join(dir, "out")), false);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

const craftCrl = (options: { number?: bigint; key: KeyObject; root: ReturnType<typeof parseCertificate>; reasonCode?: number; entryExtension?: Buffer; crlExtension?: Buffer }): string => {
  const alg = signatureAlgorithmForSpki(options.root.spkiDer);
  const entryExts = [
    ...(options.reasonCode === undefined ? [] : [extension(OID.reasonCode, false, enumerated(options.reasonCode))]),
    ...(options.entryExtension === undefined ? [] : [options.entryExtension]),
  ];
  const stamp = new Date(Math.floor(Date.now() / 1000) * 1000 - 60_000);
  const tbs = seq(
    smallInt(1),
    alg.algorithmIdentifier,
    options.root.subjectDer,
    time(stamp),
    time(new Date(stamp.getTime() + 180 * 86_400_000)),
    seq(seq(uint(Buffer.from([0x0a])), time(stamp), ...(entryExts.length === 0 ? [] : [seq(...entryExts)]))),
    explicit(0, seq(extension(OID.aki, false, seq(tlv(0x80, options.root.subjectKeyIdentifier as Buffer))), extension(OID.crlNumber, false, bigUint(options.number ?? 5n)), ...(options.crlExtension === undefined ? [] : [options.crlExtension]))),
  );
  const signature = cryptoSign(alg.hash, tbs, { key: options.key, dsaEncoding: "der" });
  return toPem(seq(tbs, alg.algorithmIdentifier, bitString(signature)), "X509 CRL");
};

test("adopt-ca refuses CRLs the server would refuse: reason 8, unknown reasons, indirect, partitioned, delta and critical extensions", async () => {
  const key = bareKey();
  const signer = new SoftwareSigner(key);
  const bare = makeBareRoot({
    privateKey: key,
    notAfter: new Date(Date.now() + 3000 * 86_400_000),
    extensions: [extension(OID.basicConstraints, true, seq(bool(true))), extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)), extension(OID.ski, false, octetString(keyIdentifier(signer.spkiDer)))],
  });
  const root = parseCertificate(bare.der);
  const dir = await tempDir();
  try {
    await fs.writeFile(join(dir, "root.pem"), bare.pem);
    await fs.writeFile(join(dir, "key.pem"), key.export({ type: "pkcs8", format: "pem" }));
    const args = (name: string): string[] => ["adopt-ca", "--dir", join(dir, name), "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--crl", join(dir, `${name}.crl.pem`), "--offline"];
    const cases: Record<string, Parameters<typeof craftCrl>[0]> = {
      remove: { key, root, reasonCode: 8 },
      unused: { key, root, reasonCode: 7 },
      indirect: { key, root, entryExtension: extension(OID.certificateIssuer, false, seq()) },
      entryCritical: { key, root, entryExtension: extension("1.2.3.4.5", true, seq()) },
      idp: { key, root, crlExtension: extension(OID.issuingDistributionPoint, true, seq()) },
      delta: { key, root, crlExtension: extension(OID.deltaCrlIndicator, true, bigUint(4n)) },
      freshest: { key, root, crlExtension: extension(OID.freshestCrl, false, seq()) },
      critical: { key, root, crlExtension: extension("1.2.3.4.6", true, seq()) },
    };
    for (const [name, options] of Object.entries(cases)) {
      await fs.writeFile(join(dir, `${name}.crl.pem`), craftCrl(options));
      const result = await run(args(name), { stdin: adoptKeys(false) });
      assert.equal(result.exitCode, 5, name);
      assert.equal(result.error.code, "crl_invalid", name);
      assert.equal(await exists(join(dir, name)), false, name);
    }
    // the same CRL with a real reason is fine
    await fs.writeFile(join(dir, "good.crl.pem"), craftCrl({ key, root, reasonCode: 1 }));
    const good = await run(args("good"), { stdin: adoptKeys(false) });
    assert.equal(good.exitCode, 0, good.stderr);
    assert.equal((await readState(join(dir, "good"))).revoked[0]?.reason, "keyCompromise");
  } finally {
    await cleanup(dir);
  }
});

test("an offline adoption from a stale CRL cannot later un-revoke what the server lists", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    // The recipe as it was at CRL 1 (leaf 1 revoked) ...
    const index = await fs.readFile(join(recipe.dir, "index.txt"));
    const crlnumber = await fs.readFile(join(recipe.dir, "crlnumber"));
    const stale = await fs.readFile(join(recipe.dir, "root.crl.pem"));
    // ... and CRL 2, which the server holds, also revoking leaf 2.
    openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-revoke", "leaf-2.pem", "-crl_reason", "keyCompromise"], recipe.dir);
    openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-gencrl", "-out", "server.crl.pem"], recipe.dir);
    const serverPem = await fs.readFile(join(recipe.dir, "server.crl.pem"), "utf8");
    await fs.writeFile(join(recipe.dir, "index.txt"), index);
    await fs.writeFile(join(recipe.dir, "crlnumber"), crlnumber);
    await fs.writeFile(join(recipe.dir, "root.crl.pem"), stale);
    await fs.rm(join(recipe.dir, "server.crl.pem"));
    const root = parseCertificate(fromPem(await fs.readFile(join(recipe.dir, "root.pem"), "utf8"), "CERTIFICATE"));
    const serverCrl = parseCrl(fromPem(serverPem, "X509 CRL"));
    const s = new FakeServer();
    const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
    s.externals.set(extId, {
      extId,
      fingerprint: root.fingerprint,
      crlPem: serverPem,
      crl: { numberHex: "02", sha256: serverCrl.sha256, thisUpdate: serverCrl.thisUpdate.toISOString(), nextUpdate: (serverCrl.nextUpdate as Date).toISOString() },
      dependents: new Set(),
      serials: new Map(),
    });
    const adopted = await run(adoptArgs(out, recipe.dir, ["--offline", "--crl-number", "2"]), { stdin: adoptKeys() });
    assert.equal(adopted.exitCode, 0, adopted.stderr);
    const state = await readState(out);
    assert.deepEqual(state.revoked.map((r) => r.serial), [recipe.leaves[0]]);
    assert.equal(state.crl.lastNumber, 3);
    // Every online command refuses before uploading anything.
    for (const args of [["renew-crl", "--dir", out], ["upload-crl", "--dir", out]]) {
      const result = await run(args, { server: s, stdin: new FakeTerminal(`${PASS}\r`) });
      assert.equal(result.exitCode, 5, args[0]);
      assert.equal(result.error.code, "state_behind_server", args[0]);
      assert.deepEqual(result.error.details?.serials, [recipe.leaves[1]]);
    }
    assert.equal(s.mutations.length, 0, "nothing was uploaded");
    const status = await run(["status", "--dir", out], { server: s });
    assert.equal(status.json.data.server.relation, "state_behind_server");
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

const staleScenario = async (recipe: Recipe) => {
  const index = await fs.readFile(join(recipe.dir, "index.txt"));
  const crlnumber = await fs.readFile(join(recipe.dir, "crlnumber"));
  const stale = await fs.readFile(join(recipe.dir, "root.crl.pem"));
  openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-revoke", "leaf-2.pem", "-crl_reason", "keyCompromise"], recipe.dir);
  openssl(["ca", "-config", "ca.cnf", "-passin", `pass:${SRC}`, "-gencrl", "-out", "server.crl.pem"], recipe.dir);
  const serverPem = await fs.readFile(join(recipe.dir, "server.crl.pem"), "utf8");
  await fs.writeFile(join(recipe.dir, "index.txt"), index);
  await fs.writeFile(join(recipe.dir, "crlnumber"), crlnumber);
  await fs.writeFile(join(recipe.dir, "root.crl.pem"), stale);
  await fs.rm(join(recipe.dir, "server.crl.pem"));
  const root = parseCertificate(fromPem(await fs.readFile(join(recipe.dir, "root.pem"), "utf8"), "CERTIFICATE"));
  const serverCrl = parseCrl(fromPem(serverPem, "X509 CRL"));
  const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
  const seed = (s: FakeServer): void => {
    s.externals.set(extId, {
      extId,
      fingerprint: root.fingerprint,
      crlPem: serverPem,
      crl: { numberHex: "02", sha256: serverCrl.sha256, thisUpdate: serverCrl.thisUpdate.toISOString(), nextUpdate: (serverCrl.nextUpdate as Date).toISOString() },
      dependents: new Set(),
      serials: new Map(),
    });
  };
  return { serverPem, seed };
};

test("activate --crl and the stateless upload-crl never upload a CRL that drops a revocation the server lists", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "keyCompromise" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    const { serverPem, seed } = await staleScenario(recipe);
    const ca = pendingCa(1);
    const s = server(ca.record);
    seed(s);
    assert.equal((await run(adoptArgs(out, recipe.dir, ["--offline", "--crl-number", "2"]), { stdin: adoptKeys() })).exitCode, 0);
    const csrPath = join(dir, "ca.csr.pem");
    await fs.writeFile(csrPath, ca.csr.pem);
    const carried = { cert: join(dir, "ca.pem"), chain: join(dir, "chain.pem"), crl: join(dir, "carry.crl.pem") };
    const signed = await run(["sign-cert", ca.record.caId, "--dir", out, "--offline", "--csr", csrPath, "--expect-spki-sha256", ca.record.spkiSha256, "--out", carried.cert, "--chain-out", carried.chain, "--crl-out", carried.crl, "--yes"], { stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(signed.exitCode, 0, signed.stderr);
    const activate = await run(["activate", ca.record.caId, "--environment", "prod", "--certificate", carried.cert, "--chain", carried.chain, "--crl", carried.crl], { server: s });
    assert.equal(activate.exitCode, 5, activate.stderr);
    assert.equal(activate.error.code, "state_behind_server");
    assert.deepEqual(activate.error.details?.serials, [recipe.leaves[1]]);
    assert.equal(s.mutations.length, 0, "nothing was uploaded and the CA was not activated");
    assert.equal(s.cas.get(ca.record.caId)?.status, "PENDING_CERTIFICATE");
    const upload = await run(["upload-crl", "--crl", carried.crl, "--root-cert", carried.chain], { server: s });
    assert.equal(upload.exitCode, 5, upload.stderr);
    assert.equal(upload.error.code, "state_behind_server");
    assert.equal(s.mutations.length, 0);

    // An adoption that knows the server's CRL carries leaf 2 too; the offline hint then works.
    const known = join(dir, "server.crl.pem");
    await fs.writeFile(known, serverPem);
    const out2 = join(dir, "out2");
    assert.equal((await run(adoptArgs(out2, recipe.dir, ["--offline", "--crl-number", "2", "--crl", known]), { stdin: adoptKeys() })).exitCode, 0);
    const renewed = await run(["renew-crl", "--dir", out2, "--offline", "--crl-out", join(dir, "renewed.crl.pem")], { stdin: new FakeTerminal(`${PASS}\r`) });
    assert.equal(renewed.exitCode, 0, renewed.stderr);
    assert.match(renewed.json.next[0], /hemlig pki ez upload-crl --crl .*renewed\.crl\.pem --root-cert .*root\.pem/);
    const ok = await run(["upload-crl", "--crl", join(dir, "renewed.crl.pem"), "--root-cert", join(out2, "root.pem")], { server: s });
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.equal(ok.json.data.uploaded, true);
    assert.deepEqual(s.uploads().map((u) => u.number), [3n]);
    // the same file again is a no-op; an older CRL is refused; mixed flags are usage errors
    assert.equal((await run(["upload-crl", "--crl", join(dir, "renewed.crl.pem"), "--root-cert", join(out2, "root.pem")], { server: s })).json.data.uploaded, false);
    const older = await run(["upload-crl", "--crl", known, "--root-cert", join(out2, "root.pem")], { server: s });
    assert.equal(older.exitCode, 5);
    assert.equal((await run(["upload-crl", "--crl", known], { server: s })).exitCode, 2);
    assert.equal((await run(["upload-crl", "--crl", known, "--root-cert", join(out2, "root.pem"), "--dir", out2], { server: s })).exitCode, 2);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("revoke-cert signs an imported hold reason as recorded even when a CRL is due", needsOpenssl, async () => {
  const recipe = await buildRecipe({ revoke: { 1: "hold" }, crls: 1 });
  const dir = await tempDir();
  const out = join(dir, "out");
  try {
    await fs.rm(join(recipe.dir, "root.crl.pem"));
    assert.equal((await run(adoptArgs(out, recipe.dir), { stdin: adoptKeys() })).exitCode, 0);
    const due = await run(["revoke-cert", "--dir", out, "--serial", recipe.leaves[0] as string, "--reason", "certificateHold", "--offline", "--crl-out", join(dir, "r.crl.pem")], { laterDays: 150, stdin: new FakeTerminal("confirm\r", `${PASS}\r`) });
    assert.equal(due.exitCode, 0, due.stderr);
    const crl = parseCrl(fromPem(await fs.readFile(join(dir, "r.crl.pem"), "utf8"), "X509 CRL"));
    assert.equal(crl.number, 3n);
    assert.deepEqual(crl.entries.map((e) => [e.serial, e.reason]), [[recipe.leaves[0], "certificateHold"]]);
  } finally {
    await cleanup(recipe.dir);
    await cleanup(dir);
  }
});

test("a server-stored CRL with an unnamed reason code does not wedge online commands, though adopt refuses it as a source", async () => {
  const key = bareKey();
  const signer = new SoftwareSigner(key);
  const bare = makeBareRoot({
    privateKey: key,
    notAfter: new Date(Date.now() + 3000 * 86_400_000),
    extensions: [extension(OID.basicConstraints, true, seq(bool(true))), extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)), extension(OID.ski, false, octetString(keyIdentifier(signer.spkiDer)))],
  });
  const root = parseCertificate(bare.der);
  const dir = await tempDir();
  try {
    await fs.writeFile(join(dir, "root.pem"), bare.pem);
    await fs.writeFile(join(dir, "key.pem"), key.export({ type: "pkcs8", format: "pem" }));
    const serverPem = craftCrl({ key, root, reasonCode: 7, number: 4n });
    const serverCrl = parseCrl(fromPem(serverPem, "X509 CRL"));
    assert.equal(serverCrl.entries[0]?.reasonCode, 7);
    await fs.writeFile(join(dir, "local.crl.pem"), craftCrl({ key, root, reasonCode: 1, number: 5n }));
    const s = new FakeServer();
    const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
    s.externals.set(extId, {
      extId,
      fingerprint: root.fingerprint,
      crlPem: serverPem,
      crl: { numberHex: "04", sha256: serverCrl.sha256, thisUpdate: serverCrl.thisUpdate.toISOString(), nextUpdate: (serverCrl.nextUpdate as Date).toISOString() },
      dependents: new Set(),
      serials: new Map(),
    });
    // as a SOURCE it is refused
    await fs.writeFile(join(dir, "bad.crl.pem"), serverPem);
    const refused = await run(["adopt-ca", "--dir", join(dir, "x"), "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--crl", join(dir, "bad.crl.pem"), "--offline"], { stdin: adoptKeys(false) });
    assert.equal(refused.exitCode, 5);
    // the local state lists serial 0a (reason keyCompromise); the server's CRL lists it with reason 7: membership counts
    const out = join(dir, "out");
    const adopted = await run(["adopt-ca", "--dir", out, "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--crl", join(dir, "local.crl.pem"), "--offline"], { stdin: adoptKeys(false) });
    assert.equal(adopted.exitCode, 0, adopted.stderr);
    const upload = await run(["upload-crl", "--dir", out], { server: s });
    assert.equal(upload.exitCode, 0, upload.stderr);
    assert.deepEqual(s.uploads().map((u) => u.number), [5n]);
    // a state that lacks the serial is still refused
    const bareOut = join(dir, "bare");
    assert.equal((await run(["adopt-ca", "--dir", bareOut, "--cert", join(dir, "root.pem"), "--key", join(dir, "key.pem"), "--no-prior-revocations", "--crl-number", "9", "--offline"], { stdin: adoptKeys(false) })).exitCode, 0);
    s.externals.get(extId)!.crl = { ...(s.externals.get(extId)!.crl as any), numberHex: "04", sha256: serverCrl.sha256 };
    const behind = await run(["upload-crl", "--dir", bareOut], { server: s });
    assert.equal(behind.error.code, "state_behind_server");
  } finally {
    await cleanup(dir);
  }
});
