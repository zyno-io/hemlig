import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EzError } from "./ez-error";
import { KEY_FILE_ITERATIONS, assertPassphrasePolicy, decryptKeyFile, encryptPkcs8, inspectKeyFile, readPrivateKey } from "./ez-keyfile";
import { generateSoftwareKey } from "./ez-signer";

const passphrase = "correct horse battery staple";

test("round trip: encrypt, inspect, decrypt; the PKCS#8 input is zeroed", () => {
  const key = generateSoftwareKey("ECDSA_P384");
  const pkcs8 = key.exportPkcs8();
  const original = Buffer.from(pkcs8);
  const pem = encryptPkcs8(pkcs8, passphrase);
  assert.ok(pkcs8.every((b) => b === 0), "plaintext zeroed");
  assert.match(pem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/);
  assert.deepEqual(inspectKeyFile(pem), { encrypted: true, kdf: { name: "pbkdf2-hmac-sha256", iterations: 1_000_000 }, cipher: "aes-256-cbc" });
  assert.equal(KEY_FILE_ITERATIONS, 1_000_000);
  const back = decryptKeyFile(pem, passphrase);
  assert.ok(back.export({ type: "pkcs8", format: "der" }).equals(original));
  assert.ok(createPublicKey(back).export({ type: "spki", format: "der" }).equals(key.spkiDer));
});

test("a wrong passphrase exits 3 with passphrase_invalid (also with none)", () => {
  const pem = encryptPkcs8(generateSoftwareKey("ECDSA_P256").exportPkcs8(), passphrase);
  for (const attempt of ["wrong passphrase here", undefined]) {
    assert.throws(
      () => readPrivateKey(pem, attempt),
      (e) => e instanceof EzError && e.exitCode === 3 && e.code === "passphrase_invalid",
    );
  }
});

test("passphrase policy: 12 to 1024 bytes", () => {
  assert.throws(() => assertPassphrasePolicy("short"), (e) => e instanceof EzError && e.code === "invalid_input");
  assert.throws(() => assertPassphrasePolicy("x".repeat(1025)), EzError);
  assertPassphrasePolicy("x".repeat(12));
  assertPassphrasePolicy(Buffer.alloc(1024, 1));
  assert.throws(() => encryptPkcs8(generateSoftwareKey("ECDSA_P256").exportPkcs8(), "short"), EzError);
});

test("reads OpenSSL-style keys: 2048-iteration PBES2, plaintext PKCS#8, legacy encrypted EC", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
  const weak = privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase }) as string;
  assert.equal(inspectKeyFile(weak).kdf?.iterations, 2048);
  assert.equal(readPrivateKey(weak, passphrase).encrypted, true);
  const plain = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  assert.deepEqual(inspectKeyFile(plain), { encrypted: false });
  assert.equal(readPrivateKey(plain).encrypted, false);
  assert.throws(() => decryptKeyFile(plain, passphrase), (e) => e instanceof EzError && e.code === "key_file_invalid");
  const legacy = privateKey.export({ type: "sec1", format: "pem", cipher: "aes-256-cbc", passphrase }) as string;
  assert.equal(readPrivateKey(legacy, passphrase).encrypted, true);
  assert.throws(() => readPrivateKey("not a key"), (e) => e instanceof EzError && e.code === "key_file_invalid");
});

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
if (!haveOpenssl && process.env.CI) {
  test("requires openssl on PATH when CI is set", () => {
    throw new Error("openssl is not on PATH, but CI requires the cross-checks.");
  });
}

test("openssl pkey reads the key file", { skip: !haveOpenssl && "openssl not on PATH" }, () => {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "ez-keyfile-"));
  try {
    const key = generateSoftwareKey("ECDSA_P384");
    writeFileSync(join(dir, "key.pem"), encryptPkcs8(key.exportPkcs8(), passphrase));
    writeFileSync(join(dir, "pass"), passphrase);
    const out = spawnSync("openssl", ["pkey", "-in", join(dir, "key.pem"), "-passin", `file:${join(dir, "pass")}`, "-pubout", "-outform", "DER"], { stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(out.status, 0, out.stderr.toString());
    assert.ok(Buffer.from(out.stdout).equals(key.spkiDer));
    const wrong = spawnSync("openssl", ["pkey", "-in", join(dir, "key.pem"), "-passin", "pass:wrongwrongwrong"], { stdio: ["ignore", "pipe", "pipe"] });
    assert.notEqual(wrong.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
