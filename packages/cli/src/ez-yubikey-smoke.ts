/**
 * Opt-in YubiKey hardware smoke for `hemlig pki ez` (never run by CI or `yarn test`, and not published). It exercises
 * the real flow on ONE YubiKey and ONE slot (9c):
 *
 *   HEMLIG_EZ_YUBIKEY_SERIAL=<serial> [HEMLIG_EZ_YUBIKEY_DENY=<serial>,<serial>] node packages/cli/dist/ez-yubikey-smoke.js
 *
 * - The serial must be given in HEMLIG_EZ_YUBIKEY_SERIAL; there is no default. If it appears in the optional
 *   comma-separated HEMLIG_EZ_YUBIKEY_DENY list, the script refuses before contacting any device.
 * - It imports a throwaway software-generated key into slot 9c with `--overwrite-slot 9c` (touch policy never), makes a
 *   PIN-verified test signature, then signs a CRL with it. No other slot is written.
 * - Before and after, it reads (read-only, metadata and certificate only) slots 9a and 82 and fails if they changed.
 * You type the passphrase, the serial acknowledgement and the PIN yourself; nothing is read from the environment.
 */
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { YkmanClient } from "./ez-yubikey";

const SLOT = "9c";
const NEIGHBORS = ["9a", "82"];

const fail = (message: string): never => {
  process.stderr.write(`ez-yubikey-smoke: ${message}\n`);
  process.exit(2);
};

class SmokeFailure extends Error {}
const abort = (message: string): never => {
  throw new SmokeFailure(message);
};

const main = async (): Promise<void> => {
  const requested = process.env.HEMLIG_EZ_YUBIKEY_SERIAL;
  if (requested === undefined || !/^\d{1,10}$/.test(requested)) fail("set HEMLIG_EZ_YUBIKEY_SERIAL=<serial of the throwaway YubiKey> to run (opt-in).");
  const SMOKE_SERIAL = Number(requested);
  const denied = (process.env.HEMLIG_EZ_YUBIKEY_DENY ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  if (denied.includes(String(SMOKE_SERIAL))) fail(`serial ${SMOKE_SERIAL} is on HEMLIG_EZ_YUBIKEY_DENY and is never used here.`);
  if (process.argv.length > 2) fail("this script takes no arguments.");
  if (process.stdin.isTTY !== true) fail("run it in a terminal; you type the PIN, passphrase and acknowledgements.");

  const client = new YkmanClient({ path: process.env.HEMLIG_YKMAN });
  const serials = (await client.list()).map((d) => d.serial);
  if (!serials.includes(SMOKE_SERIAL)) fail(`YubiKey ${SMOKE_SERIAL} is not connected (found ${serials.join(", ") || "none"}).`);

  const readNeighbors = async (): Promise<string> => {
    const out: Record<string, unknown> = {};
    for (const slot of NEIGHBORS) {
      const info = await client.info(SMOKE_SERIAL, slot);
      out[slot] = { key: info.key === null ? null : { ...info.key, spkiDer: info.key.spkiDer.toString("hex") }, certificate: info.certificateDer?.toString("hex") ?? null };
    }
    return JSON.stringify(out);
  };
  const neighborsBefore = await readNeighbors();

  const work = await fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-yk-smoke-"));
  const main = join(__dirname, "main.js");
  const run = (args: string[]): number =>
    spawnSync(process.execPath, [main, "pki", "ez", ...args], { stdio: "inherit", env: process.env }).status ?? 1;
  try {
    process.stderr.write(`\n[1/3] generate-ca --yubikey into slot ${SLOT} (working directory ${work})\n`);
    const created = run([
      "generate-ca", "--dir", work, "--subject", "CN=Hemlig EZ Smoke Root,O=Hemlig Smoke Test", "--key-algorithm", "ECDSA_P384",
      "--yes", "--yubikey", "--yubikey-serial", String(SMOKE_SERIAL), "--slot", SLOT, "--overwrite-slot", SLOT, "--touch-policy", "never",
    ]);
    if (created !== 0) abort(`generate-ca failed (exit ${created}).`);
    process.stderr.write("\n[2/3] renew-crl --offline: a CRL signed on the YubiKey\n");
    const crl = join(work, "smoke.crl.pem");
    const renewed = run(["renew-crl", "--dir", work, "--offline", "--crl-out", crl, "--yubikey-serial", String(SMOKE_SERIAL)]);
    if (renewed !== 0) abort(`renew-crl failed (exit ${renewed}).`);
    const openssl = spawnSync("openssl", ["crl", "-in", crl, "-CAfile", join(work, "root.pem"), "-noout"], { encoding: "utf8" });
    process.stderr.write(openssl.error === undefined ? `openssl crl verify: ${openssl.status === 0 ? "ok" : "FAILED"} ${openssl.stderr.trim()}\n` : "openssl not found; skipped the independent CRL check.\n");
    if (openssl.error === undefined && openssl.status !== 0) abort("the CRL signed on the YubiKey did not verify with openssl.");

    process.stderr.write("\n[3/3] checking that slots 9a and 82 are unchanged\n");
    const neighborsAfter = await readNeighbors();
    if (neighborsAfter !== neighborsBefore) abort("slot 9a or 82 CHANGED. Investigate before using this key.");
    process.stderr.write(`\nSmoke passed on YubiKey ${SMOKE_SERIAL}: slot ${SLOT} written and used; 9a and 82 unchanged.\n`);
  } finally {
    if (process.env.HEMLIG_EZ_SMOKE_KEEP === undefined) await fs.rm(work, { recursive: true, force: true });
    else process.stderr.write(`kept ${work}\n`);
  }
};

void main().catch((error: unknown) => fail(error instanceof Error ? error.message : "unexpected error"));
