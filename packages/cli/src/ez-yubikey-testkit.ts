import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

/**
 * Test double for `ykman` (not used at runtime): a Node executable that speaks the `ykman script --force <file>`
 * protocol of `ez-yubikey-script.ts`, backed by a simulated set of devices in a JSON file next to it. It keeps a log of
 * every call (argv and the non-secret request fields) so tests can assert which slots were addressed.
 */

/** Serials the test kit refuses to simulate or address: `HEMLIG_EZ_YUBIKEY_DENY` (comma-separated), read at call time. */
export const forbiddenSerials = (): number[] =>
  (process.env.HEMLIG_EZ_YUBIKEY_DENY ?? "").split(",").map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0);

export interface FakeSlot {
  keyType: string;
  pinPolicy: string;
  touchPolicy: string;
  generated: boolean;
  /** PKCS#8 DER, base64 (the simulated private key). */
  priv: string;
  spki: string;
  cert: string | null;
}

export interface FakeDevice {
  serial: number;
  firmware: string;
  fips: boolean;
  pin: string;
  pinAttempts: number;
  pinDefault: boolean;
  mgmt: { keyType: string; key: string; default: boolean };
  pivmanProtected: boolean;
  slots: Record<string, FakeSlot>;
}

export interface FakeBehavior {
  rawSignatures?: boolean;
  corruptSignature?: boolean;
  touchTimeout?: boolean;
  /** put-key reports success but stores nothing (simulates a write that did not take). */
  forgetKeys?: boolean;
}

export interface FakeState {
  devices: FakeDevice[];
  behavior: FakeBehavior;
}

export interface FakeCall {
  argv: string[];
  scriptSha256: string;
  scriptPath: string;
  op: string;
  serial: number | null;
  slot: string | null;
  items?: string[];
  keyType?: string;
  overwrite?: boolean;
  managementMode?: string;
  /** True when the request carried a PIN (it only ever arrives on stdin). */
  hadPin?: boolean;
}

const DEFAULT_MGMT_KEY = "010203040506070801020304050607080102030405060708";

export const randomSlot = (keyType = "ECCP384", extra: Partial<FakeSlot> = {}): FakeSlot => {
  const pair = keyType === "ECCP256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("ec", { namedCurve: "P-384" });
  return {
    keyType,
    pinPolicy: "always",
    touchPolicy: "never",
    generated: true,
    priv: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    spki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    cert: null,
    ...extra,
  };
};

/** A device modeled on a 5.4.3 Nano (TDES default management key); slot 9a holds a key and retired slot 82 a certificate. */
export const makeDevice = (serial: number, overrides: Partial<FakeDevice> = {}): FakeDevice => {
  if (forbiddenSerials().includes(serial)) throw new Error(`serial ${serial} is on the deny list and must never be simulated or addressed`);
  return {
    serial,
    firmware: "5.4.3",
    fips: false,
    pin: "123456",
    pinAttempts: 3,
    pinDefault: false,
    mgmt: { keyType: "TDES", key: DEFAULT_MGMT_KEY, default: true },
    pivmanProtected: false,
    slots: {
      "9a": randomSlot("ECCP384", { cert: null }),
      "82": { ...randomSlot("ECCP256"), cert: Buffer.from("not-a-real-certificate").toString("base64") },
    },
    ...overrides,
  };
};

const FAKE_SOURCE = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const dir = __dirname;
const statePath = path.join(dir, "state.json");
const logPath = path.join(dir, "calls.jsonl");
const FORBIDDEN = ${JSON.stringify(forbiddenSerials())};
const SLOTS = ["9a", "9c", "9d"].concat(Array.from({ length: 20 }, (_, i) => (0x82 + i).toString(16)));
const argv = process.argv.slice(2);
const emit = (obj) => process.stdout.write("HEMLIG-EZ-RESULT " + JSON.stringify(obj) + "\n");
const fail = (code, message, extra) => { emit(Object.assign({ ok: false, code, message }, extra || {})); process.exit(0); };
const version = (f) => f.split(".").map(Number);
const atLeast = (f, a, b) => { const v = version(f); return v[0] > a || (v[0] === a && v[1] >= b); };

if (argv[0] !== "script" || argv[1] !== "--force" || argv.length !== 3) { process.stderr.write("bad argv\n"); process.exit(64); }
const scriptPath = argv[2];
const scriptSource = fs.readFileSync(scriptPath);
if (scriptPath !== "/dev/fd/3") { process.stderr.write("the script must arrive on /dev/fd/3\n"); process.exit(65); }
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  const req = JSON.parse(input.split("\n")[0]);
  const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  const call = { argv, scriptSha256: crypto.createHash("sha256").update(scriptSource).digest("hex"), scriptPath, op: req.op, serial: req.serial === undefined ? null : req.serial, slot: req.slot === undefined ? null : req.slot };
  if (req.items) call.items = req.items.map((i) => i.id);
  if (req.keyType) call.keyType = req.keyType;
  if (req.overwrite !== undefined) call.overwrite = req.overwrite;
  if (req.managementKey) call.managementMode = req.managementKey.mode;
  call.hadPin = typeof req.pin === "string";
  fs.appendFileSync(logPath, JSON.stringify(call) + "\n");
  const save = () => fs.writeFileSync(statePath, JSON.stringify(state));
  const behavior = state.behavior || {};
  if (req.v !== 1) fail("invalid_request", "Unsupported request.");
  if (req.op === "list") { emit({ ok: true, devices: state.devices.map((d) => ({ serial: d.serial, firmware: d.firmware, fips: d.fips })) }); return; }
  let device;
  if (req.serial === null || req.serial === undefined) {
    if (state.devices.length === 0) fail("yubikey_not_found", "No YubiKey is connected.");
    if (state.devices.length > 1) fail("yubikey_multiple", "More than one YubiKey is connected.");
    device = state.devices[0];
  } else {
    device = state.devices.find((d) => d.serial === req.serial);
    if (!device) fail("yubikey_not_found", "No connected YubiKey has that serial number.");
  }
  if (FORBIDDEN.includes(device.serial)) { process.stderr.write("refused: serial is on the deny list\n"); process.exit(99); }
  if (!atLeast(device.firmware, 5, 3)) fail("yubikey_firmware_unsupported", "YubiKey firmware 5.3 or later is required.");
  if (!SLOTS.includes(req.slot)) fail("slot_not_allowed", "That PIV slot cannot be used.");
  const slot = req.slot;
  const verifyPin = () => {
    if (device.pinAttempts === 0) fail("pin_blocked", "The PIN is blocked.");
    if (req.pin !== device.pin) {
      device.pinAttempts -= 1; save();
      if (device.pinAttempts === 0) fail("pin_blocked", "The PIN is blocked.");
      fail("pin_invalid", "The PIN is incorrect.", { attemptsRemaining: device.pinAttempts });
    }
    device.pinAttempts = 3;
  };
  const authenticate = () => {
    const m = req.managementKey || {};
    if (m.mode === "default") { if (!device.mgmt.default) fail("management_key_invalid", "The management key was not accepted."); return; }
    if (m.mode === "hex") { if (m.hex !== device.mgmt.key) fail("management_key_invalid", "The management key was not accepted."); return; }
    if (m.mode === "pin") { verifyPin(); if (!device.pivmanProtected) fail("management_key_invalid", "no protected key"); return; }
    fail("invalid_request", "A management key mode is required.");
  };
  const supported = (keyType) => {
    if (["RSA3072", "RSA4096", "ED25519"].includes(keyType) && !atLeast(device.firmware, 5, 7)) fail("yubikey_algorithm_unsupported", "The YubiKey does not support that operation.");
  };
  const keyTypeOf = (key) => {
    if (key.asymmetricKeyType === "ec") return key.asymmetricKeyDetails.namedCurve === "prime256v1" ? "ECCP256" : "ECCP384";
    return "RSA" + key.asymmetricKeyDetails.modulusLength;
  };
  const occupied = () => Boolean(device.slots[slot]);
  const writable = () => { if (occupied() && req.overwrite !== true) fail("slot_occupied", "The slot already holds a key or certificate."); };
  switch (req.op) {
    case "info": {
      const s = device.slots[slot];
      emit({ ok: true, device: { serial: device.serial, firmware: device.firmware, fips: device.fips }, slot,
        pin: { default: device.pinDefault, attemptsRemaining: device.pinAttempts },
        management: { keyType: device.mgmt.keyType, default: device.mgmt.default, touchPolicy: "never", pivmanProtected: device.pivmanProtected, pivmanDerived: false },
        key: s && s.priv ? { keyType: s.keyType, pinPolicy: s.pinPolicy, touchPolicy: s.touchPolicy, generated: s.generated, spki: s.spki } : null,
        certificate: s ? s.cert : null });
      return;
    }
    case "sign": {
      verifyPin();
      save();
      const items = req.items || [];
      if (items.length === 0) { emit({ ok: true, signatures: [] }); return; }
      const s = device.slots[slot];
      if (!s || !s.priv) fail("slot_empty", "The slot holds no key.");
      const key = crypto.createPrivateKey({ key: Buffer.from(s.priv, "base64"), format: "der", type: "pkcs8" });
      const out = [];
      for (const item of items) {
        if (s.touchPolicy !== "never") process.stderr.write("HEMLIG-EZ-NOTICE touch " + item.id + "\n");
        if (behavior.touchTimeout && s.touchPolicy !== "never") fail("touch_timeout", "The YubiKey was not touched in time.");
        const data = Buffer.from(item.data, "base64");
        let sig;
        if (key.asymmetricKeyType === "ec") sig = crypto.sign(s.keyType === "ECCP256" ? "sha256" : "sha384", data, { key, dsaEncoding: behavior.rawSignatures ? "ieee-p1363" : "der" });
        else sig = crypto.sign("sha256", data, key);
        if (behavior.corruptSignature) { sig = Buffer.from(sig); sig[sig.length - 1] ^= 0xff; }
        out.push(sig.toString("base64"));
      }
      emit({ ok: true, signatures: out });
      return;
    }
    case "check-management-key": { authenticate(); emit({ ok: true }); return; }
    case "generate": {
      supported(req.keyType);
      writable();
      authenticate();
      const pair = req.keyType === "ECCP256" ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }) : req.keyType === "ECCP384" ? crypto.generateKeyPairSync("ec", { namedCurve: "P-384" }) : crypto.generateKeyPairSync("rsa", { modulusLength: Number(req.keyType.slice(3)) });
      const spki = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
      device.slots[slot] = { keyType: req.keyType, pinPolicy: "always", touchPolicy: req.touchPolicy, generated: true, priv: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"), spki, cert: null };
      save();
      emit({ ok: true, spki });
      return;
    }
    case "put-key": {
      const key = crypto.createPrivateKey({ key: Buffer.from(req.keyDer, "base64"), format: "der", type: "pkcs8" });
      const keyType = keyTypeOf(key);
      supported(keyType);
      writable();
      authenticate();
      if (behavior.forgetKeys) { emit({ ok: true, keyType }); return; }
      device.slots[slot] = { keyType, pinPolicy: "always", touchPolicy: req.touchPolicy, generated: false, priv: req.keyDer, spki: crypto.createPublicKey(key).export({ type: "spki", format: "der" }).toString("base64"), cert: req.certificateDer || null };
      save();
      emit({ ok: true, keyType });
      return;
    }
    case "put-certificate": {
      const s = device.slots[slot];
      if (!s || !s.priv) fail("slot_empty", "The slot holds no key.");
      if (s.cert && req.overwrite !== true) fail("slot_occupied", "The slot already holds a certificate.");
      authenticate();
      s.cert = req.certificateDer;
      save();
      emit({ ok: true });
      return;
    }
    case "protect-management-key": {
      if (!device.mgmt.default) fail("management_key_not_default", "Only the factory default management key is replaced.");
      verifyPin();
      device.mgmt = { keyType: atLeast(device.firmware, 5, 4) ? "AES256" : "TDES", key: crypto.randomBytes(32).toString("hex"), default: false };
      device.pivmanProtected = true;
      save();
      emit({ ok: true, algorithm: device.mgmt.keyType });
      return;
    }
    default:
      fail("invalid_request", "Unsupported request.");
  }
});
`;

export interface FakeYkman {
  readonly path: string;
  readonly dir: string;
  state(): Promise<FakeState>;
  setState(update: (state: FakeState) => void): Promise<void>;
  calls(): Promise<FakeCall[]>;
  /** A stable snapshot of one device's slots other than `except` (to assert nothing else changed). */
  otherSlots(serial: number, except: string): Promise<string>;
  cleanup(): Promise<void>;
}

export const createFakeYkman = async (base: string, devices: FakeDevice[], behavior: FakeBehavior = {}): Promise<FakeYkman> => {
  for (const device of devices) if (forbiddenSerials().includes(device.serial)) throw new Error(`serial ${device.serial} is on the deny list`);
  const dir = await fs.mkdtemp(join(base, "fake-ykman-"));
  const path = join(dir, "ykman");
  await fs.writeFile(path, `#!${process.execPath}\n${FAKE_SOURCE}`, { mode: 0o755 });
  await fs.writeFile(join(dir, "state.json"), JSON.stringify({ devices, behavior } satisfies FakeState));
  const read = async (): Promise<FakeState> => JSON.parse(await fs.readFile(join(dir, "state.json"), "utf8"));
  return {
    path,
    dir,
    state: read,
    async setState(update) {
      const state = await read();
      update(state);
      await fs.writeFile(join(dir, "state.json"), JSON.stringify(state));
    },
    async calls() {
      const text = await fs.readFile(join(dir, "calls.jsonl"), "utf8").catch(() => "");
      return text.split("\n").filter((l) => l !== "").map((l) => JSON.parse(l) as FakeCall);
    },
    async otherSlots(serial, except) {
      const device = (await read()).devices.find((d) => d.serial === serial);
      const slots = Object.entries(device?.slots ?? {}).filter(([name]) => name !== except).sort(([a], [b]) => a.localeCompare(b));
      return JSON.stringify(slots);
    },
    cleanup: () => fs.rm(dir, { recursive: true, force: true }),
  };
};
