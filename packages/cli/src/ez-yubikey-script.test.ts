import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { YUBIKEY_SCRIPT } from "./ez-yubikey-script";

/**
 * Runs the real embedded Python script under `python3` against fake `yubikit`, `ykman` and `cryptography` modules.
 * It checks the operation allowlist, slot scoping, device selection and error mapping with no hardware. The fakes log
 * every PIV call with the slot it named. Skipped when python3 is absent, required when CI is set.
 */

const haveAll = ((): boolean => {
  const probe = spawnSync("python3", ["--version"]);
  return probe.status === 0;
})();

const FAKES: Record<string, string> = {
  "cryptography/__init__.py": "",
  "cryptography/hazmat/__init__.py": "",
  "cryptography/hazmat/primitives/__init__.py": "",
  "cryptography/hazmat/primitives/hashes.py": "class SHA256:\n    name='sha256'\nclass SHA384:\n    name='sha384'\n",
  "cryptography/hazmat/primitives/serialization.py": `
class Encoding:
    DER = 'DER'
class PublicFormat:
    SubjectPublicKeyInfo = 'spki'
class _Pub:
    def __init__(self, raw): self.raw = raw
    def public_bytes(self, enc, fmt): return self.raw
class _Priv:
    def __init__(self, raw): self.raw = raw
    def public_key(self): return _Pub(self.raw[:8])
def load_der_private_key(data, password): return _Priv(data)
`,
  "cryptography/hazmat/primitives/asymmetric/__init__.py": "",
  "cryptography/hazmat/primitives/asymmetric/padding.py": "class PKCS1v15:\n    pass\n",
  "cryptography/x509.py": "class _Cert:\n    def __init__(self, d): self.d = d\n    def public_bytes(self, enc): return self.d\ndef load_der_x509_certificate(d): return _Cert(d)\n",
  "yubikit/__init__.py": "",
  "yubikit/core/__init__.py": `
class CommandError(Exception): pass
class BadResponseError(CommandError): pass
class NotSupportedError(ValueError): pass
class InvalidPinError(CommandError, ValueError):
    def __init__(self, attempts_remaining, message=None):
        Exception.__init__(self, message or 'invalid pin')
        self.attempts_remaining = attempts_remaining
`,
  "yubikit/core/smartcard/__init__.py": `
from yubikit.core import CommandError
class ApduError(CommandError):
    def __init__(self, data, sw):
        self.data = data
        self.sw = sw
class SmartCardConnection: pass
`,
  "yubikit/piv.py": `
import json, os
from enum import IntEnum
from yubikit.core import InvalidPinError, NotSupportedError
from yubikit.core.smartcard import ApduError

class SLOT(IntEnum):
    AUTHENTICATION = 0x9A
    SIGNATURE = 0x9C
    KEY_MANAGEMENT = 0x9D
    CARD_AUTH = 0x9E
    RETIRED1 = 0x82
class KEY_TYPE(IntEnum):
    ECCP256 = 0x11
    ECCP384 = 0x14
    RSA2048 = 0x07
    RSA3072 = 0x05
class PIN_POLICY(IntEnum):
    ALWAYS = 3
    ONCE = 2
class TOUCH_POLICY(IntEnum):
    NEVER = 1
    ALWAYS = 2
    CACHED = 3
class MANAGEMENT_KEY_TYPE(IntEnum):
    TDES = 3
    AES256 = 12
    @property
    def key_len(self): return 24 if self.name == 'TDES' else 32

def world(): return json.load(open(os.environ['FAKE_WORLD']))
def log(entry):
    with open(os.environ['FAKE_LOG'], 'a') as f: f.write(json.dumps(entry) + '\\n')
def save(w): json.dump(w, open(os.environ['FAKE_WORLD'], 'w'))

class _Pub:
    def __init__(self, raw): self.raw = raw
    def public_bytes(self, enc, fmt): return self.raw
class _Obj:
    def __init__(self, **kw): self.__dict__.update(kw)

class PivSession:
    def __init__(self, connection):
        self.dev = connection.dev
        self.version = tuple(self.dev['version'])
        self.pin_ok = False
    def _slot(self, slot):
        log({'m': sys._getframe(1).f_code.co_name, 'slot': int(slot)})
        return self.dev['slots'].get(str(int(slot)))
    def get_pin_metadata(self): return _Obj(default_value=False, total_attempts=3, attempts_remaining=self.dev['attempts'])
    def get_management_key_metadata(self):
        return _Obj(key_type=MANAGEMENT_KEY_TYPE.TDES, default_value=self.dev['mgmt_default'], touch_policy=TOUCH_POLICY.NEVER)
    def get_slot_metadata(self, slot):
        s = self._slot(slot)
        if s is None: raise ApduError(b'', 0x6A88)
        return _Obj(key_type=KEY_TYPE[s['key_type']], pin_policy=PIN_POLICY.ALWAYS, touch_policy=TOUCH_POLICY.ALWAYS,
                    generated=False, public_key=_Pub(bytes.fromhex(s['spki'])))
    def get_certificate(self, slot):
        s = self._slot(slot)
        if s is None or not s.get('cert'): raise ApduError(b'', 0x6A82)
        return _Obj(public_bytes=lambda enc: bytes.fromhex(s['cert']))
    def verify_pin(self, pin):
        if self.dev['attempts'] == 0: raise ApduError(b'', 0x6983)
        if pin != self.dev['pin']:
            raise InvalidPinError(self.dev['attempts'] - 1)
        self.pin_ok = True
    def authenticate(self, key):
        if key.hex() != self.dev['mgmt_key']: raise ApduError(b'', 0x6982)
    def check_key_support(self, key_type, pin, touch, generate):
        if key_type == KEY_TYPE.RSA3072 and self.version < (5, 7, 0): raise NotSupportedError('x')
    def sign(self, slot, key_type, message, hash_algorithm, padding=None):
        self._slot(slot)
        # PIN policy ALWAYS: each signature consumes the PIN verification.
        if not self.pin_ok: raise ApduError(b'', 0x6982)
        self.pin_ok = False
        return b'SIG' + message[:4]
    def put_key(self, slot, key, pin, touch):
        self._slot(slot)
        return KEY_TYPE.ECCP384
    def generate_key(self, slot, key_type, pin, touch):
        self._slot(slot)
        return _Pub(bytes.fromhex('aabbccdd'))
    def put_certificate(self, slot, cert, compress=False): self._slot(slot)
import sys
`,
  "ykman/__init__.py": "",
  "ykman/device.py": `
import json, os
from yubikit.piv import world
class _Info:
    def __init__(self, d):
        self.serial = d['serial']
        self.version = tuple(d['version'])
        self.is_fips = False
class _Conn:
    def __init__(self, dev): self.dev = dev
    def close(self): pass
class _Dev:
    def __init__(self, d): self.d = d
    def open_connection(self, kind): return _Conn(self.d)
def list_all_devices():
    w = world()
    return [(_Dev(d), _Info(d)) for d in w['devices']]
`,
  "ykman/piv.py": `
import os
class _Pivman:
    has_derived_key = False
    has_stored_key = False
    has_protected_key = False
    salt = None
def get_pivman_data(piv): return _Pivman()
def get_pivman_protected_data(piv): raise ValueError('none')
def derive_management_key(pin, salt): return b''
def pivman_set_mgm_key(piv, key, algorithm, touch=False, store=False): raise AssertionError('must not be reached for a non-default key')
`,
};

const DEFAULT_KEY = "010203040506070801020304050607080102030405060708";

interface World {
  devices: {
    serial: number;
    version: [number, number, number];
    pin: string;
    attempts: number;
    mgmt_default: boolean;
    mgmt_key: string;
    slots: Record<string, { key_type: string; spki: string; cert?: string }>;
  }[];
}

const device = (serial: number, extra: Partial<World["devices"][number]> = {}): World["devices"][number] => ({
  serial,
  version: [5, 4, 3],
  pin: "123456",
  attempts: 3,
  mgmt_default: true,
  mgmt_key: DEFAULT_KEY,
  slots: {
    "156": { key_type: "ECCP384", spki: "0102030405060708" },
    "154": { key_type: "ECCP384", spki: "2122232425262728" },
    "130": { key_type: "ECCP256", spki: "1112131415161718", cert: "aabb" },
  },
  ...extra,
});

const withPython = (name: string, fn: (run: (world: World, request: Record<string, unknown>) => Promise<{ result: any; stderr: string; stdout: string; log: any[] }>) => Promise<void>): void => {
  test(name, { skip: !haveAll && process.env.CI === undefined }, async () => {
    assert.ok(haveAll, "python3 is required in CI");
    const dir = await fs.mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "ez-py-"));
    try {
      for (const [file, content] of Object.entries(FAKES)) {
        await fs.mkdir(join(dir, "fakes", file, ".."), { recursive: true });
        await fs.writeFile(join(dir, "fakes", file), content);
      }
      await fs.mkdir(join(dir, "script"));
      await fs.writeFile(join(dir, "script", "hemlig_ez_piv.py"), YUBIKEY_SCRIPT);
      await fn(async (world, request) => {
        await fs.writeFile(join(dir, "world.json"), JSON.stringify(world));
        await fs.rm(join(dir, "log.jsonl"), { force: true });
        const out = spawnSync("python3", [join(dir, "script", "hemlig_ez_piv.py")], {
          input: `${JSON.stringify({ v: 1, ...request })}\n`,
          env: { ...process.env, PYTHONPATH: join(dir, "fakes"), FAKE_WORLD: join(dir, "world.json"), FAKE_LOG: join(dir, "log.jsonl"), PYTHONDONTWRITEBYTECODE: "1" },
          encoding: "utf8",
        });
        const frame = out.stdout.split("\n").find((l) => l.startsWith("HEMLIG-EZ-RESULT "));
        assert.ok(frame !== undefined, `no result frame; stderr: ${out.stderr}`);
        const log = (await fs.readFile(join(dir, "log.jsonl"), "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
        assert.equal(out.stderr.includes("Traceback"), false, out.stderr);
        return { result: JSON.parse(frame.slice("HEMLIG-EZ-RESULT ".length)), stderr: out.stderr, stdout: out.stdout, log };
      });
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
};

const world = (...devices: World["devices"]): World => ({ devices });

withPython("script: list and info are read-only and name only the requested slot", async (run) => {
  const w = world(device(111));
  assert.deepEqual((await run(w, { op: "list" })).result.devices, [{ serial: 111, firmware: "5.4.3", fips: false }]);
  const info = await run(w, { op: "info", serial: null, slot: "9c" });
  assert.equal(info.result.ok, true);
  assert.equal(info.result.key.keyType, "ECCP384");
  assert.equal(info.result.certificate, null);
  assert.equal(info.result.pin.attemptsRemaining, 3);
  assert.deepEqual(new Set(info.log.map((e) => e.slot)), new Set([0x9c]));
  const empty = await run(world(device(111, { slots: {} })), { op: "info", slot: "9c" });
  assert.equal(empty.result.key, null);
  const retired = await run(w, { op: "info", slot: "82" });
  assert.equal(retired.result.certificate, "qrs=");
  assert.deepEqual(new Set(retired.log.map((e) => e.slot)), new Set([0x82]));
});

withPython("script: slots 9e, f9 and out-of-range are refused before any device access; unknown ops are refused", async (run) => {
  const w = world(device(111));
  for (const slot of ["9e", "f9", "96", "81", "9b", "zz"]) {
    const r = await run(w, { op: "info", slot });
    assert.equal(r.result.code, "slot_not_allowed", slot);
    assert.deepEqual(r.log, []);
  }
  for (const op of ["reset", "delete-key", "move-key", "attest", "set-pin", ""]) {
    const r = await run(w, { op, slot: "9c" });
    assert.equal(r.result.code, "invalid_request", op);
    assert.deepEqual(r.log, []);
  }
  assert.equal((await run(w, { op: "info", slot: "9c", v: 2 } as never)).result.code, "invalid_request", "an unknown protocol version is refused");
});

withPython("script: device selection and firmware", async (run) => {
  const many = world(device(111), device(222));
  assert.equal((await run(many, { op: "info", slot: "9c" })).result.code, "yubikey_multiple");
  assert.equal((await run(many, { op: "info", slot: "9c", serial: 222 })).result.device.serial, 222);
  assert.equal((await run(many, { op: "info", slot: "9c", serial: 333 })).result.code, "yubikey_not_found");
  assert.equal((await run(world(), { op: "info", slot: "9c" })).result.code, "yubikey_not_found");
  assert.equal((await run(world(device(111, { version: [5, 2, 7] })), { op: "info", slot: "9c" })).result.code, "yubikey_firmware_unsupported");
});

withPython("script: sign verifies the PIN, announces touches, and maps PIN errors", async (run) => {
  const w = world(device(111));
  const ok = await run(w, { op: "sign", slot: "9c", pin: "123456", items: [{ id: "root-certificate", data: Buffer.from("tbs-data").toString("base64") }] });
  assert.equal(ok.result.ok, true);
  assert.match(ok.stderr, /^HEMLIG-EZ-NOTICE touch root-certificate$/m);
  assert.equal(Buffer.from(ok.result.signatures[0], "base64").toString(), "SIGtbs-");
  assert.deepEqual(new Set(ok.log.map((e) => e.slot)), new Set([0x9c]));
  const bad = await run(world(device(111)), { op: "sign", slot: "9c", pin: "000000", items: [] });
  assert.equal(bad.result.code, "pin_invalid");
  assert.equal(bad.result.attemptsRemaining, 2);
  assert.equal((await run(world(device(111, { attempts: 1 })), { op: "sign", slot: "9c", pin: "000000", items: [] })).result.code, "pin_blocked");
  assert.equal((await run(world(device(111, { attempts: 0 })), { op: "sign", slot: "9c", pin: "123456", items: [] })).result.code, "pin_blocked");
  assert.equal((await run(world(device(111, { slots: {} })), { op: "sign", slot: "9c", pin: "123456", items: [{ id: "a", data: "AA==" }] })).result.code, "slot_empty");
});

withPython("script: a batch re-verifies the PIN for every signature (PIN policy always)", async (run) => {
  const items = ["certificate", "crl"].map((id) => ({ id, data: Buffer.from(`tbs-${id}`).toString("base64") }));
  const r = await run(world(device(111)), { op: "sign", slot: "9c", pin: "123456", items });
  assert.equal(r.result.ok, true, JSON.stringify(r.result));
  assert.equal(r.result.signatures.length, 2);
  assert.equal(r.stderr.match(/HEMLIG-EZ-NOTICE touch/g)?.length, 2);
});

withPython("script: an empty slot reports no key and no certificate", async (run) => {
  const w = world(device(111, { slots: {} }));
  const none = await run(w, { op: "info", slot: "9c" });
  assert.equal(none.result.certificate, null);
});

withPython("script: writes refuse an occupied slot, authenticate, and touch only the chosen slot", async (run) => {
  const key = Buffer.from("0102030405060708aa", "hex").toString("base64");
  const put = (extra: Record<string, unknown>) => ({ op: "put-key", slot: "9c", keyDer: key, touchPolicy: "always", pinPolicy: "always", managementKey: { mode: "default" }, ...extra });
  const occupied = await run(world(device(111)), put({}));
  assert.equal(occupied.result.code, "slot_occupied");
  const ok = await run(world(device(111)), put({ overwrite: true }));
  assert.equal(ok.result.ok, true);
  assert.deepEqual(new Set(ok.log.map((e) => e.slot).filter((s) => s !== null)), new Set([0x9c]));
  const badKey = await run(world(device(111, { mgmt_key: "ff".repeat(24), mgmt_default: false })), put({ overwrite: true }));
  assert.equal(badKey.result.code, "management_key_invalid");
  const hexOk = await run(world(device(111, { mgmt_key: "ff".repeat(24), mgmt_default: false })), put({ overwrite: true, managementKey: { mode: "hex", hex: "ff".repeat(24) } }));
  assert.equal(hexOk.result.ok, true);
  const rsa = await run(world(device(111)), { op: "generate", slot: "9c", keyType: "RSA3072", touchPolicy: "always", overwrite: true, managementKey: { mode: "default" } });
  assert.equal(rsa.result.code, "yubikey_algorithm_unsupported");
  const check = await run(world(device(111)), { op: "check-management-key", slot: "9c", managementKey: { mode: "hex", hex: "00".repeat(24) } });
  assert.equal(check.result.code, "management_key_invalid");
  assert.deepEqual(check.log.filter((e) => e.m !== "authenticate" && e.slot !== null), [], "authentication only; no slot access");
  const protect = await run(world(device(111, { mgmt_default: false })), { op: "protect-management-key", slot: "9c", pin: "123456" });
  assert.equal(protect.result.code, "management_key_not_default");
});

withPython("script: certificates go only into an existing key's slot", async (run) => {
  const cert = Buffer.from("cert").toString("base64");
  const noKey = await run(world(device(111, { slots: {} })), { op: "put-certificate", slot: "9c", certificateDer: cert, managementKey: { mode: "default" } });
  assert.equal(noKey.result.code, "slot_empty");
  const w = world(device(111));
  const ok = await run(w, { op: "put-certificate", slot: "9c", certificateDer: cert, managementKey: { mode: "default" } });
  assert.equal(ok.result.ok, true);
  const existing = await run(w, { op: "put-certificate", slot: "82", certificateDer: cert, managementKey: { mode: "default" } });
  assert.equal(existing.result.code, "slot_occupied");
});
