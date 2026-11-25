import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EzError } from "./ez-error";
import type { RootSigner, SignEvents, SignItem } from "./ez-signer";
import { YUBIKEY_SCRIPT } from "./ez-yubikey-script";
import { describeSpki, signatureAlgorithmForSpki, type EzKeyAlgorithm, type SignatureAlgorithm } from "./ez-x509";

/**
 * YubiKey PIV support for `hemlig pki ez`: a client for the embedded yubikit script (run by `ykman script --force`),
 * the safety rails that run before anything is written to a device, and `YubiKeySigner`.
 *
 * Every request names exactly one slot and the script has no operation that takes a second one; nothing here deletes,
 * moves or resets anything.
 */

export const PIN_POLICIES = ["always"] as const;
export const TOUCH_POLICIES = ["always", "cached", "never"] as const;
export type TouchPolicy = (typeof TOUCH_POLICIES)[number];

/** `9e` (the PIN is never checked) and `f9` (attestation) are refused. */
export const ALLOWED_SLOTS: readonly string[] = ["9a", "9c", "9d", ...Array.from({ length: 20 }, (_, i) => (0x82 + i).toString(16))];

export const parseSlot = (text: string): string => {
  const slot = text.trim().toLowerCase();
  if (!ALLOWED_SLOTS.includes(slot)) {
    throw new EzError(2, "slot_not_allowed", `Slot ${text} cannot be used; choose 9a, 9c, 9d or 82 to 95 (9e and f9 are refused).`);
  }
  return slot;
};

export const parseSerial = (text: string, flag = "--yubikey-serial"): number => {
  if (!/^\d{1,10}$/.test(text)) throw new EzError(2, "invalid_input", `${flag} must be the YubiKey's serial number.`);
  return Number(text);
};

// ---------------------------------------------------------------------------------------------------------------------
// Firmware and algorithm gating
// ---------------------------------------------------------------------------------------------------------------------

export const parseFirmware = (text: string): [number, number, number] => {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (match === null) throw new EzError(9, "tool_failed", "The YubiKey reported an unreadable firmware version.");
  return [Number(match[1]), Number(match[2]), Number(match[3])];
};

export const firmwareAtLeast = (text: string, major: number, minor: number): boolean => {
  const [a, b] = parseFirmware(text);
  return a > major || (a === major && b >= minor);
};

export const MIN_FIRMWARE = "5.3";

export const assertFirmware = (firmware: string): void => {
  if (!firmwareAtLeast(firmware, 5, 3)) {
    throw new EzError(9, "yubikey_firmware_unsupported", `YubiKey firmware ${firmware} is too old; EZ needs ${MIN_FIRMWARE} or later (for slot, PIN and management-key metadata).`);
  }
};

/** The PIV key type for an EZ key algorithm. */
export const pivKeyType = (algorithm: string): string => {
  const map: Record<string, string> = { ECDSA_P256: "ECCP256", ECDSA_P384: "ECCP384", RSA_3072: "RSA3072", RSA_4096: "RSA4096", RSA_2048: "RSA2048" };
  const type = map[algorithm];
  if (type === undefined) throw new EzError(2, "yubikey_algorithm_unsupported", `${algorithm} cannot be held in a YubiKey PIV slot.`);
  return type;
};

/** RSA-3072, RSA-4096 and Ed25519 need firmware 5.7. */
export const assertKeyTypeSupported = (firmware: string, keyType: string): void => {
  if (["RSA3072", "RSA4096", "ED25519", "X25519"].includes(keyType) && !firmwareAtLeast(firmware, 5, 7)) {
    throw new EzError(2, "yubikey_algorithm_unsupported", `${keyType} needs YubiKey firmware 5.7 or later (this key has ${firmware}); use ECDSA_P384 or ECDSA_P256.`);
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// The ykman client
// ---------------------------------------------------------------------------------------------------------------------

export interface YkDevice {
  readonly serial: number;
  readonly firmware: string;
  readonly fips: boolean;
}

export interface YkKey {
  readonly keyType: string;
  readonly pinPolicy: string;
  readonly touchPolicy: string;
  readonly generated: boolean;
  readonly spkiDer: Buffer;
}

export interface YkInfo {
  readonly device: YkDevice;
  readonly slot: string;
  readonly pin: { readonly default: boolean; readonly attemptsRemaining: number };
  readonly management: {
    readonly keyType: string;
    readonly default: boolean;
    readonly touchPolicy: string;
    readonly pivmanProtected: boolean;
    readonly pivmanDerived: boolean;
  };
  /** The key in the chosen slot, or null when it is empty. */
  readonly key: YkKey | null;
  readonly certificateDer: Buffer | null;
}

export type ManagementKeySpec = { readonly mode: "default" } | { readonly mode: "pin" } | { readonly mode: "hex"; readonly hex: string };

const EXIT_FOR_CODE: Record<string, number> = {
  yubikey_not_found: 9,
  yubikey_multiple: 2,
  yubikey_firmware_unsupported: 9,
  yubikey_algorithm_unsupported: 2,
  pin_invalid: 3,
  pin_blocked: 3,
  pin_required: 3,
  management_key_invalid: 3,
  management_key_not_default: 5,
  touch_timeout: 9,
  slot_occupied: 5,
  slot_empty: 5,
  slot_not_allowed: 2,
};

export interface YkmanOptions {
  /** The ykman executable (default `ykman`; `HEMLIG_YKMAN` sets an absolute path). */
  readonly path?: string;
  /** Milliseconds a single call may take; signing waits for a touch (default 90 s, 30 s otherwise). */
  readonly timeoutMs?: number;
}

export interface YkmanEvents {
  /** The device is waiting for a touch to sign the item with this id. */
  readonly onTouch?: (id: string) => void;
}

const MAX_OUTPUT = 1_048_576;

const mapFailure = (result: Record<string, unknown>): EzError => {
  const code = typeof result.code === "string" ? result.code : "tool_failed";
  const message = typeof result.message === "string" ? result.message : "The YubiKey operation failed.";
  const attempts = typeof result.attemptsRemaining === "number" ? result.attemptsRemaining : undefined;
  return new EzError(EXIT_FOR_CODE[code] ?? 9, EXIT_FOR_CODE[code] === undefined ? "tool_failed" : code, attempts === undefined ? message : `${message} ${attempts} attempt(s) remain.`, attempts === undefined ? undefined : { attemptsRemaining: attempts });
};

export class YkmanClient {
  readonly #path: string;
  readonly #timeoutMs: number | undefined;

  public constructor(options: YkmanOptions = {}) {
    this.#path = options.path ?? "ykman";
    this.#timeoutMs = options.timeoutMs;
  }

  /**
   * Runs one request through `ykman script --force`. Secrets travel only on the child's stdin. The script itself is
   * handed over on an inherited pipe (`/dev/fd/3`), so no script file exists for another process to replace. Windows has
   * no `/dev/fd`; there the script goes through a private temporary file (best effort).
   */
  public async call(request: Record<string, unknown>, events: YkmanEvents = {}): Promise<Record<string, unknown>> {
    if (process.platform !== "win32") return this.#run("/dev/fd/3", { v: 1, ...request }, events);
    const dir = await fs.mkdtemp(join(tmpdir(), "hemlig-ez-"));
    try {
      const script = join(dir, "hemlig_ez_piv.py");
      await fs.writeFile(script, YUBIKEY_SCRIPT, { mode: 0o600 });
      return await this.#run(script, { v: 1, ...request }, events, false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }

  #run(script: string, request: Record<string, unknown>, events: YkmanEvents, viaPipe = true): Promise<Record<string, unknown>> {
    const timeout = this.#timeoutMs ?? (["sign", "generate", "put-key", "put-certificate"].includes(String(request.op)) ? 90_000 : 30_000);
    return new Promise((resolve, reject) => {
      const child = spawn(this.#path, ["script", "--force", script], { stdio: ["pipe", "pipe", "pipe", ...(viaPipe ? (["pipe"] as const) : [])] });
      let stdout = "";
      let stderrBuffer = "";
      let settled = false;
      const finish = (action: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        action();
      };
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(() =>
          reject(
            request.op === "sign"
              ? new EzError(9, "touch_timeout", "The YubiKey did not finish signing in time (was it touched?).")
              : new EzError(9, "tool_failed", "ykman did not answer in time."),
          ),
        );
      }, timeout);
      child.on("error", (error: NodeJS.ErrnoException) =>
        finish(() =>
          reject(
            error.code === "ENOENT"
              ? new EzError(9, "tool_missing", `Cannot run ${this.#path}. Install YubiKey Manager (ykman 5.x) or set HEMLIG_YKMAN to its absolute path.`)
              : new EzError(9, "tool_failed", "Cannot run ykman."),
          ),
        ),
      );
      child.stdout.on("data", (chunk: Buffer) => {
        if (stdout.length < MAX_OUTPUT) stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderrBuffer += chunk.toString("utf8");
        let newline = stderrBuffer.indexOf("\n");
        while (newline >= 0) {
          const line = stderrBuffer.slice(0, newline).trimEnd();
          stderrBuffer = stderrBuffer.slice(newline + 1);
          // Only our own touch notices are used; every other line is dropped (no tracebacks or tool text are echoed).
          const touch = /^HEMLIG-EZ-NOTICE touch ([A-Za-z0-9_-]{1,64})$/.exec(line);
          if (touch !== null) events.onTouch?.(touch[1] as string);
          newline = stderrBuffer.indexOf("\n");
        }
        if (stderrBuffer.length > 65536) stderrBuffer = "";
      });
      child.on("close", (code) =>
        finish(() => {
          const line = stdout.split("\n").find((l) => l.startsWith("HEMLIG-EZ-RESULT "));
          let result: Record<string, unknown> | undefined;
          try {
            result = line === undefined ? undefined : (JSON.parse(line.slice("HEMLIG-EZ-RESULT ".length)) as Record<string, unknown>);
          } catch {
            result = undefined;
          }
          if (result === undefined) {
            reject(new EzError(9, "tool_failed", `ykman produced no result (exit ${String(code)}). Is YubiKey Manager 5.x installed and the YubiKey connected?`));
          } else if (result.ok !== true) {
            reject(mapFailure(result));
          } else {
            resolve(result);
          }
        }),
      );
      child.stdin.on("error", () => undefined);
      if (viaPipe) {
        const pipe = child.stdio[3] as import("node:stream").Writable;
        pipe.on("error", () => undefined);
        pipe.end(YUBIKEY_SCRIPT);
      }
      child.stdin.end(`${JSON.stringify(request)}\n`);
    });
  }

  public async list(): Promise<YkDevice[]> {
    const result = await this.call({ op: "list" });
    return result.devices as YkDevice[];
  }

  public async info(serial: number | undefined, slot: string): Promise<YkInfo> {
    const r = await this.call({ op: "info", serial: serial ?? null, slot });
    const key = r.key as null | { keyType: string; pinPolicy: string; touchPolicy: string; generated: boolean; spki: string };
    const info: YkInfo = {
      device: r.device as YkDevice,
      slot,
      pin: r.pin as YkInfo["pin"],
      management: r.management as YkInfo["management"],
      key: key === null ? null : { keyType: key.keyType, pinPolicy: key.pinPolicy, touchPolicy: key.touchPolicy, generated: key.generated, spkiDer: Buffer.from(key.spki, "base64") },
      certificateDer: r.certificate === null ? null : Buffer.from(r.certificate as string, "base64"),
    };
    assertFirmware(info.device.firmware);
    return info;
  }

  public async sign(input: { serial: number; slot: string; pin: string; items: readonly SignItem[] }, events: YkmanEvents = {}): Promise<Buffer[]> {
    const r = await this.call(
      {
        op: "sign",
        serial: input.serial,
        slot: input.slot,
        pin: input.pin,
        items: input.items.map((item) => ({ id: item.id, data: item.data.toString("base64") })),
      },
      events,
    );
    return (r.signatures as string[]).map((s) => Buffer.from(s, "base64"));
  }

  /** Presents the management key without writing anything. */
  public async checkManagementKey(input: { serial: number; slot: string; management: ManagementKeySpec; pin?: string }): Promise<void> {
    const { management, ...rest } = input;
    await this.call({ op: "check-management-key", ...rest, managementKey: management });
  }

  public async generate(input: { serial: number; slot: string; keyType: string; touchPolicy: TouchPolicy; overwrite: boolean; management: ManagementKeySpec; pin?: string }): Promise<Buffer> {
    const r = await this.call({ op: "generate", ...input, pinPolicy: "always", managementKey: input.management });
    return Buffer.from(r.spki as string, "base64");
  }

  public async putKey(input: {
    serial: number;
    slot: string;
    touchPolicy: TouchPolicy;
    overwrite: boolean;
    management: ManagementKeySpec;
    pin?: string;
    keyDer: Buffer;
    certificateDer?: Buffer;
  }): Promise<string> {
    const { keyDer, certificateDer, management, ...rest } = input;
    const r = await this.call({
      op: "put-key",
      ...rest,
      pinPolicy: "always",
      managementKey: management,
      keyDer: keyDer.toString("base64"),
      ...(certificateDer === undefined ? {} : { certificateDer: certificateDer.toString("base64") }),
    });
    return r.keyType as string;
  }

  public async putCertificate(input: { serial: number; slot: string; overwrite: boolean; management: ManagementKeySpec; pin?: string; certificateDer: Buffer }): Promise<void> {
    const { certificateDer, management, ...rest } = input;
    await this.call({ op: "put-certificate", ...rest, managementKey: management, certificateDer: certificateDer.toString("base64") });
  }

  public async protectManagementKey(input: { serial: number; slot: string; pin: string }): Promise<string> {
    const r = await this.call({ op: "protect-management-key", ...input });
    return r.algorithm as string;
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Preflight: every rail that runs before a device is written
// ---------------------------------------------------------------------------------------------------------------------

export interface PreflightOptions {
  readonly serial?: number;
  readonly slot: string;
  /** A write (import or generate) follows; checks occupancy. */
  readonly write: boolean;
  readonly overwrite: boolean;
  readonly keyType?: string;
  readonly allowLastPinAttempt: boolean;
}

export interface DeviceTarget {
  readonly info: YkInfo;
  readonly serial: number;
  /** How the management key will be presented to the script (`hex` still needs the key typed). */
  readonly management: "default" | "pin" | "hex";
  readonly warnings: string[];
  /** The slot holds a key or certificate that a write would replace. */
  readonly occupied: boolean;
}

/** Reads the device (read-only) and applies the refusals. Never writes. */
export const inspectDevice = async (client: YkmanClient, options: PreflightOptions): Promise<DeviceTarget> => {
  const info = await client.info(options.serial, options.slot);
  const { firmware, serial } = info.device;
  if (options.keyType !== undefined) assertKeyTypeSupported(firmware, options.keyType);
  if (info.pin.default) {
    throw new EzError(5, "yubikey_default_pin", `YubiKey ${serial} still has the factory PIN. Change it first (ykman piv access change-pin), then rerun.`);
  }
  if (info.pin.attemptsRemaining === 0) throw new EzError(3, "pin_blocked", `The PIN of YubiKey ${serial} is blocked.`);
  if (info.pin.attemptsRemaining === 1 && !options.allowLastPinAttempt) {
    throw new EzError(5, "pin_last_attempt", `YubiKey ${serial} has one PIN attempt left; another wrong PIN would block it. Rerun with --allow-last-pin-attempt only if you are sure of the PIN.`);
  }
  const occupied = info.key !== null || info.certificateDer !== null;
  const warnings: string[] = [];
  if (options.write) {
    if (occupied && !options.overwrite) {
      throw new EzError(5, "slot_occupied", `Slot ${options.slot} of YubiKey ${serial} already holds a ${info.key === null ? "certificate" : "key"}. Nothing was changed. To replace it, rerun with --overwrite-slot ${options.slot}.`);
    }
    if (occupied && !firmwareAtLeast(firmware, 5, 7)) {
      warnings.push(`Firmware ${firmware} cannot delete a key: the existing key in slot ${options.slot} will be overwritten and cannot be recovered or removed later (only a PIV reset clears a slot).`);
    }
    if (info.management.default && !info.management.pivmanProtected && !info.management.pivmanDerived) {
      warnings.push(`YubiKey ${serial} uses the FACTORY DEFAULT management key: anyone with the device can replace its keys. Consider --protect-management-key (it changes the whole device).`);
    }
  }
  const management = info.management.pivmanProtected || info.management.pivmanDerived ? "pin" : info.management.default ? "default" : "hex";
  return { info, serial, management, warnings, occupied };
};

/** Required length in bytes of a typed management key. */
export const managementKeyBytes = (keyType: string): number => ({ TDES: 24, AES128: 16, AES192: 24, AES256: 32 })[keyType] ?? 24;

// ---------------------------------------------------------------------------------------------------------------------
// The signer
// ---------------------------------------------------------------------------------------------------------------------

export interface YubiKeySignerOptions {
  readonly client: YkmanClient;
  readonly serial: number;
  readonly slot: string;
  readonly spkiDer: Buffer;
  /** Called once, on the first use, to read the PIN; the signer keeps it in memory until `close()` (one prompt per command). */
  readonly pin: () => Promise<Buffer>;
  /** Called by `close()` (the device handle zeroes its own cached PIN). */
  readonly onClose?: () => void;
}

/** Signs on the YubiKey. The PIN is verified in every ykman call and never retried. */
export class YubiKeySigner implements RootSigner {
  public readonly spkiDer: Buffer;
  public readonly keyAlgorithm: string;
  public readonly signatureAlgorithm: SignatureAlgorithm;
  public readonly serial: number;
  readonly #options: YubiKeySignerOptions;
  #pin: Buffer | undefined;

  public constructor(options: YubiKeySignerOptions) {
    this.#options = options;
    this.spkiDer = options.spkiDer;
    this.serial = options.serial;
    this.keyAlgorithm = describeSpki(options.spkiDer).algorithm;
    this.signatureAlgorithm = signatureAlgorithmForSpki(options.spkiDer);
  }

  async #pinText(): Promise<string> {
    this.#pin ??= await this.#options.pin();
    return this.#pin.toString("utf8");
  }

  /** Checks the PIN without signing (so a typo is found before a key is generated). */
  public async verifyPin(): Promise<void> {
    await this.#options.client.sign({ serial: this.#options.serial, slot: this.#options.slot, pin: await this.#pinText(), items: [] });
  }

  public async sign(items: readonly SignItem[], events?: SignEvents): Promise<Buffer[]> {
    const byId = new Map(items.map((item) => [item.id, item]));
    return this.#options.client.sign(
      { serial: this.#options.serial, slot: this.#options.slot, pin: await this.#pinText(), items },
      { onTouch: (id) => { const item = byId.get(id); if (item !== undefined) events?.onTouch?.(item); } },
    );
  }

  public close(): void {
    this.#pin?.fill(0);
    this.#pin = undefined;
    this.#options.onClose?.();
  }
}

export const touchNotice = (serial: number, item: SignItem): string => `Touch the YubiKey (serial ${serial}) now to sign: ${item.description}\n`;

/** Which recorded device to use: the one flagged, else the only connected recorded one. */
export const chooseRecordedDevice = async (client: YkmanClient, recorded: readonly number[], flagged: number | undefined): Promise<number> => {
  if (flagged !== undefined) {
    if (!recorded.includes(flagged)) {
      throw new EzError(5, "yubikey_not_recorded", `YubiKey ${flagged} is not one of this root's recorded devices (${recorded.join(", ")}); use import-key to add it.`);
    }
    return flagged;
  }
  const connected = (await client.list()).filter((d) => recorded.includes(d.serial));
  if (connected.length === 0) throw new EzError(9, "yubikey_not_found", `None of this root's YubiKeys is connected (${recorded.join(", ")}).`);
  if (connected.length > 1) throw new EzError(2, "yubikey_multiple", `More than one of this root's YubiKeys is connected (${connected.map((d) => d.serial).join(", ")}); pass --yubikey-serial.`);
  return (connected[0] as YkDevice).serial;
};

export type { EzKeyAlgorithm };
