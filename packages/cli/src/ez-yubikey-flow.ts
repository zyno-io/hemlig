import { EzError } from "./ez-error";
import { displaySafe } from "./ez-x509";
import type { Prompter } from "./ez-prompt";
import {
  inspectDevice,
  managementKeyBytes,
  YubiKeySigner,
  type DeviceTarget,
  type ManagementKeySpec,
  type PreflightOptions,
  type TouchPolicy,
  type YkmanClient,
} from "./ez-yubikey";

/**
 * The interactive half of the YubiKey support: what the operator reads and types before a device is written, and the
 * per-device helper that reads the PIN and management key at most once each. The commands in `ez.ts` call into this.
 */

export interface YkIo {
  readonly prompter: Prompter;
  readonly say: (text: string) => Promise<void>;
  readonly client: YkmanClient;
  readonly pinFromStdin: boolean;
  readonly allowLastPinAttempt: boolean;
}

/** One YubiKey during a command: its preflight result plus the secrets read for it (zeroed by `close`). */
export class DeviceHandle {
  readonly target: DeviceTarget;
  readonly slot: string;
  readonly #io: YkIo;
  #pin: Buffer | undefined;
  #management: ManagementKeySpec | undefined;

  public constructor(io: YkIo, target: DeviceTarget, slot: string) {
    this.#io = io;
    this.target = target;
    this.slot = slot;
  }

  public get serial(): number {
    return this.target.serial;
  }

  public static async open(io: YkIo, options: PreflightOptions): Promise<DeviceHandle> {
    return new DeviceHandle(io, await inspectDevice(io.client, options), options.slot);
  }

  /** The PIN, read once from the terminal (or the next piped line with --pin-stdin). */
  public async pin(): Promise<Buffer> {
    if (this.#pin !== undefined) return Buffer.from(this.#pin);
    const left = this.target.info.pin.attemptsRemaining;
    this.#pin = await this.#io.prompter.pin({
      fromStdin: this.#io.pinFromStdin,
      label: `YubiKey PIN (serial ${this.serial}, slot ${this.slot}, ${left} attempt${left === 1 ? "" : "s"} left): `,
    });
    return Buffer.from(this.#pin);
  }

  /** Checks the PIN against the device without signing anything (a typo is found before any key is generated or written). */
  public async verifyPin(): Promise<void> {
    const pin = await this.pin();
    try {
      await this.#io.client.sign({ serial: this.serial, slot: this.slot, pin: pin.toString("utf8"), items: [] });
    } finally {
      pin.fill(0);
    }
  }

  /** A signer for this slot; the PIN is read on first use and kept for the command. */
  public signer(spkiDer: Buffer): YubiKeySigner {
    return new YubiKeySigner({
      client: this.#io.client,
      serial: this.serial,
      slot: this.slot,
      spkiDer,
      pin: () => this.pin(),
      onClose: () => this.close(),
    });
  }

  /** How the management key is presented. A typed key is read once; the PIN-protected key needs the PIN. */
  public async management(): Promise<{ readonly spec: ManagementKeySpec; readonly pin?: string }> {
    let management: ManagementKeySpec;
    if (this.#management !== undefined) {
      management = this.#management;
    } else {
      const mode = this.target.management;
      if (mode === "hex") {
        const keyType = this.target.info.management.keyType;
        const typed = await this.#io.prompter.secret(`YubiKey management key (serial ${this.serial}, hex, ${keyType}): `, 256);
        const hex = typed.toString("utf8").trim();
        typed.fill(0);
        if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== managementKeyBytes(keyType) * 2) {
          throw new EzError(3, "management_key_invalid", `The management key must be ${managementKeyBytes(keyType) * 2} hex characters (${keyType}).`);
        }
        management = { mode: "hex", hex };
      } else {
        management = mode === "pin" ? { mode: "pin" } : { mode: "default" };
      }
      this.#management = management;
    }
    if (management.mode !== "pin") return { spec: management };
    const pin = await this.pin();
    try {
      return { spec: management, pin: pin.toString("utf8") };
    } finally {
      pin.fill(0);
    }
  }

  /** Authenticates with the management key (no write): a typo is found before anything is created. */
  public async checkManagement(): Promise<void> {
    const management = await this.management();
    await this.#io.client.checkManagementKey({ serial: this.serial, slot: this.slot, management: management.spec, pin: management.pin });
  }

  /** The typed acknowledgement for `protectManagementKey`; ask it for every device before changing any. */
  public async acknowledgeProtect(): Promise<void> {
    if (this.target.management !== "default") {
      throw new EzError(2, "invalid_input", `--protect-management-key applies only to a YubiKey that still has the factory management key (serial ${this.serial} does not).`);
    }
    await this.#io.prompter.acknowledge(
      "protect management key",
      `This changes the management key of the WHOLE YubiKey ${this.serial} (it becomes a random key kept behind the PIN; other tools that use the factory key will stop working). Type "protect management key" to continue: `,
    );
  }

  /** Replaces the factory-default management key with a random PIN-protected one (opt-in; whole-device change). */
  public async protectManagementKey(): Promise<void> {
    if (this.target.management !== "default") {
      throw new EzError(2, "invalid_input", `--protect-management-key applies only to a YubiKey that still has the factory management key (serial ${this.serial} does not).`);
    }
    const pin = await this.pin();
    try {
      await this.#io.client.protectManagementKey({ serial: this.serial, slot: this.slot, pin: pin.toString("utf8") });
    } finally {
      pin.fill(0);
    }
    this.#management = { mode: "pin" };
  }

  /** Reads the slot back (read-only) and checks that it holds `spkiDer`. */
  public async assertHolds(spkiDer: Buffer): Promise<void> {
    const info = await this.#io.client.info(this.serial, this.slot);
    if (info.key === null || !info.key.spkiDer.equals(spkiDer)) {
      throw new EzError(5, "key_mismatch", `After writing, slot ${this.slot} of YubiKey ${this.serial} does not hold the expected key.`);
    }
  }

  public close(): void {
    this.#pin?.fill(0);
    this.#pin = undefined;
  }
}

const row = (label: string, value: string): string => `  ${`${label}:`.padEnd(18)}${value}`;

export interface WriteReview {
  readonly action: "import" | "generate";
  readonly keyType: string;
  readonly touchPolicy: TouchPolicy;
  readonly backupFile?: string;
  readonly slotCertificate: boolean;
  readonly overwrite: boolean;
}

/** What the operator reads before any YubiKey is written. */
export const renderYubiKeyReview = (devices: readonly DeviceHandle[], review: WriteReview): string => {
  const lines = ["", review.action === "generate" ? "=== Review: this will GENERATE the root key ON a YubiKey ===" : "=== Review: this will IMPORT the root key into a YubiKey ==="];
  for (const device of devices) {
    const { info } = device.target;
    lines.push(
      row("YubiKey", `serial ${info.device.serial}, firmware ${info.device.firmware}${info.device.fips ? " (FIPS)" : ""}`),
      row("  slot", `${device.slot}${device.target.occupied ? (review.overwrite ? "  (occupied: will be OVERWRITTEN)" : "  (occupied)") : "  (empty)"}`),
    );
    if (device.target.occupied && info.key !== null) lines.push(row("  existing key", `${info.key.keyType}, SPKI ${info.key.spkiDer.toString("hex").slice(-16)}`));
  }
  lines.push(
    row("Key", `${review.keyType}, PIN ${"always"}, touch ${review.touchPolicy}`),
    row("Slot certificate", review.slotCertificate ? "the root certificate is stored in the slot" : "none"),
    row("Backup", review.action === "generate" ? "NONE: the key exists only on this YubiKey" : displaySafe(review.backupFile ?? "")),
  );
  for (const device of devices) for (const warning of device.target.warnings) lines.push(`  WARNING: ${displaySafe(warning)}`);
  if (review.action === "generate") {
    lines.push(
      "",
      "  WARNING: the key is generated inside the YubiKey and can NEVER be exported or recovered.",
      "  If the YubiKey is lost, damaged or locked (PIN and PUK blocked), this root is gone: you would need a new root",
      "  and every intermediate it signed would have to be re-issued. There is no second copy.",
    );
  }
  lines.push("");
  return lines.join("\n");
};

/** The phrase typed before a key is generated with no backup. */
export const NO_BACKUP_PHRASE = "no backup";

export const acknowledgeWrites = async (io: YkIo, devices: readonly DeviceHandle[], review: WriteReview): Promise<void> => {
  if (review.action === "generate") {
    await io.prompter.acknowledge(NO_BACKUP_PHRASE, `Type "${NO_BACKUP_PHRASE}" to generate a key that can never be exported or recovered: `);
  }
  for (const device of devices) {
    await io.prompter.acknowledge(String(device.serial), `Type the serial number ${device.serial} to write to that YubiKey${device.target.occupied ? " and overwrite slot " + device.slot : ""}: `);
  }
};
