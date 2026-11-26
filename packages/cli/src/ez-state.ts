import { promises as fs } from "node:fs";
import { hostname as osHostname } from "node:os";
import { basename, isAbsolute, join, normalize, resolve } from "node:path";
import { EzError } from "./ez-error";
import {
  acquireLock,
  createImmutable,
  exists,
  readIfExists,
  writeAtomic,
  type FsFaults,
  type LockHandle,
} from "./ez-fs";
import { assertRestrictedName, describeName } from "./ez-name";
import { EZ_DEFAULTS } from "./ez-profile";
import {
  CRL_REASON_NAMES,
  DAY_MS,
  serialHex,
  serialMagnitude,
  floorSeconds,
  fromPem,
  NEW_REVOCATION_REASONS,
  parseCertificate,
  parseCrl,
  sha256Hex,
  toPem,
  verifyCertificateSignature,
  verifyCrlSignature,
  type CrlEntry,
  type CrlReasonName,
  type ParsedCertificate,
  type ParsedCrl,
} from "./ez-x509";

/**
 * The EZ state file and its state machine. One JSON state file plus immutable artifacts in `--dir`. Every mutation
 * is journalled (`pending`) before anything is signed, artifacts are written no-clobber, and the next open resolves
 * a crash at any step (design section 6).
 */

export const STATE_FORMAT = "hemlig-ez-root";
export const STATE_VERSION = 1;
export const DEFAULT_STATE_FILE = "hemlig-ez.json";

export type IssuedStatus = "signing" | "signed" | "activated" | "abandoned" | "imported";

export interface IssuedEntry {
  serial: string;
  caId: string | null;
  environment: string | null;
  adminOrigin: string | null;
  subjectDn: string;
  /** Canonical name key of the subject (case and spaces folded), the unit of the same-subject rule. */
  subjectKey: string;
  csrSha256: string | null;
  spkiSha256: string;
  certificateFile: string | null;
  fingerprint: string | null;
  notBefore: string;
  notAfter: string;
  status: IssuedStatus;
  signedAt: string | null;
  activatedAt: string | null;
}

export interface RevokedEntry {
  serial: string;
  caId: string | null;
  reason: CrlReasonName;
  revokedAt: string;
  invalidityDate: string | null;
  imported: boolean;
  /** The first CRL that listed this serial; null until one is committed. */
  listedInCrl: number | null;
}

export interface YubiKeyRecord {
  slot: string;
  keyType: string;
  generatedOnDevice: boolean;
  pinPolicy: string;
  touchPolicy: string;
  devices: { serial: number; firmware: string; fips: boolean; addedAt: string }[];
}

export interface EzState {
  format: typeof STATE_FORMAT;
  version: typeof STATE_VERSION;
  revision: number;
  updatedAt: string;
  root: {
    origin: "generated" | "adopted";
    subject: Record<string, string>;
    subjectDn: string;
    certificateFile: string;
    fingerprint: string;
    spkiSha256: string;
    extIdHint: string;
    subjectKeyIdentifier: string;
    serial: string;
    notBefore: string;
    notAfter: string;
    keyAlgorithm: string;
    pathLen: number | null;
    reissuedFrom: { fingerprint: string; file: string } | null;
  };
  adoption: {
    source: "yubikey" | "openssl-dir" | "files";
    adoptedAt: string;
    crlNumberSource: string[];
    revocationSource: string[];
  } | null;
  key: {
    storage: "software" | "yubikey";
    file: string | null;
    kdf: { name: "pbkdf2-hmac-sha256"; iterations: number } | null;
    yubikey: YubiKeyRecord | null;
  };
  defaults: { intermediateValidityDays: number; crlValidityDays: number };
  crl: {
    lastNumber: number;
    lastThisUpdate: string;
    /** Where the copy of the current CRL lives (rewritten atomically on every CRL). */
    copyFile: string;
    current: { number: number; file: string; sha256: string; thisUpdate: string; nextUpdate: string } | null;
  };
  issued: IssuedEntry[];
  revoked: RevokedEntry[];
  deployments: { adminOrigin: string; extId: string; lastUploadedCrlNumber: number; lastSeenAt: string }[];
  pending: { op: "sign" | "crl" | "adopt"; startedAt: string; serial?: string; crlNumber?: number } | null;
  lastSignedAt: string | null;
}

// ---------------------------------------------------------------------------------------------------------------------
// Strict validation (unknown keys are `state_corrupt`)
// ---------------------------------------------------------------------------------------------------------------------

type Check = (value: unknown, path: string) => void;

const corrupt = (path: string, message: string): never => {
  throw new EzError(9, "state_corrupt", `The state file is invalid at ${path}: ${message}.`);
};
const str: Check = (v, p) => typeof v === "string" || corrupt(p, "expected a string");
const hex = (min = 1, max = Infinity): Check => (v, p) =>
  (typeof v === "string" && /^[0-9a-f]+$/.test(v) && v.length >= min && v.length <= max) || corrupt(p, "expected lowercase hex");
const int = (min = 0): Check => (v, p) =>
  (typeof v === "number" && Number.isSafeInteger(v) && v >= min) || corrupt(p, `expected an integer >= ${min}`);
const bool: Check = (v, p) => typeof v === "boolean" || corrupt(p, "expected a boolean");
const iso: Check = (v, p) =>
  (typeof v === "string" && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v) || corrupt(p, "expected an ISO-8601 UTC time");
const lit = (...values: readonly string[]): Check => (v, p) =>
  (typeof v === "string" && values.includes(v)) || corrupt(p, `expected one of ${values.join(", ")}`);
const nullable = (check: Check): Check => (v, p) => {
  if (v !== null) check(v, p);
};
const arr = (check: Check): Check => (v, p) => {
  if (!Array.isArray(v)) return corrupt(p, "expected an array");
  v.forEach((item, i) => check(item, `${p}[${i}]`));
};
const strRecord: Check = (v, p) => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return corrupt(p, "expected an object");
  for (const [k, item] of Object.entries(v)) str(item, `${p}.${k}`);
};
const obj = (shape: Record<string, Check>, optional: readonly string[] = []): Check => (v, p) => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return corrupt(p, "expected an object");
  const record = v as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!Object.hasOwn(shape, key)) corrupt(`${p}.${key}`, "unknown key");
  }
  for (const [key, check] of Object.entries(shape)) {
    if (record[key] === undefined) {
      if (!optional.includes(key)) corrupt(`${p}.${key}`, "missing");
      continue;
    }
    check(record[key], `${p}.${key}`);
  }
};

const stateSchema: Check = obj({
  format: lit(STATE_FORMAT),
  version: (v, p) => v === STATE_VERSION || corrupt(p, `unsupported version (this CLI reads version ${STATE_VERSION})`),
  revision: int(1),
  updatedAt: iso,
  root: obj({
    origin: lit("generated", "adopted"),
    subject: strRecord,
    subjectDn: str,
    certificateFile: str,
    fingerprint: hex(64, 64),
    spkiSha256: hex(64, 64),
    extIdHint: str,
    subjectKeyIdentifier: hex(),
    serial: hex(),
    notBefore: iso,
    notAfter: iso,
    keyAlgorithm: str,
    pathLen: nullable(int(1)),
    reissuedFrom: nullable(obj({ fingerprint: hex(64, 64), file: str })),
  }),
  adoption: nullable(
    obj({
      source: lit("yubikey", "openssl-dir", "files"),
      adoptedAt: iso,
      crlNumberSource: arr(str),
      revocationSource: arr(str),
    }),
  ),
  key: obj({
    storage: lit("software", "yubikey"),
    file: nullable(str),
    kdf: nullable(obj({ name: lit("pbkdf2-hmac-sha256"), iterations: int(1) })),
    yubikey: nullable(
      obj({
        slot: str,
        keyType: str,
        generatedOnDevice: bool,
        pinPolicy: str,
        touchPolicy: str,
        devices: arr(obj({ serial: int(), firmware: str, fips: bool, addedAt: iso })),
      }),
    ),
  }),
  defaults: obj({ intermediateValidityDays: int(1), crlValidityDays: int(1) }),
  crl: obj({
    lastNumber: int(0),
    lastThisUpdate: iso,
    copyFile: str,
    current: nullable(obj({ number: int(1), file: str, sha256: hex(64, 64), thisUpdate: iso, nextUpdate: iso })),
  }),
  issued: arr(
    obj({
      serial: hex(),
      caId: nullable(str),
      environment: nullable(str),
      adminOrigin: nullable(str),
      subjectDn: str,
      subjectKey: hex(64, 64),
      csrSha256: nullable(hex(64, 64)),
      spkiSha256: hex(64, 64),
      certificateFile: nullable(str),
      fingerprint: nullable(hex(64, 64)),
      notBefore: iso,
      notAfter: iso,
      status: lit("signing", "signed", "activated", "abandoned", "imported"),
      signedAt: nullable(iso),
      activatedAt: nullable(iso),
    }),
  ),
  revoked: arr(
    obj({
      serial: hex(),
      caId: nullable(str),
      reason: lit(...CRL_REASON_NAMES),
      revokedAt: iso,
      invalidityDate: nullable(iso),
      imported: bool,
      listedInCrl: nullable(int(1)),
    }),
  ),
  deployments: arr(obj({ adminOrigin: str, extId: str, lastUploadedCrlNumber: int(0), lastSeenAt: iso })),
  pending: nullable(
    obj({ op: lit("sign", "crl", "adopt"), startedAt: iso, serial: hex(), crlNumber: int(1) }, ["serial", "crlNumber"]),
  ),
  lastSignedAt: nullable(iso),
});

/**
 * Relative paths only inside `--dir` (no `..`), except the three the operator may place elsewhere on purpose (the
 * key on a USB stick, the certificate and CRL copy), which may be absolute.
 */
export const resolveRecordedPath = (directory: string, recorded: string, allowAbsolute: boolean): string => {
  if (recorded.length === 0 || recorded.includes("\0")) throw new EzError(9, "state_corrupt", "A recorded path is empty or malformed.");
  if (isAbsolute(recorded)) {
    if (!allowAbsolute) throw new EzError(9, "state_corrupt", `The state records an absolute path where only a relative one is allowed (${recorded}).`);
    return normalize(recorded);
  }
  const parts = recorded.split(/[\\/]/);
  if (parts.some((part) => part === ".." || part === "" || /^[A-Za-z]:$/.test(part))) {
    throw new EzError(9, "state_corrupt", `The state records an unsafe path (${recorded}).`);
  }
  return resolve(directory, ...parts);
};

export const validateState = (raw: unknown): EzState => {
  stateSchema(raw, "$");
  const state = raw as EzState;
  const relativeOnly = [state.root.reissuedFrom?.file, state.crl.current?.file, ...state.issued.map((e) => e.certificateFile)];
  for (const file of relativeOnly) if (file) resolveRecordedPath(".", file, false);
  for (const file of [state.root.certificateFile, state.crl.copyFile, state.key.file]) {
    if (file) resolveRecordedPath(".", file, true);
  }
  if (state.key.storage === "software" && state.key.file === null) corrupt("$.key.file", "a software key needs a file");
  if (state.key.storage === "yubikey" && state.key.yubikey === null) corrupt("$.key.yubikey", "a YubiKey root needs a record");
  return state;
};

/** True when `parse` accepts the PEM text; an EzError from it (malformed PEM or DER) means a torn artifact. */
const parsesAs = (pem: Buffer, parse: (text: string) => unknown): boolean => {
  try {
    parse(pem.toString("utf8"));
    return true;
  } catch (error) {
    if (error instanceof EzError) return false;
    throw error;
  }
};

const crlFileName = (number: number): string => `crls/${String(number).padStart(6, "0")}.crl.pem`;
const issuedFileName = (serial: string): string => `issued/${serial}.pem`;

// ---------------------------------------------------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------------------------------------------------

export interface StoreOptions extends FsFaults {
  /** `create` only: a lock the caller already holds (generate-ca takes it before it writes a device). */
  readonly lock?: LockHandle;
  readonly dir: string;
  readonly stateFile?: string;
  readonly command: string;
  readonly breakStaleLock?: boolean;
  readonly now?: () => Date;
  readonly hostname?: string;
  readonly isAlive?: (pid: number) => boolean;
}

export interface ArtifactFile {
  /** As recorded in the state (relative to `dir`, or absolute where the state allows it). */
  readonly path: string;
  readonly data: Uint8Array;
  readonly mode?: number;
  /** Which absolute paths the state permits. */
  readonly allowAbsolute?: boolean;
}

export interface SignReservation {
  readonly serial: string;
  readonly caId: string | null;
  readonly environment: string | null;
  readonly adminOrigin: string | null;
  readonly subjectDn: string;
  /** `csr.subject.key` from the validated CSR. */
  readonly subjectKey: string;
  readonly csrSha256: string | null;
  readonly spkiSha256: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

export interface BeginResult {
  /** The existing signed or activated entry for the same CA and CSR; nothing new was reserved and nothing may be signed. */
  readonly resumed?: IssuedEntry;
  /** Set when `crl: true` was requested. */
  readonly crl?: { readonly number: number; readonly thisUpdate: Date };
}

export class EzStore {
  #state: EzState;
  #root: ParsedCertificate | undefined;
  #closed = false;

  private constructor(
    public readonly dir: string,
    public readonly stateFilePath: string,
    state: EzState,
    private readonly lock: LockHandle,
    private readonly options: StoreOptions,
  ) {
    this.#state = state;
  }

  public get state(): Readonly<EzState> {
    return this.#state;
  }

  /** Canonical lowercase hex of a positive serial (validated, even length, no redundant leading zero bytes). */
  public static canonicalSerial(serial: string): string {
    let canonical: string;
    try {
      canonical = serialHex(serialMagnitude(serial));
    } catch {
      throw new EzError(2, "invalid_input", "A serial must be hexadecimal.");
    }
    if (/^0+$/.test(canonical)) throw new EzError(2, "invalid_input", "A serial must be positive.");
    return canonical;
  }

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  private async fault(step: string): Promise<void> {
    await this.options.fault?.(step);
  }

  private path(recorded: string, allowAbsolute = false): string {
    return resolveRecordedPath(this.dir, recorded, allowAbsolute);
  }

  // -- creation --------------------------------------------------------------------------------------------------

  /**
   * Starts a new root directory: takes the lock, refuses to overwrite anything, writes every artifact no-clobber and the
   * state file last. A crash before the state file exists leaves `incomplete_generation` on the next attempt.
   */
  public static async create(
    options: StoreOptions,
    initial: Omit<EzState, "format" | "version" | "revision" | "updatedAt">,
    artifacts: readonly ArtifactFile[],
  ): Promise<EzStore> {
    const dir = resolve(options.dir);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const stateFilePath = join(dir, options.stateFile ?? DEFAULT_STATE_FILE);
    const lock =
      options.lock ??
      (await acquireLock(dir, {
        command: options.command,
        hostname: options.hostname ?? osHostname(),
        now: options.now,
        breakStale: options.breakStaleLock,
        isAlive: options.isAlive,
      }));
    try {
      const targets = artifacts.map((a) => resolveRecordedPath(dir, a.path, a.allowAbsolute === true));
      const present: string[] = [];
      for (const target of [stateFilePath, ...targets]) {
        if (await exists(target)) present.push(target);
      }
      if (present.length > 0) {
        throw new EzError(5, "already_exists", `Refusing to overwrite existing files: ${present.join(", ")}. Nothing was changed.`, { files: present });
      }
      const state: EzState = {
        format: STATE_FORMAT,
        version: STATE_VERSION,
        revision: 1,
        updatedAt: (options.now?.() ?? new Date()).toISOString(),
        ...initial,
      };
      validateState(state);
      for (const [index, artifact] of artifacts.entries()) {
        const target = targets[index] as string;
        await fs.mkdir(resolve(target, ".."), { recursive: true, mode: 0o700 });
        await createImmutable(target, artifact.data, artifact.mode ?? 0o600, options);
        await options.fault?.(`create:artifact:${index}`);
      }
      await fs.mkdir(join(dir, "crls"), { recursive: true, mode: 0o700 });
      await fs.mkdir(join(dir, "issued"), { recursive: true, mode: 0o700 });
      await createImmutable(stateFilePath, Buffer.from(`${JSON.stringify(state, null, 2)}\n`), 0o600, options);
      await options.fault?.("create:state");
      const store = new EzStore(dir, stateFilePath, state, lock, options);
      await store.#loadRoot();
      await store.#checkInvariants();
      return store;
    } catch (error) {
      await lock.release();
      throw error;
    }
  }

  // -- opening ---------------------------------------------------------------------------------------------------

  /** Takes the lock, loads and validates the state, resolves a journalled crash, and checks every invariant. */
  public static async open(options: StoreOptions): Promise<EzStore> {
    const dir = resolve(options.dir);
    const stateFilePath = join(dir, options.stateFile ?? DEFAULT_STATE_FILE);
    if (!(await exists(stateFilePath))) {
      throw new EzError(5, "state_missing", `${stateFilePath} does not exist. Run generate-ca or adopt-ca first.`);
    }
    const lock = await acquireLock(dir, {
      command: options.command,
      hostname: options.hostname ?? osHostname(),
      now: options.now,
      breakStale: options.breakStaleLock,
      isAlive: options.isAlive,
    });
    try {
      const state = await EzStore.#readState(stateFilePath);
      const store = new EzStore(dir, stateFilePath, state, lock, options);
      await store.#loadRoot();
      await store.#recover();
      await store.#checkInvariants();
      return store;
    } catch (error) {
      await lock.release();
      throw error;
    }
  }

  /** Reads and validates the state without the lock or any recovery (for `status`). */
  public static async peek(dir: string, stateFile = DEFAULT_STATE_FILE): Promise<EzState> {
    return EzStore.#readState(join(resolve(dir), stateFile));
  }

  static async #readState(path: string): Promise<EzState> {
    let text: string;
    try {
      text = (await fs.readFile(path)).toString("utf8");
    } catch (error) {
      throw new EzError(9, "state_io_error", `Cannot read ${path}: ${(error as Error).message}`);
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new EzError(9, "state_corrupt", `${path} is not valid JSON.`);
    }
    return validateState(raw);
  }

  public async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.lock.release();
  }

  // -- reading ---------------------------------------------------------------------------------------------------

  async #loadRoot(): Promise<void> {
    const file = this.path(this.#state.root.certificateFile, true);
    const pem = await readIfExists(file);
    if (pem === undefined) throw new EzError(5, "state_conflict", `The root certificate ${file} is missing.`, { reason: "root_missing" });
    const der = fromPem(pem.toString("utf8"), "CERTIFICATE");
    if (sha256Hex(der) !== this.#state.root.fingerprint) {
      throw new EzError(5, "state_conflict", "root.pem does not match the fingerprint in the state file.", { reason: "root_tampered" });
    }
    this.#root = parseCertificate(der);
  }

  public get rootCertificate(): ParsedCertificate {
    if (this.#root === undefined) throw new Error("The store is not loaded.");
    return this.#root;
  }

  public async readIssuedCertificate(entry: IssuedEntry): Promise<Buffer | undefined> {
    if (entry.certificateFile === null) return undefined;
    const pem = await readIfExists(this.path(entry.certificateFile));
    return pem === undefined ? undefined : fromPem(pem.toString("utf8"), "CERTIFICATE");
  }

  public async readCurrentCrl(): Promise<ParsedCrl | undefined> {
    const current = this.#state.crl.current;
    if (current === null) return undefined;
    const pem = await readIfExists(this.path(current.file));
    return pem === undefined ? undefined : parseCrl(fromPem(pem.toString("utf8"), "X509 CRL"));
  }

  /** The key file path (resolved), when there is one. */
  public get keyFilePath(): string | undefined {
    return this.#state.key.file === null ? undefined : this.path(this.#state.key.file, true);
  }

  /** True when a new CRL is due: none yet, or fewer than `beforeDays` remain before nextUpdate. */
  public crlDue(beforeDays: number = EZ_DEFAULTS.crlRenewBeforeDays, now = this.now()): boolean {
    const current = this.#state.crl.current;
    if (this.#state.revoked.some((r) => r.listedInCrl === null)) return true;
    return current === null || Date.parse(current.nextUpdate) - now.getTime() < beforeDays * DAY_MS;
  }

  /** The entries the next CRL must list: every revocation, ever. */
  public revocationEntries(): CrlEntry[] {
    return this.#state.revoked.map((r) => ({
      serial: r.serial,
      revokedAt: new Date(r.revokedAt),
      reason: r.reason,
      invalidityDate: r.invalidityDate === null ? undefined : new Date(r.invalidityDate),
    }));
  }

  /** I5: the signer's SPKI must equal the root's before any signature. */
  public assertSigner(spkiDer: Buffer): void {
    if (sha256Hex(spkiDer) !== this.#state.root.spkiSha256) {
      throw new EzError(5, "key_mismatch", "The signing key is not this root's key.");
    }
  }

  // -- persistence -----------------------------------------------------------------------------------------------

  async #persist(mutate: (draft: EzState) => void): Promise<void> {
    const draft = structuredClone(this.#state);
    mutate(draft);
    draft.revision += 1;
    draft.updatedAt = this.now().toISOString();
    validateState(draft);
    try {
      await writeAtomic(this.stateFilePath, Buffer.from(`${JSON.stringify(draft, null, 2)}\n`), 0o600, this.options);
    } catch (error) {
      if (error instanceof EzError) throw error;
      throw new EzError(9, "state_io_error", `Cannot write the state file: ${(error as Error).message}`);
    }
    this.#state = draft;
    await this.fault("state:written");
  }

  // -- journal ---------------------------------------------------------------------------------------------------

  /** I6: the next CRL thisUpdate, strictly after the previous one and never more than 5 minutes ahead of now. */
  public nextCrlThisUpdate(now = this.now()): Date {
    const previous = Date.parse(this.#state.crl.lastThisUpdate);
    const candidate = new Date(Math.max(floorSeconds(now).getTime(), previous + 1000));
    if (candidate.getTime() - now.getTime() > EZ_DEFAULTS.thisUpdateAheadSeconds * 1000) {
      throw new EzError(5, "clock_regressed", "The clock is behind the last CRL this root signed; check the system time.", {
        lastThisUpdate: this.#state.crl.lastThisUpdate,
      });
    }
    return candidate;
  }

  /**
   * Reserves what is about to be signed, before any signature exists (I1, I2). `sign` records the intermediate with
   * status `signing`; `crl` allocates the next CRL number. Both are one journal entry and one atomic write.
   */
  public async begin(input: { sign?: SignReservation; crl?: boolean }): Promise<BeginResult> {
    const now = this.now();
    if (this.#state.pending !== null) {
      throw new EzError(5, "state_conflict", "A previous operation is still pending; reopen the directory to recover.", { reason: "pending" });
    }
    if (this.#state.lastSignedAt !== null && now.getTime() < Date.parse(this.#state.lastSignedAt)) {
      throw new EzError(5, "clock_regressed", "The clock is behind the last signing time recorded for this root.", {
        lastSignedAt: this.#state.lastSignedAt,
      });
    }
    let resumed: IssuedEntry | undefined;
    if (input.sign !== undefined) {
      const sign = { ...input.sign, serial: EzStore.canonicalSerial(input.sign.serial) };
      input = { ...input, sign };
      const live = this.#state.issued.filter((e) => e.status !== "abandoned");
      if (this.#state.issued.some((e) => e.serial === sign.serial) || this.#state.revoked.some((r) => r.serial === sign.serial)) {
        throw new EzError(5, "state_conflict", "That serial was already used.", { reason: "serial_reused" });
      }
      const revokedSerials = new Set(this.#state.revoked.map((r) => r.serial));
      const clash = live.find((e) => e.subjectKey === sign.subjectKey && e.spkiSha256 !== sign.spkiSha256 && !revokedSerials.has(e.serial) && !(sign.caId !== null && e.caId === sign.caId));
      if (clash !== undefined) {
        throw new EzError(5, "issued_conflict", `A live certificate (serial ${clash.serial}) already carries that subject with a different key.`, { serial: clash.serial });
      }
      if (sign.caId !== null) {
        const same = live.filter((e) => e.caId === sign.caId);
        const conflicting = same.find((e) => e.csrSha256 !== sign.csrSha256);
        if (conflicting !== undefined) {
          throw new EzError(5, "issued_conflict", `A certificate (serial ${conflicting.serial}) was already issued for ${sign.caId} from a different CSR.`, {
            serial: conflicting.serial,
          });
        }
        resumed = same.find((e) => e.status === "signed" || e.status === "activated");
      }
    }
    const reserveSign = input.sign !== undefined && resumed === undefined;
    let crl: BeginResult["crl"];
    if (input.crl === true) {
      crl = { number: this.#state.crl.lastNumber + 1, thisUpdate: this.nextCrlThisUpdate(now) };
    }
    if (!reserveSign && crl === undefined) return { resumed };
    await this.#persist((draft) => {
      draft.pending = {
        op: reserveSign ? "sign" : "crl",
        startedAt: now.toISOString(),
        ...(reserveSign ? { serial: (input.sign as SignReservation).serial } : {}),
        ...(crl === undefined ? {} : { crlNumber: crl.number }),
      };
      if (reserveSign) {
        const s = input.sign as SignReservation;
        draft.issued.push({
          serial: s.serial,
          caId: s.caId,
          environment: s.environment,
          adminOrigin: s.adminOrigin,
          subjectDn: s.subjectDn,
          subjectKey: s.subjectKey,
          csrSha256: s.csrSha256,
          spkiSha256: s.spkiSha256,
          certificateFile: null,
          fingerprint: null,
          notBefore: s.notBefore.toISOString(),
          notAfter: s.notAfter.toISOString(),
          status: "signing",
          signedAt: null,
          activatedAt: null,
        });
      }
      if (crl !== undefined) {
        draft.crl.lastNumber = crl.number;
        draft.crl.lastThisUpdate = crl.thisUpdate.toISOString();
      }
      draft.lastSignedAt = now.toISOString();
    });
    await this.fault("begin:persisted");
    return { resumed, crl };
  }

  /** Writes `issued/<serial>.pem` no-clobber, then moves the entry to `signed`. */
  public async commitSigned(rawSerial: string, certificateDer: Buffer): Promise<IssuedEntry> {
    const serial = EzStore.canonicalSerial(rawSerial);
    const entry = this.#state.issued.find((e) => e.serial === serial);
    if (entry === undefined || entry.status !== "signing") {
      throw new EzError(5, "state_conflict", "No reservation for that serial.", { reason: "not_reserved" });
    }
    this.#verifyIssued(entry, certificateDer);
    const file = issuedFileName(serial);
    await createImmutable(this.path(file), Buffer.from(toPem(certificateDer, "CERTIFICATE")), 0o644, this.options);
    await this.fault("commitSigned:file");
    return this.#markSigned(serial, file, certificateDer);
  }

  async #markSigned(serial: string, file: string, der: Buffer): Promise<IssuedEntry> {
    const signedAt = this.now().toISOString();
    await this.#persist((draft) => {
      const entry = draft.issued.find((e) => e.serial === serial) as IssuedEntry;
      entry.status = "signed";
      entry.certificateFile = file;
      entry.fingerprint = sha256Hex(der);
      entry.signedAt = signedAt;
      this.#clearPending(draft, "serial");
    });
    return this.#state.issued.find((e) => e.serial === serial) as IssuedEntry;
  }

  #clearPending(draft: EzState, field: "serial" | "crlNumber"): void {
    if (draft.pending === null) return;
    delete draft.pending[field];
    if (draft.pending.serial === undefined && draft.pending.crlNumber === undefined) draft.pending = null;
    else draft.pending.op = draft.pending.serial !== undefined ? "sign" : "crl";
  }

  #verifyIssued(entry: IssuedEntry, der: Buffer): ParsedCertificate {
    const cert = parseCertificate(der);
    if (cert.serialHex !== entry.serial || cert.spkiSha256 !== entry.spkiSha256 || !verifyCertificateSignature(cert, this.rootCertificate.spkiDer)) {
      throw new EzError(5, "state_conflict", `The certificate for serial ${entry.serial} does not match its reservation or the root key.`, { reason: "issued_mismatch" });
    }
    return cert;
  }

  public async markActivated(rawSerial: string): Promise<void> {
    const serial = EzStore.canonicalSerial(rawSerial);
    const entry = this.#state.issued.find((e) => e.serial === serial);
    if (entry === undefined || (entry.status !== "signed" && entry.status !== "activated")) {
      throw new EzError(5, "state_conflict", "Only a signed certificate can be marked activated.", { reason: "not_signed" });
    }
    if (entry.status === "activated") return;
    const at = this.now().toISOString();
    await this.#persist((draft) => {
      const e = draft.issued.find((x) => x.serial === serial) as IssuedEntry;
      e.status = "activated";
      e.activatedAt = at;
    });
  }

  /**
   * Records a certificate this root issued before it was adopted (so it can be revoked). It must verify under the root;
   * the file is kept as `issued/<serial>.pem` (no-clobber) and the entry is `imported`. An existing entry is returned as is.
   */
  public async importIssued(input: { der: Buffer; caId: string | null; environment: string | null; adminOrigin: string | null }): Promise<IssuedEntry> {
    const cert = parseCertificate(input.der);
    const root = this.rootCertificate;
    if (!cert.issuerDer.equals(root.subjectDer) || !verifyCertificateSignature(cert, root.spkiDer)) {
      throw new EzError(5, "certificate_invalid", "That certificate was not issued by this root.");
    }
    const existing = this.#state.issued.find((e) => e.serial === cert.serialHex);
    if (existing !== undefined) {
      if ((input.caId !== null && existing.caId !== input.caId) || (existing.fingerprint !== null && existing.fingerprint !== cert.fingerprint)) {
        throw new EzError(5, "state_conflict", `Serial ${cert.serialHex} is already recorded for another CA or certificate.`, { reason: "serial_other_ca" });
      }
      return existing;
    }
    let subjectKey = sha256Hex(cert.subjectDer);
    let subjectDn = "(unreadable subject)";
    try {
      const name = assertRestrictedName(cert.subjectDer, "external");
      subjectKey = name.key;
      subjectDn = describeName(name);
    } catch {
      // not in the restricted form: the DER hash stands in
    }
    const file = issuedFileName(cert.serialHex);
    try {
      await createImmutable(this.path(file), Buffer.from(toPem(cert.der, "CERTIFICATE")), 0o644, this.options);
    } catch (error) {
      if (!(error instanceof EzError && error.code === "already_exists")) throw error;
    }
    await this.#persist((draft) => {
      draft.issued.push({
        serial: cert.serialHex,
        caId: input.caId,
        environment: input.environment,
        adminOrigin: input.adminOrigin,
        subjectDn,
        subjectKey,
        csrSha256: null,
        spkiSha256: cert.spkiSha256,
        certificateFile: file,
        fingerprint: cert.fingerprint,
        notBefore: cert.notBefore.toISOString(),
        notAfter: cert.notAfter.toISOString(),
        status: "imported",
        signedAt: null,
        activatedAt: null,
      });
    });
    return this.#state.issued.find((e) => e.serial === cert.serialHex) as IssuedEntry;
  }

  /** Marks a reservation that will never be signed (for example after the operator declined). */
  public async abandon(rawSerial: string): Promise<void> {
    const serial = EzStore.canonicalSerial(rawSerial);
    const entry = this.#state.issued.find((e) => e.serial === serial);
    if (entry === undefined || entry.status !== "signing") return;
    await this.#persist((draft) => {
      (draft.issued.find((x) => x.serial === serial) as IssuedEntry).status = "abandoned";
      this.#clearPending(draft, "serial");
    });
  }

  /** Adds a revocation (idempotent per serial). The revoked list only ever grows (I3). */
  public async addRevocation(input: {
    serial: string;
    caId: string | null;
    reason: CrlReasonName;
    invalidityDate?: Date;
    imported?: boolean;
  }): Promise<{ added: boolean }> {
    if (input.imported !== true && !NEW_REVOCATION_REASONS.includes(input.reason)) {
      throw new EzError(2, "invalid_input", `${input.reason} is not an allowed revocation reason.`);
    }
    const serial = EzStore.canonicalSerial(input.serial);
    if (this.#state.revoked.some((r) => r.serial === serial)) return { added: false };
    const at = this.now();
    if (input.invalidityDate !== undefined && input.invalidityDate.getTime() > at.getTime()) {
      throw new EzError(2, "invalid_input", "The invalidity date is in the future.");
    }
    await this.#persist((draft) => {
      draft.revoked.push({
        serial,
        caId: input.caId,
        reason: input.reason,
        revokedAt: floorSeconds(at).toISOString(),
        invalidityDate: input.invalidityDate === undefined ? null : floorSeconds(input.invalidityDate).toISOString(),
        imported: input.imported === true,
        listedInCrl: null,
      });
    });
    return { added: true };
  }

  /** Writes `crls/<number>.crl.pem` no-clobber, refreshes the CRL copy atomically, and records it as current. */
  public async commitCrl(number: number, crlDer: Buffer): Promise<void> {
    const crl = this.#verifyCrl(number, crlDer);
    const file = crlFileName(number);
    await createImmutable(this.path(file), Buffer.from(toPem(crlDer, "X509 CRL")), 0o644, this.options);
    await this.fault("commitCrl:file");
    await this.#adoptCrl(number, file, crl);
  }

  /** The CRL must be exactly the reserved one: its number, its thisUpdate, and every revocation (no more, no fewer). */
  #verifyCrl(number: number, der: Buffer): ParsedCrl {
    const crl = parseCrl(der);
    const root = this.rootCertificate;
    const state = this.#state;
    const listed = new Set(crl.entries.map((e) => e.serial));
    const revoked = new Set(state.revoked.map((r) => r.serial));
    const reason =
      state.pending?.crlNumber !== number ? "crl_not_reserved"
      : number <= (state.crl.current?.number ?? 0) ? "crl_not_newer"
      : crl.number !== BigInt(number) || crl.nextUpdate === undefined ? "crl_mismatch"
      : crl.thisUpdate.toISOString() !== state.crl.lastThisUpdate ? "crl_this_update"
      : !crl.issuerDer.equals(root.subjectDer) || !verifyCrlSignature(crl, root.spkiDer) ? "crl_mismatch"
      : [...listed].some((s) => !revoked.has(s)) ? "crl_unknown_entry"
      : [...revoked].some((s) => !listed.has(s)) ? "crl_missing_revocation"
      : this.#entriesDiffer(crl) ? "crl_entry_mismatch"
      : undefined;
    if (reason !== undefined) {
      throw new EzError(5, "state_conflict", `CRL ${number} is not the CRL that was reserved (${reason}).`, { reason });
    }
    return crl;
  }

  /** Each listed entry must carry the recorded reason (absent = unspecified), revocation date and invalidity date. */
  #entriesDiffer(crl: ParsedCrl): boolean {
    const wanted = new Map(this.revocationEntries().map((e) => [e.serial, e]));
    return crl.entries.some((e) => {
      const w = wanted.get(e.serial);
      return (
        w === undefined ||
        (e.reason ?? "unspecified") !== (w.reason ?? "unspecified") ||
        e.revokedAt.getTime() !== w.revokedAt.getTime() ||
        e.invalidityDate?.getTime() !== w.invalidityDate?.getTime()
      );
    });
  }

  async #adoptCrl(number: number, file: string, crl: ParsedCrl): Promise<void> {
    await writeAtomic(this.path(this.#state.crl.copyFile, true), Buffer.from(toPem(crl.der, "X509 CRL")), 0o644, this.options);
    await this.fault("commitCrl:copy");
    await this.#persist((draft) => {
      for (const r of draft.revoked) r.listedInCrl ??= number;
      draft.crl.current = {
        number,
        file,
        sha256: crl.sha256,
        thisUpdate: (crl.thisUpdate).toISOString(),
        nextUpdate: (crl.nextUpdate as Date).toISOString(),
      };
      this.#clearPending(draft, "crlNumber");
    });
  }

  /** `compareWithServer`, plus the local `crls/<n>` hash when the server's CRL number is below ours. */
  public async checkServer(server: ServerRootView): Promise<void> {
    let local: string | undefined;
    // The server zero-pads the number to 40 hex digits; compare as a BigInt.
    if (server.crl !== undefined && /^[0-9a-fA-F]{1,40}$/.test(server.crl.numberHex) && BigInt(`0x${server.crl.numberHex}`) < BigInt(Number.MAX_SAFE_INTEGER)) {
      const n = Number(BigInt(`0x${server.crl.numberHex}`));
      const currentNumber = this.#state.crl.current?.number ?? 0;
      if (n > currentNumber && n <= this.#state.crl.lastNumber) {
        // The server holds a CRL under a number this state allocated but never committed (burned): another signer made it.
        throw new EzError(5, "state_forked", "The server holds a root CRL under a number this state allocated but never published: two copies of this root are signing.", { number: n });
      }
      if (n >= 1 && n < this.#state.crl.lastNumber) {
        const bytes = await readIfExists(this.path(crlFileName(n)));
        if (bytes !== undefined) local = sha256Hex(fromPem(bytes.toString("utf8"), "X509 CRL"));
      }
    }
    compareWithServer(this.#state, server, local);
  }

  /** Records that a CRL number reached a deployment, for `status` and `upload-crl`. */
  public async recordUpload(adminOrigin: string, extId: string, number: number): Promise<void> {
    const seen = this.now().toISOString();
    await this.#persist((draft) => {
      const existing = draft.deployments.find((d) => d.adminOrigin === adminOrigin && d.extId === extId);
      if (existing === undefined) draft.deployments.push({ adminOrigin, extId, lastUploadedCrlNumber: number, lastSeenAt: seen });
      else {
        existing.lastUploadedCrlNumber = Math.max(existing.lastUploadedCrlNumber, number);
        existing.lastSeenAt = seen;
      }
    });
  }

  /**
   * Records a YubiKey that now holds the root key (`import-key`). The first call on a software root switches the
   * storage to `yubikey` and keeps the encrypted backup file; later calls add devices. Slot and policies are fixed by
   * the first record.
   */
  public async recordYubiKey(input: {
    readonly slot: string;
    readonly keyType: string;
    readonly generatedOnDevice: boolean;
    readonly pinPolicy: string;
    readonly touchPolicy: string;
    readonly device: { readonly serial: number; readonly firmware: string; readonly fips: boolean };
  }): Promise<void> {
    const addedAt = this.now().toISOString();
    await this.#persist((draft) => {
      draft.key.storage = "yubikey";
      const record = (draft.key.yubikey ??= {
        slot: input.slot,
        keyType: input.keyType,
        generatedOnDevice: input.generatedOnDevice,
        pinPolicy: input.pinPolicy,
        touchPolicy: input.touchPolicy,
        devices: [],
      });
      if (record.slot !== input.slot) throw new EzError(5, "state_conflict", "This root's YubiKey slot is fixed.", { reason: "slot_changed" });
      const existing = record.devices.find((d) => d.serial === input.device.serial);
      if (existing === undefined) record.devices.push({ ...input.device, addedAt });
      else Object.assign(existing, { firmware: input.device.firmware, fips: input.device.fips });
    });
  }

  /** Deployments whose last uploaded CRL is older than the current one. */
  public deploymentsBehind(): EzState["deployments"] {
    const current = this.#state.crl.current?.number ?? 0;
    return this.#state.deployments.filter((d) => d.lastUploadedCrlNumber < current);
  }

  // -- recovery --------------------------------------------------------------------------------------------------

  async #recover(): Promise<void> {
    // A signing entry: no file means the certificate only ever existed in memory; a verified file rolls forward.
    for (const entry of this.#state.issued.filter((e) => e.status === "signing")) {
      const file = issuedFileName(entry.serial);
      let pem = await readIfExists(this.path(file));
      if (pem !== undefined && !parsesAs(pem, (der) => parseCertificate(fromPem(der, "CERTIFICATE")))) {
        // A torn write (a filesystem without hard links): keep the evidence, then recover as if the file never existed.
        await this.#moveAside(this.path(file));
        pem = undefined;
      }
      if (pem === undefined) pem = await this.#rescueTemp(entry, file);
      if (pem === undefined) {
        await this.#persist((draft) => {
          (draft.issued.find((x) => x.serial === entry.serial) as IssuedEntry).status = "abandoned";
          this.#clearPending(draft, "serial");
        });
      } else {
        const der = fromPem(pem.toString("utf8"), "CERTIFICATE");
        this.#verifyIssued(entry, der);
        await this.#markSigned(entry.serial, file, der);
      }
    }
    const pending = this.#state.pending;
    if (pending?.serial !== undefined) {
      await this.#persist((draft) => this.#clearPending(draft, "serial"));
    }
    if (this.#state.pending?.crlNumber !== undefined) {
      const number = this.#state.pending.crlNumber;
      const current = this.#state.crl.current?.number ?? 0;
      const file = crlFileName(number);
      let pem = number > current ? await readIfExists(this.path(file)) : undefined;
      if (pem !== undefined && !parsesAs(pem, (text) => parseCrl(fromPem(text, "X509 CRL")))) {
        await this.#moveAside(this.path(file));
        pem = undefined;
      }
      if (pem !== undefined) {
        const crl = this.#verifyCrl(number, fromPem(pem.toString("utf8"), "X509 CRL"));
        await this.#adoptCrl(number, file, crl);
      } else {
        // The number is burned: lastNumber stays, the next CRL is N+1.
        await this.#persist((draft) => this.#clearPending(draft, "crlNumber"));
      }
    }
    await this.#sweepTemps();
    // A crash between the immutable CRL and its copy leaves a stale copy; rewrite it from the current CRL.
    const current = this.#state.crl.current;
    if (current !== null) {
      const copy = this.path(this.#state.crl.copyFile, true);
      const existing = await readIfExists(copy);
      const wanted = await readIfExists(this.path(current.file));
      if (wanted !== undefined && (existing === undefined || !existing.equals(wanted))) {
        await writeAtomic(copy, wanted, 0o644, this.options);
      }
    }
  }

  /** Renames an unreadable artifact to `<name>.torn-<time>`; never deletes it. */
  async #moveAside(path: string): Promise<void> {
    await fs.rename(path, `${path}.torn-${this.now().getTime()}`);
  }

  /**
   * A hard crash between writing and linking `issued/<serial>.pem` can leave the signed certificate as a temp file. If it
   * verifies for this reservation it is linked into place (so it is never lost); otherwise it is ignored.
   */
  async #rescueTemp(entry: IssuedEntry, file: string): Promise<Buffer | undefined> {
    const directory = this.path("issued");
    let names: string[];
    try {
      names = await fs.readdir(directory);
    } catch {
      return undefined;
    }
    const pattern = new RegExp(`^\\.${entry.serial}\\.pem\\.[0-9a-f]{12}\\.tmp$`);
    for (const name of names.filter((n) => pattern.test(n))) {
      const bytes = await readIfExists(join(directory, name));
      if (bytes === undefined) continue;
      try {
        this.#verifyIssued(entry, fromPem(bytes.toString("utf8"), "CERTIFICATE"));
      } catch (error) {
        if (error instanceof EzError) continue;
        throw error;
      }
      await createImmutable(this.path(file), bytes, 0o644, this.options);
      return bytes;
    }
    return undefined;
  }

  /** With the lock held, no `.tmp` file in the root directory, `crls/` or `issued/` can be live: remove them. */
  async #sweepTemps(): Promise<void> {
    const esc = (t: string): string => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const own = [this.stateFilePath, this.#state.crl.copyFile, this.#state.root.certificateFile, this.#state.key.file ?? ""]
      .filter((p) => p !== "")
      .map((p) => esc(basename(p)));
    const targets: [string, RegExp][] = [
      [this.dir, new RegExp(`^\\.(?:${own.join("|")})\\.[0-9a-f]{12}\\.tmp$`)],
      [this.path("crls"), /^\.\d{6}\.crl\.pem\.[0-9a-f]{12}\.tmp$/],
      [this.path("issued"), /^\.[0-9a-f]+\.pem\.[0-9a-f]{12}\.tmp$/],
    ];
    for (const [directory, pattern] of targets) {
      let names: string[];
      try {
        names = await fs.readdir(directory);
      } catch {
        continue;
      }
      for (const name of names) {
        if (pattern.test(name)) await fs.unlink(join(directory, name)).catch(() => undefined);
      }
    }
  }

  // -- invariants ------------------------------------------------------------------------------------------------

  async #checkInvariants(): Promise<void> {
    const state = this.#state;
    const conflict = (reason: string, message: string): never => {
      throw new EzError(5, "state_conflict", message, { reason });
    };
    const crl = state.crl;
    // I1
    if (crl.current !== null && crl.current.number > crl.lastNumber) conflict("crl_number_rollback", "The current CRL number exceeds the highest number allocated: the state file was rolled back.");
    // I2
    const serials = new Set<string>();
    for (const entry of state.issued) {
      if (serials.has(entry.serial)) conflict("duplicate_serial", `Serial ${entry.serial} appears twice.`);
      serials.add(entry.serial);
      if (entry.status === "signed" || entry.status === "activated") {
        const der = await this.readIssuedCertificate(entry);
        if (der === undefined) conflict("issued_missing", `The certificate file for serial ${entry.serial} is missing.`);
        else if (sha256Hex(der) !== entry.fingerprint) conflict("issued_tampered", `The certificate file for serial ${entry.serial} was altered.`);
      }
    }
    // I3, I4
    if (crl.current !== null) {
      const pem = await readIfExists(this.path(crl.current.file));
      if (pem === undefined) return conflict("crl_missing", "The current CRL file is missing.");
      const der = fromPem(pem.toString("utf8"), "X509 CRL");
      if (sha256Hex(der) !== crl.current.sha256) conflict("crl_tampered", "The current CRL file does not match the state file.");
      const parsed = parseCrl(der);
      if (parsed.number !== BigInt(crl.current.number) || !verifyCrlSignature(parsed, this.rootCertificate.spkiDer)) {
        conflict("crl_invalid", "The current CRL does not verify under the root or has the wrong number.");
      }
      const revoked = new Set(state.revoked.map((r) => r.serial));
      const listed = new Set(parsed.entries.map((e) => e.serial));
      for (const r of state.revoked) {
        if (r.listedInCrl !== null && r.listedInCrl > crl.current.number) conflict("revoked_ahead", `Serial ${r.serial} is recorded as listed in a CRL newer than the current one.`);
        if (r.listedInCrl !== null && !listed.has(r.serial)) conflict("crl_missing_revocation", `The current CRL does not list revoked serial ${r.serial}.`);
      }
      const missing = parsed.entries.filter((e) => !revoked.has(e.serial));
      if (missing.length > 0) conflict("revoked_shrunk", `The revocation list lost ${missing.length} entr${missing.length === 1 ? "y" : "ies"} that the current CRL lists.`);
    }
    if (crl.current === null && state.revoked.some((r) => r.listedInCrl !== null)) {
      conflict("crl_missing_revocation", "Revocations are recorded as listed, but there is no current CRL.");
    }
    // I7 is enforced at `begin`; here only the recorded times must be consistent.
    if (crl.current !== null && Date.parse(crl.current.thisUpdate) > Date.parse(crl.lastThisUpdate)) {
      conflict("crl_time_rollback", "The current CRL is newer than the recorded last thisUpdate.");
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Online cross-check
// ---------------------------------------------------------------------------------------------------------------------

export interface ServerRootView {
  /** The external CA record's certificate fingerprint, when the root is registered. */
  readonly fingerprint?: string;
  /** The stored root CRL: number as hex (any padding), sha256 and, if known, the revoked serials it lists. */
  readonly crl?: { readonly numberHex: string; readonly sha256: string; readonly serials?: readonly string[] };
}

const invalidResponse = (what: string): EzError => new EzError(7, "invalid_response", `The server's ${what} is malformed.`);

/**
 * Compares the local state with the server's view; throws the section 6.3 online conflicts. `localSha256AtServerNumber`
 * is the sha256 of the local `crls/<server number>` file, for when the server is behind the local state.
 */
export const compareWithServer = (state: Readonly<EzState>, server: ServerRootView, localSha256AtServerNumber?: string): void => {
  if (server.fingerprint !== undefined && server.fingerprint !== state.root.fingerprint) {
    throw new EzError(5, "root_mismatch", "The server has a different certificate for this root key.", {
      server: server.fingerprint,
      local: state.root.fingerprint,
    });
  }
  if (server.crl === undefined) return;
  if (!/^[0-9a-fA-F]{1,40}$/.test(server.crl.numberHex)) throw invalidResponse("CRL number");
  if (!/^[0-9a-fA-F]{64}$/.test(server.crl.sha256)) throw invalidResponse("CRL hash");
  const serverSha = server.crl.sha256.toLowerCase();
  const serverNumber = BigInt(`0x${server.crl.numberHex}`);
  if (serverNumber > BigInt(state.crl.lastNumber)) {
    throw new EzError(5, "state_behind_server", "The server holds a newer root CRL than this state knows: the state file is out of date or was restored from a backup.", {
      serverNumber: serverNumber.toString(),
      localNumber: state.crl.lastNumber,
    });
  }
  const current = state.crl.current;
  if (current !== null && serverNumber === BigInt(current.number) && serverSha !== current.sha256) {
    throw new EzError(5, "state_forked", "The server's root CRL has the same number as this state's but different content: two copies of this root are signing.", {
      number: current.number,
    });
  }
  if (serverNumber < BigInt(state.crl.lastNumber) && localSha256AtServerNumber !== undefined && localSha256AtServerNumber !== serverSha) {
    throw new EzError(5, "state_forked", "The server's older root CRL is not one this state signed under that number: two copies of this root are signing.", {
      number: serverNumber.toString(),
    });
  }
  if (server.crl.serials !== undefined) {
    const local = new Set(state.revoked.map((r) => r.serial));
    const unknown = server.crl.serials
      .map((s) => {
        try {
          return EzStore.canonicalSerial(s);
        } catch {
          throw invalidResponse("revoked serial");
        }
      })
      .filter((s) => !local.has(s));
    if (unknown.length > 0) {
      throw new EzError(5, "state_behind_server", "The server's root CRL revokes serials this state does not know about.", { serials: unknown });
    }
  }
};
// ---------------------------------------------------------------------------------------------------------------------
// Initial state for generate-ca / adopt-ca
// ---------------------------------------------------------------------------------------------------------------------

export type InitialState = Omit<EzState, "format" | "version" | "revision" | "updatedAt">;

export interface InitialStateInput {
  readonly origin: "generated" | "adopted";
  readonly subject: Record<string, string>;
  readonly subjectDn: string;
  readonly root: ParsedCertificate;
  readonly keyAlgorithm: string;
  readonly pathLen?: number | null;
  readonly key: EzState["key"];
  /** The first CRL (generate-ca signs CRL #1 with the root). */
  readonly crl: ParsedCrl;
  readonly certificateFile?: string;
  readonly crlCopyFile?: string;
  readonly defaults?: Partial<EzState["defaults"]>;
  readonly adoption?: EzState["adoption"];
  readonly reissuedFrom?: EzState["root"]["reissuedFrom"];
  readonly now: Date;
}

/** The state of a freshly generated (or adopted) root with its first CRL. */
export const initialState = (input: InitialStateInput): InitialState => {
  const { root, crl } = input;
  return {
    root: {
      origin: input.origin,
      subject: input.subject,
      subjectDn: input.subjectDn,
      certificateFile: input.certificateFile ?? "root.pem",
      fingerprint: root.fingerprint,
      spkiSha256: root.spkiSha256,
      extIdHint: `ext-${root.spkiSha256.slice(0, 40)}`,
      subjectKeyIdentifier: (root.subjectKeyIdentifier as Buffer).toString("hex"),
      serial: root.serialHex,
      notBefore: root.notBefore.toISOString(),
      notAfter: root.notAfter.toISOString(),
      keyAlgorithm: input.keyAlgorithm,
      pathLen: input.pathLen ?? null,
      reissuedFrom: input.reissuedFrom ?? null,
    },
    adoption: input.adoption ?? null,
    key: input.key,
    defaults: {
      intermediateValidityDays: input.defaults?.intermediateValidityDays ?? EZ_DEFAULTS.intermediateValidityDays,
      crlValidityDays: input.defaults?.crlValidityDays ?? EZ_DEFAULTS.crlValidityDays,
    },
    crl: {
      lastNumber: Number(crl.number),
      lastThisUpdate: crl.thisUpdate.toISOString(),
      copyFile: input.crlCopyFile ?? "root.crl.pem",
      current: {
        number: Number(crl.number),
        file: crlFileName(Number(crl.number)),
        sha256: crl.sha256,
        thisUpdate: crl.thisUpdate.toISOString(),
        nextUpdate: (crl.nextUpdate as Date).toISOString(),
      },
    },
    issued: [],
    revoked: [],
    deployments: [],
    pending: null,
    lastSignedAt: input.now.toISOString(),
  };
};

/** The files `EzStore.create` writes for a new root: certificate, CRL (immutable and copy) and the key file if any. */
export const initialArtifacts = (
  state: InitialState,
  parts: { readonly rootDer: Buffer; readonly crlDer: Buffer; readonly keyFilePem?: string },
): ArtifactFile[] => [
  ...(parts.keyFilePem === undefined || state.key.file === null
    ? []
    : [{ path: state.key.file, data: Buffer.from(parts.keyFilePem), mode: 0o600, allowAbsolute: true }]),
  { path: state.root.certificateFile, data: Buffer.from(toPem(parts.rootDer, "CERTIFICATE")), mode: 0o644, allowAbsolute: true },
  { path: (state.crl.current as { file: string }).file, data: Buffer.from(toPem(parts.crlDer, "X509 CRL")), mode: 0o644 },
  { path: state.crl.copyFile, data: Buffer.from(toPem(parts.crlDer, "X509 CRL")), mode: 0o644, allowAbsolute: true },
];
