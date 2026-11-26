import { EzError } from "./ez-error";
import { EZ_DEFAULTS } from "./ez-profile";
import { assertRestrictedName, subjectFromName, type Subject } from "./ez-name";
import { readPrivateKey, type ReadKey } from "./ez-keyfile";
import type { IssuedEntry, RevokedEntry } from "./ez-state";
import {
  DAY_MS,
  EXTENSION_PROFILE_REASONS,
  floorSeconds,
  OID,
  parseBasicConstraints,
  parseCrl,
  randomSerial,
  reasonName,
  selfCheckCrl,
  sha256Hex,
  verifyCrlSignature,
  type CrlEntry,
  type CrlReasonName,
  type ParsedCertificate,
  type ParsedCrl,
} from "./ez-x509";
import { EzStore } from "./ez-state";

/**
 * The pure parts of `adopt-ca` (design section 8): reading an OpenSSL recipe's `index.txt` and `crlnumber`, merging the
 * revocation sources, deciding the CRL number and whether an adopted CRL can stay current, and planning a
 * re-issued root certificate. Nothing here touches the disk, the network or a device.
 */

// ---------------------------------------------------------------------------------------------------------------------
// OpenSSL `index.txt` and `crlnumber`
// ---------------------------------------------------------------------------------------------------------------------

/** OpenSSL's revocation reason names (case-insensitive) onto CRL reasons. `removeFromCRL` has no mapping and is refused. */
const OPENSSL_REASONS: Readonly<Record<string, CrlReasonName>> = {
  unspecified: "unspecified",
  keycompromise: "keyCompromise",
  cacompromise: "caCompromise",
  affiliationchanged: "affiliationChanged",
  superseded: "superseded",
  cessationofoperation: "cessationOfOperation",
  certificatehold: "certificateHold",
  privilegewithdrawn: "privilegeWithdrawn",
  aacompromise: "aACompromise",
};

export interface IndexRevocation {
  readonly at: Date;
  readonly reason: CrlReasonName;
  readonly invalidityDate?: Date;
}

export interface IndexRow {
  readonly line: number;
  readonly status: "V" | "R" | "E";
  readonly expiry: Date;
  readonly revoked?: IndexRevocation;
  /** Canonical lowercase hex. */
  readonly serial: string;
  readonly subject: string;
}

const badIndex = (line: number, message: string): never => {
  throw new EzError(2, "invalid_input", `index.txt line ${line}: ${message}.`);
};

/** `YYMMDDHHMMSSZ` (UTCTime, years 50-99 are 19xx) or `YYYYMMDDHHMMSSZ`. */
const parseOpenSslTime = (text: string, line: number): Date => {
  const match = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (match === null) return badIndex(line, `"${text.slice(0, 32)}" is not an OpenSSL time (YYMMDDHHMMSSZ)`);
  const [, y, mo, d, h, mi, s] = match as unknown as [string, string, string, string, string, string, string];
  const year = y.length === 4 ? Number(y) : Number(y) < 50 ? 2000 + Number(y) : 1900 + Number(y);
  const date = new Date(Date.UTC(year, Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
  if (date.getUTCMonth() !== Number(mo) - 1 || date.getUTCDate() !== Number(d) || Number(h) > 23 || Number(mi) > 59 || Number(s) > 59) {
    return badIndex(line, `"${text}" is not a valid time`);
  }
  return date;
};

const parseRevocation = (field: string, line: number): IndexRevocation => {
  const [time = "", reasonText, extra] = field.split(",");
  const at = parseOpenSslTime(time, line);
  if (reasonText === undefined || reasonText === "") return { at, reason: "unspecified" };
  const lower = reasonText.toLowerCase();
  // `openssl ca -crl_hold <oid>` writes `revtime,holdInstruction,<oid>`.
  if (lower.startsWith("holdinstruction")) return { at, reason: "certificateHold" };
  if (lower === "keytime" || lower === "cakeytime") {
    // OpenSSL's `revocation,keyTime,compromiseTime` form: the compromise time becomes the invalidity date.
    return { at, reason: lower === "keytime" ? "keyCompromise" : "caCompromise", invalidityDate: extra === undefined ? undefined : parseOpenSslTime(extra, line) };
  }
  const reason = OPENSSL_REASONS[lower];
  if (reason === undefined) {
    return badIndex(line, lower === "removefromcrl" ? "removeFromCRL cannot be adopted" : `unknown revocation reason "${reasonText.slice(0, 32)}"`);
  }
  return { at, reason };
};

/** Parses an OpenSSL `index.txt`: tab-separated status, expiry, revocation, serial, file name and subject. */
export const parseOpenSslIndex = (text: string): IndexRow[] => {
  const rows: IndexRow[] = [];
  const lines = text.split("\n");
  for (const [i, raw] of lines.entries()) {
    const line = i + 1;
    const content = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (content.trim() === "") continue;
    const fields = content.split("\t");
    if (fields.length < 6) badIndex(line, "expected six tab-separated fields");
    const [status = "", expiry = "", revocation = "", serialText = "", , ...rest] = fields;
    if (status !== "V" && status !== "R" && status !== "E") badIndex(line, `unknown status "${status.slice(0, 8)}"`);
    let serial: string;
    try {
      serial = EzStore.canonicalSerial(serialText);
    } catch {
      return badIndex(line, "the serial is not a positive hexadecimal number");
    }
    if (status === "R" && revocation === "") badIndex(line, "a revoked row has no revocation time");
    if (status !== "R" && revocation !== "") badIndex(line, "only a revoked row may carry a revocation time");
    rows.push({
      line,
      status: status as IndexRow["status"],
      expiry: parseOpenSslTime(expiry, line),
      ...(status === "R" ? { revoked: parseRevocation(revocation, line) } : {}),
      serial,
      subject: rest.join("\t"),
    });
  }
  return rows;
};

/** The `crlnumber` file holds the NEXT CRL number in hex. */
export const parseOpenSslCrlNumber = (text: string): bigint => {
  const value = text.trim();
  if (!/^[0-9A-Fa-f]{1,80}$/.test(value)) throw new EzError(2, "invalid_input", "The crlnumber file must hold one hexadecimal number.");
  const next = BigInt(`0x${value}`);
  if (next < 1n) throw new EzError(2, "invalid_input", "The crlnumber file holds 0; it must hold the next CRL number (at least 1).");
  return next;
};

const IMPORTED_SPKI = "0".repeat(64);

/** One `imported` issued entry per index row (a serial may appear once; a revoked row wins). */
export const importedIssuedEntries = (rows: readonly IndexRow[], root: { readonly notBefore: Date }): IssuedEntry[] => {
  const bySerial = new Map<string, IndexRow>();
  for (const row of rows) {
    const existing = bySerial.get(row.serial);
    if (existing === undefined || (existing.status !== "R" && row.status === "R")) bySerial.set(row.serial, row);
  }
  return [...bySerial.values()].map((row) => ({
    serial: row.serial,
    caId: null,
    environment: null,
    adminOrigin: null,
    subjectDn: row.subject.replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).slice(0, 512),
    // The certificate itself is unknown, so neither its subject key nor its public key can clash with a later issuance.
    subjectKey: sha256Hex(Buffer.from(`imported:${row.serial}`)),
    csrSha256: null,
    spkiSha256: IMPORTED_SPKI,
    certificateFile: null,
    fingerprint: null,
    notBefore: root.notBefore.toISOString(),
    notAfter: row.expiry.toISOString(),
    status: "imported" as const,
    signedAt: null,
    activatedAt: null,
  }));
};

// ---------------------------------------------------------------------------------------------------------------------
// Revocation sources
// ---------------------------------------------------------------------------------------------------------------------

export type RevocationSource = "server" | "crl-file" | "openssl-index";

export interface RevocationRecord {
  readonly serial: string;
  readonly reason: CrlReasonName;
  readonly revokedAt: Date;
  readonly invalidityDate?: Date;
  readonly source: RevocationSource;
}

export const recordsFromCrl = (crl: ParsedCrl, source: RevocationSource): RevocationRecord[] =>
  crl.entries.map((entry) => ({
    serial: entry.serial,
    reason: entry.reason ?? "unspecified",
    revokedAt: entry.revokedAt,
    ...(entry.invalidityDate === undefined ? {} : { invalidityDate: entry.invalidityDate }),
    source,
  }));

export const recordsFromIndex = (rows: readonly IndexRow[]): RevocationRecord[] =>
  rows.flatMap((row) =>
    row.revoked === undefined
      ? []
      : [{ serial: row.serial, reason: row.revoked.reason, revokedAt: row.revoked.at, ...(row.revoked.invalidityDate === undefined ? {} : { invalidityDate: row.revoked.invalidityDate }), source: "openssl-index" as const }],
  );

/** The union of every source. When two sources list a serial, the first list given wins (callers pass server, CRL files, index). */
export const mergeRevocations = (lists: readonly (readonly RevocationRecord[])[]): RevocationRecord[] => {
  const merged = new Map<string, RevocationRecord>();
  for (const list of lists) for (const record of list) if (!merged.has(record.serial)) merged.set(record.serial, record);
  return [...merged.values()].sort((a, b) => (BigInt(`0x${a.serial}`) < BigInt(`0x${b.serial}`) ? -1 : 1));
};

export const revokedEntriesOf = (records: readonly RevocationRecord[], listedInCrl: number | null): RevokedEntry[] =>
  records.map((r) => ({
    serial: r.serial,
    caId: null,
    reason: r.reason,
    revokedAt: floorSeconds(r.revokedAt).toISOString(),
    invalidityDate: r.invalidityDate === undefined ? null : floorSeconds(r.invalidityDate).toISOString(),
    imported: true,
    listedInCrl,
  }));

export const crlEntriesOf = (records: readonly RevocationRecord[]): CrlEntry[] =>
  records.map((r) => ({ serial: r.serial, revokedAt: r.revokedAt, reason: r.reason, ...(r.invalidityDate === undefined ? {} : { invalidityDate: r.invalidityDate }) }));

/** A CRL given to adopt-ca must verify under the root: same issuer name and a valid signature by the root key. */
export const assertCrlFromRoot = (crl: ParsedCrl, root: ParsedCertificate, label: string, serverProfile = false): void => {
  if (!crl.issuerDer.equals(root.subjectDer) || !verifyCrlSignature(crl, root.spkiDer)) {
    throw new EzError(5, "crl_invalid", `${label} was not issued by this root (its issuer or signature does not verify under the root's key); nothing was adopted.`);
  }
  assertCrlProfile(crl, label, serverProfile);
};

/** What Hemlig's root-CRL upload refuses (`serverProfile`: exactly that and nothing more), so EZ never treats such a CRL as a source of revocations (no `src/` import). */
export const assertCrlProfile = (crl: ParsedCrl, label: string, serverProfile = false): void => {
  const refuse = (why: string): never => {
    throw new EzError(5, "crl_invalid", `${label} cannot be used: ${why}. Hemlig refuses such a CRL for a root, so it will not guess what it revokes.`, { reason: why });
  };
  const present = (oid: string): boolean => crl.extensions.some((e) => e.oid === oid);
  if (present(OID.issuingDistributionPoint)) refuse("it has an issuing distribution point (a partitioned CRL)");
  if (present(OID.deltaCrlIndicator) || present(OID.freshestCrl)) refuse("it is a delta CRL or points to one");
  if (crl.extensions.some((e) => e.critical && e.oid !== OID.crlNumber && e.oid !== OID.aki)) refuse("it has an unrecognized critical extension");
  for (const entry of crl.entries) {
    if (entry.reasonCode === 8) refuse(`serial ${entry.serial} has reason removeFromCRL`);
    // The server accepts any reason code but 8; EZ is stricter for the CRLs it adopts (it must know what they revoke).
    if (!serverProfile && entry.reasonCode !== undefined && reasonName(entry.reasonCode) === undefined) refuse(`serial ${entry.serial} has the unknown reason code ${entry.reasonCode}`);
    const extensions = entry.extensions ?? [];
    if (extensions.some((e) => e.oid === OID.certificateIssuer)) refuse("it is an indirect CRL (a certificateIssuer entry extension)");
    if (extensions.some((e) => e.critical && e.oid !== OID.reasonCode && e.oid !== OID.invalidityDate)) refuse("an entry has an unrecognized critical extension");
  }
};

export const parseCrlSource = (bytes: Buffer, fromPem: (text: string) => Buffer): ParsedCrl => {
  const text = bytes.toString("latin1");
  return parseCrl(text.includes("-----BEGIN") ? fromPem(text) : bytes);
};

// ---------------------------------------------------------------------------------------------------------------------
// CRL number and what becomes the current CRL
// ---------------------------------------------------------------------------------------------------------------------

export interface NumberSources {
  /** `--crl-number N`. */
  readonly flag?: bigint;
  /** `--openssl-crlnumber`, already `next - 1`. */
  readonly crlnumberFile?: bigint;
  /** Every verified CRL (files and the server's), with its origin. */
  readonly crls: readonly { readonly source: "server" | "crl-file"; readonly crl: ParsedCrl }[];
}

export interface CrlPlan {
  readonly lastNumber: bigint;
  /** Which sources supplied a number. */
  readonly sources: readonly string[];
  /** The newest thisUpdate among every CRL seen (a new CRL must come strictly after it). */
  readonly newestThisUpdate?: Date;
  /** The adopted CRL that stays current (no new CRL is signed), if it qualifies. */
  readonly adopted?: { readonly crl: ParsedCrl; readonly source: "server" | "crl-file" };
  /** The server's number raised the number given by the operator. */
  readonly raisedByServer: boolean;
}

export const MAX_STATE_CRL_NUMBER = BigInt(Number.MAX_SAFE_INTEGER);

export const planCrl = (
  sources: NumberSources,
  options: {
    readonly now: Date;
    readonly renewBeforeDays: number;
    readonly root: ParsedCertificate & { readonly subjectKeyIdentifier: Buffer };
    readonly records: readonly RevocationRecord[];
  },
): CrlPlan => {
  const numbers: { name: string; value: bigint }[] = [];
  if (sources.flag !== undefined) numbers.push({ name: "flag", value: sources.flag });
  if (sources.crlnumberFile !== undefined) numbers.push({ name: "openssl-crlnumber", value: sources.crlnumberFile });
  for (const { source, crl } of sources.crls) if (crl.number !== undefined) numbers.push({ name: source, value: crl.number });
  if (numbers.length === 0) {
    throw new EzError(2, "crl_number_required", "No CRL number source: pass --crl-number N, which must be at least the number of the last CRL this root ever issued (uploaded to Hemlig or not), or give a CRL, an OpenSSL crlnumber file, or log in so the server's root CRL can be read.");
  }
  const lastNumber = numbers.reduce((max, n) => (n.value > max ? n.value : max), 0n);
  if (lastNumber >= MAX_STATE_CRL_NUMBER) throw new EzError(2, "invalid_input", "The CRL number is too large for the Hemlig state file.");
  const serverNumber = numbers.find((n) => n.name === "server")?.value;
  const operatorNumber = [sources.flag, sources.crlnumberFile].filter((n): n is bigint => n !== undefined);
  const raisedByServer = serverNumber !== undefined && operatorNumber.some((n) => serverNumber > n);
  const same = sources.crls.filter(({ crl }) => crl.number === lastNumber);
  const first = same[0];
  for (const other of same.slice(1)) {
    if (other.crl.sha256 !== (first as (typeof same)[number]).crl.sha256) {
      throw new EzError(5, "state_forked", `Two different CRLs carry number ${lastNumber}: two copies of this root are signing. Nothing was adopted.`, { number: lastNumber.toString() });
    }
  }
  const newest = sources.crls.reduce<Date | undefined>((latest, { crl }) => (latest === undefined || crl.thisUpdate > latest ? crl.thisUpdate : latest), undefined);
  let adopted: CrlPlan["adopted"];
  if (first !== undefined && qualifiesAsCurrent(first.crl, options)) {
    // Prefer the server's copy when it is one of the identical candidates.
    const server = same.find((c) => c.source === "server");
    adopted = { crl: first.crl, source: (server ?? first).source };
  }
  return {
    lastNumber,
    sources: numbers.map((n) => n.name).filter((name, i, all) => all.indexOf(name) === i),
    ...(newest === undefined ? {} : { newestThisUpdate: newest }),
    ...(adopted === undefined ? {} : { adopted }),
    raisedByServer,
  };
};

/**
 * An adopted CRL may stay current only when it is exactly what EZ would sign and serve: the server's profile, still fresh
 * for the renewal window, and listing every known revocation with the recorded reason and dates.
 */
const qualifiesAsCurrent = (
  crl: ParsedCrl,
  options: { readonly now: Date; readonly renewBeforeDays: number; readonly root: ParsedCertificate & { readonly subjectKeyIdentifier: Buffer }; readonly records: readonly RevocationRecord[] },
): boolean => {
  try {
    selfCheckCrl(crl.der, { spkiDer: options.root.spkiDer, subjectDer: options.root.subjectDer, subjectKeyIdentifier: options.root.subjectKeyIdentifier });
  } catch {
    return false;
  }
  const next = crl.nextUpdate as Date;
  if (crl.thisUpdate.getTime() > options.now.getTime() + EZ_DEFAULTS.thisUpdateAheadSeconds * 1000) return false;
  if (next.getTime() - options.now.getTime() < options.renewBeforeDays * DAY_MS) return false;
  if (next.getTime() - crl.thisUpdate.getTime() > EZ_DEFAULTS.crlValidityMaxDays * DAY_MS) return false;
  if (crl.extensions.some((e) => e.critical)) return false;
  const listed = new Map(crl.entries.map((e) => [e.serial, e]));
  if (listed.size !== crl.entries.length || listed.size !== options.records.length) return false;
  return options.records.every((r) => {
    const entry = listed.get(r.serial);
    return (
      entry !== undefined &&
      (entry.reason ?? "unspecified") === r.reason &&
      entry.revokedAt.getTime() === floorSeconds(r.revokedAt).getTime() &&
      entry.invalidityDate?.getTime() === (r.invalidityDate === undefined ? undefined : floorSeconds(r.invalidityDate).getTime())
    );
  });
};

/** The thisUpdate for a CRL EZ signs now: strictly after every CRL seen, never more than 5 minutes ahead of the clock. */
export const nextThisUpdate = (now: Date, newest: Date | undefined): Date => {
  const candidate = new Date(Math.max(floorSeconds(now).getTime(), newest === undefined ? 0 : newest.getTime() + 1000));
  if (candidate.getTime() - now.getTime() > EZ_DEFAULTS.thisUpdateAheadSeconds * 1000) {
    throw new EzError(5, "clock_regressed", "The clock is behind the newest CRL this root signed; check the system time.", { newestThisUpdate: (newest as Date).toISOString() });
  }
  return candidate;
};

// ---------------------------------------------------------------------------------------------------------------------
// Root certificate checks
// ---------------------------------------------------------------------------------------------------------------------

export const REISSUE_FLAG = "--reissue-root-certificate";

/**
 * Decides what the validation reasons mean for adoption. Nothing to fix: fine (a re-issue request is refused, since it
 * would change the fingerprint for no reason). Only extension-profile failures: a re-issue can fix them, and without the
 * flag the error names it. Anything else is a plain refusal.
 */
export const gateRootProfile = (reasons: readonly string[], reissue: boolean): void => {
  if (reasons.length === 0) {
    if (reissue) throw new EzError(2, "reissue_not_needed", `The root certificate already meets the profile; ${REISSUE_FLAG} would change its fingerprint for no reason.`);
    return;
  }
  const others = reasons.filter((r) => !EXTENSION_PROFILE_REASONS.has(r));
  if (others.length > 0) {
    throw new EzError(5, "root_profile_invalid", `The root certificate cannot be adopted (${reasons.join(", ")}); ${REISSUE_FLAG} cannot fix ${others.join(", ")}.`, { reasons: [...reasons] });
  }
  if (!reissue) {
    throw new EzError(5, "root_profile_invalid", `The root certificate lacks the CA extensions Hemlig requires (${reasons.join(", ")}). Rerun with ${REISSUE_FLAG} to issue a new self-signed certificate for the same key and name; its fingerprint will change.`, { reasons: [...reasons] });
  }
};

export interface ReissuePlan {
  readonly subjectDer: Buffer;
  readonly serial: Buffer;
  readonly subjectKeyIdentifier: Buffer | undefined;
  readonly pathLen: number | undefined;
  /** The old pathLen that the re-issue drops (a root with pathLen 0 cannot sign an intermediate). */
  readonly droppedPathLen: number | undefined;
  readonly notAfter: Date;
}

/** Same subject DER and key, a new random serial, the old end date (or `--validity`), the old SKI value if there is one. */
export const planReissue = (old: ParsedCertificate, validityDays: number | undefined, now: Date): ReissuePlan => {
  const notAfter = validityDays === undefined ? old.notAfter : new Date(floorSeconds(now).getTime() + validityDays * DAY_MS);
  if (notAfter.getTime() - now.getTime() < EZ_DEFAULTS.adoptMinimumRemainingDays * DAY_MS) {
    throw new EzError(2, "invalid_input", `The re-issued root must stay valid for at least ${EZ_DEFAULTS.adoptMinimumRemainingDays} days.`);
  }
  const bc = old.extensions.find((e) => e.oid === OID.basicConstraints);
  let pathLen: number | undefined;
  try {
    pathLen = bc === undefined ? undefined : parseBasicConstraints(bc.value).pathLen;
  } catch {
    pathLen = undefined;
  }
  return {
    subjectDer: old.subjectDer,
    serial: randomSerial(),
    subjectKeyIdentifier: old.subjectKeyIdentifier,
    pathLen: pathLen !== undefined && pathLen >= 1 ? pathLen : undefined,
    droppedPathLen: pathLen !== undefined && pathLen < 1 ? pathLen : undefined,
    notAfter,
  };
};

export const subjectOfRoot = (root: ParsedCertificate): Subject => subjectFromName(assertRestrictedName(root.subjectDer, "external"));

// ---------------------------------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------------------------------

export const isEncryptedKeyPem = (pem: string): boolean => /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) || /Proc-Type:\s*4,ENCRYPTED/.test(pem);

const TOPK8 = "openssl pkcs8 -topk8 -in KEY.pem -out KEY.p8.pem";

/**
 * Reads the source key (an OpenSSL PKCS#8 PBES2 key, a traditional `-aes256` PEM, or an unencrypted key). Node reads
 * every form OpenSSL's default provider reads; a key it cannot read gets an error naming the PKCS#8 conversion.
 */
export const readSourceKey = (pem: string, passphrase: Buffer | undefined): ReadKey => {
  try {
    return readPrivateKey(pem, passphrase);
  } catch (error) {
    if (error instanceof EzError && /Proc-Type:\s*4,ENCRYPTED/.test(pem)) {
      throw new EzError(error.exitCode, error.code, `${error.message} This is a traditional PEM key: if the passphrase is right but the cipher is unsupported, convert it first with \`${TOPK8}\` and adopt the converted copy.`);
    }
    if (error instanceof EzError && error.code === "key_file_invalid") {
      throw new EzError(2, "key_file_invalid", `${error.message} Convert other key formats to PKCS#8 with \`${TOPK8}\`.`);
    }
    throw error;
  }
};

export const KEY_FILE_ALGORITHM_WARNINGS = (algorithm: string): string[] => (algorithm === "RSA_2048" ? ["root_key_rsa_2048"] : []);
