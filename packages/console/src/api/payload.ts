/**
 * Client-side mirrors of src/domain/validation.ts. These exist to give fast
 * feedback in a form; the server remains the authority on every rule here. A
 * rule enforced here but not there would be a security bug, so nothing in this
 * file may be stricter than the service.
 */
export const MAX_PAYLOAD_BYTES = 768_000;

const entryKey = /^[A-Za-z0-9._-]+$/;
export const identifier = /^[a-z][a-z0-9-]{2,63}$/;
/** Mirrors `assertEnvironmentName` in src/domain/validation.ts. */
export const environmentName = /^[a-z][a-z0-9-]{0,63}$/;
export const metadataPath =
  /^[a-z0-9][a-z0-9._-]{0,63}(?:\/[a-z0-9][a-z0-9._-]{0,63})*$/;
export const tagKey = /^[a-z][a-z0-9-]{0,31}$/;
export const tagValue = /^[A-Za-z0-9][A-Za-z0-9._@+/-]{0,127}$/;

/**
 * Mirrors `parseCatalogPathPrefix` in src/domain/validation.ts exactly (same
 * length bound, same `metadataPath` shape) — used for the folder path an
 * operator types when creating a folder, so the client rejects the same
 * inputs the service would, no stricter and no looser.
 */
export const isValidFolderPath = (value: string): boolean =>
  value.length > 0 && value.length <= 256 && metadataPath.test(value);

export type Encoding = "utf8" | "base64";

export interface PayloadRow {
  readonly id: string;
  key: string;
  value: string;
  encoding: Encoding;
}

export const isCanonicalBase64 = (value: string): boolean => {
  if (value.length === 0) {
    return true;
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    return false;
  }
  try {
    const decoded = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    let reencoded = "";
    decoded.forEach((byte) => {
      reencoded += String.fromCharCode(byte);
    });
    return btoa(reencoded) === value;
  } catch {
    return false;
  }
};

export const rowError = (row: PayloadRow): string | undefined => {
  if (row.key.length === 0) {
    return "A key is required.";
  }
  if (!entryKey.test(row.key)) {
    return "Keys may contain only letters, digits, '.', '_', and '-'.";
  }
  if (row.encoding === "base64" && !isCanonicalBase64(row.value)) {
    return "Value is not canonical RFC 4648 base64.";
  }
  return undefined;
};

export const toPayload = (
  rows: readonly PayloadRow[],
): Record<string, { encoding: Encoding; value: string }> =>
  Object.fromEntries(
    rows.map((row) => [row.key, { encoding: row.encoding, value: row.value }]),
  );

/** Measures exactly what the service measures: the serialized request payload. */
export const payloadBytes = (rows: readonly PayloadRow[]): number =>
  new TextEncoder().encode(JSON.stringify(toPayload(rows))).length;

export const duplicateKeys = (rows: readonly PayloadRow[]): readonly string[] => {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const row of rows) {
    if (row.key.length === 0) {
      continue;
    }
    if (seen.has(row.key)) {
      duplicates.add(row.key);
    }
    seen.add(row.key);
  }
  return [...duplicates];
};

export interface PayloadProblems {
  readonly rows: ReadonlyMap<string, string>;
  readonly duplicates: readonly string[];
  readonly bytes: number;
  readonly oversize: boolean;
  readonly valid: boolean;
}

export const inspectPayload = (rows: readonly PayloadRow[]): PayloadProblems => {
  const problems = new Map<string, string>();
  for (const row of rows) {
    const error = rowError(row);
    if (error !== undefined) {
      problems.set(row.id, error);
    }
  }
  const duplicates = duplicateKeys(rows);
  const bytes = payloadBytes(rows);
  const oversize = bytes > MAX_PAYLOAD_BYTES;
  return {
    rows: problems,
    duplicates,
    bytes,
    oversize,
    valid: problems.size === 0 && duplicates.length === 0 && !oversize && rows.length > 0,
  };
};

/**
 * Parses pasted .env-style text into rows. Values are treated as utf8; nothing
 * here attempts to guess base64, because guessing wrong silently corrupts a
 * delivered secret.
 */
export const parseDotEnv = (text: string, id: () => string): PayloadRow[] => {
  const rows: PayloadRow[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    const withoutExport = line.startsWith("export ") ? line.slice(7).trim() : line;
    const separator = withoutExport.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const key = withoutExport.slice(0, separator).trim();
    let value = withoutExport.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    rows.push({ id: id(), key, value, encoding: "utf8" });
  }
  return rows;
};

/** Keys present in the stored payload that this submission would destroy. */
export const destroyedKeyCount = (
  currentKeyCount: number | undefined,
  submittedCount: number,
): number | undefined =>
  currentKeyCount === undefined ? undefined : Math.max(0, currentKeyCount - submittedCount);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Pretty-prints rows as the wire format the JSON tab edits and the service accepts. */
export const toJsonText = (rows: readonly PayloadRow[]): string =>
  JSON.stringify(toPayload(rows), null, 2);

export type JsonParseResult =
  | { readonly ok: true; readonly rows: PayloadRow[] }
  | { readonly ok: false; readonly error: string };

/**
 * Parses the JSON tab's text. This is the wire format
 * (`{ key: { encoding, value } }`), not a flat `{ key: value }` map: the flat
 * form cannot express `encoding`, and silently dropping it would change what
 * gets delivered. Mirrors `parsePayload` in src/domain/validation.ts, minus
 * the byte-size check, which `inspectPayload` already applies to the
 * resulting rows regardless of which tab produced them.
 *
 * Never throws. An unparseable document or one that violates the payload
 * rules is reported as an error so the caller can leave the operator's text
 * on screen instead of discarding it.
 */
export const parseJsonPayload = (text: string, id: () => string): JsonParseResult => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { ok: false, error: `Invalid JSON: ${(error as Error).message}` };
  }
  if (!isRecord(parsed)) {
    return { ok: false, error: "payload must be an object of Secret entries." };
  }
  const rows: PayloadRow[] = [];
  for (const [key, entry] of Object.entries(parsed)) {
    if (!entryKey.test(key)) {
      return { ok: false, error: `payload key ${key} is invalid.` };
    }
    if (
      !isRecord(entry) ||
      (entry.encoding !== "utf8" && entry.encoding !== "base64") ||
      typeof entry.value !== "string"
    ) {
      return {
        ok: false,
        error: `payload entry ${key} must contain encoding=utf8|base64 and string value.`,
      };
    }
    if (entry.encoding === "base64" && !isCanonicalBase64(entry.value)) {
      return { ok: false, error: `payload entry ${key} is not canonical base64.` };
    }
    rows.push({ id: id(), key, value: entry.value, encoding: entry.encoding });
  }
  return { ok: true, rows };
};

/**
 * Quotes a value only when parseDotEnv's trim would otherwise mangle it
 * (leading or trailing whitespace, or empty). parseDotEnv strips exactly one
 * matching pair of quotes back off, so this keeps a plain utf8 round trip
 * lossless. It does not attempt to escape embedded newlines: that is a
 * limitation of the line-based .env format itself, not something introduced
 * here.
 */
const encodeDotEnvValue = (value: string): string =>
  value.length > 0 && value.trim() !== value ? `"${value}"` : value;

export interface DotEnvExport {
  readonly text: string;
  /**
   * Keys currently base64-encoded. .env has no concept of an encoding, so
   * writing these out as plain `KEY=value` lines and reading them back with
   * `parseDotEnv` would silently turn them into utf8. Callers must surface
   * this rather than let the operator discover it after submitting.
   */
  readonly lossyKeys: readonly string[];
}

/**
 * Renders rows as `.env` text. Lossless for utf8 entries; lossy for base64
 * ones, which is why `lossyKeys` is returned rather than just embedded in a
 * warning string — the caller (the .env tab, and the pre-submit confirmation)
 * each need the list of affected keys, not just the fact that some exist.
 */
export const toDotEnv = (rows: readonly PayloadRow[]): DotEnvExport => {
  const named = rows.filter((row) => row.key.length > 0);
  const lossyKeys = named.filter((row) => row.encoding === "base64").map((row) => row.key);
  const text = named.map((row) => `${row.key}=${encodeDotEnvValue(row.value)}`).join("\n");
  return { text, lossyKeys };
};
