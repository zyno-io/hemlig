/**
 * Client-side mirrors of src/domain/validation.ts. These exist to give fast
 * feedback in a form; the server remains the authority on every rule here. A
 * rule enforced here but not there would be a security bug, so nothing in this
 * file may be stricter than the service.
 */
export const MAX_PAYLOAD_BYTES = 768_000;

const entryKey = /^[A-Za-z0-9._-]+$/;
export const identifier = /^[a-z][a-z0-9-]{2,63}$/;
export const metadataPath =
  /^[a-z0-9][a-z0-9._-]{0,63}(?:\/[a-z0-9][a-z0-9._-]{0,63})*$/;
export const tagKey = /^[a-z][a-z0-9-]{0,31}$/;
export const tagValue = /^[A-Za-z0-9][A-Za-z0-9._@+/-]{0,127}$/;

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
