import type { HemligClient } from "@zyno-io/hemlig-client";

export const consumerCommands = [
  "list",
  "get",
  "identities",
  "revoke-identity",
] as const;
export type ConsumerCommand = (typeof consumerCommands)[number];

const MIN_PREFIX = 12;
const MAX_PAGES = 100;

/** Raised for invalid local input; index.ts maps it to a usage error (exit 2). */
export class ConsumerInputError extends Error {}

export function validConsumerId(value: string | undefined): string {
  if (
    value === undefined ||
    value.length > 256 ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value)
  )
    throw new ConsumerInputError("Supply a valid --consumer-id.");
  return value;
}

/** Normalizes a full SHA-256 or a prefix of at least 12 hex characters. */
export function validFingerprint(value: string | undefined): string {
  const text = value?.toLowerCase();
  if (text === undefined || !/^[0-9a-f]{12,64}$/.test(text))
    throw new ConsumerInputError(
      `Supply --fingerprint as a full 64-hex SHA-256 or a prefix of at least ${MIN_PREFIX} hex characters.`,
    );
  return text;
}

/**
 * A full fingerprint is used as given. A prefix is resolved against the
 * consumer's identities and must match exactly one.
 */
export async function resolveFingerprint(
  client: HemligClient,
  token: string,
  consumerId: string,
  fingerprint: string,
): Promise<string> {
  if (fingerprint.length === 64) return fingerprint;
  const matches: { apiFingerprint: string; status: string }[] = [];
  let cursor: string | undefined;
  const seen = new Set<string>();
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await client.listApiIdentities(token, consumerId, cursor);
    for (const identity of result.apiIdentities) {
      if (identity.apiFingerprint.toLowerCase().startsWith(fingerprint))
        matches.push(identity);
    }
    cursor = result.nextCursor;
    if (cursor === undefined || seen.has(cursor)) break;
    seen.add(cursor);
  }
  const short = (m: { apiFingerprint: string; status: string }): string =>
    `${m.apiFingerprint.slice(0, 16)}... (${m.status})`;
  if (matches.length === 0)
    throw new ConsumerInputError(
      "No API identity of this consumer matches --fingerprint. Run hemlig consumer identities.",
    );
  if (matches.length > 1)
    throw new ConsumerInputError(
      `--fingerprint matches ${matches.length} identities; use a longer prefix. Candidates: ${matches.map(short).join(", ")}.`,
    );
  return matches[0]!.apiFingerprint;
}
