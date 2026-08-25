import { badRequest } from "./errors";
import type {
  AgentCapability,
  Grant,
  SecretEntry,
  SecretMetadata,
  SecretPayload,
} from "./types";

const secretEntryKey = /^[A-Za-z0-9._-]+$/;
const identifier = /^[a-z][a-z0-9-]{2,63}$/;
const secretIdentifier = /^[a-z][a-z0-9-]{2,63}(?:\/[a-z][a-z0-9-]{2,63})*$/;
const environmentName = /^[a-z][a-z0-9-]{0,63}$/;
const tagKey = /^[a-z][a-z0-9-]{0,31}$/;
const tagValue = /^[A-Za-z0-9][A-Za-z0-9._@+\/-]{0,127}$/;
// Ordinary writes use one grouped notification record. An ACL replacement
// still atomically changes up to 80 access rows (40 grants revoked and 40
// granted), leaving room below DynamoDB's 100-action transaction limit.
const maximumAclGrants = 40;

export const assertIdentifier = (value: string, field: string): void => {
  if (!identifier.test(value)) {
    throw badRequest(
      `${field} must be 3-64 lowercase letters, numbers, or hyphens and start with a letter.`,
    );
  }
};

/**
 * Secret IDs are hierarchical names. Every segment deliberately keeps the
 * established identifier grammar; the separator only creates a catalog
 * folder. This rejects a leading/trailing slash and empty (`//`) segment.
 */
export const assertSecretIdentifier = (value: string, field: string): void => {
  if (value.length > 256 || !secretIdentifier.test(value)) {
    throw badRequest(
      `${field} must be slash-delimited lowercase identifiers (3-64 characters per segment), with no leading, trailing, or repeated slash.`,
    );
  }
};

export const assertEnvironmentName = (value: string): void => {
  if (!environmentName.test(value)) {
    throw badRequest(
      "environment must be 1-64 lowercase letters, numbers, or hyphens and start with a letter.",
    );
  }
};

export const parseMetadata = (value: unknown): SecretMetadata => {
  if (!isObject(value)) {
    throw badRequest("metadata must be an object.");
  }
  if (
    value.description !== undefined &&
    (typeof value.description !== "string" || value.description.length > 1024)
  ) {
    throw badRequest(
      "metadata.description must be a string of at most 1024 characters.",
    );
  }
  if (value.path !== undefined) {
    throw badRequest(
      "metadata.path is not supported; encode the hierarchy in secretId.",
    );
  }
  const tags = parseTags(value.tags);
  return {
    ...(value.description === undefined
      ? {}
      : { description: value.description }),
    ...(tags === undefined ? {} : { tags }),
  };
};

export const parseCatalogPathPrefix = (
  value: string | undefined,
): string | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (
    value.length === 0 ||
    value.length > 256 ||
    !secretIdentifier.test(value)
  ) {
    throw badRequest(
      "pathPrefix must be a slash-delimited secret ID prefix, with 3-64 lowercase identifier characters per segment.",
    );
  }
  return value;
};

/** A namespace-agent boundary is an explicit, bounded set of exact IDs. */
export const parseAgentSecretIds = (
  value: unknown,
  field: string,
): readonly string[] => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 20) {
    throw badRequest(
      `${field} must contain between one and twenty canonical secret IDs.`,
    );
  }
  const secretIds = value.map((entry) => {
    if (
      typeof entry !== "string" ||
      entry.length > 256 ||
      !secretIdentifier.test(entry)
    ) {
      throw badRequest(
        `${field} must contain canonical slash-delimited secret IDs.`,
      );
    }
    return entry;
  });
  if (new Set(secretIds).size !== secretIds.length) {
    throw badRequest(`${field} must not contain duplicate secret IDs.`);
  }
  return [...secretIds].sort((left, right) => left.localeCompare(right));
};

export const parseAgentCapabilities = (
  value: unknown,
): readonly AgentCapability[] => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 2) {
    throw badRequest("capabilities must contain read and/or write.");
  }
  const capabilities = value.map((entry): AgentCapability => {
    if (entry !== "read" && entry !== "write") {
      throw badRequest("capabilities must contain read and/or write.");
    }
    return entry;
  });
  if (new Set(capabilities).size !== capabilities.length) {
    throw badRequest("capabilities must not contain duplicates.");
  }
  return [...capabilities].sort();
};

export const parseCatalogSearchQuery = (
  value: string | undefined,
): string | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (value.length === 0 || value.length > 128 || value.trim().length === 0) {
    throw badRequest("q must be 1-128 characters and not only whitespace.");
  }
  return value;
};

export const parseCatalogTagFilters = (
  value: string | undefined,
): Readonly<Record<string, string>> => {
  if (value === undefined || value.length === 0) {
    return {};
  }
  const entries = value.split(",").map((entry): readonly [string, string] => {
    const separator = entry.indexOf(":");
    if (
      separator <= 0 ||
      separator === entry.length - 1 ||
      entry.indexOf(":", separator + 1) !== -1
    ) {
      throw badRequest("tags must be comma-separated key:value pairs.");
    }
    const key = entry.slice(0, separator);
    const tag = entry.slice(separator + 1);
    if (!tagKey.test(key) || !tagValue.test(tag)) {
      throw badRequest("tags contains an invalid key or value.");
    }
    return [key, tag];
  });
  if (
    entries.length > 20 ||
    new Set(entries.map(([key]) => key)).size !== entries.length
  ) {
    throw badRequest("tags must contain at most twenty unique keys.");
  }
  return Object.fromEntries(entries);
};

export const parseGrants = (value: unknown): readonly Grant[] => {
  if (!Array.isArray(value) || value.length > maximumAclGrants) {
    throw badRequest(
      `acl must contain between zero and ${maximumAclGrants} grants.`,
    );
  }
  const seen = new Set<string>();
  return value.map((grant): Grant => {
    if (
      !isObject(grant) ||
      typeof grant.consumerId !== "string" ||
      !Array.isArray(grant.permissions)
    ) {
      throw badRequest(
        "Each ACL grant must contain consumerId and permissions.",
      );
    }
    assertIdentifier(grant.consumerId, "acl.consumerId");
    if (seen.has(grant.consumerId)) {
      throw badRequest("acl contains a duplicate consumerId.");
    }
    seen.add(grant.consumerId);
    if (grant.permissions.length !== 1 || grant.permissions[0] !== "read") {
      throw badRequest("Only the read permission is supported.");
    }
    return { consumerId: grant.consumerId, permissions: ["read"] };
  });
};

export const parsePayload = (
  value: unknown,
  maxBytes: number,
): SecretPayload => {
  if (!isObject(value)) {
    throw badRequest("payload must be an object of Secret entries.");
  }
  const entries = Object.entries(value).map(
    ([key, entry]): readonly [string, SecretEntry] => {
      if (!secretEntryKey.test(key)) {
        throw badRequest(`payload key ${key} is invalid.`);
      }
      if (
        !isObject(entry) ||
        (entry.encoding !== "utf8" && entry.encoding !== "base64") ||
        typeof entry.value !== "string"
      ) {
        throw badRequest(
          `payload entry ${key} must contain encoding=utf8|base64 and string value.`,
        );
      }
      if (entry.encoding === "base64" && !isCanonicalBase64(entry.value)) {
        throw badRequest(`payload entry ${key} is not canonical base64.`);
      }
      return [key, { encoding: entry.encoding, value: entry.value }];
    },
  );
  const payload = Object.fromEntries(entries) as SecretPayload;
  const bytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  if (bytes > maxBytes) {
    throw badRequest(`payload exceeds the ${maxBytes} byte limit.`);
  }
  return payload;
};

export const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const parseTags = (
  value: unknown,
): Readonly<Record<string, string>> | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (!isObject(value)) {
    throw badRequest("metadata.tags must be an object of string values.");
  }
  const entries = Object.entries(value);
  if (entries.length > 20) {
    throw badRequest("metadata.tags must contain at most twenty entries.");
  }
  for (const [key, tag] of entries) {
    if (!tagKey.test(key) || typeof tag !== "string" || !tagValue.test(tag)) {
      throw badRequest("metadata.tags contains an invalid key or value.");
    }
  }
  return Object.fromEntries(
    entries.sort(([left], [right]) => left.localeCompare(right)),
  ) as Record<string, string>;
};

const isCanonicalBase64 = (value: string): boolean => {
  if (value.length === 0) {
    return true;
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    return false;
  }
  return Buffer.from(value, "base64").toString("base64") === value;
};
