import { badRequest } from './errors';
import type { Grant, SecretEntry, SecretMetadata, SecretPayload } from './types';

const secretEntryKey = /^[A-Za-z0-9._-]+$/;
const identifier = /^[a-z][a-z0-9-]{2,63}$/;
const metadataPath = /^[a-z0-9][a-z0-9._-]{0,63}(?:\/[a-z0-9][a-z0-9._-]{0,63})*$/;
const tagKey = /^[a-z][a-z0-9-]{0,31}$/;
const tagValue = /^[A-Za-z0-9][A-Za-z0-9._@+\/-]{0,127}$/;

export const assertIdentifier = (value: string, field: string): void => {
    if (!identifier.test(value)) {
        throw badRequest(`${field} must be 3-64 lowercase letters, numbers, or hyphens and start with a letter.`);
    }
};

export const parseMetadata = (value: unknown): SecretMetadata => {
    if (!isObject(value) || typeof value.name !== 'string' || value.name.trim().length === 0 || value.name.length > 128) {
        throw badRequest('metadata.name is required and must be at most 128 characters.');
    }
    if (value.description !== undefined && (typeof value.description !== 'string' || value.description.length > 1024)) {
        throw badRequest('metadata.description must be a string of at most 1024 characters.');
    }
    if (value.path !== undefined && (typeof value.path !== 'string' || value.path.length > 256 || !metadataPath.test(value.path))) {
        throw badRequest('metadata.path must be a lowercase slash-delimited path of at most 256 characters.');
    }
    const tags = parseTags(value.tags);
    return {
        name: value.name,
        ...(value.description === undefined ? {} : { description: value.description }),
        ...(value.path === undefined ? {} : { path: value.path }),
        ...(tags === undefined ? {} : { tags }),
    };
};

export const parseCatalogPathPrefix = (value: string | undefined): string | undefined => {
    if (value === undefined) {
        return undefined;
    }
    if (value.length === 0 || value.length > 256 || !metadataPath.test(value)) {
        throw badRequest('pathPrefix must be a lowercase slash-delimited path of at most 256 characters.');
    }
    return value;
};

export const parseCatalogTagFilters = (value: string | undefined): Readonly<Record<string, string>> => {
    if (value === undefined || value.length === 0) {
        return {};
    }
    const entries = value.split(',').map((entry): readonly [string, string] => {
        const separator = entry.indexOf(':');
        if (separator <= 0 || separator === entry.length - 1 || entry.indexOf(':', separator + 1) !== -1) {
            throw badRequest('tags must be comma-separated key:value pairs.');
        }
        const key = entry.slice(0, separator);
        const tag = entry.slice(separator + 1);
        if (!tagKey.test(key) || !tagValue.test(tag)) {
            throw badRequest('tags contains an invalid key or value.');
        }
        return [key, tag];
    });
    if (entries.length > 20 || new Set(entries.map(([key]) => key)).size !== entries.length) {
        throw badRequest('tags must contain at most twenty unique keys.');
    }
    return Object.fromEntries(entries);
};

export const parseGrants = (value: unknown): readonly Grant[] => {
    if (!Array.isArray(value) || value.length > 10) {
        throw badRequest('acl must contain between zero and ten grants.');
    }
    const seen = new Set<string>();
    return value.map((grant): Grant => {
        if (!isObject(grant) || typeof grant.clusterId !== 'string' || !Array.isArray(grant.permissions)) {
            throw badRequest('Each ACL grant must contain clusterId and permissions.');
        }
        assertIdentifier(grant.clusterId, 'acl.clusterId');
        if (seen.has(grant.clusterId)) {
            throw badRequest('acl contains a duplicate clusterId.');
        }
        seen.add(grant.clusterId);
        if (grant.permissions.length !== 1 || grant.permissions[0] !== 'read') {
            throw badRequest('Only the read permission is supported.');
        }
        return { clusterId: grant.clusterId, permissions: ['read'] };
    });
};

export const parsePayload = (value: unknown, maxBytes: number): SecretPayload => {
    if (!isObject(value)) {
        throw badRequest('payload must be an object of Secret entries.');
    }
    const entries = Object.entries(value).map(([key, entry]): readonly [string, SecretEntry] => {
        if (!secretEntryKey.test(key)) {
            throw badRequest(`payload key ${key} is invalid.`);
        }
        if (!isObject(entry) || (entry.encoding !== 'utf8' && entry.encoding !== 'base64') || typeof entry.value !== 'string') {
            throw badRequest(`payload entry ${key} must contain encoding=utf8|base64 and string value.`);
        }
        if (entry.encoding === 'base64' && !isCanonicalBase64(entry.value)) {
            throw badRequest(`payload entry ${key} is not canonical base64.`);
        }
        return [key, { encoding: entry.encoding, value: entry.value }];
    });
    const payload = Object.fromEntries(entries) as SecretPayload;
    const bytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
    if (bytes > maxBytes) {
        throw badRequest(`payload exceeds the ${maxBytes} byte limit.`);
    }
    return payload;
};

export const isObject = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const parseTags = (value: unknown): Readonly<Record<string, string>> | undefined => {
    if (value === undefined) {
        return undefined;
    }
    if (!isObject(value)) {
        throw badRequest('metadata.tags must be an object of string values.');
    }
    const entries = Object.entries(value);
    if (entries.length > 20) {
        throw badRequest('metadata.tags must contain at most twenty entries.');
    }
    for (const [key, tag] of entries) {
        if (!tagKey.test(key) || typeof tag !== 'string' || !tagValue.test(tag)) {
            throw badRequest('metadata.tags contains an invalid key or value.');
        }
    }
    return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right))) as Record<string, string>;
};

const isCanonicalBase64 = (value: string): boolean => {
    if (value.length === 0) {
        return true;
    }
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
        return false;
    }
    return Buffer.from(value, 'base64').toString('base64') === value;
};
