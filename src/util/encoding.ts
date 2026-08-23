import { createHash, randomUUID } from 'node:crypto';

export const sha256Base64 = (value: Buffer | string): string =>
    createHash('sha256').update(value).digest('base64');

export const sha256Hex = (value: Buffer | string): string =>
    createHash('sha256').update(value).digest('hex');

export const newId = (): string => randomUUID();

export const isoNow = (clock: Date = new Date()): string => clock.toISOString();

export const stableJson = (value: unknown): string => JSON.stringify(sortValue(value));

const sortValue = (value: unknown): unknown => {
    if (Array.isArray(value)) {
        return value.map(sortValue);
    }
    if (value !== null && typeof value === 'object') {
        const entries = Object.entries(value as Record<string, unknown>)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([key, nested]) => [key, sortValue(nested)]);
        return Object.fromEntries(entries);
    }
    return value;
};
