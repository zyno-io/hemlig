import {
    assertSecretIdentifier,
    parseCatalogPathPrefix,
    parseCatalogTagFilters,
    parseGrants,
    parseMetadata,
    parsePayload,
} from './validation';

describe('secret validation', () => {
    it('accepts string and explicitly base64 entries', () => {
        const payload = parsePayload({
            PASSWORD: { encoding: 'utf8', value: 'not logged' },
            CERT: { encoding: 'base64', value: 'Y2VydA==' },
        }, 1024);
        expect(payload.CERT).toEqual({ encoding: 'base64', value: 'Y2VydA==' });
    });

    it('accepts forty ACL consumers and rejects a forty-first', () => {
        const acl = Array.from({ length: 40 }, (_, index) => ({
            consumerId: `consumer-${index}`,
            permissions: ['read'],
        }));
        expect(parseGrants(acl)).toHaveLength(40);
        expect(() => parseGrants([
            ...acl,
            { consumerId: 'consumer-40', permissions: ['read'] },
        ])).toThrow('zero and 40');
    });

    it('keeps agent authorization paths separate from catalog folders', () => {
        expect(parseMetadata({
            path: 'payments/stripe/production',
            tags: { owner: 'payments', system: 'billing' },
        })).toEqual({
            path: 'payments/stripe/production',
            tags: { owner: 'payments', system: 'billing' },
        });
        expect(parseCatalogTagFilters('owner:payments,system:billing')).toEqual({
            owner: 'payments',
            system: 'billing',
        });
    });

    it('accepts slash-separated secret IDs but rejects empty path segments', () => {
        expect(() => assertSecretIdentifier('payments/stripe/api-key', 'secretId')).not.toThrow();
        expect(() => assertSecretIdentifier('/payments/api-key', 'secretId')).toThrow('leading');
        expect(() => assertSecretIdentifier('payments/api-key/', 'secretId')).toThrow('trailing');
        expect(() => assertSecretIdentifier('payments//api-key', 'secretId')).toThrow('repeated');
    });

    it('uses the same secret-ID grammar for catalog prefixes', () => {
        expect(parseCatalogPathPrefix('payments/stripe')).toBe('payments/stripe');
        expect(() => parseCatalogPathPrefix('payments//stripe')).toThrow('pathPrefix');
    });

    it('rejects ambiguous organizational tags', () => {
        expect(() => parseMetadata({ tags: { Owner: 'payments' } })).toThrow('metadata.tags');
        expect(() => parseCatalogTagFilters('owner:payments,owner:platform')).toThrow('unique');
    });
});
