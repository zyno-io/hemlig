import { parseCatalogTagFilters, parseGrants, parseMetadata, parsePayload } from './validation';

describe('secret validation', () => {
    it('accepts string and explicitly base64 entries', () => {
        const payload = parsePayload({
            PASSWORD: { encoding: 'utf8', value: 'not logged' },
            CERT: { encoding: 'base64', value: 'Y2VydA==' },
        }, 1024);
        expect(payload.CERT).toEqual({ encoding: 'base64', value: 'Y2VydA==' });
    });

    it('rejects an ACL with more than ten consumers', () => {
        const acl = Array.from({ length: 11 }, (_, index) => ({
            consumerId: `consumer-${index}`,
            permissions: ['read'],
        }));
        expect(() => parseGrants(acl)).toThrow('zero and ten');
    });

    it('accepts bounded organizational paths and tags', () => {
        expect(parseMetadata({
            name: 'payment-api',
            path: 'payments/stripe/production',
            tags: { owner: 'payments', system: 'billing' },
        })).toEqual({
            name: 'payment-api',
            path: 'payments/stripe/production',
            tags: { owner: 'payments', system: 'billing' },
        });
        expect(parseCatalogTagFilters('owner:payments,system:billing')).toEqual({
            owner: 'payments',
            system: 'billing',
        });
    });

    it('rejects ambiguous organizational tags', () => {
        expect(() => parseMetadata({ name: 'payment-api', tags: { Owner: 'payments' } })).toThrow('metadata.tags');
        expect(() => parseCatalogTagFilters('owner:payments,owner:platform')).toThrow('unique');
    });
});
