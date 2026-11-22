import { computeLifetime, evaluateIssuance, mapUsages } from './policy';
import type { CaPolicyInput, GrantPolicy, IssuancePlan, PolicyOutcome, PolicyRequest } from './policy-types';

const NOW = new Date('2026-11-22T12:00:00Z');
const DAY = 86400;

const baseGrant = (overrides: Partial<GrantPolicy> = {}): GrantPolicy => ({
    names: {
        dns: {
            allow: ['**.payments.svc.cluster.local', 'api.payments.example.com', '*.payments.example.com'],
            deny: ['internal.payments.example.com'],
        },
        ip: { allow: ['10.20.0.0/16'] },
        uri: { allow: ['spiffe://prod.example.com/ns/payments/**'] },
        commonName: { mode: 'san', addToSans: true },
        maxSans: 50,
    },
    subject: { allow: { organizationalUnit: ['payments-*'] } },
    keyAlgorithms: ['ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_3072'],
    keyUsages: ['digitalSignature', 'keyEncipherment'],
    extendedKeyUsages: { allow: ['serverAuth', 'clientAuth'], default: ['serverAuth', 'clientAuth'] },
    lifetime: { defaultSeconds: 90 * DAY, maxSeconds: 90 * DAY, minSeconds: 3600 },
    ...overrides,
});

const baseCa = (overrides: Partial<CaPolicyInput> = {}): CaPolicyInput => ({
    leafKeyAlgorithms: [
        'ECDSA_P256',
        'ECDSA_P384',
        'RSA_2048',
        'RSA_3072',
        'RSA_4096',
        'ED25519',
        'ECDSA_P521',
        'RSA_8192',
    ],
    maxLeafLifetimeSeconds: 397 * DAY,
    notBefore: new Date('2026-01-01T00:00:00Z'),
    earliestChainNotAfter: new Date('2028-01-01T00:00:00Z'),
    ...overrides,
});

const request = (overrides: Partial<PolicyRequest> = {}): PolicyRequest => ({
    source: 'consumer',
    keyAlgorithm: 'ECDSA_P256',
    sans: { dns: ['api.payments.example.com'], ip: [], uri: [] },
    subject: [],
    usages: ['digital signature', 'key encipherment', 'server auth'],
    isCA: false,
    ...overrides,
});

const run = (
    req: Partial<PolicyRequest> = {},
    grant: GrantPolicy | null = baseGrant(),
    ca: Partial<CaPolicyInput> = {},
): PolicyOutcome => evaluateIssuance({ request: request(req), ...(grant ? { grant } : {}), ca: baseCa(ca), now: NOW });

const plan = (outcome: PolicyOutcome): IssuancePlan => {
    if (!outcome.ok) {
        throw new Error(`denied: ${outcome.denial.reason} ${outcome.denial.detail}`);
    }
    return outcome.plan;
};

const denial = (outcome: PolicyOutcome) => {
    if (outcome.ok) {
        throw new Error('expected a denial');
    }
    return outcome.denial;
};

describe('isCA', () => {
    it('is denied on the consumer path and the admin path', () => {
        expect(denial(run({ isCA: true }))).toMatchObject({ reason: 'ca_not_permitted' });
        expect(denial(run({ isCA: true, source: 'admin' }, null))).toMatchObject({ reason: 'ca_not_permitted' });
    });
});

describe('usage mapping', () => {
    it.each([
        [['digital signature'], ['digitalSignature'], []],
        [['signing'], ['digitalSignature'], []],
        [['key encipherment'], ['keyEncipherment'], []],
        [['server auth', 'client auth'], [], ['serverAuth', 'clientAuth']],
        [
            ['client auth', 'signing', 'server auth', 'digital signature'],
            ['digitalSignature'],
            ['serverAuth', 'clientAuth'],
        ],
    ])('maps %j', (usages, ku, eku) => {
        expect(mapUsages(usages)).toEqual({ ok: true, keyUsages: ku, extendedKeyUsages: eku });
    });

    it.each([
        ['cert sign', 'key_usage_not_permitted'],
        ['crl sign', 'key_usage_not_permitted'],
        ['content commitment', 'key_usage_not_permitted'],
        ['key agreement', 'key_usage_not_permitted'],
        ['something unknown', 'key_usage_not_permitted'],
        ['any', 'extended_key_usage_not_permitted'],
        ['code signing', 'extended_key_usage_not_permitted'],
        ['ocsp signing', 'extended_key_usage_not_permitted'],
    ])('denies %s', (usage, reason) => {
        const result = mapUsages([usage]);
        expect(result.ok).toBe(false);
        expect(!result.ok && result.denial.reason).toBe(reason);
    });
});

describe('KeyUsage matrix', () => {
    it('keeps keyEncipherment on RSA keys', () => {
        const result = plan(run({ keyAlgorithm: 'RSA_2048' }));
        expect(result.keyUsages).toEqual(['digitalSignature', 'keyEncipherment']);
    });

    it.each(['ECDSA_P256', 'ECDSA_P384', 'ECDSA_P521', 'ED25519'])(
        'silently drops keyEncipherment on %s',
        (keyAlgorithm) => {
            const grant = baseGrant({ keyAlgorithms: ['ECDSA_P256', 'ECDSA_P384', 'ECDSA_P521', 'ED25519'] });
            const outcome = run({ keyAlgorithm }, grant);
            expect(plan(outcome).keyUsages).toEqual(['digitalSignature']);
            expect(outcome.trace.find((s) => s.step === 6)?.detail).toContain('dropped keyEncipherment');
        },
    );

    it('defaults to digitalSignature when nothing remains after normalization', () => {
        expect(plan(run({ usages: [] })).keyUsages).toEqual(['digitalSignature']);
        expect(plan(run({ usages: ['server auth'] })).keyUsages).toEqual(['digitalSignature']);
        expect(plan(run({ usages: ['key encipherment'] })).keyUsages).toEqual(['digitalSignature']); // EC: dropped, then defaulted
    });

    it('denies the default when the grant does not permit digitalSignature', () => {
        const grant = baseGrant({ keyUsages: ['keyEncipherment'], keyAlgorithms: ['RSA_2048'] });
        expect(denial(run({ keyAlgorithm: 'RSA_2048', usages: [] }, grant))).toMatchObject({
            reason: 'key_usage_not_permitted',
        });
        expect(plan(run({ keyAlgorithm: 'RSA_2048', usages: ['key encipherment'] }, grant)).keyUsages).toEqual([
            'keyEncipherment',
        ]);
    });

    it('denies a usage the grant does not list', () => {
        const grant = baseGrant({ keyUsages: ['digitalSignature'], keyAlgorithms: ['RSA_2048'] });
        expect(denial(run({ keyAlgorithm: 'RSA_2048', usages: ['key encipherment'] }, grant))).toMatchObject({
            reason: 'key_usage_not_permitted',
        });
    });
});

describe('extended key usages', () => {
    it('takes the grant default when none is requested', () => {
        expect(plan(run({ usages: ['digital signature'] })).extendedKeyUsages).toEqual(['serverAuth', 'clientAuth']);
    });

    it('uses the requested set when within allow', () => {
        expect(plan(run({ usages: ['client auth'] })).extendedKeyUsages).toEqual(['clientAuth']);
    });

    it('denies an EKU outside allow', () => {
        const grant = baseGrant({ extendedKeyUsages: { allow: ['serverAuth'], default: ['serverAuth'] } });
        expect(denial(run({ usages: ['client auth'] }, grant))).toMatchObject({
            reason: 'extended_key_usage_not_permitted',
        });
    });

    it('denies when the CA EKU constraint excludes a requested or default EKU', () => {
        expect(
            denial(run({ usages: ['digital signature'] }, baseGrant(), { extendedKeyUsages: ['serverAuth'] })),
        ).toMatchObject({
            reason: 'extended_key_usage_not_permitted',
        });
        expect(
            plan(run({ usages: ['server auth'] }, baseGrant(), { extendedKeyUsages: ['serverAuth'] }))
                .extendedKeyUsages,
        ).toEqual(['serverAuth']);
        expect(
            plan(run({ usages: ['digital signature'] }, baseGrant(), { extendedKeyUsages: ['anyExtendedKeyUsage'] }))
                .extendedKeyUsages,
        ).toEqual(['serverAuth', 'clientAuth']);
    });
});

describe('key algorithms', () => {
    it('allows P-521 and Ed25519 only when listed', () => {
        expect(denial(run({ keyAlgorithm: 'ECDSA_P521' }))).toMatchObject({ reason: 'key_algorithm_not_permitted' });
        expect(denial(run({ keyAlgorithm: 'ED25519' }))).toMatchObject({ reason: 'key_algorithm_not_permitted' });
        const listed = baseGrant({ keyAlgorithms: ['ECDSA_P521', 'ED25519'] });
        expect(plan(run({ keyAlgorithm: 'ECDSA_P521' }, listed)).keyAlgorithm).toBe('ECDSA_P521');
        expect(plan(run({ keyAlgorithm: 'ED25519' }, listed)).keyAlgorithm).toBe('ED25519');
    });

    it('uses the default set when the grant lists none', () => {
        const grant = baseGrant();
        delete grant.keyAlgorithms;
        expect(plan(run({ keyAlgorithm: 'RSA_8192' }, grant)).keyAlgorithm).toBe('RSA_8192');
        expect(denial(run({ keyAlgorithm: 'ED25519' }, grant))).toMatchObject({
            reason: 'key_algorithm_not_permitted',
        });
    });

    it('requires exact RSA sizes', () => {
        for (const keyAlgorithm of ['RSA_1024', 'RSA_2560', 'RSA_2047', 'rsa_2048', 'RSA', '']) {
            expect(denial(run({ keyAlgorithm }))).toMatchObject({ reason: 'key_algorithm_not_permitted' });
        }
        expect(denial(run({ keyAlgorithm: 'RSA_4096' }))).toMatchObject({ reason: 'key_algorithm_not_permitted' }); // not in this grant
    });

    it('also requires the CA leaf policy to list the algorithm', () => {
        expect(
            denial(run({ keyAlgorithm: 'RSA_3072' }, baseGrant(), { leafKeyAlgorithms: ['ECDSA_P256'] })),
        ).toMatchObject({
            reason: 'key_algorithm_not_permitted',
        });
    });
});

describe('names', () => {
    it('denies names outside the rules and reports the reason', () => {
        expect(denial(run({ sans: { dns: ['evil.example.org'], ip: [], uri: [] } }))).toMatchObject({
            reason: 'name_not_permitted',
        });
        expect(denial(run({ sans: { dns: ['internal.payments.example.com'], ip: [], uri: [] } }))).toMatchObject({
            reason: 'name_not_permitted',
        });
        expect(denial(run({ sans: { dns: [], ip: ['10.21.0.1'], uri: [] } }))).toMatchObject({
            reason: 'name_not_permitted',
        });
        expect(denial(run({ sans: { dns: [], ip: [], uri: ['spiffe://prod.example.com/ns/other/x'] } }))).toMatchObject(
            { reason: 'name_not_permitted' },
        );
    });

    it('canonicalizes and deduplicates names', () => {
        const result = plan(
            run({
                sans: {
                    dns: ['API.payments.example.com', 'api.payments.example.com.'],
                    ip: ['10.20.0.5', '::ffff:10.20.0.5'],
                    uri: ['SPIFFE://prod.example.com/ns/payments/sa/web'],
                },
            }),
        );
        expect(result.sans).toEqual({
            dns: ['api.payments.example.com'],
            ip: ['10.20.0.5'],
            uri: ['spiffe://prod.example.com/ns/payments/sa/web'],
        });
    });

    it('denies malformed names', () => {
        expect(denial(run({ sans: { dns: ['bad_name.example.com'], ip: [], uri: [] } }))).toMatchObject({
            reason: 'name_not_permitted',
        });
        expect(denial(run({ sans: { dns: [], ip: ['10.0.0'], uri: [] } }))).toMatchObject({
            reason: 'name_not_permitted',
        });
    });

    it('requires allowWildcardNames for a requested wildcard', () => {
        const wildcard = { dns: ['*.payments.example.com'], ip: [], uri: [] };
        expect(denial(run({ sans: wildcard }))).toMatchObject({ reason: 'wildcard_not_permitted' });
        const grant = baseGrant();
        grant.names.dns = { ...grant.names.dns, allowWildcardNames: true };
        // The wildcard also covers internal.payments.example.com, which the grant denies.
        expect(denial(run({ sans: wildcard }, grant))).toMatchObject({ reason: 'name_not_permitted' });
        grant.names.dns.deny = [];
        expect(plan(run({ sans: wildcard }, grant)).sans.dns).toEqual(['*.payments.example.com']);
        expect(denial(run({ sans: { dns: ['*.example.com'], ip: [], uri: [] } }, grant))).toMatchObject({
            reason: 'name_not_permitted',
        });
    });

    it('always denies spiffe://hemlig/', () => {
        const grant = baseGrant();
        grant.names.uri = { allow: ['spiffe://prod.example.com/**'] };
        expect(denial(run({ sans: { dns: [], ip: [], uri: ['spiffe://hemlig/consumer/x'] } }, grant))).toMatchObject({
            reason: 'reserved_name',
        });
        expect(denial(run({ sans: { dns: [], ip: [], uri: ['spiffe://Hemlig'] } }, grant))).toMatchObject({
            reason: 'reserved_name',
        });
    });

    it('denies a reserved name on the admin path too', () => {
        expect(
            denial(run({ source: 'admin', sans: { dns: [], ip: [], uri: ['spiffe://hemlig/x'] } }, null)),
        ).toMatchObject({
            reason: 'reserved_name',
        });
    });
});

describe('common name modes', () => {
    it('san mode adds a CN to the SANs by default', () => {
        const result = plan(run({ sans: { dns: [], ip: [], uri: [] }, commonName: 'API.payments.example.com' }));
        expect(result.sans.dns).toEqual(['api.payments.example.com']);
        expect(result.subject).toEqual([{ type: 'commonName', value: 'api.payments.example.com' }]);
        expect(result.commonName).toBe('api.payments.example.com');
    });

    it('does not duplicate a CN that is already a SAN', () => {
        const result = plan(run({ commonName: 'api.payments.example.com' }));
        expect(result.sans.dns).toEqual(['api.payments.example.com']);
    });

    it('accepts an IP common name and adds it as an IP SAN', () => {
        const result = plan(run({ sans: { dns: [], ip: [], uri: [] }, commonName: '10.20.0.7' }));
        expect(result.sans.ip).toEqual(['10.20.0.7']);
    });

    it('applies the name rules to the CN-derived SAN', () => {
        expect(denial(run({ commonName: 'evil.example.org' }))).toMatchObject({ reason: 'name_not_permitted' });
    });

    it('denies a CN that is not a DNS name or IP', () => {
        expect(denial(run({ commonName: 'Payments Service' }))).toMatchObject({ reason: 'common_name_not_permitted' });
        expect(denial(run({ commonName: `${'a'.repeat(70)}.example.com` }))).toMatchObject({
            reason: 'common_name_not_permitted',
        });
    });

    it('with addToSans false, requires the CN to equal an existing SAN', () => {
        const grant = baseGrant();
        grant.names.commonName = { mode: 'san', addToSans: false };
        expect(plan(run({ commonName: 'api.payments.example.com' }, grant)).commonName).toBe(
            'api.payments.example.com',
        );
        expect(denial(run({ commonName: 'x.payments.example.com' }, grant))).toMatchObject({
            reason: 'common_name_not_permitted',
        });
    });

    it('with addToSans false, accepts a CN equal to a forced SAN', () => {
        const grant = baseGrant({ forced: { sans: { dns: ['forced.payments.example.com'] } } });
        grant.names.commonName = { mode: 'san', addToSans: false };
        const result = plan(
            run(
                {
                    sans: { dns: [], ip: [], uri: ['spiffe://prod.example.com/ns/payments/a'] },
                    commonName: 'forced.payments.example.com',
                },
                grant,
            ),
        );
        expect(result.sans.dns).toEqual(['forced.payments.example.com']);
    });

    it('forbid mode denies any CN', () => {
        const grant = baseGrant();
        grant.names.commonName = { mode: 'forbid' };
        expect(denial(run({ commonName: 'api.payments.example.com' }, grant))).toMatchObject({
            reason: 'common_name_not_permitted',
        });
        expect(plan(run({}, grant)).commonName).toBeUndefined();
    });
});

describe('subject', () => {
    it('passes attributes that match an allow pattern, in C, ST, L, O, OU, CN order', () => {
        const grant = baseGrant({
            subject: { allow: { organizationalUnit: ['payments-*'], organization: ['Example *'], country: ['US'] } },
        });
        const result = plan(
            run(
                {
                    commonName: 'api.payments.example.com',
                    subject: [
                        { type: 'organizationalUnit', value: 'payments-eu' },
                        { type: 'organization', value: 'Example Corp' },
                        { type: 'country', value: 'US' },
                    ],
                },
                grant,
            ),
        );
        expect(result.subject.map((e) => e.type)).toEqual([
            'country',
            'organization',
            'organizationalUnit',
            'commonName',
        ]);
    });

    it('denies an attribute without an allow pattern or a mismatching value', () => {
        expect(denial(run({ subject: [{ type: 'organization', value: 'Evil' }] }))).toMatchObject({
            reason: 'subject_not_permitted',
        });
        expect(denial(run({ subject: [{ type: 'organizationalUnit', value: 'finance' }] }))).toMatchObject({
            reason: 'subject_not_permitted',
        });
        expect(denial(run({ subject: [{ type: 'commonName', value: 'x' }] }))).toMatchObject({
            reason: 'subject_not_permitted',
        });
    });

    it('treats glob metacharacters other than * literally', () => {
        const grant = baseGrant({ subject: { allow: { organizationalUnit: ['a.b'] } } });
        expect(plan(run({ subject: [{ type: 'organizationalUnit', value: 'a.b' }] }, grant)).subject).toHaveLength(1);
        expect(denial(run({ subject: [{ type: 'organizationalUnit', value: 'axb' }] }, grant))).toMatchObject({
            reason: 'subject_not_permitted',
        });
    });

    it('adds forced attributes and rejects a conflicting requested value', () => {
        const grant = baseGrant({
            subject: { allow: { organization: ['*'] } },
            forced: { subject: { organization: 'Example Corp', country: 'US' } },
        });
        const result = plan(run({}, grant));
        expect(result.subject).toEqual([
            { type: 'country', value: 'US' },
            { type: 'organization', value: 'Example Corp' },
        ]);
        expect(denial(run({ subject: [{ type: 'organization', value: 'Other Corp' }] }, grant))).toMatchObject({
            reason: 'subject_not_permitted',
        });
        // A requested value equal to the forced one passes without an allow pattern and is not duplicated.
        const noAllow = baseGrant({ forced: { subject: { country: 'US' } } });
        expect(plan(run({ subject: [{ type: 'country', value: 'US' }] }, noAllow)).subject).toEqual([
            { type: 'country', value: 'US' },
        ]);
    });

    it('marks the SAN critical only when the subject is empty', () => {
        expect(plan(run({})).sanCritical).toBe(true);
        expect(plan(run({ commonName: 'api.payments.example.com' })).sanCritical).toBe(false);
        expect(plan(run({}, baseGrant({ forced: { subject: { organization: 'Example Corp' } } }))).sanCritical).toBe(
            false,
        );
    });

    it('denies a certificate with neither a subject nor any names', () => {
        expect(denial(run({ sans: { dns: [], ip: [], uri: [] } }))).toMatchObject({ reason: 'name_not_permitted' });
    });
});

describe('forced attributes and the SAN count', () => {
    it('adds forced SANs and policy OIDs, deduplicated', () => {
        const grant = baseGrant({
            forced: {
                sans: { uri: ['spiffe://prod.example.com/cluster/prod-a'], dns: ['API.payments.example.com'] },
                certificatePolicies: ['1.3.6.1.4.1.55555.1.1', '1.3.6.1.4.1.55555.1.1'],
            },
        });
        const result = plan(run({}, grant));
        expect(result.sans.uri).toEqual(['spiffe://prod.example.com/cluster/prod-a']);
        expect(result.sans.dns).toEqual(['api.payments.example.com']);
        expect(result.certificatePolicies).toEqual(['1.3.6.1.4.1.55555.1.1']);
    });

    it('lets an administrator force a name outside the requester allowlist', () => {
        const grant = baseGrant({ forced: { sans: { dns: ['ops.example.net'] } } });
        expect(plan(run({}, grant)).sans.dns).toEqual(['api.payments.example.com', 'ops.example.net']);
    });

    it('counts CN-derived and forced SANs against maxSans', () => {
        const grant = baseGrant({ forced: { sans: { dns: ['f1.example.net', 'f2.example.net'] } } });
        grant.names.maxSans = 3;
        const sans = { dns: ['a.payments.example.com', 'b.payments.example.com'], ip: [], uri: [] };
        // two requested + two forced = 4 > 3
        expect(denial(run({ sans }, grant))).toMatchObject({ reason: 'too_many_names' });
        // two requested + CN-derived = 3, + two forced = 5 > 3
        expect(denial(run({ sans, commonName: 'c.payments.example.com' }, grant))).toMatchObject({
            reason: 'too_many_names',
        });
        // one requested + two forced = 3 fits
        expect(plan(run({ sans: { dns: ['a.payments.example.com'], ip: [], uri: [] } }, grant)).sans.dns).toHaveLength(
            3,
        );
    });

    it('caps at the global 100 even when maxSans is unset', () => {
        const grant = baseGrant();
        delete grant.names.maxSans;
        const many = (n: number) => Array.from({ length: n }, (_, i) => `h${i}.payments.example.com`);
        expect(plan(run({ sans: { dns: many(100), ip: [], uri: [] } }, grant)).sans.dns).toHaveLength(100);
        expect(denial(run({ sans: { dns: many(101), ip: [], uri: [] } }, grant))).toMatchObject({
            reason: 'too_many_names',
        });
    });

    it('counts every SAN type together', () => {
        const grant = baseGrant();
        grant.names.maxSans = 2;
        const outcome = run(
            {
                sans: {
                    dns: ['a.payments.example.com'],
                    ip: ['10.20.0.1'],
                    uri: ['spiffe://prod.example.com/ns/payments/x'],
                },
            },
            grant,
        );
        expect(denial(outcome)).toMatchObject({ reason: 'too_many_names' });
    });
});

describe('CA name constraints', () => {
    const constraints = { permitted: { dns: ['example.com'] } };

    it('denies requested names outside the chain constraints', () => {
        const grant = baseGrant({ names: { dns: { allow: ['**.example.net'] }, maxSans: 5 } });
        expect(
            denial(run({ sans: { dns: ['a.example.net'], ip: [], uri: [] } }, grant, { nameConstraints: constraints })),
        ).toMatchObject({
            reason: 'name_constraint_violation',
        });
    });

    it('checks forced names against the chain constraints at the final check', () => {
        const grant = baseGrant({ forced: { sans: { dns: ['x.example.net'] } } });
        const outcome = run({}, grant, { nameConstraints: constraints });
        expect(denial(outcome)).toMatchObject({ reason: 'name_constraint_violation' });
        expect(outcome.trace[outcome.trace.length - 1]).toMatchObject({ step: 10, outcome: 'deny' });
    });

    it('passes names within the constraints', () => {
        expect(plan(run({}, baseGrant(), { nameConstraints: constraints })).sans.dns).toEqual([
            'api.payments.example.com',
        ]);
    });
});

describe('lifetime', () => {
    const lifetime = (overrides: Partial<Parameters<typeof computeLifetime>[0]> = {}) =>
        computeLifetime({
            now: NOW,
            caNotBefore: new Date('2026-01-01T00:00:00Z'),
            earliestChainNotAfter: new Date('2030-01-01T00:00:00Z'),
            caMaxSeconds: 397 * DAY,
            grantMaxSeconds: 90 * DAY,
            minSeconds: 3600,
            desiredSeconds: 30 * DAY,
            ...overrides,
        });

    it('starts 60 seconds in the past and adds the duration to notBefore', () => {
        const result = lifetime();
        expect(result).toMatchObject({ ok: true, clamped: false });
        if (result.ok) {
            expect(result.notBefore.toISOString()).toBe('2026-11-22T11:59:00.000Z');
            expect(result.notAfter.getTime() - result.notBefore.getTime()).toBe(30 * DAY * 1000);
        }
    });

    it('uses the CA notBefore when the CA is younger than now - 60 s', () => {
        const result = lifetime({ caNotBefore: new Date('2026-11-22T11:59:30Z') });
        expect(result.ok && result.notBefore.toISOString()).toBe('2026-11-22T11:59:30.000Z');
    });

    it.each([
        ['grant max', { grantMaxSeconds: 10 * DAY }, 10 * DAY],
        ['CA max', { caMaxSeconds: 5 * DAY }, 5 * DAY],
        [
            '397-day ceiling',
            { grantMaxSeconds: 800 * DAY, caMaxSeconds: 800 * DAY, desiredSeconds: 800 * DAY },
            397 * DAY,
        ],
    ])('clamps to the %s', (_name, overrides, seconds) => {
        const result = lifetime(overrides);
        expect(result.ok && result.clamped).toBe(true);
        expect(result.ok && (result.notAfter.getTime() - result.notBefore.getTime()) / 1000).toBe(seconds);
    });

    it('clamps to the earliest chain notAfter', () => {
        const result = lifetime({ earliestChainNotAfter: new Date('2026-12-01T00:00:00Z') });
        expect(result.ok && result.notAfter.toISOString()).toBe('2026-12-01T00:00:00.000Z');
        expect(result.ok && result.clamped).toBe(true);
    });

    it('denies below the minimum, with ca_validity_insufficient when the CA is the cause', () => {
        expect(lifetime({ earliestChainNotAfter: new Date('2026-11-22T12:10:00Z') })).toEqual({
            ok: false,
            detail: 'ca_validity_insufficient',
        });
        expect(lifetime({ earliestChainNotAfter: new Date('2026-11-20T00:00:00Z') })).toEqual({
            ok: false,
            detail: 'ca_validity_insufficient',
        });
        const requested = lifetime({ desiredSeconds: 60 });
        expect(requested.ok).toBe(false);
        expect(!requested.ok && requested.detail).not.toBe('ca_validity_insufficient');
    });

    it('accepts exactly the minimum', () => {
        expect(lifetime({ desiredSeconds: 3600 }).ok).toBe(true);
    });

    it('is deterministic for a fixed now', () => {
        expect(lifetime()).toEqual(lifetime());
    });

    it('flows through the engine with lifetimeClamped and the plan dates', () => {
        const defaulted = plan(run({}, baseGrant({ lifetime: { defaultSeconds: 30 * DAY, maxSeconds: 90 * DAY } })));
        expect(defaulted.lifetimeClamped).toBe(false);
        expect(defaulted.notAfter.getTime() - defaulted.notBefore.getTime()).toBe(30 * DAY * 1000);

        const clamped = plan(run({ durationSeconds: 200 * DAY }));
        expect(clamped.lifetimeClamped).toBe(true);
        expect(clamped.notAfter.getTime() - clamped.notBefore.getTime()).toBe(90 * DAY * 1000);

        const caLimited = plan(run({}, baseGrant(), { earliestChainNotAfter: new Date('2026-12-22T12:00:00Z') }));
        expect(caLimited.lifetimeClamped).toBe(true);
        expect(caLimited.notAfter.toISOString()).toBe('2026-12-22T12:00:00.000Z');
    });

    it('denies lifetime_too_short through the engine', () => {
        const outcome = run({}, baseGrant(), { earliestChainNotAfter: new Date('2026-11-22T12:30:00Z') });
        expect(denial(outcome)).toEqual({ reason: 'lifetime_too_short', detail: 'ca_validity_insufficient' });
        expect(denial(run({ durationSeconds: 120 }))).toMatchObject({ reason: 'lifetime_too_short' });
        expect(denial(run({ durationSeconds: 0 }))).toMatchObject({ reason: 'lifetime_too_short' });
    });
});

describe('admin path', () => {
    const adminRequest = (overrides: Partial<PolicyRequest> = {}) =>
        run(
            { source: 'admin', sans: { dns: ['anything.example.org'], ip: [], uri: [] }, usages: [], ...overrides },
            null,
        );

    it('applies ceilings only: no name rules, default EKU, 90-day default lifetime', () => {
        const result = plan(adminRequest());
        expect(result.extendedKeyUsages).toEqual(['serverAuth', 'clientAuth']);
        expect(result.keyUsages).toEqual(['digitalSignature']);
        expect(result.notAfter.getTime() - result.notBefore.getTime()).toBe(90 * DAY * 1000);
    });

    it('still enforces CA constraints and the SAN ceiling', () => {
        const constrained = run({ source: 'admin', sans: { dns: ['a.example.org'], ip: [], uri: [] } }, null, {
            nameConstraints: { permitted: { dns: ['example.com'] } },
        });
        expect(denial(constrained)).toMatchObject({ reason: 'name_constraint_violation' });
        const many = Array.from({ length: 101 }, (_, i) => `h${i}.example.org`);
        expect(denial(adminRequest({ sans: { dns: many, ip: [], uri: [] } }))).toMatchObject({
            reason: 'too_many_names',
        });
    });

    it('allows any subject attribute and uses the 300 s minimum', () => {
        const result = plan(adminRequest({ subject: [{ type: 'organization', value: 'Ops' }], durationSeconds: 300 }));
        expect(result.subject).toEqual([{ type: 'organization', value: 'Ops' }]);
        expect(denial(adminRequest({ durationSeconds: 299 }))).toMatchObject({ reason: 'lifetime_too_short' });
    });

    it('throws when the consumer path has no grant', () => {
        expect(() => run({}, null)).toThrow('requires a grant');
    });
});

describe('decision trace', () => {
    it('lists the steps that ran, in order', () => {
        const outcome = run({});
        expect(outcome.trace.map((s) => s.step)).toEqual([1, 6, 7, 8, 9, 10]);
        expect(outcome.trace.every((s) => s.outcome === 'pass')).toBe(true);
    });

    it('stops at the denying step', () => {
        const outcome = run({ sans: { dns: ['evil.example.org'], ip: [], uri: [] } });
        expect(outcome.trace.map((s) => `${s.step}:${s.outcome}`)).toEqual(['1:pass', '6:pass', '7:deny']);
    });
});
