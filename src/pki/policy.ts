/**
 * The pure issuance policy engine ("Issuance pipeline", evaluation steps 1 and
 * 6 to 10). It takes a normalized request, a grant policy (consumer path) and
 * the CA inputs, and returns an issuance plan or a denial, with a decision
 * trace. No I/O: `now` is a parameter.
 */
import {
    type CompiledGrantPolicy,
    DEFAULT_MIN_LIFETIME_SECONDS,
    MAX_LEAF_LIFETIME_SECONDS,
    MAX_SANS,
    MIN_LEAF_LIFETIME_SECONDS,
    ANY_EXTENDED_KEY_USAGE,
    compileGrantPolicy,
    subjectGlobMatches,
    validSubjectValue,
} from './grant-policy';
import {
    checkNameConstraints,
    evaluateDnsName,
    evaluateIp,
    evaluateUri,
    isReservedUri,
    normalizeDnsName,
    normalizeIp,
    normalizeUri,
} from './names';
import {
    type Denial,
    type DenialReason,
    EXTENDED_KEY_USAGES,
    type ExtendedKeyUsageName,
    type IssuancePlan,
    KEY_USAGES,
    LEAF_KEY_ALGORITHMS,
    type KeyUsageName,
    type LeafKeyAlgorithm,
    type PolicyInput,
    type PolicyOutcome,
    SUBJECT_ATTRIBUTES,
    type SanSet,
    type SubjectEntry,
    type TraceStep,
} from './policy-types';

export const ADMIN_DEFAULT_LIFETIME_SECONDS = 90 * 86400;
export const CLOCK_SKEW_SECONDS = 60;

// ---------------------------------------------------------------------------
// Usages
// ---------------------------------------------------------------------------

const keyUsageMap: Record<string, KeyUsageName> = {
    'digital signature': 'digitalSignature',
    signing: 'digitalSignature',
    'key encipherment': 'keyEncipherment',
    digitalSignature: 'digitalSignature',
    keyEncipherment: 'keyEncipherment',
};

const extendedKeyUsageMap: Record<string, ExtendedKeyUsageName> = {
    'server auth': 'serverAuth',
    'client auth': 'clientAuth',
    serverAuth: 'serverAuth',
    clientAuth: 'clientAuth',
};

/** cert-manager extended usages Hemlig recognizes but never issues. */
const unsupportedExtendedUsages = new Set([
    'any',
    'code signing',
    'email protection',
    's/mime',
    'ipsec end system',
    'ipsec tunnel',
    'ipsec user',
    'timestamping',
    'ocsp signing',
    'microsoft sgc',
    'netscape sgc',
    'anyExtendedKeyUsage',
    'codeSigning',
    'emailProtection',
    'timeStamping',
    'OCSPSigning',
]);

export type UsageMapping =
    { ok: true; keyUsages: KeyUsageName[]; extendedKeyUsages: ExtendedKeyUsageName[] } | { ok: false; denial: Denial };

/** Map requested usage strings to Hemlig KeyUsage and EKU names. Anything else is denied. */
export const mapUsages = (usages: string[]): UsageMapping => {
    const ku = new Set<KeyUsageName>();
    const eku = new Set<ExtendedKeyUsageName>();
    for (const usage of usages) {
        const mappedKu = keyUsageMap[usage];
        const mappedEku = extendedKeyUsageMap[usage];
        if (mappedKu) {
            ku.add(mappedKu);
        } else if (mappedEku) {
            eku.add(mappedEku);
        } else if (unsupportedExtendedUsages.has(usage)) {
            return {
                ok: false,
                denial: {
                    reason: 'extended_key_usage_not_permitted',
                    detail: `extended key usage "${usage}" is not supported`,
                },
            };
        } else {
            return {
                ok: false,
                denial: { reason: 'key_usage_not_permitted', detail: `usage "${usage}" is not supported` },
            };
        }
    }
    return {
        ok: true,
        keyUsages: KEY_USAGES.filter((u) => ku.has(u)),
        extendedKeyUsages: EXTENDED_KEY_USAGES.filter((u) => eku.has(u)),
    };
};

const isRsa = (algorithm: LeafKeyAlgorithm): boolean => algorithm.startsWith('RSA_');

/**
 * KeyUsage matrix: RSA allows digitalSignature and keyEncipherment; EC and
 * Ed25519 allow digitalSignature only. `keyEncipherment` is silently dropped
 * on non-RSA keys (cert-manager's default).
 */
export const applyKeyUsageMatrix = (
    algorithm: LeafKeyAlgorithm,
    keyUsages: KeyUsageName[],
): { keyUsages: KeyUsageName[]; dropped: KeyUsageName[] } => {
    if (isRsa(algorithm)) {
        return { keyUsages, dropped: [] };
    }
    return {
        keyUsages: keyUsages.filter((u) => u === 'digitalSignature'),
        dropped: keyUsages.filter((u) => u !== 'digitalSignature'),
    };
};

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

export interface LifetimeInput {
    now: Date;
    caNotBefore: Date;
    earliestChainNotAfter: Date;
    caMaxSeconds: number;
    grantMaxSeconds: number;
    minSeconds: number;
    /** Requested or default duration. */
    desiredSeconds: number;
}

export type LifetimeResult =
    { ok: true; notBefore: Date; notAfter: Date; clamped: boolean } | { ok: false; detail: string };

/**
 * `notBefore = max(now - 60 s, CA notBefore)`; `notAfter = min(notBefore +
 * desired, + grant max, + CA max, + 397 days, earliest chain notAfter)`.
 * Clamped, never denied, except below `minSeconds`.
 */
export const computeLifetime = (input: LifetimeInput): LifetimeResult => {
    const notBeforeMs = Math.max(input.now.getTime() - CLOCK_SKEW_SECONDS * 1000, input.caNotBefore.getTime());
    const chainSeconds = Math.floor((input.earliestChainNotAfter.getTime() - notBeforeMs) / 1000);
    const policySeconds = Math.min(input.grantMaxSeconds, input.caMaxSeconds, MAX_LEAF_LIFETIME_SECONDS);
    const granted = Math.min(input.desiredSeconds, policySeconds);
    const final = Math.min(granted, chainSeconds);
    if (final < input.minSeconds) {
        const caExpiryIsCause = chainSeconds < input.minSeconds && granted >= input.minSeconds;
        return {
            ok: false,
            detail: caExpiryIsCause
                ? 'ca_validity_insufficient'
                : `lifetime of ${Math.max(final, 0)} seconds is below the minimum of ${input.minSeconds}`,
        };
    }
    return {
        ok: true,
        notBefore: new Date(notBeforeMs),
        notAfter: new Date(notBeforeMs + final * 1000),
        clamped: final < input.desiredSeconds,
    };
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

const subjectOrder = (entries: SubjectEntry[]): SubjectEntry[] =>
    SUBJECT_ATTRIBUTES.flatMap((type) => entries.filter((e) => e.type === type));

const ekuPermittedByCa = (eku: ExtendedKeyUsageName, constraint: string[] | undefined): boolean =>
    !constraint || constraint.some((e) => ANY_EXTENDED_KEY_USAGE.includes(e)) || constraint.includes(eku);

const pushUnique = (list: string[], value: string): void => {
    if (!list.includes(value)) {
        list.push(value);
    }
};

/** Evaluate a request. Never throws on request content; a denial carries the plan's reason code. */
export const evaluateIssuance = (input: PolicyInput): PolicyOutcome => {
    const { request, ca, now } = input;
    const trace: TraceStep[] = [];
    const compiled: CompiledGrantPolicy | undefined = input.grant ? compileGrantPolicy(input.grant) : undefined;
    if (request.source === 'consumer' && !compiled) {
        throw new Error('the consumer path requires a grant policy');
    }

    const pass = (step: number, name: string, detail?: string): void => {
        trace.push({ step, name, outcome: 'pass', ...(detail ? { detail } : {}) });
    };
    const skipped = (step: number, name: string, detail: string): void => {
        trace.push({ step, name, outcome: 'skipped', detail });
    };
    const deny = (step: number, name: string, reason: DenialReason, detail: string): PolicyOutcome => {
        trace.push({ step, name, outcome: 'deny', detail: `${reason}: ${detail}` });
        return { ok: false, denial: { reason, detail }, trace };
    };

    // Step 1: isCA is never permitted in v1.
    if (request.isCA) {
        return deny(1, 'parse', 'ca_not_permitted', 'CA certificates cannot be requested');
    }
    pass(1, 'parse', 'isCA is false');

    // Step 6: normalize names, CN mode and usages.
    const sans: SanSet = { dns: [], ip: [], uri: [] };
    for (const raw of request.sans.dns) {
        const name = normalizeDnsName(raw, { allowWildcard: true });
        if (!name.ok) {
            return deny(6, 'normalize', 'name_not_permitted', `dns name "${raw}": ${name.reason}`);
        }
        pushUnique(sans.dns, name.value);
    }
    for (const raw of request.sans.ip) {
        const ip = normalizeIp(raw);
        if (!ip.ok) {
            return deny(6, 'normalize', 'name_not_permitted', `ip "${raw}": ${ip.reason}`);
        }
        pushUnique(sans.ip, ip.value.text);
    }
    for (const raw of request.sans.uri) {
        const uri = normalizeUri(raw);
        if (!uri.ok) {
            return deny(6, 'normalize', 'name_not_permitted', `uri "${raw}": ${uri.reason}`);
        }
        pushUnique(sans.uri, uri.value.value);
    }

    const cnMode = compiled?.commonName.mode ?? 'san';
    const cnAddToSans = compiled?.commonName.addToSans ?? true;
    let cnCanonical: { type: 'dns' | 'ip'; value: string } | undefined;
    if (request.commonName !== undefined) {
        if (cnMode === 'forbid') {
            return deny(6, 'normalize', 'common_name_not_permitted', 'the grant forbids a common name');
        }
        const cnProblem = validSubjectValue('commonName', request.commonName);
        if (cnProblem) {
            return deny(6, 'normalize', 'common_name_not_permitted', `common name ${cnProblem}`);
        }
        const asIp = normalizeIp(request.commonName);
        const asDns = asIp.ok ? undefined : normalizeDnsName(request.commonName, { allowWildcard: true });
        if (asIp.ok) {
            cnCanonical = { type: 'ip', value: asIp.value.text };
        } else if (asDns?.ok) {
            cnCanonical = { type: 'dns', value: asDns.value };
        } else {
            return deny(
                6,
                'normalize',
                'common_name_not_permitted',
                'the common name must be a DNS name or IP address',
            );
        }
        if (cnAddToSans) {
            pushUnique(sans[cnCanonical.type], cnCanonical.value);
        }
    }

    const algorithm = (LEAF_KEY_ALGORITHMS as readonly string[]).includes(request.keyAlgorithm)
        ? (request.keyAlgorithm as LeafKeyAlgorithm)
        : undefined;
    if (!algorithm) {
        return deny(6, 'normalize', 'key_algorithm_not_permitted', `unknown key algorithm "${request.keyAlgorithm}"`);
    }

    const mapped = mapUsages(request.usages);
    if (!mapped.ok) {
        return deny(6, 'normalize', mapped.denial.reason, mapped.denial.detail);
    }
    const matrix = applyKeyUsageMatrix(algorithm, mapped.keyUsages);
    let keyUsages = matrix.keyUsages;
    const permittedKeyUsages: readonly KeyUsageName[] = compiled ? compiled.policy.keyUsages : KEY_USAGES;
    const usageNotes: string[] = [];
    if (matrix.dropped.length > 0) {
        usageNotes.push(`dropped ${matrix.dropped.join(',')} for ${algorithm}`);
    }
    if (keyUsages.length === 0) {
        if (!permittedKeyUsages.includes('digitalSignature')) {
            return deny(
                6,
                'normalize',
                'key_usage_not_permitted',
                'no key usage remains and digitalSignature is not permitted',
            );
        }
        keyUsages = ['digitalSignature'];
        usageNotes.push('defaulted to digitalSignature');
    }
    pass(
        6,
        'normalize',
        `${sans.dns.length} dns, ${sans.ip.length} ip, ${sans.uri.length} uri names; key usages ${keyUsages.join(',')}${usageNotes.length ? ` (${usageNotes.join('; ')})` : ''}`,
    );

    // Step 7: entitlement.
    let extendedKeyUsages: ExtendedKeyUsageName[] = mapped.extendedKeyUsages;
    if (compiled) {
        const grant = compiled.policy;
        if (!compiled.keyAlgorithms.includes(algorithm)) {
            return deny(7, 'entitlement', 'key_algorithm_not_permitted', `${algorithm} is not listed by the grant`);
        }
        const badKu = keyUsages.find((u) => !grant.keyUsages.includes(u));
        if (badKu) {
            return deny(7, 'entitlement', 'key_usage_not_permitted', `${badKu} is not permitted by the grant`);
        }
        if (extendedKeyUsages.length === 0) {
            extendedKeyUsages = EXTENDED_KEY_USAGES.filter((u) => grant.extendedKeyUsages.default.includes(u));
        }
        const badEku = extendedKeyUsages.find((u) => !grant.extendedKeyUsages.allow.includes(u));
        if (badEku) {
            return deny(
                7,
                'entitlement',
                'extended_key_usage_not_permitted',
                `${badEku} is not permitted by the grant`,
            );
        }
    } else {
        // Admin issuance has no grant: the CA leaf key policy is the algorithm gate.
        if (extendedKeyUsages.length === 0) {
            extendedKeyUsages = [...EXTENDED_KEY_USAGES];
        }
    }
    if (extendedKeyUsages.length === 0) {
        return deny(7, 'entitlement', 'extended_key_usage_not_permitted', 'no extended key usage remains');
    }

    if (compiled) {
        for (const name of sans.dns) {
            const decision = evaluateDnsName(name, compiled.dns);
            if (!decision.allowed) {
                return deny(7, 'entitlement', decision.reason, decision.detail);
            }
        }
        for (const text of sans.ip) {
            const ip = normalizeIp(text);
            if (ip.ok) {
                const decision = evaluateIp(ip.value, compiled.ip);
                if (!decision.allowed) {
                    return deny(7, 'entitlement', decision.reason, decision.detail);
                }
            }
        }
        for (const text of sans.uri) {
            const uri = normalizeUri(text);
            if (uri.ok) {
                if (isReservedUri(uri.value)) {
                    return deny(
                        7,
                        'entitlement',
                        'reserved_name',
                        `${uri.value.value} is in the reserved spiffe://hemlig/ namespace`,
                    );
                }
                const decision = evaluateUri(uri.value, compiled.uri);
                if (!decision.allowed) {
                    return deny(7, 'entitlement', decision.reason, decision.detail);
                }
            }
        }
    }
    if (cnCanonical && !cnAddToSans) {
        const forced = compiled?.forcedSans[cnCanonical.type] ?? [];
        if (!sans[cnCanonical.type].includes(cnCanonical.value) && !forced.includes(cnCanonical.value)) {
            return deny(7, 'entitlement', 'common_name_not_permitted', 'the common name must equal a DNS or IP SAN');
        }
    }
    // Subject attributes: the CN is handled above; everything else needs an allow pattern or a forced equal.
    for (const entry of request.subject) {
        if (entry.type === 'commonName') {
            return deny(
                7,
                'entitlement',
                'subject_not_permitted',
                'pass the common name as commonName, not as a subject attribute',
            );
        }
        const problem = validSubjectValue(entry.type, entry.value);
        if (problem) {
            return deny(7, 'entitlement', 'subject_not_permitted', `${entry.type} ${problem}`);
        }
        if (compiled) {
            const patterns = compiled.subjectAllow[entry.type] ?? [];
            const forcedValue = compiled.policy.forced?.subject?.[entry.type];
            if (!subjectGlobMatches(patterns, entry.value) && forcedValue !== entry.value) {
                return deny(
                    7,
                    'entitlement',
                    'subject_not_permitted',
                    `${entry.type} "${entry.value}" is not permitted`,
                );
            }
        }
    }
    pass(7, 'entitlement', compiled ? 'grant rules satisfied' : 'admin path: no grant, ceilings only');

    // Step 8: CA constraints and lifetime.
    if (!ca.leafKeyAlgorithms.includes(algorithm)) {
        return deny(
            8,
            'ca-constraints',
            'key_algorithm_not_permitted',
            `${algorithm} is not allowed by the CA leaf policy`,
        );
    }
    const ekuBlocked = extendedKeyUsages.find((u) => !ekuPermittedByCa(u, ca.extendedKeyUsages));
    if (ekuBlocked) {
        return deny(
            8,
            'ca-constraints',
            'extended_key_usage_not_permitted',
            `${ekuBlocked} does not fit the CA EKU constraint`,
        );
    }
    const violation = firstConstraintViolation(sans, ca.nameConstraints);
    if (violation) {
        return deny(8, 'ca-constraints', 'name_constraint_violation', violation);
    }
    const desiredSeconds =
        request.durationSeconds ?? compiled?.policy.lifetime.defaultSeconds ?? ADMIN_DEFAULT_LIFETIME_SECONDS;
    if (!Number.isFinite(desiredSeconds) || desiredSeconds <= 0) {
        return deny(8, 'ca-constraints', 'lifetime_too_short', 'the requested duration must be positive');
    }
    const lifetime = computeLifetime({
        now,
        caNotBefore: ca.notBefore,
        earliestChainNotAfter: ca.earliestChainNotAfter,
        caMaxSeconds: ca.maxLeafLifetimeSeconds,
        grantMaxSeconds: compiled?.policy.lifetime.maxSeconds ?? MAX_LEAF_LIFETIME_SECONDS,
        minSeconds: compiled
            ? (compiled.policy.lifetime.minSeconds ?? DEFAULT_MIN_LIFETIME_SECONDS)
            : MIN_LEAF_LIFETIME_SECONDS,
        desiredSeconds: Math.floor(desiredSeconds),
    });
    if (!lifetime.ok) {
        return deny(8, 'ca-constraints', 'lifetime_too_short', lifetime.detail);
    }
    pass(8, 'ca-constraints', lifetime.clamped ? 'lifetime clamped' : 'within CA limits');

    // Step 9: forced attributes.
    const subjectEntries: SubjectEntry[] = [];
    for (const entry of request.subject) {
        if (!subjectEntries.some((e) => e.type === entry.type && e.value === entry.value)) {
            subjectEntries.push(entry);
        }
    }
    const certificatePolicies: string[] = [];
    if (compiled) {
        const forcedSubject = compiled.policy.forced?.subject ?? {};
        for (const attribute of SUBJECT_ATTRIBUTES) {
            const forcedValue = forcedSubject[attribute];
            if (forcedValue === undefined) {
                continue;
            }
            const conflict = subjectEntries.find((e) => e.type === attribute && e.value !== forcedValue);
            if (conflict) {
                return deny(
                    9,
                    'forced-attributes',
                    'subject_not_permitted',
                    `requested ${attribute} "${conflict.value}" conflicts with the forced value`,
                );
            }
            if (!subjectEntries.some((e) => e.type === attribute)) {
                subjectEntries.push({ type: attribute, value: forcedValue });
            }
        }
        for (const type of ['dns', 'ip', 'uri'] as const) {
            for (const value of compiled.forcedSans[type]) {
                pushUnique(sans[type], value);
            }
        }
        for (const oid of compiled.policy.forced?.certificatePolicies ?? []) {
            pushUnique(certificatePolicies, oid);
        }
    }
    pass(9, 'forced-attributes', compiled ? 'forced subject, SANs and policies applied' : 'no grant, nothing forced');

    // Step 10: final name check.
    for (const uri of sans.uri) {
        if (isReservedUri(normalizeUriValue(uri))) {
            return deny(
                10,
                'final-name-check',
                'reserved_name',
                `${uri} is in the reserved spiffe://hemlig/ namespace`,
            );
        }
    }
    const finalViolation = firstConstraintViolation(sans, ca.nameConstraints);
    if (finalViolation) {
        return deny(10, 'final-name-check', 'name_constraint_violation', finalViolation);
    }
    const total = sans.dns.length + sans.ip.length + sans.uri.length;
    const limit = Math.min(compiled?.maxSans ?? MAX_SANS, MAX_SANS);
    if (total > limit) {
        return deny(10, 'final-name-check', 'too_many_names', `${total} SANs exceed the limit of ${limit}`);
    }
    const subject = subjectOrder(subjectEntries);
    if (cnCanonical) {
        subject.push({ type: 'commonName', value: cnCanonical.value });
    }
    if (subject.length === 0 && total === 0) {
        return deny(10, 'final-name-check', 'name_not_permitted', 'the certificate would have no subject and no names');
    }
    pass(10, 'final-name-check', `${total} SANs (limit ${limit})`);

    const plan: IssuancePlan = {
        keyAlgorithm: algorithm,
        sans,
        subject,
        ...(cnCanonical ? { commonName: cnCanonical.value } : {}),
        sanCritical: subject.length === 0,
        keyUsages,
        extendedKeyUsages,
        certificatePolicies,
        notBefore: lifetime.notBefore,
        notAfter: lifetime.notAfter,
        lifetimeClamped: lifetime.clamped,
    };
    return { ok: true, plan, trace };
};

const normalizeUriValue = (value: string): { scheme: string; host: string } => {
    const parsed = normalizeUri(value);
    return parsed.ok ? parsed.value : { scheme: '', host: '' };
};

const firstConstraintViolation = (
    sans: SanSet,
    constraints: PolicyInput['ca']['nameConstraints'],
): string | undefined => {
    for (const type of ['dns', 'ip', 'uri'] as const) {
        for (const value of sans[type]) {
            const check = checkNameConstraints(type, value, constraints);
            if (!check.ok) {
                return check.detail;
            }
        }
    }
    return undefined;
};
