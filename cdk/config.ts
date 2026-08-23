export interface DeploymentConfig {
    readonly environmentName: string;
    readonly adminFqdn: string;
    /** Public mTLS secret-delivery API endpoint. */
    readonly apiFqdn: string;
    /** Exact HTTPS console origin at this zone, when browser access is enabled. */
    readonly consoleFqdn?: string;
    /** ACM certificate ARN in us-east-1 for the console distribution. */
    readonly consoleCertificateArn?: string;
    readonly zoneDomain: string;
    readonly oidcIssuer: string;
    readonly oidcAudience: string;
    readonly oidcSubjectClaim: string;
    /** Required administrator OAuth scope when the console origin is enabled. */
    readonly oidcAdminScope?: string;
    /** OAuth client id the console SPA authenticates as; required when consoleFqdn is configured. */
    readonly oidcClientId?: string;
    /** Secret environment names surfaced to the console; defaults to [environmentName]. Parsed from the comma-separated `secretEnvironments` context key. */
    readonly secretEnvironments?: readonly string[];
    readonly existingHostedZoneId?: string;
}

export const deploymentConfigFromContext = (context: {
    tryGetContext(name: string): unknown;
}): DeploymentConfig => {
    const environmentName = (optionalContext(context, 'environment') ?? 'dev').toLowerCase();
    const adminFqdn = requiredContext(context, 'adminFqdn').toLowerCase();
    const apiFqdn = requiredContext(context, 'apiFqdn').toLowerCase();
    const consoleFqdn = optionalContext(context, 'consoleFqdn')?.toLowerCase();
    const consoleCertificateArn = optionalContext(context, 'consoleCertificateArn');
    const zoneDomain = requiredContext(context, 'zoneDomain').toLowerCase();
    const oidcIssuer = requiredContext(context, 'oidcIssuer');
    const oidcAudience = requiredContext(context, 'oidcAudience');
    const oidcSubjectClaim = optionalContext(context, 'oidcSubjectClaim') ?? 'sub';
    const oidcAdminScope = optionalContext(context, 'oidcAdminScope');
    const oidcClientId = optionalContext(context, 'oidcClientId');
    const secretEnvironmentsRaw = optionalContext(context, 'secretEnvironments');
    const secretEnvironments = secretEnvironmentsRaw === undefined
        ? undefined
        : secretEnvironmentsRaw.split(',').map((entry) => entry.trim());
    const existingHostedZoneId = optionalContext(context, 'existingHostedZoneId');
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(environmentName)) {
        throw new Error('context environment must match ^[a-z][a-z0-9-]{1,31}$');
    }
    for (const [name, value] of Object.entries({ adminFqdn, apiFqdn, zoneDomain, consoleFqdn })) {
        if (value === undefined) {
            continue;
        }
        if (!isFqdn(value)) {
            throw new Error(`context ${name} must be a lowercase FQDN.`);
        }
    }
    const configuredFqdns = consoleFqdn === undefined
        ? [adminFqdn, apiFqdn]
        : [adminFqdn, apiFqdn, consoleFqdn];
    if (new Set(configuredFqdns).size !== configuredFqdns.length) {
        throw new Error('adminFqdn, apiFqdn, and consoleFqdn must be different.');
    }
    if (!isInZone(adminFqdn, zoneDomain) || !isInZone(apiFqdn, zoneDomain) ||
        (consoleFqdn !== undefined && !isInZone(consoleFqdn, zoneDomain))) {
        throw new Error('adminFqdn, apiFqdn, and consoleFqdn must be within zoneDomain.');
    }
    if (!isHttpsUrl(oidcIssuer)) {
        throw new Error('context oidcIssuer must be an HTTPS issuer URL.');
    }
    if (oidcAudience.length > 512) {
        throw new Error('context oidcAudience must be at most 512 characters.');
    }
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(oidcSubjectClaim)) {
        throw new Error('context oidcSubjectClaim is not a valid JWT claim name.');
    }
    if (consoleFqdn !== undefined && oidcAdminScope === undefined) {
        throw new Error('context oidcAdminScope is required when consoleFqdn is configured.');
    }
    if (oidcAdminScope !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcAdminScope)) {
        throw new Error('context oidcAdminScope must be one OAuth scope token.');
    }
    if (consoleFqdn !== undefined && oidcClientId === undefined) {
        throw new Error('context oidcClientId is required when consoleFqdn is configured.');
    }
    if (consoleCertificateArn !== undefined && consoleFqdn === undefined) {
        throw new Error('context consoleCertificateArn must not be supplied unless consoleFqdn is configured.');
    }
    // CloudFront only accepts certificates issued in us-east-1, regardless of which
    // region the rest of the stack deploys to.
    if (consoleCertificateArn !== undefined && !isUsEast1CertificateArn(consoleCertificateArn)) {
        throw new Error(
            'context consoleCertificateArn must be an ACM certificate ARN in us-east-1, because CloudFront only accepts certificates from that region.',
        );
    }
    if (secretEnvironments !== undefined) {
        if (secretEnvironments.length === 0) {
            throw new Error('context secretEnvironments must not be empty.');
        }
        for (const entry of secretEnvironments) {
            if (!/^[a-z][a-z0-9-]{0,63}$/.test(entry)) {
                throw new Error('context secretEnvironments entries must match ^[a-z][a-z0-9-]{0,63}$');
            }
        }
    }
    return {
        environmentName,
        adminFqdn,
        apiFqdn,
        ...(consoleFqdn === undefined ? {} : { consoleFqdn }),
        ...(consoleCertificateArn === undefined ? {} : { consoleCertificateArn }),
        zoneDomain,
        oidcIssuer,
        oidcAudience,
        oidcSubjectClaim,
        ...(oidcAdminScope === undefined ? {} : { oidcAdminScope }),
        ...(oidcClientId === undefined ? {} : { oidcClientId }),
        ...(secretEnvironments === undefined ? {} : { secretEnvironments }),
        ...(existingHostedZoneId === undefined ? {} : { existingHostedZoneId }),
    };
};

/**
 * CloudFront only accepts ACM certificates issued in us-east-1. Exported so both
 * the CDK-context path (above) and library installers constructing HemligStack
 * directly (cdk/stack.ts) reject a wrong-region ARN at synth time rather than
 * discovering it as a CloudFormation deployment failure.
 */
export const isUsEast1CertificateArn = (value: string): boolean =>
    /^arn:aws[a-zA-Z-]*:acm:us-east-1:\d{12}:certificate\/[0-9a-f-]{36}$/.test(value);

const requiredContext = (context: { tryGetContext(name: string): unknown }, name: string): string => {
    const value = optionalContext(context, name);
    if (value === undefined) {
        throw new Error(`Missing CDK context value: ${name}`);
    }
    return value;
};

const optionalContext = (context: { tryGetContext(name: string): unknown }, name: string): string | undefined => {
    const value = context.tryGetContext(name);
    return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
};

const isFqdn = (value: string): boolean =>
    value.length <= 253 && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value);

const isInZone = (fqdn: string, zone: string): boolean => fqdn === zone || fqdn.endsWith(`.${zone}`);

const isHttpsUrl = (value: string): boolean => {
    try {
        return new URL(value).protocol === 'https:';
    } catch {
        return false;
    }
};
