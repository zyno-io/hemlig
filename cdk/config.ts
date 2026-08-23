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
    /**
     * Resource-qualified OAuth scope requested by the console SPA, for example
     * `api://<application-id>/hemlig.admin` on Microsoft Entra. This differs
     * from oidcAdminScope, the short value enforced from the access token's
     * `scp` claim by API Gateway.
     */
    readonly oidcConsoleAccessScope?: string;
    /** Optional external IdP role required by the Lambda after JWT validation. */
    readonly oidcAdminRole?: string;
    /** OAuth client id the console SPA authenticates as; required when consoleFqdn is configured. */
    readonly oidcClientId?: string;
    readonly existingHostedZoneId?: string;
    /**
     * Existing cursor HMAC secret to adopt instead of creating a new one. This
     * is useful when a prior retained CloudFormation creation must be recovered
     * under an organization SCP that forbids direct secret deletion.
     */
    readonly existingCursorHmacSecretArn?: string;
    /** Existing Hemlig application CMK to adopt after a retained failed creation. */
    readonly existingApplicationKeyArn?: string;
    /**
     * CDK bootstrap qualifier to reuse for the optional sibling console-certificate
     * stack. Supply this whenever the parent stack uses a non-default synthesizer.
     */
    readonly bootstrapQualifier?: string;
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
    const oidcConsoleAccessScope = optionalContext(context, 'oidcConsoleAccessScope');
    const oidcAdminRole = optionalContext(context, 'oidcAdminRole');
    const oidcClientId = optionalContext(context, 'oidcClientId');
    const existingHostedZoneId = optionalContext(context, 'existingHostedZoneId');
    const existingCursorHmacSecretArn = optionalContext(context, 'existingCursorHmacSecretArn');
    const existingApplicationKeyArn = optionalContext(context, 'existingApplicationKeyArn');
    const bootstrapQualifier = optionalContext(context, 'bootstrapQualifier');
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
    if (consoleFqdn !== undefined && oidcConsoleAccessScope === undefined) {
        throw new Error('context oidcConsoleAccessScope is required when consoleFqdn is configured.');
    }
    if (oidcAdminScope !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcAdminScope)) {
        throw new Error('context oidcAdminScope must be one OAuth scope token.');
    }
    if (oidcConsoleAccessScope !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcConsoleAccessScope)) {
        throw new Error('context oidcConsoleAccessScope must be one OAuth scope token.');
    }
    if (oidcAdminRole !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcAdminRole)) {
        throw new Error('context oidcAdminRole must be one role token.');
    }
    if (consoleFqdn !== undefined && oidcClientId === undefined) {
        throw new Error('context oidcClientId is required when consoleFqdn is configured.');
    }
    if (consoleCertificateArn !== undefined && consoleFqdn === undefined) {
        throw new Error('context consoleCertificateArn must not be supplied unless consoleFqdn is configured.');
    }
    if (bootstrapQualifier !== undefined && !/^[a-z0-9]{1,10}$/.test(bootstrapQualifier)) {
        throw new Error('context bootstrapQualifier must contain 1-10 lowercase letters or digits.');
    }
    if (
        existingCursorHmacSecretArn !== undefined &&
        !/^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[^\s]+$/.test(existingCursorHmacSecretArn)
    ) {
        throw new Error('context existingCursorHmacSecretArn must be a complete Secrets Manager ARN.');
    }
    if (
        existingApplicationKeyArn !== undefined &&
        !/^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/.test(existingApplicationKeyArn)
    ) {
        throw new Error('context existingApplicationKeyArn must be a complete KMS key ARN.');
    }
    // CloudFront only accepts certificates issued in us-east-1, regardless of which
    // region the rest of the stack deploys to.
    if (consoleCertificateArn !== undefined && !isUsEast1CertificateArn(consoleCertificateArn)) {
        throw new Error(
            'context consoleCertificateArn must be an ACM certificate ARN in us-east-1, because CloudFront only accepts certificates from that region.',
        );
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
        ...(oidcConsoleAccessScope === undefined ? {} : { oidcConsoleAccessScope }),
        ...(oidcAdminRole === undefined ? {} : { oidcAdminRole }),
        ...(oidcClientId === undefined ? {} : { oidcClientId }),
        ...(existingHostedZoneId === undefined ? {} : { existingHostedZoneId }),
        ...(existingCursorHmacSecretArn === undefined ? {} : { existingCursorHmacSecretArn }),
        ...(existingApplicationKeyArn === undefined ? {} : { existingApplicationKeyArn }),
        ...(bootstrapQualifier === undefined ? {} : { bootstrapQualifier }),
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
