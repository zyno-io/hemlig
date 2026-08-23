export interface DeploymentConfig {
    readonly environmentName: string;
    readonly adminFqdn: string;
    readonly clusterFqdn: string;
    readonly zoneDomain: string;
    readonly oidcIssuer: string;
    readonly oidcAudience: string;
    readonly oidcSubjectClaim: string;
    readonly existingHostedZoneId?: string;
}

export const deploymentConfigFromContext = (context: {
    tryGetContext(name: string): unknown;
}): DeploymentConfig => {
    const environmentName = (optionalContext(context, 'environment') ?? 'dev').toLowerCase();
    const adminFqdn = requiredContext(context, 'adminFqdn').toLowerCase();
    const clusterFqdn = requiredContext(context, 'clusterFqdn').toLowerCase();
    const zoneDomain = requiredContext(context, 'zoneDomain').toLowerCase();
    const oidcIssuer = requiredContext(context, 'oidcIssuer');
    const oidcAudience = requiredContext(context, 'oidcAudience');
    const oidcSubjectClaim = optionalContext(context, 'oidcSubjectClaim') ?? 'sub';
    const existingHostedZoneId = optionalContext(context, 'existingHostedZoneId');
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(environmentName)) {
        throw new Error('context environment must match ^[a-z][a-z0-9-]{1,31}$');
    }
    for (const [name, value] of Object.entries({ adminFqdn, clusterFqdn, zoneDomain })) {
        if (!isFqdn(value)) {
            throw new Error(`context ${name} must be a lowercase FQDN.`);
        }
    }
    if (adminFqdn === clusterFqdn) {
        throw new Error('adminFqdn and clusterFqdn must be different.');
    }
    if (!isInZone(adminFqdn, zoneDomain) || !isInZone(clusterFqdn, zoneDomain)) {
        throw new Error('adminFqdn and clusterFqdn must be within zoneDomain.');
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
    return {
        environmentName,
        adminFqdn,
        clusterFqdn,
        zoneDomain,
        oidcIssuer,
        oidcAudience,
        oidcSubjectClaim,
        existingHostedZoneId,
    };
};

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
