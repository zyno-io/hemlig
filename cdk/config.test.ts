import { deploymentConfigFromContext } from './config';

const context = (values: Record<string, string | undefined>) => ({
    tryGetContext: (name: string): unknown => values[name],
});

describe('deploymentConfigFromContext', () => {
    it('accepts service FQDNs in the supplied zone', () => {
        const config = deploymentConfigFromContext(context({
            environment: 'prod',
            adminFqdn: 'admin.example.com',
            clusterFqdn: 'clusters.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'clavis-api',
            existingHostedZoneId: 'Z0123456789ABCDEF',
        }));
        expect(config).toEqual({
            environmentName: 'prod',
            adminFqdn: 'admin.example.com',
            clusterFqdn: 'clusters.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'clavis-api',
            oidcSubjectClaim: 'sub',
            existingHostedZoneId: 'Z0123456789ABCDEF',
        });
    });

    it('rejects an FQDN outside the zone', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            clusterFqdn: 'clusters.other.example',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'clavis-api',
        }))).toThrow('within zoneDomain');
    });
});
