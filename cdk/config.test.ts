import { deploymentConfigFromContext } from './config';

const context = (values: Record<string, string | undefined>) => ({
    tryGetContext: (name: string): unknown => values[name],
});

describe('deploymentConfigFromContext', () => {
    it('accepts service FQDNs in the supplied zone', () => {
        const config = deploymentConfigFromContext(context({
            environment: 'prod',
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            existingHostedZoneId: 'Z0123456789ABCDEF',
        }));
        expect(config).toEqual({
            environmentName: 'prod',
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcSubjectClaim: 'sub',
            existingHostedZoneId: 'Z0123456789ABCDEF',
        });
    });

    it('rejects an FQDN outside the zone', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.other.example',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
        }))).toThrow('within zoneDomain');
    });

    it('requires a scope when a console origin enables browser access', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
        }))).toThrow('oidcAdminScope is required');
    });

    it('accepts a scoped console origin in the deployment zone', () => {
        const config = deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcAdminScope: 'hemlig.admin',
            oidcClientId: 'console-client',
        }));
        expect(config.consoleFqdn).toBe('console.example.com');
        expect(config.oidcAdminScope).toBe('hemlig.admin');
        expect(config.oidcClientId).toBe('console-client');
    });

    it('requires oidcClientId when a console origin is configured', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcAdminScope: 'hemlig.admin',
        }))).toThrow('oidcClientId is required');
    });

    it('accepts a consoleCertificateArn in us-east-1', () => {
        const config = deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            consoleCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcAdminScope: 'hemlig.admin',
            oidcClientId: 'console-client',
        }));
        expect(config.consoleCertificateArn).toBe(
            'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
        );
    });

    it('rejects a consoleCertificateArn outside us-east-1', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            consoleCertificateArn: 'arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcAdminScope: 'hemlig.admin',
            oidcClientId: 'console-client',
        }))).toThrow('ACM certificate ARN in us-east-1');
    });

    it('rejects a malformed consoleCertificateArn', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleFqdn: 'console.example.com',
            consoleCertificateArn: 'not-an-arn',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            oidcAdminScope: 'hemlig.admin',
            oidcClientId: 'console-client',
        }))).toThrow('ACM certificate ARN in us-east-1');
    });

    it('rejects a consoleCertificateArn without a console origin', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            consoleCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
        }))).toThrow('must not be supplied unless consoleFqdn');
    });

    it('parses a comma-separated secretEnvironments context value', () => {
        const config = deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            secretEnvironments: 'dev, staging, prod',
        }));
        expect(config.secretEnvironments).toEqual(['dev', 'staging', 'prod']);
    });

    it('rejects a secretEnvironments entry with an invalid name', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            secretEnvironments: 'dev,Prod',
        }))).toThrow('context secretEnvironments entries must match');
    });

    it('rejects an empty entry produced by a trailing comma in secretEnvironments', () => {
        expect(() => deploymentConfigFromContext(context({
            adminFqdn: 'admin.example.com',
            apiFqdn: 'api.example.com',
            zoneDomain: 'example.com',
            oidcIssuer: 'https://login.example.com/tenant/v2.0',
            oidcAudience: 'hemlig-api',
            secretEnvironments: 'dev,',
        }))).toThrow('context secretEnvironments entries must match');
    });
});
