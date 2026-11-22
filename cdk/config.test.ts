import { deploymentConfigFromContext } from "./config";

const context = (values: Record<string, string | undefined>) => ({
  tryGetContext: (name: string): unknown => values[name],
});

describe("deploymentConfigFromContext", () => {
  it("accepts service FQDNs in the supplied zone", () => {
    const config = deploymentConfigFromContext(
      context({
        environment: "prod",
        adminFqdn: "admin.example.com",
        apiFqdn: "api.example.com",
        zoneDomain: "example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcAudience: "hemlig-api",
        existingHostedZoneId: "Z0123456789ABCDEF",
      }),
    );
    expect(config).toEqual({
      environmentName: "prod",
      adminFqdn: "admin.example.com",
      apiFqdn: "api.example.com",
      zoneDomain: "example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
      existingHostedZoneId: "Z0123456789ABCDEF",
    });
  });

  it("rejects an FQDN outside the zone", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.other.example",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
        }),
      ),
    ).toThrow("within zoneDomain");
  });

  it("requires a scope when a console origin enables browser access", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleFqdn: "console.example.com",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
        }),
      ),
    ).toThrow("oidcAdminScope is required");
  });

  it("requires the browser access scope when a console origin is configured", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleFqdn: "console.example.com",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
          oidcAdminScope: "hemlig.admin",
          oidcClientId: "console-client",
        }),
      ),
    ).toThrow("oidcConsoleAccessScope is required");
  });

  it("accepts a scoped console origin in the deployment zone", () => {
    const config = deploymentConfigFromContext(
      context({
        adminFqdn: "admin.example.com",
        apiFqdn: "api.example.com",
        consoleFqdn: "console.example.com",
        zoneDomain: "example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcAudience: "hemlig-api",
        oidcAdminScope: "hemlig.admin",
        oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
        oidcAdminRole: "Hemlig.Administrator",
        oidcClientId: "console-client",
      }),
    );
    expect(config.consoleFqdn).toBe("console.example.com");
    expect(config.oidcAdminScope).toBe("hemlig.admin");
    expect(config.oidcConsoleAccessScope).toBe("api://hemlig-api/hemlig.admin");
    expect(config.oidcAdminRole).toBe("Hemlig.Administrator");
    expect(config.oidcClientId).toBe("console-client");
  });

  it("rejects a malformed optional administrator role", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
          oidcAdminRole: "not a role",
        }),
      ),
    ).toThrow("oidcAdminRole");
  });

  it("accepts a bootstrap qualifier for a separately bootstrapped account", () => {
    const config = deploymentConfigFromContext(
      context({
        adminFqdn: "admin.example.com",
        apiFqdn: "api.example.com",
        zoneDomain: "example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcAudience: "hemlig-api",
        bootstrapQualifier: "hmlsec01",
      }),
    );
    expect(config.bootstrapQualifier).toBe("hmlsec01");
  });

  it("defaults tracing off and accepts only true or false", () => {
    const base = {
      adminFqdn: "admin.example.com",
      apiFqdn: "api.example.com",
      zoneDomain: "example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
    };
    expect(deploymentConfigFromContext(context(base)).tracing).toBeUndefined();
    expect(
      deploymentConfigFromContext(context({ ...base, tracing: "true" }))
        .tracing,
    ).toBe(true);
    expect(
      deploymentConfigFromContext(context({ ...base, tracing: "false" }))
        .tracing,
    ).toBeUndefined();
    expect(() =>
      deploymentConfigFromContext(context({ ...base, tracing: "yes" })),
    ).toThrow('context tracing must be "true" or "false".');
  });

  it("accepts an existing application key ARN for explicit key adoption", () => {
    const config = deploymentConfigFromContext(
      context({
        adminFqdn: "admin.example.com",
        apiFqdn: "api.example.com",
        zoneDomain: "example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcAudience: "hemlig-api",
        existingApplicationKeyArn:
          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
      }),
    );
    expect(config.existingApplicationKeyArn).toContain(":key/");
  });

  it("requires oidcClientId when a console origin is configured", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleFqdn: "console.example.com",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
          oidcAdminScope: "hemlig.admin",
          oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
        }),
      ),
    ).toThrow("oidcClientId is required");
  });

  it("accepts a consoleCertificateArn in us-east-1", () => {
    const config = deploymentConfigFromContext(
      context({
        adminFqdn: "admin.example.com",
        apiFqdn: "api.example.com",
        consoleFqdn: "console.example.com",
        consoleCertificateArn:
          "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
        zoneDomain: "example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcAudience: "hemlig-api",
        oidcAdminScope: "hemlig.admin",
        oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
        oidcClientId: "console-client",
      }),
    );
    expect(config.consoleCertificateArn).toBe(
      "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
    );
  });

  it("rejects a consoleCertificateArn outside us-east-1", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleFqdn: "console.example.com",
          consoleCertificateArn:
            "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
          oidcAdminScope: "hemlig.admin",
          oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
          oidcClientId: "console-client",
        }),
      ),
    ).toThrow("ACM certificate ARN in us-east-1");
  });

  it("rejects a malformed consoleCertificateArn", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleFqdn: "console.example.com",
          consoleCertificateArn: "not-an-arn",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
          oidcAdminScope: "hemlig.admin",
          oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
          oidcClientId: "console-client",
        }),
      ),
    ).toThrow("ACM certificate ARN in us-east-1");
  });

  it("rejects a consoleCertificateArn without a console origin", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          adminFqdn: "admin.example.com",
          apiFqdn: "api.example.com",
          consoleCertificateArn:
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
          zoneDomain: "example.com",
          oidcIssuer: "https://login.example.com/tenant/v2.0",
          oidcAudience: "hemlig-api",
        }),
      ),
    ).toThrow("must not be supplied unless consoleFqdn");
  });
});

describe("PKI deployment context", () => {
  const base = {
    adminFqdn: "admin.example.com",
    apiFqdn: "api.example.com",
    zoneDomain: "example.com",
    oidcIssuer: "https://login.example.com/tenant/v2.0",
    oidcAudience: "hemlig-api",
  };
  const load = (extra: Record<string, unknown>) =>
    deploymentConfigFromContext({
      tryGetContext: (name: string): unknown =>
        ({ ...base, ...extra })[name as keyof typeof base],
    });

  it("accepts and returns both PKI role tokens", () => {
    const config = load({
      oidcPkiCaAdminRole: "hemlig-pki-ca-admin",
      oidcPkiOperatorRole: "hemlig-pki-operator",
    });
    expect(config.oidcPkiCaAdminRole).toBe("hemlig-pki-ca-admin");
    expect(config.oidcPkiOperatorRole).toBe("hemlig-pki-operator");
  });

  it("rejects malformed PKI role tokens naming the key", () => {
    expect(() => load({ oidcPkiCaAdminRole: "two words" })).toThrow(
      "context oidcPkiCaAdminRole must be one role token.",
    );
    expect(() => load({ oidcPkiOperatorRole: "bad value!" })).toThrow(
      "context oidcPkiOperatorRole must be one role token.",
    );
  });

  it("leaves the throttle keys absent when unset", () => {
    const config = load({});
    expect(config).not.toHaveProperty("pkiIssuanceRateLimit");
    expect(config).not.toHaveProperty("pkiIssuanceBurstLimit");
  });

  it("accepts numeric and string throttle values", () => {
    expect(
      load({ pkiIssuanceRateLimit: "25", pkiIssuanceBurstLimit: "50" }),
    ).toMatchObject({ pkiIssuanceRateLimit: 25, pkiIssuanceBurstLimit: 50 });
    expect(
      load({ pkiIssuanceRateLimit: 5, pkiIssuanceBurstLimit: 10 }),
    ).toMatchObject({ pkiIssuanceRateLimit: 5, pkiIssuanceBurstLimit: 10 });
  });

  it("rejects invalid throttle values", () => {
    for (const bad of ["0", "-1", "1.5", "abc"]) {
      expect(() => load({ pkiIssuanceRateLimit: bad })).toThrow(
        "context pkiIssuanceRateLimit must be a positive integer.",
      );
    }
    expect(() =>
      load({ pkiIssuanceRateLimit: 5001, pkiIssuanceBurstLimit: 5001 }),
    ).toThrow("pkiIssuanceRateLimit must be an integer from 1 to 5000.");
  });

  it("names the burst when only the burst is out of range", () => {
    expect(() =>
      load({ pkiIssuanceRateLimit: 10, pkiIssuanceBurstLimit: 5001 }),
    ).toThrow("pkiIssuanceBurstLimit must be an integer from 1 to 5000.");
  });

  it("names the rate when only the rate is out of range", () => {
    expect(() =>
      load({ pkiIssuanceRateLimit: 5001, pkiIssuanceBurstLimit: 10 }),
    ).toThrow("pkiIssuanceRateLimit must be an integer from 1 to 5000.");
  });

  it("rejects a rate above the default burst", () => {
    expect(() => load({ pkiIssuanceRateLimit: "50" })).toThrow(
      "pkiIssuanceBurstLimit must be at least pkiIssuanceRateLimit.",
    );
  });
});
