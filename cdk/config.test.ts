import { deploymentConfigFromContext, resolveOidcDefaults } from "./config";

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

describe("one-app OIDC defaults", () => {
  const base = {
    adminFqdn: "admin.example.com",
    apiFqdn: "api.example.com",
    zoneDomain: "example.com",
  };
  const entra = "https://login.microsoftonline.com/tenant/v2.0";

  it("defaults the audience to the client ID", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        oidcIssuer: entra,
        oidcClientId: "app-id",
        oidcAdminScope: "hemlig.admin",
      }),
    );
    expect(config.oidcAudience).toBe("app-id");
  });

  it("lets an explicit audience win over the client ID", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        oidcIssuer: entra,
        oidcClientId: "console-id",
        oidcAudience: "api-id",
      }),
    );
    expect(config.oidcAudience).toBe("api-id");
  });

  it("requires oidcAdminScope when the audience is derived from the client ID", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({ ...base, oidcIssuer: entra, oidcClientId: "app-id" }),
      ),
    ).toThrow("oidcAdminScope is required when oidcAudience is omitted");
  });

  it("fails when neither client ID nor audience is set", () => {
    expect(() =>
      deploymentConfigFromContext(context({ ...base, oidcIssuer: entra })),
    ).toThrow(
      "set oidcClientId (or oidcAudience for an API-only deployment without the console)",
    );
  });

  it("still validates the resolved audience", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          ...base,
          oidcIssuer: entra,
          oidcClientId: "x".repeat(513),
          oidcAdminScope: "hemlig.admin",
        }),
      ),
    ).toThrow("oidcAudience must be at most 512 characters");
  });

  it("derives an api:// console scope on Entra issuers", () => {
    for (const host of [
      "login.microsoftonline.com",
      "login.microsoftonline.us",
      "login.chinacloudapi.cn",
    ]) {
      const config = deploymentConfigFromContext(
        context({
          ...base,
          consoleFqdn: "console.example.com",
          oidcIssuer: `https://${host}/tenant/v2.0`,
          oidcClientId: "app-id",
          oidcAdminScope: "hemlig.admin",
        }),
      );
      expect(config.oidcConsoleAccessScope).toBe("api://app-id/hemlig.admin");
    }
  });

  it("derives the scope from the audience when it differs from the client ID", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        oidcIssuer: entra,
        oidcAudience: "api-id",
        oidcClientId: "console-id",
        oidcAdminScope: "hemlig.admin",
      }),
    );
    expect(config.oidcConsoleAccessScope).toBe("api://api-id/hemlig.admin");
  });

  it("uses the bare admin scope on non-Entra issuers", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        consoleFqdn: "console.example.com",
        oidcIssuer: "https://login.example.com/tenant/v2.0",
        oidcClientId: "console-client",
        oidcAdminScope: "hemlig.admin",
      }),
    );
    expect(config.oidcConsoleAccessScope).toBe("hemlig.admin");
  });

  it("lets an explicit console scope win", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        oidcIssuer: entra,
        oidcClientId: "app-id",
        oidcAdminScope: "hemlig.admin",
        oidcConsoleAccessScope: "https://custom.example.com/hemlig.admin",
      }),
    );
    expect(config.oidcConsoleAccessScope).toBe(
      "https://custom.example.com/hemlig.admin",
    );
  });

  it("does not derive a console scope without an admin scope or client ID", () => {
    const audienceOnly = deploymentConfigFromContext(
      context({ ...base, oidcIssuer: entra, oidcAudience: "api-id" }),
    );
    expect(audienceOnly.oidcConsoleAccessScope).toBeUndefined();
    const noScope = deploymentConfigFromContext(
      context({
        ...base,
        oidcIssuer: entra,
        oidcClientId: "app-id",
        oidcAudience: "api-id",
      }),
    );
    expect(noScope.oidcConsoleAccessScope).toBeUndefined();
  });

  it("still requires oidcAdminScope and oidcClientId with a console origin", () => {
    expect(() =>
      deploymentConfigFromContext(
        context({
          ...base,
          consoleFqdn: "console.example.com",
          oidcIssuer: entra,
          oidcAudience: "api-id",
          oidcAdminScope: "hemlig.admin",
        }),
      ),
    ).toThrow("oidcClientId is required");
    expect(() =>
      deploymentConfigFromContext(
        context({
          ...base,
          consoleFqdn: "console.example.com",
          oidcIssuer: entra,
          oidcClientId: "app-id",
        }),
      ),
    ).toThrow("oidcAdminScope is required");
  });

  it("accepts an API-only deployment with just an audience", () => {
    const config = deploymentConfigFromContext(
      context({ ...base, oidcIssuer: entra, oidcAudience: "api-id" }),
    );
    expect(config.oidcAudience).toBe("api-id");
    expect(config.consoleFqdn).toBeUndefined();
    expect(config.oidcClientId).toBeUndefined();
  });

  it("keeps an explicit two-app context's resolved config unchanged", () => {
    const config = deploymentConfigFromContext(
      context({
        ...base,
        consoleFqdn: "console.example.com",
        oidcIssuer: entra,
        oidcAudience: "api-id",
        oidcAdminScope: "hemlig.admin",
        oidcConsoleAccessScope: "api://api-id/hemlig.admin",
        oidcClientId: "console-id",
      }),
    );
    expect(config).toEqual({
      environmentName: "dev",
      ...base,
      consoleFqdn: "console.example.com",
      zoneDomain: "example.com",
      oidcIssuer: entra,
      oidcAudience: "api-id",
      oidcSubjectClaim: "sub",
      oidcAdminScope: "hemlig.admin",
      oidcConsoleAccessScope: "api://api-id/hemlig.admin",
      oidcClientId: "console-id",
    });
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

describe("resolveOidcDefaults role tokens (props path)", () => {
  const input = { oidcIssuer: "https://issuer.example.test", oidcAudience: "api" };

  it.each(["oidcAdminRole", "oidcPkiCaAdminRole", "oidcPkiOperatorRole"] as const)(
    "rejects a comma, space or blank in %s",
    (name) => {
      for (const value of ["Hemlig,Admin", "Hemlig Admin", ""]) {
        expect(() => resolveOidcDefaults({ ...input, [name]: value })).toThrow(`${name} must be one role token.`);
      }
      expect((resolveOidcDefaults({ ...input, [name]: "Hemlig.Administrator" }) as Record<string, unknown>)[name]).toBe("Hemlig.Administrator");
    },
  );
});
