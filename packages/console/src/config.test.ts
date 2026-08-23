import { describe, expect, it } from "vitest";
import { parseRuntimeConfig } from "./config";

const base = {
  deploymentName: "hml-dev",
};

describe("runtime configuration", () => {
  it("accepts an OIDC deployment over HTTPS", () => {
    const config = parseRuntimeConfig({
      ...base,
      adminApiUrl: "https://admin.dev.example.com",
      auth: {
        mode: "oidc",
        authority: "https://login.example.com/tenant/v2.0",
        clientId: "abc",
        scopes: ["openid", "hemlig.admin"],
      },
    });
    expect(config.auth.mode).toBe("oidc");
  });

  it("refuses an OIDC deployment over plain HTTP", () => {
    expect(() =>
      parseRuntimeConfig({
        ...base,
        adminApiUrl: "http://admin.dev.example.com",
        auth: {
          mode: "oidc",
          authority: "https://login.example.com",
          clientId: "abc",
          scopes: ["openid"],
        },
      }),
    ).toThrow(/HTTPS/);
  });

  it("permits the dev bridge only against loopback", () => {
    expect(
      parseRuntimeConfig({
        ...base,
        adminApiUrl: "http://127.0.0.1:5274",
        auth: { mode: "dev-bridge", subject: "local" },
      }).auth.mode,
    ).toBe("dev-bridge");

    // Otherwise an unauthenticated console could be pointed at a real account.
    expect(() =>
      parseRuntimeConfig({
        ...base,
        adminApiUrl: "https://admin.prod.example.com",
        auth: { mode: "dev-bridge", subject: "local" },
      }),
    ).toThrow(/loopback/);
  });

  it("rejects a document missing required fields rather than half-configuring", () => {
    expect(() => parseRuntimeConfig({ deploymentName: "x" })).toThrow();
    expect(() =>
      parseRuntimeConfig({ ...base, adminApiUrl: "not-a-url", auth: { mode: "dev-bridge", subject: "l" } }),
    ).toThrow();
  });

  it("no longer requires a static environments list", () => {
    const config = parseRuntimeConfig({
      ...base,
      adminApiUrl: "http://127.0.0.1:5274",
      auth: { mode: "dev-bridge", subject: "local" },
    });
    expect(config).not.toHaveProperty("environments");
  });

  it("ignores a stray environments field from a config document a rolling deploy has not caught up with yet", () => {
    const config = parseRuntimeConfig({
      ...base,
      // Environments are now administrator-defined API state, not a build-time
      // constant; the CDK stops writing this field, but a document from a CDK
      // version still writing it must not fail to parse mid-rollout.
      environments: ["dev", "staging"],
      adminApiUrl: "http://127.0.0.1:5274",
      auth: { mode: "dev-bridge", subject: "local" },
    });
    expect(config).not.toHaveProperty("environments");
  });
});
