import { parseRuntimeConfig } from "../packages/console/src/config";
import { consoleRuntimeConfig } from "./console-runtime-config";

// Guards the config.json <-> console-schema contract: consoleRuntimeConfig's
// output must satisfy the console's own parseRuntimeConfig (packages/console/src/config.ts),
// not a copy of it, so a field renamed on one side fails this test instead of
// the browser's boot-time fetch of /config.json.
describe("consoleRuntimeConfig", () => {
  it("produces a document the console's runtime schema accepts", () => {
    const config = consoleRuntimeConfig({
      deploymentName: "hml-test",
      adminFqdn: "admin.test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcClientId: "console-client",
      oidcAdminScope: "hemlig.admin",
      secretEnvironments: ["dev", "staging"],
    });

    const parsed = parseRuntimeConfig(config);

    expect(parsed.deploymentName).toBe("hml-test");
    expect(parsed.adminApiUrl).toBe("https://admin.test.example.com");
    expect(parsed.environments).toEqual(["dev", "staging"]);
    expect(parsed.auth.mode).toBe("oidc");
    if (parsed.auth.mode === "oidc") {
      expect(parsed.auth.authority).toBe(
        "https://login.example.com/tenant/v2.0",
      );
      expect(parsed.auth.clientId).toBe("console-client");
      expect(parsed.auth.scopes).toEqual(["openid", "profile", "hemlig.admin"]);
    }
  });

  it("rejects an empty secretEnvironments list, matching the console's non-empty requirement", () => {
    const config = consoleRuntimeConfig({
      deploymentName: "hml-test",
      adminFqdn: "admin.test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcClientId: "console-client",
      oidcAdminScope: "hemlig.admin",
      secretEnvironments: [],
    });

    expect(() => parseRuntimeConfig(config)).toThrow();
  });
});
