import { describe, expect, it, vi } from "vitest";

vi.mock("oidc-client-ts", () => ({
  WebStorageStateStore: class {},
  UserManager: class {
    public events = { addUserLoaded() {}, addUserUnloaded() {} };
    public async signinSilent() {
      return { access_token: "secret.access.token", expires_at: 4_000_000_000, profile: { sub: "s", email: "a@example.test" } };
    }
    public async signinRedirectCallback() {
      return { access_token: "secret.access.token", expires_at: 4_000_000_000, profile: { sub: "s" }, state: { returnTo: "/cli-login?x=1" } };
    }
  },
}));

import { createAuthDriver, safeReturnTo } from "./session";

describe("OidcDriver session state", () => {
  const driver = createAuthDriver({
    deploymentName: "d",
    adminApiUrl: "https://admin.example.test",
    auth: { mode: "oidc", authority: "https://login.example.com", clientId: "c", scopes: ["s"] },
  });

  it("initialize never returns the access token into reactive state", async () => {
    const session = await driver.initialize();
    expect(session).toMatchObject({ subject: "s", email: "a@example.test" });
    expect(JSON.stringify(session)).not.toContain("secret.access.token");
    expect(session).not.toHaveProperty("token");
  });

  it("completeSignIn does not expose it either, and keeps returnTo", async () => {
    const session = await driver.completeSignIn();
    expect(JSON.stringify(session)).not.toContain("secret.access.token");
    expect(session?.returnTo).toBe("/cli-login?x=1");
  });

  it("the token is still available through accessToken()", async () => {
    await driver.initialize();
    expect(await driver.accessToken()).toBe("secret.access.token");
  });
});

describe("safeReturnTo", () => {
  it("keeps same-origin paths with their query string", () => {
    expect(safeReturnTo("/cli-login?port=40000&state=abc")).toBe("/cli-login?port=40000&state=abc");
  });
  it.each(["//evil.example.com", "/\\evil.example.com", "https://evil.example.com", "/auth/callback?x", "", undefined, 5])(
    "rejects %s",
    (value) => {
      expect(safeReturnTo(value)).toBeUndefined();
    },
  );
});
