import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const oidc = vi.hoisted(() => ({
  settings: undefined as Record<string, unknown> | undefined,
  endSession: "https://login.example.com/logout" as string | undefined,
  calls: [] as string[],
  signoutArgs: undefined as unknown,
  signoutThrows: false,
}));

vi.mock("oidc-client-ts", () => ({
  WebStorageStateStore: class {},
  UserManager: class {
    public events = { addUserLoaded() {}, addUserUnloaded() {} };
    public metadataService = {
      getEndSessionEndpoint: async () => oidc.endSession,
    };
    public constructor(settings: Record<string, unknown>) {
      oidc.settings = settings;
    }
    public async removeUser() {
      oidc.calls.push("removeUser");
    }
    public async signoutRedirect(args: unknown) {
      oidc.calls.push("signoutRedirect");
      oidc.signoutArgs = args;
      if (oidc.signoutThrows) {
        throw new Error("No end session endpoint");
      }
    }
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

describe("OidcDriver sign-out and authorize params", () => {
  const make = (extraQueryParams?: Record<string, string>) =>
    createAuthDriver({
      deploymentName: "d",
      adminApiUrl: "https://admin.example.test",
      auth: {
        mode: "oidc",
        authority: "https://login.example.com",
        clientId: "c",
        scopes: ["s"],
        ...(extraQueryParams === undefined ? {} : { extraQueryParams }),
      },
    });
  const assign = vi.fn();

  beforeEach(() => {
    oidc.calls.length = 0;
    oidc.endSession = "https://login.example.com/logout";
    oidc.signoutThrows = false;
    oidc.signoutArgs = undefined;
    assign.mockClear();
    vi.stubGlobal("window", {
      location: { origin: "https://console.example.test", assign },
      sessionStorage: {},
    });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("passes extraQueryParams to UserManager only when configured", () => {
    make();
    expect(oidc.settings).not.toHaveProperty("extraQueryParams");
    make({ audience: "https://api.example.com" });
    expect(oidc.settings?.extraQueryParams).toEqual({ audience: "https://api.example.com" });
  });

  it("redirects through the end session endpoint, without the authorize-only params", async () => {
    await make({ audience: "x" }).signOut();
    expect(oidc.calls).toEqual(["signoutRedirect"]);
    expect(oidc.signoutArgs).toEqual({ extraQueryParams: {} });
    expect(assign).not.toHaveBeenCalled();
  });

  it("with no end_session_endpoint, clears the session and goes to the console origin", async () => {
    oidc.endSession = undefined;
    await make().signOut();
    expect(oidc.calls).toEqual(["removeUser"]);
    expect(assign).toHaveBeenCalledWith("https://console.example.test");
  });

  it("falls back to the same local sign-out if the redirect throws", async () => {
    oidc.signoutThrows = true;
    await make().signOut();
    expect(oidc.calls).toEqual(["signoutRedirect", "removeUser"]);
    expect(assign).toHaveBeenCalledWith("https://console.example.test");
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
