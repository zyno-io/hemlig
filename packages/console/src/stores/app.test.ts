import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RuntimeConfig } from "../config";

const driver = vi.hoisted(() => ({
  initialize: vi.fn(async () => ({ subject: "admin" })),
  signIn: vi.fn(async () => {}),
  signOut: vi.fn(async () => {}),
  completeSignIn: vi.fn(async () => ({ subject: "admin" })),
  accessToken: vi.fn(async () => "t"),
}));
vi.mock("../auth/session", () => ({ createAuthDriver: () => driver }));

import { useAppStore } from "./app";

const runtime: RuntimeConfig = {
  deploymentName: "d",
  adminApiUrl: "https://admin.example.test",
  auth: { mode: "oidc", authority: "https://login.example.test", clientId: "c", scopes: ["openid"] },
};

// Node 26 can leave window.sessionStorage undefined in this environment; the
// store must behave (in memory) either way, so only touch it when present.
const storage = (): Storage | undefined => {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
};

describe("app store sign-out", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    storage()?.clear();
    vi.clearAllMocks();
  });
  afterEach(() => {
    storage()?.clear();
  });

  it("raises the signed-out flag before the driver signs out (provider with an end-session endpoint)", async () => {
    const store = useAppStore();
    await store.initialize(runtime);
    let seen: boolean | undefined;
    driver.signOut.mockImplementationOnce(async () => {
      seen = store.signedOut;
    });
    await store.signOut();
    expect(seen).toBe(true);
    expect(store.session).toBeUndefined();
    expect(driver.signIn).not.toHaveBeenCalled();
  });

  it("after the local-only fallback reloads the page, a provider session is not silently renewed", async () => {
    const first = useAppStore();
    await first.initialize(runtime);
    await first.signOut();
    if (storage() === undefined) {
      return; // no storage in this environment: nothing survives a reload to test
    }
    setActivePinia(createPinia());
    const reloaded = useAppStore();
    driver.initialize.mockClear();
    await reloaded.initialize(runtime);
    expect(reloaded.signedOut).toBe(true);
    expect(driver.initialize).not.toHaveBeenCalled();
    expect(reloaded.session).toBeUndefined();
  });

  it("an explicit sign-in clears the flag", async () => {
    const store = useAppStore();
    await store.initialize(runtime);
    await store.signOut();
    await store.signIn("/");
    expect(store.signedOut).toBe(false);
    expect(driver.signIn).toHaveBeenCalledWith("/");
  });
});
