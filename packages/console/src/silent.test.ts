import { beforeEach, describe, expect, it, vi } from "vitest";

// vi.mock is hoisted above every import, so the mocks it closes over must be
// created through vi.hoisted rather than as ordinary top-level consts.
const { mockSigninSilentCallback, mockUserManager, mockStateStore } = vi.hoisted(() => {
  const mockSigninSilentCallback = vi.fn(async () => {});
  const mockUserManager = vi.fn().mockImplementation(() => ({
    signinSilentCallback: mockSigninSilentCallback,
  }));
  const mockStateStore = vi
    .fn()
    .mockImplementation((options: { store: unknown }) => ({ store: options.store }));
  return { mockSigninSilentCallback, mockUserManager, mockStateStore };
});

vi.mock("oidc-client-ts", () => ({
  UserManager: mockUserManager,
  WebStorageStateStore: mockStateStore,
}));

// Importing this module also runs its top-level `void runSilentRenew()`
// once against the real global fetch, but the function swallows every
// failure itself, so that side effect cannot fail the tests below.
import { runSilentRenew } from "./silent";

const jsonResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

describe("silent renew entry", () => {
  beforeEach(() => {
    mockUserManager.mockClear();
    mockSigninSilentCallback.mockClear();
    mockStateStore.mockClear();
  });

  it("does nothing when the dev bridge has no provider to renew against", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        deploymentName: "hml-local",
        adminApiUrl: "http://127.0.0.1:5274",
        environments: ["dev"],
        auth: { mode: "dev-bridge", subject: "local" },
      }),
    );

    await runSilentRenew(fetchImpl as unknown as typeof fetch);

    expect(mockUserManager).not.toHaveBeenCalled();
    expect(mockSigninSilentCallback).not.toHaveBeenCalled();
  });

  it("calls signinSilentCallback with the OIDC provider's settings", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        deploymentName: "hml-test",
        adminApiUrl: "https://admin.example.com",
        environments: ["dev"],
        auth: {
          mode: "oidc",
          authority: "https://idp.example.com",
          clientId: "console-client",
          scopes: ["openid", "hemlig.admin"],
        },
      }),
    );

    await runSilentRenew(fetchImpl as unknown as typeof fetch);

    expect(mockUserManager).toHaveBeenCalledWith(
      expect.objectContaining({
        authority: "https://idp.example.com",
        client_id: "console-client",
        scope: "openid hemlig.admin",
        silent_redirect_uri: expect.stringContaining("/silent.html"),
      }),
    );
    expect(mockSigninSilentCallback).toHaveBeenCalledOnce();
  });

  it("swallows a fetch failure instead of leaving an unhandled rejection", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network unreachable");
    });

    await expect(runSilentRenew(fetchImpl as unknown as typeof fetch)).resolves.toBeUndefined();
    expect(mockUserManager).not.toHaveBeenCalled();
  });

  it("reads signin state from the same store the parent wrote it to", async () => {
    // oidc-client-ts defaults stateStore to localStorage while the parent
    // driver in src/auth/session.ts uses sessionStorage. A mismatch fails
    // every renewal with "no matching state", and a hidden iframe makes that
    // invisible.
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        deploymentName: "hml-test",
        adminApiUrl: "https://admin.example.com",
        environments: ["dev"],
        auth: {
          mode: "oidc",
          authority: "https://idp.example.com",
          clientId: "client",
          scopes: ["openid"],
        },
      }),
    ) as unknown as typeof fetch;

    await runSilentRenew(fetchImpl);

    expect(mockStateStore).toHaveBeenCalledWith({ store: window.sessionStorage });
    const settings = mockUserManager.mock.calls[0]?.[0] as { stateStore?: unknown };
    expect(settings.stateStore).toBeDefined();
  });
});
