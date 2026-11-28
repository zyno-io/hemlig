import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import App from "./App.vue";
import { useAppStore } from "./stores/app";

const authDriver = vi.hoisted(() => ({
  initialize: vi.fn(async () => ({ subject: "admin" })),
  signOut: vi.fn(async () => {}),
}));
vi.mock("./auth/session", () => ({ createAuthDriver: () => authDriver }));

vi.mock("./components/AppShell.vue", () => ({
  default: { template: '<div data-testid="app-shell"><slot /></div>' },
}));

vi.mock("./views/AuthCallback.vue", () => ({
  default: { template: '<div data-testid="auth-callback" />' },
}));

const createRouterForPath = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "root", component: { template: '<div data-testid="route-content" />' } },
      {
        path: "/cli-login",
        name: "cli-login",
        component: { template: '<div data-testid="route-content" />' },
      },
      {
        path: "/auth/callback",
        name: "auth-callback",
        component: { template: '<div data-testid="callback-route-content" />' },
      },
    ],
  });

const mountApp = async (
  path: string,
  { session = false, signedOut = false }: { session?: boolean; signedOut?: boolean } = {},
): Promise<{ wrapper: ReturnType<typeof mount>; signIn: MockInstance<(returnTo?: string) => Promise<void>> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  const signIn = vi.spyOn(store, "signIn").mockResolvedValue();
  store.signedOut = signedOut;
  if (session) {
    store.adoptSession({ subject: "admin" });
  }

  const router = createRouterForPath();
  await router.push(path);
  await router.isReady();

  const wrapper = mount(App, { global: { plugins: [pinia, router] } });
  await flushPromises();
  return { wrapper, signIn };
};

afterEach(() => {
  vi.restoreAllMocks();
  window.sessionStorage?.clear();
});

describe("App", () => {
  it("starts OIDC sign-in and does not mount the shell or router outlet without a session", async () => {
    const { wrapper, signIn } = await mountApp("/");

    expect(signIn).toHaveBeenCalledOnce();
    expect(wrapper.find('[data-testid="app-shell"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="route-content"]').exists()).toBe(false);
  });

  it("starts sign-in with the full path and query so /cli-login survives the round trip", async () => {
    const { signIn } = await mountApp("/cli-login?port=40000&state=abc");

    expect(signIn).toHaveBeenCalledWith("/cli-login?port=40000&state=abc");
  });

  it("mounts the authenticated shell and router outlet when a session exists", async () => {
    const { wrapper, signIn } = await mountApp("/", { session: true });

    expect(signIn).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="app-shell"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="route-content"]').exists()).toBe(true);
  });

  it("processes the OIDC callback outside the router outlet without starting another redirect", async () => {
    const { wrapper, signIn } = await mountApp("/auth/callback");

    expect(signIn).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="auth-callback"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="callback-route-content"]').exists()).toBe(false);
  });

  it("after an explicit sign-out shows a signed-out state and does not start sign-in", async () => {
    const { wrapper, signIn } = await mountApp("/", { signedOut: true });

    expect(signIn).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("You're signed out");
    expect(wrapper.find('[data-testid="app-shell"]').exists()).toBe(false);

    await wrapper.find("button").trigger("click");
    expect(signIn).toHaveBeenCalledOnce();
  });

  it("signing out does not race a sign-in redirect against the end-session redirect", async () => {
    const { wrapper, signIn } = await mountApp("/", { session: true });
    const store = useAppStore();
    await store.initialize({
      deploymentName: "d",
      adminApiUrl: "https://admin.example.test",
      auth: { mode: "oidc", authority: "https://login.example.test", clientId: "c", scopes: ["openid"] },
    });
    await flushPromises();
    signIn.mockClear();
    await store.signOut();
    await flushPromises();

    expect(authDriver.signOut).toHaveBeenCalledOnce();
    expect(signIn).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("You're signed out");
  });
});
