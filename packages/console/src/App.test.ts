import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import App from "./App.vue";
import { useAppStore } from "./stores/app";

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
        path: "/auth/callback",
        name: "auth-callback",
        component: { template: '<div data-testid="callback-route-content" />' },
      },
    ],
  });

const mountApp = async (
  path: string,
  { session = false }: { session?: boolean } = {},
): Promise<{ wrapper: ReturnType<typeof mount>; signIn: ReturnType<typeof vi.spyOn> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  const signIn = vi.spyOn(store, "signIn").mockResolvedValue();
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
});

describe("App", () => {
  it("starts OIDC sign-in and does not mount the shell or router outlet without a session", async () => {
    const { wrapper, signIn } = await mountApp("/");

    expect(signIn).toHaveBeenCalledOnce();
    expect(wrapper.find('[data-testid="app-shell"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="route-content"]').exists()).toBe(false);
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
});
