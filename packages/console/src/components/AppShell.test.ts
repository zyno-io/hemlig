import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { ref } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import AppShell from "./AppShell.vue";

const envList = vi.hoisted(() => ({ names: ["prod"] as string[] }));
vi.mock("../composables/useEnvironments", () => ({
  useEnvironmentsQuery: () => ({
    data: ref({ environments: envList.names.map((name) => ({ name })) }),
    error: ref(undefined),
  }),
}));

const mountShell = async (names: string[]) => {
  envList.names = names;
  setActivePinia(createPinia());
  const stub = { template: "<div/>" };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "root", component: stub },
      { path: "/e/:env/secrets", name: "secrets", component: stub },
      { path: "/e/:env/pki", name: "pki", component: stub },
      { path: "/e/:env/consumers", name: "consumers", component: stub },
      { path: "/environments", name: "environments", component: stub },
      { path: "/audit", name: "audit", component: stub },
      { path: "/trust", name: "trust", component: stub },
      { path: "/about", name: "about", component: stub },
    ],
  });
  await router.push({ name: "environments" });
  await router.isReady();
  const wrapper = mount(AppShell, {
    global: { plugins: [router], stubs: { ThemeMenu: true } },
  });
  await flushPromises();
  return wrapper;
};

/** Link labels, with "|" where the separator sits. */
const nav = (wrapper: Awaited<ReturnType<typeof mountShell>>): string[] =>
  wrapper
    .findAll("nav.primary-nav > *")
    .map((el) => (el.attributes("data-testid") === "nav-separator" ? "|" : el.text()));

describe("AppShell", () => {
  it("orders the environment tabs Secrets, PKI, Consumers and separates them from the global tabs", async () => {
    const wrapper = await mountShell(["prod"]);
    const items = nav(wrapper);
    expect(items.slice(0, 5)).toEqual(["Secrets", "PKI", "Consumers", "|", "Environments"]);
    expect(items.filter((item) => item === "|")).toHaveLength(1);
    const separator = wrapper.get('[data-testid="nav-separator"]');
    expect(separator.attributes("aria-hidden")).toBe("true");
  });

  it("shows no separator when there is no environment", async () => {
    const wrapper = await mountShell([]);
    expect(nav(wrapper)[0]).toBe("Environments");
    expect(wrapper.find('[data-testid="nav-separator"]').exists()).toBe(false);
  });
});
