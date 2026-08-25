import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia, type Pinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import { ApiError } from "../api/errors";
import type { CatalogEntry, CatalogPage, SecretTreePage } from "../api/schemas";
import { useAppStore } from "../stores/app";
import SecretsCatalog, {
  parseCatalogFilter,
  pathSegments,
} from "./SecretsCatalog.vue";

describe("pathSegments", () => {
  it("has no crumbs at the root, for both undefined and empty input", () => {
    expect(pathSegments(undefined)).toEqual([]);
    expect(pathSegments("")).toEqual([]);
  });

  it("derives a single crumb for a one-segment path", () => {
    expect(pathSegments("payments")).toEqual([
      { segment: "payments", path: "payments" },
    ]);
  });

  it("derives a cumulative path for each segment of a nested path", () => {
    expect(pathSegments("payments/stripe/keys")).toEqual([
      { segment: "payments", path: "payments" },
      { segment: "stripe", path: "payments/stripe" },
      { segment: "keys", path: "payments/stripe/keys" },
    ]);
  });
});

describe("parseCatalogFilter", () => {
  it("treats bare text as free text", () => {
    expect(parseCatalogFilter("stripe-api-key")).toEqual({
      text: "stripe-api-key",
      tags: [],
    });
  });

  it("parses a single key:value token as a tag filter", () => {
    expect(parseCatalogFilter("owner:payments")).toEqual({
      text: "",
      tags: [{ key: "owner", value: "payments" }],
    });
  });

  it("parses several tag tokens", () => {
    expect(parseCatalogFilter("owner:payments system:billing")).toEqual({
      text: "",
      tags: [
        { key: "owner", value: "payments" },
        { key: "system", value: "billing" },
      ],
    });
  });

  it("mixes tags and free text, joining the free-text tokens with a single space", () => {
    expect(parseCatalogFilter("owner:payments stripe api")).toEqual({
      text: "stripe api",
      tags: [{ key: "owner", value: "payments" }],
    });
  });

  it("falls back to free text for a colon-bearing token that fails the tag patterns, such as a URL fragment", () => {
    expect(parseCatalogFilter("https://example.com/callback")).toEqual({
      text: "https://example.com/callback",
      tags: [],
    });
  });

  it("returns no text and no tags for empty input", () => {
    expect(parseCatalogFilter("")).toEqual({ text: "", tags: [] });
    expect(parseCatalogFilter("   ")).toEqual({ text: "", tags: [] });
  });
});

const emptyTreePage: SecretTreePage = {
  environment: "dev",
  folders: [],
  secrets: [],
  truncated: false,
  generatedAt: "2026-08-23T00:00:00.000Z",
};

const emptyCatalogPage: CatalogPage = {
  secrets: [],
  generatedAt: "2026-08-23T00:00:00.000Z",
};

const secretFixture = (
  overrides: Partial<CatalogEntry> = {},
): CatalogEntry => ({
  secretId: "stripe-api-key",
  environment: "dev",
  controlVersionId: "ctl-1",
  state: "ACTIVE",
  metadata: {},
  ...overrides,
});

interface FakeApi {
  getSecretsTree: (...args: unknown[]) => Promise<SecretTreePage>;
  listSecrets: (...args: unknown[]) => Promise<CatalogPage>;
}

const defaultApi = (overrides: Partial<FakeApi> = {}): FakeApi => ({
  getSecretsTree: async () => emptyTreePage,
  listSecrets: async () => emptyCatalogPage,
  ...overrides,
});

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: "/e/:env/secrets",
        name: "secrets",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/browse/:path*",
        name: "secrets-browse",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/new",
        name: "secret-new",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId",
        name: "secret",
        component: { template: "<div/>" },
      },
    ],
  });

const mountCatalog = async (
  api: FakeApi,
  props: { env: string; path?: string[] } = { env: "dev" },
  query: Record<string, string> = {},
): Promise<{
  wrapper: ReturnType<typeof mount>;
  router: Router;
  pinia: Pinia;
  queryClient: QueryClient;
}> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  // Bypasses HemligApi/fetch entirely; the transport is covered by
  // client.test.ts. This is a fake satisfying only the surface this
  // component calls, not the real class.
  store.api = api as unknown as ReturnType<typeof store.requireApi>;

  const router = buildRouter();
  await router.push({ name: "secrets", params: { env: props.env }, query });
  await router.isReady();

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  const wrapper = mount(SecretsCatalog, {
    props,
    // The global RouterLink stub (vitest.setup.ts) drops `to` entirely, which
    // hides it from the href-based assertions below; the real router already
    // provided as a plugin is enough to resolve real hrefs instead.
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: false },
    },
  });
  await flushPromises();
  return { wrapper, router, pinia, queryClient };
};

describe("SecretsCatalog tree browsing", () => {
  it("says a level is incomplete rather than showing a silently short list", async () => {
    const api = defaultApi({
      getSecretsTree: async () => ({ ...emptyTreePage, truncated: true }),
    });
    const { wrapper } = await mountCatalog(api);

    expect(wrapper.text()).toContain("incomplete");
  });

  it("renders folders with their secret counts", async () => {
    const api = defaultApi({
      getSecretsTree: async () => ({
        ...emptyTreePage,
        folders: [
          {
            segment: "stripe",
            path: "payments/stripe",
            secretCount: 12,
            kind: "derived",
          },
        ],
      }),
    });
    const { wrapper } = await mountCatalog(api, {
      env: "dev",
      path: ["payments"],
    });

    expect(wrapper.text()).toContain("stripe");
    expect(wrapper.text()).toContain("12 secrets");
  });

  it("carries the folder being browsed into the New secret link", async () => {
    const { wrapper } = await mountCatalog(defaultApi(), {
      env: "dev",
      path: ["payments", "stripe"],
    });

    const link = wrapper.findAll("a").find((a) => a.text() === "New secret");
    const url = new URL(
      link?.attributes("href") ?? "",
      "http://console.invalid",
    );
    expect(url.pathname).toBe("/e/dev/secrets/new");
    expect(url.searchParams.get("path")).toBe("payments/stripe");
  });

  it("carries the current folder into a secret detail return link", async () => {
    const { wrapper } = await mountCatalog(
      defaultApi({
        getSecretsTree: async () => ({
          ...emptyTreePage,
          secrets: [secretFixture()],
        }),
      }),
      { env: "dev", path: ["payments", "stripe"] },
    );
    const link = wrapper
      .findAll("a")
      .find((anchor) => anchor.text() === "stripe-api-key");
    const url = new URL(
      link?.attributes("href") ?? "",
      "http://console.invalid",
    );
    expect(url.pathname).toBe("/e/dev/secrets/stripe-api-key");
    expect(url.searchParams.get("catalogPath")).toBe("payments/stripe");
  });

  it("renders a derived folder normally", async () => {
    const api = defaultApi({
      getSecretsTree: async () => ({
        ...emptyTreePage,
        folders: [
          {
            segment: "archived",
            path: "archived",
            secretCount: 0,
            kind: "derived",
          },
        ],
      }),
    });
    const { wrapper } = await mountCatalog(api);

    expect(wrapper.text()).toContain("archived");
    expect(wrapper.text()).toContain("0 secrets");
    expect(wrapper.text()).not.toContain("Nothing directly at this path.");
  });

  it("carries no path into the New secret link from the root", async () => {
    const { wrapper } = await mountCatalog(defaultApi());

    const link = wrapper.findAll("a").find((a) => a.text() === "New secret");
    const url = new URL(
      link?.attributes("href") ?? "",
      "http://console.invalid",
    );
    expect(url.pathname).toBe("/e/dev/secrets/new");
    expect(url.searchParams.has("path")).toBe(false);
  });
});

describe("SecretsCatalog search", () => {
  const searchInput = (
    wrapper: Awaited<ReturnType<typeof mountCatalog>>["wrapper"],
  ) => wrapper.find("#catalog-filter");

  it("waits for the debounce before calling listSecrets with q, and not before", async () => {
    vi.useFakeTimers();
    try {
      const listSecrets = vi.fn(
        async (): Promise<CatalogPage> => emptyCatalogPage,
      );
      const { wrapper } = await mountCatalog(defaultApi({ listSecrets }));

      await searchInput(wrapper).setValue("stripe");
      // A search-as-you-type box with no debounce would write three
      // permanent audit objects per keystroke, forever — this must not have
      // fired yet.
      expect(listSecrets).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(299);
      expect(listSecrets).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      expect(listSecrets).toHaveBeenCalledTimes(1);
      expect(listSecrets).toHaveBeenCalledWith(
        expect.objectContaining({ environment: "dev", q: "stripe" }),
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("restores a search carried back from secret detail", async () => {
    const listSecrets = vi.fn(async (): Promise<CatalogPage> => ({
      secrets: [secretFixture()],
      generatedAt: "2026-08-23T00:00:00.000Z",
    }));

    await mountCatalog(
      defaultApi({ listSecrets }),
      { env: "dev" },
      { catalogFilter: "stripe" },
    );

    expect(listSecrets).toHaveBeenCalledWith(
      expect.objectContaining({ environment: "dev", q: "stripe" }),
    );
  });

  it("renders the results of a completed search, spanning the whole environment", async () => {
    vi.useFakeTimers();
    try {
      const api = defaultApi({
        listSecrets: async () => ({
          secrets: [secretFixture()],
          generatedAt: "2026-08-23T00:00:00.000Z",
        }),
      });
      const { wrapper } = await mountCatalog(api);

      await searchInput(wrapper).setValue("stripe");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      expect(wrapper.text()).toContain("stripe-api-key");
      // Search is environment-wide, not scoped to the folder being browsed —
      // this must be visible, not a silent behind-the-scenes widening.
      expect(wrapper.text()).toContain("Showing search results across all of");
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders the incomplete-results warning when the server truncated the search", async () => {
    vi.useFakeTimers();
    try {
      const api = defaultApi({
        listSecrets: async () => ({
          secrets: [secretFixture()],
          truncated: true,
          generatedAt: "2026-08-23T00:00:00.000Z",
        }),
      });
      const { wrapper } = await mountCatalog(api);

      await searchInput(wrapper).setValue("stripe");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      expect(wrapper.text()).toContain("incomplete");
    } finally {
      vi.useRealTimers();
    }
  });

  it("says plainly that there are no matches", async () => {
    vi.useFakeTimers();
    try {
      const { wrapper } = await mountCatalog(
        defaultApi({ listSecrets: async () => emptyCatalogPage }),
      );

      await searchInput(wrapper).setValue("no-such-secret");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      // Unlike the browse path, a `q` response is bounded-complete on the
      // first request — there is no cursor left to chase — so there is no
      // ambiguity to hedge about here.
      expect(wrapper.text()).toContain('No matches for "no-such-secret"');
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns to tree browsing once the query is cleared", async () => {
    vi.useFakeTimers();
    try {
      const api = defaultApi({
        listSecrets: async () => ({
          secrets: [secretFixture()],
          generatedAt: "2026-08-23T00:00:00.000Z",
        }),
      });
      const { wrapper } = await mountCatalog(api);
      const input = searchInput(wrapper);

      await input.setValue("stripe");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();
      expect(wrapper.text()).toContain("Showing search results across all of");

      await input.setValue("");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      expect(wrapper.text()).not.toContain(
        "Showing search results across all of",
      );
      expect(wrapper.text()).toContain("Nothing directly at this path.");
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns to browsing immediately when the query is cleared", async () => {
    vi.useFakeTimers();
    try {
      const listSecrets = vi.fn(
        async (): Promise<CatalogPage> => emptyCatalogPage,
      );
      const { wrapper } = await mountCatalog(defaultApi({ listSecrets }));

      await searchInput(wrapper).setValue("stripe");
      await vi.advanceTimersByTimeAsync(300);
      expect(listSecrets).toHaveBeenCalledTimes(1);

      // Clearing issues no request, so it must not sit behind the debounce.
      await searchInput(wrapper).setValue("");
      await flushPromises();
      expect(wrapper.text()).not.toContain("No matches");
      expect(listSecrets).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("SecretsCatalog smart search composition", () => {
  const searchInput = (
    wrapper: Awaited<ReturnType<typeof mountCatalog>>["wrapper"],
  ) => wrapper.find("#catalog-filter");

  it("issues one request carrying both q and tags once mixed input settles", async () => {
    vi.useFakeTimers();
    try {
      const listSecrets = vi.fn(
        async (): Promise<CatalogPage> => emptyCatalogPage,
      );
      const { wrapper } = await mountCatalog(defaultApi({ listSecrets }));

      await searchInput(wrapper).setValue("owner:payments stripe");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      expect(listSecrets).toHaveBeenCalledTimes(1);
      expect(listSecrets).toHaveBeenCalledWith(
        expect.objectContaining({
          environment: "dev",
          q: "stripe",
          tags: "owner:payments",
        }),
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows the interpretation of mixed input immediately, without waiting for the debounce", async () => {
    const { wrapper } = await mountCatalog(defaultApi());

    await searchInput(wrapper).setValue("owner:payments stripe");
    await flushPromises();

    expect(wrapper.text()).toContain("owner=payments");
    expect(wrapper.text()).toContain('matching "stripe"');
  });

  it("shows the service's tag-filter rejection inline instead of the generic error notice", async () => {
    vi.useFakeTimers();
    try {
      const listSecrets = vi.fn(async (): Promise<CatalogPage> => {
        throw new ApiError(
          400,
          "bad_request",
          "tags contains a duplicate key.",
        );
      });
      const { wrapper } = await mountCatalog(defaultApi({ listSecrets }));

      await searchInput(wrapper).setValue("owner:payments owner:billing");
      await vi.advanceTimersByTimeAsync(300);
      await flushPromises();

      expect(wrapper.text()).toContain("tags contains a duplicate key.");
      expect(wrapper.text()).not.toContain("The request failed.");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("SecretsCatalog folder prefix", () => {
  const clickButtonNamed = async (
    wrapper: Awaited<ReturnType<typeof mountCatalog>>["wrapper"],
    text: string,
  ): Promise<void> => {
    const button = wrapper.findAll("button").find((b) => b.text() === text);
    expect(button).toBeDefined();
    await button?.trigger("click");
  };

  it("takes a new folder to a prefixed secret form without calling the API", async () => {
    const { wrapper, router } = await mountCatalog(defaultApi(), {
      env: "dev",
      path: ["payments"],
    });

    await clickButtonNamed(wrapper, "New folder");
    await wrapper.find('input[placeholder="invoices"]').setValue("archived");
    await clickButtonNamed(wrapper, "Create secret here");
    await flushPromises();

    expect(router.currentRoute.value.fullPath).toBe(
      "/e/dev/secrets/new?path=payments/archived",
    );
  });

  it("explains that an empty folder is not persisted", async () => {
    const { wrapper } = await mountCatalog(defaultApi());

    await clickButtonNamed(wrapper, "New folder");
    expect(wrapper.text()).toContain("empty folders are not stored");
  });

  it("does not offer to delete derived folders", async () => {
    const { wrapper } = await mountCatalog(
      defaultApi({
        getSecretsTree: async () => ({
          ...emptyTreePage,
          folders: [
            {
              segment: "derived-only",
              path: "derived-only",
              secretCount: 3,
              kind: "derived",
            },
            {
              segment: "other",
              path: "other",
              secretCount: 2,
              kind: "derived",
            },
          ],
        }),
      }),
    );

    expect(
      wrapper.findAll("button").find((b) => b.text() === "Delete"),
    ).toBeUndefined();
  });
});
