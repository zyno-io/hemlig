import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter } from "vue-router";
import { useAppStore } from "../stores/app";
import { confirmationCode } from "../auth/confirmationCode";
import CliLogin from "./CliLogin.vue";

const goodState = "A".repeat(43);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

const mountAt = async (query: string) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.adoptSession({ subject: "sub-1", email: "admin@example.test" });
  store.config = {
    deploymentName: "d",
    adminApiUrl: "https://admin.example.test/",
    auth: { mode: "oidc", authority: "https://login.example.com", clientId: "c", scopes: ["s"] },
  };
  const accessToken = vi.spyOn(store, "accessToken").mockResolvedValue("hdr.body.sig");
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/cli-login", component: CliLogin }],
  });
  await router.push(`/cli-login?${query}`);
  await router.isReady();
  const wrapper = mount(CliLogin, { global: { plugins: [pinia, router] } });
  await flushPromises();
  return { wrapper, accessToken };
};

const arm = async (): Promise<void> => {
  await vi.advanceTimersByTimeAsync(1500);
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

describe("CliLogin", () => {
  for (const query of [
    `port=80&state=${goodState}`,
    `port=70000&state=${goodState}`,
    `port=abc&state=${goodState}`,
    `port=40000&state=short`,
    `port=40000&state=${"!".repeat(40)}`,
    `state=${goodState}`,
    `port=40000`,
  ]) {
    it(`shows an error and no Authorize button for ${query.slice(0, 30)}`, async () => {
      const { wrapper } = await mountAt(query);
      expect(wrapper.text()).toContain("invalid");
      expect(wrapper.findAll("button")).toHaveLength(0);
    });
  }

  it("shows the target, account and warning for a valid link", async () => {
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    expect(wrapper.text()).toContain("Authorize the Hemlig CLI on this computer?");
    expect(wrapper.text()).toContain("127.0.0.1:40000");
    expect(wrapper.text()).toContain("admin@example.test");
    expect(wrapper.text()).toContain("full administrator access");
    expect(wrapper.text()).toContain("Only authorize if this matches the code in your terminal.");
    expect(wrapper.get('[data-testid="confirmation-code"]').text()).toBe(
      await confirmationCode(goodState),
    );
  });

  it("derives the same confirmation code as the CLI for a fixed state", async () => {
    // Vector shared with packages/cli/src/login.test.ts.
    expect(await confirmationCode("A".repeat(43))).toBe("1W07-71DP");
  });

  it("keeps Authorize disabled for 1.5 s and ignores early clicks", async () => {
    const submit = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    const button = wrapper.findAll("button").find((b) => b.text() === "Authorize")!;
    expect(button.attributes("disabled")).toBeDefined();
    await button.trigger("click");
    await vi.advanceTimersByTimeAsync(1400);
    expect(button.attributes("disabled")).toBeDefined();
    expect(submit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(200);
    expect(button.attributes("disabled")).toBeUndefined();
  });

  it("Authorize renews if needed and submits a loopback form POST", async () => {
    let submitted: HTMLFormElement | undefined;
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(function (this: HTMLFormElement) {
      submitted = this;
    });
    const { wrapper, accessToken } = await mountAt(`port=40000&state=${goodState}`);
    await arm();
    await wrapper.findAll("button").find((b) => b.text() === "Authorize")!.trigger("click");
    await flushPromises();

    expect(accessToken).toHaveBeenCalledWith(5 * 60 * 1000);
    expect(submitted).toBeDefined();
    expect(submitted!.method).toBe("post");
    expect(submitted!.getAttribute("action")).toBe("http://127.0.0.1:40000/callback");
    expect(submitted!.enctype).toBe("application/x-www-form-urlencoded");
    const fields = Object.fromEntries(new FormData(submitted!).entries());
    expect(fields).toEqual({
      access_token: "hdr.body.sig",
      state: goodState,
      admin_url: "https://admin.example.test",
    });
  });

  it("shows an error and posts nothing when no token is available", async () => {
    const submit = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    const { wrapper, accessToken } = await mountAt(`port=40000&state=${goodState}`);
    accessToken.mockResolvedValue(undefined);
    await arm();
    await wrapper.findAll("button").find((b) => b.text() === "Authorize")!.trigger("click");
    await flushPromises();
    expect(submit).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("Could not authorize");
  });

  it("Cancel posts nothing and shows Cancelled", async () => {
    const submit = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    await wrapper.findAll("button").find((b) => b.text() === "Cancel")!.trigger("click");
    expect(wrapper.text()).toContain("Cancelled");
    expect(submit).not.toHaveBeenCalled();
    expect(wrapper.findAll("button")).toHaveLength(0);
  });
});
