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
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
});

const mountAt = async (query: string) => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.adoptSession({ subject: "sub-1", email: "admin@example.test" });
  store.config = {
    deploymentName: "d",
    adminApiUrl: "https://admin.example.test/",
    auth: {
      mode: "oidc",
      authority: "https://login.example.com",
      clientId: "c",
      scopes: ["s"],
    },
  };
  const accessToken = vi
    .spyOn(store, "accessToken")
    .mockResolvedValue("hdr.body.sig");
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/cli-login", component: CliLogin }],
  });
  await router.push(`/cli-login?${query}`);
  await router.isReady();
  const wrapper = mount(CliLogin, { global: { plugins: [pinia, router] } });
  await flushPromises();
  // The confirmation code comes from crypto.subtle, which settles on a later
  // event-loop turn than flushPromises reaches. setImmediate is not faked.
  const codeEl = () => wrapper.find('[data-testid="confirmation-code"]');
  for (
    let i = 0;
    i < 100 && codeEl().exists() && codeEl().text() === "…";
    i++
  ) {
    await new Promise((resolve) => setImmediate(resolve));
    await flushPromises();
  }
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
    expect(wrapper.text()).toContain(
      "Authorize the Hemlig CLI on this computer?",
    );
    expect(wrapper.text()).toContain("127.0.0.1:40000");
    expect(wrapper.text()).toContain("admin@example.test");
    expect(wrapper.text()).toContain("full administrator access");
    expect(wrapper.text()).toContain(
      "Only authorize if this matches the code in your terminal.",
    );
    expect(wrapper.get('[data-testid="confirmation-code"]').text()).toBe(
      await confirmationCode(goodState),
    );
  });

  it("does not arm while the window lacks focus", async () => {
    vi.mocked(document.hasFocus).mockReturnValue(false);
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    const button = wrapper
      .findAll("button")
      .find((b) => b.text() === "Authorize")!;
    await vi.advanceTimersByTimeAsync(5000);
    expect(button.attributes("disabled")).toBeDefined();
    vi.mocked(document.hasFocus).mockReturnValue(true);
    window.dispatchEvent(new Event("focus"));
    await arm();
    expect(button.attributes("disabled")).toBeUndefined();
  });

  it("disarms on window blur and re-arms 1.5 s after focus", async () => {
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    const button = wrapper
      .findAll("button")
      .find((b) => b.text() === "Authorize")!;
    await arm();
    expect(button.attributes("disabled")).toBeUndefined();
    window.dispatchEvent(new Event("blur"));
    await flushPromises();
    expect(button.attributes("disabled")).toBeDefined();
    await vi.advanceTimersByTimeAsync(5000);
    expect(button.attributes("disabled")).toBeDefined();
    window.dispatchEvent(new Event("focus"));
    await vi.advanceTimersByTimeAsync(1400);
    expect(button.attributes("disabled")).toBeDefined();
    await vi.advanceTimersByTimeAsync(200);
    expect(button.attributes("disabled")).toBeUndefined();
  });

  it("derives the same confirmation code as the CLI for a fixed state", async () => {
    // Vector shared with packages/cli/src/login.test.ts.
    expect(await confirmationCode("A".repeat(43))).toBe("1W07-71DP");
  });

  it("keeps Authorize disabled for 1.5 s and ignores early clicks", async () => {
    const submit = vi
      .spyOn(HTMLFormElement.prototype, "submit")
      .mockImplementation(() => {});
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    const button = wrapper
      .findAll("button")
      .find((b) => b.text() === "Authorize")!;
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
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(function (
      this: HTMLFormElement,
    ) {
      submitted = this;
    });
    const { wrapper, accessToken } = await mountAt(
      `port=40000&state=${goodState}`,
    );
    await arm();
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "Authorize")!
      .trigger("click");
    await flushPromises();

    expect(accessToken).toHaveBeenCalledWith(5 * 60 * 1000);
    expect(submitted).toBeDefined();
    expect(submitted!.method).toBe("post");
    expect(submitted!.getAttribute("action")).toBe(
      "http://127.0.0.1:40000/callback",
    );
    expect(submitted!.enctype).toBe("application/x-www-form-urlencoded");
    const fields = Object.fromEntries(new FormData(submitted!).entries());
    expect(fields).toEqual({
      access_token: "hdr.body.sig",
      state: goodState,
    });
  });

  it("shows an error and posts nothing when no token is available", async () => {
    const submit = vi
      .spyOn(HTMLFormElement.prototype, "submit")
      .mockImplementation(() => {});
    const { wrapper, accessToken } = await mountAt(
      `port=40000&state=${goodState}`,
    );
    accessToken.mockResolvedValue(undefined);
    await arm();
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "Authorize")!
      .trigger("click");
    await flushPromises();
    expect(submit).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("Could not authorize");
  });

  it("Cancel posts nothing and shows Cancelled", async () => {
    const submit = vi
      .spyOn(HTMLFormElement.prototype, "submit")
      .mockImplementation(() => {});
    const { wrapper } = await mountAt(`port=40000&state=${goodState}`);
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "Cancel")!
      .trigger("click");
    expect(wrapper.text()).toContain("Cancelled");
    expect(submit).not.toHaveBeenCalled();
    expect(wrapper.findAll("button")).toHaveLength(0);
  });

  describe("mode=code", () => {
    for (const query of [
      `mode=code&state=short`,
      `mode=code`,
      `mode=code&port=40000&state=${goodState}`,
      `mode=other&state=${goodState}`,
      `mode=other&port=40000&state=${goodState}`,
    ]) {
      it(`is invalid for ${query.slice(0, 40)}`, async () => {
        const { wrapper } = await mountAt(query);
        expect(wrapper.text()).toContain("invalid");
        expect(wrapper.findAll("button")).toHaveLength(0);
      });
    }

    const authorizeButton = (wrapper: Awaited<ReturnType<typeof mountAt>>["wrapper"]) =>
      wrapper.findAll("button").find((b) => b.text() === "Authorize")!;

    it("is valid with a state and no port and shows the paste target", async () => {
      const { wrapper } = await mountAt(`mode=code&state=${goodState}`);
      expect(wrapper.text()).toContain("Paste into terminal");
      expect(wrapper.text()).not.toContain("127.0.0.1");
      expect(wrapper.get('[data-testid="confirmation-code"]').text()).toBe(
        await confirmationCode(goodState),
      );
      expect(wrapper.text()).toContain("admin@example.test");
    });

    it("stays disarmed before 1.5 s and reveals nothing on an early click", async () => {
      const { wrapper, accessToken } = await mountAt(`mode=code&state=${goodState}`);
      const button = authorizeButton(wrapper);
      await button.trigger("click");
      await vi.advanceTimersByTimeAsync(1400);
      expect(button.attributes("disabled")).toBeDefined();
      await button.trigger("click");
      expect(accessToken).not.toHaveBeenCalled();
      expect(wrapper.find("textarea").exists()).toBe(false);
    });

    it("reveals hemlig1.<state>.<token> without any form or network call, then copies and hides", async () => {
      const submit = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
      const { wrapper, accessToken } = await mountAt(`mode=code&state=${goodState}`);
      await arm();
      await authorizeButton(wrapper).trigger("click");
      await flushPromises();
      expect(accessToken).toHaveBeenCalledWith(5 * 60 * 1000);
      const area = wrapper.get("textarea");
      expect(area.element.value).toBe(`hemlig1.${goodState}.hdr.body.sig`);
      expect(area.attributes("readonly")).toBeDefined();
      expect(wrapper.text()).toContain("full administrator access");
      expect(wrapper.text()).toContain(await confirmationCode(goodState));
      expect(submit).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(document.querySelector("form")).toBeNull();

      await wrapper.findAll("button").find((b) => b.text() === "Copy")!.trigger("click");
      await flushPromises();
      expect(writeText).toHaveBeenCalledWith(`hemlig1.${goodState}.hdr.body.sig`);

      await wrapper.findAll("button").find((b) => b.text() === "Hide")!.trigger("click");
      expect(wrapper.find("textarea").exists()).toBe(false);
      expect(wrapper.html()).not.toContain("hdr.body.sig");
      vi.unstubAllGlobals();
    });

    it("tells the user to copy manually when the clipboard write fails", async () => {
      const writeText = vi.fn().mockRejectedValue(new Error("denied"));
      Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
      const { wrapper } = await mountAt(`mode=code&state=${goodState}`);
      await arm();
      await authorizeButton(wrapper).trigger("click");
      await flushPromises();
      await wrapper.findAll("button").find((b) => b.text() === "Copy")!.trigger("click");
      await flushPromises();
      expect(wrapper.text()).toContain("copy it manually");
    });

    it("clears the revealed code after 5 minutes", async () => {
      const { wrapper } = await mountAt(`mode=code&state=${goodState}`);
      await arm();
      await authorizeButton(wrapper).trigger("click");
      await flushPromises();
      expect(wrapper.find("textarea").exists()).toBe(true);
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 10);
      expect(wrapper.find("textarea").exists()).toBe(false);
    });
  });
});
