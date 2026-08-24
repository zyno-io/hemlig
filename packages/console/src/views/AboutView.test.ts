import { mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it } from "vitest";
import { useAppStore } from "../stores/app";
import AboutView from "./AboutView.vue";

describe("AboutView", () => {
  it("prefers the OIDC email over the opaque subject for display", () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const store = useAppStore();
    store.adoptSession({
      subject: "opaque-stable-subject",
      email: "admin@example.test",
    });

    const wrapper = mount(AboutView, { global: { plugins: [pinia] } });

    expect(wrapper.text()).toContain("admin@example.test");
    expect(wrapper.text()).toContain("opaque-stable-subject");
  });
});
