import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import TypedConfirmDialog from "./TypedConfirmDialog.vue";

const mountDialog = (props: { expected?: string; busy?: boolean } = {}) =>
  mount(TypedConfirmDialog, {
    props: {
      title: "Destroy key",
      expected: props.expected ?? "prod-issuing-1",
      confirmLabel: "Destroy key",
      busy: props.busy,
    },
    slots: { default: "<p>This is permanent.</p>" },
    attachTo: document.body,
  });

const confirmButton = (wrapper: ReturnType<typeof mountDialog>) =>
  wrapper.get('[data-testid="typed-confirm-confirm"]');
const type = async (wrapper: ReturnType<typeof mountDialog>, text: string) =>
  wrapper.get('[data-testid="typed-confirm-input"]').setValue(text);

describe("TypedConfirmDialog", () => {
  it("renders the consequences slot and disables autocomplete", () => {
    const wrapper = mountDialog();
    expect(wrapper.text()).toContain("This is permanent.");
    expect(wrapper.get('[data-testid="typed-confirm-input"]').attributes("autocomplete")).toBe("off");
    wrapper.unmount();
  });

  it("enables confirm only on an exact match", async () => {
    const wrapper = mountDialog();
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await type(wrapper, "prod-issuing-");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await type(wrapper, "prod-issuing-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeUndefined();
    wrapper.unmount();
  });

  it("stays disabled for a wrong case or a trailing space", async () => {
    const wrapper = mountDialog();
    await type(wrapper, "Prod-Issuing-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await type(wrapper, "prod-issuing-1 ");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    wrapper.unmount();
  });

  it("emits confirm once", async () => {
    const wrapper = mountDialog();
    await type(wrapper, "prod-issuing-1");
    await confirmButton(wrapper).trigger("click");
    expect(wrapper.emitted("confirm")).toHaveLength(1);
    wrapper.unmount();
  });

  it("does not confirm on Enter until it matches", async () => {
    const wrapper = mountDialog();
    await wrapper.get("form").trigger("submit");
    expect(wrapper.emitted("confirm")).toBeUndefined();
    wrapper.unmount();
  });

  it("cancels on Escape and on Cancel", async () => {
    const wrapper = mountDialog();
    await wrapper.get('[data-testid="typed-confirm-input"]').trigger("keydown.esc");
    await wrapper.get('[data-testid="typed-confirm-cancel"]').trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(2);
    expect(wrapper.emitted("confirm")).toBeUndefined();
    wrapper.unmount();
  });

  it("disables confirm while busy", async () => {
    const wrapper = mountDialog({ busy: true });
    await type(wrapper, "prod-issuing-1");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    await wrapper.get("form").trigger("submit");
    expect(wrapper.emitted("confirm")).toBeUndefined();
    wrapper.unmount();
  });

  it("resets the input when the expected text changes", async () => {
    const wrapper = mountDialog();
    await type(wrapper, "prod-issuing-1");
    await wrapper.setProps({ expected: "prod-issuing-2" });
    const input = wrapper.get('[data-testid="typed-confirm-input"]').element as HTMLInputElement;
    expect(input.value).toBe("");
    expect(confirmButton(wrapper).attributes("disabled")).toBeDefined();
    wrapper.unmount();
  });
});
