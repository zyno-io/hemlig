import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import type { AuditPage } from "../api/schemas";
import { useAppStore } from "../stores/app";
import AuditLog from "./AuditLog.vue";

vi.mock("vue-router", () => ({
  useRoute: () => ({ query: {} }),
}));

const page = (date: string): AuditPage => ({
  date,
  events: [
    {
      eventId: "event-1",
      at: "2026-08-23T10:00:00.000Z",
      correlationId: "corr-1",
      outcome: "succeeded",
      actor: {
        type: "human",
        id: "admin-subject-1",
        email: "admin@example.test",
      },
      operation: "adminget:/v1/admin/secrets",
      target: { secretId: "payments-api" },
      sourceIp: "203.0.113.10",
    },
  ],
  generatedAt: "2026-08-23T10:00:01.000Z",
});

describe("AuditLog", () => {
  it("lists safe evidence for the selected UTC date", async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const store = useAppStore();
    const listAudit = vi.fn(async ({ date }: { date: string }) => page(date));
    store.api = { listAudit } as unknown as ReturnType<typeof store.requireApi>;

    const wrapper = mount(AuditLog, { global: { plugins: [pinia] } });
    await flushPromises();

    const today = new Date().toISOString().slice(0, 10);
    expect(listAudit).toHaveBeenCalledWith({ date: today, cursor: undefined });
    expect(wrapper.text()).toContain("payments-api");
    expect(wrapper.text()).toContain("admin@example.test");
    expect(wrapper.text()).toContain("Admin");
    expect(wrapper.text()).toContain("203.0.113.10");

    await wrapper.find('input[type="date"]').setValue("2026-08-22");
    await flushPromises();
    expect(listAudit).toHaveBeenLastCalledWith({
      date: "2026-08-22",
      cursor: undefined,
    });

    await wrapper
      .find('input[placeholder="All secrets"]')
      .setValue("payments-api");
    await wrapper.find("form").trigger("submit");
    await flushPromises();
    expect(listAudit).toHaveBeenLastCalledWith({
      date: "2026-08-22",
      secretId: "payments-api",
      cursor: undefined,
    });
  });

  it("offers another bounded search when a secret filter skips five pages", async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const store = useAppStore();
    const listAudit = vi.fn(async ({ date }: { date: string }) => ({
      date,
      events: [],
      nextCursor: "more",
      generatedAt: "2026-08-23T10:00:01.000Z",
    }));
    store.api = { listAudit } as unknown as ReturnType<typeof store.requireApi>;

    const wrapper = mount(AuditLog, { global: { plugins: [pinia] } });
    await flushPromises();

    expect(listAudit).toHaveBeenCalledTimes(5);
    expect(wrapper.text()).toContain("More pages may still contain a match.");
    expect(wrapper.findAll("button").map((button) => button.text())).toContain(
      "Load more",
    );
  });
});
