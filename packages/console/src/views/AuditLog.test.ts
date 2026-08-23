import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import type { AuditPage } from "../api/schemas";
import { useAppStore } from "../stores/app";
import AuditLog from "./AuditLog.vue";

const page = (date: string): AuditPage => ({
  date,
  events: [
    {
      eventId: "event-1",
      at: "2026-08-23T10:00:00.000Z",
      correlationId: "corr-1",
      outcome: "succeeded",
      actor: { type: "human", id: "admin-1" },
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
    expect(wrapper.text()).toContain("admin-1");
    expect(wrapper.text()).toContain("203.0.113.10");

    await wrapper.find('input[type="date"]').setValue("2026-08-22");
    await flushPromises();
    expect(listAudit).toHaveBeenLastCalledWith({
      date: "2026-08-22",
      cursor: undefined,
    });
  });
});
