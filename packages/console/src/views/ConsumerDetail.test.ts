import { QueryClient, VueQueryPlugin } from "@tanstack/vue-query";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it, vi } from "vitest";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import type {
  AgentGrant,
  ConsumerDetail as ConsumerDetailModel,
  ConsumerSecretGrantPage,
  ControlRevision,
} from "../api/schemas";
import { useAppStore } from "../stores/app";
import ConsumerDetail from "./ConsumerDetail.vue";

interface FakeApi {
  getConsumer: (consumerId: string) => Promise<ConsumerDetailModel>;
  listApiIdentities: (consumerId: string) => Promise<{
    consumerId: string;
    environment: string;
    apiIdentities: [];
    generatedAt: string;
  }>;
  listConsumerSecretGrants: (
    consumerId: string,
    cursor?: string,
  ) => Promise<ConsumerSecretGrantPage>;
  revokeConsumerSecretGrant: (
    consumerId: string,
    secretId: string,
    idempotencyKey: string,
  ) => Promise<ControlRevision>;
  updateAgentGrant: (
    grantId: string,
    input: {
      capabilities: readonly ("read" | "write")[];
      secretGrants: readonly {
        secretId: string;
        permissions: readonly ("read" | "write")[];
      }[];
      displayName?: string;
    },
  ) => Promise<AgentGrant>;
}

const consumer = (): ConsumerDetailModel => ({
  consumerId: "prod-east",
  environment: "prod",
  status: "ACTIVE",
  subjectUri: "spiffe://hemlig/consumer/prod-east",
  createdAt: "2026-08-25T00:00:00.000Z",
});

const revision = (): ControlRevision => ({
  schemaVersion: 1,
  secretUid: "sec-postgres",
  secretId: "platform/database/postgres",
  controlVersionId: "ctl-revoked",
  environment: "prod",
  state: "ACTIVE",
  createdAt: "2026-08-25T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: {},
  acl: [],
});

const agentGrant = (): AgentGrant => ({
  grantId: "grant-prod-east",
  consumerId: "prod-east",
  environment: "prod",
  capabilities: ["read", "write"],
  secretGrants: [
    {
      secretId: "platform/database/postgres",
      secretUid: "sec-postgres",
      permissions: ["read", "write"],
    },
  ],
  displayName: "Production east",
  status: "ACTIVE",
  createdAt: "2026-08-25T00:00:00.000Z",
});

const buildRouter = (): Router =>
  createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: "/e/:env/consumers",
        name: "consumers",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/consumers/:consumerId",
        name: "consumer",
        component: { template: "<div/>" },
      },
      {
        path: "/e/:env/secrets/:secretId",
        name: "secret",
        component: { template: "<div/>" },
      },
    ],
  });

const mountView = async (
  api: FakeApi,
): Promise<{ wrapper: ReturnType<typeof mount> }> => {
  const pinia = createPinia();
  setActivePinia(pinia);
  const store = useAppStore();
  store.api = api as unknown as ReturnType<typeof store.requireApi>;
  const router = buildRouter();
  await router.push({
    name: "consumer",
    params: { env: "prod", consumerId: "prod-east" },
  });
  await router.isReady();
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = mount(ConsumerDetail, {
    props: { env: "prod", consumerId: "prod-east" },
    global: {
      plugins: [pinia, router, [VueQueryPlugin, { queryClient }]],
      stubs: { RouterLink: false },
    },
  });
  await flushPromises();
  return { wrapper };
};

describe("ConsumerDetail secret access", () => {
  it("lists grants and revokes the selected secret after confirmation", async () => {
    const listConsumerSecretGrants = vi.fn(async () => ({
      consumerId: "prod-east",
      environment: "prod",
      grants: [
        {
          secretUid: "sec-postgres",
          secretId: "platform/database/postgres",
          permissions: ["read" as const],
          controlVersionId: "ctl-postgres",
          state: "ACTIVE" as const,
        },
      ],
      generatedAt: "2026-08-25T00:00:00.000Z",
    }));
    const revokeConsumerSecretGrant = vi.fn(async () => revision());
    const { wrapper } = await mountView({
      getConsumer: async () => consumer(),
      listApiIdentities: async () => ({
        consumerId: "prod-east",
        environment: "prod",
        apiIdentities: [],
        generatedAt: "2026-08-25T00:00:00.000Z",
      }),
      listConsumerSecretGrants,
      revokeConsumerSecretGrant,
      updateAgentGrant: async () => agentGrant(),
    });

    expect(wrapper.text()).toContain("platform/database/postgres");
    await wrapper
      .get(
        '[aria-label="Revoke read permission for platform/database/postgres"]',
      )
      .trigger("click");
    const dialog = wrapper.get('[role="dialog"]');
    expect(dialog.text()).toContain("Revoke this permission?");
    await dialog
      .findAll("button")
      .find((button) => button.text() === "Revoke")
      ?.trigger("click");
    await flushPromises();

    expect(revokeConsumerSecretGrant).toHaveBeenCalledWith(
      "prod-east",
      "platform/database/postgres",
      expect.any(String),
    );
    expect(listConsumerSecretGrants).toHaveBeenCalledTimes(2);
  });

  it("revokes only the selected AgentGrant permission", async () => {
    const updateAgentGrant = vi.fn(async () => ({
      ...agentGrant(),
      capabilities: ["write" as const],
      secretGrants: [
        {
          secretId: "platform/database/postgres",
          secretUid: "sec-postgres",
          permissions: ["write" as const],
        },
      ],
    }));
    const { wrapper } = await mountView({
      getConsumer: async () => ({ ...consumer(), agentGrant: agentGrant() }),
      listApiIdentities: async () => ({
        consumerId: "prod-east",
        environment: "prod",
        apiIdentities: [],
        generatedAt: "2026-08-25T00:00:00.000Z",
      }),
      listConsumerSecretGrants: async () => ({
        consumerId: "prod-east",
        environment: "prod",
        grants: [],
        generatedAt: "2026-08-25T00:00:00.000Z",
      }),
      revokeConsumerSecretGrant: async () => revision(),
      updateAgentGrant,
    });

    expect(wrapper.text()).toContain("Canonical exact permissions");
    await wrapper
      .get(
        '[aria-label="Revoke read permission for platform/database/postgres"]',
      )
      .trigger("click");
    const dialog = wrapper.get('[role="dialog"]');
    expect(dialog.text()).toContain("Revoke this permission?");
    await dialog
      .findAll("button")
      .find((button) => button.text() === "Revoke")
      ?.trigger("click");
    await flushPromises();

    expect(updateAgentGrant).toHaveBeenCalledWith("grant-prod-east", {
      capabilities: ["write"],
      secretGrants: [
        {
          secretId: "platform/database/postgres",
          permissions: ["write"],
        },
      ],
      displayName: "Production east",
    });
  });
});
