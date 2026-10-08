import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import {
  HemligClient,
  HemligError,
  type AgentSyncEntry,
  type AgentConfig,
} from "@hemlig/client";
import { HemligV1BetaController } from "./v1beta";

type Resource = {
  metadata: {
    name: string;
    namespace: string;
    generation: number;
    uid: string;
  };
  spec: Record<string, any>;
  status?: Record<string, any>;
};
const meta = (name: string) => ({
  name,
  namespace: "ns",
  generation: 1,
  uid: `resource-${name}`,
});
const fixture = (t: TestContext) => {
  const consumer: Resource = {
    metadata: meta("consumer"),
    spec: {
      providerRef: "provider",
      identity: { secretName: "identity" },
      bootstrapTokenRef: { name: "bootstrap", key: "token" },
    },
  };
  const imports: Resource[] = ["a", "b"].map((name) => ({
    metadata: meta(`import-${name}`),
    spec: { consumerRef: "consumer", secretId: name, deletionPolicy: "Retain" },
  }));
  const exporter: Resource = {
    metadata: meta("export"),
    spec: {
      consumerRef: "consumer",
      secretId: "export",
      source: { name: "source" },
      metadata: {},
    },
  };
  const config: AgentConfig = {
    consumerId: "agent",
    environment: "prod",
    grant: {
      grantId: "grant",
      capabilities: ["read", "write"],
      secretGrants: [
        { secretId: "a", secretUid: "uid-a", permissions: ["read"] },
        { secretId: "b", secretUid: "uid-b", permissions: ["read"] },
        { secretId: "export", secretUid: "uid-export", permissions: ["write"] },
      ],
    },
    mqtt: { endpoint: "iot.test", clientId: "agent", topic: "topic" },
  };
  const records = new Map<string, AgentSyncEntry>(
    ["a", "b", "export"].map((name) => [
      name,
      {
        secretId: name,
        secretUid: `uid-${name}`,
        controlVersionId: `ctl-${name}-1`,
        payloadVersionId: `pay-${name}-1`,
        state: "ACTIVE",
        permissions: name === "export" ? ["write"] : ["read"],
        ...(name === "export" ? { metadata: {} } : {}),
      },
    ]),
  );
  const secrets = new Map<string, any>([
    [
      "identity",
      {
        metadata: {
          labels: { "hemlig.io/managed-by": "consumer" },
          annotations: { "hemlig.io/consumer-owner": "ns/consumer" },
        },
        data: {
          "tls.crt": Buffer.from("fixture").toString("base64"),
          "tls.key": Buffer.from("fixture").toString("base64"),
        },
      },
    ],
    [
      "source",
      { metadata: {}, data: { value: "Zml4dHVyZQ==" }, type: "Opaque" },
    ],
  ]);
  let changes: AgentSyncEntry[] = [];
  let checkpoint = "checkpoint-1";
  let failApply = false;
  let failCheckpoint = false;
  let requireReset = false;
  const sync = t.mock.method(
    HemligClient.prototype,
    "syncAgent",
    async (query: { syncCursor?: string; cursor?: string } = {}) => {
      if (requireReset && query.syncCursor !== undefined) {
        requireReset = false;
        throw new HemligError(410, "sync_reset_required");
      }
      return {
        config,
        snapshot: query.syncCursor === undefined,
        changes:
          query.syncCursor === undefined ? [...records.values()] : changes,
        syncCursor: checkpoint,
      };
    },
  );
  const payload = t.mock.method(
    HemligClient.prototype,
    "getAgentSecret",
    async (name: string, ifNoneMatch?: string) => {
      const entry = records.get(name);
      if (entry === undefined) throw new HemligError(404, "missing");
      if (entry.controlVersionId === ifNoneMatch) return undefined;
      return {
        secretId: name,
        controlVersionId: entry.controlVersionId,
        payloadVersionId: entry.payloadVersionId!,
        payload: {
          value: { encoding: "base64" as const, value: "Zml4dHVyZQ==" },
        },
      };
    },
  );
  const control = t.mock.method(
    HemligClient.prototype,
    "getAgentControl",
    async (name: string) => {
      const entry = records.get(name)!;
      return { ...entry, environment: "prod", metadata: entry.metadata ?? {} };
    },
  );
  const configReads = t.mock.method(
    HemligClient.prototype,
    "getAgentConfig",
    async () => {
      throw new Error("configuration polling is forbidden in sync tests");
    },
  );
  let writes = 0;
  const put = t.mock.method(
    HemligClient.prototype,
    "putAgentPayload",
    async (
      name: string,
      ifMatch: string,
      _payload: unknown,
      idempotencyKey: string,
    ) => {
      const entry = records.get(name)!;
      assert.equal(ifMatch, entry.controlVersionId);
      assert.ok(idempotencyKey.length >= 8);
      writes += 1;
      const next = {
        ...entry,
        controlVersionId: `ctl-${name}-${writes + 1}`,
        payloadVersionId: `pay-${name}-${writes + 1}`,
      };
      records.set(name, next);
      return {
        ...next,
        schemaVersion: 1 as const,
        environment: "prod",
        createdAt: "2026-10-07T00:00:00Z",
        createdBy: { type: "consumer" as const, id: "agent" },
        metadata: next.metadata ?? {},
        acl: [],
      };
    },
  );
  const update = t.mock.method(
    HemligClient.prototype,
    "updateAgentSecret",
    async (
      name: string,
      ifMatch: string,
      metadata: object,
      idempotencyKey: string,
    ) => {
      const entry = records.get(name)!;
      assert.equal(ifMatch, entry.controlVersionId);
      assert.ok(idempotencyKey.length >= 8);
      const next = { ...entry, controlVersionId: "ctl-metadata", metadata };
      records.set(name, next);
      return {
        ...next,
        schemaVersion: 1 as const,
        environment: "prod",
        createdAt: "2026-10-07T00:00:00Z",
        createdBy: { type: "consumer" as const, id: "agent" },
        metadata,
        acl: [],
      };
    },
  );
  const core = {
    async readNamespace() {
      return { metadata: { labels: {} } };
    },
    async readNamespacedSecret(input: { name: string }) {
      const value = secrets.get(input.name);
      if (value === undefined)
        throw Object.assign(new Error("missing"), { code: 404 });
      return structuredClone(value);
    },
    async createNamespacedSecret(input: { body: any }) {
      if (failApply)
        throw Object.assign(new Error("unavailable"), { code: 503 });
      secrets.set(input.body.metadata.name, structuredClone(input.body));
    },
    async replaceNamespacedSecret(input: { name: string; body: any }) {
      if (failApply)
        throw Object.assign(new Error("unavailable"), { code: 503 });
      secrets.set(input.name, structuredClone(input.body));
    },
    async deleteNamespacedSecret(input: { name: string }) {
      secrets.delete(input.name);
    },
  };
  const custom = {
    async listClusterCustomObject() {
      return {
        items: [
          {
            metadata: { name: "provider" },
            spec: {
              apiUrl: "https://api.test",
              allowedNamespaces: { matchLabels: {} },
            },
          },
        ],
      };
    },
    async listCustomObjectForAllNamespaces(input: { plural: string }) {
      return {
        items:
          input.plural === "hemligconsumers"
            ? [consumer]
            : input.plural === "hemligsecretimports"
              ? imports
              : input.plural === "hemligsecretexports"
                ? [exporter]
                : [],
      };
    },
    async patchNamespacedCustomObjectStatus(input: {
      plural: string;
      name: string;
      body: any[];
    }) {
      if (
        failCheckpoint &&
        input.plural === "hemligconsumers" &&
        input.body[0].value.syncCursor === "checkpoint-2"
      )
        throw Object.assign(new Error("status unavailable"), { code: 503 });
      const resource =
        input.plural === "hemligconsumers"
          ? consumer
          : input.plural === "hemligsecretexports"
            ? exporter
            : imports.find((value) => value.metadata.name === input.name)!;
      resource.status = structuredClone(input.body[0].value);
    },
  };
  const controller = new HemligV1BetaController(
    core as never,
    custom as never,
    { intervalMilliseconds: 600_000, sourceDebounceMilliseconds: 250 },
  );
  Object.assign(controller, { mqtt: { ensure() {}, stop() {} } });
  t.after(() => {
    const timer = (controller as unknown as { reconcileTimer?: NodeJS.Timeout })
      .reconcileTimer;
    if (timer !== undefined) clearTimeout(timer);
  });
  const counts = () => ({
    sync: sync.mock.callCount(),
    payload: payload.mock.callCount(),
    control: control.mock.callCount(),
    config: configReads.mock.callCount(),
    put: put.mock.callCount(),
    update: update.mock.callCount(),
  });
  return {
    controller,
    core,
    custom,
    consumer,
    imports,
    exporter,
    config,
    records,
    secrets,
    sync,
    payload,
    control,
    put,
    update,
    counts,
    change: (entries: AgentSyncEntry[]) => {
      changes = entries;
      checkpoint = "checkpoint-2";
    },
    failApply: () => {
      failApply = true;
    },
    failCheckpoint: () => {
      failCheckpoint = true;
    },
    reset: () => {
      requireReset = true;
    },
  };
};

test("unchanged multi-resource passes make one sync call and no payload/control/config reads", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
  const before = f.counts();
  await f.controller.reconcileAll();
  const after = f.counts();
  assert.deepEqual(after, { ...before, sync: before.sync + 1 });
  assert.equal(
    f.sync.mock.calls.at(-1)?.arguments[0]?.syncCursor,
    "checkpoint-1",
  );
});

test("a changed index entry fetches only its affected import", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  const next = {
    ...f.records.get("a")!,
    controlVersionId: "ctl-a-next",
    payloadVersionId: "pay-a-next",
  };
  f.records.set("a", next);
  f.change([next]);
  await f.controller.reconcileAll();
  assert.deepEqual(f.counts(), {
    ...before,
    sync: before.sync + 1,
    payload: before.payload + 1,
  });
  assert.equal(f.imports[0]?.status?.controlVersionId, "ctl-a-next");
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-2");
});

test("restart reuses a persisted checkpoint without rereading unchanged secrets", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  const restarted = new HemligV1BetaController(
    f.core as never,
    f.custom as never,
    { intervalMilliseconds: 600_000, sourceDebounceMilliseconds: 250 },
  );
  Object.assign(restarted, { mqtt: { ensure() {}, stop() {} } });
  await restarted.reconcileAll();
  assert.deepEqual(f.counts(), { ...before, sync: before.sync + 1 });
});

test("missing or tampered targets fetch authoritative data despite an empty delta", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  f.secrets.delete("import-a");
  f.secrets.get("import-b").data = { value: "dGFtcGVyZWQ=" };
  await f.controller.reconcileAll();
  assert.deepEqual(f.counts(), {
    ...before,
    sync: before.sync + 1,
    payload: before.payload + 2,
  });
  assert.equal(f.secrets.get("import-b").data.value, "Zml4dHVyZQ==");
});

test("revocation deletes an owned target even with Retain without fetching a payload", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  f.change([{ ...f.records.get("a")!, state: "REVOKED", permissions: [] }]);
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), false);
  assert.equal(f.secrets.has("import-b"), true);
  assert.equal(f.counts().payload, before.payload);
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-2");
});

test("grant removal resets synchronization and deletes the removed mirror", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  (
    f.config.grant as { secretGrants: typeof f.config.grant.secretGrants }
  ).secretGrants = f.config.grant.secretGrants.filter(
    (entry) => entry.secretId !== "a",
  );
  f.records.delete("a");
  f.reset();
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), false);
  assert.equal(f.counts().sync, before.sync + 2);
  assert.equal(f.counts().payload, before.payload);
});

test("local export drift preserves the authoritative If-Match and changes only its export", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  f.secrets.get("source").data = { value: "bmV3" };
  await f.controller.reconcileAll();
  assert.deepEqual(f.counts(), {
    ...before,
    sync: before.sync + 1,
    control: before.control + 1,
    put: before.put + 1,
  });
});

test("metadata changes do not rewrite an unchanged exported payload", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const before = f.counts();
  f.exporter.spec.metadata = { description: "updated" };
  f.exporter.metadata.generation += 1;
  await f.controller.reconcileAll();
  assert.deepEqual(f.counts(), {
    ...before,
    sync: before.sync + 1,
    control: before.control + 1,
    update: before.update + 1,
  });
});

test("failed target application never advances the completed checkpoint", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  const next = { ...f.records.get("a")!, controlVersionId: "changed" };
  f.records.set("a", next);
  f.change([next]);
  f.failApply();
  await f.controller.reconcileAll();
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
});

test("failed checkpoint status publication retains the old checkpoint", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  f.change([]);
  f.failCheckpoint();
  await assert.rejects(f.controller.reconcileAll());
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
});

test("a missing bootstrap index entry is verified rather than treated as revoked", async (t) => {
  const f = fixture(t);
  const sync = t.mock.method(HemligClient.prototype, "syncAgent", async () => ({
    config: f.config,
    snapshot: true,
    changes: [...f.records.values()].filter((entry) => entry.secretId !== "a"),
    syncCursor: "checkpoint-1",
  }));
  await f.controller.reconcileAll();
  assert.ok(f.secrets.has("import-a"));
  assert.equal(
    f.payload.mock.calls.filter((call) => call.arguments[0] === "a").length,
    1,
  );
  assert.equal(sync.mock.callCount(), 1);
});

test("export conflicts retain the checkpoint and schedule synchronization retry", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  f.change([]);
  f.secrets.get("source").data = { value: "bmV3" };
  t.mock.method(HemligClient.prototype, "putAgentPayload", async () => {
    throw new HemligError(412, "precondition_failed");
  });
  await f.controller.reconcileAll();
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
  assert.ok(
    (f.controller as unknown as { reconcileTimer?: NodeJS.Timeout })
      .reconcileTimer,
  );
});

test("an empty active grant revokes imports and exporters and can commit its checkpoint", async (t) => {
  const f = fixture(t);
  await f.controller.reconcileAll();
  (
    f.config.grant as {
      secretGrants: typeof f.config.grant.secretGrants;
      capabilities: typeof f.config.grant.capabilities;
    }
  ).secretGrants = [];
  (
    f.config.grant as { capabilities: typeof f.config.grant.capabilities }
  ).capabilities = [];
  f.change([]);
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), false);
  assert.equal(f.secrets.has("import-b"), false);
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-2");
});

test("removing cross-namespace opt-in deletes the formerly permitted owned mirror", async (t) => {
  const f = fixture(t);
  f.consumer.spec.allowCrossNamespaceReferences = true;
  f.imports[0]!.metadata.namespace = "other";
  f.imports[0]!.spec.consumerNamespace = "ns";
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), true);
  const before = f.counts();
  f.consumer.spec.allowCrossNamespaceReferences = false;
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), false);
  assert.deepEqual(f.counts(), { ...before, sync: before.sync + 1 });
});

test("unrelated Secret events do not schedule a sync while referenced source drift does", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(t);
  const watches: {
    path: string;
    event: (phase: string, object: unknown) => void;
  }[] = [];
  Object.assign(f.controller, {
    watch: {
      async watch(
        path: string,
        _query: unknown,
        event: (phase: string, object: unknown) => void,
      ) {
        watches.push({ path, event });
        return new AbortController();
      },
    },
  });
  const abort = new AbortController();
  const running = f.controller.run(abort.signal);
  const settle = async () => {
    for (let i = 0; i < 150; i += 1) await Promise.resolve();
  };
  await settle();
  const secretWatch = watches.find((watch) => watch.path === "/api/v1/secrets");
  assert.ok(secretWatch);
  const before = f.counts();
  secretWatch.event("MODIFIED", {
    metadata: { name: "unrelated", namespace: "ns", resourceVersion: "1" },
  });
  t.mock.timers.tick(250);
  await settle();
  assert.deepEqual(f.counts(), before);
  secretWatch.event("MODIFIED", {
    metadata: { name: "source", namespace: "ns", resourceVersion: "2" },
  });
  t.mock.timers.tick(250);
  await settle();
  assert.deepEqual(f.counts(), { ...before, sync: before.sync + 1 });
  abort.abort();
  await running;
});
