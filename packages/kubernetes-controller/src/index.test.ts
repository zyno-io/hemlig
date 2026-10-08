import assert from "node:assert/strict";
import test from "node:test";
import {
  isOwnedByImport,
  kubernetesDataToPayload,
  payloadChecksum,
  payloadToKubernetesData,
} from "./index";
import {
  allowsConsumerReference,
  consumerReferenceKey,
  HemligV1BetaController,
  isTransientResourceError,
} from "./v1beta";
import { HemligError } from "@zyno-io/hemlig-client";

test("converts UTF-8 and base64 Hemlig entries into Kubernetes Secret data", () => {
  const data = payloadToKubernetesData({
    USERNAME: { encoding: "utf8", value: "service" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
  assert.deepEqual(data, { USERNAME: "c2VydmljZQ==", TOKEN: "AQID" });
  assert.deepEqual(kubernetesDataToPayload(data), {
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
});

test("uses a key-order-independent checksum for exported material", () => {
  const first = payloadChecksum({
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
  const second = payloadChecksum({
    TOKEN: { encoding: "base64", value: "AQID" },
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
  });
  assert.equal(first, second);
});

test("recognizes only the exact import owner", () => {
  const metadata = {
    labels: { "hemlig.io/managed-by": "import" },
    annotations: { "hemlig.io/import-owner": "payments/payments-api" },
  };
  assert.equal(isOwnedByImport(metadata, "payments/payments-api"), true);
  assert.equal(isOwnedByImport(metadata, "payments/other"), false);
});

test("requires an explicit consumer opt-in for a cross-namespace reference", () => {
  assert.equal(consumerReferenceKey("payments", "cluster", "hemlig-system"), "hemlig-system/cluster");
  assert.equal(allowsConsumerReference("payments", "hemlig-system", undefined), false);
  assert.equal(allowsConsumerReference("payments", "hemlig-system", {
    apiVersion: "hemlig.io/v1beta1",
    kind: "HemligConsumer",
    metadata: { name: "cluster", namespace: "hemlig-system" },
    spec: {
      allowCrossNamespaceReferences: true,
      bootstrapTokenRef: { key: "token", name: "bootstrap" },
      identity: { secretName: "identity" },
      providerRef: "staging",
    },
  }), true);
});

test("retries transient Hemlig responses but not denied or invalid resources", () => {
  assert.equal(isTransientResourceError(new HemligError(500, "busy")), true);
  assert.equal(
    isTransientResourceError(new HemligError(409, "conflict")),
    true,
  );
  assert.equal(isTransientResourceError(new HemligError(403, "denied")), false);
  assert.equal(
    isTransientResourceError(new HemligError(412, "precondition_failed")),
    true,
  );
  assert.equal(isTransientResourceError(new HemligError(404, "absent")), false);
});

test("retries only transient Kubernetes API statuses", () => {
  const apiError = (code: number) =>
    Object.assign(new Error(`HTTP-Code: ${code}`), { code });
  assert.equal(isTransientResourceError(apiError(429)), true);
  assert.equal(isTransientResourceError(apiError(409)), true);
  assert.equal(isTransientResourceError(apiError(503)), true);
  assert.equal(isTransientResourceError(apiError(404)), false);
  assert.equal(isTransientResourceError(apiError(403)), false);
  assert.equal(isTransientResourceError(apiError(422)), false);
  assert.equal(
    isTransientResourceError(Object.assign(new Error("reset"), { code: "ECONNRESET" })),
    true,
  );
  assert.equal(isTransientResourceError(new Error("socket hang up")), true);
});

test("backs off exponentially while a reconciliation keeps failing", async () => {
  let listAttempts = 0;
  const custom = {
    async listClusterCustomObject(): Promise<unknown> {
      listAttempts += 1;
      throw new Error("apiserver unavailable");
    },
    async listCustomObjectForAllNamespaces(): Promise<unknown> {
      return { items: [] };
    },
  };
  const controller = new HemligV1BetaController(
    {} as never,
    custom as never,
    {
      intervalMilliseconds: 1,
      sourceDebounceMilliseconds: 1,
      reconcileRetryMilliseconds: 10,
      reconcileRetryMaxMilliseconds: 1_000,
    },
  );
  const abort = new AbortController();
  const running = controller.run(abort.signal);
  await new Promise((resolve) => setTimeout(resolve, 300));
  abort.abort();
  await running;

  // Fixed 10 ms retries would make about 30 attempts in 300 ms; backoff with
  // equal jitter (5-10, 10-20, 20-40, 40-80, 80-160 ms, ...) allows at most 7.
  assert.ok(listAttempts >= 3 && listAttempts <= 7, `attempts: ${listAttempts}`);
});

test("writes reconciliation status as JSON Patch", async () => {
  const statusPatches: unknown[] = [];
  const consumer = {
    apiVersion: "hemlig.io/v1beta1" as const,
    kind: "HemligConsumer" as const,
    metadata: { generation: 1, name: "sentinel", namespace: "hemlig-sentinel" },
    spec: {
      bootstrapTokenRef: { key: "token", name: "bootstrap" },
      identity: { secretName: "identity" },
      providerRef: "missing",
    },
  };
  const custom = {
    async listClusterCustomObject(): Promise<unknown> {
      return { items: [] };
    },
    async listCustomObjectForAllNamespaces(input: { readonly plural: string }): Promise<unknown> {
      return {
        items: input.plural === "hemligconsumers"
          ? [consumer]
          : [],
      };
    },
    async patchNamespacedCustomObjectStatus(input: unknown): Promise<unknown> {
      statusPatches.push(input);
      const patch = input as {
        readonly body: readonly [{ readonly value: Record<string, unknown> }];
      };
      Object.assign(consumer, { status: patch.body[0].value });
      return {};
    },
  };
  const controller = new HemligV1BetaController(
    {} as never,
    custom as never,
    { intervalMilliseconds: 60_000, sourceDebounceMilliseconds: 250 },
  );

  await controller.reconcileAll();
  await controller.reconcileAll();

  assert.equal(statusPatches.length, 1);
  const patch = statusPatches[0] as {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
    readonly body: readonly [{
      readonly op: string;
      readonly path: string;
      readonly value: {
        readonly observedGeneration?: number;
        readonly conditions?: readonly [{
          readonly type: string;
          readonly status: string;
          readonly reason: string;
          readonly message: string;
          readonly lastTransitionTime: string;
        }];
      };
    }];
  };
  assert.deepEqual(
    {
      group: patch.group,
      version: patch.version,
      namespace: patch.namespace,
      plural: patch.plural,
      name: patch.name,
      body: patch.body.map(({ op, path, value }) => ({
        op,
        path,
        observedGeneration: value.observedGeneration,
        type: value.conditions?.[0]?.type,
        status: value.conditions?.[0]?.status,
        reason: value.conditions?.[0]?.reason,
        message: value.conditions?.[0]?.message,
      })),
    },
    {
      group: "hemlig.io",
      version: "v1beta1",
      namespace: "hemlig-sentinel",
      plural: "hemligconsumers",
      name: "sentinel",
      body: [{
        op: "add",
        path: "/status",
        observedGeneration: 1,
        type: "Ready",
        status: "False",
        reason: "ProviderNotFound",
        message: "The referenced HemligProvider was not found.",
      }],
    },
  );
  assert.match(patch.body[0].value.conditions?.[0]?.lastTransitionTime ?? "", /^\d{4}-\d{2}-\d{2}T/);
});

test("retries a transient Kubernetes API failure without exiting", async () => {
  let listAttempts = 0;
  const custom = {
    async listClusterCustomObject(): Promise<unknown> {
      listAttempts += 1;
      if (listAttempts === 1) {
        throw Object.assign(new Error("storage is initializing"), {
          headers: { "retry-after": "0" },
        });
      }
      return { items: [] };
    },
    async listCustomObjectForAllNamespaces(): Promise<unknown> {
      return { items: [] };
    },
  };
  const controller = new HemligV1BetaController(
    {} as never,
    custom as never,
    {
      intervalMilliseconds: 1,
      sourceDebounceMilliseconds: 1,
      reconcileRetryMilliseconds: 1,
    },
  );
  const abort = new AbortController();
  const running = controller.run(abort.signal);
  await new Promise((resolve) => setTimeout(resolve, 20));
  abort.abort();
  await running;

  assert.ok(listAttempts > 1);
});

interface TestWatchSession {
  readonly path: string;
  readonly query: Record<string, unknown>;
  readonly event: (phase: string, object: unknown) => void;
  readonly done: (error: unknown) => void;
}

const settleWatch = async (): Promise<void> => {
  // Drain the async list/reconcile chain without advancing the periodic timer.
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
  }
};

const watchController = () => {
  const sessions: TestWatchSession[] = [];
  let passes = 0;
  const controller = new HemligV1BetaController(
    {} as never,
    {
      async listClusterCustomObject(): Promise<unknown> {
        passes += 1;
        return { items: [] };
      },
      async listCustomObjectForAllNamespaces(): Promise<unknown> {
        return { items: [] };
      },
    } as never,
    { intervalMilliseconds: 600_000, sourceDebounceMilliseconds: 1 },
  );
  Object.assign(controller, {
    watch: {
      async watch(
        path: string,
        query: Record<string, unknown>,
        event: TestWatchSession["event"],
        done: TestWatchSession["done"],
      ): Promise<AbortController> {
        sessions.push({ path, query, event, done });
        return new AbortController();
      },
    },
  });
  return { controller, sessions, passes: () => passes };
};

test("resumes each Kubernetes watch from its bookmark without reconciling bookmarks", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = watchController();
  const abort = new AbortController();
  const running = fixture.controller.run(abort.signal);
  await settleWatch();
  const secretWatch = fixture.sessions.find(
    (s) => s.path === "/api/v1/secrets",
  );
  const namespaceWatch = fixture.sessions.find(
    (s) => s.path === "/api/v1/namespaces",
  );
  assert.ok(secretWatch);
  assert.ok(namespaceWatch);
  assert.deepEqual(secretWatch.query, { allowWatchBookmarks: true });

  secretWatch.event("ADDED", { metadata: { resourceVersion: "secret-event" } });
  t.mock.timers.tick(1);
  await settleWatch();
  assert.equal(fixture.passes(), 2);

  secretWatch.event("BOOKMARK", {
    metadata: { resourceVersion: "secret-bookmark" },
  });
  namespaceWatch.event("BOOKMARK", {
    metadata: { resourceVersion: "namespace-bookmark" },
  });
  t.mock.timers.tick(1);
  await settleWatch();
  assert.equal(fixture.passes(), 2);

  secretWatch.done(null);
  namespaceWatch.done(null);
  t.mock.timers.tick(1_000);
  await settleWatch();
  const resumedSecret = fixture.sessions
    .filter((s) => s.path === secretWatch.path)
    .at(-1);
  const resumedNamespace = fixture.sessions
    .filter((s) => s.path === namespaceWatch.path)
    .at(-1);
  assert.ok(resumedSecret);
  assert.ok(resumedNamespace);
  assert.deepEqual(resumedSecret.query, {
    allowWatchBookmarks: true,
    resourceVersion: "secret-bookmark",
  });
  assert.deepEqual(resumedNamespace.query, {
    allowWatchBookmarks: true,
    resourceVersion: "namespace-bookmark",
  });
  assert.equal(fixture.passes(), 2);

  resumedSecret.event("DELETED", {
    metadata: { resourceVersion: "secret-deleted" },
  });
  t.mock.timers.tick(1);
  await settleWatch();
  assert.equal(fixture.passes(), 3);
  abort.abort();
  await running;
});

test("advances the watch position even when a controller status update needs no reconciliation", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = watchController();
  const abort = new AbortController();
  const running = fixture.controller.run(abort.signal);
  await settleWatch();
  const session = fixture.sessions.find((s) =>
    s.path.endsWith("/hemligsecretimports"),
  );
  assert.ok(session);
  session.event("MODIFIED", {
    apiVersion: "hemlig.io/v1beta1",
    metadata: { generation: 1, resourceVersion: "status-update" },
    status: { observedGeneration: 1 },
  });
  t.mock.timers.tick(1);
  await settleWatch();
  assert.equal(fixture.passes(), 1);
  session.done(null);
  t.mock.timers.tick(1_000);
  await settleWatch();
  const resumed = fixture.sessions
    .filter((s) => s.path === session.path)
    .at(-1);
  assert.equal(resumed?.query.resourceVersion, "status-update");
  abort.abort();
  await running;
});

for (const delivery of ["stream", "http"] as const) {
  test(`rebuilds the snapshot after an expired ${delivery} watch position`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = watchController();
    const abort = new AbortController();
    const running = fixture.controller.run(abort.signal);
    await settleWatch();
    const session = fixture.sessions.find((s) => s.path === "/api/v1/secrets");
    assert.ok(session);
    session.event("BOOKMARK", { metadata: { resourceVersion: "expired" } });
    if (delivery === "stream") {
      session.event("ERROR", { code: 410, reason: "Expired" });
      session.done(null);
    } else {
      session.done({ statusCode: 410 });
    }
    t.mock.timers.tick(1);
    await settleWatch();
    assert.equal(fixture.passes(), 2);
    t.mock.timers.tick(1_000);
    await settleWatch();
    const fresh = fixture.sessions
      .filter((s) => s.path === session.path)
      .at(-1);
    assert.deepEqual(fresh?.query, { allowWatchBookmarks: true });
    abort.abort();
    await running;
  });
}
