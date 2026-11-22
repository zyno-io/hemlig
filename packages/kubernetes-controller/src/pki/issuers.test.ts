import assert from "node:assert/strict";
import test from "node:test";
import { IssuerReconciler } from "./issuers";
import {
  consumerObject,
  errorResponse,
  flush,
  grantBody,
  registered,
  FakeTransport,
  rig,
} from "./test-fakes";

const issuerSpec = (extra: Record<string, unknown> = {}) => ({
  metadata: {
    name: "issuer",
    namespace: "app",
    uid: "issuer-uid",
    generation: 1,
  },
  spec: { consumerRef: "consumer", issuanceGrant: "grant-one", ...extra },
});
const KEY = "issuer/app/issuer";
const CKEY = "clusterissuer/shared";

const setup = (spec: Record<string, unknown> = {}) => {
  const r = rig();
  r.custom.put("hemligissuers", issuerSpec(spec));
  const status = () => r.custom.peek("hemligissuers", "app", "issuer")!.status;
  const ready = () =>
    status()?.conditions?.find((c: { type: string }) => c.type === "Ready");
  return { ...r, status, ready };
};
const putCluster = (r: ReturnType<typeof rig>, allowedNamespaces?: object) =>
  r.custom.put("hemligclusterissuers", {
    metadata: { name: "shared", uid: "ci-uid", generation: 1 },
    spec: {
      consumerRef: { name: "consumer", namespace: "app" },
      issuanceGrant: "grant-one",
      ...(allowedNamespaces === undefined ? {} : { allowedNamespaces }),
    },
  });

test("Ready issuer writes the exact status", async () => {
  const r = setup();
  await r.run(KEY);
  assert.deepEqual(r.status(), {
    observedGeneration: 1,
    consumerId: "agent",
    environment: "prod",
    caId: "ca-issuing-1",
    caFingerprint: "ab:cd",
    caNotAfter: "2030-01-01T00:00:00Z",
    issuanceGrantVersion: "gv1",
    grantUid: "grant-uid",
    conditions: [
      {
        type: "Ready",
        status: "True",
        reason: "Ready",
        message: "The issuance grant and its CA are active",
        lastTransitionTime: "2026-06-01T00:00:00Z",
      },
    ],
  });
});

test("an unchanged pass writes nothing", async () => {
  const r = setup();
  await r.run(KEY);
  await r.scheduler.advance(120_000);
  await r.run(KEY);
  assert.equal(r.custom.count("patchStatus"), 1);
  // lastTransitionTime is preserved while the status holds.
  assert.equal(r.ready().lastTransitionTime, "2026-06-01T00:00:00Z");
});

test("ConsumerNotFound", async () => {
  const r = setup();
  r.custom.remove("hemligconsumers", "app", "consumer");
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotFound");
  assert.equal(r.ready().status, "False");
  assert.equal(r.status().observedGeneration, 1);
});

test("ConsumerNotReady: missing from the registry, uid or generation mismatch", async () => {
  const r = setup();
  r.registry.entries.clear();
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotReady");
  r.registry.entries.set(
    "app/consumer",
    registered(r.transport, { uid: "other" }),
  );
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotReady");
  r.registry.entries.set(
    "app/consumer",
    registered(r.transport, { generation: 7 }),
  );
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotReady");
  assert.equal(r.transport.requests.length, 0);
  r.registry.entries.set("app/consumer", registered(r.transport));
  await r.run(KEY);
  assert.equal(r.ready().reason, "Ready");
});

test("ConsumerNotReady: 403 identity_not_active and code-less 403", async () => {
  const r = setup();
  r.transport.handler = () => errorResponse(403, "identity_not_active");
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotReady");
  assert.equal(r.ready().message, "Hemlig rejected the consumer identity");
  r.transport.handler = () => errorResponse(403);
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerNotReady");
});

test("ConsumerReferenceNotPermitted needs the consumer's opt-in", async () => {
  const r = setup({ consumerNamespace: "other" });
  const other = consumerObject();
  other.metadata.namespace = "other";
  r.custom.put("hemligconsumers", other);
  r.core.labels.set("other", {});
  r.registry.entries.set(
    "other/consumer",
    registered(r.transport, { key: "other/consumer" }),
  );
  await r.run(KEY);
  assert.equal(r.ready().reason, "ConsumerReferenceNotPermitted");
  other.spec.allowCrossNamespaceReferences = true;
  r.custom.put("hemligconsumers", other);
  await r.run(KEY);
  assert.equal(r.ready().reason, "Ready");
});

test("ClusterIssuerNotPermitted: allowCrossNamespaceReferences alone is not enough", async () => {
  const r = rig();
  putCluster(r);
  const consumer = consumerObject({ allowCrossNamespaceReferences: true });
  r.custom.put("hemligconsumers", consumer);
  await r.run(CKEY);
  const ready = () =>
    r.custom.peek("hemligclusterissuers", undefined, "shared")!.status
      .conditions[0];
  assert.equal(ready().reason, "ClusterIssuerNotPermitted");
  consumer.spec.allowClusterIssuers = true;
  r.custom.put("hemligconsumers", consumer);
  await r.run(CKEY);
  assert.equal(ready().reason, "Ready");
  assert.equal(r.custom.count("patchClusterStatus"), 2);
});

test("ProviderNotPermitted uses the issuer namespace for HemligIssuer", async () => {
  const r = setup({ consumerNamespace: "app" });
  const provider = {
    metadata: { generation: 1 },
    spec: {
      apiUrl: "https://api.test",
      allowedNamespaces: { matchLabels: { team: "a" } },
    },
  };
  r.registry.entries.set(
    "app/consumer",
    registered(r.transport, { provider: provider as never }),
  );
  r.core.labels.set("app", {});
  await r.run(KEY);
  assert.equal(r.ready().reason, "ProviderNotPermitted");
  r.core.labels.set("app", { team: "a" });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Ready");
});

test("ProviderNotPermitted uses the consumer namespace for a cluster issuer", async () => {
  const r = rig();
  putCluster(r);
  r.custom.put(
    "hemligconsumers",
    consumerObject({ allowClusterIssuers: true }),
  );
  r.registry.entries.set(
    "app/consumer",
    registered(r.transport, {
      provider: {
        metadata: { generation: 1 },
        spec: {
          apiUrl: "x",
          allowedNamespaces: { matchLabels: { team: "a" } },
        },
      } as never,
    }),
  );
  await r.run(CKEY);
  const reason = () =>
    r.custom.peek("hemligclusterissuers", undefined, "shared")!.status
      .conditions[0].reason;
  assert.equal(reason(), "ProviderNotPermitted");
  r.core.labels.set("app", { team: "a" });
  await r.run(CKEY);
  assert.equal(reason(), "Ready");
});

test("grant states", async () => {
  const r = setup();
  r.transport.handler = () => errorResponse(404, "issuance_grant_not_found");
  await r.run(KEY);
  assert.equal(r.ready().reason, "IssuanceGrantNotFound");
  r.transport.handler = () => ({
    status: 200,
    headers: {},
    body: grantBody({ status: "DISABLED" }),
  });
  await r.run(KEY);
  assert.equal(r.ready().reason, "IssuanceGrantInactive");
  r.transport.handler = () => ({
    status: 200,
    headers: {},
    body: grantBody({ expired: true }),
  });
  await r.run(KEY);
  assert.equal(r.ready().reason, "IssuanceGrantInactive");
  for (const status of ["RETIRED", "UNKNOWN"]) {
    r.transport.handler = () => ({
      status: 200,
      headers: {},
      body: grantBody({ ca: { caId: "ca-issuing-1", status } }),
    });
    await r.run(KEY);
    assert.equal(r.ready().reason, "CaNotActive");
  }
  r.transport.handler = () => ({ status: 200, headers: {}, body: grantBody() });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Ready");
});

test("a transient failure keeps a Ready issuer and retries fast", async () => {
  const r = setup();
  await r.run(KEY);
  r.transport.handler = () => errorResponse(503);
  await r.run(KEY);
  assert.equal(r.ready().reason, "Ready");
  assert.equal(r.custom.count("patchStatus"), 1);
  assert.equal(r.queue.scheduledDelay(KEY), 500);
  r.queue.stop();
});

test("a transient failure on a non-Ready issuer writes RemoteError", async () => {
  const r = setup();
  r.transport.handler = () => errorResponse(503);
  await r.run(KEY);
  assert.equal(r.ready().reason, "RemoteError");
  assert.equal(r.ready().message, "Hemlig is unavailable");
  assert.equal(r.queue.scheduledDelay(KEY), 500);
  r.queue.stop();
});

test("other errors write RemoteError and retry slowly", async () => {
  const r = setup();
  r.transport.handler = () => errorResponse(404, "not_found");
  await r.run(KEY);
  assert.equal(r.ready().reason, "RemoteError");
  assert.equal(r.queue.scheduledDelay(KEY), 15_000);
  assert.ok(!r.ready().message.includes("SECRET"));
  r.queue.stop();
});

test("a deleted issuer clears state and finishes", async () => {
  const r = setup();
  r.custom.remove("hemligissuers", "app", "issuer");
  r.issuers.waitFor(KEY, "cr/app/x");
  await r.run(KEY);
  assert.equal(r.queue.scheduledDelay(KEY), undefined);
});

const direct = () => {
  const r = rig();
  const adds: { key: string; options?: { resetBackoff?: boolean } }[] = [];
  const issuers = new IssuerReconciler(r.deps, {
    add: (key, options) => {
      adds.push({ key, ...(options === undefined ? {} : { options }) });
    },
  });
  r.custom.put("hemligissuers", issuerSpec());
  return { ...r, issuers, adds, ctx: { tryAcquire: () => () => {} } };
};

test("a Ready transition wakes waiters with resetBackoff", async () => {
  const d = direct();
  d.issuers.waitFor(KEY, "cr/app/a");
  d.issuers.waitFor(KEY, "cr/app/b");
  d.issuers.stopWaiting("cr/app/b");
  await d.issuers.reconcile(KEY, d.ctx);
  assert.deepEqual(d.adds, [
    { key: "cr/app/a", options: { resetBackoff: true } },
  ]);
  await d.issuers.reconcile(KEY, d.ctx);
  assert.equal(d.adds.length, 1);
});

test("requestRefresh is limited to one enqueue per 30 seconds", async () => {
  const d = direct();
  d.issuers.requestRefresh(KEY);
  assert.equal(d.adds.length, 1);
  await d.issuers.reconcile(KEY, d.ctx);
  d.issuers.requestRefresh(KEY);
  assert.equal(d.adds.length, 1);
  d.scheduler.time += 31_000;
  d.issuers.requestRefresh(KEY);
  assert.equal(d.adds.length, 2);
});

test("a slow grant call does not leak an unhandled rejection after the timeout", async () => {
  const d = direct();
  d.transport.handler = () => new Promise(() => {});
  const running = d.issuers.reconcile(KEY, d.ctx);
  await flush();
  await d.scheduler.advance(61_000);
  const outcome = await running;
  assert.deepEqual(outcome, { kind: "retry", policy: "fast" });
  assert.equal(
    d.custom.peek("hemligissuers", "app", "issuer")!.status.conditions[0]
      .reason,
    "RemoteError",
  );
});

test("a registry entry replaced mid-run is not used for the grant call", async () => {
  const r = setup();
  const other = new FakeTransport();
  const original = r.core.readNamespace.bind(r.core);
  let swapped = false;
  r.core.readNamespace = async (input: { name: string }) => {
    if (!swapped) {
      swapped = true;
      r.registry.entries.set("app/consumer", registered(other));
    }
    return original(input);
  };
  await r.run(KEY);
  assert.equal(r.transport.requests.length, 0);
  assert.equal(other.requests.length, 1);
  assert.equal(r.ready().reason, "Ready");
});
