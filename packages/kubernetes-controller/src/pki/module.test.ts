import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { PkiModule } from "./module";
import {
  FakeCore,
  FakeCustom,
  FakeRegistry,
  FakeWatch,
  FakeScheduler,
  FakeTransport,
  consumerObject,
  crObject,
  flush,
  issuerObject,
  registered,
} from "./test-fakes";

const CR_PATH = "/apis/cert-manager.io/v1/certificaterequests";
const ISSUER_PATH = "/apis/hemlig.zyno.io/v1alpha1/hemligissuers";
const CLUSTER_PATH = "/apis/hemlig.zyno.io/v1alpha1/hemligclusterissuers";
const GONE = { code: 410 };

const world = (
  t: TestContext,
  options: { issuer?: boolean; watch?: FakeWatch } = {},
) => {
  const scheduler = new FakeScheduler();
  const custom = new FakeCustom();
  const core = new FakeCore();
  core.labels.set("app", {});
  const registry = new FakeRegistry();
  const transport = new FakeTransport();
  registry.entries.set("app/consumer", registered(transport));
  custom.put("hemligconsumers", consumerObject());
  if (options.issuer !== false) custom.put("hemligissuers", issuerObject());
  const watch = options.watch ?? new FakeWatch();
  const module = new PkiModule({
    core: core as never,
    custom: custom as never,
    watch,
    registry,
    config: { concurrency: 4 },
    scheduler,
  });
  const abort = new AbortController();
  t.after(() => {
    abort.abort();
    module.stop();
  });
  const settle = async () => {
    await flush();
    await module.queue.whenIdle();
    await flush();
  };
  const ready = (name = "cr-1") =>
    custom
      .peek("certificaterequests", "app", name)
      ?.status?.conditions?.find((c: { type: string }) => c.type === "Ready");
  return {
    scheduler,
    custom,
    core,
    registry,
    transport,
    watch,
    module,
    abort,
    settle,
    ready,
    start: async () => {
      await module.resyncNow();
      await settle();
    },
  };
};

test("relist enqueues non-terminal Hemlig requests only and watches from the list version", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject());
  w.custom.put(
    "certificaterequests",
    crObject({
      name: "done",
      uid: "d",
      conditions: [{ type: "Ready", status: "True", reason: "Issued" }],
    }),
  );
  w.custom.put(
    "certificaterequests",
    crObject({
      name: "other",
      uid: "o",
      spec: {
        issuerRef: { group: "cert-manager.io", kind: "Issuer", name: "x" },
      },
    }),
  );
  const listed = (await w.custom.listCustomObjectForAllNamespaces({
    plural: "certificaterequests",
  })) as { metadata: { resourceVersion: string } };
  await w.start();
  assert.equal(w.transport.posts().length, 1);
  assert.equal(w.ready()?.reason, "Issued");
  const watcher = w.watch.active(CR_PATH)!;
  assert.equal(watcher.query.resourceVersion, listed.metadata.resourceVersion);
  assert.equal(watcher.query.allowWatchBookmarks, true);
  const timeout = watcher.query.timeoutSeconds as number;
  assert.ok(timeout >= 300 && timeout < 600);
  assert.ok(w.watch.active(ISSUER_PATH));
  assert.ok(w.watch.active(CLUSTER_PATH));
});

test("an ADDED event is processed and a DELETED event forgets the key", async (t) => {
  const w = world(t, { issuer: false });
  await w.start();
  w.custom.put("certificaterequests", crObject());
  w.watch.emit(
    CR_PATH,
    "ADDED",
    w.custom.peek("certificaterequests", "app", "cr-1"),
  );
  await w.settle();
  // No issuer: the request waits on a slow retry.
  assert.ok(w.module.queue.scheduledDelay("cr/app/cr-1") !== undefined);
  w.watch.emit(
    CR_PATH,
    "DELETED",
    w.custom.peek("certificaterequests", "app", "cr-1"),
  );
  assert.equal(w.module.queue.scheduledDelay("cr/app/cr-1"), undefined);
});

test("an ERROR 410 relists and finds a request approved during the gap", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject({ approved: false }));
  await w.start();
  assert.equal(w.ready()?.message, "Waiting for approval");
  const before = w.watch.watches.filter((x) => x.path === CR_PATH).length;
  w.custom.update("certificaterequests", "app", "cr-1", (o) => {
    o.status.conditions.push({ type: "Approved", status: "True" });
  });
  w.watch.emit(CR_PATH, "ERROR", GONE);
  await w.settle();
  assert.equal(w.ready()?.reason, "Issued");
  assert.equal(
    w.watch.watches.filter((x) => x.path === CR_PATH).length,
    before + 1,
  );
});

test("a watch closing with 410 relists too, and other closes re-watch from the last version", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject({ approved: false }));
  await w.start();
  w.custom.update("certificaterequests", "app", "cr-1", (o) => {
    o.status.conditions.push({ type: "Approved", status: "True" });
  });
  w.watch.end(CR_PATH, GONE);
  await w.settle();
  assert.equal(w.ready()?.reason, "Issued");
  const count = w.watch.watches.filter((x) => x.path === CR_PATH).length;
  w.watch.emit(CR_PATH, "BOOKMARK", { metadata: { resourceVersion: "9999" } });
  w.watch.end(CR_PATH);
  await w.scheduler.advance(1_000);
  const watches = w.watch.watches.filter((x) => x.path === CR_PATH);
  assert.equal(watches.length, count + 1);
  assert.equal(watches.at(-1)!.query.resourceVersion, "9999");
});

test("relist follows metadata.continue", async (t) => {
  const w = world(t);
  w.custom.pageSize = 1;
  for (const [name, uid] of [
    ["a", "ua"],
    ["b", "ub"],
    ["c", "uc"],
  ] as const) {
    w.custom.put("certificaterequests", crObject({ name, uid }));
  }
  await w.start();
  assert.equal(w.transport.posts().length, 3);
  for (const name of ["a", "b", "c"])
    assert.equal(w.ready(name)?.reason, "Issued");
});

test("the five-minute resync picks up an approval the watch never reported", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject({ approved: false }));
  w.module.start(w.abort.signal);
  await w.settle();
  assert.equal(w.ready()?.message, "Waiting for approval");
  w.custom.update("certificaterequests", "app", "cr-1", (o) => {
    o.status.conditions.push({ type: "Approved", status: "True" });
  });
  await w.scheduler.advance(330_000);
  await w.settle();
  assert.equal(w.ready()?.reason, "Issued");
});

test("an absent cert-manager CRD starts nothing and is picked up by a later resync", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject());
  w.custom.absent.add("certificaterequests");
  await w.start();
  assert.equal(w.watch.watches.length, 0);
  assert.equal(w.transport.requests.length, 0);
  assert.equal(w.module.enabled, false);
  w.custom.absent.delete("certificaterequests");
  await w.start();
  assert.equal(w.module.enabled, true);
  assert.ok(w.watch.active(CR_PATH));
  assert.equal(w.ready()?.reason, "Issued");
});

test("a missing issuer CRD alone disables the feature; RBAC 403 counts as absent", async (t) => {
  const w = world(t);
  w.custom.put("certificaterequests", crObject());
  w.custom.absent.add("hemligissuers");
  await w.start();
  assert.equal(w.watch.watches.length, 0);
  w.custom.absent.delete("hemligissuers");
  w.custom.forbidden.add("hemligclusterissuers");
  await w.start();
  assert.equal(w.watch.watches.length, 0);
  assert.equal(w.module.enabled, false);
});

test("a CRD removed while enabled stops the streams and forgets keys", async (t) => {
  const w = world(t, { issuer: false });
  w.custom.put("certificaterequests", crObject());
  await w.start();
  assert.ok(w.module.queue.scheduledDelay("cr/app/cr-1") !== undefined);
  const watcher = w.watch.active(CR_PATH)!;
  w.custom.absent.add("hemligclusterissuers");
  await w.start();
  assert.equal(w.module.enabled, false);
  assert.equal(watcher.controller.signal.aborted, true);
  assert.equal(w.module.queue.scheduledDelay("cr/app/cr-1"), undefined);
});

test("the issuer's own status MODIFIED event is ignored; spec changes are not", async (t) => {
  const w = world(t);
  await w.start();
  const gets = () => w.custom.count("get", "hemligissuers");
  const before = gets();
  w.watch.emit(
    ISSUER_PATH,
    "MODIFIED",
    w.custom.peek("hemligissuers", "app", "issuer"),
  );
  await w.settle();
  assert.equal(gets(), before);
  const changed = structuredClone(
    w.custom.peek("hemligissuers", "app", "issuer"),
  )!;
  changed.metadata.generation = 2;
  w.watch.emit(ISSUER_PATH, "MODIFIED", changed);
  await w.settle();
  assert.ok(gets() > before);
});

test("a registry change enqueues every issuer", async (t) => {
  const w = world(t);
  w.module.start(w.abort.signal);
  await w.settle();
  const before = w.custom.count("get", "hemligissuers");
  w.registry.fire("app/consumer");
  await w.settle();
  assert.ok(w.custom.count("get", "hemligissuers") > before);
});

test("stop unsubscribes and halts the queue", async (t) => {
  const w = world(t);
  w.module.start(w.abort.signal);
  await w.settle();
  assert.equal(w.registry.listeners.size, 1);
  w.abort.abort();
  assert.equal(w.registry.listeners.size, 0);
});

test("PKI code never couples to the full reconcile pass", () => {
  const dir = __dirname;
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".js") || file.includes(".test.")) continue;
    const source = readFileSync(path.join(dir, file), "utf8");
    assert.ok(!source.includes("scheduleReconcile"), file);
    assert.ok(!/require\(["']\.\.\/v1beta["']\)/.test(source), file);
  }
});

test("a 410 delivered while the first watch opens triggers another relist", async (t) => {
  class SyncGone extends FakeWatch {
    private first = true;
    public override async watch(
      path: string,
      query: Record<string, unknown>,
      onEvent: (phase: string, object: unknown) => void,
      done: (error: unknown) => void,
    ) {
      if (path === CR_PATH && this.first) {
        this.first = false;
        done(GONE);
      }
      return super.watch(path, query, onEvent, done);
    }
  }
  const w = world(t, { watch: new SyncGone() });
  w.custom.put("certificaterequests", crObject({ approved: false }));
  await w.start();
  w.custom.update("certificaterequests", "app", "cr-1", (o) => {
    o.status.conditions.push({ type: "Approved", status: "True" });
  });
  // probe + first relist + the relist forced by the 410
  assert.ok(w.custom.count("list", "certificaterequests") >= 3);
  assert.ok(w.watch.active(CR_PATH));
  assert.equal(
    w.watch.watches.filter((x) => x.path === CR_PATH).length >= 2,
    true,
  );
});
