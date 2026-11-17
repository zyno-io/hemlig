import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test, { type TestContext } from "node:test";
import forge from "node-forge";
import {
  HemligClient,
  HemligError,
  type AgentSyncEntry,
  type AgentConfig,
} from "@zyno-io/hemlig-client";
import { HemligV1BetaController } from "./v1beta";

const day = 86_400_000;
const keyPair = () => {
  const pair = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  return { publicKeyPem: pair.publicKey, privateKeyPem: pair.privateKey };
};
const ca = (() => {
  const pair = keyPair();
  return { key: forge.pki.privateKeyFromPem(pair.privateKeyPem) };
})();
const issue = (
  publicKey: forge.pki.PublicKey,
  notBefore: Date,
  notAfter: Date,
) => {
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = createHash("sha256")
    .update(String(Math.random()))
    .digest("hex")
    .slice(0, 16);
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  cert.setSubject([{ name: "commonName", value: "agent" }]);
  cert.setIssuer([{ name: "commonName", value: "test ca" }]);
  cert.sign(ca.key, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
};
const sharedIdentityKey = keyPair();
/** An identity with `daysLeft` of a `lifetimeDays` certificate remaining. */
const makeIdentity = (daysLeft: number, lifetimeDays = 365) => {
  const now = Date.now();
  return {
    crtPem: issue(
      forge.pki.publicKeyFromPem(sharedIdentityKey.publicKeyPem),
      new Date(now + (daysLeft - lifetimeDays) * day),
      new Date(now + daysLeft * day),
    ),
    keyPem: sharedIdentityKey.privateKeyPem,
  };
};
const b64 = (value: string) => Buffer.from(value, "utf8").toString("base64");

type Resource = {
  metadata: {
    name: string;
    namespace: string;
    generation: number;
    uid: string;
    annotations?: Record<string, string>;
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
const fixture = (
  t: TestContext,
  options: {
    identity?: { crtPem: string; keyPem: string };
    rotateBefore?: string;
  } = {},
) => {
  const consumer: Resource = {
    metadata: meta("consumer"),
    spec: {
      providerRef: "provider",
      identity: {
        secretName: "identity",
        ...(options.rotateBefore === undefined
          ? {}
          : { rotateBefore: options.rotateBefore }),
      },
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
          resourceVersion: "1",
          labels: { "hemlig.io/managed-by": "consumer" },
          annotations: { "hemlig.io/consumer-owner": "ns/consumer" },
        },
        data: {
          "tls.crt": b64(options.identity?.crtPem ?? "fixture"),
          "tls.key": b64(options.identity?.keyPem ?? "fixture"),
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
  let configBehavior: (certificate: string) => AgentConfig = () => {
    throw new Error("configuration polling is forbidden in sync tests");
  };
  const configReads = t.mock.method(
    HemligClient.prototype,
    "getAgentConfig",
    async function (this: { transport: { options: { cert?: Buffer } } }) {
      return configBehavior(this.transport.options.cert?.toString() ?? "");
    },
  );
  // Default rotation: sign the CSR's public key with the test CA.
  let rotateBehavior = async (csrPem: string) => {
    const csr = forge.pki.certificationRequestFromPem(csrPem);
    const now = Date.now();
    const notBefore = new Date(now - 3_600_000);
    const notAfter = new Date(now + 365 * day);
    return {
      consumerId: "agent",
      environment: "prod",
      rootFingerprint: "root",
      apiFingerprint: "api",
      apiCertificatePem: issue(csr.publicKey!, notBefore, notAfter),
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      status: "ACTIVE" as const,
    };
  };
  const rotate = t.mock.method(
    HemligClient.prototype,
    "rotateAgentIdentity",
    async (csrPem: string, idempotencyKey: string) => {
      assert.equal(
        idempotencyKey,
        createHash("sha256").update(csrPem).digest("hex"),
      );
      return rotateBehavior(csrPem);
    },
  );
  const ensured: { certificate: Buffer; privateKey: Buffer }[] = [];
  const removed: string[] = [];
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
      const stored = secrets.get(input.name);
      const version = input.body.metadata?.resourceVersion;
      if (
        version !== undefined &&
        stored?.metadata?.resourceVersion !== undefined &&
        version !== stored.metadata.resourceVersion
      )
        throw Object.assign(new Error("conflict"), { code: 409 });
      const next = structuredClone(input.body);
      if (stored?.metadata?.resourceVersion !== undefined)
        next.metadata.resourceVersion = String(
          Number(stored.metadata.resourceVersion) + 1,
        );
      secrets.set(input.name, next);
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
    {
      intervalMilliseconds: 600_000,
      sourceDebounceMilliseconds: 250,
      identityRotationRetryMilliseconds: 0,
      identityRotationRetryMaxMilliseconds: 0,
      identityKeyBits: 2048,
    },
  );
  Object.assign(controller, {
    mqtt: {
      ensure(input: { certificate: Buffer; privateKey: Buffer }) {
        ensured.push(input);
      },
      remove(key: string) {
        removed.push(key);
      },
      stop() {},
    },
  });
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
    rotate,
    original: options.identity?.crtPem ?? "fixture",
    ensured,
    removed,
    configReads,
    counts,
    onConfig: (fn: (certificate: string) => AgentConfig) => {
      configBehavior = fn;
    },
    onRotate: (fn: typeof rotateBehavior) => {
      rotateBehavior = fn;
    },
    /** Passes that must not leave a backoff retry timer racing the test. */
    pass: async () => {
      await controller.reconcileAll();
      const timer = (controller as unknown as { reconcileTimer?: NodeJS.Timeout })
        .reconcileTimer;
      if (timer !== undefined) clearTimeout(timer);
      (controller as unknown as { reconcileTimer?: NodeJS.Timeout }).reconcileTimer =
        undefined;
    },
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

type Fixture = ReturnType<typeof fixture>;
const data = (f: Fixture, key: string): string | undefined => {
  const value = f.secrets.get("identity").data[key];
  return value === undefined
    ? undefined
    : Buffer.from(value, "base64").toString("utf8");
};
const annotation = (f: Fixture, key: string): string | undefined =>
  f.secrets.get("identity").metadata.annotations?.[key];
const condition = (resource: Resource, type: string) =>
  (resource.status?.conditions as { type: string; status: string; reason: string }[])
    ?.find((entry) => entry.type === type);
const pendingKeys = ["hemlig.io.next-tls.key", "hemlig.io.next-csr", "hemlig.io.next-tls.crt"];
const withVerification = (f: Fixture) =>
  f.onConfig((certificate) => {
    if (certificate === f.original) throw new Error("unexpected old-cert config read");
    return f.config;
  });
/** A due identity (10 of 365 days left) with a verifying new-cert config read. */
const dueFixture = (t: TestContext, extra: Parameters<typeof fixture>[1] = {}) => {
  const identity = makeIdentity(10);
  const f = fixture(t, { identity, ...extra });
  withVerification(f);
  return f;
};

test("R1: an identity outside its rotation window is not rotated and reports status", async (t) => {
  const identity = makeIdentity(365);
  const f = fixture(t, { identity });
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 0);
  const status = f.consumer.status?.identity;
  assert.equal(
    Date.parse(status.rotateAfter),
    Date.parse(status.notAfter) - 30 * day,
  );
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(condition(f.consumer, "IdentityRotation")?.status, "True");
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "NotDue");
});

test("R2: a due identity is rotated through persisted pending state and swapped after verification", async (t) => {
  const f = dueFixture(t);
  let seenPending: { key?: string; csr?: string } = {};
  f.onRotate(async (csrPem) => {
    seenPending = {
      key: data(f, "hemlig.io.next-tls.key"),
      csr: data(f, "hemlig.io.next-csr"),
    };
    assert.equal(seenPending.csr, csrPem);
    return (await rotateDefault(f, csrPem)) as never;
  });
  await f.pass();
  assert.ok(seenPending.key?.includes("PRIVATE KEY"));
  assert.equal(f.rotate.mock.callCount(), 1);
  const newCrt = data(f, "tls.crt")!;
  assert.notEqual(newCrt, f.original);
  assert.equal(data(f, "tls.key"), seenPending.key);
  assert.equal(data(f, "hemlig.io.previous-tls.crt"), f.original);
  assert.equal(
    data(f, "hemlig.io.previous-tls.key"),
    sharedIdentityKey.privateKeyPem,
  );
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
  assert.ok(annotation(f, "hemlig.io/rotated-at"));
  assert.equal(
    annotation(f, "hemlig.io/api-fingerprint"),
    f.consumer.status?.identity.apiFingerprint,
  );
  assert.equal(f.ensured.at(-1)?.certificate.toString(), newCrt);
  assert.equal(
    f.consumer.status?.syncIdentity,
    createHash("sha256")
      .update("https://api.test")
      .update(Buffer.from(newCrt))
      .digest("hex"),
  );
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 1);
  assert.equal(f.sync.mock.calls.at(-1)?.arguments[0]?.syncCursor, "checkpoint-1");
});

test("R3: a failed rotation request keeps the old identity Ready and retries with the same pending CSR", async (t) => {
  const f = dueFixture(t);
  let fail = true;
  f.onRotate(async (csrPem) => {
    if (fail) throw new Error("network down");
    return (await rotateDefault(f, csrPem)) as never;
  });
  await f.pass();
  assert.equal(data(f, "tls.crt"), f.original);
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationFailed");
  const pendingCsr = data(f, "hemlig.io.next-csr");
  const pendingKey = data(f, "hemlig.io.next-tls.key");
  assert.ok(pendingCsr && pendingKey);
  fail = false;
  await f.pass();
  assert.equal(f.rotate.mock.calls[0]?.arguments[0], pendingCsr);
  assert.equal(f.rotate.mock.calls[1]?.arguments[0], pendingCsr);
  assert.equal(data(f, "tls.key"), pendingKey);
  assert.notEqual(data(f, "tls.crt"), f.original);
});

test("R3b: an issued but unverified certificate is persisted and swapped later without re-requesting", async (t) => {
  const f = dueFixture(t);
  let verified = false;
  f.onConfig((certificate) => {
    if (certificate === f.original || !verified)
      throw new HemligError(503, "unavailable");
    return f.config;
  });
  await f.pass();
  assert.equal(data(f, "tls.crt"), f.original);
  assert.ok(data(f, "hemlig.io.next-tls.crt"));
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "VerificationFailed");
  verified = true;
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 1);
  assert.notEqual(data(f, "tls.crt"), f.original);
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
});

test("R4: invalid_csr discards the pending key and the next attempt uses a new CSR", async (t) => {
  const f = dueFixture(t);
  let reject = true;
  f.onRotate(async (csrPem) => {
    if (reject) throw new HemligError(400, "bad csr", "invalid_csr");
    return (await rotateDefault(f, csrPem)) as never;
  });
  await f.pass();
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationRejected");
  reject = false;
  await f.pass();
  assert.notEqual(
    f.rotate.mock.calls[0]?.arguments[0],
    f.rotate.mock.calls[1]?.arguments[0],
  );
  assert.notEqual(data(f, "tls.crt"), f.original);
});

test("R5: an old server's bad_request is RotationUnsupported and keeps the pending key", async (t) => {
  const f = dueFixture(t);
  f.onRotate(async () => {
    throw new HemligError(400, "bad_request", "bad_request");
  });
  await f.pass();
  const pendingKey = data(f, "hemlig.io.next-tls.key");
  const pendingCsr = data(f, "hemlig.io.next-csr");
  assert.ok(pendingKey);
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationUnsupported");
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  await f.pass();
  assert.equal(data(f, "hemlig.io.next-tls.key"), pendingKey);
  assert.equal(f.rotate.mock.calls[1]?.arguments[0], pendingCsr);
});

test("R6: identity_limit_reached is reported without making the consumer unready", async (t) => {
  const f = dueFixture(t);
  f.onRotate(async () => {
    throw new HemligError(409, "limit", "identity_limit_reached");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "IdentityLimitReached");
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(data(f, "tls.crt"), f.original);
});

test("R7: a new certificate that authenticates as another consumer is never swapped in", async (t) => {
  const f = dueFixture(t);
  f.onConfig(() => ({ ...f.config, consumerId: "someone-else" }));
  await f.pass();
  assert.equal(data(f, "tls.crt"), f.original);
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(condition(f.consumer, "IdentityRotation")?.status, "False");
});

test("R8: a returned certificate for a different public key is rejected and discarded", async (t) => {
  const f = dueFixture(t);
  const other = keyPair();
  f.onRotate(async () => {
    const now = Date.now();
    return {
      consumerId: "agent",
      environment: "prod",
      rootFingerprint: "root",
      apiFingerprint: "api",
      apiCertificatePem: issue(
        forge.pki.publicKeyFromPem(other.publicKeyPem),
        new Date(now - 1000),
        new Date(now + 365 * day),
      ),
      notBefore: new Date(now - 1000).toISOString(),
      notAfter: new Date(now + 365 * day).toISOString(),
      status: "ACTIVE" as const,
    };
  });
  await f.pass();
  assert.equal(data(f, "tls.crt"), f.original);
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
  assert.equal(f.configReads.mock.callCount(), 0);
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationRejected");
});

test("R9: a manual token rotates once even when not due and is consumed durably", async (t) => {
  const identity = makeIdentity(300);
  const f = fixture(t, { identity });
  withVerification(f);
  f.consumer.metadata.annotations = { "hemlig.io/rotate-identity": "t1" };
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 1);
  assert.equal(annotation(f, "hemlig.io/rotation-request"), "t1");
  assert.equal(f.consumer.status?.identity.rotationRequest, "t1");
  f.sync.mock.mockImplementationOnce(async () => {
    throw new HemligError(503, "unavailable");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "Ready")?.status, "False");
  await f.pass();
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(f.rotate.mock.callCount(), 1);
});

test("R10: rotateBefore 0h disables automatic rotation but not manual rotation", async (t) => {
  const identity = makeIdentity(1);
  const f = fixture(t, { identity, rotateBefore: "0h" });
  withVerification(f);
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 0);
  assert.equal(f.consumer.status?.identity.rotateAfter, undefined);
  assert.equal(
    condition(f.consumer, "IdentityRotation")?.reason,
    "AutomaticRotationDisabled",
  );
  f.consumer.metadata.annotations = { "hemlig.io/rotate-identity": "now" };
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 1);
});

test("R11: an oversized rotateBefore is clamped to half the certificate lifetime", async (t) => {
  const identity = makeIdentity(60, 100);
  const f = fixture(t, { identity, rotateBefore: "9999d" });
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 0);
  const status = f.consumer.status?.identity;
  assert.equal(
    Date.parse(status.rotateAfter),
    (Date.parse(status.notBefore) + Date.parse(status.notAfter)) / 2,
  );
});

test("R12: a failed synchronization attempts no rotation", async (t) => {
  const f = dueFixture(t);
  f.sync.mock.mockImplementationOnce(async () => {
    throw new HemligError(503, "unavailable");
  });
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 0);
  assert.equal(data(f, "hemlig.io.next-tls.key"), undefined);
});

const watchedFixture = async (t: TestContext) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(t);
  const watches: { path: string; event: (phase: string, object: unknown) => void }[] = [];
  Object.assign(f.controller, {
    watch: {
      async watch(path: string, _query: unknown, event: (phase: string, object: unknown) => void) {
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
  const consumerWatch = watches.find((entry) => entry.path.endsWith("/hemligconsumers"));
  assert.ok(consumerWatch);
  const event = (annotations: Record<string, string>, rotationRequest?: string) => ({
    apiVersion: "hemlig.io/v1beta1",
    kind: "HemligConsumer",
    metadata: { generation: 1, resourceVersion: "5", annotations },
    status: { observedGeneration: 1, identity: { rotationRequest } },
  });
  const send = async (annotations: Record<string, string>, rotationRequest?: string) => {
    consumerWatch.event("MODIFIED", event(annotations, rotationRequest));
    t.mock.timers.tick(250);
    await settle();
  };
  return {
    f,
    send,
    stop: async () => {
      abort.abort();
      await running;
    },
  };
};

test("R13: a new manual rotation annotation schedules a reconcile; own status updates do not", async (t) => {
  const { f, send, stop } = await watchedFixture(t);
  const before = f.counts();
  await send({});
  assert.deepEqual(f.counts(), before);
  await send({ "hemlig.io/rotate-identity": "t2" }, "t1");
  assert.equal(f.counts().sync, before.sync + 1);
  await stop();
});

test("R13b: a watch event whose rotation annotation equals the consumed request schedules no reconcile", async (t) => {
  const { f, send, stop } = await watchedFixture(t);
  const before = f.counts();
  await send({ "hemlig.io/rotate-identity": "t1" }, "t1");
  assert.deepEqual(f.counts(), before);
  await stop();
});

/** Default CA-signing behaviour, reused by tests that wrap the rotate mock. */
const rotateDefault = async (_f: Fixture, csrPem: string) => {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  const now = Date.now();
  return {
    consumerId: "agent",
    environment: "prod",
    rootFingerprint: "root",
    apiFingerprint: "api",
    apiCertificatePem: issue(
      csr.publicKey!,
      new Date(now - 3_600_000),
      new Date(now + 365 * day),
    ),
    notBefore: new Date(now - 3_600_000).toISOString(),
    notAfter: new Date(now + 365 * day).toISOString(),
    status: "ACTIVE" as const,
  };
};

const retrying = (f: Fixture) => {
  const next = { ...f.records.get("a")!, controlVersionId: "ctl-a-next" };
  const nextB = { ...f.records.get("b")!, controlVersionId: "ctl-b-next" };
  f.records.set("a", next);
  f.records.set("b", nextB);
  f.change([next, nextB]);
};
const importFixture = async (t: TestContext) => {
  const f = fixture(t, { identity: makeIdentity(300) });
  await f.pass();
  retrying(f);
  return f;
};
const denyPayloads = (f: Fixture, status: number) =>
  f.payload.mock.mockImplementation(async () => {
    throw new HemligError(status, "denied");
  });
const retryTimer = (f: Fixture) =>
  (f.controller as unknown as { reconcileTimer?: NodeJS.Timeout }).reconcileTimer;
const importReason = (f: Fixture, index: number) => condition(f.imports[index]!, "Ready")?.reason;

test("G1: a remote 403 while the grant still allows read keeps targets and does not stall the checkpoint", async (t) => {
  const f = await importFixture(t);
  f.onConfig(() => f.config);
  denyPayloads(f, 403);
  const before = f.configReads.mock.callCount();
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(f.secrets.has("import-b"), true);
  assert.equal(importReason(f, 0), "RemoteAccessDenied");
  assert.equal(importReason(f, 1), "RemoteAccessDenied");
  assert.equal(f.configReads.mock.callCount(), before + 1);
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-2");
});

test("G2: a 403 confirmed by an identity_not_active config read keeps targets and retries without advancing", async (t) => {
  const f = await importFixture(t);
  f.onConfig(() => {
    throw new HemligError(403, "inactive", "identity_not_active");
  });
  denyPayloads(f, 403);
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(importReason(f, 0), "AuthenticationFailed");
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
  assert.ok(retryTimer(f));
});

test("G3: an unconfirmed revocation (config read network error) keeps targets", async (t) => {
  const f = await importFixture(t);
  f.onConfig(() => {
    throw new Error("network");
  });
  denyPayloads(f, 403);
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(importReason(f, 0), "RevocationUnconfirmed");
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
  assert.ok(retryTimer(f));
});

test("G4: a remote 404 confirmed by a successful config that drops the grant deletes the target", async (t) => {
  const f = await importFixture(t);
  f.onConfig(() => ({
    ...f.config,
    grant: {
      ...f.config.grant,
      secretGrants: f.config.grant.secretGrants.filter(
        (entry) => entry.secretId !== "a",
      ),
    },
  }));
  f.payload.mock.mockImplementation(async (name: string) => {
    if (name === "a") throw new HemligError(404, "gone");
    return undefined;
  });
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), false);
  assert.equal(f.secrets.has("import-b"), true);
  assert.equal(importReason(f, 0), "AccessRevoked");
});

test("G5: code-less 403 on both the read and the confirmation keeps targets", async (t) => {
  const f = await importFixture(t);
  f.onConfig(() => {
    throw new HemligError(403, "forbidden");
  });
  denyPayloads(f, 403);
  await f.controller.reconcileAll();
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(f.secrets.has("import-b"), true);
  assert.equal(importReason(f, 0), "AuthenticationFailed");
});

test("G6: a secret without a value yet is AwaitingValue and is not re-fetched on later passes", async (t) => {
  const f = fixture(t);
  f.records.set("a", { ...f.records.get("a")!, state: "PENDING_VALUE" });
  await f.pass();
  const payloadCalls = () =>
    f.payload.mock.calls.filter((call) => call.arguments[0] === "a").length;
  assert.equal(payloadCalls(), 0);
  assert.equal(importReason(f, 0), "AwaitingValue");
  assert.equal(f.secrets.has("import-a"), false);
  assert.equal(f.consumer.status?.syncCursor, "checkpoint-1");
  await f.pass();
  assert.equal(payloadCalls(), 0);
  assert.equal(importReason(f, 0), "AwaitingValue");
});

test("G7: an expired identity reports AuthenticationFailed, retains identity status, and keeps targets", async (t) => {
  const f = fixture(t, { identity: makeIdentity(300) });
  await f.pass();
  const notAfter = f.consumer.status?.identity.notAfter;
  f.sync.mock.mockImplementationOnce(async () => {
    throw new HemligError(403, "inactive", "identity_not_active");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "Ready")?.reason, "AuthenticationFailed");
  assert.equal(f.consumer.status?.identity.notAfter, notAfter);
  assert.equal(importReason(f, 0), "ConsumerNotReady");
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(f.secrets.has("import-b"), true);
  assert.deepEqual(f.removed, ["ns/consumer"]);
});

const pendingNext = (f: Fixture) => {
  const pair = keyPair();
  const now = Date.now();
  const crt = issue(
    forge.pki.publicKeyFromPem(pair.publicKeyPem),
    new Date(now - 3_600_000),
    new Date(now + 365 * day),
  );
  Object.assign(f.secrets.get("identity").data, {
    "hemlig.io.next-tls.key": b64(pair.privateKeyPem),
    "hemlig.io.next-tls.crt": b64(crt),
  });
  return crt;
};
/** Old certificate is rejected by sync; any other certificate authenticates. */
const rejectOldSync = (f: Fixture) => {
  f.sync.mock.mockImplementation(async function (
    this: { transport: { options: { cert?: Buffer } } },
    query: { syncCursor?: string } = {},
  ) {
    if (this.transport.options.cert?.toString() === f.original)
      throw new HemligError(403, "inactive", "identity_not_active");
    return {
      config: f.config,
      snapshot: query.syncCursor === undefined,
      changes: [...f.records.values()],
      syncCursor: "checkpoint-1",
    };
  });
};

test("L2: a rejected old certificate with a valid persisted successor swaps and continues Ready", async (t) => {
  const f = fixture(t, { identity: makeIdentity(300) });
  await f.pass();
  const nextCrt = pendingNext(f);
  f.onConfig(() => f.config);
  rejectOldSync(f);
  await f.pass();
  assert.equal(data(f, "tls.crt"), nextCrt);
  assert.equal(data(f, "hemlig.io.previous-tls.crt"), f.original);
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
  assert.equal(condition(f.consumer, "Ready")?.status, "True");
  assert.equal(f.ensured.at(-1)?.certificate.toString(), nextCrt);
  assert.equal(f.rotate.mock.callCount(), 0);
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(importReason(f, 0), "TargetReady");
});

test("L2: a successor that fails verification leaves AuthenticationFailed with pending keys and targets kept", async (t) => {
  const f = fixture(t, { identity: makeIdentity(300) });
  await f.pass();
  const nextCrt = pendingNext(f);
  f.onConfig(() => {
    throw new HemligError(403, "inactive", "identity_not_active");
  });
  rejectOldSync(f);
  await f.pass();
  assert.equal(condition(f.consumer, "Ready")?.reason, "AuthenticationFailed");
  assert.equal(data(f, "tls.crt"), f.original);
  assert.equal(data(f, "hemlig.io.next-tls.crt"), nextCrt);
  assert.ok(data(f, "hemlig.io.next-tls.key"));
  assert.equal(f.secrets.has("import-a"), true);
  assert.equal(f.secrets.has("import-b"), true);
});

test("L3: an operator changing tls.crt before the swap prevents the swap and is left intact", async (t) => {
  const f = dueFixture(t);
  const operator = makeIdentity(200);
  f.onConfig(() => {
    const secret = f.secrets.get("identity");
    secret.data["tls.crt"] = b64(operator.crtPem);
    secret.data["tls.key"] = b64(operator.keyPem);
    return f.config;
  });
  await f.pass();
  assert.equal(data(f, "tls.crt"), operator.crtPem);
  assert.equal(data(f, "tls.key"), operator.keyPem);
  assert.equal(data(f, "hemlig.io.previous-tls.crt"), undefined);
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationFailed");
});

test("C1: identity_already_rotated reports and keeps the pending key", async (t) => {
  const f = dueFixture(t);
  f.onRotate(async () => {
    throw new HemligError(409, "rotated", "identity_already_rotated");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "IdentityAlreadyRotated");
  assert.ok(data(f, "hemlig.io.next-tls.key"));
  assert.ok(data(f, "hemlig.io.next-csr"));
});

test("C2: rotation_replay_inactive discards the pending key", async (t) => {
  const f = dueFixture(t);
  f.onRotate(async () => {
    throw new HemligError(409, "inactive", "rotation_replay_inactive");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "RotationRejected");
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
});

test("C3: a 403 identity_not_active while verifying the successor discards it", async (t) => {
  const f = dueFixture(t);
  f.onConfig(() => {
    throw new HemligError(403, "inactive", "identity_not_active");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "VerificationFailed");
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
  assert.equal(data(f, "tls.crt"), f.original);
});

test("C4: a code-less 403 at rotate time is AuthenticationFailed and keeps the pending key", async (t) => {
  const f = dueFixture(t);
  f.onRotate(async () => {
    throw new HemligError(403, "forbidden");
  });
  await f.pass();
  assert.equal(condition(f.consumer, "IdentityRotation")?.reason, "AuthenticationFailed");
  assert.ok(data(f, "hemlig.io.next-tls.key"));
  assert.ok(data(f, "hemlig.io.next-csr"));
});

test("L4: a resourceVersion conflict on the pending-key write is resumable with a single issuance", async (t) => {
  const f = dueFixture(t);
  const replace = f.core.replaceNamespacedSecret.bind(f.core);
  let conflicted = false;
  f.core.replaceNamespacedSecret = async (input: { name: string; body: any }) => {
    if (!conflicted && input.body.data["hemlig.io.next-tls.key"] !== undefined) {
      conflicted = true;
      // A concurrent writer bumps the Secret between our read and write.
      const stored = f.secrets.get(input.name);
      stored.metadata.resourceVersion = "99";
    }
    return replace(input);
  };
  await f.pass();
  assert.ok(conflicted);
  assert.equal(f.rotate.mock.callCount(), 0);
  assert.equal(data(f, "tls.crt"), f.original);
  assert.equal(data(f, "hemlig.io.next-tls.key"), undefined);
  await f.pass();
  assert.equal(f.rotate.mock.callCount(), 1);
  assert.notEqual(data(f, "tls.crt"), f.original);
  for (const key of pendingKeys) assert.equal(data(f, key), undefined);
});
