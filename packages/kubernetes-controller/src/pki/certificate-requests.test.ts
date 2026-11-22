import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { CertificateRequestReconciler } from "./certificate-requests";
import { IssuerReconciler } from "./issuers";
import {
  chainPem,
  consumerObject,
  crObject,
  crUid,
  csrPem,
  errorResponse,
  flush,
  grantBody,
  leafPem,
  registered,
  rig,
  rootPem,
  FakeTransport,
} from "./test-fakes";

const KEY = "cr/app/cr-1";
const ISSUER_KEY = "issuer/app/issuer";
const b64 = (value: string) => Buffer.from(value, "utf8").toString("base64");

const setup = (
  options: Parameters<typeof crObject>[0] & {
    issuer?:
      boolean | { ready?: boolean; generation?: number; observed?: number };
  } = {},
) => {
  const r = rig();
  const { issuer, ...crOptions } = options;
  if (issuer !== false) {
    const spec = typeof issuer === "object" ? issuer : {};
    const generation = spec.generation ?? 1;
    r.custom.put("hemligissuers", {
      metadata: {
        name: "issuer",
        namespace: "app",
        uid: "issuer-uid",
        generation,
      },
      spec: { consumerRef: "consumer", issuanceGrant: "grant-one" },
      status: {
        observedGeneration: spec.observed ?? generation,
        consumerId: "agent",
        conditions: [
          {
            type: "Ready",
            status: spec.ready === false ? "False" : "True",
            reason: spec.ready === false ? "CaNotActive" : "Ready",
            message: "m",
            lastTransitionTime: "2026-05-01T00:00:00Z",
          },
        ],
      },
    });
  }
  r.custom.put("certificaterequests", crObject(crOptions));
  const message = () => r.ready()?.message as string | undefined;
  return { ...r, message };
};
const crWrites = (r: ReturnType<typeof setup>) =>
  r.custom.count("replaceStatus", "certificaterequests");

test("another group or kind is ignored entirely", async () => {
  for (const issuerRef of [
    { group: "cert-manager.io", kind: "Issuer", name: "issuer" },
    { kind: "HemligIssuer", name: "issuer" },
    { group: "hemlig.zyno.io", kind: "Issuer", name: "issuer" },
  ]) {
    const r = setup({ spec: { issuerRef } });
    await r.run(KEY);
    assert.equal(r.custom.count("get", "hemligissuers"), 0);
    assert.equal(r.transport.requests.length, 0);
    assert.equal(crWrites(r), 0);
  }
});

test("an unapproved request waits and rewrites nothing", async () => {
  const r = setup({ approved: false });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Pending");
  assert.equal(r.message(), "Waiting for approval");
  assert.equal(r.transport.requests.length, 0);
  assert.equal(r.queue.scheduledDelay(KEY), undefined);
  await r.run(KEY);
  assert.equal(crWrites(r), 1);
});

test("Denied and InvalidRequest end the request without a call", async () => {
  const denied = setup({
    conditions: [
      { type: "Denied", status: "True", reason: "x", message: "no" },
    ],
  });
  await denied.run(KEY);
  assert.equal(denied.ready().reason, "Denied");
  assert.equal(denied.message(), "The CertificateRequest was denied.");
  assert.match(
    denied.cr().status.failureTime,
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/,
  );
  assert.equal(denied.transport.requests.length, 0);
  const invalid = setup({
    conditions: [{ type: "InvalidRequest", status: "True" }],
  });
  await invalid.run(KEY);
  assert.equal(invalid.ready().reason, "Failed");
  assert.equal(
    invalid.message(),
    "The CertificateRequest is marked InvalidRequest.",
  );
  assert.equal(invalid.transport.requests.length, 0);
});

test("terminal requests are untouched", async () => {
  const forms: object[][] = [
    [{ type: "Ready", status: "True", reason: "Issued" }],
    [{ type: "Ready", status: "False", reason: "Failed" }],
    [{ type: "Ready", status: "False", reason: "Denied" }],
  ];
  for (const conditions of forms) {
    const r = setup({ conditions });
    await r.run(KEY);
    assert.equal(crWrites(r), 0);
    assert.equal(r.transport.requests.length, 0);
  }
  const withCert = setup();
  withCert.custom.update("certificaterequests", "app", "cr-1", (o) => {
    o.status.certificate = "Zm9v";
  });
  await withCert.run(KEY);
  assert.equal(crWrites(withCert), 0);
  assert.equal(withCert.transport.requests.length, 0);
});

test("issuance sends the five-field body and writes the certificate", async () => {
  const r = setup({
    metadata: {
      annotations: {
        "cert-manager.io/certificate-name": "web",
        "cert-manager.io/certificate-revision": "2",
      },
    },
  });
  const approved = structuredClone(r.cr().status.conditions[0]);
  await r.run(KEY);
  const post = r.transport.posts()[0]!;
  assert.equal(
    post.url.pathname,
    "/v1/pki/issuance-grants/grant-one/certificates",
  );
  assert.equal(post.headers?.["idempotency-key"], `hml-cr-${crUid}`);
  assert.deepEqual(post.body, {
    certificateSigningRequestPem: csrPem,
    durationSeconds: 3600,
    usages: ["serverAuth"],
    isCA: false,
    requester: {
      kubernetes: {
        namespace: "app",
        name: "cr-1",
        uid: crUid,
        certificateName: "web",
        revision: "2",
      },
    },
  });
  const status = r.cr().status;
  assert.deepEqual(status.conditions[0], approved);
  assert.equal(r.ready().status, "True");
  assert.equal(r.ready().reason, "Issued");
  assert.equal(r.message(), "Issued by ca-issuing-1, serial 0a1b2c3d");
  assert.equal(status.certificate, b64(leafPem + chainPem));
  assert.equal(status.ca, b64(rootPem));
  assert.equal(status.failureTime, undefined);
  assert.equal(r.core.secretWrites, 0);
  assert.equal(r.pending.has(KEY), false);
});

test("a status conflict re-reads and keeps foreign conditions; only PUT is used", async () => {
  const r = setup();
  const original = structuredClone(r.cr().status.conditions[0]);
  const foreign = { type: "Custom", status: "True", reason: "Other" };
  r.custom.beforeReplace(() =>
    r.custom.update("certificaterequests", "app", "cr-1", (o) => {
      o.status.conditions.push(foreign);
    }),
  );
  await r.run(KEY);
  const conditions = r.cr().status.conditions;
  assert.deepEqual(conditions[0], original);
  assert.deepEqual(conditions[1], foreign);
  assert.equal(conditions[2].type, "Ready");
  assert.equal(conditions[2].status, "True");
  assert.equal(r.transport.posts().length, 1);
  assert.equal(crWrites(r), 2);
  for (const call of r.custom.calls) {
    if (call.plural === "certificaterequests") {
      assert.ok(
        ["get", "list", "replaceStatus"].includes(call.method),
        call.method,
      );
    }
  }
});

test("a recreated CertificateRequest never receives the old result", async () => {
  const r = setup();
  const newUid = "99999999-2222-3333-4444-555555555555";
  let swapped = false;
  const original = r.transport.handler;
  r.transport.handler = (request) => {
    if (request.method === "POST" && !swapped) {
      swapped = true;
      r.custom.remove("certificaterequests", "app", "cr-1");
      r.custom.put("certificaterequests", crObject({ uid: newUid }));
    }
    return original(request);
  };
  await r.run(KEY);
  const posts = r.transport.posts();
  assert.equal(posts.length, 2);
  assert.equal(posts[0]!.headers?.["idempotency-key"], `hml-cr-${crUid}`);
  assert.equal(posts[1]!.headers?.["idempotency-key"], `hml-cr-${newUid}`);
  const puts = r.custom.calls.filter((c) => c.method === "replaceStatus");
  assert.equal(
    (puts[0]!.body as { metadata: { uid: string } }).metadata.uid,
    crUid,
  );
  assert.equal(r.cr().metadata.uid, newUid);
  assert.equal(r.ready().reason, "Issued");
  assert.equal(puts.length, 2);
});

test("a terminal state written by another writer is not overwritten", async () => {
  const r = setup();
  r.custom.beforeReplace(() =>
    r.custom.update("certificaterequests", "app", "cr-1", (o) => {
      o.status.conditions.push({
        type: "Ready",
        status: "False",
        reason: "Failed",
        message: "other writer",
      });
    }),
  );
  await r.run(KEY);
  assert.equal(r.message(), "other writer");
  assert.equal(r.cr().status.certificate, undefined);
});

test("issuance_revoked fails the request without a certificate", async () => {
  const r = setup();
  r.transport.handler = () =>
    errorResponse(409, "issuance_revoked", { reason: "certificate_revoked" });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Failed");
  assert.equal(r.message(), "issuance_revoked (certificate_revoked)");
  assert.ok(r.cr().status.failureTime);
  assert.equal(r.cr().status.certificate, undefined);
  assert.equal(r.core.secretWrites, 0);
  assert.equal(r.queue.scheduledDelay(KEY), undefined);
});

test("issuance_denied reports the denied name", async () => {
  const r = setup();
  r.transport.handler = () =>
    errorResponse(403, "issuance_denied", {
      reason: "name_not_permitted",
      deniedNameType: "dns",
      deniedName: "api.not-granted.example.com",
    });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Failed");
  assert.match(r.message()!, /name_not_permitted/);
  assert.match(r.message()!, /api\.not-granted\.example\.com/);
});

test("Retry-After 120 is honored with jitter", async () => {
  const r = setup();
  r.scheduler.randomValue = 1;
  r.transport.handler = () =>
    errorResponse(
      429,
      "issuance_rate_limited",
      { reason: "grant_hour" },
      {
        "retry-after": "120",
      },
    );
  await r.run(KEY);
  assert.equal(r.ready().reason, "Pending");
  assert.equal(r.queue.scheduledDelay(KEY), 132_000);
  await r.scheduler.advance(119_000);
  assert.equal(r.transport.posts().length, 1);
  await r.scheduler.advance(13_000);
  assert.equal(r.transport.posts().length, 2);
  r.queue.stop();
});

test("a gateway 429 backs off fast and doubles", async () => {
  const r = setup();
  r.scheduler.randomValue = 0;
  r.transport.handler = () => errorResponse(429);
  await r.run(KEY);
  assert.equal(r.queue.scheduledDelay(KEY), 500);
  assert.equal(r.message(), "HemligUnavailable (429)");
  await r.scheduler.advance(500);
  assert.equal(r.queue.scheduledDelay(KEY), 1_000);
  r.scheduler.randomValue = 1;
  await r.scheduler.advance(1_000);
  assert.equal(r.queue.scheduledDelay(KEY), 4_000);
  r.queue.stop();
});

test("ca_not_active retries slowly and enqueues the issuer", async () => {
  const r = setup();
  r.scheduler.randomValue = 0;
  r.transport.handler = (request) =>
    request.method === "GET"
      ? { status: 200, headers: {}, body: grantBody() }
      : errorResponse(409, "ca_not_active", { reason: "retired" });
  await r.run(KEY);
  assert.equal(r.message(), "ca_not_active (retired)");
  assert.equal(r.queue.scheduledDelay(KEY), 15_000);
  assert.ok(r.custom.count("patchStatus", "hemligissuers") >= 1);
  r.queue.stop();
});

test("a malformed response is InvalidResponse and retried", async () => {
  const r = setup();
  r.transport.handler = () => ({
    status: 201,
    headers: {},
    body: {
      caId: "ca-x",
      serial: "ab",
      certificatePem: "junk",
      chainPem: "",
      caPem: "",
    },
  });
  await r.run(KEY);
  assert.equal(
    r.message(),
    "InvalidResponse: Hemlig returned an unexpected certificate response",
  );
  assert.equal(r.cr().status.certificate, undefined);
  r.queue.stop();
});

test("replay after a transient failure, a rotation and a restart is identical", async () => {
  const r = setup();
  r.transport.handler = () => errorResponse(503);
  await r.run(KEY);
  r.registry.entries.set(
    "app/consumer",
    registered(r.transport, { identityFingerprint: "fp2" }),
  );
  r.transport.handler = () => errorResponse(503);
  await r.scheduler.advance(1_000);
  r.queue.stop();
  const restarted = new CertificateRequestReconciler(
    r.deps,
    new IssuerReconciler(r.deps, { add() {} }),
    { add() {} },
    new Set(),
  );
  await restarted.reconcile(KEY, { tryAcquire: () => () => {} });
  const posts = r.transport.posts();
  assert.ok(posts.length >= 3);
  for (const post of posts) {
    assert.equal(post.headers?.["idempotency-key"], `hml-cr-${crUid}`);
    assert.deepEqual(post.body, posts[0]!.body);
  }
});

test("the issuer generation gate holds the request until the issuer catches up", async () => {
  const r = setup({ issuer: { generation: 2, observed: 1 } });
  r.scheduler.randomValue = 0;
  const base = r.transport.handler;
  // The refresh the request triggers must not heal the issuer yet.
  r.transport.handler = (request) =>
    request.method === "GET" ? errorResponse(503) : base(request);
  await r.run(KEY);
  assert.equal(r.message(), "IssuerNotReady: HemligIssuer issuer (Stale)");
  r.transport.handler = base;
  assert.equal(r.transport.posts().length, 0);
  // The issuer reconciles to generation 2 and wakes the waiting request.
  r.queue.add(ISSUER_KEY, { resetBackoff: true });
  await r.queue.whenIdle();
  await flush();
  await r.queue.whenIdle();
  assert.equal(r.ready().reason, "Issued");
  assert.equal(r.transport.posts().length, 1);
});

test("a not-Ready issuer reports its reason", async () => {
  const r = setup({ issuer: { ready: false } });
  r.transport.handler = () => errorResponse(503);
  await r.run(KEY);
  assert.equal(
    r.message(),
    "IssuerNotReady: HemligIssuer issuer (CaNotActive)",
  );
  r.queue.stop();
});

test("a missing issuer is Pending IssuerNotFound", async () => {
  const r = setup({ issuer: false });
  await r.run(KEY);
  assert.equal(r.message(), "IssuerNotFound: HemligIssuer issuer not found");
  assert.ok(r.queue.scheduledDelay(KEY) !== undefined);
  r.queue.stop();
});

test("an invalid issuerRef.name fails the request", async () => {
  const r = setup({
    spec: {
      issuerRef: {
        group: "hemlig.zyno.io",
        kind: "HemligIssuer",
        name: "Bad_Name",
      },
    },
  });
  await r.run(KEY);
  assert.equal(r.ready().reason, "Failed");
  assert.equal(r.message(), "UnsupportedRequest: invalid issuerRef.name");
});

test("a withdrawn cross-namespace opt-in blocks issuance even with a stale registry", async () => {
  const r = setup({ issuer: false });
  r.custom.put("hemligissuers", {
    metadata: { name: "issuer", namespace: "app", uid: "i", generation: 1 },
    spec: {
      consumerRef: "consumer",
      consumerNamespace: "other",
      issuanceGrant: "grant-one",
    },
    status: {
      observedGeneration: 1,
      consumerId: "agent",
      conditions: [{ type: "Ready", status: "True", reason: "Ready" }],
    },
  });
  const other = consumerObject({ allowCrossNamespaceReferences: false });
  other.metadata.namespace = "other";
  r.custom.put("hemligconsumers", other);
  r.registry.entries.set(
    "other/consumer",
    registered(r.transport, { key: "other/consumer" }),
  );
  await r.run(KEY);
  assert.equal(r.message()?.split(":")[0], "ConsumerReferenceNotPermitted");
  assert.equal(r.ready().reason, "Pending");
  assert.equal(r.transport.requests.length, 0);
  assert.ok(r.custom.count("patchStatus", "hemligissuers") >= 1);
  r.queue.stop();
});

const clusterSetup = (
  consumerSpec: Record<string, unknown>,
  allowedNamespaces?: object,
) => {
  const r = setup({
    issuer: false,
    spec: {
      issuerRef: {
        group: "hemlig.zyno.io",
        kind: "HemligClusterIssuer",
        name: "shared",
      },
    },
  });
  r.custom.put("hemligclusterissuers", {
    metadata: { name: "shared", uid: "ci", generation: 1 },
    spec: {
      consumerRef: { name: "consumer", namespace: "app" },
      issuanceGrant: "grant-one",
      ...(allowedNamespaces === undefined ? {} : { allowedNamespaces }),
    },
    status: {
      observedGeneration: 1,
      consumerId: "agent",
      conditions: [{ type: "Ready", status: "True", reason: "Ready" }],
    },
  });
  r.custom.put("hemligconsumers", consumerObject(consumerSpec));
  return r;
};

test("a cluster issuer needs allowClusterIssuers", async () => {
  const r = clusterSetup({ allowCrossNamespaceReferences: true });
  await r.run(KEY);
  assert.equal(r.message()?.split(":")[0], "ClusterIssuerNotPermitted");
  assert.equal(r.transport.posts().length, 0);
  r.queue.stop();
  const ok = clusterSetup({ allowClusterIssuers: true });
  await ok.run(KEY);
  assert.equal(ok.ready().reason, "Issued");
});

test("a cluster issuer's allowedNamespaces rejects other namespaces for good", async () => {
  const r = clusterSetup(
    { allowClusterIssuers: true },
    { matchLabels: { env: "prod" } },
  );
  await r.run(KEY);
  assert.equal(r.ready().reason, "Failed");
  assert.equal(
    r.message(),
    "NamespaceNotPermitted: namespace app is not selected by HemligClusterIssuer shared",
  );
  assert.equal(r.transport.requests.length, 0);
  r.core.labels.set("app", { env: "prod" });
  const again = clusterSetup(
    { allowClusterIssuers: true },
    { matchLabels: { env: "prod" } },
  );
  again.core.labels.set("app", { env: "prod" });
  await again.run(KEY);
  assert.equal(again.ready().reason, "Issued");
});

test("a namespace that stops matching the provider selector blocks issuance", async () => {
  const r = setup();
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
  await r.run(KEY);
  assert.equal(r.message()?.split(":")[0], "ProviderNotPermitted");
  assert.equal(r.transport.posts().length, 0);
  r.queue.stop();
});

test("a CA request or unsupported usage fails without a call", async () => {
  const ca = setup({ spec: { isCA: true } });
  await ca.run(KEY);
  assert.equal(ca.ready().reason, "Failed");
  assert.equal(
    ca.message(),
    "UnsupportedRequest: CA certificates are not issued by Hemlig",
  );
  assert.equal(ca.transport.posts().length, 0);
  const usage = setup({ spec: { usages: ["code signing"] } });
  await usage.run(KEY);
  assert.equal(usage.ready().reason, "Failed");
  assert.match(usage.message()!, /^UnsupportedRequest: usage "code signing"/);
  assert.equal(usage.transport.posts().length, 0);
});

test("logs never contain CSRs, certificates, tokens or server messages", async (t: TestContext) => {
  const captured: string[] = [];
  const sink = (chunk: unknown) => {
    captured.push(String(chunk));
    return true;
  };
  t.mock.method(process.stderr, "write", sink);
  t.mock.method(console, "log", (...args: unknown[]) =>
    captured.push(args.join(" ")),
  );
  t.mock.method(console, "error", (...args: unknown[]) =>
    captured.push(args.join(" ")),
  );
  const outcomes: ((r: ReturnType<typeof setup>) => void)[] = [
    () => {},
    (r) => {
      r.transport.handler = () =>
        errorResponse(403, "issuance_denied", {
          reason: "name_not_permitted",
          deniedNameType: "dns",
          deniedName: "x.example.com",
        });
    },
    (r) => {
      r.transport.handler = () => errorResponse(503);
    },
    (r) => {
      r.transport.handler = () =>
        errorResponse(409, "issuance_revoked", {
          reason: "certificate_revoked",
        });
    },
  ];
  for (const configure of outcomes) {
    const r = setup();
    configure(r);
    await r.run(KEY);
    r.queue.stop();
  }
  t.mock.restoreAll();
  const text = captured.join("\n");
  assert.ok(text.includes("Hemlig PKI:"));
  for (const forbidden of [
    "-----BEGIN",
    b64(csrPem),
    b64(leafPem),
    "certificatePem",
    "Bearer",
    "hmlb_",
    "SECRET",
  ]) {
    assert.ok(!text.includes(forbidden), forbidden);
  }
});

test("an issuer turning Ready during a run still wakes the waiting request", async () => {
  const r = setup({ issuer: { ready: false } });
  r.scheduler.randomValue = 0;
  const base = r.transport.handler;
  r.transport.handler = (request) =>
    request.method === "GET" ? errorResponse(503) : base(request);
  await r.run(KEY);
  assert.equal(r.message()?.split(" ")[0], "IssuerNotReady:");
  // Isolate the wake-up: no issuer retry may heal the issuer on its own.
  r.queue.forget(ISSUER_KEY);
  r.transport.handler = base;
  const readNamespace = r.core.readNamespace.bind(r.core);
  let hooked = false;
  r.core.readNamespace = async (input: { name: string }) => {
    if (!hooked) {
      hooked = true;
      // The issuer reconciles to Ready between the CR's issuer read and its wait.
      await r.issuers.reconcile(ISSUER_KEY, { tryAcquire: () => () => {} });
    }
    return readNamespace(input);
  };
  await r.scheduler.advance(15_000);
  await r.queue.whenIdle();
  assert.equal(hooked, true);
  assert.equal(r.ready().reason, "Issued");
  assert.equal(r.scheduler.pendingTimers, 0);
});

const onNamespaceRead = (
  r: ReturnType<typeof setup>,
  fn: () => void | Promise<void>,
) => {
  const original = r.core.readNamespace.bind(r.core);
  let fired = false;
  r.core.readNamespace = async (input: { name: string }) => {
    if (!fired) {
      fired = true;
      await fn();
    }
    return original(input);
  };
};

test("an InvalidRequest or Denied added mid-run stops the call before Hemlig", async () => {
  for (const [type, reason] of [
    ["InvalidRequest", "Failed"],
    ["Denied", "Denied"],
  ] as const) {
    const r = setup();
    onNamespaceRead(r, () =>
      r.custom.update("certificaterequests", "app", "cr-1", (o) => {
        o.status.conditions.push({ type, status: "True" });
      }),
    );
    await r.run(KEY);
    assert.equal(r.transport.posts().length, 0, type);
    assert.equal(r.ready().reason, reason, type);
    assert.equal(r.cr().status.certificate, undefined);
  }
});

test("a request denied after the call is never written as Issued", async () => {
  for (const type of ["InvalidRequest", "Denied"]) {
    const r = setup();
    const base = r.transport.handler;
    r.transport.handler = (request) => {
      if (request.method === "POST") {
        r.custom.update("certificaterequests", "app", "cr-1", (o) => {
          o.status.conditions.push({ type, status: "True" });
        });
      }
      return base(request);
    };
    await r.run(KEY);
    assert.equal(r.transport.posts().length, 1);
    assert.equal(r.ready(), undefined, type);
    assert.equal(r.cr().status.certificate, undefined);
  }
});

test("a registry entry replaced mid-run blocks the call and retries", async () => {
  const r = setup();
  const other = new FakeTransport();
  r.scheduler.randomValue = 0;
  onNamespaceRead(r, () => {
    r.registry.entries.set("app/consumer", registered(other));
  });
  await r.run(KEY);
  assert.equal(r.transport.posts().length, 0);
  assert.equal(r.transport.requests.length, 0);
  assert.equal(other.posts().length, 1);
  assert.equal(r.ready().reason, "Issued");
});

test("a replaced registry entry leaves the pending message when it cannot recover", async () => {
  const r = setup();
  const other = new FakeTransport();
  other.handler = () => errorResponse(503);
  onNamespaceRead(r, () => {
    r.registry.entries.set("app/consumer", registered(other));
  });
  await r.run(KEY);
  assert.equal(r.transport.posts().length, 0);
  assert.ok(r.queue.scheduledDelay(KEY) !== undefined);
  r.queue.stop();
});
