import assert from "node:assert/strict";
import test from "node:test";
import {
  CONFIGMAP_MAX_BYTES,
  CRL_NUMBER_ANNOTATION,
  CRL_SHA256_ANNOTATION,
  MANAGED_BY_LABEL,
  OWNER_ANNOTATION,
  pkiConfigFromEnvironment,
} from "./types";
import {
  certificateData,
  configMapPayloadBytes,
  crlConfigMapName,
  derSha256OfPemBlock,
  derToPem,
  freshness,
  isOwnedByTrustBundle,
  pemCertificateBlocks,
  readyFor,
  storedCrl,
  type ReadyInput,
} from "./trust-bundles";
import {
  bundleObject,
  bundleRig,
  caView,
  consumerObject,
  crlFixture,
  fault,
  pemOf,
  registered,
  rootPem,
  sha256Of,
} from "./test-fakes";

const EXT = `ext-${"ab".repeat(20)}`;
const withExt = (id: string) => [
  { id, source: "GENERATED" },
  { id: EXT, source: "UPLOADED" },
];
const crlName = (id: string) => `trust-crl-${id}`;

type Rig = ReturnType<typeof bundleRig>;

/** A bundle plus a server that knows every CA in `ids`, each with its own CRL and the shared external one. */
const setup = (
  spec: Record<string, unknown> = {},
  ids: readonly string[] = ["ca-aaa"],
  options: { withExt?: boolean } = {},
): Rig => {
  const r = bundleRig();
  r.custom.put(
    "hemligtrustbundles",
    bundleObject({ caIds: [...ids], ...spec }),
  );
  for (const id of ids) {
    r.server.views.set(
      id,
      caView(id, {
        crlIssuers:
          options.withExt === false
            ? [{ id, source: "GENERATED" }]
            : withExt(id),
      }),
    );
    r.server.crls.set(id, crlFixture(40, "1", "2027-01-01T00:00:00.000Z", 1));
  }
  if (options.withExt !== false) {
    r.server.crls.set(EXT, crlFixture(50, "9", "2027-01-01T00:00:00.000Z", 2));
  }
  return r;
};

const cm = (r: Rig, name: string) => r.core.configMap("app", name);
const crlRequests = (r: Rig, id: string) =>
  r.transport.requests.filter((q) => q.url.pathname === `/v1/pki/crls/${id}`);
const writes = (r: Rig, name: string) =>
  r.core.callsOf("create", name).length +
  r.core.callsOf("replace", name).length;
const crlEntry = (r: Rig, id: string) =>
  r.bundle().status?.crls?.find((c: { id: string }) => c.id === id);

// -- Pure helpers ----------------------------------------------------------------

test("crlConfigMapName, derToPem and the PEM helpers", () => {
  assert.equal(crlConfigMapName("trust", "ca-x"), "trust-crl-ca-x");
  const der = Buffer.alloc(100, 3);
  const pem = derToPem(der);
  const lines = pem.split("\n");
  assert.equal(lines[0], "-----BEGIN X509 CRL-----");
  assert.equal(lines.at(-2), "-----END X509 CRL-----");
  assert.equal(lines.at(-1), "");
  for (const line of lines.slice(1, -2)) assert.ok(line.length <= 64);
  assert.equal(lines[1]?.length, 64);
  assert.deepEqual(pemCertificateBlocks(pemOf("a") + "junk" + pemOf("b")), [
    pemOf("a"),
    pemOf("b"),
  ]);
  assert.equal(derSha256OfPemBlock(pemOf("a")), sha256Of(Buffer.from("a")));
});

test("certificateData deduplicates, sorts by caId and lets distrust win", () => {
  const view = (
    caId: string,
    anchorTrusted: boolean,
    anchorLabel = "root",
  ) => ({
    caId,
    anchorTrusted,
    anchorPem: pemOf(anchorLabel),
    chainPem: pemOf(caId) + pemOf("shared"),
  });
  const data = certificateData([
    view("ca-b", true),
    view("ca-a", true),
    view("ca-c", true, "other"),
  ]);
  assert.equal(data["ca.crt"], pemOf("root") + pemOf("other"));
  assert.equal(
    data["chain.crt"],
    pemOf("ca-a") + pemOf("shared") + pemOf("ca-b") + pemOf("ca-c"),
  );
  const distrusted = certificateData([
    view("ca-a", false),
    view("ca-b", true),
    view("ca-c", true, "other"),
  ]);
  assert.equal(distrusted["ca.crt"], pemOf("other"));
  assert.equal(certificateData([])["ca.crt"], "");
});

test("configMapPayloadBytes counts decoded binaryData, never base64", () => {
  const bytes = Buffer.alloc(1_000_000, 1);
  assert.equal(
    configMapPayloadBytes({ binaryData: { a: bytes.toString("base64") } }),
    1_000_000,
  );
  assert.equal(
    configMapPayloadBytes({ data: { a: "héllo" }, binaryData: { b: "AAAA" } }),
    6 + 3,
  );
  assert.equal(configMapPayloadBytes({}), 0);
});

test("isOwnedByTrustBundle needs the label and the exact owner", () => {
  const meta = (labels: object, annotations: object) =>
    ({ labels, annotations }) as never;
  assert.equal(
    isOwnedByTrustBundle(
      meta(
        { [MANAGED_BY_LABEL]: "trust-bundle" },
        { [OWNER_ANNOTATION]: "app/b" },
      ),
      "app/b",
    ),
    true,
  );
  assert.equal(
    isOwnedByTrustBundle(
      meta({ [MANAGED_BY_LABEL]: "import" }, { [OWNER_ANNOTATION]: "app/b" }),
      "app/b",
    ),
    false,
  );
  assert.equal(
    isOwnedByTrustBundle(
      meta(
        { [MANAGED_BY_LABEL]: "trust-bundle" },
        { [OWNER_ANNOTATION]: "app/bb" },
      ),
      "app/b",
    ),
    false,
  );
  assert.equal(isOwnedByTrustBundle(undefined, "app/b"), false);
});

test("storedCrl verifies annotations, key, format and sha256", () => {
  const der = Buffer.from("crl-bytes");
  const annotations = {
    "hemlig.zyno.io/crl-issuer": "ca-x",
    "hemlig.zyno.io/crl-sha256": sha256Of(der),
    "hemlig.zyno.io/crl-number": "3",
    "hemlig.zyno.io/crl-this-update": "2026-06-01T00:00:00.000Z",
    "hemlig.zyno.io/crl-next-update": "2026-06-08T00:00:00.000Z",
  };
  const derCm = {
    metadata: { annotations },
    binaryData: { "crl.der": der.toString("base64") },
  };
  const pemCm = {
    metadata: { annotations },
    data: { "crl.pem": derToPem(der) },
  };
  assert.equal(storedCrl(derCm, "ca-x", "der")?.sha256, sha256Of(der));
  assert.equal(storedCrl(pemCm, "ca-x", "pem")?.number, "3");
  assert.equal(storedCrl(derCm, "ca-x", "pem"), undefined);
  assert.equal(storedCrl(pemCm, "ca-x", "der"), undefined);
  assert.equal(storedCrl(derCm, "ca-y", "der"), undefined);
  assert.equal(
    storedCrl(
      {
        ...derCm,
        binaryData: { "crl.der": Buffer.from("x").toString("base64") },
      },
      "ca-x",
      "der",
    ),
    undefined,
  );
  assert.equal(
    storedCrl({ ...derCm, data: { "crl.pem": "stray" } }, "ca-x", "der"),
    undefined,
  );
  assert.equal(
    storedCrl(
      { metadata: { annotations: {} }, binaryData: derCm.binaryData },
      "ca-x",
      "der",
    ),
    undefined,
  );
  assert.equal(
    storedCrl(
      {
        ...pemCm,
        data: {
          "crl.pem": derToPem(der).replace("\n-----END", "\n\n-----END"),
        },
      },
      "ca-x",
      "pem",
    ),
    undefined,
  );
});

test("freshness turns Stale exactly at nextUpdate", () => {
  const next = "2026-06-08T00:00:00.000Z";
  const at = Date.parse(next);
  assert.equal(freshness(next, at - 1), "Current");
  assert.equal(freshness(next, at), "Stale");
  assert.equal(freshness("garbage", 0), "Stale");
});

test("readyFor follows the precedence and keeps messages short", () => {
  const base: ReadyInput = {
    partial: false,
    keep: undefined,
    target: "unchanged",
    notFound: [],
    notActive: [],
    crls: [],
    drained: false,
  };
  const entry = (
    id: string,
    state: "Current" | "Stale" | "Missing" | "Rejected" | "Conflict",
    required = true,
  ) => ({
    id,
    source: "GENERATED" as const,
    configMap: id,
    state,
    required,
  });
  const reason = (input: Partial<ReadyInput>) => {
    const result = readyFor({ ...base, ...input });
    return "keep" in result ? "keep" : result.reason;
  };
  assert.equal(reason({}), "Ready");
  assert.equal(reason({ drained: true }), "CaDrained");
  assert.equal(
    reason({
      target: "conflict",
      notFound: ["a"],
      crls: [entry("x", "Stale")],
    }),
    "ConfigMapConflict",
  );
  assert.equal(reason({ crls: [entry("x", "Conflict")] }), "ConfigMapConflict");
  assert.equal(
    reason({ target: "rejected", notFound: ["a"] }),
    "ConfigMapRejected",
  );
  assert.equal(reason({ notFound: ["a"], notActive: ["b"] }), "CaNotFound");
  assert.equal(
    reason({ notActive: ["b"], crls: [entry("x", "Rejected")] }),
    "CaNotActive",
  );
  assert.equal(
    reason({ crls: [entry("x", "Rejected"), entry("y", "Missing")] }),
    "CrlRejected",
  );
  assert.equal(
    reason({ crls: [entry("x", "Missing"), entry("y", "Stale")] }),
    "CrlMissing",
  );
  assert.equal(reason({ crls: [entry("x", "Stale")] }), "CrlStale");
  assert.equal(reason({ crls: [entry("x", "Stale", false)] }), "Ready");
  assert.equal(
    reason({ crls: [entry("x", "Rejected", false)] }),
    "CrlRejected",
  );
  assert.equal(reason({ partial: true }), "RemoteError");
  const previous = {
    type: "Ready",
    status: "True",
    reason: "Ready",
    message: "m",
  };
  assert.equal(reason({ partial: true, keep: previous }), "keep");
  assert.equal(
    reason({ partial: true, keep: previous, notFound: ["z"] }),
    "CaNotFound",
  );
  const many = readyFor({
    ...base,
    notFound: ["g", "f", "e", "d", "c", "b", "a"],
  });
  assert.ok(!("keep" in many));
  assert.equal(
    (many as { message: string }).message,
    "CA not found: a, b, c, d, e, …",
  );
  const huge = readyFor({
    ...base,
    notFound: ["x".repeat(2000)],
  }) as { message: string };
  assert.equal(huge.message.length, 1024);
});

test("pkiConfigFromEnvironment parses the bundle interval", () => {
  assert.equal(pkiConfigFromEnvironment({}).bundleIntervalMs, 300_000);
  assert.equal(
    pkiConfigFromEnvironment({ HEMLIG_PKI_BUNDLE_INTERVAL_MS: "60000" })
      .bundleIntervalMs,
    60_000,
  );
  assert.equal(
    pkiConfigFromEnvironment({ HEMLIG_PKI_BUNDLE_INTERVAL_MS: "30000" })
      .bundleIntervalMs,
    30_000,
  );
  assert.equal(
    pkiConfigFromEnvironment({ HEMLIG_PKI_BUNDLE_INTERVAL_MS: "3600000" })
      .bundleIntervalMs,
    3_600_000,
  );
  for (const bad of ["abc", "29999", "3600001", "1e6", "-5", "6.5e4"]) {
    assert.throws(
      () => pkiConfigFromEnvironment({ HEMLIG_PKI_BUNDLE_INTERVAL_MS: bad }),
      /HEMLIG_PKI_BUNDLE_INTERVAL_MS must be an integer from 30000 to 3600000\./,
      bad,
    );
  }
  assert.equal(pkiConfigFromEnvironment({}).concurrency, 4);
  assert.throws(
    () => pkiConfigFromEnvironment({ HEMLIG_PKI_CONCURRENCY: "0" }),
    /HEMLIG_PKI_CONCURRENCY/,
  );
});

// -- Reconciler --------------------------------------------------------------------

test("the target holds the anchors only and the owned metadata is exact", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"]);
  r.server.views.set(
    "ca-bbb",
    caView("ca-bbb", {
      chainPem: pemOf("ca-bbb") + pemOf("int-1"),
      crlIssuers: withExt("ca-bbb"),
    }),
  );
  await r.run();
  const target = cm(r, "trust");
  assert.equal(target.data["ca.crt"], rootPem);
  assert.equal(
    target.data["chain.crt"],
    pemOf("ca-aaa") + pemOf("ca-bbb") + pemOf("int-1"),
  );
  assert.ok(!target.data["chain.crt"].includes(rootPem));
  assert.equal(target.metadata.labels[MANAGED_BY_LABEL], "trust-bundle");
  assert.equal(target.metadata.annotations[OWNER_ANNOTATION], "app/bundle");
  assert.equal(
    target.metadata.annotations["hemlig.zyno.io/ca-ids"],
    "ca-aaa,ca-bbb",
  );
  assert.deepEqual(target.metadata.ownerReferences, [
    {
      apiVersion: "hemlig.zyno.io/v1alpha1",
      kind: "HemligTrustBundle",
      name: "bundle",
      uid: "bundle-uid",
      controller: true,
    },
  ]);
  assert.equal(r.ready()?.reason, "Ready");
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa", "ca-bbb"]);
  assert.equal(r.bundle().status.consumerId, "agent");
  assert.equal(r.bundle().status.observedGeneration, 1);
});

test("one CRL ConfigMap per issuer, deduplicated, with the exact bytes and metadata", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"]);
  await r.run();
  assert.deepEqual(r.core.configMapNames("app"), [
    "trust",
    crlName("ca-aaa"),
    crlName("ca-bbb"),
    crlName(EXT),
  ]);
  const ext = cm(r, crlName(EXT));
  const fixture = r.server.crls.get(EXT) as ReturnType<typeof crlFixture>;
  assert.equal(
    Buffer.from(ext.binaryData["crl.der"], "base64").compare(fixture.der),
    0,
  );
  assert.equal(ext.data, undefined);
  assert.equal(
    ext.metadata.annotations[CRL_SHA256_ANNOTATION],
    sha256Of(fixture.der),
  );
  assert.equal(ext.metadata.annotations[CRL_NUMBER_ANNOTATION], "9");
  assert.equal(
    ext.metadata.annotations["hemlig.zyno.io/crl-source"],
    "UPLOADED",
  );
  assert.equal(ext.metadata.annotations["hemlig.zyno.io/crl-issuer"], EXT);
  assert.equal(ext.metadata.annotations[OWNER_ANNOTATION], "app/bundle");
  assert.equal(ext.metadata.ownerReferences[0].uid, "bundle-uid");
  assert.equal("blockOwnerDeletion" in ext.metadata.ownerReferences[0], false);
  assert.equal(
    cm(r, crlName("ca-aaa")).metadata.annotations["hemlig.zyno.io/crl-source"],
    "GENERATED",
  );
  assert.deepEqual(
    r.bundle().status.crls.map((c: { id: string }) => c.id),
    ["ca-aaa", "ca-bbb", EXT],
  );
  assert.deepEqual(crlEntry(r, EXT), {
    id: EXT,
    source: "UPLOADED",
    configMap: crlName(EXT),
    state: "Current",
    number: "9",
    thisUpdate: fixture.thisUpdate,
    nextUpdate: fixture.nextUpdate,
  });
});

test("the PEM format writes data only, in 64-column lines", async () => {
  const r = setup({ crlFormat: "pem" });
  await r.run();
  const fixture = r.server.crls.get("ca-aaa") as ReturnType<typeof crlFixture>;
  const stored = cm(r, crlName("ca-aaa"));
  assert.equal(stored.data["crl.pem"], derToPem(fixture.der));
  assert.equal(stored.binaryData, undefined);
  assert.ok(stored.data["crl.pem"].startsWith("-----BEGIN X509 CRL-----\n"));
  for (const line of stored.data["crl.pem"].split("\n").slice(1, -2)) {
    assert.ok(line.length <= 64);
  }
  assert.equal(r.ready()?.reason, "Ready");
});

test("an externally revoked CA keeps its anchor and the bundle stays Ready", async () => {
  const r = setup();
  r.server.views.set(
    "ca-aaa",
    caView("ca-aaa", { status: "REVOKED", crlIssuers: withExt("ca-aaa") }),
  );
  // The revoked CA's own CRL is no longer required; the external one still is.
  r.server.crls.set("ca-aaa", fault(404, "not_found", "crl_missing"));
  await r.run();
  assert.equal(cm(r, "trust").data["ca.crt"], rootPem);
  assert.ok(cm(r, "trust").data["chain.crt"].includes(pemOf("ca-aaa")));
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa"]);
  assert.equal(crlEntry(r, "ca-aaa").state, "Missing");
  assert.ok(cm(r, crlName(EXT)) !== undefined);
  assert.equal(crlEntry(r, EXT).state, "Current");
  assert.equal(r.ready()?.status, "True");
  assert.equal(r.ready()?.reason, "Ready");
});

test("a revoked CA still needs its external CRL", async () => {
  const r = setup();
  r.server.views.set(
    "ca-aaa",
    caView("ca-aaa", { status: "REVOKED", crlIssuers: withExt("ca-aaa") }),
  );
  r.server.crls.set("ca-aaa", fault(404, "not_found", "crl_missing"));
  r.server.crls.set(EXT, fault(404, "not_found", "crl_missing"));
  await r.run();
  assert.equal(crlEntry(r, EXT).state, "Missing");
  assert.equal(r.ready()?.reason, "CrlMissing");
});

test("distrust wins across CAs", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  r.server.views.set("ca-aaa", caView("ca-aaa", { anchorTrusted: false }));
  await r.run();
  assert.equal(cm(r, "trust").data["ca.crt"], "");
  assert.ok(cm(r, "trust").data["chain.crt"].includes(pemOf("ca-bbb")));
});

test("CaNotFound and CaNotActive exclude the CA and CaNotFound wins", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb", "ca-ccc", "ca-ddd"], {
    withExt: false,
  });
  r.server.views.set("ca-bbb", fault(404, "not_found", "ca_not_found"));
  r.server.views.set(
    "ca-ccc",
    fault(409, "ca_not_active", "pending_certificate"),
  );
  r.server.views.set("ca-ddd", caView("ca-ddd", { status: "FAILED" }));
  await r.run();
  const chain = cm(r, "trust").data["chain.crt"];
  assert.ok(chain.includes(pemOf("ca-aaa")));
  for (const id of ["ca-bbb", "ca-ccc", "ca-ddd"]) {
    assert.ok(!chain.includes(pemOf(id)));
  }
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa"]);
  assert.equal(r.ready()?.reason, "CaNotFound");
  assert.equal(r.ready()?.status, "False");
  r.edit({ caIds: ["ca-aaa", "ca-ccc", "ca-ddd"] });
  await r.run();
  assert.equal(r.ready()?.reason, "CaNotActive");
  assert.match(r.ready()?.message, /ca-ccc, ca-ddd/);
});

test("a rejected target keeps refreshing the CRLs of the accepted CAs", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  r.edit({ caIds: ["ca-aaa"] });
  await r.run();
  assert.equal(r.ready()?.reason, "Ready");
  r.core.rejectConfigMaps.add("trust");
  r.edit({ caIds: ["ca-aaa", "ca-bbb"] });
  await r.run();
  assert.equal(r.ready()?.reason, "ConfigMapRejected");
  assert.ok(!cm(r, "trust").data["chain.crt"].includes(pemOf("ca-bbb")));
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa"]);
  assert.equal(cm(r, crlName("ca-bbb")), undefined);
  r.server.crls.set(
    "ca-aaa",
    crlFixture(60, "2", "2027-02-01T00:00:00.000Z", 5),
  );
  await r.run();
  const fresh = cm(r, crlName("ca-aaa"));
  assert.equal(Buffer.from(fresh.binaryData["crl.der"], "base64").length, 60);
  assert.equal(fresh.metadata.annotations[CRL_NUMBER_ANNOTATION], "2");
  assert.equal(crlEntry(r, "ca-aaa").number, "2");
  assert.equal(r.ready()?.reason, "ConfigMapRejected");
});

test("an oversized target is refused locally with no write", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  r.edit({ caIds: ["ca-aaa"] });
  await r.run();
  const before = writes(r, "trust");
  r.server.views.set(
    "ca-bbb",
    caView("ca-bbb", { chainPem: pemOf("y".repeat(1_100_000)) }),
  );
  r.edit({ caIds: ["ca-aaa", "ca-bbb"] });
  await r.run();
  assert.equal(r.ready()?.reason, "ConfigMapRejected");
  assert.equal(writes(r, "trust"), before);
  assert.ok(r.core.maxWrittenBytes <= CONFIGMAP_MAX_BYTES);
});

test("freshness comes from the mounted copy", async () => {
  const r = setup({}, ["ca-aaa"]);
  r.server.crls.set(EXT, fault(404, "not_found", "crl_missing"));
  await r.run();
  assert.equal(crlEntry(r, EXT).state, "Missing");
  assert.equal(cm(r, crlName(EXT)), undefined);
  assert.equal(r.ready()?.reason, "CrlMissing");
  assert.equal(r.ready()?.status, "False");
  // The upload lands.
  r.server.crls.set(EXT, crlFixture(50, "9", "2026-06-08T00:00:00.000Z", 2));
  await r.run();
  assert.equal(crlEntry(r, EXT).state, "Current");
  assert.equal(r.ready()?.reason, "Ready");
  // Time passes while the server keeps answering 304.
  const version = cm(r, crlName(EXT)).metadata.resourceVersion;
  await r.scheduler.advance(8 * 86_400_000);
  await r.run();
  assert.equal(crlEntry(r, EXT).state, "Stale");
  assert.equal(cm(r, crlName(EXT)).metadata.resourceVersion, version);
  assert.equal(r.ready()?.reason, "CrlStale");
  // An outage leaves the mounted copy and its staleness in place.
  r.server.crls.set(EXT, fault(503, "service_unavailable"));
  await r.run();
  assert.equal(crlEntry(r, EXT).state, "Stale");
  assert.ok(cm(r, crlName(EXT)) !== undefined);
  assert.equal(cm(r, crlName(EXT)).metadata.resourceVersion, version);
  assert.equal(r.ready()?.reason, "CrlStale");
  assert.equal(r.queue.scheduledDelay(r.key) !== undefined, true);
});

test("size limits count decoded bytes and are enforced before the write", async () => {
  const big = setup({}, ["ca-aaa"], { withExt: false });
  big.server.crls.set(
    "ca-aaa",
    crlFixture(1_000_000, "4", "2027-01-01T00:00:00.000Z", 9),
  );
  await big.run();
  const stored = cm(big, crlName("ca-aaa"));
  assert.equal(
    Buffer.from(stored.binaryData["crl.der"], "base64").length,
    1_000_000,
  );
  assert.equal(big.ready()?.reason, "Ready");

  const pem = setup({ crlFormat: "pem" }, ["ca-aaa"], { withExt: false });
  await pem.run();
  const previous = cm(pem, crlName("ca-aaa")).data["crl.pem"];
  pem.server.crls.set(
    "ca-aaa",
    crlFixture(1_000_000, "5", "2027-01-01T00:00:00.000Z", 9),
  );
  await pem.run();
  assert.equal(pem.ready()?.reason, "CrlRejected");
  assert.equal(crlEntry(pem, "ca-aaa").state, "Rejected");
  assert.equal(cm(pem, crlName("ca-aaa")).data["crl.pem"], previous);
  assert.ok(pem.core.maxWrittenBytes <= CONFIGMAP_MAX_BYTES);

  const api = setup({}, ["ca-aaa"], { withExt: false });
  api.core.rejectConfigMaps.add(crlName("ca-aaa"));
  await api.run();
  assert.equal(api.ready()?.reason, "CrlRejected");
  assert.equal(cm(api, crlName("ca-aaa")), undefined);
});

test("a foreign or foreign-managed ConfigMap is never touched", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  r.core.seedConfigMap("app", {
    metadata: { name: "trust" },
    data: { "ca.crt": "mine" },
  });
  await r.run();
  assert.equal(r.ready()?.reason, "ConfigMapConflict");
  assert.equal(r.core.callsOf("replace", "trust").length, 0);
  assert.equal(r.core.callsOf("create", "trust").length, 0);
  assert.equal(r.core.callsOf("delete", "trust").length, 0);
  assert.equal(cm(r, "trust").data["ca.crt"], "mine");
  assert.deepEqual(r.bundle().status.acceptedCaIds, []);

  for (const meta of [
    {
      labels: { [MANAGED_BY_LABEL]: "trust-bundle" },
      annotations: { [OWNER_ANNOTATION]: "app/other" },
    },
    {
      labels: { [MANAGED_BY_LABEL]: "import" },
      annotations: { [OWNER_ANNOTATION]: "app/bundle" },
    },
  ]) {
    const c = setup({}, ["ca-aaa"], { withExt: false });
    c.core.seedConfigMap("app", {
      metadata: { name: crlName("ca-aaa"), ...meta },
      binaryData: { "crl.der": "AAAA" },
    });
    await c.run();
    assert.equal(crlEntry(c, "ca-aaa").state, "Conflict");
    assert.equal(c.core.callsOf("replace", crlName("ca-aaa")).length, 0);
    assert.equal(c.ready()?.reason, "ConfigMapConflict");
    assert.equal(cm(c, crlName("ca-aaa")).binaryData["crl.der"], "AAAA");
    assert.equal(crlRequests(c, "ca-aaa").length, 0);
  }

  const d = setup({}, ["ca-aaa"], { withExt: false });
  await d.run();
  assert.ok(cm(d, crlName("ca-aaa")) !== undefined);
  // Somebody replaces our CRL ConfigMap with their own, then the issuer leaves.
  d.core.seedConfigMap("app", {
    metadata: { name: crlName("ca-aaa") },
    data: { theirs: "x" },
  });
  d.edit({ includeCrl: false });
  await d.run();
  assert.equal(d.core.callsOf("delete").length, 0);
  assert.equal(cm(d, crlName("ca-aaa")).data.theirs, "x");
  assert.deepEqual(d.bundle().status.crls, []);
});

test("rollover: both CRLs stay mounted, then the old one is deleted by uid", async () => {
  const r = setup({}, ["ca-old", "ca-new"]);
  r.edit({ caIds: ["ca-old"] });
  await r.run();
  r.edit({ caIds: ["ca-old", "ca-new"] });
  await r.run();
  assert.equal(cm(r, "trust").data["ca.crt"], rootPem);
  assert.equal(
    cm(r, "trust").data["chain.crt"],
    pemOf("ca-new") + pemOf("ca-old"),
  );
  assert.deepEqual(
    r.core.configMapNames("app"),
    ["trust", crlName(EXT), crlName("ca-new"), crlName("ca-old")].sort(),
  );
  // Retired but still in the bundle.
  r.server.views.set(
    "ca-old",
    caView("ca-old", { status: "RETIRED", crlIssuers: withExt("ca-old") }),
  );
  await r.run();
  assert.equal(r.ready()?.reason, "Ready");
  // Drained, and its own CRL goes stale: still Ready.
  r.server.views.set(
    "ca-old",
    caView("ca-old", {
      status: "RETIRED",
      drained: true,
      crlIssuers: withExt("ca-old"),
    }),
  );
  r.server.crls.set(
    "ca-old",
    crlFixture(40, "1", "2026-06-08T00:00:00.000Z", 1),
  );
  await r.run();
  await r.scheduler.advance(8 * 86_400_000);
  await r.run();
  assert.equal(crlEntry(r, "ca-old").state, "Stale");
  assert.equal(r.ready()?.status, "True");
  assert.equal(r.ready()?.reason, "CaDrained");
  // Cut over.
  const oldUid = cm(r, crlName("ca-old")).metadata.uid;
  const oldVersion = cm(r, crlName("ca-old")).metadata.resourceVersion;
  r.edit({ caIds: ["ca-new"] });
  await r.run();
  const deletes = r.core.callsOf("delete");
  assert.equal(deletes.length, 1);
  assert.equal(deletes[0]?.name, crlName("ca-old"));
  assert.deepEqual(deletes[0]?.body, {
    preconditions: { uid: oldUid, resourceVersion: oldVersion },
  });
  assert.equal(cm(r, crlName("ca-old")), undefined);
  assert.ok(cm(r, crlName(EXT)) !== undefined);
  assert.equal(cm(r, "trust").data["chain.crt"], pemOf("ca-new"));
  assert.equal(r.bundle().status.crls.length, 2);
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-new"]);
  assert.equal(r.ready()?.reason, "Ready");
});

test("conditional GETs are sent only for verified stored bytes in the right format", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  await r.run();
  const sha = (
    cm(r, crlName("ca-aaa")).metadata.annotations as Record<string, string>
  )[CRL_SHA256_ANNOTATION];
  assert.equal(
    crlRequests(r, "ca-aaa")[0]?.headers?.["if-none-match"],
    undefined,
  );
  const before = r.core.configMapCalls.filter((c) => c.op !== "read").length;
  await r.run();
  assert.equal(
    crlRequests(r, "ca-aaa")[1]?.headers?.["if-none-match"],
    `"${sha}"`,
  );
  assert.equal(
    r.core.configMapCalls.filter((c) => c.op !== "read").length,
    before,
  );
  // Tampered bytes: no If-None-Match, and the copy is repaired.
  cm(r, crlName("ca-aaa")).binaryData["crl.der"] =
    Buffer.from("evil").toString("base64");
  await r.run();
  assert.equal(
    crlRequests(r, "ca-aaa")[2]?.headers?.["if-none-match"],
    undefined,
  );
  assert.equal(
    Buffer.from(cm(r, crlName("ca-aaa")).binaryData["crl.der"], "base64")
      .length,
    40,
  );
  // Format switch.
  r.edit({ crlFormat: "pem" });
  await r.run();
  assert.equal(
    crlRequests(r, "ca-aaa")[3]?.headers?.["if-none-match"],
    undefined,
  );
  const switched = cm(r, crlName("ca-aaa"));
  assert.ok(typeof switched.data["crl.pem"] === "string");
  assert.equal(switched.binaryData, undefined);
});

test("a partial pass writes and deletes nothing", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  await r.run();
  const target = cm(r, "trust");
  const version = target.metadata.resourceVersion;
  const beforeCalls = r.core.configMapCalls.filter(
    (c) => c.op !== "read",
  ).length;
  r.server.views.set("ca-bbb", fault(503, "service_unavailable"));
  r.edit({ caIds: ["ca-aaa"] });
  await r.run();
  assert.equal(cm(r, "trust").metadata.resourceVersion, version);
  assert.equal(
    r.core.configMapCalls.filter((c) => c.op !== "read").length,
    beforeCalls,
  );
  assert.equal(r.core.callsOf("delete").length, 0);
  assert.ok(r.queue.scheduledDelay(r.key) !== undefined);
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa", "ca-bbb"]);
  assert.equal(r.bundle().status.crls.length, 2);
  // The previously Ready status is kept (at the previous generation it was Ready;
  // a new generation has no Ready to keep).
  assert.equal(r.ready()?.reason, "RemoteError");

  const same = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  await same.run();
  same.server.views.set("ca-bbb", fault(503, "service_unavailable"));
  await same.run();
  assert.equal(same.ready()?.reason, "Ready");
  assert.equal(same.ready()?.status, "True");

  const first = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  first.server.views.set("ca-bbb", fault(503, "service_unavailable"));
  await first.run();
  assert.equal(cm(first, "trust"), undefined);
  assert.equal(first.ready()?.reason, "RemoteError");
  assert.equal(first.ready()?.status, "False");
  assert.ok(first.queue.scheduledDelay(first.key) !== undefined);
});

test("includeCrl false creates none and removes earlier ones on the next complete pass", async () => {
  const none = setup({ includeCrl: false });
  await none.run();
  assert.deepEqual(none.core.configMapNames("app"), ["trust"]);
  assert.equal(none.ready()?.reason, "Ready");

  const r = setup();
  await r.run();
  assert.equal(r.core.configMapNames("app").length, 3);
  r.edit({ includeCrl: false });
  await r.run();
  assert.deepEqual(r.core.configMapNames("app"), ["trust"]);
  assert.equal(r.core.callsOf("delete").length, 2);
  assert.deepEqual(r.bundle().status.crls, []);
});

test("consumer failures make no remote call and leave ConfigMaps alone", async () => {
  const expectUntouched = (r: Rig) => {
    assert.equal(r.transport.requests.length, 0);
    assert.equal(
      r.core.configMapCalls.filter((c) => c.op !== "read").length,
      0,
    );
  };
  const missing = setup();
  missing.custom.remove("hemligconsumers", "app", "consumer");
  await missing.run();
  assert.equal(missing.ready()?.reason, "ConsumerNotFound");
  expectUntouched(missing);

  const notReady = setup();
  notReady.registry.entries.delete("app/consumer");
  await notReady.run();
  assert.equal(notReady.ready()?.reason, "ConsumerNotReady");
  expectUntouched(notReady);

  const crossNamespace = setup({ consumerNamespace: "other" });
  crossNamespace.custom.put("hemligconsumers", {
    ...consumerObject(),
    metadata: { ...consumerObject().metadata, namespace: "other" },
  });
  await crossNamespace.run();
  assert.equal(crossNamespace.ready()?.reason, "ConsumerReferenceNotPermitted");
  expectUntouched(crossNamespace);

  const provider = setup();
  provider.registry.entries.set(
    "app/consumer",
    registered(provider.transport, {
      provider: {
        metadata: { generation: 1 },
        spec: {
          apiUrl: "https://api.test",
          allowedNamespaces: { matchLabels: { team: "x" } },
        },
      } as never,
    }),
  );
  await provider.run();
  assert.equal(provider.ready()?.reason, "ProviderNotPermitted");
  expectUntouched(provider);

  const existing = setup();
  await existing.run();
  const writesBefore = existing.core.configMapCalls.filter(
    (c) => c.op !== "read",
  ).length;
  existing.registry.entries.delete("app/consumer");
  await existing.run();
  assert.equal(existing.ready()?.reason, "ConsumerNotReady");
  assert.equal(
    existing.core.configMapCalls.filter((c) => c.op !== "read").length,
    writesBefore,
  );
  assert.deepEqual(existing.bundle().status.acceptedCaIds, ["ca-aaa"]);

  const rejected = setup();
  rejected.server.views.set("ca-aaa", fault(403, "identity_not_active"));
  await rejected.run();
  assert.equal(rejected.ready()?.reason, "ConsumerNotReady");
  assert.equal(rejected.core.configMapNames("app").length, 0);
});

test("a CRL whose sha256 differs from its ETag writes nothing", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  const inner = r.server.handler;
  r.transport.handler = (request) => {
    const response = inner(request);
    return request.url.pathname.startsWith("/v1/pki/crls/")
      ? { ...response, headers: { ...response.headers, etag: "0".repeat(64) } }
      : response;
  };
  await r.run();
  assert.equal(cm(r, crlName("ca-aaa")), undefined);
  assert.ok(r.queue.scheduledDelay(r.key) !== undefined);
  assert.equal(r.ready()?.status, "False");
});

test("an unchanged pass patches no status and keeps lastTransitionTime", async () => {
  const r = setup();
  await r.run();
  const transition = r.ready()?.lastTransitionTime;
  const patches = r.custom.count("patchStatus", "hemligtrustbundles");
  await r.scheduler.advance(60_000);
  await r.run();
  assert.equal(r.custom.count("patchStatus", "hemligtrustbundles"), patches);
  assert.equal(r.ready()?.lastTransitionTime, transition);
  // A generation bump with the same content rewrites the status but keeps the time.
  r.edit({ includeCrl: true });
  await r.scheduler.advance(60_000);
  await r.run();
  assert.equal(
    r.custom.count("patchStatus", "hemligtrustbundles"),
    patches + 1,
  );
  assert.equal(r.ready()?.lastTransitionTime, transition);
  assert.equal(r.bundle().status.observedGeneration, 2);
});

test("a deleted bundle is a no-op", async () => {
  const r = setup();
  r.custom.remove("hemligtrustbundles", "app", "bundle");
  await r.run();
  assert.equal(r.transport.requests.length, 0);
});

test("logs never carry PEM, DER, base64 or server messages", async () => {
  const chunks: string[] = [];
  const stderr = process.stderr.write.bind(process.stderr);
  const stdout = process.stdout.write.bind(process.stdout);
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as never;
  process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => {
    chunks.push(String(chunk));
    return (stdout as (...args: unknown[]) => boolean)(chunk, ...rest);
  }) as never;
  const bytes = Buffer.alloc(80, 0x42);
  try {
    const r = setup({}, ["ca-aaa", "ca-bbb", "ca-ccc"]);
    r.server.crls.set(
      "ca-aaa",
      crlFixture(80, "1", "2027-01-01T00:00:00.000Z", 0x42),
    );
    r.server.views.set("ca-ccc", fault(503, "service_unavailable"));
    await r.run();
    r.server.views.set("ca-ccc", fault(409, "ca_not_active", "failed"));
    await r.run();
    r.server.crls.set(EXT, fault(500, "internal_error"));
    await r.run();
    r.server.views.set("ca-bbb", fault(404, "not_found", "ca_not_found"));
    await r.run();
    r.core.rejectConfigMaps.add("trust");
    r.edit({ caIds: ["ca-aaa"] });
    r.server.views.set(
      "ca-aaa",
      caView("ca-aaa", { chainPem: pemOf("z") + pemOf("w") }),
    );
    await r.run();
    r.server.views.set("ca-aaa", fault(403, "identity_not_active"));
    await r.run();
  } finally {
    process.stderr.write = stderr as never;
    process.stdout.write = stdout as never;
  }
  const text = chunks.join("");
  assert.ok(text.includes("Hemlig PKI:"));
  assert.ok(!text.includes("-----BEGIN"));
  assert.ok(!text.includes(bytes.toString("base64").slice(0, 16)));
  assert.ok(!text.includes("SECRET server message"));
});

test("an expired mounted copy shows Stale from the previous entry during an outage", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  r.server.crls.set(
    "ca-aaa",
    crlFixture(40, "1", "2026-06-08T00:00:00.000Z", 1),
  );
  await r.run();
  assert.equal(crlEntry(r, "ca-aaa").state, "Current");
  r.server.crls.set("ca-aaa", fault(503, "service_unavailable"));
  r.edit({ crlFormat: "pem" });
  await r.scheduler.advance(8 * 86_400_000);
  await r.run();
  assert.equal(crlEntry(r, "ca-aaa").state, "Stale");
  assert.equal(r.ready()?.reason, "CrlStale");
});

test("one transient CA failure stops the remaining bundle fetches", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb", "ca-ccc"], { withExt: false });
  r.server.views.set("ca-aaa", fault(503, "service_unavailable"));
  await r.run();
  const fetches = r.transport.requests.filter((q) =>
    q.url.pathname.endsWith("/bundle"),
  );
  assert.equal(fetches.length, 1);
  assert.equal(cm(r, "trust"), undefined);
});

test("a pass with no usable CA never wipes the mounted bundle", async () => {
  const r = setup();
  await r.run();
  const version = cm(r, "trust").metadata.resourceVersion;
  r.server.views.set("ca-aaa", fault(404, "not_found", "ca_not_found"));
  await r.run();
  assert.equal(cm(r, "trust").metadata.resourceVersion, version);
  assert.ok(cm(r, "trust").data["chain.crt"].includes(pemOf("ca-aaa")));
  assert.equal(r.core.callsOf("delete").length, 0);
  assert.deepEqual(r.bundle().status.acceptedCaIds, ["ca-aaa"]);
  assert.equal(r.bundle().status.crls.length, 2);
  assert.equal(r.ready()?.reason, "CaNotFound");
  assert.ok(r.queue.scheduledDelay(r.key) !== undefined);
});

test("a confirmed-absent CRL ConfigMap stays Missing through a transient failure", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  r.server.crls.set("ca-aaa", fault(503, "service_unavailable"));
  await r.run();
  assert.equal(cm(r, crlName("ca-aaa")), undefined);
  assert.equal(crlEntry(r, "ca-aaa").state, "Missing");
  // A stored copy that verifies in neither format is Missing too.
  r.server.crls.set(
    "ca-aaa",
    crlFixture(40, "1", "2027-01-01T00:00:00.000Z", 1),
  );
  await r.scheduler.advance(300_000);
  assert.equal(crlEntry(r, "ca-aaa").state, "Current");
  cm(r, crlName("ca-aaa")).binaryData["crl.der"] =
    Buffer.from("evil").toString("base64");
  r.server.crls.set("ca-aaa", fault(503, "service_unavailable"));
  await r.run();
  assert.equal(crlEntry(r, "ca-aaa").state, "Missing");
});

test("rollover cleanup never deletes once the pass turned partial", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb"], { withExt: false });
  await r.run();
  assert.ok(cm(r, crlName("ca-aaa")) !== undefined);
  r.server.crls.set("ca-bbb", fault(503, "service_unavailable"));
  r.edit({ caIds: ["ca-bbb"] });
  await r.run();
  assert.equal(r.core.callsOf("delete").length, 0);
  assert.ok(cm(r, crlName("ca-aaa")) !== undefined);
  assert.ok(
    r.bundle().status.crls.some((c: { id: string }) => c.id === "ca-aaa"),
  );
  assert.ok(r.queue.scheduledDelay(r.key) !== undefined);
});

test("one transient CRL failure skips the remaining CRL fetches", async () => {
  const r = setup({}, ["ca-aaa", "ca-bbb", "ca-ccc"], { withExt: false });
  r.server.crls.set("ca-aaa", fault(503, "service_unavailable"));
  await r.run();
  const fetches = r.transport.requests.filter((q) =>
    q.url.pathname.startsWith("/v1/pki/crls/"),
  );
  assert.equal(fetches.length, 1);
  assert.equal(cm(r, crlName("ca-bbb")), undefined);
  assert.equal(r.bundle().status.crls.length, 3);
  assert.ok(r.queue.scheduledDelay(r.key) !== undefined);
});

test("the status patch is guarded by the bundle uid and a recreated bundle re-queues", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  const inner = r.server.handler;
  let swapped = false;
  r.transport.handler = (request) => {
    if (!swapped && request.url.pathname.endsWith("/bundle")) {
      swapped = true;
      r.custom.update("hemligtrustbundles", "app", "bundle", (o) => {
        o.metadata.uid = "recreated-uid";
      });
    }
    return inner(request);
  };
  await r.run();
  const patches = r.custom.calls.filter((c) => c.method === "patchStatus");
  assert.equal(patches.length, 2);
  const first = patches[0]?.body as {
    op: string;
    path: string;
    value: unknown;
  }[];
  assert.deepEqual(first[0], {
    op: "test",
    path: "/metadata/uid",
    value: "bundle-uid",
  });
  assert.equal(first[1]?.op, "add");
  assert.equal(
    (patches[1]?.body as { value: unknown }[])[0]?.value,
    "recreated-uid",
  );
  assert.equal(r.ready()?.reason, "Ready");
});

test("freshness is recomputed at publish time on every path", async () => {
  const r = setup({}, ["ca-aaa"], { withExt: false });
  r.server.crls.set(
    "ca-aaa",
    crlFixture(40, "1", "2026-06-01T00:00:01.000Z", 1),
  );
  const inner = r.server.handler;
  r.transport.handler = (request) => {
    if (request.url.pathname.startsWith("/v1/pki/crls/")) {
      r.scheduler.time += 5_000;
    }
    return inner(request);
  };
  await r.run();
  assert.equal(crlEntry(r, "ca-aaa").state, "Stale");
  assert.equal(r.ready()?.reason, "CrlStale");

  const x = setup({}, ["ca-aaa"], { withExt: false });
  x.server.crls.set(
    "ca-aaa",
    crlFixture(40, "1", "2026-06-02T00:00:00.000Z", 1),
  );
  await x.run();
  assert.equal(crlEntry(x, "ca-aaa").state, "Current");
  await x.scheduler.advance(2 * 86_400_000);
  x.registry.entries.delete("app/consumer");
  await x.run();
  assert.equal(x.ready()?.reason, "ConsumerNotReady");
  assert.equal(crlEntry(x, "ca-aaa").state, "Stale");

  const y = setup({}, ["ca-aaa"], { withExt: false });
  y.server.crls.set(
    "ca-aaa",
    crlFixture(40, "1", "2026-06-02T00:00:00.000Z", 1),
  );
  await y.run();
  await y.scheduler.advance(2 * 86_400_000);
  y.server.views.set("ca-aaa", fault(403, "identity_not_active"));
  await y.run();
  assert.equal(y.ready()?.reason, "ConsumerNotReady");
  assert.equal(crlEntry(y, "ca-aaa").state, "Stale");
});

// -- Hemlig ROOT and INTERMEDIATE CAs -----------------------------------------------

const ROOT_ID = "ca-root";
const rootCaPem = pemOf("hemlig-root");
const rootView = (overrides: Record<string, unknown> = {}) =>
  caView(ROOT_ID, {
    anchorPem: rootCaPem,
    chainPem: "",
    crlIssuers: [{ id: ROOT_ID, source: "GENERATED" }],
    ...overrides,
  });
const childView = (id: string, overrides: Record<string, unknown> = {}) =>
  caView(id, {
    anchorPem: rootCaPem,
    chainPem: pemOf(id),
    crlIssuers: [
      { id, source: "GENERATED" },
      { id: ROOT_ID, source: "GENERATED" },
    ],
    ...overrides,
  });
const hemligSetup = (
  ids: readonly string[],
  views: Record<string, Record<string, unknown>>,
  rootNextUpdate = "2027-01-01T00:00:00.000Z",
): Rig => {
  const r = setup({}, ids, { withExt: false });
  for (const [id, view] of Object.entries(views)) r.server.views.set(id, view);
  r.server.crls.set(ROOT_ID, crlFixture(41, "1", rootNextUpdate, 3));
  return r;
};

test("a bundle listing only a ROOT becomes Ready with no chain", async () => {
  const r = hemligSetup([ROOT_ID], { [ROOT_ID]: rootView() });
  await r.run();
  const target = cm(r, "trust");
  assert.equal(target.data["ca.crt"], rootCaPem);
  assert.equal(target.data["chain.crt"], "");
  assert.deepEqual(r.core.configMapNames("app"), ["trust", crlName(ROOT_ID)]);
  assert.equal(r.ready()?.reason, "Ready");
  assert.equal(r.ready()?.status, "True");
});

test("two intermediates under one root: one anchor, two chain entries, three CRLs", async () => {
  const r = hemligSetup(["ca-hem1", "ca-hem2"], {
    "ca-hem1": childView("ca-hem1"),
    "ca-hem2": childView("ca-hem2"),
  });
  await r.run();
  const target = cm(r, "trust");
  assert.equal(target.data["ca.crt"], rootCaPem);
  assert.equal(target.data["chain.crt"], pemOf("ca-hem1") + pemOf("ca-hem2"));
  assert.deepEqual(r.core.configMapNames("app"), [
    "trust",
    crlName("ca-hem1"),
    crlName("ca-hem2"),
    crlName(ROOT_ID),
  ]);
  for (const id of ["ca-hem1", "ca-hem2", ROOT_ID]) {
    assert.equal(
      cm(r, crlName(id)).metadata.annotations["hemlig.zyno.io/crl-source"],
      "GENERATED",
    );
  }
  assert.equal(r.ready()?.reason, "Ready");
});

test("distrust through every listed child empties ca.crt and stays Ready", async () => {
  const r = hemligSetup([ROOT_ID, "ca-hem1", "ca-hem2"], {
    [ROOT_ID]: rootView({ status: "REVOKED", anchorTrusted: false }),
    "ca-hem1": childView("ca-hem1", { anchorTrusted: false }),
    "ca-hem2": childView("ca-hem2", { anchorTrusted: false }),
  });
  await r.run();
  const target = cm(r, "trust");
  assert.equal(target.data["ca.crt"], "");
  assert.equal(target.data["chain.crt"], pemOf("ca-hem1") + pemOf("ca-hem2"));
  assert.deepEqual(r.bundle().status.acceptedCaIds, [
    "ca-hem1",
    "ca-hem2",
    ROOT_ID,
  ]);
  assert.equal(r.ready()?.reason, "Ready");
});

test("the root CRL is required only while a listed child can still validate", async () => {
  const stalePast = "2026-06-08T00:00:00.000Z";
  // Distrusted dependents: a stale root CRL is no longer required.
  const distrusted = hemligSetup(
    ["ca-hem1", "ca-hem2"],
    {
      "ca-hem1": childView("ca-hem1", { anchorTrusted: false }),
      "ca-hem2": childView("ca-hem2", { anchorTrusted: false }),
    },
    stalePast,
  );
  await distrusted.run();
  await distrusted.scheduler.advance(8 * 86_400_000);
  await distrusted.run();
  assert.equal(crlEntry(distrusted, ROOT_ID).state, "Stale");
  assert.equal(distrusted.ready()?.reason, "Ready");
  // A CA-revoked child keeps a trusted anchor, so the root CRL is still required.
  const revoked = hemligSetup(
    ["ca-hem1", "ca-hem2"],
    {
      "ca-hem1": childView("ca-hem1", { status: "REVOKED" }),
      "ca-hem2": childView("ca-hem2", { status: "REVOKED" }),
    },
    stalePast,
  );
  await revoked.run();
  await revoked.scheduler.advance(8 * 86_400_000);
  await revoked.run();
  assert.equal(crlEntry(revoked, ROOT_ID).state, "Stale");
  assert.equal(revoked.ready()?.reason, "CrlStale");
  // A CA-revoked child past its own notAfter can validate nothing: the root CRL stops being required.
  const expired = hemligSetup(
    ["ca-hem1", "ca-hem2"],
    {
      "ca-hem1": childView("ca-hem1", {
        status: "REVOKED",
        notAfter: "2026-06-02T00:00:00.000Z",
      }),
      "ca-hem2": childView("ca-hem2", {
        status: "REVOKED",
        notAfter: "2026-06-02T00:00:00.000Z",
      }),
    },
    stalePast,
  );
  await expired.run();
  await expired.scheduler.advance(8 * 86_400_000);
  await expired.run();
  assert.equal(crlEntry(expired, ROOT_ID).state, "Stale");
  assert.equal(expired.ready()?.reason, "Ready");
  // Drained dependents: not required, and the bundle reports CaDrained.
  const drained = hemligSetup(
    ["ca-hem1", "ca-hem2"],
    {
      "ca-hem1": childView("ca-hem1", { drained: true }),
      "ca-hem2": childView("ca-hem2", { drained: true }),
    },
    stalePast,
  );
  await drained.run();
  await drained.scheduler.advance(8 * 86_400_000);
  await drained.run();
  assert.equal(crlEntry(drained, ROOT_ID).state, "Stale");
  assert.equal(drained.ready()?.reason, "CaDrained");
});

test("a root CRL stays required while an accepted child's view is missing", async () => {
  const stalePast = "2026-06-08T00:00:00.000Z";
  const r = hemligSetup(
    ["ca-hem1", "ca-hem2"],
    {
      "ca-hem1": childView("ca-hem1", { drained: true }),
      "ca-hem2": childView("ca-hem2"),
    },
    stalePast,
  );
  await r.run();
  // The live child's bundle fetch now fails; the drained child alone would make the root CRL optional.
  r.server.views.set("ca-hem2", fault(503, "service_unavailable"));
  await r.scheduler.advance(8 * 86_400_000);
  await r.run();
  assert.equal(crlEntry(r, ROOT_ID).state, "Stale");
  assert.notEqual(r.ready()?.status, "True");
});
