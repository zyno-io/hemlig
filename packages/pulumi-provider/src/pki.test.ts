import assert from "node:assert/strict";
import test from "node:test";
import * as pulumi from "@pulumi/pulumi";
import {
  HemligError,
  type PkiCaDetail,
  type PkiIssuanceGrant,
} from "@zyno-io/hemlig-client";
import {
  HemligCertificateAuthorityProvider,
  HemligIssuanceGrantProvider,
  pemBodiesEqual,
  type HemligCaClient,
  type HemligGrantClient,
  type ResolvedCertificateAuthorityInputs,
  type ResolvedCertificateAuthorityState,
  type ResolvedIssuanceGrantInputs,
  type ResolvedIssuanceGrantState,
} from "./pki";

const TOKEN = "tok-sentinel-9f3a7c";
const ADMIN_URL = "https://admin.example.com";
const NO_DELAY = [0, 0];
const CERT = "-----BEGIN CERTIFICATE-----\nMIIBsigned\nAAAA\n-----END CERTIFICATE-----\n";
const CERT_REWRAPPED =
  "-----BEGIN CERTIFICATE-----\r\n  MIIBsigned  AAAA\r\n-----END CERTIFICATE-----";
const OTHER_CERT = "-----BEGIN CERTIFICATE-----\nMIIBother\n-----END CERTIFICATE-----\n";
const ROOT = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n";
const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBcsr\n-----END CERTIFICATE REQUEST-----\n";

interface Call {
  readonly method: string;
  readonly args: readonly unknown[];
}

/** A client that records calls and throws on any method it was not given. */
const fake = <T extends object>(
  impl: Record<string, (...args: never[]) => unknown>,
): { client: T; calls: Call[] } => {
  const calls: Call[] = [];
  const client = new Proxy(
    {},
    {
      get: (_target, property) => {
        const method = String(property);
        const handler = impl[method];
        if (handler === undefined) {
          throw new Error(`unexpected client call: ${method}`);
        }
        return (...args: unknown[]) => {
          calls.push({ method, args });
          return Promise.resolve(
            (handler as (...a: unknown[]) => unknown)(...args),
          );
        };
      },
    },
  ) as T;
  return { client, calls };
};

const callsOf = (calls: readonly Call[], method: string): Call[] =>
  calls.filter((call) => call.method === method);

const http = (
  status: number,
  code: string,
  reason?: string,
  message = `${code} happened`,
): HemligError =>
  new HemligError(
    status,
    message,
    code,
    reason === undefined ? undefined : { reason },
  );

const caDetail = (overrides: Partial<PkiCaDetail> = {}): PkiCaDetail => ({
  caId: "ca-1",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "PENDING_CERTIFICATE",
  version: "v1",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-01-01T00:00:00Z",
  key: {
    custody: "WRAPPED",
    algorithm: "ECDSA_P256",
    spkiSha256: "abc",
    state: "ACTIVE",
  },
  subject: { commonName: "Prod Issuing CA 1" },
  subjectDn: "CN=Prod Issuing CA 1",
  requestedConstraints: {},
  crlIssuers: [],
  policy: {
    maxLeafLifetimeSeconds: 7776000,
    leafKeyAlgorithms: ["ECDSA_P256", "ED25519"],
    capacity: 8000,
    issuancePerHour: 100,
    crlValiditySeconds: 604800,
    issueLeaves: true,
    issueSubordinates: false,
  },
  maxIssueLifetimeEverSeconds: 0,
  createdBy: {},
  drained: false,
  csrPem: CSR,
  ...overrides,
});

const activeDetail = (overrides: Partial<PkiCaDetail> = {}): PkiCaDetail =>
  caDetail({
    status: "ACTIVE",
    version: "v2",
    certificatePem: CERT,
    chainPem: ROOT,
    fingerprint: "fp",
    serial: "01",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2027-01-01T00:00:00Z",
    ...overrides,
  });

const caInputs = (
  overrides: Partial<ResolvedCertificateAuthorityInputs> = {},
): ResolvedCertificateAuthorityInputs => ({
  adminUrl: ADMIN_URL,
  providerSchemaVersion: "1",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  keyAlgorithm: "ECDSA_P256",
  subject: { commonName: "Prod Issuing CA 1" },
  ...overrides,
});

const caState = (
  overrides: Partial<ResolvedCertificateAuthorityState> = {},
): ResolvedCertificateAuthorityState => ({
  ...caInputs(),
  caId: "ca-1",
  status: "PENDING_CERTIFICATE",
  version: "v1",
  keyState: "ACTIVE",
  subjectDn: "CN=Prod Issuing CA 1",
  csrPem: CSR,
  ...overrides,
});

const caProvider = (client: HemligCaClient): HemligCertificateAuthorityProvider =>
  new HemligCertificateAuthorityProvider(() => client, () => TOKEN, NO_DELAY);

const failedProperties = (result: pulumi.dynamic.CheckResult): string[] =>
  (result.failures ?? []).map((failure) => failure.property);

// ---------------------------------------------------------------------------
// CertificateAuthority
// ---------------------------------------------------------------------------

test("CA: external create posts without activation fields and outputs the CSR", async () => {
  const { client, calls } = fake<HemligCaClient>({
    createPkiCa: () => ({ ...caDetail(), warnings: [{ code: "w", message: "m" }] }),
  });
  const result = await caProvider(client).create(
    caInputs({ policy: { capacity: 8000 }, displayName: "Prod" }),
  );

  assert.equal(result.id, "ca-1");
  assert.equal(result.outs?.csrPem, CSR);
  assert.equal(result.outs?.status, "PENDING_CERTIFICATE");
  assert.deepEqual(result.outs?.warnings, [{ code: "w", message: "m" }]);
  const [call] = callsOf(calls, "createPkiCa");
  const [token, body, key] = call?.args as [string, Record<string, unknown>, string];
  assert.equal(token, TOKEN);
  assert.equal("certificatePem" in body, false);
  assert.equal("signedCertificatePem" in body, false);
  assert.deepEqual(body.policy, { capacity: 8000 });
  assert.match(key, /^pulumi-ca-create-[0-9a-f-]{36}$/);
  assert.ok(key.length >= 8 && key.length <= 128);
});

test("CA: activation sends only the certificate and chain, never a root CRL", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => caDetail(),
    activatePkiCa: () => activeDetail(),
  });
  const result = await caProvider(client).update(
    "ca-1",
    caState(),
    caInputs({ signedCertificatePem: CERT, chainPem: ROOT }),
  );

  const activations = callsOf(calls, "activatePkiCa");
  assert.equal(activations.length, 1);
  assert.deepEqual(activations[0]?.args[2], {
    certificatePem: CERT,
    chainPem: ROOT,
  });
  assert.equal(callsOf(calls, "updatePkiCa").length, 0);
  assert.equal(result.outs?.status, "ACTIVE");
  assert.equal(result.outs?.issuerChainPem, ROOT);
  assert.equal(result.outs?.fingerprint, "fp");
});

test("CA: acceptBroaderConstraints is sent only with activation", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => caDetail(),
    activatePkiCa: () => activeDetail(),
  });
  await caProvider(client).update(
    "ca-1",
    caState(),
    caInputs({
      signedCertificatePem: CERT,
      chainPem: ROOT,
      acceptBroaderConstraints: true,
    }),
  );
  assert.deepEqual(callsOf(calls, "activatePkiCa")[0]?.args[2], {
    certificatePem: CERT,
    chainPem: ROOT,
    acceptBroaderConstraints: true,
  });
});

test("CA: an ACTIVE CA with the same certificate makes no mutation; a different one throws", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
  });
  const provider = caProvider(client);
  const result = await provider.update(
    "ca-1",
    caState(),
    caInputs({ signedCertificatePem: CERT_REWRAPPED, chainPem: ROOT }),
  );
  assert.equal(result.outs?.status, "ACTIVE");
  assert.deepEqual(
    calls.map((call) => call.method),
    ["getPkiCa"],
  );

  await assert.rejects(
    provider.update(
      "ca-1",
      caState(),
      caInputs({ signedCertificatePem: OTHER_CERT, chainPem: ROOT }),
    ),
    /different certificate/,
  );
});

test("CA: activation of a CA in another status throws", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => caDetail({ status: "RETIRED" }),
  });
  await assert.rejects(
    caProvider(client).update(
      "ca-1",
      caState(),
      caInputs({ signedCertificatePem: CERT, chainPem: ROOT }),
    ),
    /RETIRED/,
  );
  assert.equal(calls.length, 1);
});

test("CA: check rejects activation inputs at create and on a ROOT", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);

  const atCreate = await provider.check(
    {},
    caInputs({ signedCertificatePem: CERT, chainPem: ROOT }),
  );
  assert.deepEqual(failedProperties(atCreate), ["signedCertificatePem"]);
  assert.match(atCreate.failures?.[0]?.reason ?? "", /csrPem/);

  const onRoot = await provider.check(
    {},
    caInputs({
      kind: "ROOT",
      validitySeconds: 100,
      signedCertificatePem: CERT,
      chainPem: ROOT,
    }),
  );
  assert.ok(failedProperties(onRoot).includes("signedCertificatePem"));
});

test("CA: check rejects changing, removing or half-setting the activation inputs", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);
  const olds = caInputs({ signedCertificatePem: CERT, chainPem: ROOT });

  const changed = await provider.check(
    olds,
    caInputs({ signedCertificatePem: OTHER_CERT, chainPem: ROOT }),
  );
  assert.deepEqual(failedProperties(changed), ["signedCertificatePem"]);

  const removed = await provider.check(olds, caInputs());
  assert.ok(failedProperties(removed).includes("signedCertificatePem"));

  const whitespaceOnly = await provider.check(
    olds,
    caInputs({ signedCertificatePem: CERT_REWRAPPED, chainPem: ROOT }),
  );
  assert.equal(whitespaceOnly.failures, undefined);

  const half = await provider.check(
    caInputs(),
    caInputs({ signedCertificatePem: CERT }),
  );
  assert.ok(failedProperties(half).includes("signedCertificatePem"));
});

test("CA: check fails every immutable change with the rollover message", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);
  const base = caInputs({
    kind: "INTERMEDIATE",
    parentCaId: "ca-root",
    validitySeconds: 100,
    requestedConstraints: { extendedKeyUsages: ["serverAuth"] },
  });
  const changes: Partial<ResolvedCertificateAuthorityInputs>[] = [
    { environment: "stage" },
    { name: "prod-issuing-2" },
    { kind: "EXTERNAL_INTERMEDIATE", parentCaId: undefined, validitySeconds: undefined },
    { keyAlgorithm: "ECDSA_P384" },
    { subject: { commonName: "Other" } },
    { parentCaId: "ca-other" },
    { validitySeconds: 200 },
    { requestedConstraints: { extendedKeyUsages: ["clientAuth"] } },
  ];
  for (const change of changes) {
    const [property] = Object.keys(change);
    const result = await provider.check(base, { ...base, ...change });
    assert.ok(
      failedProperties(result).includes(property as string),
      `${property} change should fail`,
    );
    assert.match(
      result.failures?.find((failure) => failure.property === property)
        ?.reason ?? "",
      /Create a new CertificateAuthority with a new name and DN/,
    );
  }
});

test("CA: check rejects a ROOT leaf policy, a missing parent, private keys; skips unknowns", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);

  const rootLeaf = await provider.check(
    {},
    caInputs({
      kind: "ROOT",
      validitySeconds: 100,
      policy: { maxLeafLifetimeSeconds: 60 },
    }),
  );
  assert.deepEqual(failedProperties(rootLeaf), ["policy"]);

  const noParent = await provider.check(
    {},
    caInputs({ kind: "INTERMEDIATE", validitySeconds: 100 }),
  );
  assert.deepEqual(failedProperties(noParent), ["parentCaId"]);

  const secret = await provider.check(
    {},
    caInputs({
      displayName: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    }),
  );
  assert.deepEqual(failedProperties(secret), ["inputs"]);

  const unknown = await provider.check(
    caInputs(),
    caInputs({
      name: pulumi.runtime.unknownValue as string,
      subject: { commonName: pulumi.runtime.unknownValue as string },
    }),
  );
  assert.equal(unknown.failures, undefined);
});

test("CA: diff never replaces, ignores removed policy keys and leafKeyAlgorithms order", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);
  const olds = caState({
    policy: { capacity: 8000, leafKeyAlgorithms: ["ECDSA_P256", "ED25519"] },
    displayName: "Prod",
  });

  const everything = await provider.diff("ca-1", olds, {
    ...caInputs({ kind: "ROOT", keyAlgorithm: "ED25519", name: "other" }),
    environment: "stage",
  });
  assert.deepEqual(everything.replaces, []);

  assert.equal(
    (await provider.diff("ca-1", olds, caInputs())).changes,
    false,
    "removing every policy key is not a change",
  );
  assert.equal(
    (
      await provider.diff(
        "ca-1",
        olds,
        caInputs({
          policy: { leafKeyAlgorithms: ["ED25519", "ECDSA_P256"] },
          displayName: "Prod",
        }),
      )
    ).changes,
    false,
  );
  assert.equal(
    (await provider.diff("ca-1", olds, caInputs({ policy: { capacity: 9000 } })))
      .changes,
    true,
  );
  assert.equal(
    (await provider.diff("ca-1", olds, caInputs({ displayName: "New" }))).changes,
    true,
  );
  assert.equal(
    (
      await provider.diff(
        "ca-1",
        olds,
        caInputs({ signedCertificatePem: CERT, chainPem: ROOT }),
      )
    ).changes,
    true,
  );
  assert.equal(
    (
      await provider.diff("ca-1", olds, {
        ...caInputs(),
        adminUrl: "https://other.example.com",
      })
    ).changes,
    true,
  );
});

test("CA: a policy update sends If-Match equal to the fresh version and only declared keys", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail({ version: "v7" }),
    updatePkiCa: () => activeDetail({ version: "v8" }),
  });
  const result = await caProvider(client).update(
    "ca-1",
    caState({ status: "ACTIVE", policy: { capacity: 8000 } }),
    caInputs({ policy: { capacity: 9000 } }),
  );

  const [call] = callsOf(calls, "updatePkiCa");
  assert.equal(call?.args[1], "ca-1");
  assert.equal(call?.args[2], "v7");
  assert.deepEqual(call?.args[3], { policy: { capacity: 9000 } });
  assert.equal(result.outs?.version, "v8");
});

test("CA: a policy that already matches the server makes no mutation", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
  });
  await caProvider(client).update(
    "ca-1",
    caState({ status: "ACTIVE" }),
    caInputs({ policy: { capacity: 8000 } }),
  );
  assert.deepEqual(
    calls.map((call) => call.method),
    ["getPkiCa"],
  );
});

test("CA: a 412 re-reads and retries with the new version and a new key; three 412s throw", async () => {
  let puts = 0;
  let gets = 0;
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail({ version: `v${(gets += 1)}` }),
    updatePkiCa: () => {
      puts += 1;
      if (puts === 1) {
        throw http(412, "precondition_failed");
      }
      return activeDetail({ version: "done" });
    },
  });
  const result = await caProvider(client).update(
    "ca-1",
    caState({ status: "ACTIVE" }),
    caInputs({ policy: { capacity: 9000 } }),
  );
  const puts1 = callsOf(calls, "updatePkiCa");
  assert.equal(puts1.length, 2);
  assert.equal(puts1[0]?.args[2], "v1");
  assert.equal(puts1[1]?.args[2], "v2");
  assert.notEqual(puts1[0]?.args[4], puts1[1]?.args[4]);
  assert.equal(result.outs?.version, "done");

  const always = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
    updatePkiCa: () => {
      throw http(412, "precondition_failed");
    },
  });
  await assert.rejects(
    caProvider(always.client).update(
      "ca-1",
      caState({ status: "ACTIVE" }),
      caInputs({ policy: { capacity: 9000 } }),
    ),
    /three times/,
  );
  assert.equal(callsOf(always.calls, "updatePkiCa").length, 3);
});

test("CA: a 412 on a CA that is no longer pending or active throws ca_not_active", async () => {
  let gets = 0;
  const { client } = fake<HemligCaClient>({
    getPkiCa: () => ((gets += 1) === 1 ? activeDetail() : activeDetail({ status: "RETIRED" })),
    updatePkiCa: () => {
      throw http(412, "precondition_failed");
    },
  });
  await assert.rejects(
    caProvider(client).update(
      "ca-1",
      caState({ status: "ACTIVE" }),
      caInputs({ policy: { capacity: 9000 } }),
    ),
    /ca_not_active/,
  );
});

test("CA: a network error on PUT retries with the same key and If-Match", async () => {
  let puts = 0;
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail({ version: "v7" }),
    updatePkiCa: () => {
      puts += 1;
      if (puts === 1) {
        throw new Error("socket hang up");
      }
      return activeDetail({ version: "v8" });
    },
  });
  await caProvider(client).update(
    "ca-1",
    caState({ status: "ACTIVE" }),
    caInputs({ policy: { capacity: 9000 } }),
  );
  const attempts = callsOf(calls, "updatePkiCa");
  assert.equal(attempts.length, 2);
  assert.equal(attempts[0]?.args[2], "v7");
  assert.equal(attempts[1]?.args[2], "v7");
  assert.equal(attempts[0]?.args[4], attempts[1]?.args[4]);
});

test("CA: update re-asserts immutability", async () => {
  const provider = caProvider(fake<HemligCaClient>({}).client);
  await assert.rejects(
    provider.update("ca-1", caState(), caInputs({ keyAlgorithm: "ECDSA_P384" })),
    /Create a new CertificateAuthority with a new name and DN/,
  );
});

test("CA: delete retires an ACTIVE CA with no live grants, once", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
    listCaIssuanceGrants: () => ({ grants: [], generatedAt: "now" }),
    retirePkiCa: () => activeDetail({ status: "RETIRED" }),
  });
  await caProvider(client).delete("ca-1", caState({ status: "ACTIVE" }));
  const retires = callsOf(calls, "retirePkiCa");
  assert.equal(retires.length, 1);
  assert.match(retires[0]?.args[2] as string, /^pulumi-ca-retire-/);
});

test("CA: delete makes no mutation for PENDING, RETIRED, REVOKED, FAILED or a missing CA", async () => {
  for (const status of ["PENDING_CERTIFICATE", "RETIRED", "REVOKED", "FAILED"] as const) {
    const { client, calls } = fake<HemligCaClient>({
      getPkiCa: () => caDetail({ status }),
    });
    await caProvider(client).delete("ca-1", caState());
    assert.deepEqual(
      calls.map((call) => call.method),
      ["getPkiCa"],
      status,
    );
  }
  const missing = fake<HemligCaClient>({
    getPkiCa: () => {
      throw http(404, "not_found");
    },
  });
  await caProvider(missing.client).delete("ca-1", caState());
  assert.equal(missing.calls.length, 1);
});

const liveGrant = (overrides: Partial<PkiIssuanceGrant> = {}): PkiIssuanceGrant =>
  grantDetail({ caId: "ca-1", ...overrides });

test("CA: delete refuses while live grants reference the CA and lists them", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
    listCaIssuanceGrants: () => ({
      grants: [liveGrant({ name: "web" }), liveGrant({ name: "api" })],
      generatedAt: "now",
    }),
    getAdminIssuanceGrant: (_token: string, _consumer: string, name: string) =>
      liveGrant({ name }),
  });
  await assert.rejects(
    caProvider(client).delete("ca-1", caState({ status: "ACTIVE" })),
    (error: Error) =>
      /payments-prod\/web/.test(error.message) &&
      /payments-prod\/api/.test(error.message) &&
      /migrate/i.test(error.message),
  );
  assert.equal(callsOf(calls, "retirePkiCa").length, 0);
});

test("CA: delete ignores listed grants that a strongly consistent read shows deleted or moved", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
    listCaIssuanceGrants: () => ({
      grants: [liveGrant({ name: "gone" }), liveGrant({ name: "moved" }), liveGrant({ name: "missing" })],
      generatedAt: "now",
    }),
    getAdminIssuanceGrant: (_token: string, _consumer: string, name: string) => {
      if (name === "gone") return liveGrant({ name, status: "DELETED" });
      if (name === "moved") return liveGrant({ name, caId: "ca-2" });
      throw http(404, "not_found");
    },
    retirePkiCa: () => activeDetail({ status: "RETIRED" }),
  });
  await caProvider(client).delete("ca-1", caState({ status: "ACTIVE" }));
  assert.equal(callsOf(calls, "retirePkiCa").length, 1);
});

test("CA: delete refuses when more than 20 grants are listed", async () => {
  const { client, calls } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail(),
    listCaIssuanceGrants: () => ({
      grants: Array.from({ length: 21 }, (_v, index) => liveGrant({ name: `g-${index}` })),
      generatedAt: "now",
    }),
  });
  await assert.rejects(
    caProvider(client).delete("ca-1", caState({ status: "ACTIVE" })),
    /more than 20/,
  );
  assert.equal(callsOf(calls, "retirePkiCa").length, 0);
});

test("CA: a concurrent retire (ca_not_active) counts as success", async () => {
  let gets = 0;
  const { client } = fake<HemligCaClient>({
    getPkiCa: () => ((gets += 1) === 1 ? activeDetail() : activeDetail({ status: "RETIRED" })),
    listCaIssuanceGrants: () => ({ grants: [], generatedAt: "now" }),
    retirePkiCa: () => {
      throw http(409, "ca_not_active", "retired");
    },
  });
  await caProvider(client).delete("ca-1", caState({ status: "ACTIVE" }));
});

test("CA: name_in_use explains how to import and adopts nothing", async () => {
  const { client, calls } = fake<HemligCaClient>({
    createPkiCa: () => {
      throw http(409, "conflict", "name_in_use");
    },
    listPkiCas: () => ({
      cas: [
        {
          ...caDetail({ caId: "ca-existing", status: "ACTIVE" }),
        },
      ],
      generatedAt: "now",
    }),
  });
  await assert.rejects(
    caProvider(client).create(caInputs()),
    (error: Error) =>
      /ca-existing/.test(error.message) &&
      /ACTIVE/.test(error.message) &&
      /import: "ca-existing"/.test(error.message),
  );
  assert.deepEqual(
    calls.map((call) => call.method),
    ["createPkiCa", "listPkiCas"],
  );
});

test("CA: ca_subject_in_use is reported with its reason", async () => {
  const { client } = fake<HemligCaClient>({
    createPkiCa: () => {
      throw http(409, "ca_subject_in_use");
    },
  });
  await assert.rejects(caProvider(client).create(caInputs()), /ca_subject_in_use/);
});

test("CA: read throws on 404 instead of dropping the CA from state", async () => {
  const { client } = fake<HemligCaClient>({
    getPkiCa: () => {
      throw http(404, "not_found");
    },
  });
  await assert.rejects(
    caProvider(client).read("ca-1", caState()),
    /never deleted.*adminUrl|adminUrl/,
  );
});

test("CA: refresh keeps declared inputs and surfaces drift on one declared policy key", async () => {
  const { client } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail({ policy: { ...activeDetail().policy, capacity: 5000 } }),
  });
  const provider = caProvider(client);
  const declared = caState({
    status: "ACTIVE",
    policy: { capacity: 8000, issuancePerHour: 100 },
  });
  const result = (await provider.read("ca-1", declared)) as pulumi.dynamic.ReadResult & {
    inputs: ResolvedCertificateAuthorityInputs;
  };
  assert.deepEqual(result.inputs.policy, { capacity: 5000, issuancePerHour: 100 });
  assert.equal((result.props as ResolvedCertificateAuthorityState).status, "ACTIVE");

  const clean = fake<HemligCaClient>({ getPkiCa: () => activeDetail() });
  const unchanged = (await caProvider(clean.client).read(
    "ca-1",
    declared,
  )) as pulumi.dynamic.ReadResult & { inputs: ResolvedCertificateAuthorityInputs };
  assert.deepEqual(unchanged.inputs.policy, { capacity: 8000, issuancePerHour: 100 });
});

test("CA: import rebuilds the inputs from the detail, with the activated certificate", async () => {
  const { client } = fake<HemligCaClient>({
    getPkiCa: () => activeDetail({ displayName: "Prod" }),
  });
  const result = (await caProvider(client).read("ca-1", {
    adminUrl: ADMIN_URL,
  } as ResolvedCertificateAuthorityState)) as pulumi.dynamic.ReadResult & {
    inputs: ResolvedCertificateAuthorityInputs;
  };
  assert.equal(result.id, "ca-1");
  assert.equal(result.inputs.name, "prod-issuing-1");
  assert.equal(result.inputs.kind, "EXTERNAL_INTERMEDIATE");
  assert.equal(result.inputs.signedCertificatePem, CERT);
  assert.equal(result.inputs.chainPem, ROOT);
  assert.equal(result.inputs.displayName, "Prod");
  assert.equal(result.inputs.validitySeconds, undefined);
  assert.equal(result.inputs.adminUrl, ADMIN_URL);
  assert.equal((result.props as ResolvedCertificateAuthorityState).caId, "ca-1");
});

// ---------------------------------------------------------------------------
// IssuanceGrant
// ---------------------------------------------------------------------------

function grantDetail(overrides: Partial<PkiIssuanceGrant> = {}): PkiIssuanceGrant {
  return {
    consumerId: "payments-prod",
    environment: "prod",
    name: "web",
    uid: "uid-1",
    caId: "ca-1",
    status: "ACTIVE",
    expired: false,
    policy: {
      names: { dns: { allow: ["*.payments.example.com"], deny: [] } },
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
      lifetime: { defaultSeconds: 3600, maxSeconds: 7200, minSeconds: 60 },
    },
    policyDigest: "digest-1",
    quotas: { perHour: 100, perDay: 1000 },
    version: "g1",
    createdAt: "2026-01-01T00:00:00Z",
    createdBy: {},
    updatedAt: "2026-01-01T00:00:00Z",
    updatedBy: {},
    ...overrides,
  };
}

const grantInputs = (
  overrides: Partial<ResolvedIssuanceGrantInputs> = {},
): ResolvedIssuanceGrantInputs => ({
  adminUrl: ADMIN_URL,
  providerSchemaVersion: "1",
  consumerId: "payments-prod",
  name: "web",
  caId: "ca-1",
  status: "ACTIVE",
  names: { dns: { allow: ["*.payments.example.com"] } },
  keyUsages: ["digitalSignature"],
  extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
  lifetime: { defaultSeconds: 3600, maxSeconds: 7200 },
  ...overrides,
});

const grantState = (
  overrides: Partial<ResolvedIssuanceGrantState> = {},
): ResolvedIssuanceGrantState => ({
  ...grantInputs(),
  uid: "uid-1",
  version: "g1",
  environment: "prod",
  expired: false,
  policyDigest: "digest-1",
  resolvedQuotas: { perHour: 100, perDay: 1000 },
  ...overrides,
});

const grantProvider = (client: HemligGrantClient): HemligIssuanceGrantProvider =>
  new HemligIssuanceGrantProvider(() => client, () => TOKEN, NO_DELAY);

test("grant: create over a 404 posts the full body with a key", async () => {
  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
    createIssuanceGrant: () => grantDetail(),
  });
  const result = await grantProvider(client).create(grantInputs());
  assert.equal(result.id, "payments-prod/web");
  assert.equal(result.outs?.uid, "uid-1");
  assert.deepEqual(result.outs?.resolvedQuotas, { perHour: 100, perDay: 1000 });
  const [call] = callsOf(calls, "createIssuanceGrant");
  assert.equal(call?.args[1], "payments-prod");
  const body = call?.args[2] as Record<string, unknown>;
  assert.equal(body.name, "web");
  assert.equal(body.status, "ACTIVE");
  assert.equal("displayName" in body, false);
  assert.match(call?.args[3] as string, /^pulumi-grant-create-/);
});

test("grant: create over a tombstone posts; over a live grant throws without posting", async () => {
  const tombstone = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ status: "DELETED" }),
    createIssuanceGrant: () => grantDetail({ uid: "uid-2" }),
  });
  const result = await grantProvider(tombstone.client).create(grantInputs());
  assert.equal(result.outs?.uid, "uid-2");

  const live = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail(),
  });
  await assert.rejects(
    grantProvider(live.client).create(grantInputs()),
    /import: "payments-prod\/web"/,
  );
  assert.equal(callsOf(live.calls, "createIssuanceGrant").length, 0);

  const raced = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
    createIssuanceGrant: () => {
      throw http(409, "conflict", "grant_exists");
    },
  });
  await assert.rejects(grantProvider(raced.client).create(grantInputs()), /exists/);
});

test("grant: update is read-modify-write with If-Match equal to the fresh version", async () => {
  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ version: "g9" }),
    updateIssuanceGrant: () => grantDetail({ version: "g10" }),
  });
  const result = await grantProvider(client).update(
    "payments-prod/web",
    grantState(),
    grantInputs({ lifetime: { defaultSeconds: 3600, maxSeconds: 3600 } }),
  );
  const [call] = callsOf(calls, "updateIssuanceGrant");
  assert.equal(call?.args[3], "g9");
  assert.equal((call?.args[4] as Record<string, unknown>).status, "ACTIVE");
  assert.match(call?.args[5] as string, /^pulumi-grant-update-/);
  assert.equal(result.outs?.version, "g10");
});

test("grant: a 412 re-reads and retries with the new version and a new key; three 412s throw", async () => {
  let gets = 0;
  let puts = 0;
  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ version: `g${(gets += 1)}` }),
    updateIssuanceGrant: () => {
      puts += 1;
      if (puts === 1) {
        throw http(412, "precondition_failed");
      }
      return grantDetail({ version: "done" });
    },
  });
  const result = await grantProvider(client).update(
    "payments-prod/web",
    grantState(),
    grantInputs({ displayName: "Web" }),
  );
  const attempts = callsOf(calls, "updateIssuanceGrant");
  assert.equal(attempts.length, 2);
  assert.equal(attempts[0]?.args[3], "g1");
  assert.equal(attempts[1]?.args[3], "g2");
  assert.notEqual(attempts[0]?.args[5], attempts[1]?.args[5]);
  assert.equal(result.outs?.version, "done");

  const always = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail(),
    updateIssuanceGrant: () => {
      throw http(412, "precondition_failed");
    },
  });
  await assert.rejects(
    grantProvider(always.client).update(
      "payments-prod/web",
      grantState(),
      grantInputs({ displayName: "Web" }),
    ),
    /three times/,
  );
  assert.equal(callsOf(always.calls, "updateIssuanceGrant").length, 3);
});

test("grant: a network error on PUT retries with the same key and version", async () => {
  let puts = 0;
  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ version: "g5" }),
    updateIssuanceGrant: () => {
      puts += 1;
      if (puts === 1) {
        throw new Error("ECONNRESET");
      }
      return grantDetail({ version: "g6" });
    },
  });
  await grantProvider(client).update(
    "payments-prod/web",
    grantState(),
    grantInputs({ displayName: "Web" }),
  );
  const attempts = callsOf(calls, "updateIssuanceGrant");
  assert.equal(attempts[0]?.args[3], "g5");
  assert.equal(attempts[1]?.args[3], "g5");
  assert.equal(attempts[0]?.args[5], attempts[1]?.args[5]);
});

test("grant: the drift guard refuses to undo an out-of-band disable or migration", async () => {
  const disabled = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ status: "DISABLED" }),
  });
  await assert.rejects(
    grantProvider(disabled.client).update(
      "payments-prod/web",
      grantState(),
      grantInputs({ displayName: "Web" }),
    ),
    /status changed outside Pulumi/,
  );
  assert.equal(callsOf(disabled.calls, "updateIssuanceGrant").length, 0);

  const migrated = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ caId: "ca-2" }),
  });
  await assert.rejects(
    grantProvider(migrated.client).update(
      "payments-prod/web",
      grantState(),
      grantInputs({ displayName: "Web" }),
    ),
    /caId changed outside Pulumi/,
  );
  assert.equal(callsOf(migrated.calls, "updateIssuanceGrant").length, 0);

  // A deliberate disable, or a deliberate move to another CA, is allowed.
  const allowed = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ caId: "ca-2" }),
    updateIssuanceGrant: () => grantDetail({ caId: "ca-2" }),
  });
  await grantProvider(allowed.client).update(
    "payments-prod/web",
    grantState(),
    grantInputs({ caId: "ca-2" }),
  );
});

test("grant: update of a grant deleted outside Pulumi asks for a refresh", async () => {
  const missing = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
  });
  await assert.rejects(
    grantProvider(missing.client).update("payments-prod/web", grantState(), grantInputs()),
    /pulumi refresh/,
  );
  const tombstone = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ status: "DELETED" }),
  });
  await assert.rejects(
    grantProvider(tombstone.client).update("payments-prod/web", grantState(), grantInputs()),
    /pulumi refresh/,
  );
});

test("grant: a caId change updates in place; consumerId and name replace", async () => {
  const provider = grantProvider(fake<HemligGrantClient>({}).client);
  assert.deepEqual(await provider.diff("x", grantState(), grantInputs({ caId: "ca-2" })), {
    changes: true,
    replaces: [],
    deleteBeforeReplace: false,
  });
  const replaced = await provider.diff(
    "x",
    grantState(),
    grantInputs({ consumerId: "other", name: "api" }),
  );
  assert.deepEqual(replaced.replaces, ["consumerId", "name"]);
  assert.equal(replaced.deleteBeforeReplace, false);
  assert.equal((await provider.diff("x", grantState(), grantInputs())).changes, false);
  assert.equal(
    (
      await provider.diff(
        "x",
        grantState({ expiresAt: "2027-01-01T00:00:00Z" }),
        grantInputs({ expiresAt: "2027-01-01T00:00:00.000Z" }),
      )
    ).changes,
    false,
    "expiresAt compares as an instant",
  );
});

test("grant: check defaults status to ACTIVE and an omitted displayName is sent without it", async () => {
  const provider = grantProvider(fake<HemligGrantClient>({}).client);
  const { status: _status, ...withoutStatus } = grantInputs();
  const checked = await provider.check({}, withoutStatus as ResolvedIssuanceGrantInputs);
  assert.equal((checked.inputs as ResolvedIssuanceGrantInputs).status, "ACTIVE");

  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ displayName: "Old" }),
    updateIssuanceGrant: () => grantDetail(),
  });
  await grantProvider(client).update(
    "payments-prod/web",
    grantState({ displayName: "Old" }),
    grantInputs(),
  );
  assert.equal(
    "displayName" in (callsOf(calls, "updateIssuanceGrant")[0]?.args[4] as object),
    false,
  );

  const secret = await provider.check(
    {},
    grantInputs({ displayName: "-----BEGIN RSA PRIVATE KEY-----" }),
  );
  assert.deepEqual(failedProperties(secret), ["inputs"]);
});

test("grant: delete retries a 412; a tombstone or 404 makes no call; it never revokes", async () => {
  let deletes = 0;
  let gets = 0;
  const { client, calls } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ version: `g${(gets += 1)}` }),
    deleteIssuanceGrant: () => {
      deletes += 1;
      if (deletes === 1) {
        throw http(412, "precondition_failed");
      }
      return grantDetail({ status: "DELETED" });
    },
  });
  await grantProvider(client).delete("payments-prod/web", grantState());
  const attempts = callsOf(calls, "deleteIssuanceGrant");
  assert.equal(attempts.length, 2);
  assert.equal(attempts[0]?.args[3], "g1");
  assert.equal(attempts[1]?.args[3], "g2");
  assert.notEqual(attempts[0]?.args[4], attempts[1]?.args[4]);

  const tombstone = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ status: "DELETED" }),
  });
  await grantProvider(tombstone.client).delete("payments-prod/web", grantState());
  const missing = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
  });
  await grantProvider(missing.client).delete("payments-prod/web", grantState());
  assert.equal(tombstone.calls.length, 1);
  assert.equal(missing.calls.length, 1);
});

test("grant: read of a missing grant throws; a tombstone returns {}", async () => {
  const missing = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
  });
  await assert.rejects(
    grantProvider(missing.client).read("payments-prod/web", grantState()),
    /not found/,
  );
  const tombstone = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ status: "DELETED" }),
  });
  assert.deepEqual(
    await grantProvider(tombstone.client).read("payments-prod/web", grantState()),
    {},
  );
});

test("grant: refresh keeps the declared form on an equal digest and takes the server policy otherwise", async () => {
  const equal = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ displayName: "Web" }),
  });
  const kept = (await grantProvider(equal.client).read(
    "payments-prod/web",
    grantState({ displayName: "Web" }),
  )) as pulumi.dynamic.ReadResult & { inputs: ResolvedIssuanceGrantInputs };
  assert.deepEqual(kept.inputs.names, { dns: { allow: ["*.payments.example.com"] } });

  const different = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () =>
      grantDetail({
        policyDigest: "digest-2",
        caId: "ca-2",
        policy: {
          ...grantDetail().policy,
          names: { dns: { allow: ["*.other.example.com"], deny: [] } },
        },
      }),
  });
  const refreshed = (await grantProvider(different.client).read(
    "payments-prod/web",
    grantState(),
  )) as pulumi.dynamic.ReadResult & { inputs: ResolvedIssuanceGrantInputs };
  assert.deepEqual(refreshed.inputs.names, {
    dns: { allow: ["*.other.example.com"], deny: [] },
  });
  assert.equal(refreshed.inputs.caId, "ca-2");
  assert.equal((refreshed.props as ResolvedIssuanceGrantState).policyDigest, "digest-2");
});

test("grant: import takes the server's normalized form", async () => {
  const { client } = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => grantDetail({ displayName: "Web" }),
  });
  const result = (await grantProvider(client).read("payments-prod/web", {
    adminUrl: ADMIN_URL,
  } as ResolvedIssuanceGrantState)) as pulumi.dynamic.ReadResult & {
    inputs: ResolvedIssuanceGrantInputs;
  };
  assert.equal(result.id, "payments-prod/web");
  assert.equal(result.inputs.consumerId, "payments-prod");
  assert.equal(result.inputs.name, "web");
  assert.deepEqual(result.inputs.names, {
    dns: { allow: ["*.payments.example.com"], deny: [] },
  });
});

// ---------------------------------------------------------------------------
// Provider-wide
// ---------------------------------------------------------------------------

test("pemBodiesEqual ignores whitespace and labels", () => {
  assert.equal(pemBodiesEqual(CERT, CERT_REWRAPPED), true);
  assert.equal(pemBodiesEqual(CERT, OTHER_CERT), false);
  assert.equal(pemBodiesEqual(undefined, undefined), true);
  assert.equal(pemBodiesEqual(CERT, undefined), false);
});

test("no output contains the token or private key material, and errors redact the token", async () => {
  const { client } = fake<HemligCaClient>({
    createPkiCa: () => caDetail({ csrPem: CSR }),
  });
  const created = await caProvider(client).create(caInputs());
  const grants = fake<HemligGrantClient>({
    getAdminIssuanceGrant: () => {
      throw http(404, "not_found");
    },
    createIssuanceGrant: () => grantDetail(),
  });
  const grant = await grantProvider(grants.client).create(grantInputs());
  for (const outs of [created.outs, grant.outs]) {
    const text = JSON.stringify(outs);
    assert.equal(text.includes(TOKEN), false);
    assert.equal(text.includes("PRIVATE KEY"), false);
  }

  const leaky = fake<HemligCaClient>({
    createPkiCa: () => {
      throw http(400, "bad_request", "invalid", `echoed Authorization: Bearer ${TOKEN}`);
    },
  });
  const previous = process.env.HEMLIG_ADMIN_TOKEN;
  process.env.HEMLIG_ADMIN_TOKEN = TOKEN;
  try {
    await assert.rejects(caProvider(leaky.client).create(caInputs()), (error: Error) => {
      assert.equal(error.message.includes(TOKEN), false);
      assert.match(error.message, /\[redacted\]/);
      return true;
    });
  } finally {
    if (previous === undefined) {
      delete process.env.HEMLIG_ADMIN_TOKEN;
    } else {
      process.env.HEMLIG_ADMIN_TOKEN = previous;
    }
  }
});

test("serializing either provider does not capture the administrator token", async () => {
  const previous = process.env.HEMLIG_ADMIN_TOKEN;
  process.env.HEMLIG_ADMIN_TOKEN = "sentinel-serialization-token";
  try {
    for (const provider of [
      new HemligCertificateAuthorityProvider(),
      new HemligIssuanceGrantProvider(),
    ]) {
      const serialized = await pulumi.runtime.serializeFunction(() => provider);
      assert.equal(serialized.text.includes("sentinel-serialization-token"), false);
    }
  } finally {
    if (previous === undefined) {
      delete process.env.HEMLIG_ADMIN_TOKEN;
    } else {
      process.env.HEMLIG_ADMIN_TOKEN = previous;
    }
  }
});
