import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  HemligError,
  type TransportRequest,
  type TransportResponse,
} from "@zyno-io/hemlig-client";
import { runCli } from "./index";
import {
  derToPem,
  incrementTrailingInteger,
  isCaId,
  parseDuration,
  parseSubject,
} from "./pki";

const token = "test.header.signature";
const env = {
  HEMLIG_ADMIN_URL: "https://admin.example.test",
  HEMLIG_ENVIRONMENT: "production",
  HEMLIG_ADMIN_TOKEN: token,
};
const caId = "ca-11111111-2222-3333-4444-555555555555";
const extId = `ext-${"ab".repeat(20)}`;
const policy = {
  maxLeafLifetimeSeconds: 7776000,
  leafKeyAlgorithms: ["ECDSA_P256"],
  capacity: 8000,
  issuancePerHour: 2000,
  crlValiditySeconds: 604800,
  issueLeaves: true,
  issueSubordinates: false,
};
const detail = {
  caId,
  environment: "production",
  name: "issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "pkv-1",
  keyAlgorithm: "ECDSA_P256",
  key: { algorithm: "ECDSA_P256", state: "ACTIVE" },
  subject: { commonName: "Issuing CA 1", organization: "Example" },
  requestedConstraints: {
    nameConstraints: { permitted: { dns: [".a.test"] } },
  },
  policy,
  parent: { type: "external", id: extId },
};

type Responder = (request: TransportRequest) => TransportResponse;

async function execute(
  args: string[],
  respond: Responder = () => ({ status: 200, headers: {}, body: detail }),
  environment: NodeJS.ProcessEnv = env,
) {
  const requests: TransportRequest[] = [];
  let stdout = "";
  let stderr = "";
  const exitCode = await runCli(args, {
    env: environment,
    configDir: join(tmpdir(), "hemlig-cli-test-no-config"),
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    transport: {
      async request(request) {
        requests.push(request);
        return respond(request);
      },
    },
  });
  return { exitCode, stdout, stderr, requests };
}

const withDir = async (run: (dir: string) => Promise<void>) => {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-pki-test-"));
  try {
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

test("helpers: subject parsing, durations, ids and rollover increments", () => {
  assert.deepEqual(parseSubject("cn=Example CA, O=Acme\\, Inc., c=US"), {
    commonName: "Example CA",
    organization: "Acme, Inc.",
    country: "US",
  });
  assert.throws(() => parseSubject("O=Acme"), /CN/);
  assert.throws(() => parseSubject("CN=a,CN=b"), /repeats/);
  for (const bad of [
    "CN=Issuing CA 1,o=Example Corp,x",
    "CN=X,O=Example,DC=example",
    "CN=X,",
    "CN=X,O=",
    "CN=X,O=Acme, Inc.",
  ])
    assert.throws(() => parseSubject(bad), bad);
  assert.deepEqual(parseSubject("CN=X,o=Example"), {
    commonName: "X",
    organization: "Example",
  });
  assert.throws(() => parseSubject("XX=a,CN=b"), /KEY=value/);
  assert.equal(parseDuration("x", "90d"), 7776000);
  assert.equal(parseDuration("x", "2h"), 7200);
  assert.equal(parseDuration("x", "45"), 45);
  assert.throws(() => parseDuration("x", "1w"));
  assert.equal(isCaId(caId), true);
  assert.equal(isCaId("ca-prod"), false);
  assert.equal(incrementTrailingInteger("issuing-1"), "issuing-2");
  assert.equal(incrementTrailingInteger("CA 009"), "CA 010");
  assert.equal(incrementTrailingInteger("issuing"), undefined);
  assert.match(
    derToPem(Buffer.alloc(100), "CERTIFICATE"),
    /^-----BEGIN CERTIFICATE-----\n/,
  );
});

test("usage errors exit 2 and send nothing", async () => {
  for (const args of [
    ["pki"],
    ["pki", "ca"],
    ["pki", "ca", "bogus"],
    ["pki", "ca", "get"],
    ["pki", "ca", "get", caId, "extra"],
    ["pki", "ca", "get", caId, "--cursor", "x"],
    ["pki", "ca", "get", caId, "--environment", "a", "--environment", "b"],
    ["pki", "ca", "delete", caId],
    ["pki", "ca", "crl", "get", caId],
    ["pki", "ca", "create", "--name", "x"],
    ["pki", "external-ca", "get", "ext-short"],
    ["pki", "external-ca", "upload-crl", "--crl", "x"],
  ]) {
    const result = await execute(args);
    assert.equal(result.exitCode, 2, args.join(" "));
    assert.equal(result.stdout, "");
    assert.equal(result.requests.length, 0, args.join(" "));
  }
});

test("pki help is JSON and the top-level help lists pki", async () => {
  const result = await execute(["pki", "--help"]);
  assert.equal(result.exitCode, 0);
  assert.ok(JSON.parse(result.stdout).commands["ca create"]);
  assert.ok(JSON.parse((await execute(["--help"])).stdout).pki);
});

test("ca get resolves a name by listing pages and reports exit 4 when missing", async () => {
  const pages: Responder = (request) => {
    if (request.url.pathname.endsWith("/cas") && request.method === "GET") {
      const cursor = request.url.searchParams.get("cursor");
      return {
        status: 200,
        headers: {},
        body:
          cursor === null
            ? { cas: [{ caId: "ca-other", name: "x" }], nextCursor: "p2" }
            : { cas: [{ caId, name: "issuing-1" }] },
      };
    }
    return { status: 200, headers: {}, body: detail };
  };
  const found = await execute(["pki", "ca", "get", "issuing-1"], pages);
  assert.equal(found.exitCode, 0);
  assert.deepEqual(
    found.requests.map((r) => r.url.pathname + r.url.search),
    [
      "/v1/admin/pki/cas?environment=production",
      "/v1/admin/pki/cas?environment=production&cursor=p2",
      `/v1/admin/pki/cas/${caId}`,
    ],
  );
  assert.equal(JSON.parse(found.stdout).etag, "pkv-1");
  const missing = await execute(["pki", "ca", "get", "nope"], pages);
  assert.equal(missing.exitCode, 4);
  const noEnv = await execute(["pki", "ca", "get", "issuing-1"], pages, {
    ...env,
    HEMLIG_ENVIRONMENT: undefined,
  });
  assert.equal(noEnv.exitCode, 2);
  const byId = await execute(["pki", "ca", "get", caId], pages, {
    ...env,
    HEMLIG_ENVIRONMENT: undefined,
  });
  assert.equal(byId.exitCode, 0);
  assert.equal(byId.requests.length, 1);
});

test("ca create builds the request, writes the CSR file and refuses to overwrite", async () => {
  await withDir(async (dir) => {
    const csrPath = join(dir, "ca.csr");
    const respond: Responder = () => ({
      status: 201,
      headers: {},
      body: {
        ...detail,
        csrPem:
          "-----BEGIN CERTIFICATE REQUEST-----\nAA\n-----END CERTIFICATE REQUEST-----\n",
        warnings: [
          { code: "ed25519_compatibility", message: "Ed25519 caveat." },
        ],
      },
    });
    const args = [
      "pki",
      "ca",
      "create",
      "--name",
      "issuing-1",
      "--key-algorithm",
      "ED25519",
      "--subject",
      "CN=Issuing CA 1,O=Example",
      "--permit-dns",
      ".a.test",
      "--permit-dns",
      ".b.test",
      "--exclude-ip",
      "10.0.0.0/8",
      "--eku",
      "serverAuth",
      "--max-leaf-lifetime",
      "30d",
      "--leaf-key-algorithm",
      "ECDSA_P256",
      "--leaf-key-algorithm",
      "ED25519",
      "--capacity",
      "100",
      "--crl-validity",
      "1d",
      "--idempotency-key",
      "key-12345678",
      "--csr-out",
      csrPath,
    ];
    const result = await execute(args, respond);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stderr, /warning: Ed25519 caveat/);
    const request = result.requests[0]!;
    assert.equal(request.method, "POST");
    assert.equal(request.headers?.["idempotency-key"], "key-12345678");
    assert.deepEqual(request.body, {
      environment: "production",
      name: "issuing-1",
      kind: "EXTERNAL_INTERMEDIATE",
      keyAlgorithm: "ED25519",
      subject: { commonName: "Issuing CA 1", organization: "Example" },
      requestedConstraints: {
        nameConstraints: {
          permitted: { dns: [".a.test", ".b.test"] },
          excluded: { ip: ["10.0.0.0/8"] },
        },
        extendedKeyUsages: ["serverAuth"],
      },
      policy: {
        maxLeafLifetimeSeconds: 2592000,
        leafKeyAlgorithms: ["ECDSA_P256", "ED25519"],
        capacity: 100,
        crlValiditySeconds: 86400,
      },
    });
    assert.match(await readFile(csrPath, "utf8"), /BEGIN CERTIFICATE REQUEST/);
    const receipt = JSON.parse(result.stdout);
    assert.equal(receipt.data.csrPem, undefined);
    assert.equal(receipt.data.csrOut, csrPath);
    assert.equal(receipt.data.warnings[0].code, "ed25519_compatibility");

    const again = await execute(args, respond);
    assert.equal(again.exitCode, 9);
    assert.equal(again.requests.length, 0);
    assert.equal(
      await readFile(csrPath, "utf8").then((t) => t.includes("AA")),
      true,
    );
  });
});

test("a failed create leaves no --csr-out placeholder", async () => {
  await withDir(async (dir) => {
    const csrPath = join(dir, "ca.csr");
    const result = await execute(
      [
        "pki",
        "ca",
        "create",
        "--name",
        "n",
        "--key-algorithm",
        "ECDSA_P256",
        "--subject",
        "CN=x",
        "--csr-out",
        csrPath,
      ],
      () => ({
        status: 409,
        headers: {},
        body: {
          error: {
            code: "conflict",
            message: "m",
            details: { reason: "name_in_use" },
          },
        },
      }),
    );
    assert.equal(result.exitCode, 5);
    await assert.rejects(readFile(csrPath));
  });
});

test("rollover copies the old CA and increments name and CN", async () => {
  const respond: Responder = (request) =>
    request.method === "POST"
      ? { status: 201, headers: {}, body: { ...detail, csrPem: "CSR" } }
      : { status: 200, headers: {}, body: detail };
  const result = await execute(
    ["pki", "ca", "create", "--rollover-from", caId, "--capacity", "50"],
    respond,
    { ...env, HEMLIG_ENVIRONMENT: undefined },
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const body = result.requests[1]!.body as Record<string, unknown>;
  assert.equal(body.environment, "production");
  assert.equal(body.name, "issuing-2");
  assert.equal(body.keyAlgorithm, "ECDSA_P256");
  assert.deepEqual(body.subject, {
    commonName: "Issuing CA 2",
    organization: "Example",
  });
  assert.deepEqual(body.requestedConstraints, detail.requestedConstraints);
  assert.deepEqual(body.policy, {
    maxLeafLifetimeSeconds: 7776000,
    leafKeyAlgorithms: ["ECDSA_P256"],
    capacity: 50,
    issuancePerHour: 2000,
    crlValiditySeconds: 604800,
  });
  // explicit flags override; a name without a trailing integer needs --name
  const override = await execute(
    [
      "pki",
      "ca",
      "create",
      "--rollover-from",
      caId,
      "--name",
      "next",
      "--subject",
      "CN=Next",
    ],
    respond,
  );
  assert.equal(override.exitCode, 0);
  assert.equal((override.requests[1]!.body as { name: string }).name, "next");
  const noInteger = await execute(
    ["pki", "ca", "create", "--rollover-from", caId],
    (request) =>
      request.method === "GET"
        ? { status: 200, headers: {}, body: { ...detail, name: "issuing" } }
        : { status: 500, headers: {} },
  );
  assert.equal(noInteger.exitCode, 2);
  assert.equal(noInteger.requests.length, 1);
});

test("activate reads PEM as text and DER as wrapped PEM / base64", async () => {
  await withDir(async (dir) => {
    const pemPath = join(dir, "cert.pem");
    const derPath = join(dir, "chain.der");
    const crlPath = join(dir, "root.crl");
    const pem =
      "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const der = Buffer.from([0x30, 0x82, 0xff, 0x00]);
    await writeFile(pemPath, pem);
    await writeFile(derPath, der);
    await writeFile(crlPath, der);
    const result = await execute([
      "pki",
      "ca",
      "activate",
      caId,
      "--certificate",
      pemPath,
      "--chain",
      derPath,
      "--root-crl",
      crlPath,
      "--accept-broader-constraints",
    ]);
    assert.equal(result.exitCode, 0, result.stderr);
    const request = result.requests[0]!;
    assert.equal(request.url.pathname, `/v1/admin/pki/cas/${caId}/certificate`);
    assert.deepEqual(request.body, {
      certificatePem: pem,
      chainPem: derToPem(der, "CERTIFICATE"),
      rootCrl: der.toString("base64"),
      acceptBroaderConstraints: true,
    });
    const missing = await execute([
      "pki",
      "ca",
      "activate",
      caId,
      "--certificate",
      join(dir, "none"),
      "--chain",
      pemPath,
    ]);
    assert.equal(missing.exitCode, 9);
    assert.equal(missing.requests.length, 0);
  });
});

test("update merges flags over the current policy and supports --if-match current", async () => {
  const respond: Responder = () => ({
    status: 200,
    headers: {},
    body: { ...detail, displayName: "Shown" },
  });
  const result = await execute(
    ["pki", "ca", "update", caId, "--if-match", "current", "--capacity", "10"],
    respond,
  );
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.requests[0]!.method, "GET");
  const put = result.requests[1]!;
  assert.equal(put.method, "PUT");
  assert.equal(put.headers?.["if-match"], '"pkv-1"');
  assert.deepEqual(put.body, {
    displayName: "Shown",
    policy: {
      maxLeafLifetimeSeconds: 7776000,
      leafKeyAlgorithms: ["ECDSA_P256"],
      capacity: 10,
      issuancePerHour: 2000,
      crlValiditySeconds: 604800,
    },
  });
  assert.equal(JSON.parse(result.stdout).ifMatch, "pkv-1");
  const noFlags = await execute([
    "pki",
    "ca",
    "update",
    caId,
    "--if-match",
    "pkv-1",
  ]);
  assert.equal(noFlags.exitCode, 2);
  const weak = await execute([
    "pki",
    "ca",
    "delete",
    caId,
    "--if-match",
    "W/x",
  ]);
  assert.equal(weak.exitCode, 2);
});

test("delete, retire, destroy-key and crl publish use the right routes", async () => {
  const cases: [string[], string, string][] = [
    [
      ["delete", caId, "--if-match", "pkv-1"],
      "DELETE",
      `/v1/admin/pki/cas/${caId}`,
    ],
    [["retire", caId], "POST", `/v1/admin/pki/cas/${caId}/retire`],
    [["destroy-key", caId], "POST", `/v1/admin/pki/cas/${caId}/destroy-key`],
    [["crl", "publish", caId], "POST", `/v1/admin/pki/cas/${caId}/crl`],
  ];
  for (const [args, method, path] of cases) {
    const result = await execute(["pki", "ca", ...args]);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.requests[0]!.method, method);
    assert.equal(result.requests[0]!.url.pathname, path);
    assert.match(JSON.parse(result.stdout).idempotencyKey, /^[a-f0-9-]{36}$/);
  }
});

test("crl get writes the exact bytes (and PEM on request) and reports the receipt", async () => {
  await withDir(async (dir) => {
    const bytes = Uint8Array.from([0x30, 0xff, 0xfe, 0x00, 0x80]);
    const sha = createHash("sha256").update(bytes).digest("hex");
    const respond: Responder = () => ({
      status: 200,
      headers: { etag: `"${sha}"` },
      bytes,
    });
    const derPath = join(dir, "ca.crl");
    const result = await execute(
      ["pki", "ca", "crl", "get", caId, "--out", derPath],
      respond,
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(Array.from(await readFile(derPath)), Array.from(bytes));
    assert.equal(result.requests[0]!.responseType, "binary");
    const receipt = JSON.parse(result.stdout).data;
    assert.equal(receipt.bytes, 5);
    assert.equal(receipt.etag, sha);
    assert.equal(receipt.notModified, false);
    assert.match(receipt.sha256, /^[0-9a-f]{64}$/);
    assert.equal(result.stdout.includes("MP"), false);

    const pemPath = join(dir, "ca.pem");
    const pem = await execute(
      ["pki", "ca", "crl", "get", extId, "--out", pemPath, "--format", "pem"],
      respond,
    );
    assert.equal(pem.exitCode, 0);
    assert.equal(pem.requests[0]!.url.pathname, `/v1/admin/pki/crls/${extId}`);
    assert.match(
      await readFile(pemPath, "utf8"),
      /^-----BEGIN X509 CRL-----\n/,
    );

    const notModified = await execute(
      [
        "pki",
        "ca",
        "crl",
        "get",
        caId,
        "--out",
        join(dir, "none.crl"),
        "--if-none-match",
        "abc",
      ],
      () => ({ status: 304, headers: { etag: '"abc"' } }),
    );
    assert.equal(notModified.exitCode, 0);
    assert.equal(notModified.requests[0]!.headers?.["if-none-match"], '"abc"');
    assert.equal(JSON.parse(notModified.stdout).data.notModified, true);
    await assert.rejects(readFile(join(dir, "none.crl")));
  });
});

test("upload-crl accepts an ext id or --for-ca and sends DER as base64", async () => {
  await withDir(async (dir) => {
    const crlPath = join(dir, "root.crl");
    const der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0xff]);
    await writeFile(crlPath, der);
    const direct = await execute([
      "pki",
      "external-ca",
      "upload-crl",
      extId,
      "--crl",
      crlPath,
    ]);
    assert.equal(direct.exitCode, 0, direct.stderr);
    assert.equal(
      direct.requests[0]!.url.pathname,
      `/v1/admin/pki/external-cas/${extId}/crl`,
    );
    assert.deepEqual(direct.requests[0]!.body, { crl: der.toString("base64") });
    const viaCa = await execute([
      "pki",
      "external-ca",
      "upload-crl",
      "--for-ca",
      caId,
      "--crl",
      crlPath,
    ]);
    assert.equal(viaCa.exitCode, 0, viaCa.stderr);
    assert.equal(viaCa.requests[0]!.method, "GET");
    assert.equal(
      viaCa.requests[1]!.url.pathname,
      `/v1/admin/pki/external-cas/${extId}/crl`,
    );
    const both = await execute([
      "pki",
      "external-ca",
      "upload-crl",
      extId,
      "--for-ca",
      caId,
      "--crl",
      crlPath,
    ]);
    assert.equal(both.exitCode, 2);
    const pending = await execute(
      ["pki", "external-ca", "upload-crl", "--for-ca", caId, "--crl", crlPath],
      () => ({
        status: 200,
        headers: {},
        body: { ...detail, parent: undefined },
      }),
    );
    assert.equal(pending.exitCode, 5);
  });
});

test("external-ca list and get", async () => {
  const list = await execute(["pki", "external-ca", "list", "--cursor", "c1"]);
  assert.equal(list.requests[0]!.url.search, "?cursor=c1");
  const get = await execute(["pki", "external-ca", "get", extId]);
  assert.equal(
    get.requests[0]!.url.pathname,
    `/v1/admin/pki/external-cas/${extId}`,
  );
});

test("error envelope carries apiCode and apiDetails and maps exit codes", async () => {
  const failing =
    (status: number, code: string): Responder =>
    () => ({
      status,
      headers: {},
      body: {
        error: {
          code,
          message: "secret-detail",
          details: { reason: "ca_not_active" },
        },
      },
    });
  const cases: [number, number][] = [
    [400, 2],
    [403, 3],
    [404, 4],
    [409, 5],
    [412, 6],
    [503, 7],
  ];
  for (const [status, exit] of cases) {
    const result = await execute(
      ["pki", "ca", "retire", caId],
      failing(status, "ca_not_active"),
    );
    assert.equal(result.exitCode, exit, String(status));
    const body = JSON.parse(result.stderr);
    assert.equal(body.error.apiCode, "ca_not_active");
    assert.deepEqual(body.error.apiDetails, { reason: "ca_not_active" });
    assert.equal(body.error.outcome, exit <= 6 ? "rejected" : "unknown");
    assert.equal(result.stderr.includes("secret-detail"), false);
  }
  const network = await runCli(["pki", "ca", "get", caId], {
    env,
    configDir: join(tmpdir(), "hemlig-cli-test-no-config"),
    stderr: () => undefined,
    transport: {
      async request() {
        throw new TypeError("fetch failed");
      },
    },
  });
  assert.equal(network, 8);
  assert.ok(new HemligError(500, "x") instanceof Error);
});

test("non-pki error envelopes stay unchanged", async () => {
  const result = await runCli(
    ["secret", "read", "--secret-id", "payments/stripe/api-key"],
    {
      env,
      configDir: join(tmpdir(), "hemlig-cli-test-no-config"),
      stderr: () => undefined,
      transport: {
        async request() {
          return {
            status: 409,
            headers: {},
            body: {
              error: {
                code: "conflict",
                message: "m",
                details: { reason: "r" },
              },
            },
          };
        },
      },
    },
  );
  assert.equal(result, 5);
});

test("crl get verifies type and ETag and leaves no file on failure", async () => {
  await withDir(async (dir) => {
    const out = join(dir, "x.crl");
    const bad = await execute(
      ["pki", "ca", "crl", "get", caId, "--out", out],
      () => ({
        status: 200,
        headers: { etag: '"deadbeef"', "content-type": "application/pkix-crl" },
        bytes: Uint8Array.from([0x30, 0x00]),
      }),
    );
    assert.equal(bad.exitCode, 7);
    const html = await execute(
      ["pki", "ca", "crl", "get", caId, "--out", out],
      () => ({
        status: 200,
        headers: { "content-type": "text/html" },
        bytes: Buffer.from("<html>"),
      }),
    );
    assert.equal(html.exitCode, 7);
    await assert.rejects(readFile(out));
    assert.deepEqual(await readdir(dir), []);
  });
});

test("an unrelated invalid HEMLIG_ENVIRONMENT is ignored when not needed", async () => {
  const bad = { ...env, HEMLIG_ENVIRONMENT: "BAD ENV" };
  assert.equal(
    (await execute(["pki", "ca", "get", caId], undefined, bad)).exitCode,
    0,
  );
  assert.equal(
    (await execute(["pki", "ca", "list"], undefined, bad)).exitCode,
    2,
  );
  assert.equal(
    (await execute(["pki", "ca", "get", "name"], undefined, bad)).exitCode,
    2,
  );
});

test("global flags may precede pki, and --if-none-match errors name that flag", async () => {
  const result = await execute([
    "--admin-url",
    "https://admin.example.test",
    "pki",
    "ca",
    "get",
    caId,
  ]);
  assert.equal(result.exitCode, 0, result.stderr);
  await withDir(async (dir) => {
    const bad = await execute([
      "pki",
      "ca",
      "crl",
      "get",
      caId,
      "--out",
      join(dir, "o"),
      "--if-none-match",
      "W/x",
    ]);
    assert.equal(bad.exitCode, 2);
    assert.match(JSON.parse(bad.stderr).error.message, /--if-none-match/);
  });
});

test("a CSR write failure after create says the CA exists", async () => {
  await withDir(async (dir) => {
    const csrPath = join(dir, "ca.csr");
    const result = await execute(
      [
        "pki",
        "ca",
        "create",
        "--name",
        "n",
        "--key-algorithm",
        "ECDSA_P256",
        "--subject",
        "CN=x",
        "--csr-out",
        csrPath,
      ],
      // csrPem is not a string, so the write through the handle fails.
      () => ({ status: 201, headers: {}, body: { ...detail, csrPem: 42 } }),
    );
    assert.equal(result.exitCode, 9);
    assert.match(JSON.parse(result.stderr).error.message, /CA was created/);
  });
});

// ---------------------------------------------------------------------------
// Phase 4: grants, certificates and bulk revocation.

const grantPolicy = {
  names: { dns: { allow: ["*.acc.example.com"] }, maxSans: 5 },
  keyUsages: ["digitalSignature"],
  extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
  lifetime: { defaultSeconds: 3600, maxSeconds: 86400 },
};
const otherCaId = "ca-99999999-2222-3333-4444-555555555555";
const grantView = (over: Record<string, unknown> = {}) => ({
  consumerId: "web-1",
  environment: "production",
  name: "acc-web",
  uid: "pkg-1",
  caId,
  status: "ACTIVE",
  expired: false,
  policy: grantPolicy,
  version: "pkv-1",
  ...over,
});
const jsonResponse = (body: unknown, status = 200): TransportResponse => ({
  status,
  headers: {},
  body,
});

test("grant file rules and --ca resolution are checked before any request", async () => {
  await withDir(async (dir) => {
    const good = join(dir, "grant.json");
    await writeFile(good, JSON.stringify(grantPolicy));
    const named = join(dir, "named.json");
    await writeFile(named, JSON.stringify({ ...grantPolicy, name: "other" }));
    const withCa = join(dir, "with-ca.json");
    await writeFile(withCa, JSON.stringify({ ...grantPolicy, caId }));
    const notJson = join(dir, "bad.json");
    await writeFile(notJson, "{");
    const big = join(dir, "big.json");
    await writeFile(big, "x".repeat(65537));
    const array = join(dir, "array.json");
    await writeFile(array, "[]");
    for (const args of [
      ["grant", "create", "web-1", "acc-web"],
      ["grant", "create", "web-1", "acc-web", "--file", good],
      ["grant", "create", "web-1", "acc-web", "--file", named, "--ca", caId],
      ["grant", "create", "web-1", "acc-web", "--file", notJson, "--ca", caId],
      ["grant", "create", "web-1", "acc-web", "--file", big, "--ca", caId],
      ["grant", "create", "web-1", "acc-web", "--file", array, "--ca", caId],
      [
        "grant",
        "create",
        "web-1",
        "acc-web",
        "--file",
        withCa,
        "--ca",
        otherCaId,
      ],
      ["grant", "create", "Web", "acc-web", "--file", withCa],
      ["grant", "update", "web-1", "acc-web", "--file", withCa],
      [
        "grant",
        "create",
        "web-1",
        "acc-web",
        "--file",
        withCa,
        "--validate-only",
        "--idempotency-key",
        "key-12345678",
      ],
      ["grant", "delete", "web-1", "acc-web"],
      ["grant", "list"],
      ["grant", "list", "web-1", "--ca", caId],
      ["grant", "get", "web-1"],
    ]) {
      const result = await execute(["pki", ...args]);
      assert.equal(result.exitCode, 2, args.join(" "));
      assert.equal(result.requests.length, 0, args.join(" "));
    }
    const missing = await execute([
      "pki",
      "grant",
      "create",
      "web-1",
      "acc-web",
      "--file",
      join(dir, "nope.json"),
      "--ca",
      caId,
    ]);
    assert.equal(missing.exitCode, 9);
  });
});

test("grant create sends the envelope, resolves --ca by name and replays by key", async () => {
  await withDir(async (dir) => {
    const file = join(dir, "grant.json");
    await writeFile(
      file,
      JSON.stringify({ ...grantPolicy, name: "acc-web", displayName: "Web" }),
    );
    const result = await execute(
      [
        "pki",
        "grant",
        "create",
        "web-1",
        "acc-web",
        "--file",
        file,
        "--ca",
        "issuing-1",
        "--idempotency-key",
        "key-12345678",
      ],
      (request) =>
        request.method === "GET"
          ? jsonResponse({ cas: [{ caId, name: "issuing-1" }] })
          : jsonResponse(grantView(), 201),
    );
    assert.equal(result.exitCode, 0, result.stderr);
    const post = result.requests[1]!;
    assert.equal(post.method, "POST");
    assert.equal(
      post.url.pathname,
      "/v1/admin/pki/consumers/web-1/issuance-grants",
    );
    assert.equal(post.url.search, "");
    assert.equal(post.headers?.["idempotency-key"], "key-12345678");
    assert.deepEqual(post.body, {
      ...grantPolicy,
      displayName: "Web",
      caId,
      name: "acc-web",
    });
    const receipt = JSON.parse(result.stdout);
    assert.equal(receipt.etag, "pkv-1");
    assert.equal(receipt.idempotencyKey, "key-12345678");
  });
});

test("grant create and update --validate-only send validateOnly and no key", async () => {
  await withDir(async (dir) => {
    const file = join(dir, "grant.json");
    await writeFile(file, JSON.stringify({ ...grantPolicy, caId }));
    const created = await execute(
      [
        "pki",
        "grant",
        "create",
        "web-1",
        "acc-web",
        "--file",
        file,
        "--validate-only",
      ],
      () => jsonResponse({ valid: true, errors: [], warnings: [] }),
    );
    assert.equal(created.exitCode, 0, created.stderr);
    const first = created.requests[0]!;
    assert.equal(first.url.searchParams.get("validateOnly"), "true");
    assert.equal(first.headers?.["idempotency-key"], undefined);
    assert.equal(JSON.parse(created.stdout).idempotencyKey, undefined);

    const updated = await execute(
      [
        "pki",
        "grant",
        "update",
        "web-1",
        "acc-web",
        "--file",
        file,
        "--if-match",
        "current",
        "--validate-only",
      ],
      (request) =>
        request.method === "GET"
          ? jsonResponse(grantView({ version: "pkv-7" }))
          : jsonResponse({
              valid: false,
              errors: [{ code: "x", path: "p", message: "m" }],
              warnings: [],
            }),
    );
    assert.equal(updated.exitCode, 5);
    const put = updated.requests[1]!;
    assert.equal(put.method, "PUT");
    assert.equal(put.url.searchParams.get("validateOnly"), "true");
    assert.equal(put.headers?.["if-match"], '"pkv-7"');
    assert.equal(put.headers?.["idempotency-key"], undefined);
    assert.equal(JSON.parse(updated.stdout).data.valid, false);
  });
});

test("grant update and delete send If-Match, and list/get/evaluate read", async () => {
  await withDir(async (dir) => {
    const file = join(dir, "grant.json");
    await writeFile(file, JSON.stringify(grantPolicy));
    const update = await execute(
      [
        "pki",
        "grant",
        "update",
        "web-1",
        "acc-web",
        "--file",
        file,
        "--ca",
        caId,
        "--if-match",
        '"pkv-1"',
        "--idempotency-key",
        "key-12345678",
      ],
      () => jsonResponse(grantView({ version: "pkv-2" })),
    );
    assert.equal(update.exitCode, 0, update.stderr);
    assert.equal(update.requests[0]?.method, "PUT");
    assert.equal(update.requests[0]?.headers?.["if-match"], '"pkv-1"');
    assert.deepEqual(update.requests[0]?.body, { ...grantPolicy, caId });
    const del = await execute(
      ["pki", "grant", "delete", "web-1", "acc-web", "--if-match", "pkv-2"],
      () => jsonResponse(grantView({ status: "DELETED" })),
    );
    assert.equal(del.exitCode, 0, del.stderr);
    assert.equal(del.requests[0]?.method, "DELETE");
    assert.equal(del.requests[0]?.headers?.["if-match"], '"pkv-2"');
    assert.ok(del.requests[0]?.headers?.["idempotency-key"]);

    const byConsumer = await execute(
      ["pki", "grant", "list", "web-1", "--include-deleted", "--cursor", "c1"],
      () => jsonResponse({ grants: [] }),
    );
    assert.equal(
      byConsumer.requests[0]?.url.search,
      "?includeDeleted=true&cursor=c1",
    );
    const byCa = await execute(["pki", "grant", "list", "--ca", caId], () =>
      jsonResponse({ grants: [] }),
    );
    assert.equal(
      byCa.requests[0]?.url.pathname,
      `/v1/admin/pki/cas/${caId}/issuance-grants`,
    );
    const got = await execute(["pki", "grant", "get", "web-1", "acc-web"], () =>
      jsonResponse(grantView()),
    );
    assert.equal(JSON.parse(got.stdout).etag, "pkv-1");
  });
});

test("grant evaluate takes a CSR or names, never both, and refuses a private key", async () => {
  await withDir(async (dir) => {
    const csr = join(dir, "x.csr");
    await writeFile(
      csr,
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
    );
    const key = join(dir, "x.key");
    await writeFile(
      key,
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    );
    for (const args of [
      ["grant", "evaluate", "web-1", "acc-web"],
      [
        "grant",
        "evaluate",
        "web-1",
        "acc-web",
        "--csr",
        csr,
        "--dns",
        "a.example.com",
      ],
      [
        "grant",
        "evaluate",
        "web-1",
        "acc-web",
        "--key-algorithm",
        "ECDSA_P256",
      ],
      [
        "grant",
        "evaluate",
        "web-1",
        "acc-web",
        "--key-algorithm",
        "DES",
        "--cn",
        "x",
      ],
      ["grant", "evaluate", "web-1", "acc-web", "--csr", key],
    ]) {
      const result = await execute(["pki", ...args]);
      assert.equal(result.exitCode, 2, args.join(" "));
      assert.equal(result.requests.length, 0);
      assert.doesNotMatch(result.stderr, /PRIVATE KEY/);
    }
    const viaCsr = await execute(
      [
        "pki",
        "grant",
        "evaluate",
        "web-1",
        "acc-web",
        "--csr",
        csr,
        "--duration",
        "2h",
        "--usage",
        "server auth",
      ],
      () => jsonResponse({ decision: "allow", trace: [], context: {} }),
    );
    assert.equal(viaCsr.exitCode, 0, viaCsr.stderr);
    assert.equal(
      viaCsr.requests[0]?.url.pathname,
      "/v1/admin/pki/consumers/web-1/issuance-grants/acc-web/evaluate",
    );
    assert.deepEqual(viaCsr.requests[0]?.body, {
      certificateSigningRequestPem: await readFile(csr, "utf8"),
      durationSeconds: 7200,
      usages: ["server auth"],
    });
    const viaNames = await execute(
      [
        "pki",
        "grant",
        "evaluate",
        "web-1",
        "acc-web",
        "--key-algorithm",
        "ECDSA_P256",
        "--dns",
        "a.acc.example.com",
        "--dns",
        "b.acc.example.com",
        "--ip",
        "10.0.0.1",
        "--cn",
        "a.acc.example.com",
      ],
      () => jsonResponse({ decision: "deny", trace: [], context: {} }),
    );
    assert.deepEqual(viaNames.requests[0]?.body, {
      keyAlgorithm: "ECDSA_P256",
      sans: {
        dns: ["a.acc.example.com", "b.acc.example.com"],
        ip: ["10.0.0.1"],
      },
      commonName: "a.acc.example.com",
    });
  });
});

const migrateKey = (consumer: string, name: string, version: string) =>
  `migrate-${createHash("sha256")
    .update(JSON.stringify([caId, otherCaId, consumer, name, version]))
    .digest("hex")
    .slice(0, 32)}`;

function migrationServer(
  onPut?: (request: TransportRequest) => TransportResponse,
) {
  const grants: Record<string, ReturnType<typeof grantView>> = {
    a: grantView({
      consumerId: "web-1",
      name: "a",
      uid: "pkg-a",
      version: "v-a",
      displayName: "A",
      expiresAt: "2099-01-01T00:00:00.000Z",
      status: "DISABLED",
    }),
    b: grantView({
      consumerId: "web-2",
      name: "b",
      uid: "pkg-b",
      version: "v-b",
      caId: otherCaId,
    }),
    c: grantView({
      consumerId: "web-3",
      name: "c",
      uid: "pkg-c",
      version: "v-c",
      status: "DELETED",
    }),
    d: grantView({
      consumerId: "web-4",
      name: "d",
      uid: "pkg-d",
      version: "v-d",
    }),
  };
  const respond: Responder = (request) => {
    const path = request.url.pathname;
    if (path === `/v1/admin/pki/cas/${caId}/issuance-grants`)
      return jsonResponse({
        grants: Object.values(grants).filter((g) => g.caId === caId),
      });
    const match = /consumers\/(web-\d)\/issuance-grants\/([a-z])$/.exec(path);
    if (match === null) return jsonResponse({}, 404);
    const grant = grants[match[2]!]!;
    if (request.method === "GET") return jsonResponse(grant);
    return onPut ? onPut(request) : jsonResponse({ ...grant, caId: otherCaId });
  };
  return respond;
}

test("grant migrate --dry-run validates with If-Match, sends no key and writes nothing", async () => {
  const result = await execute(
    ["pki", "grant", "migrate", "--from", caId, "--to", otherCaId, "--dry-run"],
    (request) =>
      request.method === "PUT"
        ? jsonResponse({
            valid: !request.url.pathname.endsWith("/d"),
            errors: request.url.pathname.endsWith("/d")
              ? [
                  {
                    code: "name_outside_constraints",
                    path: "names",
                    message: "m",
                  },
                ]
              : [],
            warnings: [],
          })
        : migrationServer()(request),
  );
  const puts = result.requests.filter((r) => r.method === "PUT");
  assert.equal(puts.length, 2);
  for (const put of puts) {
    assert.equal(put.url.searchParams.get("validateOnly"), "true");
    assert.equal(put.headers?.["idempotency-key"], undefined);
  }
  assert.equal(puts[0]?.headers?.["if-match"], '"v-a"');
  assert.deepEqual(puts[0]?.body, {
    ...grantPolicy,
    caId: otherCaId,
    status: "DISABLED",
    displayName: "A",
    expiresAt: "2099-01-01T00:00:00.000Z",
  });
  assert.equal(result.exitCode, 5);
  const data = JSON.parse(result.stdout).data;
  assert.deepEqual(
    data.results.map((r: { name: string; outcome: string }) => [
      r.name,
      r.outcome,
    ]),
    [
      ["a", "valid"],
      ["c", "skipped"],
      ["d", "invalid"],
    ],
  );
});

test("grant migrate skips moved and deleted grants, uses deterministic keys and exits 5 on failure", async () => {
  // The listing is a snapshot: b lists under the old CA but was moved already.
  const base = migrationServer();
  const listing = [
    { consumerId: "web-1", name: "a" },
    { consumerId: "web-2", name: "b" },
    { consumerId: "web-3", name: "c" },
    { consumerId: "web-4", name: "d" },
  ];
  let listCalls = 0;
  const respond: Responder = (request) => {
    if (
      request.url.pathname.endsWith("/issuance-grants") &&
      request.method === "GET"
    ) {
      listCalls += 1;
      return jsonResponse({
        grants:
          listCalls === 1 ? listing : [{ consumerId: "web-4", name: "d" }],
      });
    }
    if (request.method === "PUT" && request.url.pathname.endsWith("/d"))
      return {
        status: 412,
        headers: {},
        body: {
          error: { code: "precondition_failed", message: "secret detail" },
        },
      };
    return base(request);
  };
  const first = await execute(
    ["pki", "grant", "migrate", "--from", caId, "--to", otherCaId],
    respond,
  );
  assert.equal(first.exitCode, 5);
  const puts = first.requests.filter((r) => r.method === "PUT");
  assert.equal(puts.length, 2);
  assert.equal(
    puts[0]?.headers?.["idempotency-key"],
    migrateKey("web-1", "a", "v-a"),
  );
  assert.equal(puts[0]?.headers?.["if-match"], '"v-a"');
  assert.equal(puts[0]?.url.search, "");
  const data = JSON.parse(first.stdout).data;
  assert.deepEqual(
    data.results.map((r: { name: string; outcome: string }) => [
      r.name,
      r.outcome,
    ]),
    [
      ["a", "migrated"],
      ["b", "skipped"],
      ["c", "skipped"],
      ["d", "failed"],
    ],
  );
  assert.equal(data.remainingListed, 1);
  assert.deepEqual(data.results[3].errors, [
    { status: 412, code: "precondition_failed" },
  ]);
  assert.doesNotMatch(first.stdout, /secret detail/);

  listCalls = 0;
  const rerun = await execute(
    ["pki", "grant", "migrate", "--from", caId, "--to", otherCaId],
    respond,
  );
  assert.equal(
    rerun.requests.find((r) => r.method === "PUT")?.headers?.[
      "idempotency-key"
    ],
    migrateKey("web-1", "a", "v-a"),
  );
});

test("grant migrate needs two different CAs and aborts on an auth failure", async () => {
  for (const args of [
    ["--from", caId],
    ["--from", caId, "--to", caId],
  ]) {
    const result = await execute(["pki", "grant", "migrate", ...args]);
    assert.equal(result.exitCode, 2);
  }
  const denied = await execute(
    ["pki", "grant", "migrate", "--from", caId, "--to", otherCaId],
    (request) =>
      request.method === "GET" &&
      request.url.pathname.endsWith("/issuance-grants")
        ? jsonResponse({ grants: [{ consumerId: "web-1", name: "a" }] })
        : {
            status: 403,
            headers: {},
            body: { error: { code: "forbidden", message: "m" } },
          },
  );
  assert.equal(denied.exitCode, 3);
});

const issued = {
  caId,
  serial: "0a1b",
  fingerprint: "ff",
  certificatePem: "LEAF\n",
  chainPem: "CHAIN\n",
  caPem: "ANCHOR\n",
  notBefore: "2026-01-01T00:00:00.000Z",
  notAfter: "2026-01-02T00:00:00.000Z",
  lifetimeClamped: false,
};

test("cert issue builds the admin request and writes the requested files without overwriting", async () => {
  await withDir(async (dir) => {
    const csr = join(dir, "x.csr");
    await writeFile(
      csr,
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
    );
    const out = join(dir, "leaf.pem");
    const chain = join(dir, "chain.pem");
    const args = [
      "pki",
      "cert",
      "issue",
      caId,
      "--csr",
      csr,
      "--dns",
      "a.example.com",
      "--subject",
      "O=Example,C=US",
      "--duration",
      "1h",
      "--usage",
      "server auth",
      "--out",
      out,
      "--chain-out",
      chain,
      "--idempotency-key",
      "key-12345678",
    ];
    const result = await execute(args, () => jsonResponse(issued, 201));
    assert.equal(result.exitCode, 0, result.stderr);
    const request = result.requests[0]!;
    assert.equal(
      request.url.pathname,
      `/v1/admin/pki/cas/${caId}/certificates`,
    );
    assert.equal(request.headers?.["idempotency-key"], "key-12345678");
    assert.deepEqual(request.body, {
      certificateSigningRequestPem: await readFile(csr, "utf8"),
      sans: { dns: ["a.example.com"] },
      subject: { organization: "Example", country: "US" },
      durationSeconds: 3600,
      usages: ["server auth"],
    });
    assert.equal(await readFile(out, "utf8"), "LEAF\n");
    assert.equal(await readFile(chain, "utf8"), "CHAIN\n");
    const data = JSON.parse(result.stdout).data;
    assert.equal(data.certificatePem, undefined);
    assert.equal(data.chainPem, undefined);
    assert.equal(data.caPem, "ANCHOR\n");
    assert.equal(data.out, out);

    // Existing output files are never replaced, and nothing is sent.
    const again = await execute(args, () => jsonResponse(issued, 201));
    assert.equal(again.exitCode, 9);
    assert.equal(again.requests.length, 0);
    assert.equal(await readFile(out, "utf8"), "LEAF\n");
  });
});

test("cert issue validates names, leaves no placeholder on failure and prints PEM without --out", async () => {
  await withDir(async (dir) => {
    const csr = join(dir, "x.csr");
    await writeFile(
      csr,
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
    );
    for (const args of [
      ["cert", "issue", caId],
      ["cert", "issue", caId, "--csr", csr],
      [
        "cert",
        "issue",
        caId,
        "--csr",
        csr,
        "--use-csr-names",
        "--dns",
        "a.example.com",
      ],
      [
        "cert",
        "issue",
        caId,
        "--csr",
        csr,
        "--use-csr-names",
        "--out",
        csr,
        "--chain-out",
        csr,
      ],
    ]) {
      const result = await execute(["pki", ...args]);
      assert.equal(result.exitCode, 2, args.join(" "));
      assert.equal(result.requests.length, 0);
    }
    const out = join(dir, "leaf.pem");
    const failed = await execute(
      [
        "pki",
        "cert",
        "issue",
        caId,
        "--csr",
        csr,
        "--use-csr-names",
        "--out",
        out,
      ],
      () => ({
        status: 403,
        headers: {},
        body: {
          error: {
            code: "issuance_denied",
            message: "m",
            details: { reason: "name_not_permitted" },
          },
        },
      }),
    );
    assert.equal(failed.exitCode, 3);
    assert.equal(
      JSON.parse(failed.stderr).error.apiDetails.reason,
      "name_not_permitted",
    );
    await assert.rejects(readFile(out));

    const printed = await execute(
      ["pki", "cert", "issue", caId, "--csr", csr, "--use-csr-names"],
      () => jsonResponse(issued, 201),
    );
    assert.equal(JSON.parse(printed.stdout).data.certificatePem, "LEAF\n");
    assert.equal(
      printed.requests[0]?.body &&
        (printed.requests[0].body as Record<string, unknown>).useCsrNames,
      true,
    );
  });
});

test("cert revoke validates the reason and serial; cert get writes the PEM; cert list filters", async () => {
  for (const args of [
    ["cert", "revoke", caId, "0a1b", "--reason", "caCompromise"],
    [
      "cert",
      "revoke",
      caId,
      "0a1b",
      "--invalidity-date",
      "2026-01-01T00:00:00Z",
    ],
    ["cert", "revoke", caId, "xyz"],
    ["cert", "list"],
    ["cert", "list", caId, "--consumer", "web-1"],
    ["cert", "list", "--consumer", "web-1", "--status", "REVOKED"],
    ["cert", "list", caId, "--include-expired"],
    ["cert", "list", caId, "--status", "BOGUS"],
  ]) {
    const result = await execute(["pki", ...args]);
    assert.equal(result.exitCode, 2, args.join(" "));
    assert.equal(result.requests.length, 0);
  }
  const revoked = await execute(
    [
      "pki",
      "cert",
      "revoke",
      caId,
      "0A1B",
      "--reason",
      "keyCompromise",
      "--invalidity-date",
      "2026-01-01T00:00:00Z",
      "--idempotency-key",
      "key-12345678",
    ],
    () => jsonResponse({ crlEntry: true, crlPublished: true, changed: true }),
  );
  assert.equal(revoked.exitCode, 0, revoked.stderr);
  assert.equal(
    revoked.requests[0]?.url.pathname,
    `/v1/admin/pki/cas/${caId}/certificates/0a1b/revoke`,
  );
  assert.deepEqual(revoked.requests[0]?.body, {
    reason: "keyCompromise",
    invalidityDate: "2026-01-01T00:00:00.000Z",
  });

  await withDir(async (dir) => {
    const out = join(dir, "got.pem");
    const got = await execute(
      ["pki", "cert", "get", caId, "0a1b", "--out", out],
      () => jsonResponse({ ...issued, status: "ISSUED" }),
    );
    assert.equal(got.exitCode, 0, got.stderr);
    assert.equal(await readFile(out, "utf8"), "LEAF\n");
    assert.equal(JSON.parse(got.stdout).data.certificatePem, undefined);
    const clash = await execute([
      "pki",
      "cert",
      "get",
      caId,
      "0a1b",
      "--out",
      out,
    ]);
    assert.equal(clash.exitCode, 9);
    assert.equal(clash.requests.length, 0);
    assert.equal(await readFile(out, "utf8"), "LEAF\n");
  });

  const byCa = await execute(
    [
      "pki",
      "cert",
      "list",
      caId,
      "--status",
      "ISSUED",
      "--expiring-before",
      "2h",
    ],
    () => jsonResponse({ certificates: [] }),
    // No fixed clock in `execute`; assert the shape only.
  );
  assert.equal(byCa.requests[0]?.url.searchParams.get("status"), "ISSUED");
  assert.match(
    byCa.requests[0]?.url.searchParams.get("expiringBefore") ?? "",
    /^\d{4}-\d{2}-\d{2}T.*Z$/,
  );
  const byConsumer = await execute(
    [
      "pki",
      "cert",
      "list",
      "--consumer",
      "web-1",
      "--grant",
      "acc-web",
      "--include-expired",
    ],
    () => jsonResponse({ certificates: [] }),
  );
  assert.equal(
    byConsumer.requests[0]?.url.pathname,
    "/v1/admin/pki/consumers/web-1/certificates",
  );
  assert.equal(
    byConsumer.requests[0]?.url.search,
    "?issuanceGrant=acc-web&includeExpired=true",
  );
});

test("consumer revoke-certificates repeats with the same key until complete", async () => {
  let calls = 0;
  const result = await execute(
    [
      "pki",
      "consumer",
      "revoke-certificates",
      "web-1",
      "--grant",
      "acc-web",
      "--reason",
      "superseded",
      "--idempotency-key",
      "key-12345678",
    ],
    () => {
      calls += 1;
      return jsonResponse({
        consumerId: "web-1",
        complete: calls >= 3,
        revoked: calls,
        alreadyRevoked: 0,
        caIds: [caId],
      });
    },
  );
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.requests.length, 3);
  for (const request of result.requests) {
    assert.equal(request.method, "POST");
    assert.equal(
      request.url.pathname,
      "/v1/admin/pki/consumers/web-1/certificates/revoke",
    );
    assert.equal(request.headers?.["idempotency-key"], "key-12345678");
    assert.deepEqual(request.body, {
      reason: "superseded",
      issuanceGrant: "acc-web",
    });
  }
  const data = JSON.parse(result.stdout).data;
  assert.equal(data.attempts, 3);
  assert.equal(data.complete, true);
});

test("consumer revoke-certificates gives up after 20 incomplete attempts", async () => {
  const result = await execute(
    [
      "pki",
      "consumer",
      "revoke-certificates",
      "web-1",
      "--idempotency-key",
      "key-12345678",
    ],
    () =>
      jsonResponse({
        consumerId: "web-1",
        complete: false,
        revoked: 1,
        alreadyRevoked: 0,
        caIds: [],
      }),
  );
  assert.equal(result.requests.length, 20);
  assert.equal(result.exitCode, 7);
  const error = JSON.parse(result.stderr);
  assert.equal(error.error.code, "revoke_incomplete");
  assert.equal(error.idempotencyKey, "key-12345678");
  assert.equal(error.error.outcome, "unknown");
  for (const args of [
    ["consumer", "revoke-certificates"],
    ["consumer", "revoke-certificates", "Web"],
    ["consumer", "revoke-certificates", "web-1", "--reason", "caCompromise"],
  ]) {
    const bad = await execute(["pki", ...args]);
    assert.equal(bad.exitCode, 2, args.join(" "));
    assert.equal(bad.requests.length, 0);
  }
});

test("pki help lists the new commands", async () => {
  const result = await execute(["pki", "--help"]);
  const help = JSON.parse(result.stdout);
  for (const key of [
    "grant migrate",
    "cert issue <ca>",
    "consumer revoke-certificates <consumer>",
  ])
    assert.ok(key in help.commands, key);
});

test("cert issue refuses private keys in any encoding and non-CSR DER", async () => {
  await withDir(async (dir) => {
    const csrPem =
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
    const keyPem =
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    const files: Record<string, Buffer | string> = {
      bom: Buffer.concat([
        Buffer.from([0xef, 0xbb, 0xbf]),
        Buffer.from(keyPem),
      ]),
      bag: `Bag Attributes\n    friendlyName: x\n${keyPem}`,
      derKey: Buffer.from([0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00]),
      notCsr: "hello world",
      pemCert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
      bomCsrWithKey: Buffer.from(csrPem + keyPem),
    };
    for (const [label, content] of Object.entries(files)) {
      const path = join(dir, label);
      await writeFile(path, content);
      const result = await execute([
        "pki",
        "cert",
        "issue",
        caId,
        "--csr",
        path,
        "--use-csr-names",
      ]);
      assert.equal(result.exitCode, 2, label);
      assert.equal(result.requests.length, 0, label);
      assert.doesNotMatch(result.stderr, /AAAA/, label);
    }
    // A DER CSR shape (SEQUENCE { SEQUENCE ... }) and a BOM-prefixed PEM CSR pass.
    const der = join(dir, "csr.der");
    await writeFile(der, Buffer.from([0x30, 0x04, 0x30, 0x02, 0x05, 0x00]));
    const ok = await execute(
      ["pki", "cert", "issue", caId, "--csr", der, "--use-csr-names"],
      () => jsonResponse(issued, 201),
    );
    assert.equal(ok.exitCode, 0, ok.stderr);
    assert.match(
      (ok.requests[0]!.body as { certificateSigningRequestPem: string })
        .certificateSigningRequestPem,
      /^-----BEGIN CERTIFICATE REQUEST-----/,
    );
    const bomCsr = join(dir, "bom.csr");
    await writeFile(
      bomCsr,
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(csrPem)]),
    );
    const bomOk = await execute(
      ["pki", "cert", "issue", caId, "--csr", bomCsr, "--use-csr-names"],
      () => jsonResponse(issued, 201),
    );
    assert.equal(bomOk.exitCode, 0, bomOk.stderr);
  });
});

test("cert issue removes incomplete files and reports the serial after a write failure", async () => {
  await withDir(async (dir) => {
    const csr = join(dir, "x.csr");
    await writeFile(
      csr,
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
    );
    const out = join(dir, "leaf.pem");
    const ca = join(dir, "ca.pem");
    const result = await execute(
      [
        "pki",
        "cert",
        "issue",
        caId,
        "--csr",
        csr,
        "--use-csr-names",
        "--out",
        out,
        "--ca-out",
        ca,
        "--idempotency-key",
        "key-12345678",
      ],
      // caPem is not a string, so that write fails after the leaf was written.
      () => jsonResponse({ ...issued, caPem: 42 }, 201),
    );
    assert.equal(result.exitCode, 9);
    const error = JSON.parse(result.stderr);
    assert.match(error.error.message, /serial 0a1b/);
    assert.match(error.error.message, new RegExp(caId));
    assert.match(error.error.message, /same --idempotency-key/);
    assert.equal(error.idempotencyKey, "key-12345678");
    assert.equal(await readFile(out, "utf8"), "LEAF\n");
    await assert.rejects(readFile(ca));
  });
});

test("migrate skips expired grants and a truncated listing exits 5", async () => {
  const listed = [
    { consumerId: "web-1", name: "a" },
    { consumerId: "web-2", name: "b" },
  ];
  const result = await execute(
    ["pki", "grant", "migrate", "--from", caId, "--to", otherCaId],
    (request) => {
      if (request.url.pathname.endsWith("/issuance-grants"))
        return request.url.searchParams.has("cursor")
          ? jsonResponse({ grants: [], nextCursor: "again" })
          : jsonResponse({ grants: listed, nextCursor: "again" });
      return jsonResponse(
        grantView({
          consumerId: request.url.pathname.includes("web-1")
            ? "web-1"
            : "web-2",
          name: request.url.pathname.endsWith("/a") ? "a" : "b",
          expired: request.url.pathname.endsWith("/a"),
          expiresAt: "2020-01-01T00:00:00.000Z",
        }),
      );
    },
  );
  assert.equal(result.requests.filter((r) => r.method === "PUT").length, 1);
  const data = JSON.parse(result.stdout).data;
  assert.equal(data.results[0].outcome, "skipped");
  assert.equal(data.results[0].reason, "expired");
  assert.equal(data.results[1].outcome, "migrated");
  assert.equal(data.listedTruncated, true);
  assert.equal(result.exitCode, 5);
});

test("revoke-certificates sums revoked and --invalidity-date durations count backwards", async () => {
  let calls = 0;
  const bulk = await execute(
    ["pki", "consumer", "revoke-certificates", "web-1"],
    () => {
      calls += 1;
      return jsonResponse({
        consumerId: "web-1",
        complete: calls === 2,
        revoked: 5 * calls,
        alreadyRevoked: 0,
        caIds: [],
      });
    },
  );
  assert.equal(JSON.parse(bulk.stdout).data.revoked, 15);
  const before = Date.now();
  const revoke = await execute(
    [
      "pki",
      "cert",
      "revoke",
      caId,
      "0a1b",
      "--reason",
      "keyCompromise",
      "--invalidity-date",
      "1h",
    ],
    () => jsonResponse({}),
  );
  const when = Date.parse(
    (revoke.requests[0]!.body as { invalidityDate: string }).invalidityDate,
  );
  assert.ok(
    when <= Date.now() - 3600_000 + 1000 && when >= before - 3600_000 - 1000,
  );
});

const rootId = "ca-aaaaaaaa-2222-3333-4444-555555555555";
const rootDetail = {
  ...detail,
  caId: rootId,
  name: "root-1",
  kind: "ROOT",
  subject: { commonName: "Root CA 1", organization: "Example" },
  policy: { ...policy, issueLeaves: false, issueSubordinates: true },
  parent: undefined,
};
const rootWarning =
  "An external offline root is strongly recommended: this ROOT's key is WRAPPED and online, so a compromised PKI role can copy it, and local distrust only reaches relying parties that use Hemlig trust bundles.";
const rootArgs = [
  "pki",
  "ca",
  "create",
  "--kind",
  "ROOT",
  "--name",
  "root-1",
  "--key-algorithm",
  "ECDSA_P384",
  "--subject",
  "CN=Root CA 1,O=Example",
  "--validity",
  "3650d",
];

test("ca create ROOT builds the request and prints the callout fallback on stderr", async () => {
  const bare = await execute(rootArgs, () => ({
    status: 201,
    headers: {},
    body: rootDetail,
  }));
  assert.equal(bare.exitCode, 0, bare.stderr);
  assert.deepEqual(bare.requests[0]!.body, {
    environment: "production",
    name: "root-1",
    kind: "ROOT",
    validitySeconds: 3650 * 86400,
    keyAlgorithm: "ECDSA_P384",
    subject: { commonName: "Root CA 1", organization: "Example" },
  });
  assert.equal(bare.stderr, `warning: ${rootWarning}\n`);

  const withServerWarning = await execute(rootArgs, () => ({
    status: 201,
    headers: {},
    body: {
      ...rootDetail,
      warnings: [{ code: "external_root_recommended", message: rootWarning }],
    },
  }));
  assert.equal(withServerWarning.stderr, `warning: ${rootWarning}\n`);
});

test("ca create INTERMEDIATE resolves --parent by name", async () => {
  const respond: Responder = (request) =>
    request.method === "GET"
      ? {
          status: 200,
          headers: {},
          body: { cas: [{ caId: rootId, name: "root-1" }] },
        }
      : {
          status: 201,
          headers: {},
          body: { ...detail, kind: "INTERMEDIATE", parentCaId: rootId },
        };
  const result = await execute(
    [
      "pki",
      "ca",
      "create",
      "--kind",
      "INTERMEDIATE",
      "--parent",
      "root-1",
      "--name",
      "int-1",
      "--key-algorithm",
      "ECDSA_P256",
      "--subject",
      "CN=Int 1",
    ],
    respond,
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const body = result.requests[1]!.body as Record<string, unknown>;
  assert.equal(body.kind, "INTERMEDIATE");
  assert.equal(body.parentCaId, rootId);
  assert.equal(result.stderr, "");
});

test("ca create kind rules are usage errors before any request", async () => {
  const base = [
    "--name",
    "x-1",
    "--key-algorithm",
    "ECDSA_P256",
    "--subject",
    "CN=X 1",
  ];
  for (const extra of [
    ["--kind", "BOGUS"],
    ["--kind", "INTERMEDIATE"],
    ["--kind", "ROOT", "--parent", rootId],
    ["--parent", rootId],
    ["--validity", "30d"],
    ["--kind", "ROOT", "--csr-out", "/nonexistent-dir/x.csr"],
    ["--kind", "ROOT", "--max-leaf-lifetime", "30d"],
    ["--kind", "ROOT", "--leaf-key-algorithm", "ECDSA_P256"],
  ]) {
    const result = await execute(["pki", "ca", "create", ...base, ...extra]);
    assert.equal(result.exitCode, 2, extra.join(" "));
    assert.equal(result.requests.length, 0, extra.join(" "));
  }
  const message = await execute([
    "pki",
    "ca",
    "create",
    ...base,
    "--kind",
    "ROOT",
    "--max-leaf-lifetime",
    "30d",
  ]);
  assert.match(message.stderr, /A ROOT CA issues no leaves; omit/);
});

test("ca revoke sends the body, validates the reason and returns the receipt", async () => {
  const response = {
    ca: { ...rootDetail, status: "REVOKED", version: "pkv-9" },
    changed: true,
    crlEntry: false,
    crlPublished: false,
    revokedCaIds: [caId],
    complete: true,
  };
  const result = await execute(
    [
      "pki",
      "ca",
      "revoke",
      rootId,
      "--reason",
      "caCompromise",
      "--invalidity-date",
      "2026-01-01T00:00:00Z",
      "--idempotency-key",
      "key-12345678",
    ],
    () => ({ status: 200, headers: {}, body: response }),
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const request = result.requests[0]!;
  assert.equal(request.method, "POST");
  assert.equal(request.url.pathname, `/v1/admin/pki/cas/${rootId}/revoke`);
  assert.equal(request.headers?.["idempotency-key"], "key-12345678");
  assert.deepEqual(request.body, {
    reason: "caCompromise",
    invalidityDate: "2026-01-01T00:00:00.000Z",
  });
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.etag, "pkv-9");
  assert.deepEqual(receipt.data.revokedCaIds, [caId]);

  for (const args of [
    ["--reason", "keyCompromise"],
    ["--reason", "bogus"],
    ["--invalidity-date", "2026-01-01T00:00:00Z"],
    ["--reason", "superseded", "--invalidity-date", "2026-01-01T00:00:00Z"],
  ]) {
    const bad = await execute(["pki", "ca", "revoke", rootId, ...args]);
    assert.equal(bad.exitCode, 2, args.join(" "));
    assert.equal(bad.requests.length, 0, args.join(" "));
  }
});

test("ca update on a ROOT strips leaf fields and refuses leaf flags", async () => {
  const respond: Responder = (request) =>
    request.method === "GET"
      ? { status: 200, headers: {}, body: rootDetail }
      : { status: 200, headers: {}, body: rootDetail };
  const result = await execute(
    [
      "pki",
      "ca",
      "update",
      rootId,
      "--if-match",
      "current",
      "--capacity",
      "50",
    ],
    respond,
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const body = result.requests[1]!.body as { policy: Record<string, unknown> };
  assert.equal("maxLeafLifetimeSeconds" in body.policy, false);
  assert.equal("leafKeyAlgorithms" in body.policy, false);
  assert.equal(body.policy.capacity, 50);

  const refused = await execute(
    [
      "pki",
      "ca",
      "update",
      rootId,
      "--if-match",
      "current",
      "--max-leaf-lifetime",
      "30d",
    ],
    respond,
  );
  assert.equal(refused.exitCode, 2);
  assert.equal(refused.requests.length, 1);
});

test("rollover from an INTERMEDIATE copies the kind and the parent", async () => {
  const intDetail = {
    ...detail,
    name: "int-1",
    kind: "INTERMEDIATE",
    parentCaId: rootId,
    subject: { commonName: "Int CA 1" },
  };
  const result = await execute(
    ["pki", "ca", "create", "--rollover-from", caId],
    (request) =>
      request.method === "POST"
        ? { status: 201, headers: {}, body: intDetail }
        : { status: 200, headers: {}, body: intDetail },
    { ...env, HEMLIG_ENVIRONMENT: undefined },
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const body = result.requests[1]!.body as Record<string, unknown>;
  assert.equal(body.kind, "INTERMEDIATE");
  assert.equal(body.parentCaId, rootId);
  assert.equal(body.name, "int-2");
});

test("rollover from a ROOT omits leaf fields and keeps the kind", async () => {
  const result = await execute(
    ["pki", "ca", "create", "--rollover-from", rootId],
    (request) =>
      request.method === "POST"
        ? { status: 201, headers: {}, body: rootDetail }
        : { status: 200, headers: {}, body: rootDetail },
    { ...env, HEMLIG_ENVIRONMENT: undefined },
  );
  assert.equal(result.exitCode, 0, result.stderr);
  const body = result.requests[1]!.body as {
    kind: string;
    policy: Record<string, unknown>;
  };
  assert.equal(body.kind, "ROOT");
  assert.equal("maxLeafLifetimeSeconds" in body.policy, false);
  assert.equal("leafKeyAlgorithms" in body.policy, false);
  assert.match(result.stderr, /external offline root is strongly recommended/);
});

test("--kind INTERMEDIATE over a non-INTERMEDIATE rollover base needs --parent, locally", async () => {
  const result = await execute(
    ["pki", "ca", "create", "--rollover-from", caId, "--kind", "INTERMEDIATE"],
    () => ({ status: 200, headers: {}, body: detail }),
    { ...env, HEMLIG_ENVIRONMENT: undefined },
  );
  assert.equal(result.exitCode, 2);
  assert.match(result.stderr, /needs --parent/);
  assert.equal(result.requests.filter((r) => r.method === "POST").length, 0);
});
