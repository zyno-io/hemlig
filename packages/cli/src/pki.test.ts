import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
  assert.deepEqual(parseSubject("CN=Example CA, O=Acme, Inc., C=US"), {
    commonName: "Example CA",
    organization: "Acme, Inc.",
    country: "US",
  });
  assert.throws(() => parseSubject("O=Acme"), /CN/);
  assert.throws(() => parseSubject("CN=a,CN=b"), /repeats/);
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
    const respond: Responder = () => ({
      status: 200,
      headers: { etag: '"abc"' },
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
    assert.equal(receipt.etag, "abc");
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
