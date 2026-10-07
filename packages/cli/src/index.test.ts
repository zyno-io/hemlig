import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { type HemligTransport, type TransportRequest } from "@hemlig/client";
import { runCli } from "./index";

const token = "test.header.signature";
const control = {
  secretId: "payments/stripe/api-key",
  secretUid: "sec-original",
  environment: "production",
  controlVersionId: "ctl-next",
  state: "ACTIVE",
  metadata: { description: "Existing" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
};
const env = {
  HEMLIG_ADMIN_URL: "https://admin.example.test",
  HEMLIG_ENVIRONMENT: "production",
  HEMLIG_ADMIN_TOKEN: token,
};
const target = ["--secret-id", control.secretId];

async function execute(
  args: string[],
  options: {
    input?: string;
    env?: NodeJS.ProcessEnv;
    status?: number;
    body?: unknown;
    transport?: HemligTransport;
    isTTY?: boolean;
  } = {},
) {
  const requests: TransportRequest[] = [];
  let stdout = "";
  let stderr = "";
  const input = options.input ?? "";
  const stream = {
    isTTY: options.isTTY,
    async *[Symbol.asyncIterator]() {
      yield Buffer.from(input);
    },
  };
  const transport = options.transport ?? {
    async request(request: TransportRequest) {
      requests.push(request);
      return {
        status: options.status ?? 200,
        headers: {},
        body: options.body ?? control,
      };
    },
  };
  const exitCode = await runCli(args, {
    env: options.env ?? env,
    stdin: stream,
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    transport,
  });
  return { exitCode, stdout, stderr, requests };
}

test("create uses typed administrator contract and returns a minted operation key", async () => {
  const input = { metadata: {}, acl: [] };
  const result = await execute(
    ["secret", "create", ...target, "--input", "-"],
    { input: JSON.stringify(input) },
  );
  assert.equal(result.exitCode, 0);
  assert.equal(result.stderr, "");
  const receipt = JSON.parse(result.stdout);
  assert.match(receipt.idempotencyKey, /^[a-f0-9-]{36}$/);
  assert.equal(receipt.etag, "ctl-next");
  assert.equal(receipt.data.secretUid, "sec-original");
  assert.equal(result.requests.length, 1);
  const request = result.requests[0]!;
  assert.equal(request.method, "POST");
  assert.equal(request.url.pathname, "/v1/admin/secrets");
  assert.deepEqual(request.body, {
    ...input,
    environment: "production",
    secretId: control.secretId,
  });
  assert.equal(request.headers?.authorization, `Bearer ${token}`);
  assert.equal(request.headers?.["idempotency-key"], receipt.idempotencyKey);
  assert.equal(request.headers?.["if-match"], undefined);
});

for (const input of [
  { metadata: { tags: { owner: "payments" } } },
  { acl: [] },
]) {
  test(`update preserves omitted fields for ${Object.keys(input)[0]}-only writes`, async () => {
    const result = await execute(
      [
        "secret",
        "update",
        ...target,
        "--input",
        "-",
        "--if-match",
        '"ctl-existing"',
        "--idempotency-key",
        "operation-stable",
      ],
      { input: JSON.stringify(input) },
    );
    assert.equal(result.exitCode, 0);
    assert.equal(result.requests.length, 1);
    const request = result.requests[0]!;
    assert.equal(request.method, "PUT");
    assert.equal(
      request.url.pathname,
      "/v1/admin/secrets/payments%2Fstripe%2Fapi-key",
    );
    assert.equal(request.url.searchParams.get("environment"), "production");
    assert.deepEqual(request.body, input);
    assert.equal(request.headers?.["if-match"], '"ctl-existing"');
    assert.equal(request.headers?.["idempotency-key"], "operation-stable");
  });
}

test("payload write wraps raw entries and does not print payload material", async () => {
  const payload = {
    password: { encoding: "utf8", value: "PAYLOAD_SENTINEL" },
    binary: { encoding: "base64", value: "AP8=" },
  };
  const result = await execute(
    [
      "secret",
      "write-payload",
      ...target,
      "--input",
      "-",
      "--if-match",
      "ctl-old",
    ],
    { input: JSON.stringify(payload) },
  );
  assert.equal(result.exitCode, 0);
  assert.equal(
    result.requests[0]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key/payload",
  );
  assert.deepEqual(result.requests[0]?.body, { payload });
  assert.equal(result.requests[0]?.headers?.["if-match"], '"ctl-old"');
  assert.ok(!result.stdout.includes("PAYLOAD_SENTINEL"));
  assert.ok(!result.stderr.includes("PAYLOAD_SENTINEL"));
});

test("current performs exactly one metadata read then a guarded write, never a payload read", async () => {
  const requests: TransportRequest[] = [];
  const result = await execute(
    ["secret", "archive", ...target, "--if-match", "current"],
    {
      transport: {
        async request(request) {
          requests.push(request);
          return {
            status: 200,
            headers: {},
            body: {
              ...control,
              controlVersionId:
                request.method === "GET" ? "ctl-current" : "ctl-archived",
              state: request.method === "GET" ? "ACTIVE" : "ARCHIVED",
            },
          };
        },
      },
    },
  );
  assert.equal(result.exitCode, 0);
  assert.equal(requests.length, 2);
  assert.equal(requests[0]?.method, "GET");
  assert.equal(
    requests[0]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key",
  );
  assert.equal(requests[1]?.method, "POST");
  assert.equal(
    requests[1]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key/archive",
  );
  assert.equal(requests[1]?.headers?.["if-match"], '"ctl-current"');
  assert.equal(requests[1]?.body, undefined);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.ifMatch, "ctl-current");
  assert.equal(receipt.data.secretUid, "sec-original");
});

test("archived reads address old immutable UID even after public ID reuse", async () => {
  const result = await execute(
    ["secret", "read", "--secret-uid", "sec-original"],
    { body: { ...control, state: "ARCHIVED" } },
  );
  assert.equal(result.exitCode, 0);
  assert.equal(result.requests.length, 1);
  assert.equal(
    result.requests[0]?.url.pathname,
    "/v1/admin/archived-secrets/sec-original",
  );
  assert.equal(result.requests[0]?.headers?.["idempotency-key"], undefined);
  assert.equal(JSON.parse(result.stdout).data.state, "ARCHIVED");
});

test("metadata and payload reads are distinct explicit commands", async () => {
  const metadata = await execute(["secret", "read", ...target]);
  assert.equal(metadata.exitCode, 0);
  assert.equal(
    metadata.requests[0]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key",
  );
  const payload = await execute(["secret", "read-payload", ...target], {
    body: {
      secretId: control.secretId,
      controlVersionId: "ctl-next",
      payloadVersionId: "pay-current",
      payload: { value: { encoding: "utf8", value: "REQUESTED_VALUE" } },
    },
  });
  assert.equal(payload.exitCode, 0);
  assert.equal(
    payload.requests[0]?.url.pathname,
    "/v1/admin/secrets/payments%2Fstripe%2Fapi-key/payload",
  );
  assert.equal(
    JSON.parse(payload.stdout).data.payload.value.value,
    "REQUESTED_VALUE",
  );
  assert.equal(payload.stderr, "");
});

for (const [status, exitCode] of [
  [400, 2],
  [401, 3],
  [403, 3],
  [404, 4],
  [409, 5],
  [412, 6],
  [429, 7],
  [500, 7],
  [503, 7],
]) {
  test(`HTTP ${status} has stable exit ${exitCode} and never leaks remote error details`, async () => {
    const result = await execute(
      [
        "secret",
        "archive",
        ...target,
        "--if-match",
        "ctl-old",
        "--idempotency-key",
        "durable-operation",
      ],
      {
        status,
        body: {
          error: {
            message: "SECRET_TOKEN_PAYLOAD_SENTINEL",
            code: "SECRET_TOKEN_PAYLOAD_SENTINEL",
          },
        },
      },
    );
    assert.equal(result.exitCode, exitCode);
    assert.equal(result.stdout, "");
    assert.equal(result.requests.length, 1);
    assert.ok(!result.stderr.includes("SENTINEL"));
    const error = JSON.parse(result.stderr);
    assert.equal(error.error.status, status);
    assert.equal(error.idempotencyKey, "durable-operation");
    assert.equal(error.ifMatch, "ctl-old");
    assert.equal(error.error.outcome, exitCode === 7 ? "unknown" : "rejected");
  });
}

test("concurrent update returns 412 without refetching, minting a replacement key, or retrying", async () => {
  const requests: TransportRequest[] = [];
  const result = await execute(
    [
      "secret",
      "archive",
      ...target,
      "--if-match",
      "current",
      "--idempotency-key",
      "durable-operation",
    ],
    {
      transport: {
        async request(request) {
          requests.push(request);
          return request.method === "GET"
            ? { status: 200, headers: {}, body: control }
            : { status: 412, headers: {}, body: {} };
        },
      },
    },
  );
  assert.equal(result.exitCode, 6);
  assert.equal(requests.length, 2);
  assert.equal(JSON.parse(result.stderr).ifMatch, "ctl-next");
  assert.equal(JSON.parse(result.stderr).idempotencyKey, "durable-operation");
});

test("lost response retains operation key and reports unknown outcome with no retry", async () => {
  let calls = 0;
  const result = await execute(
    ["secret", "archive", ...target, "--if-match", "ctl-old"],
    {
      transport: {
        async request() {
          calls++;
          throw new TypeError("NETWORK_TOKEN_SENTINEL");
        },
      },
    },
  );
  assert.equal(calls, 1);
  assert.equal(result.exitCode, 8);
  assert.equal(result.stdout, "");
  assert.ok(!result.stderr.includes("SENTINEL"));
  const error = JSON.parse(result.stderr);
  assert.equal(error.error.outcome, "unknown");
  assert.match(error.idempotencyKey, /^[a-f0-9-]{36}$/);
});

test("failed current-version read never sends mutation and retains the chosen key", async () => {
  const result = await execute(
    ["secret", "archive", ...target, "--if-match", "current"],
    { status: 404 },
  );
  assert.equal(result.exitCode, 4);
  assert.equal(result.requests.length, 1);
  assert.equal(result.requests[0]?.method, "GET");
  assert.equal(JSON.parse(result.stderr).error.outcome, "not_sent");
});

for (const args of [
  ["secret", "archive", ...target],
  ["secret", "archive", ...target, "--if-match", "*"],
  ["secret", "archive", ...target, "--if-match", 'W/"ctl-old"'],
  ["secret", "archive", ...target, "--if-match", "ctl-old\r\nINJECTED"],
  [
    "secret",
    "archive",
    ...target,
    "--if-match",
    "ctl-old",
    "--idempotency-key",
    "short",
  ],
  [
    "secret",
    "archive",
    ...target,
    "--if-match",
    "ctl-old",
    "--idempotency-key",
    "operation\r\nINJECTED",
  ],
  ["secret", "read", ...target, "--secret-uid", "sec-original"],
  ["secret", "read-payload", "--secret-uid", "sec-original"],
  [
    "secret",
    "read",
    ...target,
    "--environment",
    "production",
    "--environment",
    "staging",
  ],
  ["secret", "read", ...target, "--admin-url", "http://remote.example.test"],
  [
    "secret",
    "read",
    ...target,
    "--admin-url",
    "https://TOKEN_SENTINEL@admin.example.test",
  ],
  [
    "secret",
    "read",
    ...target,
    "--admin-url",
    "https://admin.example.test/base",
  ],
  ["secret", "read", ...target, "--input", "-"],
  ["secret", "read", ...target, "--token", "TOKEN_SENTINEL"],
  ["secret", "read", ...target, "--timeout-ms", "Infinity"],
  ["secret", "read", ...target, "--secret-id", "../bad"],
]) {
  test(`unsafe/unsupported arguments rejected before HTTP: ${args.slice(0, 2).join(" ")} case ${JSON.stringify(args).length}`, async () => {
    const result = await execute(args);
    assert.equal(result.exitCode, 2);
    assert.equal(result.requests.length, 0);
    assert.equal(result.stdout, "");
    assert.ok(!result.stderr.includes("TOKEN_SENTINEL"));
  });
}

for (const input of [
  "{PAYLOAD_SENTINEL",
  "null",
  "[]",
  "{}",
  '{"payload":{"value":"PAYLOAD_SENTINEL"}}',
  '{"metadata":{"path":"PAYLOAD_SENTINEL"},"acl":[]}',
]) {
  test(`invalid control input never echoes data (length ${input.length})`, async () => {
    const result = await execute(
      ["secret", "create", ...target, "--input", "-"],
      { input },
    );
    assert.equal(result.exitCode, 2);
    assert.equal(result.requests.length, 0);
    assert.ok(!result.stderr.includes("PAYLOAD_SENTINEL"));
  });
}

for (const input of [
  '{"password":{"encoding":"base64","value":"YQ"}}',
  '{"password":{"encoding":"utf8","value":5}}',
  '{"bad/key":{"encoding":"utf8","value":"PAYLOAD_SENTINEL"}}',
]) {
  test(`invalid payload fails safely before network (length ${input.length})`, async () => {
    const result = await execute(
      [
        "secret",
        "write-payload",
        ...target,
        "--if-match",
        "current",
        "--input",
        "-",
      ],
      { input },
    );
    assert.equal(result.exitCode, 2);
    assert.equal(result.requests.length, 0);
    assert.ok(!result.stderr.includes("PAYLOAD_SENTINEL"));
  });
}

test("large input and interactive stdin fail without issuing a request", async () => {
  const args = ["secret", "create", ...target, "--input", "-"];
  const large = await execute(args, { input: " ".repeat(768001) });
  assert.equal(large.exitCode, 2);
  assert.equal(large.requests.length, 0);
  const tty = await execute(args, { isTTY: true });
  assert.equal(tty.exitCode, 2);
  assert.equal(tty.requests.length, 0);
});

test("bootstrap values and missing token/config are rejected with no network", async () => {
  for (const override of [
    { HEMLIG_ADMIN_TOKEN: "hmlb_TOKEN_SENTINEL" },
    { HEMLIG_ADMIN_TOKEN: undefined },
    { HEMLIG_ADMIN_URL: undefined },
    { HEMLIG_ENVIRONMENT: undefined },
  ]) {
    const result = await execute(["secret", "read", ...target], {
      env: { ...env, ...override },
    });
    assert.equal(result.exitCode, 2);
    assert.equal(result.requests.length, 0);
    assert.ok(!result.stderr.includes("TOKEN_SENTINEL"));
  }
});

test("token file overrides token env; input file is parsed without logging either", async () => {
  const directory = await mkdtemp(join(tmpdir(), "hemlig-cli-test-"));
  try {
    const tokenPath = join(directory, "token");
    const inputPath = join(directory, "input.json");
    await writeFile(tokenPath, "  file.token.signature\n", { mode: 0o600 });
    await writeFile(inputPath, '{"metadata":{},"acl":[]}');
    const result = await execute(
      [
        "secret",
        "create",
        ...target,
        "--input",
        inputPath,
        "--token-file",
        tokenPath,
      ],
      { env: { ...env, HEMLIG_ADMIN_TOKEN: "hmlb_unused" } },
    );
    assert.equal(result.exitCode, 0);
    assert.equal(
      result.requests[0]?.headers?.authorization,
      "Bearer file.token.signature",
    );
    assert.ok(!result.stdout.includes("file.token.signature"));
    const missing = await execute([
      "secret",
      "read",
      ...target,
      "--token-file",
      join(directory, "absent"),
    ]);
    assert.equal(missing.exitCode, 9);
    assert.equal(missing.requests.length, 0);
    const envFile = await execute(["secret", "read", ...target], {
      env: { ...env, HEMLIG_ADMIN_TOKEN_FILE: tokenPath },
    });
    assert.equal(envFile.exitCode, 0);
    assert.equal(
      envFile.requests[0]?.headers?.authorization,
      "Bearer file.token.signature",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI flags override environment selection", async () => {
  const result = await execute([
    "--admin-url",
    "https://admin.other.test",
    "--environment",
    "staging",
    "secret",
    "read",
    ...target,
  ]);
  assert.equal(result.exitCode, 0);
  assert.equal(result.requests[0]?.url.origin, "https://admin.other.test");
  assert.equal(
    result.requests[0]?.url.searchParams.get("environment"),
    "staging",
  );
});

test("malformed API success is a protocol error without dumping its body", async () => {
  const result = await execute(["secret", "read", ...target], {
    body: { payload: "PAYLOAD_SENTINEL" },
  });
  assert.equal(result.exitCode, 7);
  assert.equal(result.stdout, "");
  assert.ok(!result.stderr.includes("PAYLOAD_SENTINEL"));
});

test("help and durable-key minting require no endpoint/token/environment", async () => {
  const help = await execute(["--help"], { env: {} });
  assert.equal(help.exitCode, 0);
  assert.equal(JSON.parse(help.stdout).exitCodes[6], "Stale revision (412)");
  const key = await execute(["idempotency-key"], { env: {} });
  assert.equal(key.exitCode, 0);
  assert.match(JSON.parse(key.stdout).idempotencyKey, /^[a-f0-9-]{36}$/);
  assert.equal(key.requests.length, 0);
});

test("output failure is a stable I/O error and a closed stderr never throws", async () => {
  let stderr = "";
  const exitCode = await runCli(["idempotency-key"], {
    stdout: async () => {
      throw Object.assign(new Error("OUTPUT_SENTINEL"), { code: "EPIPE" });
    },
    stderr: (text) => {
      stderr += text;
    },
  });
  assert.equal(exitCode, 9);
  assert.equal(JSON.parse(stderr).error.code, "output_io_error");
  assert.ok(!stderr.includes("OUTPUT_SENTINEL"));
  const closed = await runCli(["unsupported"], {
    stderr: async () => {
      throw Object.assign(new Error("closed"), { code: "EPIPE" });
    },
  });
  assert.equal(closed, 9);
});

async function processCli(
  args: string[],
  input = "",
  overrides: NodeJS.ProcessEnv = {},
) {
  const child = spawn(process.execPath, [join(__dirname, "main.js"), ...args], {
    env: { ...process.env, ...env, HEMLIG_ADMIN_TOKEN_FILE: "", ...overrides },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += String(chunk);
  });
  child.stderr.on("data", (chunk) => {
    stderr += String(chunk);
  });
  child.stdin.end(input);
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  return { exitCode, stdout, stderr };
}

test("installed bin source keeps a shebang; real process emits JSON help/errors and stable exits", async () => {
  const main = await readFile(join(__dirname, "main.js"), "utf8");
  assert.ok(main.startsWith("#!/usr/bin/env node"));
  const help = await processCli(["--help"]);
  assert.equal(help.exitCode, 0);
  assert.equal(help.stderr, "");
  assert.ok(JSON.parse(help.stdout).commands.includes("archive"));
  const error = await processCli(["--token", "TOKEN_SENTINEL"]);
  assert.equal(error.exitCode, 2);
  assert.equal(error.stdout, "");
  assert.ok(!error.stderr.includes("TOKEN_SENTINEL"));
  assert.equal(JSON.parse(error.stderr).error.exitCode, 2);
});

async function localServer(
  handler: (
    request: IncomingMessage,
    response: import("node:http").ServerResponse,
  ) => void,
) {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

test("real process sends OIDC/If-Match/idempotency once and receives JSON receipt over local HTTP", async () => {
  const seen: {
    method?: string;
    url?: string;
    authorization?: string;
    ifMatch?: string;
    key?: string;
    body: string;
  }[] = [];
  const server = await localServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += String(chunk);
    });
    request.on("end", () => {
      seen.push({
        method: request.method,
        url: request.url,
        authorization: request.headers.authorization,
        ifMatch: request.headers["if-match"] as string,
        key: request.headers["idempotency-key"] as string,
        body,
      });
      response.writeHead(200, {
        "content-type": "application/json",
        etag: '"ctl-next"',
      });
      response.end(JSON.stringify(control));
    });
  });
  try {
    const result = await processCli(
      [
        "secret",
        "update",
        ...target,
        "--input",
        "-",
        "--if-match",
        "ctl-existing",
        "--idempotency-key",
        "durable-operation",
      ],
      '{"acl":[]}',
      { HEMLIG_ADMIN_URL: server.origin, HEMLIG_ADMIN_TOKEN_FILE: undefined },
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.authorization, `Bearer ${token}`);
    assert.equal(seen[0]?.ifMatch, '"ctl-existing"');
    assert.equal(seen[0]?.key, "durable-operation");
    assert.deepEqual(JSON.parse(seen[0]!.body), { acl: [] });
    assert.equal(JSON.parse(result.stdout).etag, "ctl-next");
  } finally {
    await server.close();
  }
});

test("real process refuses redirects instead of forwarding a bearer token", async () => {
  let destinationCalls = 0;
  const destination = await localServer((_request, response) => {
    destinationCalls++;
    response.end(JSON.stringify(control));
  });
  const redirect = await localServer((_request, response) => {
    response.writeHead(307, { location: destination.origin });
    response.end();
  });
  try {
    const result = await processCli(["secret", "read", ...target], "", {
      HEMLIG_ADMIN_URL: redirect.origin,
      HEMLIG_ADMIN_TOKEN_FILE: undefined,
    });
    assert.equal(result.exitCode, 8);
    assert.equal(destinationCalls, 0);
    assert.equal(result.stdout, "");
    assert.ok(!result.stderr.includes(token));
  } finally {
    await redirect.close();
    await destination.close();
  }
});

test("real process bounds a stalled request and reports unknown mutation outcome", async () => {
  let calls = 0;
  const server = await localServer((_request, _response) => {
    calls++;
  });
  try {
    const result = await processCli(
      [
        "secret",
        "archive",
        ...target,
        "--if-match",
        "ctl-old",
        "--timeout-ms",
        "100",
        "--idempotency-key",
        "durable-operation",
      ],
      "",
      { HEMLIG_ADMIN_URL: server.origin, HEMLIG_ADMIN_TOKEN_FILE: undefined },
    );
    assert.equal(result.exitCode, 8);
    assert.equal(calls, 1);
    assert.equal(JSON.parse(result.stderr).error.outcome, "unknown");
    assert.equal(JSON.parse(result.stderr).idempotencyKey, "durable-operation");
  } finally {
    await server.close();
  }
});
