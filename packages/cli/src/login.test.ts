import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  type HemligTransport,
  type TransportRequest,
} from "@zyno-io/hemlig-client";
import { runCli } from "./index";

const consoleUrl = "https://console.example.com";
const NOW = Date.UTC(2030, 0, 1);

const jwt = (exp: number): string =>
  `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(
    JSON.stringify({ exp }),
  ).toString("base64url")}.sig`;
const validToken = jwt(NOW / 1000 + 600);

interface Post {
  path?: string;
  method?: string;
  origin?: string | null;
  state?: (state: string) => string;
  token?: string;
}

/** What a browser would do after the console page: one request to the loopback listener. */
function send(url: string, post: Post): Promise<{ status: number; body: string; csp?: string }> {
  const target = new URL(url);
  const state = post.state ? post.state(target.searchParams.get("state")!) : target.searchParams.get("state")!;
  const body = new URLSearchParams({
    access_token: post.token ?? validToken,
    state,
  }).toString();
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: Number(target.searchParams.get("port")),
        path: post.path ?? "/callback",
        method: post.method ?? "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": Buffer.byteLength(body),
          ...(post.origin === null ? {} : { origin: post.origin ?? consoleUrl }),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () =>
          resolve({
            status: res.statusCode!,
            body: text,
            csp: res.headers["content-security-policy"] as string | undefined,
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

async function login(
  posts: Post[],
  options: { args?: string[]; timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
) {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const configDir = join(dir, "hemlig");
  let stdout = "";
  let stderr = "";
  const results: { status: number; body: string; csp?: string }[] = [];
  const opened: string[] = [];
  const exitCode = await runCli(options.args ?? ["login"], {
    env: options.env ?? { HEMLIG_CONSOLE_URL: consoleUrl },
    configDir,
    now: () => NOW,
    loginTimeoutMs: options.timeoutMs ?? 5000,
    openBrowser: async (url) => {
      opened.push(url);
      for (const post of posts) results.push(await send(url, post));
    },
    stdout: (t) => {
      stdout += t;
    },
    stderr: (t) => {
      stderr += t;
    },
  });
  return { exitCode, stdout, stderr, results, opened, configDir, dir };
}

test("login relays the token from the console page and caches it privately", async () => {
  const r = await login([{}]);
  try {
    assert.equal(r.exitCode, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), {
      loggedIn: true,
      expiresAt: new Date(NOW + 600_000).toISOString(),
    });
    const url = new URL(r.opened[0]!);
    assert.equal(url.origin + url.pathname, `${consoleUrl}/cli-login`);
    assert.match(url.searchParams.get("state")!, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(Number(url.searchParams.get("port")) >= 1024);
    assert.ok(r.stderr.includes(r.opened[0]!), "URL is printed to stderr");
    assert.ok(!r.stdout.includes("cli-login"), "stdout carries only the receipt");
    assert.equal(r.results[0]!.status, 200);
    assert.match(r.results[0]!.body, /Hemlig CLI signed in\. You can close this tab\./);
    assert.equal(r.results[0]!.csp, "default-src 'none'");
    assert.equal((await readFile(join(r.configDir, "admin-token"), "utf8")).trim(), validToken);
    if (process.platform !== "win32") {
      assert.equal((await stat(join(r.configDir, "admin-token"))).mode & 0o777, 0o600);
      assert.equal((await stat(r.configDir)).mode & 0o777, 0o700);
    }
  } finally {
    await rm(r.dir, { recursive: true, force: true });
  }
});

test("--no-browser prints the URL and never calls the opener", async () => {
  let opened = false;
  let stderr = "";
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const exitCode = await runCli(["login", "--no-browser", "--console-url", consoleUrl], {
    env: {},
    configDir: join(dir, "h"),
    now: () => NOW,
    loginTimeoutMs: 100,
    openBrowser: () => {
      opened = true;
    },
    stdout: () => {},
    stderr: (t) => {
      stderr += t;
    },
  });
  await rm(dir, { recursive: true, force: true });
  assert.equal(exitCode, 8);
  assert.equal(opened, false);
  assert.match(stderr, /https:\/\/console\.example\.com\/cli-login\?port=\d+&state=/);
});

for (const [name, bad] of [
  ["a wrong Origin", { origin: "https://evil.example" }],
  ["a wrong state", { state: (s: string) => `${s.slice(0, -1)}${s.endsWith("A") ? "B" : "A"}` }],
  ["a wrong state with Origin null", { origin: "null", state: () => "x".repeat(43) }],
  ["a short state", { state: () => "x" }],
  ["a GET", { method: "GET" }],
  ["a wrong path", { path: "/other" }],
  ["a malformed token", { token: "not-a-jwt" }],
  ["an expired token", { token: jwt(NOW / 1000 - 1) }],
] as [string, Post][]) {
  test(`login rejects ${name} and keeps waiting until the timeout`, async () => {
    const r = await login([bad], { timeoutMs: 300 });
    try {
      assert.equal(r.exitCode, 8);
      assert.ok([400, 403, 404].includes(r.results[0]!.status), String(r.results[0]!.status));
      assert.equal(JSON.parse(r.stderr.split("\n").filter((l) => l.startsWith("{"))[0]!).error.code, "login_timeout");
      assert.equal(r.stdout, "");
      await assert.rejects(stat(join(r.configDir, "admin-token")));
    } finally {
      await rm(r.dir, { recursive: true, force: true });
    }
  });
}

for (const [name, origin] of [["Origin: null", "null"], ["no Origin", null]] as [string, string | null][]) {
  test(`login accepts a POST with ${name} when state is correct`, async () => {
    const r = await login([{ origin }]);
    try {
      assert.equal(r.exitCode, 0, r.stderr);
      assert.equal(r.results[0]!.status, 200);
    } finally {
      await rm(r.dir, { recursive: true, force: true });
    }
  });
}

test("a rejected attempt does not stop a later valid one", async () => {
  const r = await login([{ origin: "https://evil.example" }, {}]);
  try {
    assert.equal(r.exitCode, 0);
    assert.deepEqual(r.results.map((x) => x.status), [403, 200]);
  } finally {
    await rm(r.dir, { recursive: true, force: true });
  }
});

test("an oversized body is rejected", async () => {
  const r = await login([{ token: `a.b.${"c".repeat(20_000)}` }], { timeoutMs: 300 });
  try {
    assert.equal(r.exitCode, 8);
    assert.ok([400, 413].includes(r.results[0]!.status));
  } finally {
    await rm(r.dir, { recursive: true, force: true });
  }
});

test("login requires a console URL and rejects unsupported options", async () => {
  for (const [args, env] of [
    [["login"], {}],
    [["login", "--console-url", "http://console.example.com"], {}],
    [["login", "--environment", "production"], { HEMLIG_CONSOLE_URL: consoleUrl }],
  ] as [string[], NodeJS.ProcessEnv][]) {
    let stderr = "";
    const exitCode = await runCli(args, {
      env,
      configDir: "/nonexistent",
      stdout: () => {},
      stderr: (t) => {
        stderr += t;
      },
    });
    assert.equal(exitCode, 2, stderr);
  }
});

test("logout removes the cached token and is idempotent", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const configDir = join(dir, "hemlig");
  try {
    await mkdir(configDir);
    await writeFile(join(configDir, "admin-token"), validToken);
    for (let i = 0; i < 2; i++) {
      let stdout = "";
      const exitCode = await runCli(["logout"], {
        env: {},
        configDir,
        stdout: (t) => {
          stdout += t;
        },
        stderr: () => {},
      });
      assert.equal(exitCode, 0);
      assert.deepEqual(JSON.parse(stdout), { loggedIn: false });
      await assert.rejects(stat(join(configDir, "admin-token")));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const control = {
  secretId: "payments/stripe/api-key",
  secretUid: "sec-original",
  environment: "production",
  controlVersionId: "ctl-next",
  state: "ACTIVE",
  metadata: {},
  acl: [],
};

async function readWith(
  env: NodeJS.ProcessEnv,
  options: { cached?: string; extraArgs?: string[]; tokenFile?: string } = {},
) {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const configDir = join(dir, "hemlig");
  const requests: TransportRequest[] = [];
  let stderr = "";
  try {
    if (options.cached !== undefined) {
      await mkdir(configDir);
      await writeFile(join(configDir, "admin-token"), `${options.cached}\n`);
    }
    const transport: HemligTransport = {
      async request(req: TransportRequest) {
        requests.push(req);
        return { status: 200, headers: {}, body: control };
      },
    };
    const exitCode = await runCli(
      ["secret", "read", "--secret-id", control.secretId, ...(options.extraArgs ?? [])],
      {
        env: {
          HEMLIG_ADMIN_URL: "https://admin.example.test",
          HEMLIG_ENVIRONMENT: "production",
          ...env,
        },
        configDir,
        now: () => NOW,
        transport,
        stdout: () => {},
        stderr: (t) => {
          stderr += t;
        },
      },
    );
    return { exitCode, stderr, bearer: requests[0]?.headers?.authorization, dir };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("token resolution order: --token-file, env file, env token, cached login", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  try {
    const flagFile = join(dir, "flag");
    const envFile = join(dir, "env");
    await writeFile(flagFile, "flag.token.file");
    await writeFile(envFile, "envfile.token.file");
    const cached = jwt(NOW / 1000 + 60);
    const all = {
      HEMLIG_ADMIN_TOKEN_FILE: envFile,
      HEMLIG_ADMIN_TOKEN: "envvar.token.value",
    };
    assert.equal(
      (await readWith(all, { cached, extraArgs: ["--token-file", flagFile] })).bearer,
      "Bearer flag.token.file",
    );
    assert.equal((await readWith(all, { cached })).bearer, "Bearer envfile.token.file");
    assert.equal(
      (await readWith({ HEMLIG_ADMIN_TOKEN: "envvar.token.value" }, { cached })).bearer,
      "Bearer envvar.token.value",
    );
    assert.equal((await readWith({}, { cached })).bearer, `Bearer ${cached}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an expired cached login fails with exit 3 and sends no request", async () => {
  const r = await readWith({}, { cached: jwt(NOW / 1000 - 1) });
  assert.equal(r.exitCode, 3);
  assert.equal(r.bearer, undefined);
  const error = JSON.parse(r.stderr).error;
  assert.equal(error.code, "login_expired");
  assert.equal(error.message, "Login expired; run `hemlig login`.");
});

test("an expired cached token is ignored when an explicit token source is set", async () => {
  const r = await readWith({ HEMLIG_ADMIN_TOKEN: "envvar.token.value" }, { cached: jwt(NOW / 1000 - 1) });
  assert.equal(r.exitCode, 0);
});

test("no token source and no cache is a usage error mentioning login", async () => {
  const r = await readWith({});
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr, /hemlig login/);
});

test("--help documents login, logout and the console URL", async () => {
  let stdout = "";
  await runCli(["--help"], { env: {}, stdout: (t) => { stdout += t; }, stderr: () => {} });
  const help = JSON.parse(stdout);
  assert.match(help.usage, /hemlig login/);
  assert.match(help.usage, /hemlig logout/);
  assert.ok("--console-url" in help.options);
  assert.ok("login" in help.topLevelCommands && "logout" in help.topLevelCommands);
});
