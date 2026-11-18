import assert from "node:assert/strict";
import { request } from "node:http";
import { chmod, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  type HemligTransport,
  type TransportRequest,
} from "@zyno-io/hemlig-client";
import { runCli } from "./index";
import { browserCommand, confirmationCode, openInBrowser } from "./login";

const consoleUrl = "https://console.example.com";
const NOW = Date.UTC(2030, 0, 1);

const jwt = (exp: number): string =>
  `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(
    JSON.stringify({ exp }),
  ).toString("base64url")}.sig`;
const validToken = jwt(NOW / 1000 + 600);
const adminUrl = "https://admin.example.test";
const cacheJson = (token: string, admin = adminUrl) =>
  JSON.stringify({ version: 1, token, consoleOrigin: consoleUrl, adminOrigin: admin });

interface Post {
  path?: string;
  method?: string;
  origin?: string | null;
  state?: (state: string) => string;
  token?: string;
  /** Extra form fields a forger might add; the CLI must ignore them. */
  extra?: Record<string, string>;
  /** Do not follow the 303 to /done. */
  noFollow?: boolean;
}

/** What a browser would do after the console page: one request to the loopback listener. */
type Reply = { status: number; body: string; csp?: string; location?: string };

function get(port: number, path: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () =>
        resolve({
          status: res.statusCode!,
          body: text,
          csp: res.headers["content-security-policy"] as string | undefined,
        }),
      );
    })
      .on("error", reject)
      .end();
  });
}

async function send(url: string, post: Post): Promise<Reply> {
  const first = await sendOnce(url, post);
  if (first.status === 303 && !post.noFollow) {
    const port = Number(new URL(url).searchParams.get("port"));
    const done = await get(port, first.location!);
    return { ...done, status: 303, location: first.location, body: done.body };
  }
  return first;
}

function sendOnce(url: string, post: Post): Promise<Reply> {
  const target = new URL(url);
  const state = post.state ? post.state(target.searchParams.get("state")!) : target.searchParams.get("state")!;
  const fields: Record<string, string> = {
    access_token: post.token ?? validToken,
    state,
  };
  Object.assign(fields, post.extra);
  const body = new URLSearchParams(fields).toString();
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
            location: res.headers.location,
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
  options: {
    args?: string[];
    timeoutMs?: number;
    env?: NodeJS.ProcessEnv;
    config?: () => Promise<Response>;
  } = {},
) {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const configDir = join(dir, "hemlig");
  let stdout = "";
  let stderr = "";
  const results: Reply[] = [];
  const opened: string[] = [];
  const fetched: string[] = [];
  const exitCode = await runCli(options.args ?? ["login"], {
    env: options.env ?? { HEMLIG_CONSOLE_URL: consoleUrl },
    configDir,
    now: () => NOW,
    loginTimeoutMs: options.timeoutMs ?? 5000,
    fetch: (async (input: URL | string) => {
      fetched.push(String(input));
      return options.config
        ? options.config()
        : new Response(JSON.stringify({ deploymentName: "d", adminApiUrl: `${adminUrl}/` }));
    }) as typeof fetch,
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
  return { exitCode, stdout, stderr, results, opened, fetched, configDir, dir };
}

test("login relays the token from the console page and caches it privately", async () => {
  const r = await login([{}]);
  try {
    assert.equal(r.exitCode, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), {
      loggedIn: true,
      adminUrl,
      expiresAt: new Date(NOW + 600_000).toISOString(),
    });
    const url = new URL(r.opened[0]!);
    assert.equal(url.origin + url.pathname, `${consoleUrl}/cli-login`);
    assert.match(url.searchParams.get("state")!, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(Number(url.searchParams.get("port")) >= 1024);
    assert.ok(r.stderr.includes(r.opened[0]!), "URL is printed to stderr");
    assert.ok(!r.stdout.includes("cli-login"), "stdout carries only the receipt");
    const state = url.searchParams.get("state")!;
    assert.ok(r.stderr.includes(`Confirm the browser shows code ${confirmationCode(state)}`));
    // POST is answered with 303 to /done, which serves the page.
    assert.equal(r.results[0]!.status, 303);
    assert.equal(r.results[0]!.location, "/done");
    assert.match(r.results[0]!.body, /Hemlig CLI signed in\. You can close this tab\./);
    assert.equal(r.results[0]!.csp, "default-src 'none'");
    assert.deepEqual(JSON.parse(await readFile(join(r.configDir, "admin-token"), "utf8")), {
      version: 1,
      token: validToken,
      consoleOrigin: consoleUrl,
      adminOrigin: adminUrl,
    });
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
      assert.equal(r.results[0]!.status, 303);
    } finally {
      await rm(r.dir, { recursive: true, force: true });
    }
  });
}

test("a rejected attempt does not stop a later valid one", async () => {
  const r = await login([{ origin: "https://evil.example" }, {}]);
  try {
    assert.equal(r.exitCode, 0);
    assert.deepEqual(r.results.map((x) => x.status), [403, 303]);
  } finally {
    await rm(r.dir, { recursive: true, force: true });
  }
});

test("after the 303 the token cannot be replayed and the listener closes after /done", async () => {
  let replay: Reply | undefined;
  let after: unknown;
  const r = await login([{ noFollow: true }]);
  // The listener is still up for GET /done only; a second POST is refused.
  // (Run separately below with a hand-driven opener.)
  await rm(r.dir, { recursive: true, force: true });
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const exitCode = await runCli(["login"], {
    env: { HEMLIG_CONSOLE_URL: consoleUrl },
    configDir: join(dir, "h"),
    now: () => NOW,
    loginTimeoutMs: 5000,
    fetch: (async () => new Response(JSON.stringify({ adminApiUrl: adminUrl }))) as typeof fetch,
    openBrowser: async (url) => {
      const port = Number(new URL(url).searchParams.get("port"));
      const first = await sendOnce(url, {});
      replay = await sendOnce(url, {});
      assert.equal(first.status, 303);
      const done = await get(port, "/done");
      assert.equal(done.status, 200);
      after = await get(port, "/done").catch((e: unknown) => e);
    },
    stdout: () => {},
    stderr: () => {},
  });
  await rm(dir, { recursive: true, force: true });
  assert.equal(exitCode, 0);
  assert.equal(replay!.status, 409);
  assert.ok(after instanceof Error, "listener is closed after /done is sent");
});

test("extra POST fields such as admin_url never choose the API; the console's config.json does", async () => {
  const r = await login([{ extra: { admin_url: "https://attacker.example" } }]);
  try {
    assert.equal(r.exitCode, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).adminUrl, adminUrl);
    assert.deepEqual(r.fetched, [`${consoleUrl}/config.json`]);
    const cache = JSON.parse(await readFile(join(r.configDir, "admin-token"), "utf8"));
    assert.equal(cache.adminOrigin, adminUrl);
    assert.ok(!JSON.stringify(cache).includes("attacker"));
  } finally {
    await rm(r.dir, { recursive: true, force: true });
  }
});

for (const [name, config, code] of [
  ["a failed fetch", async () => { throw new TypeError("network"); }, 8],
  ["a non-200 response", async () => new Response("no", { status: 500 }), 8],
  ["an oversized config", async () => new Response("x".repeat(20_000)), 8],
  ["invalid JSON", async () => new Response("{"), 7],
  ["a missing adminApiUrl", async () => new Response("{}"), 7],
  ["an http adminApiUrl for an https console", async () => new Response(JSON.stringify({ adminApiUrl: "http://admin.example.test" })), 7],
  ["an adminApiUrl with a path", async () => new Response(JSON.stringify({ adminApiUrl: "https://admin.example.test/x" })), 7],
] as [string, () => Promise<Response>, number][]) {
  test(`login fails and caches nothing when config.json gives ${name}`, async () => {
    const r = await login([{}], { config });
    try {
      assert.equal(r.exitCode, code, r.stderr);
      assert.equal(r.stdout, "");
      await assert.rejects(stat(join(r.configDir, "admin-token")));
    } finally {
      await rm(r.dir, { recursive: true, force: true });
    }
  });
}

test("the first valid POST wins when an earlier slow POST finishes later", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  const good = jwt(NOW / 1000 + 600);
  const forged = jwt(NOW / 1000 + 300);
  let outcome: { slow: number; fast: number } | undefined;
  const exitCode = await runCli(["login"], {
    env: { HEMLIG_CONSOLE_URL: consoleUrl },
    configDir: join(dir, "h"),
    now: () => NOW,
    loginTimeoutMs: 5000,
    fetch: (async () => new Response(JSON.stringify({ adminApiUrl: adminUrl }))) as typeof fetch,
    openBrowser: async (url) => {
      const target = new URL(url);
      const state = target.searchParams.get("state")!;
      const port = Number(target.searchParams.get("port"));
      // Slow POST: headers and a partial body now, remainder after the fast POST completes.
      const first = (token: string) =>
        new URLSearchParams({ access_token: token, state }).toString();
      const slowBody = first(forged);
      const slow = await new Promise<number>((resolve, reject) => {
        const req = request(
          { host: "127.0.0.1", port, path: "/callback", method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded", "content-length": Buffer.byteLength(slowBody) } },
          (res) => { res.resume(); resolve(res.statusCode!); },
        );
        req.on("error", reject);
        req.write(slowBody.slice(0, 10));
        void (async () => {
          const fast = await sendOnce(url, { token: good });
          outcome = { slow: 0, fast: fast.status };
          req.end(slowBody.slice(10));
        })();
      });
      outcome!.slow = slow;
      await get(port, "/done").catch(() => undefined);
    },
    stdout: () => {},
    stderr: () => {},
  });
  try {
    assert.equal(exitCode, 0);
    assert.deepEqual(outcome, { slow: 409, fast: 303 });
    const cache = JSON.parse(await readFile(join(dir, "h", "admin-token"), "utf8"));
    assert.equal(cache.token, good);
  } finally {
    await rm(dir, { recursive: true, force: true });
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
    await writeFile(join(configDir, "admin-token"), cacheJson(validToken));
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
      await writeFile(join(configDir, "admin-token"), options.cached);
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
    const cachedToken = jwt(NOW / 1000 + 60);
    const cached = cacheJson(cachedToken);
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
    assert.equal((await readWith({}, { cached })).bearer, `Bearer ${cachedToken}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an expired cached login fails with exit 3 and sends no request", async () => {
  const r = await readWith({}, { cached: cacheJson(jwt(NOW / 1000 - 1)) });
  assert.equal(r.exitCode, 3);
  assert.equal(r.bearer, undefined);
  const error = JSON.parse(r.stderr).error;
  assert.equal(error.code, "login_expired");
  assert.equal(error.message, "Login expired; run `hemlig login`.");
});

test("an expired cached token is ignored when an explicit token source is set", async () => {
  const r = await readWith({ HEMLIG_ADMIN_TOKEN: "envvar.token.value" }, { cached: cacheJson(jwt(NOW / 1000 - 1)) });
  assert.equal(r.exitCode, 0);
});

test("a cached login for another API fails with exit 3 and names that API", async () => {
  const r = await readWith(
    { HEMLIG_ADMIN_URL: "https://other.example.test" },
    { cached: cacheJson(jwt(NOW / 1000 + 60)) },
  );
  assert.equal(r.exitCode, 3);
  assert.equal(r.bearer, undefined);
  assert.equal(
    JSON.parse(r.stderr).error.message,
    `Cached login is for ${adminUrl}; run \`hemlig login\` for this API.`,
  );
});

test("with no admin URL set, the cached login's API is the default", async () => {
  const cachedToken = jwt(NOW / 1000 + 60);
  const r = await readWith(
    { HEMLIG_ADMIN_URL: undefined as unknown as string },
    { cached: cacheJson(cachedToken, "https://cached.example.test") },
  );
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(r.bearer, `Bearer ${cachedToken}`);
});

for (const [name, text] of [
  ["raw token text", validToken],
  ["invalid JSON", "{"],
  ["a wrong version", JSON.stringify({ version: 2, token: validToken, consoleOrigin: consoleUrl, adminOrigin: adminUrl })],
  ["a bad adminOrigin", JSON.stringify({ version: 1, token: validToken, consoleOrigin: consoleUrl, adminOrigin: "http://admin.example.test" })],
  ["a bad token", JSON.stringify({ version: 1, token: "x", consoleOrigin: consoleUrl, adminOrigin: adminUrl })],
] as [string, string][]) {
  test(`a malformed cache (${name}) fails with exit 3`, async () => {
    const r = await readWith({}, { cached: text });
    assert.equal(r.exitCode, 3);
    assert.equal(JSON.parse(r.stderr).error.code, "login_invalid");
  });
}

test("an unreadable cache is exit 3 even with no admin URL configured", async () => {
  const r = await readWith({ HEMLIG_ADMIN_URL: undefined as unknown as string }, { cached: "{" });
  assert.equal(r.exitCode, 3);
  assert.equal(JSON.parse(r.stderr).error.code, "login_invalid");
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

test("browser opener argv uses no shell and keeps the URL one argument", () => {
  const url = "https://console.example.com/cli-login?port=1234&state=abc";
  assert.deepEqual(browserCommand(url, "darwin"), ["open", [url]]);
  assert.deepEqual(browserCommand(url, "linux"), ["xdg-open", [url]]);
  assert.deepEqual(browserCommand(url, "win32"), [
    "rundll32",
    ["url.dll,FileProtocolHandler", url],
  ]);
  for (const platform of ["darwin", "linux", "win32"] as const) {
    let seen: { command: string; args: readonly string[]; options: { shell?: unknown } } | undefined;
    openInBrowser(url, platform, ((command: string, args: readonly string[], options: { shell?: unknown }) => {
      seen = { command, args, options };
      return { on() {}, unref() {} };
    }) as never);
    assert.equal(seen!.options.shell, false);
    assert.equal(seen!.args.at(-1), url);
  }
});

for (const bad of [
  "https://evil&calc.example.com",
  "https://user@console.example.com",
  "https://console.example.com/path",
  "https://console.example.com/?q=1",
  "https://console.example.com/#frag",
  "https://console_x.example.com",
  "http://console.example.com",
]) {
  test(`login rejects console URL ${bad}`, async () => {
    let opened = false;
    const exitCode = await runCli(["login", "--console-url", bad], {
      env: {},
      configDir: "/nonexistent",
      openBrowser: () => {
        opened = true;
      },
      stdout: () => {},
      stderr: () => {},
    });
    assert.equal(exitCode, 2);
    assert.equal(opened, false);
  });
}

test("login accepts localhost and 127.0.0.1 consoles for development", async () => {
  for (const url of ["http://localhost:5273", "http://127.0.0.1:5273"]) {
    const exitCode = await runCli(["login", "--no-browser", "--console-url", url], {
      env: {},
      configDir: "/nonexistent",
      loginTimeoutMs: 50,
      stdout: () => {},
      stderr: () => {},
    });
    assert.equal(exitCode, 8, url);
  }
});

test("confirmation code is stable and matches the console implementation's vector", () => {
  assert.equal(confirmationCode("A".repeat(43)), "1W07-71DP");
  assert.match(confirmationCode("anything"), /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
});

test("a pre-existing world-writable config dir is tightened to 0700; a symlink is refused", async (t) => {
  if (process.platform === "win32") return t.skip();
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  try {
    const loose = join(dir, "loose");
    await mkdir(loose, { mode: 0o777 });
    await chmod(loose, 0o777);
    const real = join(dir, "real");
    await mkdir(real);
    const link = join(dir, "link");
    await symlink(real, link);
    const run = (configDir: string) =>
      runCli(["login", "--console-url", consoleUrl], {
        env: {},
        configDir,
        now: () => NOW,
        loginTimeoutMs: 5000,
        fetch: (async () => new Response(JSON.stringify({ adminApiUrl: adminUrl }))) as typeof fetch,
        openBrowser: (url) => void send(url, {}),
        stdout: () => {},
        stderr: () => {},
      });
    assert.equal(await run(loose), 0);
    assert.equal((await stat(loose)).mode & 0o777, 0o700);
    assert.equal(await run(link), 9);
    await assert.rejects(stat(join(real, "admin-token")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
