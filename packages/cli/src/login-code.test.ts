import assert from "node:assert/strict";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runCli } from "./index";
import {
  LoginError,
  confirmationCode,
  formatLoginCode,
  loginViaCode,
  parseLoginCode,
  readCodeLine,
  type CodeInput,
} from "./login";

const consoleUrl = "https://console.example.com";
const adminUrl = "https://admin.example.test";
const NOW = Date.UTC(2030, 0, 1);
const jwt = (exp: number | undefined, pad = 0): string =>
  `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(
    JSON.stringify(exp === undefined ? { pad: "x".repeat(pad) } : { exp, pad: "x".repeat(pad) }),
  ).toString("base64url")}.sig`;
const validToken = jwt(NOW / 1000 + 600);
const STATE = "A".repeat(43);

/** Fake stdin that yields the given chunks, then (optionally) never ends. */
function fakeStdin(chunks: string[], opts: { tty?: boolean; hang?: boolean } = {}) {
  const calls: string[] = [];
  const input: CodeInput = {
    isTTY: opts.tty ?? false,
    setRawMode: (m: boolean) => void calls.push(`raw:${m}`),
    pause: () => void calls.push("pause"),
    destroy: () => void calls.push("destroy"),
    async *[Symbol.asyncIterator]() {
      for (const c of chunks) yield Buffer.from(c);
      if (opts.hang) await new Promise(() => {});
    },
  };
  return { input, calls };
}

const configResponse = async () =>
  new Response(JSON.stringify({ deploymentName: "d", adminApiUrl: `${adminUrl}/` }));

test("parseLoginCode accepts hemlig1.<state>.<jwt> and round-trips formatLoginCode", () => {
  const parsed = parseLoginCode(formatLoginCode(STATE, validToken));
  assert.deepEqual(parsed, { state: STATE, token: validToken });
  assert.deepEqual(parseLoginCode(`  ${formatLoginCode(STATE, validToken)}\n`).token, validToken);
});

for (const [name, value] of [
  ["a wrong prefix", `hemlig2.${STATE}.${validToken}`],
  ["no prefix", `${STATE}.${validToken}`],
  ["a missing state", `hemlig1..${validToken}`],
  ["no token", `hemlig1.${STATE}`],
  ["a malformed token", `hemlig1.${STATE}.not-a-jwt`],
  ["a malformed state", `hemlig1.${"!".repeat(10)}.${validToken}`],
  ["an empty string", ""],
] as [string, string][]) {
  test(`parseLoginCode rejects ${name}`, () => {
    assert.throws(() => parseLoginCode(value), (e) => e instanceof LoginError && e.code === "invalid_code");
  });
}

function codeOptions(stdin: CodeInput, extra: Partial<Parameters<typeof loginViaCode>[0]> = {}) {
  const announced: { url: string; code: string }[] = [];
  const events: string[] = [];
  return {
    announced,
    events,
    options: {
      consoleOrigin: new URL(consoleUrl),
      timeoutMs: 2000,
      now: () => NOW,
      fetch: configResponse as unknown as typeof fetch,
      open: undefined,
      announce: (url: string, code: string) => void announced.push({ url, code }),
      prompt: () => void events.push("prompt"),
      stdin,
      ...extra,
    },
  };
}

/** Runs the flow, feeding the code built from the state the CLI announced. */
async function run(
  build: (state: string) => string[],
  tty: boolean,
  tokenCheck?: (r: Awaited<ReturnType<typeof loginViaCode>>) => void,
) {
  let announcedState = "";
  let release!: (c: string[]) => void;
  const gate = new Promise<string[]>((r) => (release = r));
  const calls: string[] = [];
  const input: CodeInput = {
    isTTY: tty,
    setRawMode: (m: boolean) => void calls.push(`raw:${m}`),
    pause: () => void calls.push("pause"),
    async *[Symbol.asyncIterator]() {
      for (const c of await gate) yield Buffer.from(c);
    },
  };
  const announcedList: { url: string; code: string }[] = [];
  const { options } = codeOptions(input, {
    announce: (url: string, announcedCode: string) => {
      announcedList.push({ url, code: announcedCode });
      announcedState = new URL(url).searchParams.get("state")!;
      release(build(announcedState));
    },
  });
  const result = await loginViaCode(options);
  tokenCheck?.(result);
  return { result, announced: announcedList, calls, announcedState };
}

test("loginViaCode: non-TTY stdin line, URL has mode=code and no port, confirmation code announced", async () => {
  const { result, announced, announcedState } = await run(
    (s) => [`${formatLoginCode(s, validToken)}\n`],
    false,
  );
  assert.equal(result.token, validToken);
  assert.equal(result.adminOrigin, adminUrl);
  assert.equal(result.expiresAt.getTime(), NOW + 600_000);
  const url = new URL(announced[0]!.url);
  assert.equal(url.searchParams.get("mode"), "code");
  assert.equal(url.searchParams.has("port"), false);
  assert.equal(announced[0]!.code, confirmationCode(announcedState));
});

test("loginViaCode: non-TTY input without a trailing newline (pbpaste) and split chunks", async () => {
  const { result } = await run(
    (s) => {
      const code = formatLoginCode(s, validToken);
      return [code.slice(0, 20), code.slice(20)];
    },
    false,
  );
  assert.equal(result.token, validToken);
});

test("loginViaCode: raw-mode TTY handles >1 KiB code, bracketed paste markers, backspace", async () => {
  const big = jwt(NOW / 1000 + 600, 3000);
  assert.ok(big.length > 2048);
  const { result, calls } = await run(
    (s) => {
      const code = formatLoginCode(s, big);
      // Marker split across chunks, a typo erased with backspace and DEL.
      return ["\x1b[20", `0~${code}XY`, "\x7f\x08", "\x1b[201", "~\r"];
    },
    true,
  );
  assert.equal(result.token, big);
  assert.deepEqual(calls.filter((c) => c.startsWith("raw")), ["raw:true", "raw:false"]);
  assert.ok(calls.includes("pause"));
});

test("loginViaCode: raw-mode Ctrl-C and Ctrl-D on empty input cancel and restore the terminal", async () => {
  for (const key of ["\x03", "\x04"]) {
    const { input, calls } = fakeStdin(["abc\x7f\x7f\x7f", key], { tty: true });
    const { options } = codeOptions(input);
    await assert.rejects(loginViaCode(options), (e) => e instanceof LoginError && e.code === "login_cancelled");
    assert.deepEqual(calls.filter((c) => c.startsWith("raw")), ["raw:true", "raw:false"]);
  }
});

test("readCodeLine: Ctrl-D with pending input is ignored; oversized input is refused", async () => {
  assert.equal(await readCodeLine(fakeStdin(["ab\x04c\n"], { tty: true }).input), "abc");
  await assert.rejects(
    readCodeLine(fakeStdin(["x".repeat(20000)], { tty: true }).input),
    (e) => e instanceof LoginError && e.code === "code_too_large",
  );
  await assert.rejects(
    readCodeLine(fakeStdin(["x".repeat(20000)]).input),
    (e) => e instanceof LoginError && e.code === "code_too_large",
  );
});

test("loginViaCode: a code from another attempt is rejected as state_mismatch", async () => {
  await assert.rejects(
    run(() => [`${formatLoginCode("B".repeat(43), validToken)}\n`], false),
    (e) => e instanceof LoginError && e.code === "state_mismatch" && /different/.test(e.message),
  );
});

for (const [name, token] of [
  ["expired", jwt(NOW / 1000 - 1)],
  ["without exp", jwt(undefined)],
] as [string, string][]) {
  test(`loginViaCode rejects a ${name} token`, async () => {
    await assert.rejects(
      run((s) => [`${formatLoginCode(s, token)}\n`], false),
      (e) => e instanceof LoginError && e.code === "invalid_code",
    );
  });
}

test("loginViaCode: config.json failure saves nothing", async () => {
  let announcedState = "";
  let release!: (c: string[]) => void;
  const gate = new Promise<string[]>((r) => (release = r));
  const input: CodeInput = {
    async *[Symbol.asyncIterator]() {
      for (const c of await gate) yield Buffer.from(c);
    },
  };
  const { options } = codeOptions(input, {
    fetch: (async () => new Response("no", { status: 500 })) as unknown as typeof fetch,
    announce: (url: string) => {
      announcedState = new URL(url).searchParams.get("state")!;
      release([`${formatLoginCode(announcedState, validToken)}\n`]);
    },
  });
  await assert.rejects(
    loginViaCode(options),
    (e) => e instanceof LoginError && e.code === "config_fetch_failed",
  );
});

test("loginViaCode times out with login_timeout and restores the terminal", async () => {
  const { input, calls } = fakeStdin([], { tty: true, hang: true });
  const { options } = codeOptions(input, { timeoutMs: 50 });
  await assert.rejects(loginViaCode(options), (e) => e instanceof LoginError && e.code === "login_timeout");
  assert.deepEqual(calls.filter((c) => c.startsWith("raw")), ["raw:true", "raw:false"]);
  assert.ok(calls.includes("pause"));
  assert.ok(calls.includes("destroy"), "an abandoned read closes stdin so the process can exit");
});

test("loginViaCode times out on a non-TTY stdin that never delivers and destroys it", async () => {
  const { input, calls } = fakeStdin([], { hang: true });
  const { options } = codeOptions(input, { timeoutMs: 50 });
  await assert.rejects(loginViaCode(options), (e) => e instanceof LoginError && e.code === "login_timeout");
  assert.ok(calls.includes("destroy"));
});

// ---- runCli mode selection ----

async function cli(args: string[], env: NodeJS.ProcessEnv, stdinChunks?: (state: string) => string[]) {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-cli-"));
  let stdout = "";
  let stderr = "";
  const opened: string[] = [];
  let release!: (c: string[]) => void;
  const gate = new Promise<string[]>((r) => (release = r));
  const exitCode = await runCli(["login", ...args], {
    env: { HEMLIG_CONSOLE_URL: consoleUrl, ...env },
    configDir: join(dir, "hemlig"),
    now: () => NOW,
    loginTimeoutMs: 300,
    fetch: configResponse as unknown as typeof fetch,
    openBrowser: (url) => void opened.push(url),
    stdin: {
      isTTY: false,
      async *[Symbol.asyncIterator]() {
        for (const c of await gate) yield Buffer.from(c);
      },
    },
    stdout: (t) => void (stdout += t),
    stderr: (t) => {
      stderr += t;
      const m = /state=([A-Za-z0-9_-]+)/.exec(t);
      if (m && stdinChunks) release(stdinChunks(m[1]!));
    },
  });
  const cached = await stat(join(dir, "hemlig", "admin-token")).then(
    () => true,
    () => false,
  );
  await rm(dir, { recursive: true, force: true });
  return { exitCode, stdout, stderr, opened, cached };
}

test("SSH_CONNECTION selects the code flow, does not open a browser, and keeps the stdout receipt", async () => {
  for (const env of [{ SSH_CONNECTION: "1 2 3 4" }, { SSH_TTY: "/dev/pts/1" }]) {
    const r = await cli([], env, (s) => [`${formatLoginCode(s, validToken)}\n`]);
    assert.equal(r.exitCode, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), {
      loggedIn: true,
      adminUrl,
      expiresAt: new Date(NOW + 600_000).toISOString(),
    });
    assert.match(r.stderr, /mode=code&state=/);
    assert.doesNotMatch(r.stderr, /port=/);
    assert.match(r.stderr, /Paste the login code from the console, then press Enter:/);
    assert.deepEqual(r.opened, []);
    assert.equal(r.cached, true);
  }
});

test("--no-localhost without SSH opens the browser unless --no-browser", async () => {
  const chunks = (s: string) => [`${formatLoginCode(s, validToken)}\n`];
  const a = await cli(["--no-localhost"], {}, chunks);
  assert.equal(a.exitCode, 0, a.stderr);
  assert.equal(a.opened.length, 1);
  assert.match(a.opened[0]!, /mode=code/);
  const b = await cli(["--no-localhost", "--no-browser"], {}, chunks);
  assert.equal(b.exitCode, 0, b.stderr);
  assert.deepEqual(b.opened, []);
});

test("--localhost overrides SSH detection and uses the loopback listener", async () => {
  const r = await cli(["--localhost"], { SSH_CONNECTION: "x" });
  assert.equal(r.exitCode, 8); // times out waiting for the browser POST
  assert.match(r.stderr, /cli-login\?port=\d+&state=/);
  assert.equal(r.opened.length, 1);
});

test("--no-localhost with --localhost is a usage error", async () => {
  const r = await cli(["--no-localhost", "--localhost"], {});
  assert.equal(r.exitCode, 2);
  assert.deepEqual(r.opened, []);
});

test("a mismatched code via the CLI saves nothing and exits non-zero", async () => {
  const r = await cli(["--no-localhost", "--no-browser"], {}, () => [`${formatLoginCode("B".repeat(43), validToken)}\n`]);
  assert.notEqual(r.exitCode, 0);
  assert.equal(r.cached, false);
  assert.match(r.stderr, /state_mismatch/);
  assert.equal(r.stdout, "");
});

test("--help lists --no-localhost and --localhost", async () => {
  let stdout = "";
  await runCli(["--help"], { env: {}, stdout: (t) => void (stdout += t), stderr: () => {} });
  const help = JSON.parse(stdout);
  assert.match(help.usage, /\[--no-localhost\|--localhost\]/);
  assert.ok("--no-localhost" in help.options && "--localhost" in help.options);
});

test("no HTTP server is started by the code flow", async () => {
  const http = await import("node:http");
  const original = http.Server.prototype.listen;
  let listened = false;
  http.Server.prototype.listen = function (this: unknown, ...args: unknown[]) {
    listened = true;
    return (original as (...a: unknown[]) => unknown).apply(this, args) as never;
  } as typeof original;
  try {
    const r = await cli(["--no-localhost", "--no-browser"], {}, (s) => [`${formatLoginCode(s, validToken)}\n`]);
    assert.equal(r.exitCode, 0, r.stderr);
    assert.equal(listened, false);
  } finally {
    http.Server.prototype.listen = original;
  }
});
