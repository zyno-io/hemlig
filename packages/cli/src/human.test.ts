import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { HemligError, type TransportRequest } from "@zyno-io/hemlig-client";
import { runCli } from "./index";
import { formatLoginCode } from "./login";
import { humanResult, formatValue } from "./human";

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b/;
const NOW = Date.UTC(2030, 0, 1);
const adminUrl = "https://admin.example.test";
const consoleUrl = "https://console.example.com";
const token = "test.header.signature";
const env = { HEMLIG_ADMIN_URL: adminUrl, HEMLIG_ENVIRONMENT: "production", HEMLIG_ADMIN_TOKEN: token, NO_COLOR: "1" };
const caId = "ca-11111111-2222-3333-4444-555555555555";

const control = {
  secretId: "payments/stripe/api-key",
  secretUid: "sec-original",
  environment: "production",
  controlVersionId: "ctl-next",
  payloadKeyCount: 2,
  state: "ACTIVE",
  metadata: { description: "Stripe key", tags: { owner: "payments", tier: "1" } },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }, { consumerId: "prod-west", permissions: ["read"] }],
};
const consumer = {
  consumerId: "prod-east",
  environment: "production",
  status: "ACTIVE",
  subjectUri: "spiffe://example/prod-east",
  createdAt: "2030-01-01T00:00:00.000Z",
};
const fingerprint = "ab".repeat(32);
const caSummary = {
  caId,
  environment: "production",
  name: "issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "ACTIVE",
  version: "v1",
  keyAlgorithm: "ECDSA_P384",
  keyState: "ACTIVE",
  notAfter: "2032-01-01T00:00:00.000Z",
  createdAt: "2030-01-01T00:00:00.000Z",
};
const caDetail = {
  ...caSummary,
  subjectDn: "CN=Issuing 1,O=Example",
  serial: "0a1b",
  notBefore: "2030-01-01T00:00:00.000Z",
  crl: { number: 4, thisUpdate: "2030-01-01T00:00:00.000Z", nextUpdate: "2030-01-08T00:00:00.000Z", state: "CURRENT" },
  capacity: { capacity: 1000, issuancePerHour: 100, count: 12 },
};

interface Options {
  tty?: boolean;
  errTty?: boolean;
  body?: unknown | ((request: TransportRequest) => unknown);
  fail?: HemligError;
  env?: NodeJS.ProcessEnv;
  input?: string;
}

async function run(args: string[], options: Options = {}) {
  let stdout = "";
  let stderr = "";
  const requests: TransportRequest[] = [];
  const exitCode = await runCli(args, {
    env: options.env ?? env,
    configDir: join(tmpdir(), "hemlig-human-test-no-config"),
    now: () => NOW,
    stdin: {
      isTTY: false,
      async *[Symbol.asyncIterator]() {
        yield Buffer.from(options.input ?? "");
      },
    },
    stdout: (text) => void (stdout += text),
    stderr: (text) => void (stderr += text),
    stdoutIsTTY: options.tty ?? false,
    stderrIsTTY: options.errTty ?? options.tty ?? false,
    transport: {
      async request(request) {
        requests.push(request);
        if (options.fail !== undefined) throw options.fail;
        const body = typeof options.body === "function" ? options.body(request) : options.body;
        return { status: 200, headers: {}, body };
      },
    },
  });
  return { exitCode, stdout, stderr, requests };
}

const tty = (args: string[], options: Options = {}) => run(args, { ...options, tty: true });

// -- help ----------------------------------------------------------------------------------------------------------------

test("terminal help: global, group and command pages are plain text with usage, a description and aligned options", async () => {
  const global = await tty(["--help"]);
  assert.equal(global.exitCode, 0);
  assert.doesNotMatch(global.stdout, /^\{/);
  assert.match(global.stdout, /^Hemlig administrator CLI/);
  assert.match(global.stdout, /\nUsage\n {2}hemlig secret <command> \[options\]\n {2}hemlig pki /);
  assert.match(global.stdout, /\n {2}--environment <env> +Logical environment;/);
  assert.match(global.stdout, /\nExit codes\n {2}0 {2}Success\n/);

  const group = await tty(["secret", "--help"]);
  assert.match(group.stdout, /^Usage\n {2}hemlig secret <create\|update\|write-payload\|read\|read-payload\|archive> \[options\]\n/);
  assert.match(group.stdout, /\n {2}write-payload {2}Write the secret's value/);

  const command = await tty(["secret", "create", "--help"]);
  assert.match(command.stdout, /^Create a secret's control record/);
  assert.match(command.stdout, /\nUsage\n {2}hemlig secret create --environment <env> --secret-id <id> --input <file\|-> \[options\]\n/);
  assert.doesNotMatch(command.stdout, /--if-match/);
  assert.match(command.stdout, /\n {2}--json {2,}Print the JSON envelope/);

  const login = await tty(["login", "--help"]);
  assert.match(login.stdout, /\nUsage\n {2}hemlig login \[options\]\n/);
  assert.match(login.stdout, /--no-localhost {2,}login only/);
  assert.doesNotMatch(login.stdout, /--environment/);

  const consumerHelp = await tty(["consumer", "revoke-identity", "--help"]);
  assert.match(consumerHelp.stdout, /^Revoke one API identity\./);
  assert.match(consumerHelp.stdout, /--consumer-id <id> --fingerprint <hex>/);
});

test("terminal help for pki splits the usage string one alternative per line and narrows by group and command", async () => {
  const all = await tty(["pki", "--help"]);
  assert.match(all.stdout, /\nUsage\n {2}hemlig pki ca <list\|get\|create[^\n]*\n {2}hemlig pki ca crl <publish\|get>\n {2}hemlig pki external-ca /);
  assert.match(all.stdout, /\n {2}cert issue <ca> /);
  const group = await tty(["pki", "ca", "--help"]);
  assert.doesNotMatch(group.stdout, /grant list/);
  assert.match(group.stdout, /\n {2}ca retire <ca> {2,}\[--idempotency-key\]/);
  const command = await tty(["pki", "ca", "create", "--help"]);
  assert.match(command.stdout, /^Usage\n {2}hemlig pki ca create \[options\]\n/);
  assert.match(command.stdout, /\n {2}--environment {2,}required\n/);
  assert.match(command.stdout, /\n {2}--capacity N {2,}optional\n/);
  const withOperand = await tty(["pki", "ca", "get", caId, "--help"]);
  assert.match(withOperand.stdout, /hemlig pki ca get <ca> \[options\]/);
  const ez = await tty(["pki", "ez", "--help"]);
  assert.match(ez.stdout, /^Create and operate the offline root/);
  assert.match(ez.stdout, /\n {2}status {2,}\[--offline\]/);
});

test("help is the unchanged JSON when piped and with --json, even on a terminal", async () => {
  for (const args of [["--help"], ["secret", "--help"], ["pki", "--help"], ["pki", "ca", "create", "--help"], ["pki", "ez", "--help"]]) {
    const piped = await run(args);
    const json = await tty([...args, "--json"]);
    assert.equal(json.stdout, piped.stdout, args.join(" "));
    const parsed = JSON.parse(piped.stdout);
    assert.equal(typeof parsed.usage, "string");
    assert.equal(piped.stdout.endsWith("}\n"), true);
  }
  const help = JSON.parse((await run(["--help"])).stdout);
  assert.deepEqual(Object.keys(help), ["usage", "commands", "consumerCommands", "pki", "topLevelCommands", "options", "output", "exitCodes"]);
  assert.equal(help.options["--timeout-ms"], "Per-request timeout (1–300000 milliseconds); default 30000.");
  assert.equal(Object.keys(help.options).includes("--json"), false);
});

// -- results ---------------------------------------------------------------------------------------------------------------

test("secret get, mutation and the payload read on a terminal", async () => {
  const get = await tty(["secret", "read", "--secret-id", control.secretId], { body: control });
  assert.equal(get.exitCode, 0);
  assert.equal(get.stderr, "");
  assert.match(get.stdout, /^Secret payments\/stripe\/api-key\n/);
  assert.match(get.stdout, /\n {2}Environment {2,}production\n/);
  assert.match(get.stdout, /\n {2}Tags {2,}owner: payments, tier: 1\n/);
  assert.match(get.stdout, /\n {2}Access {2,}2 consumers: prod-east, prod-west\n/);
  assert.doesNotMatch(get.stdout, /^\{/);

  const create = await tty(["secret", "create", "--secret-id", control.secretId, "--input", "-", "--idempotency-key", "op-12345678"], {
    body: { ...control, state: "PENDING_VALUE" },
    input: JSON.stringify({ metadata: {}, acl: [] }),
  });
  assert.match(create.stdout, /^✓ Secret created: payments\/stripe\/api-key\n/);
  assert.match(create.stdout, /\n {2}State {2,}PENDING_VALUE\n/);
  assert.match(create.stdout, /\n {2}Idempotency key {2}op-12345678\n/);
  assert.match(create.stdout, /\nNext steps\n {2}1\. Write the value: hemlig secret write-payload/);

  // The payload command keeps printing the JSON receipt, payload and all, even on a terminal.
  const payload = { secretId: control.secretId, controlVersionId: "ctl-1", payloadVersionId: "pay-1", payload: { password: { encoding: "utf8", value: "hunter2" } } };
  const read = await tty(["secret", "read-payload", "--secret-id", control.secretId], { body: payload });
  assert.equal(JSON.parse(read.stdout).data.payload.password.value, "hunter2");
  const piped = await run(["secret", "read-payload", "--secret-id", control.secretId], { body: payload });
  assert.equal(read.stdout, piped.stdout);
});

test("secret write-payload never prints entry values, whatever the server returns", async () => {
  const result = await tty(["secret", "write-payload", "--secret-id", control.secretId, "--if-match", "ctl-next", "--input", "-"], {
    body: { ...control, payload: { password: { encoding: "utf8", value: "hunter2" } } },
    input: JSON.stringify({ password: { encoding: "utf8", value: "hunter2" } }),
  });
  assert.match(result.stdout, /^✓ Payload written: payments\/stripe\/api-key \(2 keys\)\n/);
  assert.doesNotMatch(result.stdout, /hunter2/);
  const fallback = humanResult("something new", { data: { id: "x", payload: { password: { value: "hunter2" } }, nested: { payload: { a: "hunter2" } } } }, { now: new Date(NOW) });
  assert.doesNotMatch(JSON.stringify(fallback), /hunter2/);
});

test("consumer list, get and revoke-identity on a terminal", async () => {
  const list = await tty(["consumer", "list"], { body: { consumers: [consumer, { ...consumer, consumerId: "prod-west", status: "PENDING" }], nextCursor: "page 2", generatedAt: "2030-01-01T00:00:00Z" } });
  assert.match(list.stdout, /^2 consumers on this page\n/);
  assert.match(list.stdout, /\n {2}CONSUMER ID {2}STATUS {3}ENVIRONMENT {2}CREATED\n {2}prod-east {4}ACTIVE {3}production {3}2030-01-01\n/);
  assert.match(list.stdout, /\n {2}More results: pass --cursor 'page 2' for the next page\.\n/);

  const empty = await tty(["consumer", "list"], { body: { consumers: [], generatedAt: "x" } });
  assert.equal(empty.stdout, "No consumers found\n");

  const get = await tty(["consumer", "get", "--consumer-id", "prod-east"], { body: { ...consumer, activeApiIdentityCount: 1, createdBy: { type: "user", id: "u1" } } });
  assert.match(get.stdout, /^Consumer prod-east\n/);
  assert.match(get.stdout, /\n {2}Created by {2,}type: user, id: u1\n/);
  assert.match(get.stdout, /\n {2}Created {2,}2030-01-01 00:00 UTC\n/);

  const revoke = await tty(["consumer", "revoke-identity", "--consumer-id", "prod-east", "--fingerprint", fingerprint, "--idempotency-key", "op-12345678"], {
    body: { consumerId: "prod-east", environment: "production", apiFingerprint: fingerprint, status: "REVOKED" },
  });
  assert.match(revoke.stdout, /^✓ API identity revoked: abababababababab\.\.\.\n/);
  assert.match(revoke.stdout, /\n {2}Status {2,}REVOKED\n/);
});

test("pki list, get and mutation on a terminal", async () => {
  const list = await tty(["pki", "ca", "list"], { body: { cas: [caSummary], generatedAt: "x" } });
  assert.match(list.stdout, /^1 CA\n\n {2}NAME {7}CA ID {36}KIND {19}STATUS {2}KEY {9}EXPIRES\n {2}issuing-1 {2}ca-11111111/);
  assert.doesNotMatch(list.stdout, /More results/);

  const get = await tty(["pki", "ca", "get", caId], { body: caDetail });
  assert.match(get.stdout, /^CA issuing-1\n/);
  assert.match(get.stdout, /\n {2}Key {2,}ECDSA_P384, active\n/);
  assert.match(get.stdout, /\n {2}CRL {2,}#4, current, next update 2030-01-08\n/);
  assert.match(get.stdout, /\n {2}Capacity {2,}12 of 1000 certificates\n/);

  const revoke = await tty(["pki", "ca", "revoke", caId, "--idempotency-key", "op-12345678"], {
    body: { ca: { ...caDetail, status: "REVOKED" }, changed: true, crlEntry: true, crlPublished: true, crlNumber: 5, revokedCaIds: [caId], complete: true },
  });
  assert.match(revoke.stdout, /^✓ CA revoked: issuing-1\n/);
  assert.match(revoke.stdout, /\n {2}CRL number {2,}5\n/);
  assert.match(revoke.stdout, /\n {2}Revoked CAs {2,}ca-11111111-2222-3333-4444-555555555555\n/);

  const certs = await tty(["pki", "cert", "list", caId], {
    body: { certificates: [{ caId, serial: "0f", subject: "CN=a.example", status: "ISSUED", notAfter: "2031-01-01T00:00:00Z" }], nextCursor: "c2", generatedAt: "x" },
  });
  assert.match(certs.stdout, /\n {2}0f {6}CN=a\.example {2}ISSUED {2}2031-01-01 {2}ca-1111/);
  assert.match(certs.stdout, /pass --cursor c2 for the next page/);

  const rendered = humanResult(
    "pki cert issue",
    { data: { caId, serial: "0f", certificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", out: "leaf.pem" }, idempotencyKey: "op-1" },
    { now: new Date(NOW) },
  );
  assert.equal(rendered.headline, "Certificate issued: serial 0f");
  assert.deepEqual(rendered.facts?.find(([label]) => label === "Certificate file"), ["Certificate file", "leaf.pem"]);
  assert.match(rendered.notes?.[0] ?? "", /PEM text is not shown/);
});

test("validate-only, grant migrate and a partial CA revoke are not shown as plain successes", () => {
  const now = { now: new Date(NOW) };
  const invalid = humanResult("pki grant create", { data: { valid: false, errors: [{ code: "bad_name", path: "names.dns", message: "no" }], warnings: [] } }, now);
  assert.match(invalid.headline, /^Grant is invalid: 1 error \(nothing was written\)/);
  assert.equal(invalid.mark, "warn");
  assert.deepEqual(invalid.table?.rows, [["bad_name", "names.dns", "no"]]);
  const migrate = humanResult("pki grant migrate", { data: { from: "a", to: "b", dryRun: false, results: [{ consumerId: "c", name: "g", outcome: "failed" }, { consumerId: "c", name: "h", outcome: "migrated" }], remainingListed: 1 } }, now);
  assert.equal(migrate.headline, "1 grant moved from a to b");
  assert.equal(migrate.mark, "warn");
  const revoke = humanResult("pki ca revoke", { data: { ca: caDetail, changed: true, complete: false, revokedCaIds: [] }, idempotencyKey: "op-12345678" }, now);
  assert.match(revoke.next?.[0] ?? "", /--idempotency-key op-12345678/);
});

test("a command without a renderer falls back to indented key/value text, never JSON", () => {
  const result = humanResult("pki widget list", { data: { widgets: [{ id: "w1", size: 3, name: "one" }], nextCursor: "n" } }, { now: new Date(NOW) });
  assert.equal(result.headline, "1 widget");
  assert.deepEqual(result.table?.head, ["NAME", "ID", "SIZE"]);
  const single = humanResult("pki widget get", { data: { id: "w1", owner: { name: "a", team: "b" }, tags: ["x", "y"], enabled: true, nothing: null } }, { now: new Date(NOW) });
  assert.deepEqual(single.facts, [["id", "w1"], ["owner.name", "a"], ["owner.team", "b"], ["tags", "x, y"], ["enabled", "yes"]]);
  assert.equal(formatValue({ a: 1, b: { c: 2 } }), "a: 1, b: c: 2");
});

test("login prints a tick, the API and the expiry; the prompts stay on stderr as before", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hemlig-human-login-"));
  try {
    const jwt = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify({ exp: NOW / 1000 + 7200 })).toString("base64url")}.sig`;
    let release!: (c: string[]) => void;
    const gate = new Promise<string[]>((r) => (release = r));
    let stdout = "";
    let stderr = "";
    const exitCode = await runCli(["login", "--no-localhost", "--no-browser"], {
      env: { HEMLIG_CONSOLE_URL: consoleUrl, NO_COLOR: "1" },
      configDir: join(dir, "hemlig"),
      now: () => NOW,
      loginTimeoutMs: 2000,
      fetch: (async () => new Response(JSON.stringify({ deploymentName: "d", adminApiUrl: `${adminUrl}/` }))) as unknown as typeof fetch,
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
        if (m) release([`${formatLoginCode(m[1]!, jwt)}\n`]);
      },
      stdoutIsTTY: true,
      stderrIsTTY: true,
    });
    assert.equal(exitCode, 0, stderr);
    assert.equal(stdout, `✓ Logged in to ${adminUrl}\n\n  Expires  2030-01-01 02:00 UTC (in 2 hours)\n`);
    assert.match(stderr, /^Open this URL to sign in to the Hemlig CLI:\n/);
    assert.match(stderr, /Paste the login code from the console, then press Enter:\n$/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("logout and idempotency-key on a terminal", async () => {
  const out = await run(["logout"], { tty: true, env: { ...env, XDG_CONFIG_HOME: join(tmpdir(), "hemlig-human-logout") } });
  assert.equal(out.stdout, "✓ Logged out\n\n  Cached login  removed\n");
  const key = await tty(["idempotency-key"]);
  assert.match(key.stdout, /^[0-9a-f-]{36}\n$/);
  const piped = await run(["idempotency-key"]);
  assert.match(piped.stdout, /^\{"idempotencyKey":"[0-9a-f-]{36}"\}\n$/);
});

// -- errors ----------------------------------------------------------------------------------------------------------------

test("errors on a terminal: message, code and exit code, hint, API status and the outcome of a mutation", async () => {
  const missing = await tty(["consumer", "get", "--consumer-id", "nope-none"], { fail: new HemligError(404, "secret detail that must not be echoed") });
  assert.equal(missing.exitCode, 4);
  assert.equal(missing.stdout, "");
  assert.equal(missing.stderr, "✗ Consumer or API identity was not found.\n  (not_found, exit 4)\n  HTTP status: 404\n");
  assert.doesNotMatch(missing.stderr, /must not be echoed/);

  const stale = await tty(["secret", "archive", "--secret-id", control.secretId, "--if-match", "ctl-old", "--idempotency-key", "op-12345678"], { fail: new HemligError(412, "x") });
  assert.equal(stale.exitCode, 6);
  assert.match(stale.stderr, /^✗ Control revision changed\. Read the current metadata and decide on a new operation\.\n {2}\(precondition_failed, exit 6\)\n {2}Someone changed it first\./);
  assert.match(stale.stderr, /\n {2}The server rejected the request; nothing changed\.\n/);

  const unknown = await tty(["secret", "archive", "--secret-id", control.secretId, "--if-match", "ctl-old", "--idempotency-key", "op-12345678"], { fail: new HemligError(503, "x") });
  assert.equal(unknown.exitCode, 7);
  assert.match(unknown.stderr, /outcome is unknown/);
  assert.match(unknown.stderr, /Idempotency key: op-12345678 \(pass it again to replay safely\)/);

  const usage = await tty(["secret", "read"], { env: { HEMLIG_ENVIRONMENT: "production", NO_COLOR: "1" } });
  assert.equal(usage.exitCode, 2);
  assert.match(usage.stderr, /^✗ Supply --admin-url or HEMLIG_ADMIN_URL/);
  assert.match(usage.stderr, /\(invalid_input, exit 2\)\n {2}Run hemlig --help/);
});

// -- modes -----------------------------------------------------------------------------------------------------------------

test("piped output is the JSON envelope, byte for byte, for results and errors", async () => {
  const read = await run(["secret", "read", "--secret-id", control.secretId], { body: control });
  assert.equal(read.stdout, `${JSON.stringify({ data: control, etag: "ctl-next" })}\n`);
  assert.equal(read.stderr, "");
  const list = await run(["consumer", "list"], { body: { consumers: [consumer], generatedAt: "g" } });
  assert.equal(list.stdout, `${JSON.stringify({ data: { consumers: [consumer], generatedAt: "g" } })}\n`);
  const cas = await run(["pki", "ca", "list"], { body: { cas: [caSummary], generatedAt: "g" } });
  assert.equal(cas.stdout, `${JSON.stringify({ data: { cas: [caSummary], generatedAt: "g" } })}\n`);
  const failed = await run(["consumer", "get", "--consumer-id", "nope-none"], { fail: new HemligError(404, "x") });
  assert.equal(failed.exitCode, 4);
  assert.equal(failed.stdout, "");
  assert.equal(
    failed.stderr,
    `${JSON.stringify({ error: { exitCode: 4, code: "not_found", message: "Consumer or API identity was not found.", status: 404 } })}\n`,
  );
  // Piped stdout with a terminal stderr still prints the JSON receipt; stdout decides, and the error follows stderr.
  const mixed = await run(["secret", "read", "--secret-id", control.secretId], { body: control, tty: false, errTty: true });
  assert.equal(mixed.stdout, read.stdout);
  const mixedError = await run(["consumer", "get", "--consumer-id", "nope-none"], { fail: new HemligError(404, "x"), tty: false, errTty: false });
  assert.equal(mixedError.stderr, failed.stderr);
});

test("--json on a terminal prints the JSON envelope for results and errors, with the same exit codes", async () => {
  const piped = await run(["secret", "read", "--secret-id", control.secretId], { body: control });
  const json = await tty(["secret", "read", "--secret-id", control.secretId, "--json"], { body: control });
  assert.equal(json.stdout, piped.stdout);
  const pki = await tty(["pki", "ca", "list", "--json"], { body: { cas: [], generatedAt: "g" } });
  assert.equal(pki.stdout, `${JSON.stringify({ data: { cas: [], generatedAt: "g" } })}\n`);
  const failed = await tty(["consumer", "get", "--consumer-id", "nope-none", "--json"], { fail: new HemligError(404, "x") });
  assert.equal(failed.exitCode, 4);
  assert.match(failed.stderr, /^\{"error":\{"exitCode":4,"code":"not_found"/);
  // Accepted before the group too, and by every kind of command.
  const before = await tty(["--json", "consumer", "list"], { body: { consumers: [], generatedAt: "g" } });
  assert.match(before.stdout, /^\{"data"/);
  const logout = await run(["logout", "--json"], { tty: true, env: { ...env, XDG_CONFIG_HOME: join(tmpdir(), "hemlig-human-logout") } });
  assert.equal(logout.stdout, '{"loggedIn":false}\n');
  const piped2 = await run(["secret", "read", "--secret-id", control.secretId, "--json"], { body: control });
  assert.equal(piped2.stdout, piped.stdout);
});

test("color follows NO_COLOR and TERM=dumb", async () => {
  const colored = await tty(["consumer", "get", "--consumer-id", "prod-east"], { body: { ...consumer, activeApiIdentityCount: 1 }, env: { ...env, NO_COLOR: undefined } });
  assert.match(colored.stdout, ANSI);
  for (const extra of [{ NO_COLOR: "1" }, { TERM: "dumb" }]) {
    const plain = await tty(["consumer", "get", "--consumer-id", "prod-east"], { body: { ...consumer, activeApiIdentityCount: 1 }, env: { ...env, ...extra } });
    assert.doesNotMatch(plain.stdout, ANSI, JSON.stringify(extra));
  }
});

test("a renderer that throws falls back to the JSON envelope with the real exit code", async () => {
  // `state` is read by the human renderer but is not enumerable, so the JSON envelope never touches it.
  const hostile = { ...control } as Record<string, unknown>;
  Object.defineProperty(hostile, "state", {
    enumerable: false,
    get() {
      throw new Error("renderer bug");
    },
  });
  const piped = await run(["secret", "read", "--secret-id", control.secretId], { body: hostile });
  assert.equal(piped.exitCode, 0);
  const result = await tty(["secret", "read", "--secret-id", control.secretId], { body: hostile });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, piped.stdout);
  assert.match(result.stdout, /^\{"data":/);
  assert.equal(result.stderr, "");
});

test("hostile server strings are escaped in every kind of human output", async () => {
  const evil = "\x1b]0;pwned\x07\x1b[31mred‮evil\u0085\nforged: line\r";
  const bad = { ...control, secretId: "payments/x", metadata: { description: evil, tags: { [evil]: evil } }, acl: [{ consumerId: evil, permissions: ["read"] }] };
  const get = await tty(["secret", "read", "--secret-id", control.secretId], { body: bad, env: { ...env, NO_COLOR: "1" } });
  const list = await tty(["consumer", "list"], { body: { consumers: [{ ...consumer, consumerId: evil, subjectUri: evil }], nextCursor: evil, generatedAt: evil }, env: { ...env, NO_COLOR: "1" } });
  const ca = await tty(["pki", "ca", "get", caId], { body: { ...caDetail, name: evil, subjectDn: evil, warnings: [{ code: "x", message: evil }] }, env: { ...env, NO_COLOR: "1" } });
  const fallback = await tty(["pki", "ca", "crl", "publish", caId], { body: { caId: evil, crl: { number: evil, state: evil }, extra: { [evil]: evil } }, env: { ...env, NO_COLOR: "1" } });
  for (const out of [get, list, ca, fallback]) {
    // eslint-disable-next-line no-control-regex
    assert.doesNotMatch(out.stdout, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f‮]/, out.stdout);
    assert.doesNotMatch(out.stdout, /\nforged: line/);
    assert.match(out.stdout, /\\x1b/);
  }
  const failed = await tty(["pki", "ca", "get", caId], { fail: new HemligError(409, evil, evil, { [evil]: evil }), env: { ...env, NO_COLOR: "1" } });
  assert.equal(failed.exitCode, 5);
  // eslint-disable-next-line no-control-regex
  assert.doesNotMatch(failed.stderr, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f‮]/);
});

// -- the real binary -------------------------------------------------------------------------------------------------------

const havePty = spawnSync("python3", ["-c", "import pty,os; m,s=pty.openpty(); os.close(m); os.close(s)"], { encoding: "utf8" }).status === 0;
const PTY_RUNNER = `
import os, pty, subprocess, sys
master, slave = pty.openpty()
env = dict(os.environ, NO_COLOR="1")
proc = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=env)
os.close(slave)
out = b""
while True:
    try:
        chunk = os.read(master, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
proc.wait()
sys.stdout.write(out.decode("utf8", "replace").replace("\\r\\n", "\\n"))
sys.exit(proc.returncode)
`;

test("the real binary prints text under a pty for help, a command and an error, and JSON when piped", { skip: !havePty && "no pty available" }, () => {
  const main = join(__dirname, "main.js");
  const pty = (...args: string[]) => spawnSync("python3", ["-c", PTY_RUNNER, process.execPath, main, ...args], { encoding: "utf8", env: { ...process.env, HEMLIG_ADMIN_URL: "", HEMLIG_ENVIRONMENT: "" } });
  const help = pty("--help");
  assert.equal(help.status, 0);
  assert.match(help.stdout, /^Hemlig administrator CLI/);
  assert.match(help.stdout, /\nUsage\n {2}hemlig secret <command> \[options\]\n/);
  assert.doesNotMatch(help.stdout, /^\{/);
  const login = pty("login", "--help");
  assert.match(login.stdout, /\nUsage\n {2}hemlig login \[options\]\n/);
  // A non-ez command that fails locally on a terminal: the human error, with the exit code.
  const failing = pty("secret", "read", "--secret-id", "abc-def");
  assert.equal(failing.status, 2);
  assert.match(failing.stdout, /^✗ Supply --admin-url or HEMLIG_ADMIN_URL[^\n]*\n {2}\(invalid_input, exit 2\)\n/);
  const asJson = pty("secret", "read", "--secret-id", "abc-def", "--json");
  assert.equal(asJson.status, 2);
  assert.equal(JSON.parse(asJson.stdout.trim()).error.code, "invalid_input");
  const piped = spawnSync(process.execPath, [main, "--help"], { encoding: "utf8" });
  assert.equal(JSON.parse(piped.stdout).usage.startsWith("hemlig secret <command>"), true);
  const pipedError = spawnSync(process.execPath, [main, "secret", "read", "--secret-id", "abc-def"], { encoding: "utf8", env: { ...process.env, HEMLIG_ADMIN_URL: "", HEMLIG_ENVIRONMENT: "" } });
  assert.equal(pipedError.status, 2);
  assert.equal(JSON.parse(pipedError.stderr).error.code, "invalid_input");
});
