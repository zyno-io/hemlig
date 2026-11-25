import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { parseArgs } from "node:util";
import {
  HemligClient,
  type ControlRevision,
  type SecretPayload,
} from "@zyno-io/hemlig-client";
import {
  DEFAULT_LOGIN_TIMEOUT_MS,
  defaultConfigDir,
  loginViaConsole,
  loginViaCode,
  openInBrowser,
  removeCachedToken,
  writeCachedLogin,
} from "./login";
import {
  CliError,
  adminOrigin,
  createTransport,
  httpsOrigin,
  isObject,
  loadCachedLogin,
  parseTimeoutMs,
  readText,
  reportFailure,
  resolveAdminOrigin,
  resolveAdminToken,
  resolveIdempotencyKey,
  usage,
  type CliDependencies,
} from "./common";
import { pkiHelp, runPkiCli } from "./pki";
import {
  ConsumerInputError,
  consumerCommands,
  resolveFingerprint,
  validConsumerId,
  validFingerprint,
  type ConsumerCommand,
} from "./consumer";

const commands = [
  "create",
  "update",
  "write-payload",
  "read",
  "read-payload",
  "archive",
] as const;
type Command = (typeof commands)[number];

const help = {
  usage:
    "hemlig secret <command> [options] | hemlig pki <ca|external-ca|grant|cert|consumer> <command> [options] | hemlig consumer <list|get|identities|revoke-identity> [options] | hemlig login [--console-url <url>] [--no-browser] [--no-localhost|--localhost] | hemlig logout | hemlig idempotency-key",
  commands,
  consumerCommands: {
    list: "List consumers in --environment. Optional --cursor from the previous page's nextCursor.",
    get: "Read one consumer. Needs --consumer-id; no environment.",
    identities:
      "List a consumer's API identities (client certificates). Needs --consumer-id; optional --cursor.",
    "revoke-identity":
      "Revoke one API identity. Needs --consumer-id and --fingerprint; mutation with an idempotency key.",
  },
  pki: pkiHelp,
  topLevelCommands: {
    login:
      "Authorize via the web console's SSO session and cache a short-lived admin token. Opens a browser. The localhost callback never prompts; --no-localhost (default over SSH) asks for a login code.",
    logout: "Delete the cached login token.",
    "idempotency-key": "Print a newly minted UUID operation key.",
  },
  options: {
    "--console-url":
      "Console HTTPS origin for login; defaults to HEMLIG_CONSOLE_URL.",
    "--no-browser": "login only: print the URL instead of opening a browser.",
    "--no-localhost":
      "login only: no local callback listener; copy the login code shown by the console and paste it into the terminal. Default when SSH_CONNECTION or SSH_TTY is set.",
    "--localhost":
      "login only: use the 127.0.0.1 callback listener even in an SSH session. Cannot be combined with --no-localhost.",
    "--admin-url":
      "Administrator origin; defaults to HEMLIG_ADMIN_URL, then the API recorded by hemlig login when the cached login is the token source.",
    "--environment":
      "Logical environment; defaults to HEMLIG_ENVIRONMENT. Not used by consumer get, identities or revoke-identity.",
    "--token-file":
      "OIDC bearer token file; defaults to HEMLIG_ADMIN_TOKEN_FILE, then HEMLIG_ADMIN_TOKEN, then the token cached by hemlig login.",
    "--consumer-id":
      "Consumer ID, for hemlig consumer get|identities|revoke-identity.",
    "--fingerprint":
      "revoke-identity only: full 64-hex SHA-256 or a unique prefix of at least 12 hex characters, resolved against the consumer's identities.",
    "--cursor":
      "consumer list|identities: nextCursor from the previous page; one page is returned per call.",
    "--secret-id": "Reusable secret ID for active records.",
    "--secret-uid": "Immutable UID for archived records (read only).",
    "--input":
      "JSON file, or - for stdin. Required for create, update, write-payload.",
    "--if-match":
      "Known controlVersionId/strong ETag, or current to fetch it once. Required for update, write-payload, archive.",
    "--idempotency-key":
      "Durable operation key (secret mutations and consumer revoke-identity); defaults to a newly minted UUID for each mutation.",
    "--timeout-ms":
      "Per-request timeout (1–300000 milliseconds); default 30000.",
  },
  output:
    "One JSON receipt on stdout; one JSON error on stderr. No prompts or automatic retries. Exception: login prints its sign-in URL and confirmation code on stderr on success, and with --no-localhost (default over SSH) also prints a prompt on stderr and reads the login code from stdin.",
  exitCodes: {
    "0": "Success",
    "2": "Usage or invalid local input",
    "3": "Authentication/authorization (401/403)",
    "4": "Not found (404)",
    "5": "Conflict (409)",
    "6": "Stale revision (412)",
    "7": "Service/protocol or unexpected internal error",
    "8": "Network/timeout error",
    "9": "Local input/output error",
  },
};

export type { CliDependencies };

/** Runs one operation. Secret material is emitted only by the explicit payload-read command. */
export async function runCli(
  args: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> {
  const env = dependencies.env ?? process.env;
  const stdin = dependencies.stdin ?? process.stdin;
  const stdout =
    dependencies.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr =
    dependencies.stderr ?? ((text: string) => process.stderr.write(text));
  const now = dependencies.now ?? Date.now;
  const configDir = dependencies.configDir ?? defaultConfigDir(env);
  const pkiAt = pkiTokenIndex(args);
  if (pkiAt >= 0)
    return runPkiCli(
      [...args.slice(0, pkiAt), ...args.slice(pkiAt + 1)],
      dependencies,
    );
  let idempotencyKey: string | undefined;
  let ifMatch: string | undefined;
  let mutationAttempted = false;
  let group: string | undefined;
  try {
    let parsed;
    try {
      parsed = parseArgs({
        args: [...args],
        allowPositionals: true,
        strict: true,
        tokens: true,
        options: {
          help: { type: "boolean" },
          "admin-url": { type: "string" },
          "console-url": { type: "string" },
          "no-browser": { type: "boolean" },
          "no-localhost": { type: "boolean" },
          localhost: { type: "boolean" },
          environment: { type: "string" },
          "token-file": { type: "string" },
          "secret-id": { type: "string" },
          "secret-uid": { type: "string" },
          "consumer-id": { type: "string" },
          fingerprint: { type: "string" },
          cursor: { type: "string" },
          input: { type: "string" },
          "if-match": { type: "string" },
          "idempotency-key": { type: "string" },
          "timeout-ms": { type: "string" },
        },
      });
    } catch {
      usage(
        "Invalid arguments. Run hemlig --help for the JSON command reference.",
      );
    }
    const seen = new Set<string>();
    for (const token of parsed.tokens) {
      if (token.kind !== "option") continue;
      if (seen.has(token.name)) usage("An option was supplied more than once.");
      seen.add(token.name);
    }
    if (parsed.values.help) {
      await stdout(`${JSON.stringify(help)}\n`);
      return 0;
    }
    if (
      parsed.positionals.length === 1 &&
      parsed.positionals[0] === "idempotency-key"
    ) {
      if (seen.size !== 0) usage("idempotency-key does not accept options.");
      await stdout(`${JSON.stringify({ idempotencyKey: randomUUID() })}\n`);
      return 0;
    }
    if (parsed.positionals.length === 1 && parsed.positionals[0] === "logout") {
      if (seen.size !== 0) usage("logout does not accept options.");
      await removeCachedToken(configDir);
      await stdout(`${JSON.stringify({ loggedIn: false })}\n`);
      return 0;
    }
    if (parsed.positionals.length === 1 && parsed.positionals[0] === "login") {
      for (const name of seen) {
        if (
          name !== "console-url" &&
          name !== "no-browser" &&
          name !== "no-localhost" &&
          name !== "localhost"
        )
          usage("An option is not supported by login.");
      }
      if (parsed.values["no-localhost"] && parsed.values.localhost)
        usage("--no-localhost and --localhost cannot be combined.");
      const overSsh = Boolean(env.SSH_CONNECTION || env.SSH_TTY);
      const noLocalhost =
        parsed.values["no-localhost"] === true ||
        (parsed.values.localhost !== true && overSsh);
      const consoleOrigin = httpsOrigin(
        parsed.values["console-url"] ?? env.HEMLIG_CONSOLE_URL,
        "Supply --console-url or HEMLIG_CONSOLE_URL.",
        "Console URL",
        true,
      );
      const url = async (target: string, code: string): Promise<void> => {
        await stderr(
          `Open this URL to sign in to the Hemlig CLI:\n${target}\nConfirm the browser shows code ${code}\n`,
        );
      };
      // With the copy-the-code flow over SSH a browser opened here would be on the remote host.
      const open =
        parsed.values["no-browser"] || (noLocalhost && overSsh)
          ? undefined
          : (dependencies.openBrowser ?? openInBrowser);
      const timeoutMs = dependencies.loginTimeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS;
      const fetchImpl = dependencies.fetch ?? globalThis.fetch;
      const result = noLocalhost
        ? await loginViaCode({
            consoleOrigin,
            timeoutMs,
            now,
            fetch: fetchImpl,
            open,
            announce: url,
            prompt: async () => {
              await stderr(
                "Paste the login code from the console, then press Enter:\n",
              );
            },
            stdin,
          })
        : await loginViaConsole({
            consoleOrigin,
            timeoutMs,
            now,
            fetch: fetchImpl,
            open,
            announce: url,
          });
      await writeCachedLogin(configDir, {
        token: result.token,
        consoleOrigin: consoleOrigin.origin,
        adminOrigin: result.adminOrigin,
      });
      await stdout(
        `${JSON.stringify({ loggedIn: true, adminUrl: result.adminOrigin, expiresAt: result.expiresAt.toISOString() })}\n`,
      );
      return 0;
    }
    const candidate = parsed.positionals[1];
    group = parsed.positionals[0];
    const isConsumer = group === "consumer";
    if (
      parsed.positionals.length !== 2 ||
      (parsed.positionals[0] !== "secret" && !isConsumer) ||
      !(isConsumer ? consumerCommands : commands).includes(
        candidate as Command & ConsumerCommand,
      )
    )
      usage(
        "Expected hemlig secret <command> or hemlig consumer <command>. Run hemlig --help.",
      );
    const command: string = candidate!;
    const mutation = isConsumer
      ? command === "revoke-identity"
      : ["create", "update", "write-payload", "archive"].includes(command);
    const needsInput =
      !isConsumer && ["create", "update", "write-payload"].includes(command);
    const needsMatch = !isConsumer && mutation && command !== "create";
    const allowed = new Set(["admin-url", "token-file", "timeout-ms"]);
    if (isConsumer) {
      if (command === "list") allowed.add("environment");
      else allowed.add("consumer-id");
      if (command === "list" || command === "identities") allowed.add("cursor");
      if (command === "revoke-identity") allowed.add("fingerprint");
    } else {
      allowed.add("environment");
      allowed.add("secret-id");
    }
    if (command === "read" && !isConsumer) allowed.add("secret-uid");
    if (mutation) allowed.add("idempotency-key");
    if (needsInput) allowed.add("input");
    if (needsMatch) allowed.add("if-match");
    for (const name of seen) {
      if (!allowed.has(name))
        usage("An option is not supported by this command.");
    }
    const values = parsed.values;
    const cachedLogin = await loadCachedLogin(values, env, configDir);
    const origin = resolveAdminOrigin(values, env, cachedLogin);
    const requestedEnvironment = values.environment ?? env.HEMLIG_ENVIRONMENT;
    const needsEnvironment = !isConsumer || command === "list";
    if (
      needsEnvironment &&
      (!requestedEnvironment ||
        !/^[a-z][a-z0-9-]{0,63}$/.test(requestedEnvironment))
    ) {
      usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
    }
    // Undefined only for consumer commands that take no environment.
    const environment = requestedEnvironment as string;
    const secretId = values["secret-id"];
    const secretUid = values["secret-uid"];
    let consumerId: string | undefined;
    let fingerprint: string | undefined;
    if (isConsumer) {
      try {
        if (command !== "list")
          consumerId = validConsumerId(values["consumer-id"]);
        if (command === "revoke-identity")
          fingerprint = validFingerprint(values.fingerprint);
      } catch (error) {
        if (error instanceof ConsumerInputError) usage(error.message);
        throw error;
      }
      const cursor = values.cursor;
      if (cursor !== undefined && (!cursor || cursor.length > 2048))
        usage("--cursor must be a nextCursor value from the previous page.");
    } else if (secretUid !== undefined) {
      if (secretId !== undefined)
        usage("Use exactly one of --secret-id or --secret-uid.");
      if (!/^sec-[A-Za-z0-9-]+$/.test(secretUid))
        usage("Supply a valid --secret-uid from an archive receipt.");
    } else if (
      !secretId ||
      secretId.length > 256 ||
      !/^[a-z][a-z0-9-]{2,63}(\/[a-z][a-z0-9-]{2,63})*$/.test(secretId)
    ) {
      usage("Supply a valid --secret-id.");
    }
    const timeoutMs = parseTimeoutMs(values["timeout-ms"]);
    if (needsMatch) {
      if (!values["if-match"])
        usage(
          "Supply --if-match with a known ETag, or current to fetch it once.",
        );
      if (values["if-match"] !== "current")
        ifMatch = controlVersion(values["if-match"]);
    }
    const inputPath = values.input;
    if (needsInput && !inputPath)
      usage("This command requires --input <file|->.");
    if (inputPath === "-" && stdin.isTTY)
      usage("--input - requires piped stdin; the CLI never prompts.");
    const input =
      inputPath === undefined ? undefined : await readJson(inputPath, stdin);
    let controlInput:
      Partial<Pick<ControlRevision, "metadata" | "acl">> | undefined;
    let payload: SecretPayload | undefined;
    if (command === "create" || command === "update") {
      controlInput = validateControlInput(input, command === "create");
    } else if (command === "write-payload") {
      payload = validatePayload(input);
    }
    const token = await resolveAdminToken(
      values,
      env,
      cachedLogin,
      origin,
      now,
    );
    if (mutation) {
      idempotencyKey = resolveIdempotencyKey(values["idempotency-key"]);
    }
    const transport = createTransport(dependencies, timeoutMs);
    const client = new HemligClient(origin, transport);
    if (needsMatch && values["if-match"] === "current") {
      const current = await client.getAdminSecret(
        token,
        environment,
        secretId!,
      );
      ifMatch = responseVersion(current);
    }
    if (isConsumer) {
      let result: unknown;
      switch (command as ConsumerCommand) {
        case "list":
          result = await client.listConsumers(token, {
            environment,
            cursor: values.cursor,
          });
          break;
        case "get":
          result = await client.getConsumer(token, consumerId!);
          break;
        case "identities":
          result = await client.listApiIdentities(
            token,
            consumerId!,
            values.cursor,
          );
          break;
        case "revoke-identity": {
          let resolved: string;
          try {
            resolved = await resolveFingerprint(
              client,
              token,
              consumerId!,
              fingerprint!,
            );
          } catch (error) {
            if (error instanceof ConsumerInputError) usage(error.message);
            throw error;
          }
          mutationAttempted = true;
          result = await client.revokeApiIdentity(
            token,
            consumerId!,
            resolved,
            idempotencyKey!,
          );
          break;
        }
      }
      await stdout(`${JSON.stringify({ data: result, idempotencyKey })}\n`);
      return 0;
    }
    let data:
      | ControlRevision
      | Awaited<ReturnType<HemligClient["getAdminSecretPayload"]>>;
    switch (command as Command) {
      case "read":
        data =
          secretUid === undefined
            ? await client.getAdminSecret(token, environment, secretId!)
            : await client.getArchivedAdminSecret(
                token,
                environment,
                secretUid,
              );
        break;
      case "read-payload":
        data = await client.getAdminSecretPayload(
          token,
          environment,
          secretId!,
        );
        break;
      case "create":
        mutationAttempted = true;
        data = await client.createAdminSecret(
          token,
          {
            secretId: secretId!,
            environment,
            metadata: controlInput!.metadata!,
            acl: controlInput!.acl!,
          },
          idempotencyKey!,
        );
        break;
      case "update":
        mutationAttempted = true;
        data = await client.updateAdminSecret(
          token,
          environment,
          secretId!,
          ifMatch!,
          controlInput!,
          idempotencyKey!,
        );
        break;
      case "write-payload":
        mutationAttempted = true;
        data = await client.putAdminPayload(
          token,
          environment,
          secretId!,
          ifMatch!,
          payload!,
          idempotencyKey!,
        );
        break;
      case "archive":
        mutationAttempted = true;
        data = await client.archiveAdminSecret(
          token,
          environment,
          secretId!,
          ifMatch!,
          idempotencyKey!,
        );
        break;
    }
    const etag = responseVersion(data);
    await stdout(
      `${JSON.stringify({ data, etag, idempotencyKey, ifMatch })}\n`,
    );
    return 0;
  } catch (error) {
    return reportFailure(
      error,
      { group, idempotencyKey, ifMatch, mutationAttempted },
      stderr,
    );
  }
}

function controlVersion(value: string): string {
  const raw =
    value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
  if (
    !raw ||
    raw === "*" ||
    raw.startsWith("W/") ||
    !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(raw)
  ) {
    usage(
      "--if-match must be a controlVersionId or strong ETag; wildcard and weak ETags are forbidden.",
    );
  }
  return raw;
}

function responseVersion(value: unknown): string {
  if (!isObject(value) || typeof value.controlVersionId !== "string") {
    throw new CliError(
      7,
      "invalid_response",
      "Administrator API returned an invalid revision response.",
    );
  }
  try {
    return controlVersion(value.controlVersionId);
  } catch {
    throw new CliError(
      7,
      "invalid_response",
      "Administrator API returned an invalid revision response.",
    );
  }
}

function validateControlInput(
  value: unknown,
  create: boolean,
): Partial<Pick<ControlRevision, "metadata" | "acl">> {
  if (
    !isObject(value) ||
    Object.keys(value).some((key) => key !== "metadata" && key !== "acl")
  ) {
    usage(
      "Control input must be a JSON object containing only metadata and/or acl.",
    );
  }
  if (create && (value.metadata === undefined || value.acl === undefined))
    usage("Create input requires metadata and acl.");
  if (value.metadata === undefined && value.acl === undefined)
    usage("Update input requires metadata and/or acl.");
  if (value.metadata !== undefined) {
    if (
      !isObject(value.metadata) ||
      Object.keys(value.metadata).some(
        (key) => key !== "description" && key !== "tags",
      )
    )
      usage("metadata accepts description and tags only.");
    if (
      value.metadata.description !== undefined &&
      typeof value.metadata.description !== "string"
    )
      usage("metadata.description must be a string.");
    if (
      value.metadata.tags !== undefined &&
      (!isObject(value.metadata.tags) ||
        Object.values(value.metadata.tags).some(
          (tag) => typeof tag !== "string",
        ))
    )
      usage("metadata.tags must be a string map.");
  }
  if (
    value.acl !== undefined &&
    (!Array.isArray(value.acl) ||
      value.acl.some((grant) => {
        return (
          !isObject(grant) ||
          Object.keys(grant).some(
            (key) => key !== "consumerId" && key !== "permissions",
          ) ||
          typeof grant.consumerId !== "string" ||
          !Array.isArray(grant.permissions) ||
          grant.permissions.length !== 1 ||
          grant.permissions[0] !== "read"
        );
      }))
  )
    usage("acl must be an array of consumerId/read-permission grants.");
  return value as Partial<Pick<ControlRevision, "metadata" | "acl">>;
}

function validatePayload(value: unknown): SecretPayload {
  if (
    !isObject(value) ||
    Object.entries(value).some(([key, entry]) => {
      return (
        !/^[A-Za-z0-9._-]+$/.test(key) ||
        !isObject(entry) ||
        Object.keys(entry).some(
          (field) => field !== "encoding" && field !== "value",
        ) ||
        (entry.encoding !== "utf8" && entry.encoding !== "base64") ||
        typeof entry.value !== "string" ||
        (entry.encoding === "base64" &&
          Buffer.from(entry.value, "base64").toString("base64") !== entry.value)
      );
    })
  )
    usage(
      "Payload input must map valid entry names to encoding=utf8|base64 and a string value; base64 must be canonical.",
    );
  if (Buffer.byteLength(JSON.stringify({ payload: value }), "utf8") > 768000)
    usage("Serialized payload request exceeds 768000 bytes.");
  return value as SecretPayload;
}

async function readJson(
  path: string,
  stdin: AsyncIterable<string | Uint8Array>,
): Promise<unknown> {
  const text = await readText(
    path === "-" ? stdin : createReadStream(path),
    768000,
    "Cannot read JSON input.",
  );
  try {
    return JSON.parse(text);
  } catch {
    return usage("Input is not valid JSON.");
  }
}

// Every value-taking option of the strict parser below, so an option value is never mistaken for the group.
const globalValueFlags = new Set([
  "--admin-url",
  "--console-url",
  "--token-file",
  "--timeout-ms",
  "--environment",
  "--secret-id",
  "--secret-uid",
  "--consumer-id",
  "--fingerprint",
  "--cursor",
  "--input",
  "--if-match",
  "--idempotency-key",
]);

/** Index of a `pki` first positional token, allowing global flags before it; -1 if absent. */
function pkiTokenIndex(args: readonly string[]): number {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) return arg === "pki" ? index : -1;
    if (globalValueFlags.has(arg)) index += 1;
  }
  return -1;
}
