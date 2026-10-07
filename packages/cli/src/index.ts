import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { parseArgs } from "node:util";
import {
  FetchTransport,
  HemligClient,
  HemligError,
  type ControlRevision,
  type HemligTransport,
  type SecretPayload,
} from "@hemlig/client";

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
  usage: "hemlig secret <command> [options] | hemlig idempotency-key",
  commands,
  options: {
    "--admin-url": "Administrator origin; defaults to HEMLIG_ADMIN_URL.",
    "--environment": "Logical environment; defaults to HEMLIG_ENVIRONMENT.",
    "--token-file":
      "OIDC bearer token file; defaults to HEMLIG_ADMIN_TOKEN_FILE, otherwise HEMLIG_ADMIN_TOKEN.",
    "--secret-id": "Reusable secret ID for active records.",
    "--secret-uid": "Immutable UID for archived records (read only).",
    "--input":
      "JSON file, or - for stdin. Required for create, update, write-payload.",
    "--if-match":
      "Known controlVersionId/strong ETag, or current to fetch it once. Required for update, write-payload, archive.",
    "--idempotency-key":
      "Durable operation key; defaults to a newly minted UUID for each mutation.",
    "--timeout-ms":
      "Per-request timeout (1–300000 milliseconds); default 30000.",
  },
  output:
    "One JSON receipt on stdout; one JSON error on stderr. No prompts or automatic retries.",
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

export interface CliDependencies {
  readonly env?: NodeJS.ProcessEnv;
  readonly stdin?: AsyncIterable<string | Uint8Array> & {
    readonly isTTY?: boolean;
  };
  readonly stdout?: (text: string) => void | Promise<void>;
  readonly stderr?: (text: string) => void | Promise<void>;
  /** Transport injection is for local tests; the executable always uses HTTPS fetch. */
  readonly transport?: HemligTransport;
}

class CliError extends Error {
  constructor(
    readonly exitCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function usage(message: string): never {
  throw new CliError(2, "invalid_input", message);
}

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
  let idempotencyKey: string | undefined;
  let ifMatch: string | undefined;
  let mutationAttempted = false;
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
          environment: { type: "string" },
          "token-file": { type: "string" },
          "secret-id": { type: "string" },
          "secret-uid": { type: "string" },
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
    const candidate = parsed.positionals[1];
    if (
      parsed.positionals.length !== 2 ||
      parsed.positionals[0] !== "secret" ||
      !commands.includes(candidate as Command)
    )
      usage("Expected hemlig secret <command>. Run hemlig --help.");
    const command = candidate as Command;
    const mutation = ["create", "update", "write-payload", "archive"].includes(
      command,
    );
    const needsInput = ["create", "update", "write-payload"].includes(command);
    const needsMatch = mutation && command !== "create";
    const allowed = new Set([
      "admin-url",
      "environment",
      "token-file",
      "timeout-ms",
      "secret-id",
    ]);
    if (command === "read") allowed.add("secret-uid");
    if (mutation) allowed.add("idempotency-key");
    if (needsInput) allowed.add("input");
    if (needsMatch) allowed.add("if-match");
    for (const name of seen) {
      if (!allowed.has(name))
        usage("An option is not supported by this command.");
    }
    const values = parsed.values;
    const origin = adminOrigin(values["admin-url"] ?? env.HEMLIG_ADMIN_URL);
    const environment = values.environment ?? env.HEMLIG_ENVIRONMENT;
    if (!environment || !/^[a-z][a-z0-9-]{0,63}$/.test(environment)) {
      usage("Supply a valid logical --environment or HEMLIG_ENVIRONMENT.");
    }
    const secretId = values["secret-id"];
    const secretUid = values["secret-uid"];
    if (secretUid !== undefined) {
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
    const timeoutText = values["timeout-ms"] ?? "30000";
    const timeoutMs = Number(timeoutText);
    if (!/^\d+$/.test(timeoutText) || timeoutMs < 1 || timeoutMs > 300000) {
      usage("--timeout-ms must be an integer from 1 to 300000.");
    }
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
    const tokenFile = values["token-file"] ?? env.HEMLIG_ADMIN_TOKEN_FILE;
    const tokenText =
      tokenFile === undefined
        ? env.HEMLIG_ADMIN_TOKEN
        : await readText(
            createReadStream(tokenFile),
            16384,
            "Cannot read administrator token file.",
          );
    const token = tokenText?.trim();
    // Syntax screening is not token verification: API Gateway validates issuer, audience, scope and expiry.
    if (
      !token ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
    ) {
      usage(
        "Supply an OIDC bearer JWT via --token-file, HEMLIG_ADMIN_TOKEN_FILE, or HEMLIG_ADMIN_TOKEN.",
      );
    }
    if (mutation) {
      const key = values["idempotency-key"] ?? randomUUID();
      if (!/^[\x21-\x7e]{8,128}$/.test(key))
        usage(
          "--idempotency-key must be 8–128 printable, non-space ASCII characters.",
        );
      idempotencyKey = key;
    }
    const transport =
      dependencies.transport ??
      new FetchTransport((url, init) => {
        return globalThis.fetch(url, {
          ...init,
          redirect: "error",
          signal: AbortSignal.timeout(timeoutMs),
        });
      });
    const client = new HemligClient(origin, transport);
    if (needsMatch && values["if-match"] === "current") {
      const current = await client.getAdminSecret(
        token,
        environment,
        secretId!,
      );
      ifMatch = responseVersion(current);
    }
    let data:
      | ControlRevision
      | Awaited<ReturnType<HemligClient["getAdminSecretPayload"]>>;
    switch (command) {
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
    const failure = classifyError(error);
    try {
      await stderr(
        `${JSON.stringify({
          error: {
            ...failure,
            ...(idempotencyKey === undefined
              ? {}
              : {
                  outcome: !mutationAttempted
                    ? "not_sent"
                    : failure.exitCode >= 2 && failure.exitCode <= 6
                      ? "rejected"
                      : "unknown",
                }),
          },
          idempotencyKey,
          ifMatch,
        })}\n`,
      );
    } catch {
      // A closed stderr cannot carry an envelope, but must not produce an unhandled exception.
      return 9;
    }
    return failure.exitCode;
  }
}

function adminOrigin(value: string | undefined): URL {
  if (!value)
    usage(
      "Supply --admin-url or HEMLIG_ADMIN_URL; no production endpoint is assumed.",
    );
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return usage("Invalid administrator origin.");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && local)) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    usage(
      "Administrator URL must be an HTTPS origin (HTTP is allowed only on loopback).",
    );
  return url;
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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

async function readText(
  source: AsyncIterable<string | Uint8Array>,
  limit: number,
  message: string,
): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    for await (const chunk of source) {
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > limit) usage("Input exceeds the supported byte limit.");
      chunks.push(bytes);
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(9, "input_io_error", message);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function classifyError(error: unknown): {
  exitCode: number;
  code: string;
  message: string;
  status?: number;
} {
  if (error instanceof CliError)
    return {
      exitCode: error.exitCode,
      code: error.code,
      message: error.message,
    };
  if (
    isObject(error) &&
    ["EPIPE", "EBADF", "EIO", "ENOSPC"].includes(String(error.code))
  ) {
    return {
      exitCode: 9,
      code: "output_io_error",
      message: "Cannot write CLI output.",
    };
  }
  if (error instanceof HemligError) {
    // Never echo a remote error message: some API validation messages contain payload entry names.
    const failures: Record<number, [number, string, string]> = {
      400: [2, "bad_request", "Administrator API rejected the request."],
      401: [3, "unauthorized", "Administrator authentication failed."],
      403: [3, "forbidden", "Administrator authorization failed."],
      404: [4, "not_found", "Secret or active payload was not found."],
      409: [
        5,
        "conflict",
        "Operation key was already used, or the resource is busy. No retry was made.",
      ],
      412: [
        6,
        "precondition_failed",
        "Control revision changed. Read the current metadata and decide on a new operation.",
      ],
    };
    const [exitCode, code, message] = failures[error.status] ?? [
      7,
      "service_error",
      "Administrator API failed. A mutation may already have completed; no retry was made.",
    ];
    return { exitCode, code, message, status: error.status };
  }
  if (
    error instanceof TypeError ||
    (error instanceof Error &&
      ["AbortError", "TimeoutError"].includes(error.name))
  ) {
    return {
      exitCode: 8,
      code: "transport_error",
      message:
        "Network or timeout failure. A mutation may already have completed; no retry was made.",
    };
  }
  return {
    exitCode: 7,
    code: "internal_error",
    message: "CLI failed. No automatic retry was made.",
  };
}
