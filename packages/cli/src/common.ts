import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  FetchTransport,
  HemligError,
  type HemligTransport,
} from "@zyno-io/hemlig-client";
import {
  JWT_PATTERN,
  LoginError,
  jwtExpiry,
  parseHttpsOrigin,
  readCachedLogin,
  type CachedLogin,
} from "./login";
import { ConsumerProtocolError } from "./consumer";
import { EzError } from "./ez-error";

export interface CliDependencies {
  readonly env?: NodeJS.ProcessEnv;
  readonly stdin?: AsyncIterable<string | Uint8Array> & {
    readonly isTTY?: boolean;
    /** Present on a terminal; `hemlig login --no-localhost` reads the code in raw mode. */
    setRawMode?(mode: boolean): unknown;
    pause?(): unknown;
    resume?(): unknown;
  };
  readonly stdout?: (text: string) => void | Promise<void>;
  readonly stderr?: (text: string) => void | Promise<void>;
  /** Transport injection is for local tests; the executable always uses HTTPS fetch. */
  readonly transport?: HemligTransport;
  /** Browser launcher for `hemlig login`; defaults to open / xdg-open / cmd start. */
  readonly openBrowser?: (url: string) => void | Promise<void>;
  /** Directory holding the cached login token; defaults to the XDG/APPDATA hemlig directory. */
  readonly configDir?: string;
  /** Clock in epoch milliseconds, for token expiry checks. */
  readonly now?: () => number;
  /** Fetch used to read the console's /config.json during login; defaults to global fetch. */
  readonly fetch?: typeof fetch;
  /** Login wait limit; defaults to five minutes. */
  readonly loginTimeoutMs?: number;
  /**
   * `hemlig pki ez`: opens the controlling terminal for the typed `confirm` when stdin is a pipe (for example with
   * `--passphrase-stdin`). Defaults to `/dev/tty`; resolves to undefined when there is none.
   */
  /** `hemlig pki ez`: milliseconds after the confirm prompt during which keystrokes are discarded (default 300; tests use 0). */
  readonly confirmArmMs?: number;
  readonly openTerminal?: () => Promise<
    | (AsyncIterable<string | Uint8Array> & {
        readonly isTTY?: boolean;
        setRawMode?(mode: boolean): unknown;
        pause?(): unknown;
        destroy?(): unknown;
        iterator?(options: { destroyOnReturn: boolean }): AsyncIterator<string | Uint8Array>;
        unshift?(chunk: Buffer): unknown;
      })
    | undefined
  >;
}

export class CliError extends Error {
  constructor(
    readonly exitCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export function usage(message: string): never {
  throw new CliError(2, "invalid_input", message);
}

export function adminOrigin(value: string | undefined): URL {
  return httpsOrigin(
    value,
    "Supply --admin-url or HEMLIG_ADMIN_URL; no production endpoint is assumed.",
    "Administrator URL",
  );
}

export function httpsOrigin(
  value: string | undefined,
  missing: string,
  label: string,
  strictHost = false,
): URL {
  if (!value) usage(missing);
  try {
    new URL(value);
  } catch {
    return usage(`Invalid ${label.toLowerCase().replace(" url", "")} origin.`);
  }
  const url = parseHttpsOrigin(value, strictHost);
  if (url === undefined)
    return usage(
      `${label} must be an HTTPS origin (HTTP is allowed only on loopback)${strictHost ? ", with a plain hostname" : ""}.`,
    );
  return url;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function readText(
  source: AsyncIterable<string | Uint8Array>,
  limit: number,
  message: string,
): Promise<string> {
  return (await readBytes(source, limit, message)).toString("utf8");
}

export async function readBytes(
  source: AsyncIterable<string | Uint8Array>,
  limit: number,
  message: string,
): Promise<Buffer> {
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
  return Buffer.concat(chunks);
}

export interface SessionValues {
  readonly "admin-url"?: string;
  readonly "token-file"?: string;
}

/**
 * Reads the cached login when it is a candidate token source (no explicit token
 * source exists). An unusable cache is reported before a missing admin URL.
 */
export async function loadCachedLogin(
  values: SessionValues,
  env: NodeJS.ProcessEnv,
  configDir: string,
): Promise<CachedLogin | undefined> {
  const explicitToken =
    values["token-file"] !== undefined ||
    env.HEMLIG_ADMIN_TOKEN_FILE !== undefined ||
    env.HEMLIG_ADMIN_TOKEN !== undefined;
  if (explicitToken) return undefined;
  try {
    return await readCachedLogin(configDir);
  } catch (error) {
    throw error instanceof LoginError
      ? error
      : new CliError(9, "input_io_error", "Cannot read cached login.");
  }
}

export function resolveAdminOrigin(
  values: SessionValues,
  env: NodeJS.ProcessEnv,
  cachedLogin: CachedLogin | undefined,
): URL {
  return adminOrigin(
    values["admin-url"] ?? env.HEMLIG_ADMIN_URL ?? cachedLogin?.adminOrigin,
  );
}

export async function resolveAdminToken(
  values: SessionValues,
  env: NodeJS.ProcessEnv,
  cachedLogin: CachedLogin | undefined,
  origin: URL,
  now: () => number,
): Promise<string> {
  const tokenFile = values["token-file"] ?? env.HEMLIG_ADMIN_TOKEN_FILE;
  let tokenText =
    tokenFile === undefined
      ? env.HEMLIG_ADMIN_TOKEN
      : await readText(
          createReadStream(tokenFile),
          16384,
          "Cannot read administrator token file.",
        );
  let cached = false;
  if (tokenText === undefined) {
    if (cachedLogin !== undefined) {
      if (origin.origin !== cachedLogin.adminOrigin) {
        throw new CliError(
          3,
          "login_mismatch",
          `Cached login is for ${cachedLogin.adminOrigin}; run \`hemlig login\` for this API.`,
        );
      }
      tokenText = cachedLogin.token;
      cached = true;
    }
  }
  const token = tokenText?.trim();
  // Syntax screening is not token verification: API Gateway validates issuer, audience, scope and expiry.
  if (!token || !JWT_PATTERN.test(token)) {
    usage(
      "Supply an OIDC bearer JWT via --token-file, HEMLIG_ADMIN_TOKEN_FILE, HEMLIG_ADMIN_TOKEN, or `hemlig login`.",
    );
  }
  if (cached) {
    // Decoded without verification, only to fail fast with a useful message.
    const exp = jwtExpiry(token);
    if (exp !== undefined && exp * 1000 <= now()) {
      throw new CliError(
        3,
        "login_expired",
        "Login expired; run `hemlig login`.",
      );
    }
  }
  return token;
}

/** Administrator origin and bearer token, resolved in the CLI's usual order. */
export async function resolveAdminSession(
  values: SessionValues,
  env: NodeJS.ProcessEnv,
  deps: { readonly configDir: string; readonly now: () => number },
): Promise<{ origin: URL; token: string }> {
  const cachedLogin = await loadCachedLogin(values, env, deps.configDir);
  const origin = resolveAdminOrigin(values, env, cachedLogin);
  const token = await resolveAdminToken(
    values,
    env,
    cachedLogin,
    origin,
    deps.now,
  );
  return { origin, token };
}

export function parseTimeoutMs(text: string | undefined): number {
  const value = text ?? "30000";
  const timeoutMs = Number(value);
  if (!/^\d+$/.test(value) || timeoutMs < 1 || timeoutMs > 300000) {
    usage("--timeout-ms must be an integer from 1 to 300000.");
  }
  return timeoutMs;
}

export function resolveIdempotencyKey(value: string | undefined): string {
  const key = value ?? randomUUID();
  if (!/^[\x21-\x7e]{8,128}$/.test(key))
    usage(
      "--idempotency-key must be 8–128 printable, non-space ASCII characters.",
    );
  return key;
}

export function createTransport(
  dependencies: CliDependencies,
  timeoutMs: number,
): HemligTransport {
  return (
    dependencies.transport ??
    new FetchTransport((url, init) => {
      return globalThis.fetch(url, {
        ...init,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    })
  );
}

export interface Failure {
  exitCode: number;
  code: string;
  message: string;
  status?: number;
  apiCode?: string;
  apiDetails?: Readonly<Record<string, string | number | boolean>>;
  /** EZ library errors carry structured details (a lock holder, failed profile reasons, and so on). */
  details?: Readonly<Record<string, unknown>>;
}

export function classifyError(
  error: unknown,
  group: string | undefined,
): Failure {
  if (error instanceof LoginError)
    return {
      exitCode:
        error.code === "login_timeout"
          ? 8
          : error.code === "login_invalid"
            ? 3
            : error.code === "config_dir_unsafe" || error.code === "login_cancelled"
              ? 9
              : error.code === "config_fetch_failed"
                ? 8
                : ["invalid_code", "state_mismatch", "code_too_large"].includes(error.code)
                  ? 2
                  : 7,
      code: error.code,
      message: error.message,
    };
  if (error instanceof ConsumerProtocolError)
    return { exitCode: 7, code: "invalid_response", message: error.message };
  if (error instanceof EzError)
    return {
      exitCode: error.exitCode,
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    };
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
    const pki = group === "pki";
    // Never echo a remote error message: some API validation messages contain payload entry names.
    const failures: Record<number, [number, string, string]> = {
      400: [2, "bad_request", "Administrator API rejected the request."],
      401: [3, "unauthorized", "Administrator authentication failed."],
      403: [3, "forbidden", "Administrator authorization failed."],
      404: [
        4,
        "not_found",
        pki
          ? "CA, external CA, CRL, consumer, issuance grant or certificate was not found."
          : group === "consumer"
            ? "Consumer or API identity was not found."
            : "Secret or active payload was not found.",
      ],
      409: [
        5,
        "conflict",
        pki
          ? "The CA, grant, certificate or operation state conflicts with this request; see apiCode and apiDetails. No retry was made."
          : "Operation key was already used, or the resource is busy. No retry was made.",
      ],
      412: [
        6,
        "precondition_failed",
        pki
          ? "CA or grant version changed. Read the current resource and decide on a new operation."
          : "Control revision changed. Read the current metadata and decide on a new operation.",
      ],
    };
    const [exitCode, code, message] = failures[error.status] ?? [
      7,
      "service_error",
      "Administrator API failed. A mutation may already have completed; no retry was made.",
    ];
    return {
      exitCode,
      code,
      message,
      status: error.status,
      ...(pki && error.code !== undefined ? { apiCode: error.code } : {}),
      ...(pki && error.details !== undefined
        ? { apiDetails: error.details }
        : {}),
    };
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

export interface FailureContext {
  readonly group: string | undefined;
  readonly idempotencyKey?: string;
  readonly ifMatch?: string;
  readonly mutationAttempted: boolean;
  /** `hemlig pki ez`: what finished before the failure, so a rerun knows where it stands. */
  readonly ez?: {
    readonly completed: readonly string[];
    readonly files?: Readonly<Record<string, string>>;
    readonly rerun?: string;
  };
}

/** Writes the one-line JSON error envelope and returns the process exit code. */
export async function reportFailure(
  error: unknown,
  context: FailureContext,
  stderr: (text: string) => unknown,
): Promise<number> {
  const failure = classifyError(error, context.group);
  try {
    await stderr(
      `${JSON.stringify({
        error: {
          ...failure,
          ...(context.idempotencyKey === undefined
            ? {}
            : {
                outcome: !context.mutationAttempted
                  ? "not_sent"
                  : failure.exitCode >= 2 && failure.exitCode <= 6
                    ? "rejected"
                    : "unknown",
              }),
        },
        idempotencyKey: context.idempotencyKey,
        ifMatch: context.ifMatch,
        ...(context.ez === undefined ? {} : { ez: context.ez }),
      })}\n`,
    );
  } catch {
    // A closed stderr cannot carry an envelope, but must not produce an unhandled exception.
    return 9;
  }
  return failure.exitCode;
}
