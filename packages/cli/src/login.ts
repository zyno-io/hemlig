import { randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";

/** Same syntax screen the CLI applies to every bearer token; not verification. */
export const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const MAX_BODY_BYTES = 16 * 1024;
export const DEFAULT_LOGIN_TIMEOUT_MS = 5 * 60 * 1000;

export class LoginError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Directory holding the cached token: $XDG_CONFIG_HOME/hemlig, ~/.config/hemlig, or %APPDATA%\hemlig. */
export function defaultConfigDir(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform === "win32") {
    return join(env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "hemlig");
  }
  return join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "hemlig");
}

export const tokenCachePath = (configDir: string): string =>
  join(configDir, "admin-token");

/** Decodes the JWT `exp` (seconds) without verifying the token. */
export function jwtExpiry(token: string): number | undefined {
  const payload = token.split(".")[1];
  if (payload === undefined) return undefined;
  try {
    const claims: unknown = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    );
    const exp = (claims as { exp?: unknown } | null)?.exp;
    return typeof exp === "number" && Number.isFinite(exp) ? exp : undefined;
  } catch {
    return undefined;
  }
}

export async function readCachedToken(
  configDir: string,
): Promise<string | undefined> {
  try {
    return (await readFile(tokenCachePath(configDir), "utf8")).trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/** Atomic write: temp file in the same directory, then rename. */
export async function writeCachedToken(
  configDir: string,
  token: string,
): Promise<void> {
  await mkdir(configDir, { recursive: true, mode: 0o700 });
  const path = tokenCachePath(configDir);
  const temp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    await writeFile(temp, `${token}\n`, { mode: 0o600, flag: "wx" });
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

export async function removeCachedToken(configDir: string): Promise<void> {
  await rm(tokenCachePath(configDir), { force: true });
}

/** Default opener; failures are non-fatal because the URL is always printed. */
export function openInBrowser(
  url: string,
  platform: NodeJS.Platform = process.platform,
): void {
  const [command, args]: [string, string[]] =
    platform === "darwin"
      ? ["open", [url]]
      : platform === "win32"
        ? ["cmd", ["/c", "start", '""', url]]
        : ["xdg-open", [url]];
  const child = spawn(command, args, { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}

export interface LoginOptions {
  /** Exact console origin, e.g. https://console.example.com. */
  readonly consoleOrigin: URL;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly open: ((url: string) => void | Promise<void>) | undefined;
  readonly announce: (url: string) => void | Promise<void>;
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function reply(
  response: ServerResponse,
  status: number,
  body: string,
  extra: Record<string, string> = {},
): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": "default-src 'none'",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extra,
    connection: "close",
  });
  response.end(body);
}

async function readBody(request: IncomingMessage): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_BODY_BYTES) return undefined;
    chunks.push(bytes);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Listens on 127.0.0.1 for one valid POST /callback from the console's
 * /cli-login page and resolves with the access token. Anything else is
 * rejected and the wait continues until the timeout.
 */
export async function loginViaConsole(
  options: LoginOptions,
): Promise<{ token: string; expiresAt: Date }> {
  const state = randomBytes(32).toString("base64url");
  const expectedOrigin = options.consoleOrigin.origin;

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const server = createServer(async (request, response) => {
      try {
        const path = (request.url ?? "").split("?")[0];
        if (request.method !== "POST" || path !== "/callback") {
          return reply(response, 404, "Not found");
        }
        // Origin is only a coarse filter. Browsers serialise it as `null` (or omit
        // it) for a cross-origin form POST under several referrer policies, so an
        // exact match would be fragile. Absent, `null` or the console origin pass;
        // any other origin is refused. The real authenticator is `state`: a
        // 256-bit nonce known only to this process and the URL it opened.
        const origin = request.headers.origin;
        if (
          origin !== undefined &&
          origin !== "null" &&
          origin !== expectedOrigin
        ) {
          return reply(response, 403, "Forbidden");
        }
        const body = await readBody(request);
        if (body === undefined) {
          return reply(response, 400, "Request too large");
        }
        const form = new URLSearchParams(body);
        const presentedState = form.get("state");
        const token = form.get("access_token")?.trim();
        if (presentedState === null || !constantTimeEqual(presentedState, state)) {
          return reply(response, 403, "Forbidden");
        }
        if (!token || !JWT_PATTERN.test(token)) {
          return reply(response, 400, "Invalid token");
        }
        const exp = jwtExpiry(token);
        if (exp === undefined || exp * 1000 <= options.now()) {
          return reply(response, 400, "Token is expired or has no expiry");
        }
        reply(
          response,
          200,
          "<!doctype html><title>Hemlig CLI</title><p>Hemlig CLI signed in. You can close this tab.</p>",
        );
        finish(() => resolve({ token, expiresAt: new Date(exp * 1000) }), false);
      } catch {
        if (!response.headersSent) reply(response, 400, "Bad request");
      }
    });

    const finish = (settle: () => void, force = true): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      server.close();
      // The success page is sent with `connection: close`; let it flush.
      if (force) server.closeAllConnections();
      else server.closeIdleConnections();
      settle();
    };

    server.on("error", (error) => {
      finish(() => reject(error));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      const url = new URL("/cli-login", options.consoleOrigin);
      url.searchParams.set("port", String(port));
      url.searchParams.set("state", state);
      timer = setTimeout(
        () =>
          finish(() =>
            reject(
              new LoginError(
                "login_timeout",
                "Timed out waiting for browser authorization. Run `hemlig login` again.",
              ),
            ),
          ),
        options.timeoutMs,
      );
      void (async () => {
        try {
          await options.announce(url.toString());
          await options.open?.(url.toString());
        } catch {
          // The URL has been printed; a failed opener must not abort the wait.
        }
      })();
    });
  });
}
