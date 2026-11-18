import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";

/** Same syntax screen the CLI applies to every bearer token; not verification. */
export const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Parses an HTTPS origin (HTTP only on loopback). Rejects userinfo, any path
 * other than `/`, a query and a fragment. With `strictHost`, the hostname is
 * also limited to [A-Za-z0-9.-] so it can never carry shell or URL syntax.
 */
export function parseHttpsOrigin(
  value: string,
  strictHost = false,
): URL | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
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
    return undefined;
  if (strictHost && !/^[A-Za-z0-9.-]+$/.test(url.hostname)) return undefined;
  return url;
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Short confirmation code shown by both the CLI and the console so an operator
 * can tell a link they started from one a third party crafted. SHA-256 of the
 * state string, first 5 bytes, Crockford base32, formatted XXXX-XXXX. The
 * console implements the same function with crypto.subtle.
 */
export function confirmationCode(state: string): string {
  const bytes = createHash("sha256").update(state, "utf8").digest().subarray(0, 5);
  let bits = 0n;
  for (const byte of bytes) bits = (bits << 8n) | BigInt(byte);
  let out = "";
  for (let i = 7; i >= 0; i--) out += CROCKFORD[Number((bits >> BigInt(i * 5)) & 31n)];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

const DONE_PAGE =
  "<!doctype html><title>Hemlig CLI</title><p>Hemlig CLI signed in. You can close this tab.</p>";

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

export interface CachedLogin {
  readonly version: 1;
  readonly token: string;
  readonly consoleOrigin: string;
  readonly adminOrigin: string;
}

/** Returns undefined when no login is cached; throws LoginError when the file is unusable. */
export async function readCachedLogin(
  configDir: string,
): Promise<CachedLogin | undefined> {
  let text: string;
  try {
    text = await readFile(tokenCachePath(configDir), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const bad = new LoginError(
    "login_invalid",
    "Cached login is unreadable; run `hemlig login`.",
  );
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw bad;
  }
  const v = value as Partial<Record<string, unknown>> | null;
  if (
    typeof v !== "object" ||
    v === null ||
    v.version !== 1 ||
    typeof v.token !== "string" ||
    !JWT_PATTERN.test(v.token) ||
    typeof v.consoleOrigin !== "string" ||
    typeof v.adminOrigin !== "string" ||
    parseHttpsOrigin(v.consoleOrigin)?.origin !== v.consoleOrigin ||
    parseHttpsOrigin(v.adminOrigin)?.origin !== v.adminOrigin
  )
    throw bad;
  return v as unknown as CachedLogin;
}

/** Creates the directory privately, refusing a symlink or another user's directory. */
async function ensurePrivateDir(configDir: string): Promise<void> {
  await mkdir(configDir, { recursive: true, mode: 0o700 });
  const info = await lstat(configDir);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new LoginError(
      "config_dir_unsafe",
      "The CLI config directory is a symlink or not a directory; refusing to store a token there.",
    );
  }
  if (process.platform !== "win32") {
    if (info.uid !== process.getuid!()) {
      throw new LoginError(
        "config_dir_unsafe",
        "The CLI config directory is owned by another user; refusing to store a token there.",
      );
    }
    await chmod(configDir, 0o700);
  }
}

/** Atomic write: temp file in the same directory, then rename. */
export async function writeCachedLogin(
  configDir: string,
  login: Omit<CachedLogin, "version">,
): Promise<void> {
  await ensurePrivateDir(configDir);
  const path = tokenCachePath(configDir);
  const temp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    await writeFile(
      temp,
      `${JSON.stringify({ version: 1, ...login })}\n`,
      { mode: 0o600, flag: "wx" },
    );
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

export async function removeCachedToken(configDir: string): Promise<void> {
  await rm(tokenCachePath(configDir), { force: true });
}

/**
 * Opener argv per platform. Never a shell: the URL contains `&`, which cmd.exe
 * would treat as a command separator, so Windows uses rundll32 directly.
 */
export function browserCommand(
  url: string,
  platform: NodeJS.Platform = process.platform,
): [string, string[]] {
  if (platform === "darwin") return ["open", [url]];
  if (platform === "win32")
    return ["rundll32", ["url.dll,FileProtocolHandler", url]];
  return ["xdg-open", [url]];
}

/** Default opener; failures are non-fatal because the URL is always printed. */
export function openInBrowser(
  url: string,
  platform: NodeJS.Platform = process.platform,
  spawnImpl: typeof spawn = spawn,
): void {
  const [command, args] = browserCommand(url, platform);
  const child = spawnImpl(command, args, {
    stdio: "ignore",
    detached: true,
    shell: false,
  });
  child.on("error", () => {});
  child.unref();
}

const MAX_CONFIG_BYTES = 16 * 1024;
const CONFIG_TIMEOUT_MS = 10_000;

/**
 * Reads the admin API origin from the console's published runtime config
 * (`<console>/config.json`, field `adminApiUrl`) over the console's own HTTPS
 * origin. It is never taken from the POST: whoever can reach the loopback port
 * must not be able to choose where later commands send the token.
 */
export async function fetchAdminOrigin(
  consoleOrigin: URL,
  fetchImpl: typeof fetch,
): Promise<string> {
  let text: string;
  try {
    const response = await fetchImpl(new URL("/config.json", consoleOrigin), {
      redirect: "error",
      signal: AbortSignal.timeout(CONFIG_TIMEOUT_MS),
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of response.body ?? []) {
      length += chunk.byteLength;
      if (length > MAX_CONFIG_BYTES) throw new Error("too large");
      chunks.push(Buffer.from(chunk));
    }
    text = Buffer.concat(chunks).toString("utf8");
  } catch {
    throw new LoginError(
      "config_fetch_failed",
      "Could not read the console's /config.json; no login was saved.",
    );
  }
  let adminApiUrl: unknown;
  try {
    adminApiUrl = (JSON.parse(text) as { adminApiUrl?: unknown }).adminApiUrl;
  } catch {
    adminApiUrl = undefined;
  }
  const admin =
    typeof adminApiUrl === "string" ? parseHttpsOrigin(adminApiUrl) : undefined;
  // HTTP is for local development only: the console itself must be on HTTP too.
  if (
    admin === undefined ||
    (admin.protocol === "http:" && consoleOrigin.protocol !== "http:")
  ) {
    throw new LoginError(
      "config_invalid",
      "The console's /config.json has no valid adminApiUrl; no login was saved.",
    );
  }
  return admin.origin;
}

export interface LoginOptions {
  /** Exact console origin, e.g. https://console.example.com. */
  readonly consoleOrigin: URL;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly open: ((url: string) => void | Promise<void>) | undefined;
  readonly fetch: typeof fetch;
  readonly announce: (url: string, code: string) => void | Promise<void>;
  /** How long to keep serving /done after the POST before closing anyway. */
  readonly doneGraceMs?: number;
}

export interface LoginResult {
  readonly token: string;
  readonly expiresAt: Date;
  readonly adminOrigin: string;
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
 * rejected and the wait continues until the timeout. A valid POST is answered
 * with a 303 to GET /done; the server closes once that page has been sent.
 */
export async function loginViaConsole(
  options: LoginOptions,
): Promise<LoginResult> {
  const state = randomBytes(32).toString("base64url");
  const expectedOrigin = options.consoleOrigin.origin;

  return new Promise((resolve, reject) => {
    let settled = false;
    // Claimed synchronously by the first valid POST; later ones are refused.
    let claimed = false;
    let accepted: LoginResult | undefined;
    let timer: NodeJS.Timeout | undefined;
    const server = createServer(async (request, response) => {
      try {
        const path = (request.url ?? "").split("?")[0];
        if (claimed) {
          // Token already received: serve only the post-redirect page, then close.
          if (accepted !== undefined && request.method === "GET" && path === "/done") {
            response.once("finish", () => finish(() => resolve(accepted!), false));
            return reply(response, 200, DONE_PAGE);
          }
          return reply(response, request.method === "POST" ? 409 : 404, "Not found");
        }
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
        // The first valid POST wins. A slower earlier POST re-checks here, after
        // its body was read, and no await separates this check from the claim.
        if (claimed) return reply(response, 409, "Already completed");
        claimed = true;
        let adminOrigin: string;
        try {
          adminOrigin = await fetchAdminOrigin(options.consoleOrigin, options.fetch);
        } catch (error) {
          reply(response, 502, "Could not read the console configuration");
          return finish(() => reject(error));
        }
        if (settled) return reply(response, 503, "Login timed out");
        accepted = {
          token,
          expiresAt: new Date(exp * 1000),
          adminOrigin,
        };
        // 303 to a GET page so reloading the tab cannot re-send the token. The
        // listener stays up for that GET, with a grace timer in case the browser
        // never follows the redirect.
        if (timer) clearTimeout(timer);
        timer = setTimeout(
          () => finish(() => resolve(accepted!), true),
          options.doneGraceMs ?? 5000,
        );
        reply(response, 303, "", { location: "/done" });
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
          await options.announce(url.toString(), confirmationCode(state));
          await options.open?.(url.toString());
        } catch {
          // The URL has been printed; a failed opener must not abort the wait.
        }
      })();
    });
  });
}
