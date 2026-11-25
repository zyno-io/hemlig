import { randomBytes } from "node:crypto";
import { constants, promises as fs } from "node:fs";
import { basename, dirname, join } from "node:path";
import { EzError } from "./ez-error";

/** Crash-safe file primitives. `fault` lets tests throw between the steps of a write. */
export interface FsFaults {
  readonly fault?: (step: string) => void | Promise<void>;
}

const fsyncDirectory = async (directory: string): Promise<void> => {
  let handle: fs.FileHandle | undefined;
  try {
    handle = await fs.open(directory, constants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Windows cannot fsync a directory; some filesystems refuse it.
    if (code !== "EISDIR" && code !== "EPERM" && code !== "EINVAL" && code !== "ENOTSUP" && code !== "EACCES") throw error;
  } finally {
    await handle?.close();
  }
};

const tempName = (path: string): string => join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);

const writeTemp = async (path: string, data: Uint8Array, mode: number): Promise<string> => {
  const temp = tempName(path);
  const handle = await fs.open(temp, "wx", mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await fs.unlink(temp).catch(() => undefined);
    throw error;
  }
  await handle.close();
  return temp;
};

/** Replaces `path` atomically: temp file with `wx`, fsync, rename, fsync of the directory. */
export const writeAtomic = async (path: string, data: Uint8Array, mode = 0o600, hooks: FsFaults = {}): Promise<void> => {
  const temp = await writeTemp(path, data, mode);
  try {
    await hooks.fault?.("atomic:temp-written");
    await fs.rename(temp, path);
  } catch (error) {
    await fs.unlink(temp).catch(() => undefined);
    throw error;
  }
  await hooks.fault?.("atomic:renamed");
  await fsyncDirectory(dirname(path));
};

/**
 * Creates `path` only if it does not exist: temp file, then `link` (which fails with EEXIST instead of clobbering),
 * then unlink of the temp. Where hard links are unsupported (FAT/exFAT), falls back to `open(path, "wx")`.
 */
export const createImmutable = async (path: string, data: Uint8Array, mode = 0o600, hooks: FsFaults = {}): Promise<void> => {
  const temp = await writeTemp(path, data, mode);
  try {
    await hooks.fault?.("immutable:temp-written");
    try {
      await fs.link(temp, path);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EEXIST") throw new EzError(5, "already_exists", `${path} already exists; nothing was overwritten.`);
      if (code !== "EPERM" && code !== "ENOTSUP" && code !== "EXDEV" && code !== "ENOSYS" && code !== "EOPNOTSUPP") throw error;
      let handle: fs.FileHandle;
      try {
        handle = await fs.open(path, "wx", mode);
      } catch (inner) {
        if ((inner as NodeJS.ErrnoException).code === "EEXIST") {
          throw new EzError(5, "already_exists", `${path} already exists; nothing was overwritten.`);
        }
        throw inner;
      }
      try {
        await handle.writeFile(data);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
  } finally {
    await fs.unlink(temp).catch(() => undefined);
  }
  await hooks.fault?.("immutable:linked");
  await fsyncDirectory(dirname(path));
};

export const readIfExists = async (path: string): Promise<Buffer | undefined> => {
  try {
    return await fs.readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
};

export const exists = async (path: string): Promise<boolean> => {
  try {
    await fs.lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------------------------------------------------

export const LOCK_FILE = ".hemlig-ez.lock";

export interface LockInfo {
  readonly pid: number;
  readonly hostname: string;
  readonly command: string;
  readonly startedAt: string;
  readonly nonce: string;
}

export interface LockOptions {
  readonly command: string;
  readonly hostname: string;
  readonly pid?: number;
  readonly now?: () => Date;
  /** Remove a lock whose holder is on this host and no longer running. */
  readonly breakStale?: boolean;
  /** Test seam; defaults to `process.kill(pid, 0)` returning false on ESRCH. */
  readonly isAlive?: (pid: number) => boolean;
}

export interface LockHandle {
  readonly info: LockInfo;
  release(): Promise<void>;
}

const processAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
};

const GUARD_FILE = `${LOCK_FILE}.break`;

const readHolder = async (path: string): Promise<Partial<LockInfo>> => {
  try {
    return JSON.parse((await fs.readFile(path)).toString("utf8")) as Partial<LockInfo>;
  } catch {
    return {};
  }
};

/**
 * `open(wx)` lock held for the whole command, network calls included. Local disks and removable media only. Breaking
 * a stale lock is serialized by a second `wx` guard file and re-checks the holder's nonce under the guard, so two
 * breakers (or a breaker and a fresh acquirer) can never both end up holding the lock.
 */
export const acquireLock = async (directory: string, options: LockOptions): Promise<LockHandle> => {
  const path = join(directory, LOCK_FILE);
  const info: LockInfo = {
    pid: options.pid ?? process.pid,
    hostname: options.hostname,
    command: options.command,
    startedAt: (options.now?.() ?? new Date()).toISOString(),
    nonce: randomBytes(16).toString("hex"),
  };
  const create = async (): Promise<void> => {
    const handle = await fs.open(path, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify(info));
      await handle.sync();
    } finally {
      await handle.close();
    }
  };
  const locked = (holder: Partial<LockInfo>): EzError =>
    new EzError(5, "state_locked", "Another hemlig pki ez command holds the lock on this directory.", { holder });
  try {
    await create();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const holder = await readHolder(path);
    const stale = (h: Partial<LockInfo>): boolean =>
      options.breakStale === true &&
      h.hostname === options.hostname &&
      typeof h.pid === "number" &&
      typeof h.nonce === "string" &&
      !(options.isAlive ?? processAlive)(h.pid);
    if (!stale(holder)) throw locked(holder);
    const guardPath = join(directory, GUARD_FILE);
    let guard: fs.FileHandle;
    try {
      guard = await fs.open(guardPath, "wx", 0o600);
    } catch (guardError) {
      if ((guardError as NodeJS.ErrnoException).code === "EEXIST") throw locked(holder);
      throw guardError;
    }
    try {
      const again = await readHolder(path);
      // Still the same dead holder? Otherwise someone else has taken (or re-created) the lock.
      if (again.nonce !== holder.nonce || !stale(again)) throw locked(again);
      await fs.unlink(path);
      try {
        await create();
      } catch (createError) {
        if ((createError as NodeJS.ErrnoException).code === "EEXIST") throw locked(await readHolder(path));
        throw createError;
      }
    } finally {
      await guard.close();
      await fs.unlink(guardPath).catch(() => undefined);
    }
  }
  return {
    info,
    release: async () => {
      const current = await readHolder(path);
      if (current.nonce === info.nonce) await fs.unlink(path).catch(() => undefined);
    },
  };
};
