import type { PkiServiceDeps } from "./service-types";

const cursorLifetimeMs = 15 * 60 * 1000;

/** Decodes an optional cursor under `scope`, fetches one page and encodes the next cursor. */
export const pageWithCursor = async <T>(
  deps: Pick<PkiServiceDeps, "cursors" | "now">,
  scope: string,
  rawCursor: string | undefined,
  fetch: (start?: Record<string, unknown>) => Promise<{
    items: T[];
    lastEvaluatedKey?: Record<string, unknown>;
  }>,
): Promise<{ items: T[]; nextCursor?: string }> => {
  const decoded =
    rawCursor === undefined
      ? undefined
      : await deps.cursors.decode(rawCursor, scope, deps.now());
  const result = await fetch(decoded?.lastEvaluatedKey);
  const nextCursor =
    result.lastEvaluatedKey === undefined
      ? undefined
      : await deps.cursors.encode({
          scope,
          lastEvaluatedKey: result.lastEvaluatedKey as Record<string, string>,
          expiresAt: new Date(
            deps.now().getTime() + cursorLifetimeMs,
          ).toISOString(),
        });
  return {
    items: result.items,
    ...(nextCursor === undefined ? {} : { nextCursor }),
  };
};
