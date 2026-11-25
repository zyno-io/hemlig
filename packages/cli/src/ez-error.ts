/**
 * Error type of the EZ library. Standalone on purpose: it must not import `common.ts` (which pulls in the client
 * package), so the library can be loaded from the server's jest suite without a build. The EZ commands map it onto
 * the CLI's `{exitCode, code, message}` envelope.
 */
export class EzError extends Error {
  public constructor(
    public readonly exitCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "EzError";
  }
}

export function ezFail(
  exitCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
): never {
  throw new EzError(exitCode, code, message, details);
}
