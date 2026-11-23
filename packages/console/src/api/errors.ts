import { z } from "zod";

/**
 * Codes are the enum published in openapi/consumer-secrets.yaml. `unauthorized`
 * is synthetic: API Gateway rejects a bad token before the Lambda runs and
 * returns a bare 401 with no envelope, so there is no server-sent code to read.
 */
export type ApiErrorCode =
  | "unauthorized"
  | "bad_request"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "enrollment_failed"
  | "precondition_failed"
  | "internal_error"
  | "service_unavailable"
  | "network"
  // PKI administration and issuance (openapi 0.8.0).
  | "ca_not_active"
  | "ca_subject_in_use"
  | "ca_issuance_budget_exceeded"
  | "ca_key_unavailable"
  | "ca_capacity_exceeded"
  | "chain_invalid"
  | "crl_invalid"
  | "crl_not_newer"
  | "issuance_denied"
  | "issuance_rate_limited"
  | "issuance_revoked"
  | "issuance_expired"
  | "issuance_grant_not_found"
  | "issuance_grant_inactive";

const envelope = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    correlationId: z.string(),
    details: z
      .record(z.union([z.string(), z.number(), z.boolean()]))
      .optional(),
  }),
});

export class ApiError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: ApiErrorCode,
    message: string,
    public readonly correlationId?: string,
    /** Underlying transport failure, when there is no server response. */
    public readonly cause?: unknown,
    /** Machine-readable detail from the envelope, such as `reason`. */
    public readonly details?: Readonly<Record<string, string | number | boolean>>,
    public readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** `details.reason`, the stable sub-code PKI errors carry. */
  public get reason(): string | undefined {
    const value = this.details?.reason;
    return typeof value === "string" ? value : undefined;
  }

  /** Transport detail for a `network` failure, which has no correlation ID. */
  public get transportDetail(): string | undefined {
    if (this.cause === undefined) {
      return undefined;
    }
    return this.cause instanceof Error
      ? `${this.cause.name}: ${this.cause.message}`
      : String(this.cause);
  }

  /**
   * True when the request may or may not have been applied. The caller must
   * re-read and compare rather than retrying: administrator secret mutations
   * hard-conflict on a reused idempotency key and never replay a result.
   */
  public get outcomeUnknown(): boolean {
    return (
      this.code === "network" ||
      this.code === "internal_error" ||
      this.code === "service_unavailable"
    );
  }

  /** True when re-authenticating could plausibly help. */
  public get requiresSignIn(): boolean {
    return this.code === "unauthorized";
  }
}

export const errorFromResponse = async (response: Response): Promise<ApiError> => {
  if (response.status === 401) {
    return new ApiError(
      401,
      "unauthorized",
      "The identity provider token was rejected before the request reached Hemlig.",
    );
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  const parsed = envelope.safeParse(body);
  if (!parsed.success) {
    return new ApiError(
      response.status,
      response.status >= 500 ? "internal_error" : "bad_request",
      `The request failed with status ${response.status}.`,
    );
  }
  const { code, message, correlationId, details } = parsed.data.error;
  return new ApiError(
    response.status,
    code as ApiErrorCode,
    message,
    correlationId,
    undefined,
    details,
    retryAfter(response.headers.get("retry-after"), details),
  );
};

/** The `retry-after` header wins over `details.retryAfterSeconds`. */
const retryAfter = (
  header: string | null,
  details: Readonly<Record<string, string | number | boolean>> | undefined,
): number | undefined => {
  const fromHeader = header === null || header.trim() === "" ? Number.NaN : Number(header);
  if (Number.isFinite(fromHeader) && fromHeader >= 0) {
    return fromHeader;
  }
  const raw = details?.retryAfterSeconds;
  const fromDetails = typeof raw === "number" ? raw : Number.NaN;
  return Number.isFinite(fromDetails) && fromDetails >= 0 ? fromDetails : undefined;
};
