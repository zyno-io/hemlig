import { ApiError } from "../domain/errors";

/**
 * PKI errors carry the plan's `details.reason`, also recorded as the audit `safeReason`. Messages never contain key,
 * CSR or certificate material.
 */
export const chainInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "chain_invalid",
    message ?? `The certificate chain is invalid (${reason}).`,
    reason,
    { details: { reason } },
  );

export const crlInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "crl_invalid",
    message ?? `The CRL is invalid (${reason}).`,
    reason,
    { details: { reason } },
  );

export interface DeniedNameDetails {
  readonly type: string;
  readonly value: string;
}

const uriLike = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * A URI without userinfo, query or fragment (`scheme://host[:port]/path`), since those can carry credentials. A value
 * that does not parse is omitted.
 */
const redactUri = (value: string): string | undefined => {
  try {
    const url = new URL(value);
    return `${url.protocol}${url.host === "" ? "" : `//${url.host}`}${url.pathname}`;
  } catch {
    return undefined;
  }
};

/**
 * The denied name for an error or audit target. Caller text is dropped when it could carry key material or control
 * characters: anything with `-----` or outside printable ASCII. A URI loses its userinfo, query and fragment.
 */
export const deniedNameFields = (
  denied: DeniedNameDetails,
): { deniedNameType: string; deniedName: string } | Record<string, never> => {
  if (denied.value.includes("-----") || /[^\x20-\x7e]/.test(denied.value)) {
    return {};
  }
  let value = denied.value;
  if (denied.type === "uri" || uriLike.test(value)) {
    const redacted = redactUri(value);
    if (redacted === undefined || /[^\x20-\x7e]/.test(redacted)) {
      return {};
    }
    value = redacted;
  }
  return { deniedNameType: denied.type, deniedName: value.slice(0, 253) };
};

export const issuanceDenied = (
  reason: string,
  message?: string,
  denied?: DeniedNameDetails,
): ApiError =>
  new ApiError(
    403,
    "issuance_denied",
    message ?? `Issuance denied (${reason}).`,
    reason,
    {
      details: {
        reason,
        ...(denied === undefined ? {} : deniedNameFields(denied)),
      },
    },
  );

export const csrInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "invalid_csr",
    message ?? `The certificate request is invalid (${reason}).`,
    reason,
    { details: { reason } },
  );

export const caKeyUnavailable = (): ApiError =>
  new ApiError(
    409,
    "ca_key_unavailable",
    "The CA key is unavailable.",
    "ca_key_unavailable",
  );

const reasoned = (
  statusCode: number,
  code: string,
  reason: string,
  message: string,
  headers?: Record<string, string>,
): ApiError =>
  new ApiError(statusCode, code, message, reason, {
    details: { reason },
    ...(headers === undefined ? {} : { headers }),
  });

export const caNotActive = (reason: string): ApiError =>
  reasoned(409, "ca_not_active", reason, `The CA is not active (${reason}).`);

export const caSubjectInUse = (reason: string): ApiError =>
  reasoned(
    409,
    "ca_subject_in_use",
    reason,
    `The CA subject is already in use (${reason}).`,
  );

export const crlNotNewer = (): ApiError =>
  reasoned(
    409,
    "crl_not_newer",
    "crl_not_newer",
    "The uploaded CRL is not newer than the stored one.",
  );

export const caIssuanceBudgetExceeded = (): ApiError =>
  reasoned(
    409,
    "ca_issuance_budget_exceeded",
    "ca_issuance_budget_exceeded",
    "capacity + 2 x issuancePerHour must not exceed 12000.",
  );

export const pkiConflict = (reason: string): ApiError =>
  reasoned(409, "conflict", reason, `The request conflicts (${reason}).`);

export const pkiBadRequest = (reason: string, message: string): ApiError =>
  reasoned(400, "bad_request", reason, message);

export const pkiNotFound = (reason: string): ApiError =>
  reasoned(404, "not_found", reason, "The requested resource was not found.");

export const pkiRoleRequired = (role: string): ApiError =>
  new ApiError(
    403,
    "forbidden",
    "The administrator role for this PKI operation is required.",
    "pki_role_required",
    { details: { reason: "pki_role_required", role } },
  );

export const crlPublicationBusy = (): ApiError =>
  reasoned(
    503,
    "service_unavailable",
    "crl_publication_busy",
    "A CRL publication is already in progress.",
    { "retry-after": "30" },
  );

export const issuanceGrantNotFound = (): ApiError =>
  reasoned(
    404,
    "issuance_grant_not_found",
    "grant_not_found",
    "The issuance grant was not found.",
  );

export const issuanceGrantInactive = (
  reason: "grant_disabled" | "grant_expired",
): ApiError =>
  reasoned(
    403,
    "issuance_grant_inactive",
    reason,
    `The issuance grant is not active (${reason}).`,
  );

export const caCapacityExceeded = (): ApiError =>
  reasoned(
    409,
    "ca_capacity_exceeded",
    "ca_capacity_exceeded",
    "The CA has reached its certificate capacity.",
  );

export const issuanceRevoked = (
  reason: "certificate_revoked" | "ca_revoked" | "ancestor_revoked",
): ApiError =>
  reasoned(
    409,
    "issuance_revoked",
    reason,
    `The issued certificate is no longer valid (${reason}).`,
  );

export const issuanceExpired = (
  reason: "result_expiring" | "inventory_expired" | "issuance_expired",
): ApiError =>
  reasoned(
    409,
    "issuance_expired",
    reason,
    `The certificate is too close to expiry (${reason}).`,
  );

export type RateLimitReason =
  "grant_hour" | "grant_day" | "admin_hour" | "ca_hour";

export const issuanceRateLimited = (
  reason: RateLimitReason,
  retryAfterSeconds: number,
): ApiError =>
  new ApiError(
    429,
    "issuance_rate_limited",
    `The issuance rate limit was reached (${reason}).`,
    reason,
    {
      details: { reason, retryAfterSeconds },
      headers: { "retry-after": String(retryAfterSeconds) },
    },
  );

export const agentGrantInactive = (): ApiError =>
  new ApiError(
    403,
    "identity_not_active",
    "The agent grant is not active.",
    "agent_grant_inactive",
    { details: { reason: "agent_grant_inactive" } },
  );

export const idempotencyKeyReused = (): ApiError =>
  reasoned(
    409,
    "conflict",
    "idempotency_key_reused",
    "This idempotency key has already been used for a different request.",
  );

export const grantInvalid = (
  first: { code: string; path: string; message: string },
  count: number,
): ApiError =>
  new ApiError(
    400,
    "bad_request",
    `The grant policy is invalid (${first.code} at ${first.path}).`,
    first.code === "policy_too_large"
      ? "policy_too_large"
      : "invalid_grant_policy",
    {
      details: {
        reason:
          first.code === "policy_too_large"
            ? "policy_too_large"
            : "invalid_grant_policy",
        code: first.code,
        path: first.path,
        errorCount: count,
      },
    },
  );
