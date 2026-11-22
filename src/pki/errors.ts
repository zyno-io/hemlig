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

export const issuanceDenied = (reason: string, message?: string): ApiError =>
  new ApiError(
    403,
    "issuance_denied",
    message ?? `Issuance denied (${reason}).`,
    reason,
    { details: { reason } },
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
