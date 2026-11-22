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
