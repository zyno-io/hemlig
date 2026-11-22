import { ApiError } from "../domain/errors";

/**
 * PKI errors carry the plan's `details.reason` as `safeReason` until `ApiError` gains `details`. Messages never
 * contain key, CSR or certificate material.
 */
export const chainInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "chain_invalid",
    message ?? `The certificate chain is invalid (${reason}).`,
    reason,
  );

export const crlInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "crl_invalid",
    message ?? `The CRL is invalid (${reason}).`,
    reason,
  );

export const issuanceDenied = (reason: string, message?: string): ApiError =>
  new ApiError(
    403,
    "issuance_denied",
    message ?? `Issuance denied (${reason}).`,
    reason,
  );

export const csrInvalid = (reason: string, message?: string): ApiError =>
  new ApiError(
    400,
    "invalid_csr",
    message ?? `The certificate request is invalid (${reason}).`,
    reason,
  );
