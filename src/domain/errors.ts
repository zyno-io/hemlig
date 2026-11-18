import type { Actor } from './types';

export class ApiError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly safeReason?: string;

    public constructor(statusCode: number, code: string, message: string, safeReason?: string) {
        super(message);
        this.name = 'ApiError';
        this.statusCode = statusCode;
        this.code = code;
        this.safeReason = safeReason;
    }
}

export const badRequest = (message: string): ApiError => new ApiError(400, 'bad_request', message);

export const forbidden = (message = 'The caller is not permitted to perform this operation.'): ApiError =>
    new ApiError(403, 'forbidden', message);

/**
 * An identityNotActive rejection of a certificate that parsed. Carries the
 * attributable partial actor (fingerprint, and consumer/environment only when
 * the identity record exists) so the handler can audit it. Never holds PEM.
 */
export class IdentityRejectedError extends ApiError {
    public readonly actor: Actor;

    public constructor(actor: Actor, message: string) {
        super(403, 'identity_not_active', message);
        this.actor = actor;
    }
}

export const identityNotActive = (message = 'The client certificate is not an active consumer API identity.'): ApiError =>
    new ApiError(403, 'identity_not_active', message);

export const invalidCsr = (message: string): ApiError => new ApiError(400, 'invalid_csr', message);

export const identityLimitReached = (message: string): ApiError =>
    new ApiError(409, 'identity_limit_reached', message);

export const identityAlreadyRotated = (message: string): ApiError =>
    new ApiError(409, 'identity_already_rotated', message);

export const identityRotationConflict = (message: string): ApiError =>
    new ApiError(409, 'identity_rotation_conflict', message);

export const rotationReplayInactive = (message: string): ApiError =>
    new ApiError(409, 'rotation_replay_inactive', message);

export const notFound = (message = 'The requested resource was not found.'): ApiError =>
    new ApiError(404, 'not_found', message);

export const conflict = (message: string): ApiError => new ApiError(409, 'conflict', message);

export const enrollmentFailed = (message: string): ApiError =>
    new ApiError(409, 'enrollment_failed', message);

export const preconditionFailed = (message: string): ApiError =>
    new ApiError(412, 'precondition_failed', message);

export const serviceUnavailable = (message: string): ApiError =>
    new ApiError(503, 'service_unavailable', message);
