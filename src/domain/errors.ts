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

export const notFound = (message = 'The requested resource was not found.'): ApiError =>
    new ApiError(404, 'not_found', message);

export const conflict = (message: string): ApiError => new ApiError(409, 'conflict', message);

export const enrollmentFailed = (message: string): ApiError =>
    new ApiError(409, 'enrollment_failed', message);

export const preconditionFailed = (message: string): ApiError =>
    new ApiError(412, 'precondition_failed', message);

export const serviceUnavailable = (message: string): ApiError =>
    new ApiError(503, 'service_unavailable', message);
