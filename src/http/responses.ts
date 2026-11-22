import type { APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { ApiError } from '../domain/errors';

export const json = (statusCode: number, body: unknown, headers: Record<string, string> = {}): APIGatewayProxyStructuredResultV2 => ({
    statusCode,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
    body: JSON.stringify(body),
});

export const empty = (statusCode: number, headers: Record<string, string> = {}): APIGatewayProxyStructuredResultV2 => ({
    statusCode,
    headers: { 'cache-control': 'no-store', ...headers },
});

export const errorResponse = (error: unknown, correlationId: string): APIGatewayProxyStructuredResultV2 => {
    if (error instanceof ApiError) {
        // An error may add headers such as Retry-After but never override the content type or caching.
        const headers = Object.fromEntries(
            Object.entries(error.headers ?? {}).filter(
                ([name]) => !['content-type', 'cache-control'].includes(name.toLowerCase()),
            ),
        );
        return json(
            error.statusCode,
            {
                error: {
                    code: error.code,
                    message: error.message,
                    correlationId,
                    ...(error.details === undefined ? {} : { details: error.details }),
                },
            },
            headers,
        );
    }
    return json(500, {
        error: { code: 'internal_error', message: 'The request could not be completed.', correlationId },
    });
};

export const parseJsonBody = (body: string | undefined): unknown => {
    if (body === undefined || body.length === 0) {
        return {};
    }
    return JSON.parse(body) as unknown;
};
