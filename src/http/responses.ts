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
        return json(error.statusCode, {
            error: { code: error.code, message: error.message, correlationId },
        });
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
