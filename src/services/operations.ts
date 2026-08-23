import type { APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import type { Application } from '../app';
import type { Actor } from '../domain/types';
import { newId } from '../util/encoding';

export const humanOperation = async (
    app: Application,
    actor: Actor,
    idempotencyKey: string,
    correlationId: string,
    operation: string,
    sourceIp: string,
    target: Readonly<Record<string, string>>,
    response: () => APIGatewayProxyStructuredResultV2,
): Promise<APIGatewayProxyStructuredResultV2> => {
    const eventId = newId();
    const auditEvent = await app.audit.write({
        eventId,
        correlationId,
        outcome: 'succeeded',
        actor,
        operation,
        target,
        sourceIp,
    });
    await app.repository.markAuditSucceeded(actor, idempotencyKey, auditEvent.eventId);
    return response();
};
