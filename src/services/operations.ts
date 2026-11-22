import type { APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import type { Actor } from '../domain/types';
import type { DynamoRepository } from '../repositories/dynamo';
import type { AuditWriter } from './audit';
import { newId } from '../util/encoding';

/** The slice of the application `humanOperation` uses, so the PKI Lambdas can call it without the generic app. */
export interface HumanOperationApplication {
    readonly audit: Pick<AuditWriter, 'write'>;
    readonly repository: Pick<DynamoRepository, 'markAuditSucceeded'>;
}

export const humanOperation = async (
    app: HumanOperationApplication,
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
