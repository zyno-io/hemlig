import type { Handler } from "aws-lambda";
import { isoNow } from "../util/encoding";
import { getApplication } from "./shared";

export const handler: Handler = async (): Promise<void> => {
  const app = getApplication();
  const expired = await app.repository.listExpiredPrepared(isoNow());
  const byOperation = new Map<string, typeof expired>();
  for (const workflow of expired) {
    const group = byOperation.get(workflow.operationId) ?? [];
    group.push(workflow);
    byOperation.set(workflow.operationId, group);
  }
  for (const [operationId, workflows] of byOperation) {
    const workflow = workflows[0];
    if (workflow === undefined) {
      continue;
    }
    if (workflow.workflowKind === "consumer.enrollment") {
      try {
        const result = await app.consumers.resume(operationId);
        const enrollment = await app.repository.getEnrollment(operationId);
        if (enrollment !== undefined) {
          const idempotency = await app.repository.getIdempotency(
            enrollment.actor,
            enrollment.idempotencyKey,
          );
          if (idempotency?.status !== "SUCCEEDED") {
            const auditEvent = await app.audit.write({
              correlationId: operationId,
              outcome: "succeeded",
              actor: enrollment.actor,
              operation: enrollment.operationType,
              target: {
                consumerId: result.consumerId,
                rootFingerprint: result.rootFingerprint,
                apiFingerprint: result.apiFingerprint,
              },
            });
            await app.repository.markAuditSucceeded(
              enrollment.actor,
              enrollment.idempotencyKey,
              auditEvent.eventId,
            );
          }
        }
      } catch {
        await app.audit.write({
          correlationId: operationId,
          outcome: "failed",
          actor: { type: "system", id: "recovery" },
          operation: "consumer.enrollment.recovery",
          target: { operationId },
          reasonCode: "truststore_publication_pending",
        });
      }
      continue;
    }
    const retryResults = await Promise.all(
      workflows.map((item) => app.repository.markRetryable(item)),
    );
    if (!retryResults.some(Boolean)) {
      continue;
    }
    const secretId = workflow.pk.slice("SECRET#".length);
    const abortedCreate = await app.repository.abortPreparedCreate(
      secretId,
      operationId,
    );
    if (!abortedCreate) {
      const releasedLease = await app.repository.releaseLease(
        secretId,
        operationId,
      );
      if (!releasedLease) {
        continue;
      }
    }
    await app.audit.write({
      correlationId: operationId,
      outcome: "failed",
      actor: { type: "system", id: "recovery" },
      operation: "workflow.recovery",
      target: { secretId },
      reasonCode: "prepared_workflow_expired",
    });
  }
  // The delivery custom domain is replaceable (for example, when a deployment
  // moves from an old delivery subdomain to api.<zone>). Its truststore setting is not a
  // CloudFormation property, so reconcile the current immutable bundle after
  // normal recovery work. This is a no-op before enrollment and in steady state.
  await app.consumers.reconcileTruststore();
};
