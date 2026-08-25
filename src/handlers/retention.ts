import type { Handler } from "aws-lambda";
import type { HeadRecord, ObjectReference } from "../domain/types";
import { secretIdentityFromPk } from "../repositories/dynamo";
import { getApplication } from "./shared";

export const handler: Handler = async (): Promise<void> => {
  const app = getApplication();
  const workflows = await app.repository.listReadyWorkflows();
  for (const workflow of workflows) {
    if (workflow.s3VersionId === undefined) {
      continue;
    }
    const identity = secretIdentityFromPk(workflow.pk);
    if (identity === undefined) {
      continue;
    }
    const head = await app.repository.getHeadBySecretUid(identity.secretUid);
    const serialized = workflow.serialized as
      | { readonly environment?: unknown; readonly secretId?: unknown }
      | undefined;
    const environment =
      head?.environment ??
      (typeof serialized?.environment === "string"
        ? serialized.environment
        : undefined);
    const secretId =
      head?.secretId ??
      (typeof serialized?.secretId === "string"
        ? serialized.secretId
        : undefined);
    if (environment === undefined || secretId === undefined) {
      continue;
    }
    if (isCurrent(workflow.sk, head)) {
      continue;
    }
    const reference: ObjectReference = {
      bucket: app.config.revisionBucketName,
      key: workflow.objectKey,
      versionId: workflow.s3VersionId,
      checksumSha256: workflow.checksumSha256,
    };
    const canDelete = await app.objects.canDeleteVersion(reference);
    if (canDelete) {
      await app.objects.deleteVersion(reference);
      await app.repository.markRetentionDeleted(workflow);
      await app.audit.write({
        correlationId: workflow.operationId,
        outcome: "succeeded",
        actor: { type: "system", id: "retention" },
        operation: "revision.retention.delete",
        target: { environment, secretId, workflow: workflow.sk },
      });
    }
  }
};

const isCurrent = (sk: string, head: HeadRecord | undefined): boolean => {
  if (head === undefined) {
    return false;
  }
  return (
    sk === `CONTROL#${head.controlVersionId}` ||
    (head.payloadVersionId !== undefined &&
      sk === `PAYLOAD#${head.payloadVersionId}`)
  );
};
