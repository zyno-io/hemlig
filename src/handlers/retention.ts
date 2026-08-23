import type { Handler } from 'aws-lambda';
import type { HeadRecord, ObjectReference } from '../domain/types';
import { getApplication } from './shared';

export const handler: Handler = async (): Promise<void> => {
    const app = getApplication();
    const workflows = await app.repository.listReadyWorkflows();
    for (const workflow of workflows) {
        if (workflow.s3VersionId === undefined) {
            continue;
        }
        const secretId = workflow.pk.slice('SECRET#'.length);
        const head = await app.repository.getHead(secretId);
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
                outcome: 'succeeded',
                actor: { type: 'system', id: 'retention' },
                operation: 'revision.retention.delete',
                target: { secretId, workflow: workflow.sk },
            });
        }
    }
};

const isCurrent = (sk: string, head: HeadRecord | undefined): boolean => {
    if (head === undefined) {
        return false;
    }
    return sk === `CONTROL#${head.controlVersionId}` ||
        (head.payloadVersionId !== undefined && sk === `PAYLOAD#${head.payloadVersionId}`);
};
