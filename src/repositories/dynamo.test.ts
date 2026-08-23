import { QueryCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../aws/config";
import { DynamoRepository } from "./dynamo";

const config: AppConfig = {
  region: "us-east-1",
  environmentName: "test",
  controlTableName: "control",
  workflowDueIndex: "workflow-due",
  retentionDueIndex: "retention-due",
  catalogPathIndex: "catalog-path",
  consumerDirectoryIndex: "consumer-directory",
  consumerIdentityIndex: "consumer-identity",
  secretRevisionIndex: "secret-revision",
  revisionBucketName: "revisions",
  truststoreBucketName: "truststores",
  truststoreKeyPrefix: "truststores",
  payloadKmsKeyArn: "arn:aws:kms:us-east-1:111122223333:key/test",
  auditBucketName: "audit",
  auditPrefix: "audit",
    deliveryApiCustomDomainName: "api.example.test",
    deliveryApiHostname: "api.example.test",
  cursorHmacKey: Buffer.alloc(32, 1),
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "hemlig",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

describe("console management indexes", () => {
  it("queries the environment-scoped consumer directory", async () => {
    const dynamo = { send: jest.fn().mockResolvedValue({ Items: [] }) } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.listConsumers("prod");

    const command = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "consumer-directory",
      KeyConditionExpression: "consumerDirectoryPk = :directory",
      ExpressionAttributeValues: { ":directory": "CONSUMERS#prod" },
      Limit: 100,
    });
  });

  it("returns newest-first revision history and marks an extra record as truncated", async () => {
    const revisions = Array.from({ length: 501 }, (_, index) => ({
      pk: "SECRET#payments-api",
      sk: `CONTROL#ctl-${index}`,
      workflowState: "READY",
      serialized: {
        schemaVersion: 1,
        secretId: "payments-api",
        controlVersionId: `ctl-${index}`,
        environment: "prod",
        state: "ACTIVE",
        createdAt: "2026-08-22T00:00:00.000Z",
        createdBy: { type: "human", id: "admin" },
        metadata: { name: "payments-api" },
        acl: [],
      },
    }));
    const dynamo = { send: jest.fn().mockResolvedValue({ Items: revisions }) } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listRecentControlRevisions("payments-api");

    const command = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "secret-revision",
      KeyConditionExpression: "revisionPk = :secret",
      ExpressionAttributeValues: { ":secret": "SECRET#payments-api" },
      Limit: 501,
      ScanIndexForward: false,
    });
    expect(page.revisions).toHaveLength(500);
    expect(page.truncated).toBe(true);
  });
});
