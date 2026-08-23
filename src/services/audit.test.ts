import type { AppConfig } from "../aws/config";
import type { ObjectStore } from "../repositories/object-store";
import { AuditQueryService, AuditWriter, parseAuditDate } from "./audit";

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
  iotEndpoint: "iot.example.test",
  iotNotificationPolicyName: "test-agent-notifications",
  iotNotificationTopicPrefix: "hemlig/test/consumers",
  cursorHmacKey: Buffer.alloc(32, 1),
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "hemlig",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

describe("audit archive", () => {
  it("writes a newest-first daily object key", async () => {
    const objects = { putImmutable: jest.fn().mockResolvedValue({}) };
    const writer = new AuditWriter(objects as unknown as ObjectStore, config);

    await writer.write({
      eventId: "event-1",
      at: "2026-08-23T10:11:12.000Z",
      correlationId: "corr-1",
      outcome: "succeeded",
      actor: { type: "human", id: "admin-1" },
      operation: "adminget:/v1/admin/audit",
    });

    const key = (objects.putImmutable as jest.Mock).mock
      .calls[0]?.[1] as string;
    expect(key).toMatch(/^audit\/2026\/08\/23\/\d{13}-event-1\.json$/);
  });

  it("reads and orders one bounded, immutable archive page", async () => {
    const objects = {
      listKeys: jest.fn().mockResolvedValue({
        keys: ["audit/2026/08/23/first.json", "audit/2026/08/23/second.json"],
        nextContinuationToken: "next-token",
      }),
      getJson: jest
        .fn()
        .mockResolvedValueOnce({
          eventId: "old",
          at: "2026-08-23T09:00:00.000Z",
          correlationId: "corr-old",
          outcome: "succeeded",
          actor: { type: "human", id: "admin-1" },
          operation: "adminget:/v1/admin/secrets",
        })
        .mockResolvedValueOnce({
          eventId: "new",
          at: "2026-08-23T10:00:00.000Z",
          correlationId: "corr-new",
          outcome: "failed",
          actor: { type: "human", id: "admin-2" },
          operation: "adminput:/v1/admin/secrets/payments-api",
        }),
    };
    const query = new AuditQueryService(
      objects as unknown as ObjectStore,
      config,
    );

    const page = await query.list("2026-08-23", "previous-token");

    expect(objects.listKeys).toHaveBeenCalledWith(
      "audit",
      "audit/2026/08/23/",
      "previous-token",
      50,
    );
    expect(page.events.map((event) => event.eventId)).toEqual(["new", "old"]);
    expect(page.nextContinuationToken).toBe("next-token");
  });

  it("accepts only real UTC calendar dates", () => {
    expect(parseAuditDate("2026-08-23")).toBe("2026-08-23");
    expect(() => parseAuditDate("2026-02-30")).toThrow(
      "real UTC calendar date",
    );
  });
});
