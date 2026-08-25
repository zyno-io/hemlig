import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../aws/config";
import {
  catalogSk,
  DynamoRepository,
  type CompletedMutation,
  type PreparedMutation,
} from "./dynamo";

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
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "hemlig",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

describe("opaque cursor storage", () => {
  const cursor = {
    token: "A".repeat(43),
    scope: "admin:actor:scope",
    lastEvaluatedKey: { pk: "SECRET#payments-api", sk: "HEAD" },
    expiresAt: "2026-08-23T00:15:00.000Z",
    ttl: 1_787_438_500,
  };

  it("stores bounded cursor state with a collision guard", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(repository.createCursor(cursor)).resolves.toBe(true);

    const command = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as PutCommand;
    expect(command.input).toEqual({
      TableName: "control",
      Item: {
        pk: `CURSOR#${cursor.token}`,
        sk: "STATE",
        scope: cursor.scope,
        lastEvaluatedKey: cursor.lastEvaluatedKey,
        expiresAt: cursor.expiresAt,
        ttl: cursor.ttl,
      },
      ConditionExpression: "attribute_not_exists(pk)",
    });
  });

  it("treats a token collision as retryable and decodes only valid stored state", async () => {
    const collision = new Error("conditional write failed");
    collision.name = "ConditionalCheckFailedException";
    const dynamo = {
      send: jest
        .fn()
        .mockRejectedValueOnce(collision)
        .mockResolvedValueOnce({
          Item: {
            pk: `CURSOR#${cursor.token}`,
            sk: "STATE",
            scope: cursor.scope,
            lastEvaluatedKey: cursor.lastEvaluatedKey,
            expiresAt: cursor.expiresAt,
            ttl: cursor.ttl,
          },
        }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(repository.createCursor(cursor)).resolves.toBe(false);
    await expect(repository.getCursor(cursor.token)).resolves.toEqual(cursor);

    const command = (dynamo.send as jest.Mock).mock.calls[1]?.[0] as GetCommand;
    expect(command.input).toEqual({
      TableName: "control",
      Key: { pk: `CURSOR#${cursor.token}`, sk: "STATE" },
      ConsistentRead: true,
    });
  });
});

describe("secret ID catalog index", () => {
  it("keys every secret under its parent ID path", () => {
    expect(catalogSk("payments/stripe/api-key")).toBe(
      "PATH#payments/stripe/SECRET#payments/stripe/api-key",
    );
    expect(catalogSk("root-secret")).toBe("PATH#_/SECRET#root-secret");
  });
});

describe("consumer secret grants", () => {
  it("lists only live ACL rows and refreshes their current control version", async () => {
    const dynamo = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Items: [
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#sec-live",
              consumerId: "prod-east",
              secretUid: "sec-live",
              secretId: "platform/database/postgres",
              environment: "prod",
              permissions: ["read"],
              controlVersionId: "ctl-prior",
              state: "ACTIVE",
              changeKind: "secret.changed",
            },
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#sec-revoked",
              consumerId: "prod-east",
              secretUid: "sec-revoked",
              secretId: "platform/database/retired",
              environment: "prod",
              permissions: [],
              controlVersionId: "ctl-retired",
              state: "REVOKED",
              changeKind: "secret.revoked",
            },
          ],
          LastEvaluatedKey: { pk: "CONSUMER#prod-east", sk: "next" },
        })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET#sec-live",
            sk: "HEAD",
            secretUid: "sec-live",
            secretId: "platform/database/postgres",
            environment: "prod",
            controlVersionId: "ctl-current",
            state: "ACTIVE",
          },
        }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(
      repository.listConsumerSecretGrants("prod-east", "prod"),
    ).resolves.toEqual({
      grants: [
        {
          secretUid: "sec-live",
          secretId: "platform/database/postgres",
          permissions: ["read"],
          controlVersionId: "ctl-current",
          state: "ACTIVE",
        },
      ],
      nextCursor: JSON.stringify({ pk: "CONSUMER#prod-east", sk: "next" }),
    });

    const query = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as QueryCommand;
    expect(query.input).toMatchObject({
      TableName: "control",
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: {
        ":pk": "CONSUMER#prod-east",
        ":prefix": "SECRET#prod#",
      },
      Limit: 100,
      ConsistentRead: true,
    });
  });
});

describe("notification outbox", () => {
  it("aliases the ttl attribute when marking a notification delivered", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(repository.markNotificationDelivered("event-1")).resolves.toBe(
      true,
    );

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as UpdateCommand;
    expect(command.input).toMatchObject({
      TableName: "control",
      Key: { pk: "NOTIFICATION#event-1", sk: "EVENT" },
      UpdateExpression:
        "SET #status = :delivered, deliveredAt = :deliveredAt, #ttl = :ttl",
      ConditionExpression: "#status = :pending",
      ExpressionAttributeNames: { "#status": "status", "#ttl": "ttl" },
    });
  });
});

describe("console management indexes", () => {
  it("uses separate records for the same secret ID in different environments", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const mutation = (environment: string): PreparedMutation => ({
      operationId: `op-${environment}`,
      idempotencyKey: `create-${environment}`,
      actor: { type: "human", id: "admin-1" },
      requestDigest: `digest-${environment}`,
      secretId: "shared-secret",
      secretUid: `sec-${environment}`,
      environment,
      control: {
        schemaVersion: 1,
        secretUid: `sec-${environment}`,
        secretId: "shared-secret",
        controlVersionId: `ctl-${environment}`,
        environment,
        state: "PENDING_VALUE",
        createdAt: "2026-08-24T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
        metadata: {},
        acl: [],
      },
      controlKey: `secrets/sec-${environment}/control.json`,
      controlChecksumSha256: "checksum",
      controlBytes: Buffer.from("control"),
      expiresAt: "2026-08-24T00:10:00.000Z",
    });

    await repository.prepareMutation(mutation("dev"));
    await repository.prepareMutation(mutation("prod"));

    const heads = (dynamo.send as jest.Mock).mock.calls.map(([command]) => {
      const transaction = command as TransactWriteCommand;
      const items = transaction.input.TransactItems ?? [];
      return items
        .flatMap((item) =>
          item.Put?.Item === undefined ? [] : [item.Put.Item],
        )
        .find((item) => item.sk === "HEAD");
    });
    expect(heads).toEqual([
      expect.objectContaining({ pk: "SECRET#sec-dev" }),
      expect.objectContaining({ pk: "SECRET#sec-prod" }),
    ]);
    const lookups = (dynamo.send as jest.Mock).mock.calls.map(([command]) => {
      const transaction = command as TransactWriteCommand;
      const items = transaction.input.TransactItems ?? [];
      return items
        .flatMap((item) =>
          item.Put?.Item === undefined ? [] : [item.Put.Item],
        )
        .find((item) => item.sk === "LOOKUP");
    });
    expect(lookups).toEqual([
      expect.objectContaining({
        pk: "SECRET_NAME#dev#shared-secret",
        secretUid: "sec-dev",
      }),
      expect.objectContaining({
        pk: "SECRET_NAME#prod#shared-secret",
        secretUid: "sec-prod",
      }),
    ]);
  });

  it("does not rewrite unchanged consumer grants for a payload-only mutation", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const control = {
      schemaVersion: 1 as const,
      secretUid: "sec-payments",
      secretId: "payments-api",
      controlVersionId: "ctl-next",
      payloadVersionId: "pay-next",
      payloadKeyCount: 1,
      environment: "prod",
      state: "ACTIVE" as const,
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human" as const, id: "admin-1" },
      metadata: {},
      acl: [
        { consumerId: "prod-east", permissions: ["read"] as const },
        { consumerId: "prod-west", permissions: ["read"] as const },
      ],
    };
    const priorAccess = control.acl.map((grant) => ({
      pk: `CONSUMER#${grant.consumerId}`,
      sk: "SECRET#prod#sec-payments",
      consumerId: grant.consumerId,
      secretUid: "sec-payments",
      secretId: "payments-api",
      environment: "prod",
      permissions: ["read"] as const,
      controlVersionId: "ctl-prior",
      payloadVersionId: "pay-prior",
      state: "ACTIVE" as const,
      changeKind: "secret.changed" as const,
    }));
    const completed: CompletedMutation = {
      prepared: {
        operationId: "op-1",
        idempotencyKey: "payload-update-key",
        actor: { type: "human", id: "admin-1" },
        requestDigest: "digest",
        secretId: control.secretId,
        secretUid: "sec-payments",
        environment: control.environment,
        expectedControlVersionId: "ctl-prior",
        control,
        controlKey: "controls/payments-api/ctl-next.json",
        controlChecksumSha256: "checksum-control",
        controlBytes: Buffer.from("control"),
        payload: {
          revision: {
            schemaVersion: 1,
            secretUid: "sec-payments",
            secretId: control.secretId,
            payloadVersionId: "pay-next",
            environment: control.environment,
            createdAt: control.createdAt,
            createdBy: control.createdBy,
            payload: {
              algorithm: "AES-256-GCM",
              encryptedDataKey: "key",
              iv: "iv",
              tag: "tag",
              ciphertext: "ciphertext",
            },
          },
          key: "payloads/payments-api/pay-next.json",
          checksumSha256: "checksum-payload",
          bytes: Buffer.from("payload"),
        },
        expiresAt: "2026-08-23T00:10:00.000Z",
      },
      controlObject: {
        bucket: "revisions",
        key: "controls/payments-api/ctl-next.json",
        versionId: "control-version",
        checksumSha256: "checksum-control",
      },
      payloadObject: {
        bucket: "revisions",
        key: "payloads/payments-api/pay-next.json",
        versionId: "payload-version",
        checksumSha256: "checksum-payload",
      },
      priorHead: {
        pk: "SECRET#sec-payments",
        sk: "HEAD",
        secretUid: "sec-payments",
        secretId: "payments-api",
        environment: "prod",
        controlVersionId: "ctl-prior",
        payloadVersionId: "pay-prior",
        state: "ACTIVE",
      },
      priorAccess,
    };

    await repository.completeMutation(completed);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    const items = command.input.TransactItems ?? [];
    const putItems = items.flatMap((item) =>
      item.Put?.Item === undefined ? [] : [item.Put.Item],
    );
    expect(putItems).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pk: "CONSUMER#prod-east" }),
        expect.objectContaining({ pk: "CONSUMER#prod-west" }),
      ]),
    );
    expect(putItems).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          pk: expect.stringMatching(/^NOTIFICATION#/),
          consumerIds: ["prod-east", "prod-west"],
          kind: "secret.changed",
          controlVersionId: "ctl-next",
          payloadVersionId: "pay-next",
        }),
      ]),
    );
  });

  it("atomically replaces a full ACL and emits grouped grant and revocation hints", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const revokedConsumerIds = Array.from(
      { length: 40 },
      (_, index) => `old-${index}`,
    );
    const grantedConsumerIds = Array.from(
      { length: 40 },
      (_, index) => `new-${index}`,
    );
    const control = {
      schemaVersion: 1 as const,
      secretUid: "sec-payments",
      secretId: "payments-api",
      controlVersionId: "ctl-next",
      payloadVersionId: "pay-next",
      payloadKeyCount: 1,
      environment: "prod",
      state: "ACTIVE" as const,
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human" as const, id: "admin-1" },
      metadata: {},
      acl: grantedConsumerIds.map((consumerId) => ({
        consumerId,
        permissions: ["read"] as const,
      })),
    };
    const completed: CompletedMutation = {
      prepared: {
        operationId: "op-2",
        idempotencyKey: "acl-replacement-key",
        actor: { type: "human", id: "admin-1" },
        requestDigest: "digest",
        secretId: control.secretId,
        secretUid: "sec-payments",
        environment: control.environment,
        expectedControlVersionId: "ctl-prior",
        control,
        controlKey: "controls/payments-api/ctl-next.json",
        controlChecksumSha256: "checksum-control",
        controlBytes: Buffer.from("control"),
        payload: {
          revision: {
            schemaVersion: 1,
            secretUid: "sec-payments",
            secretId: control.secretId,
            payloadVersionId: "pay-next",
            environment: control.environment,
            createdAt: control.createdAt,
            createdBy: control.createdBy,
            payload: {
              algorithm: "AES-256-GCM",
              encryptedDataKey: "key",
              iv: "iv",
              tag: "tag",
              ciphertext: "ciphertext",
            },
          },
          key: "payloads/payments-api/pay-next.json",
          checksumSha256: "checksum-payload",
          bytes: Buffer.from("payload"),
        },
        expiresAt: "2026-08-23T00:10:00.000Z",
      },
      controlObject: {
        bucket: "revisions",
        key: "controls/payments-api/ctl-next.json",
        versionId: "control-version",
        checksumSha256: "checksum-control",
      },
      payloadObject: {
        bucket: "revisions",
        key: "payloads/payments-api/pay-next.json",
        versionId: "payload-version",
        checksumSha256: "checksum-payload",
      },
      priorHead: {
        pk: "SECRET#sec-payments",
        sk: "HEAD",
        secretUid: "sec-payments",
        secretId: "payments-api",
        environment: "prod",
        controlVersionId: "ctl-prior",
        payloadVersionId: "pay-prior",
        state: "ACTIVE",
      },
      priorAccess: revokedConsumerIds.map((consumerId) => ({
        pk: `CONSUMER#${consumerId}`,
        sk: "SECRET#prod#sec-payments",
        consumerId,
        secretUid: "sec-payments",
        secretId: "payments-api",
        environment: "prod",
        permissions: ["read"] as const,
        controlVersionId: "ctl-prior",
        payloadVersionId: "pay-prior",
        state: "ACTIVE" as const,
        changeKind: "secret.changed" as const,
      })),
    };

    await repository.completeMutation(completed);

    expect(dynamo.send).toHaveBeenCalledTimes(1);
    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    const items = command.input.TransactItems ?? [];
    const putItems = items.flatMap((item) =>
      item.Put?.Item === undefined ? [] : [item.Put.Item],
    );
    const accessItems = putItems.filter((item) =>
      String(item.pk).startsWith("CONSUMER#"),
    );
    const notifications = putItems.filter((item) =>
      String(item.pk).startsWith("NOTIFICATION#"),
    );

    expect(items).toHaveLength(87);
    expect(accessItems).toHaveLength(80);
    expect(accessItems).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          consumerId: grantedConsumerIds[0],
          permissions: ["read"],
          state: "ACTIVE",
          controlVersionId: "ctl-next",
          payloadVersionId: "pay-next",
        }),
        expect.objectContaining({
          consumerId: revokedConsumerIds[0],
          permissions: [],
          state: "REVOKED",
          controlVersionId: "ctl-next",
          payloadVersionId: "pay-next",
        }),
      ]),
    );
    expect(notifications).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          consumerIds: grantedConsumerIds,
          kind: "secret.changed",
          controlVersionId: "ctl-next",
          payloadVersionId: "pay-next",
        }),
        expect.objectContaining({
          consumerIds: revokedConsumerIds,
          kind: "secret.revoked",
          controlVersionId: "ctl-next",
        }),
      ]),
    );
    const revocation = notifications.find(
      (item) => item.kind === "secret.revoked",
    );
    expect(revocation).not.toHaveProperty("payloadVersionId");
  });

  it("hydrates listed access grants from each secret's current head", async () => {
    const dynamo = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Items: [
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#payments-api",
              consumerId: "prod-east",
              secretId: "payments-api",
              environment: "prod",
              permissions: ["read"],
              controlVersionId: "ctl-prior",
              payloadVersionId: "pay-prior",
              state: "ACTIVE",
              changeKind: "secret.changed",
            },
          ],
        })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET#prod#payments-api",
            sk: "HEAD",
            secretId: "payments-api",
            environment: "prod",
            controlVersionId: "ctl-current",
            payloadVersionId: "pay-current",
            state: "ACTIVE",
          },
        }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listAccess("prod-east", "prod");

    expect(page.changes).toEqual([
      expect.objectContaining({
        controlVersionId: "ctl-current",
        payloadVersionId: "pay-current",
      }),
    ]);
  });

  it("turns a still-stored grant into a revocation when its UID head is archived", async () => {
    const dynamo = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Items: [
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#sec-payments",
              consumerId: "prod-east",
              secretUid: "sec-payments",
              secretId: "payments-api",
              environment: "prod",
              permissions: ["read"],
              controlVersionId: "ctl-prior",
              payloadVersionId: "pay-prior",
              state: "ACTIVE",
              changeKind: "secret.changed",
            },
          ],
        })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET#sec-payments",
            sk: "HEAD",
            secretUid: "sec-payments",
            secretId: "payments-api",
            environment: "prod",
            controlVersionId: "ctl-archived",
            state: "ARCHIVED",
          },
        }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listAccess("prod-east", "prod");

    expect(page.changes).toEqual([
      expect.objectContaining({
        permissions: [],
        payloadVersionId: undefined,
        state: "REVOKED",
        changeKind: "secret.revoked",
      }),
    ]);
  });

  it("prefers the live UID over an archived revocation when a secret ID is reused", async () => {
    const dynamo = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Items: [
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#sec-archived",
              consumerId: "prod-east",
              secretUid: "sec-archived",
              secretId: "payments-api",
              environment: "prod",
              permissions: [],
              controlVersionId: "ctl-archived",
              state: "REVOKED",
              changeKind: "secret.revoked",
            },
            {
              pk: "CONSUMER#prod-east",
              sk: "SECRET#prod#sec-reused",
              consumerId: "prod-east",
              secretUid: "sec-reused",
              secretId: "payments-api",
              environment: "prod",
              permissions: ["read"],
              controlVersionId: "ctl-created",
              payloadVersionId: "pay-created",
              state: "ACTIVE",
              changeKind: "secret.changed",
            },
          ],
        })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET#sec-reused",
            sk: "HEAD",
            secretUid: "sec-reused",
            secretId: "payments-api",
            environment: "prod",
            controlVersionId: "ctl-current",
            payloadVersionId: "pay-current",
            state: "ACTIVE",
          },
        })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET_NAME#prod#payments-api",
            sk: "LOOKUP",
            secretUid: "sec-reused",
          },
        }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listAccess("prod-east", "prod");

    expect(page.changes).toEqual([
      expect.objectContaining({
        secretUid: "sec-reused",
        state: "ACTIVE",
        controlVersionId: "ctl-current",
        payloadVersionId: "pay-current",
      }),
    ]);
  });

  it("archives atomically by moving the catalog head, revoking grants, and deleting only its name lookup", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const control = {
      schemaVersion: 1 as const,
      secretUid: "sec-payments",
      secretId: "payments-api",
      controlVersionId: "ctl-archived",
      payloadVersionId: "pay-current",
      payloadKeyCount: 1,
      environment: "prod",
      state: "ARCHIVED" as const,
      createdAt: "2026-08-24T00:00:00.000Z",
      createdBy: { type: "human" as const, id: "admin-1" },
      metadata: { description: "old payments API" },
      acl: [],
    };
    const completed: CompletedMutation = {
      prepared: {
        operationId: "archive-op",
        idempotencyKey: "archive-payments-api",
        actor: { type: "human", id: "admin-1" },
        requestDigest: "digest",
        secretId: control.secretId,
        secretUid: control.secretUid,
        environment: control.environment,
        expectedControlVersionId: "ctl-current",
        archive: true,
        control,
        controlKey: "secrets/sec-payments/control/ctl-archived.json",
        controlChecksumSha256: "checksum",
        controlBytes: Buffer.from("control"),
        expiresAt: "2026-08-24T00:10:00.000Z",
      },
      controlObject: {
        bucket: "revisions",
        key: "secrets/sec-payments/control/ctl-archived.json",
        versionId: "control-version",
        checksumSha256: "checksum",
      },
      priorHead: {
        pk: "SECRET#sec-payments",
        sk: "HEAD",
        secretUid: "sec-payments",
        secretId: "payments-api",
        environment: "prod",
        controlVersionId: "ctl-current",
        payloadVersionId: "pay-current",
        state: "ACTIVE",
      },
      priorAccess: [
        {
          pk: "CONSUMER#prod-east",
          sk: "SECRET#prod#sec-payments",
          consumerId: "prod-east",
          secretUid: "sec-payments",
          secretId: "payments-api",
          environment: "prod",
          permissions: ["read"],
          controlVersionId: "ctl-current",
          payloadVersionId: "pay-current",
          state: "ACTIVE",
          changeKind: "secret.changed",
        },
      ],
    };

    await repository.completeMutation(completed);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    const items = command.input.TransactItems ?? [];
    expect(items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Update: expect.objectContaining({
            Key: { pk: "SECRET#sec-payments", sk: "HEAD" },
            ExpressionAttributeValues: expect.objectContaining({
              ":catalogPk": "ARCHIVED_CATALOG#prod",
              ":state": "ARCHIVED",
            }),
          }),
        }),
        expect.objectContaining({
          Delete: expect.objectContaining({
            Key: {
              pk: "SECRET_NAME#prod#payments-api",
              sk: "LOOKUP",
            },
            ConditionExpression: "secretUid = :secretUid",
            ExpressionAttributeValues: { ":secretUid": "sec-payments" },
          }),
        }),
        expect.objectContaining({
          Put: expect.objectContaining({
            Item: expect.objectContaining({
              pk: "CONSUMER#prod-east",
              permissions: [],
              state: "REVOKED",
              changeKind: "secret.revoked",
            }),
          }),
        }),
        expect.objectContaining({
          Put: expect.objectContaining({
            Item: expect.objectContaining({
              consumerIds: ["prod-east"],
              kind: "secret.revoked",
            }),
          }),
        }),
      ]),
    );
    expect(items).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Put: expect.objectContaining({
            Item: expect.objectContaining({ kind: "secret.changed" }),
          }),
        }),
      ]),
    );
  });

  it("stores environment definitions in a bounded, dedicated registry", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const environment = {
      pk: "SYSTEM#ENVIRONMENTS" as const,
      sk: "ENVIRONMENT#prod",
      name: "prod",
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human" as const, id: "admin-1" },
    };

    await repository.createEnvironment(environment);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    expect(command.input.TransactItems).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Put: expect.objectContaining({
            Item: environment,
            ConditionExpression: "attribute_not_exists(pk)",
          }),
        }),
        expect.objectContaining({
          Update: expect.objectContaining({
            Key: { pk: "SYSTEM#ENVIRONMENTS", sk: "STATE" },
            ConditionExpression:
              "attribute_not_exists(environmentCount) OR environmentCount < :maximum",
          }),
        }),
      ]),
    );
  });

  it("reads only environment records from the dedicated registry", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({
        Items: [
          { pk: "SYSTEM#ENVIRONMENTS", sk: "ENVIRONMENT#prod", name: "prod" },
        ],
      }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.listEnvironments();

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: {
        ":pk": "SYSTEM#ENVIRONMENTS",
        ":prefix": "ENVIRONMENT#",
      },
      Limit: 101,
      ConsistentRead: true,
    });
  });

  it("requires an exact environment definition", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({
        Item: {
          pk: "SYSTEM#ENVIRONMENTS",
          sk: "ENVIRONMENT#prod",
          name: "prod",
        },
      }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.requireEnvironment("prod");

    const command = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as GetCommand;
    expect(command.input).toMatchObject({
      Key: { pk: "SYSTEM#ENVIRONMENTS", sk: "ENVIRONMENT#prod" },
      ConsistentRead: true,
    });
  });

  it("queries the environment-scoped consumer directory", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: [] }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.listConsumers("prod");

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "consumer-directory",
      KeyConditionExpression: "consumerDirectoryPk = :directory",
      ExpressionAttributeValues: { ":directory": "CONSUMERS#prod" },
      Limit: 100,
    });
  });

  it("returns newest-first revision history and marks an extra record as truncated", async () => {
    const revisions = Array.from({ length: 501 }, (_, index) => ({
      pk: "SECRET#sec-payments",
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
        metadata: { description: "Payments API" },
        acl: [],
      },
    }));
    const dynamo = {
      send: jest
        .fn()
        .mockResolvedValueOnce({ Item: { secretUid: "sec-payments" } })
        .mockResolvedValueOnce({
          Item: {
            pk: "SECRET#sec-payments",
            sk: "HEAD",
            secretUid: "sec-payments",
            secretId: "payments-api",
            environment: "prod",
            controlVersionId: "ctl-current",
            state: "ACTIVE",
          },
        })
        .mockResolvedValueOnce({ Items: revisions }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listRecentControlRevisions(
      "prod",
      "payments-api",
    );

    const command = (dynamo.send as jest.Mock).mock
      .calls[2]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "secret-revision",
      KeyConditionExpression: "revisionPk = :secret",
      ExpressionAttributeValues: { ":secret": "SECRET#sec-payments" },
      Limit: 501,
      ScanIndexForward: false,
    });
    expect(page.revisions).toHaveLength(500);
    expect(page.truncated).toBe(true);
  });
});

describe("secret tree browsing", () => {
  const mockTreeDynamo = (
    secretItems: readonly Record<string, unknown>[],
  ): DynamoDBDocumentClient =>
    ({
      send: jest.fn(async () => ({ Items: secretItems })),
    }) as unknown as DynamoDBDocumentClient;

  it("groups descendants by immediate segment, counts recursively, and keeps unpathed secrets at the root", async () => {
    const items = [
      {
        secretId: "root-secret",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: {},
      },
      {
        secretId: "payments/paypal-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: {},
      },
      {
        secretId: "payments/stripe/stripe-key",
        environment: "prod",
        controlVersionId: "c3",
        state: "ACTIVE",
        metadata: {},
      },
      {
        secretId: "infra/aws/aws-key",
        environment: "prod",
        controlVersionId: "c4",
        state: "ACTIVE",
        metadata: {},
      },
    ];
    const dynamo = mockTreeDynamo(items);
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listSecretTree("prod", undefined);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "catalog-path",
      KeyConditionExpression:
        "catalogPk = :catalogPk AND begins_with(catalogSk, :prefix)",
      FilterExpression: "#workflowState = :ready",
      ExpressionAttributeValues: {
        ":catalogPk": "CATALOG#prod",
        ":prefix": "PATH#",
        ":ready": "READY",
      },
      Limit: 501,
    });
    expect(dynamo.send).toHaveBeenCalledTimes(1);
    expect(page.truncated).toBe(false);
    expect(page.secrets.map((secret) => secret.secretId)).toEqual([
      "root-secret",
    ]);
    expect(page.folders).toEqual([
      { segment: "infra", path: "infra", secretCount: 1, kind: "derived" },
      {
        segment: "payments",
        path: "payments",
        secretCount: 2,
        kind: "derived",
      },
    ]);
  });

  it("uses the separate archive catalog partition only when explicitly requested", async () => {
    const dynamo = mockTreeDynamo([]);
    const repository = new DynamoRepository(dynamo, config);

    await repository.listSecretTree("prod", undefined, true);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input.ExpressionAttributeValues).toMatchObject({
      ":catalogPk": "ARCHIVED_CATALOG#prod",
      ":prefix": "PATH#",
    });
  });

  it("returns only the exact-path secret and immediate child folders at a prefix", async () => {
    const items = [
      {
        secretId: "payments/paypal-key",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: {},
      },
      {
        secretId: "payments/stripe/stripe-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: {},
      },
      {
        secretId: "payments/stripe/live/stripe-live-key",
        environment: "prod",
        controlVersionId: "c3",
        state: "ACTIVE",
        metadata: {},
      },
    ];
    const dynamo = mockTreeDynamo(items);
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listSecretTree("prod", "payments");

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      ExpressionAttributeValues: {
        ":catalogPk": "CATALOG#prod",
        ":prefix": "PATH#payments/",
        ":ready": "READY",
      },
    });
    expect(page.secrets.map((secret) => secret.secretId)).toEqual([
      "payments/paypal-key",
    ]);
    expect(page.folders).toEqual([
      {
        segment: "stripe",
        path: "payments/stripe",
        secretCount: 2,
        kind: "derived",
      },
    ]);
  });

  it("caps the internal scan and reports truncated instead of returning a cursor", async () => {
    const items = Array.from({ length: 501 }, (_, index) => ({
      secretId: `secret-${String(index).padStart(4, "0")}`,
      environment: "prod",
      controlVersionId: `c${index}`,
      state: "ACTIVE",
      metadata: {},
    }));
    const dynamo = mockTreeDynamo(items);
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listSecretTree("prod", undefined);

    expect(page.truncated).toBe(true);
    expect(page.secrets).toHaveLength(500);
  });
});

describe("secret catalog search", () => {
  it("matches a secretId substring case-insensitively and composes with pathPrefix and tags", async () => {
    const items = [
      {
        secretId: "stripe-live-key",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: { description: "unrelated" },
      },
      {
        secretId: "paypal-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: {},
      },
    ];
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: items }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const result = await repository.searchSecrets(
      "prod",
      "payments",
      { owner: "payments" },
      "STRIPE",
    );

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "catalog-path",
      KeyConditionExpression:
        "catalogPk = :catalogPk AND begins_with(catalogSk, :pathPrefix)",
      FilterExpression:
        "#workflowState = :ready AND catalogTags.#tagKey0 = :tagValue0",
      ExpressionAttributeValues: {
        ":catalogPk": "CATALOG#prod",
        ":pathPrefix": "PATH#payments/",
        ":ready": "READY",
        ":tagValue0": "payments",
      },
      Limit: 501,
    });
    expect(result.secrets.map((secret) => secret.secretId)).toEqual([
      "stripe-live-key",
    ]);
    expect(result.truncated).toBe(false);
  });

  it("matches a metadata.description substring", async () => {
    const items = [
      {
        secretId: "database-credentials",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: { description: "Stripe webhook signing secret" },
      },
      {
        secretId: "other-secret",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: { description: "unrelated" },
      },
    ];
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: items }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const result = await repository.searchSecrets(
      "prod",
      undefined,
      {},
      "webhook",
    );

    expect(result.secrets.map((secret) => secret.secretId)).toEqual([
      "database-credentials",
    ]);
  });

  it("searches archived records only when archived is explicitly true", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: [] }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.searchSecrets("prod", undefined, {}, "legacy", true);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input.ExpressionAttributeValues).toMatchObject({
      ":catalogPk": "ARCHIVED_CATALOG#prod",
      ":pathPrefix": "PATH#",
    });
  });

  it("caps the internal scan and reports truncated instead of returning a cursor", async () => {
    const items = Array.from({ length: 501 }, (_, index) => ({
      secretId: `stripe-secret-${String(index).padStart(4, "0")}`,
      environment: "prod",
      controlVersionId: `c${index}`,
      state: "ACTIVE",
      metadata: {},
    }));
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: items }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const result = await repository.searchSecrets(
      "prod",
      undefined,
      {},
      "stripe",
    );

    expect(result.truncated).toBe(true);
    expect(result.secrets).toHaveLength(500);
  });
});
