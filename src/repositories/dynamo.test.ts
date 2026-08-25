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
      environment,
      control: {
        schemaVersion: 1,
        secretId: "shared-secret",
        controlVersionId: `ctl-${environment}`,
        environment,
        state: "PENDING_VALUE",
        createdAt: "2026-08-24T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
        metadata: {},
        acl: [],
      },
      controlKey: `secrets/${environment}/shared-secret/control.json`,
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
      expect.objectContaining({ pk: "SECRET#dev#shared-secret" }),
      expect.objectContaining({ pk: "SECRET#prod#shared-secret" }),
    ]);
  });

  it("does not rewrite unchanged consumer grants for a payload-only mutation", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const control = {
      schemaVersion: 1 as const,
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
      sk: "SECRET#prod#payments-api",
      consumerId: grant.consumerId,
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
        environment: control.environment,
        expectedControlVersionId: "ctl-prior",
        control,
        controlKey: "controls/payments-api/ctl-next.json",
        controlChecksumSha256: "checksum-control",
        controlBytes: Buffer.from("control"),
        payload: {
          revision: {
            schemaVersion: 1,
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
        pk: "SECRET#prod#payments-api",
        sk: "HEAD",
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
        environment: control.environment,
        expectedControlVersionId: "ctl-prior",
        control,
        controlKey: "controls/payments-api/ctl-next.json",
        controlChecksumSha256: "checksum-control",
        controlBytes: Buffer.from("control"),
        payload: {
          revision: {
            schemaVersion: 1,
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
        pk: "SECRET#prod#payments-api",
        sk: "HEAD",
        secretId: "payments-api",
        environment: "prod",
        controlVersionId: "ctl-prior",
        payloadVersionId: "pay-prior",
        state: "ACTIVE",
      },
      priorAccess: revokedConsumerIds.map((consumerId) => ({
        pk: `CONSUMER#${consumerId}`,
        sk: "SECRET#prod#payments-api",
        consumerId,
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
      pk: "SECRET#prod#payments-api",
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
      send: jest.fn().mockResolvedValue({ Items: revisions }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listRecentControlRevisions(
      "prod",
      "payments-api",
    );

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "secret-revision",
      KeyConditionExpression: "revisionPk = :secret",
      ExpressionAttributeValues: { ":secret": "SECRET#prod#payments-api" },
      Limit: 501,
      ScanIndexForward: false,
    });
    expect(page.revisions).toHaveLength(500);
    expect(page.truncated).toBe(true);
  });
});

describe("folder registry", () => {
  it("stores a folder record scoped to its environment, bounded by count", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);
    const folder = {
      pk: "FOLDER#prod",
      sk: "PATH#payments/adyen",
      environment: "prod",
      path: "payments/adyen",
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human" as const, id: "admin-1" },
    };

    await repository.createFolder(folder);

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    expect(command.input.TransactItems).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Put: expect.objectContaining({
            Item: folder,
            ConditionExpression: "attribute_not_exists(pk)",
          }),
        }),
        expect.objectContaining({
          Update: expect.objectContaining({
            Key: { pk: "FOLDER#prod", sk: "STATE" },
            ConditionExpression:
              "attribute_not_exists(folderCount) OR folderCount < :maximum",
            ExpressionAttributeValues: expect.objectContaining({
              ":maximum": 1000,
            }),
          }),
        }),
      ]),
    );
  });

  it("surfaces a duplicate path or a full registry as a conflict", async () => {
    const dynamo = {
      send: jest
        .fn()
        .mockRejectedValue(new Error("ConditionalCheckFailedException")),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(
      repository.createFolder({
        pk: "FOLDER#prod",
        sk: "PATH#a",
        environment: "prod",
        path: "a",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      }),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("reads a folder record by environment and exact path", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({
        Item: { pk: "FOLDER#prod", sk: "PATH#a", path: "a" },
      }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const folder = await repository.getFolder("prod", "a");

    const command = (dynamo.send as jest.Mock).mock.calls[0]?.[0] as GetCommand;
    expect(command.input).toMatchObject({
      Key: { pk: "FOLDER#prod", sk: "PATH#a" },
      ConsistentRead: true,
    });
    expect(folder).toEqual({ pk: "FOLDER#prod", sk: "PATH#a", path: "a" });
  });

  it("lists only PATH# folder records for an environment, bounded", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: [{ path: "a" }] }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const folders = await repository.listFolders("prod");

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": "FOLDER#prod", ":prefix": "PATH#" },
      Limit: 1001,
      ConsistentRead: true,
    });
    expect(folders).toEqual([{ path: "a" }]);
  });

  it("rejects a folder registry that exceeds its supported size", async () => {
    const items = Array.from({ length: 1001 }, (_, index) => ({
      path: `folder-${index}`,
    }));
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Items: items }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(repository.listFolders("prod")).rejects.toMatchObject({
      code: "service_unavailable",
    });
  });

  it("deletes a folder record and decrements its environment's count in one transaction", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({}),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await repository.deleteFolder("prod", "a");

    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as TransactWriteCommand;
    expect(command.input.TransactItems).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Delete: expect.objectContaining({
            Key: { pk: "FOLDER#prod", sk: "PATH#a" },
            ConditionExpression: "attribute_exists(pk)",
          }),
        }),
        expect.objectContaining({
          Update: expect.objectContaining({
            Key: { pk: "FOLDER#prod", sk: "STATE" },
            UpdateExpression: "SET folderCount = folderCount - :one",
          }),
        }),
      ]),
    );
  });

  it("reports occupancy when a READY secret sits at or beneath a path", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Count: 1 }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    const occupied = await repository.hasSecretsAtOrBeneathPath(
      "prod",
      "payments",
    );

    expect(occupied).toBe(true);
    const command = (dynamo.send as jest.Mock).mock
      .calls[0]?.[0] as QueryCommand;
    expect(command.input).toMatchObject({
      IndexName: "catalog-path",
      KeyConditionExpression:
        "catalogPk = :catalogPk AND begins_with(catalogSk, :prefix)",
      ExpressionAttributeValues: {
        ":catalogPk": "CATALOG#prod",
        ":prefix": "PATH#payments/",
        ":ready": "READY",
      },
      Select: "COUNT",
    });
  });

  it("reports no occupancy when no secret matches", async () => {
    const dynamo = {
      send: jest.fn().mockResolvedValue({ Count: 0 }),
    } as unknown as DynamoDBDocumentClient;
    const repository = new DynamoRepository(dynamo, config);

    await expect(
      repository.hasSecretsAtOrBeneathPath("prod", "payments"),
    ).resolves.toBe(false);
  });
});

describe("secret tree browsing", () => {
  // listSecretTree now issues two internal queries -- the secret-derived one
  // (against the catalog-path GSI, so its input has an IndexName) and
  // listFolders' explicit-record one (a base-table query, no IndexName).
  // This distinguishes them so each test's fixture only ever populates the
  // half of the merge it means to exercise.
  const mockTreeDynamo = (
    secretItems: readonly Record<string, unknown>[],
    folderItems: readonly Record<string, unknown>[] = [],
  ): DynamoDBDocumentClient =>
    ({
      send: jest.fn(async (command: QueryCommand) =>
        command.input.IndexName === undefined
          ? { Items: folderItems }
          : { Items: secretItems },
      ),
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
        secretId: "paypal-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: { path: "payments" },
      },
      {
        secretId: "stripe-key",
        environment: "prod",
        controlVersionId: "c3",
        state: "ACTIVE",
        metadata: { path: "payments/stripe" },
      },
      {
        secretId: "aws-key",
        environment: "prod",
        controlVersionId: "c4",
        state: "ACTIVE",
        metadata: { path: "infra/aws" },
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

  it("returns only the exact-path secret and immediate child folders at a prefix", async () => {
    const items = [
      {
        secretId: "paypal-key",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: { path: "payments" },
      },
      {
        secretId: "stripe-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: { path: "payments/stripe" },
      },
      {
        secretId: "stripe-live-key",
        environment: "prod",
        controlVersionId: "c3",
        state: "ACTIVE",
        metadata: { path: "payments/stripe/live" },
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
      "paypal-key",
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

  it("returns an explicit empty folder record with secretCount 0", async () => {
    const folderItems = [
      {
        pk: "FOLDER#prod",
        sk: "PATH#adyen",
        environment: "prod",
        path: "adyen",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      },
    ];
    const dynamo = mockTreeDynamo([], folderItems);
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listSecretTree("prod", undefined);

    expect(page.folders).toEqual([
      { segment: "adyen", path: "adyen", secretCount: 0, kind: "explicit" },
    ]);
  });

  it("merges an explicit folder record and a derived secret into one folder, not two", async () => {
    const secretItems = [
      {
        secretId: "stripe-key",
        environment: "prod",
        controlVersionId: "c1",
        state: "ACTIVE",
        metadata: { path: "stripe" },
      },
    ];
    const folderItems = [
      {
        pk: "FOLDER#prod",
        sk: "PATH#stripe",
        environment: "prod",
        path: "stripe",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      },
    ];
    const dynamo = mockTreeDynamo(secretItems, folderItems);
    const repository = new DynamoRepository(dynamo, config);

    const page = await repository.listSecretTree("prod", undefined);

    expect(page.folders).toEqual([
      { segment: "stripe", path: "stripe", secretCount: 1, kind: "both" },
    ]);
  });

  it("shows a folder record's implied ancestor as derived, then the record itself as explicit one level down", async () => {
    const folderItems = [
      {
        pk: "FOLDER#prod",
        sk: "PATH#reporting/weekly",
        environment: "prod",
        path: "reporting/weekly",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      },
    ];
    const dynamo = mockTreeDynamo([], folderItems);
    const repository = new DynamoRepository(dynamo, config);

    const root = await repository.listSecretTree("prod", undefined);
    expect(root.folders).toEqual([
      {
        segment: "reporting",
        path: "reporting",
        secretCount: 0,
        kind: "derived",
      },
    ]);

    const nested = await repository.listSecretTree("prod", "reporting");
    expect(nested.folders).toEqual([
      {
        segment: "weekly",
        path: "reporting/weekly",
        secretCount: 0,
        kind: "explicit",
      },
    ]);
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
        metadata: { path: "payments", description: "unrelated" },
      },
      {
        secretId: "paypal-key",
        environment: "prod",
        controlVersionId: "c2",
        state: "ACTIVE",
        metadata: { path: "payments" },
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
