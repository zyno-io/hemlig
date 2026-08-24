import type { AppConfig } from "../aws/config";
import type {
  AccessRecord,
  ControlRevision,
  HeadRecord,
  PayloadRevision,
} from "../domain/types";
import { SecretService } from "./secrets";

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

const head: HeadRecord = {
  pk: "SECRET#database-credentials",
  sk: "HEAD",
  secretId: "database-credentials",
  environment: "prod",
  controlVersionId: "ctl-current",
  controlObjectVersionId: "ctl-object-version",
  payloadVersionId: "pay-current",
  payloadKeyCount: 2,
  payloadObjectVersionId: "pay-object-version",
  state: "ACTIVE",
};

const access: AccessRecord = {
  pk: "CONSUMER#prod-east",
  sk: "SECRET#database-credentials",
  consumerId: "prod-east",
  secretId: "database-credentials",
  environment: "prod",
  permissions: ["read"],
  controlVersionId: "ctl-current",
  payloadVersionId: "pay-current",
  state: "ACTIVE",
  changeKind: "secret.changed",
};

const control: ControlRevision = {
  schemaVersion: 1,
  secretId: "database-credentials",
  controlVersionId: "ctl-current",
  payloadVersionId: "pay-current",
  payloadKeyCount: 2,
  environment: "prod",
  state: "ACTIVE",
  createdAt: "2026-08-22T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: { description: "database credentials" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
};

const payload: PayloadRevision = {
  schemaVersion: 1,
  secretId: "database-credentials",
  payloadVersionId: "pay-current",
  environment: "prod",
  createdAt: "2026-08-22T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  payload: {
    algorithm: "AES-256-GCM",
    encryptedDataKey: "key",
    iv: "iv",
    tag: "tag",
    ciphertext: "ciphertext",
  },
};

describe("SecretService.read", () => {
  it("does not authorize a denied grant", async () => {
    const repository = {
      getAccessAndHead: jest.fn().mockResolvedValue({
        access: { ...access, permissions: [] },
        head,
      }),
    };
    const objects = { getJson: jest.fn() };
    const crypto = { decrypt: jest.fn() };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );
    const authorized = jest.fn().mockResolvedValue(undefined);

    await expect(
      service.read(
        "prod-east",
        "prod",
        "database-credentials",
        undefined,
        authorized,
      ),
    ).rejects.toMatchObject({ code: "forbidden" });

    expect(authorized).not.toHaveBeenCalled();
    expect(objects.getJson).not.toHaveBeenCalled();
    expect(crypto.decrypt).not.toHaveBeenCalled();
  });

  it("authorizes against the current head when a grant projection has an older payload pointer", async () => {
    const repository = {
      getAccessAndHead: jest.fn().mockResolvedValue({
        access: {
          ...access,
          controlVersionId: "ctl-prior",
          payloadVersionId: "pay-prior",
        },
        head,
      }),
    };
    const objects = {
      getJson: jest
        .fn()
        .mockResolvedValueOnce(control)
        .mockResolvedValueOnce(payload),
    };
    const crypto = {
      decrypt: jest.fn().mockResolvedValue({
        PASSWORD: { encoding: "utf8", value: "current-value" },
      }),
    };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );

    await expect(
      service.read("prod-east", "prod", "database-credentials"),
    ).resolves.toMatchObject({
      controlVersionId: "ctl-current",
      payloadVersionId: "pay-current",
    });
    expect(crypto.decrypt).toHaveBeenCalledWith(payload);
  });

  it("fails closed when an immutable control document does not match the authorized head", async () => {
    const repository = {
      getAccessAndHead: jest.fn().mockResolvedValue({ access, head }),
    };
    const objects = {
      getJson: jest
        .fn()
        .mockResolvedValue({ ...control, secretId: "other-secret" }),
    };
    const crypto = { decrypt: jest.fn() };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );
    const authorized = jest.fn().mockResolvedValue(undefined);

    await expect(
      service.read(
        "prod-east",
        "prod",
        "database-credentials",
        undefined,
        authorized,
      ),
    ).rejects.toMatchObject({ code: "service_unavailable" });

    expect(authorized).toHaveBeenCalledTimes(1);
    expect(crypto.decrypt).not.toHaveBeenCalled();
  });

  it("fails closed when an immutable payload document does not match the authorized head", async () => {
    const repository = {
      getAccessAndHead: jest.fn().mockResolvedValue({ access, head }),
    };
    const objects = {
      getJson: jest
        .fn()
        .mockResolvedValueOnce(control)
        .mockResolvedValueOnce({ ...payload, environment: "other" }),
    };
    const crypto = { decrypt: jest.fn() };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );

    await expect(
      service.read("prod-east", "prod", "database-credentials"),
    ).rejects.toMatchObject({ code: "service_unavailable" });

    expect(crypto.decrypt).not.toHaveBeenCalled();
  });
});

describe("SecretService.create", () => {
  it("rejects an environment that an administrator has not defined", async () => {
    const environments = {
      require: jest.fn().mockRejectedValue({ code: "not_found" }),
    };
    const service = new SecretService(
      {} as never,
      {} as never,
      {} as never,
      config,
      environments as never,
    );

    await expect(
      service.create({
        secretId: "staging-secret",
        environment: "staging",
        metadata: {},
        acl: [],
        actor: { type: "human", id: "admin" },
        idempotencyKey: "defined-environments-only",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(environments.require).toHaveBeenCalledWith("staging");
  });
});

describe("SecretService.readAdminPayload", () => {
  it("decrypts only the current immutable active payload", async () => {
    const repository = { requireHead: jest.fn().mockResolvedValue(head) };
    const objects = {
      getJson: jest
        .fn()
        .mockResolvedValueOnce(control)
        .mockResolvedValueOnce(payload),
    };
    const crypto = {
      decrypt: jest
        .fn()
        .mockResolvedValue({ PASSWORD: { encoding: "utf8", value: "value" } }),
    };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );

    await expect(
      service.readAdminPayload("database-credentials"),
    ).resolves.toEqual({
      controlVersionId: "ctl-current",
      payloadVersionId: "pay-current",
      payload: { PASSWORD: { encoding: "utf8", value: "value" } },
    });

    expect(repository.requireHead).toHaveBeenCalledWith("database-credentials");
    expect(objects.getJson).toHaveBeenCalledTimes(2);
    expect(crypto.decrypt).toHaveBeenCalledWith(payload);
  });

  it("does not decrypt a secret without an active payload", async () => {
    const repository = {
      requireHead: jest
        .fn()
        .mockResolvedValue({ ...head, state: "PENDING_VALUE" }),
    };
    const objects = { getJson: jest.fn() };
    const crypto = { decrypt: jest.fn() };
    const service = new SecretService(
      repository as never,
      objects as never,
      crypto as never,
      config,
      {} as never,
    );

    await expect(
      service.readAdminPayload("database-credentials"),
    ).rejects.toMatchObject({
      code: "not_found",
    });
    expect(objects.getJson).not.toHaveBeenCalled();
    expect(crypto.decrypt).not.toHaveBeenCalled();
  });
});

describe("SecretService.update", () => {
  it("preserves the payload entry count across a metadata-only revision", async () => {
    let preparedControl: ControlRevision | undefined;
    const repository = {
      requireHead: jest.fn().mockResolvedValue(head),
      getConsumer: jest.fn().mockResolvedValue({
        status: "ACTIVE",
        environment: "prod",
      }),
      getAccess: jest.fn().mockResolvedValue(access),
      getIdempotency: jest.fn().mockResolvedValue(undefined),
      prepareMutation: jest
        .fn()
        .mockImplementation(
          async (prepared: { readonly control: ControlRevision }) => {
            preparedControl = prepared.control;
          },
        ),
      completeMutation: jest.fn().mockResolvedValue(undefined),
    };
    const objects = {
      getJson: jest.fn().mockResolvedValue(control),
      putImmutable: jest.fn().mockResolvedValue({
        bucket: "revisions",
        key: "control",
        versionId: "new-version",
        checksumSha256: "checksum",
      }),
      extendComplianceRetention: jest.fn().mockResolvedValue(undefined),
    };
    const service = new SecretService(
      repository as never,
      objects as never,
      {} as never,
      config,
      {} as never,
    );

    await service.update({
      secretId: "database-credentials",
      expectedControlVersionId: "ctl-current",
      metadata: { description: "renamed database credentials" },
      actor: { type: "human", id: "admin" },
      idempotencyKey: "metadata-count-inheritance",
    });

    expect(preparedControl?.payloadKeyCount).toBe(2);
  });
});
