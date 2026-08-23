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
  revisionBucketName: "revisions",
  truststoreBucketName: "truststores",
  truststoreKeyPrefix: "truststores",
  payloadKmsKeyArn: "arn:aws:kms:us-east-1:111122223333:key/test",
  auditBucketName: "audit",
  auditPrefix: "audit",
  clusterCustomDomainName: "clusters.example.test",
  clusterApiHostname: "clusters.example.test",
  cursorHmacKey: Buffer.alloc(32, 1),
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "clavis",
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
  payloadObjectVersionId: "pay-object-version",
  state: "ACTIVE",
};

const access: AccessRecord = {
  pk: "CLUSTER#prod-east",
  sk: "SECRET#database-credentials",
  clusterId: "prod-east",
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
  environment: "prod",
  state: "ACTIVE",
  createdAt: "2026-08-22T00:00:00.000Z",
  createdBy: { type: "human", id: "admin" },
  metadata: { name: "database credentials" },
  acl: [{ clusterId: "prod-east", permissions: ["read"] }],
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
    );

    await expect(
      service.read("prod-east", "prod", "database-credentials"),
    ).rejects.toMatchObject({ code: "service_unavailable" });

    expect(crypto.decrypt).not.toHaveBeenCalled();
  });
});
