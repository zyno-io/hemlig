import {
  DecryptCommand,
  GenerateDataKeyCommand,
  KMSClient,
} from "@aws-sdk/client-kms";
import type { AppConfig } from "../aws/config";
import { EnvelopeCrypto } from "./envelope";

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
  payloadKmsKeyArn: "arn:aws:kms:us-east-1:000000000000:key/test",
  auditBucketName: "audit",
  auditPrefix: "audit",
  deliveryApiCustomDomainName: "api.example.test",
  deliveryApiHostname: "api.example.test",
  iotEndpoint: "iot.example.test",
  iotNotificationPolicyName: "test-agent-notifications",
  iotNotificationTopicPrefix: "hemlig/test/consumers",
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "audience",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

describe("EnvelopeCrypto", () => {
  it("binds an AES-GCM payload to its exact payload version", async () => {
    const key = Buffer.alloc(32, 9);
    const kms = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Plaintext: key,
          CiphertextBlob: Buffer.from("encrypted-key"),
        })
        .mockResolvedValueOnce({ Plaintext: key }),
    } as unknown as KMSClient;
    const crypto = new EnvelopeCrypto(kms, config);
    const revision = await crypto.encrypt(
      { PASSWORD: { encoding: "utf8", value: "correct horse battery staple" } },
      {
        environment: "staging",
        secretId: "sec-example",
        payloadVersionId: "pay-example",
      },
      { type: "human", id: "operator-1" },
      "2026-08-22T00:00:00.000Z",
    );
    const payload = await crypto.decrypt(revision);
    expect(payload).toEqual({
      PASSWORD: { encoding: "utf8", value: "correct horse battery staple" },
    });
    expect(kms.send).toHaveBeenCalledTimes(2);
    const generate = (kms.send as jest.Mock).mock
      .calls[0]?.[0] as GenerateDataKeyCommand;
    const decrypt = (kms.send as jest.Mock).mock
      .calls[1]?.[0] as DecryptCommand;
    expect(generate.input.EncryptionContext).toMatchObject({
      service: "hemlig",
      purpose: "secret-payload",
    });
    expect(decrypt.input.EncryptionContext).toMatchObject({
      service: "hemlig",
      purpose: "secret-payload",
    });
  });

  it("rejects a ciphertext rebound to a different payload version", async () => {
    const key = Buffer.alloc(32, 3);
    const kms = {
      send: jest
        .fn()
        .mockResolvedValueOnce({
          Plaintext: key,
          CiphertextBlob: Buffer.from("encrypted-key"),
        })
        .mockResolvedValueOnce({ Plaintext: key }),
    } as unknown as KMSClient;
    const crypto = new EnvelopeCrypto(kms, config);
    const revision = await crypto.encrypt(
      { TOKEN: { encoding: "utf8", value: "not logged" } },
      {
        environment: "production",
        secretId: "sec-example",
        payloadVersionId: "pay-one",
      },
      { type: "human", id: "operator-1" },
      "2026-08-22T00:00:00.000Z",
    );
    const rebound = { ...revision, payloadVersionId: "pay-two" };
    await expect(crypto.decrypt(rebound)).rejects.toThrow();
  });
});
