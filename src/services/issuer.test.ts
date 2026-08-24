import {
  DecryptCommand,
  GenerateDataKeyCommand,
  type KMSClient,
} from "@aws-sdk/client-kms";
import { X509Certificate } from "node:crypto";
import forge from "node-forge";
import type { AppConfig } from "../aws/config";
import type { IssuerRecord } from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import { IssuerService } from "./issuer";

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

describe("Hemlig issuer", () => {
  it("creates one KMS-wrapped root and issues a CSR-backed client leaf", async () => {
    let issuer: IssuerRecord | undefined;
    const repository = {
      getIssuer: jest.fn(async () => issuer),
      createIssuer: jest.fn(async (created: IssuerRecord) => {
        issuer = created;
        return created;
      }),
      ensureIssuerTruststoreRoot: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const dataKey = Buffer.alloc(32, 9);
    const kms = {
      send: jest.fn(async (command: unknown) => {
        if (command instanceof GenerateDataKeyCommand) {
          return {
            Plaintext: dataKey,
            CiphertextBlob: Buffer.from("wrapped-data-key"),
          };
        }
        if (command instanceof DecryptCommand) {
          return { Plaintext: dataKey };
        }
        throw new Error("Unexpected KMS command");
      }),
    } as unknown as KMSClient;
    const service = new IssuerService(repository, kms, config);
    const csrPem = createCsr();

    const rootFingerprint = await service.issuerFingerprint();
    const issued = await service.issueApiIdentity("prod-east", "prod", csrPem);

    expect(issued.rootFingerprint).toBe(rootFingerprint);
    expect(issued.apiIdentity.certificatePem).toContain("BEGIN CERTIFICATE");
    expect(
      service.certificateRequestMatchesCertificate(
        csrPem,
        issued.apiIdentity.certificatePem,
      ),
    ).toBe(true);
    expect(
      service.certificateRequestMatchesCertificate(
        createCsr(),
        issued.apiIdentity.certificatePem,
      ),
    ).toBe(false);
    const root = new X509Certificate(issuer?.rootCertificatePem as string);
    const leaf = new X509Certificate(
      issued.apiIdentity.certificatePem as string,
    );
    const forgeRoot = forge.pki.certificateFromPem(
      issuer?.rootCertificatePem as string,
    );
    const forgeLeaf = forge.pki.certificateFromPem(
      issued.apiIdentity.certificatePem as string,
    );
    expect(leaf.checkIssued(root)).toBe(true);
    expect(leaf.verify(root.publicKey)).toBe(true);
    expect(leaf.keyUsage).toContain("1.3.6.1.5.5.7.3.2");
    expect(leaf.subjectAltName).toContain(
      "URI:spiffe://hemlig/consumer/prod-east",
    );
    expect(
      Number.parseInt(forgeRoot.serialNumber.slice(0, 2), 16),
    ).toBeLessThan(128);
    expect(
      Number.parseInt(forgeLeaf.serialNumber.slice(0, 2), 16),
    ).toBeLessThan(128);
    expect(kms.send).toHaveBeenCalledTimes(2);
    const generate = (kms.send as jest.Mock).mock
      .calls[0]?.[0] as GenerateDataKeyCommand;
    const decrypt = (kms.send as jest.Mock).mock
      .calls[1]?.[0] as DecryptCommand;
    expect(generate.input.EncryptionContext).toEqual({
      service: "hemlig",
      purpose: "issuer-ca",
    });
    expect(decrypt.input.EncryptionContext).toEqual({
      service: "hemlig",
      purpose: "issuer-ca",
    });
    expect(repository.createIssuer).toHaveBeenCalledTimes(1);
  });

  it("rejects a non-CSR request before calling KMS", () => {
    const service = new IssuerService(
      {} as DynamoRepository,
      {} as KMSClient,
      config,
    );
    expect(() => service.certificateRequestFingerprint("not a CSR")).toThrow(
      "apiCertificateSigningRequestPem",
    );
  });
});

const createCsr = (): string => {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: "commonName", value: "prod-east" }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
};
