import { createPkiApplication } from "./app";
import type { PkiConfig } from "../aws/config";
import type { CaRecord } from "./types";

const sendMock = jest.fn();
jest.mock("../aws/pki-clients", () => ({
  createPkiAwsClients: jest.fn(() => ({
    dynamo: { send: jest.fn() },
    kms: { send: (...args: unknown[]) => sendMock(...args) },
    s3: { send: jest.fn() },
  })),
}));

const config = {
  region: "us-east-1",
  environmentName: "test",
  controlTableName: "control",
  pkiDirectoryIndex: "pki-directory",
  pkiBucketName: "pki",
  payloadKmsKeyArn: "arn:aws:kms:us-east-1:111122223333:key/test",
  auditBucketName: "audit",
  auditPrefix: "audit",
} as unknown as PkiConfig;

const wrapped = {
  algorithm: "AES-256-GCM" as const,
  encryptedDataKey: Buffer.from("key").toString("base64"),
  iv: Buffer.alloc(12).toString("base64"),
  tag: Buffer.alloc(16).toString("base64"),
  ciphertext: Buffer.from("x").toString("base64"),
};
const ca = (
  key: Partial<CaRecord["key"]>,
): Pick<CaRecord, "caId" | "environment" | "key"> => ({
  caId: "ca-test-one",
  environment: "prod",
  key: {
    custody: "WRAPPED",
    algorithm: "ECDSA_P256",
    spkiSha256: "a".repeat(64),
    state: "ACTIVE",
    wrapped,
    ...key,
  },
});

describe("createPkiApplication", () => {
  beforeEach(() => sendMock.mockReset());

  it("builds exactly the PKI members", () => {
    const app = createPkiApplication(config);
    expect(Object.keys(app).sort()).toEqual(
      [
        "audit",
        "capacity",
        "cas",
        "certificates",
        "clients",
        "config",
        "crls",
        "cursors",
        "externalCas",
        "grants",
        "issuance",
        "now",
        "objects",
        "pki",
        "repository",
        "signerFor",
      ].sort(),
    );
    expect(Object.keys(app.clients).sort()).toEqual(["dynamo", "kms", "s3"]);
  });

  it("refuses a signer for a disabled key or one without wrapped material", () => {
    const app = createPkiApplication(config);
    expect(() => app.signerFor(ca({ state: "DISABLED" }))).toThrow(
      expect.objectContaining({ statusCode: 409, code: "ca_key_unavailable" }),
    );
    expect(() => app.signerFor(ca({ wrapped: undefined }))).toThrow(
      expect.objectContaining({ statusCode: 409, code: "ca_key_unavailable" }),
    );
  });

  it("decrypts with the application key under the pki-ca context", async () => {
    sendMock.mockRejectedValue(
      Object.assign(new Error("bad"), { name: "InvalidCiphertextException" }),
    );
    const app = createPkiApplication(config);
    const signer = app.signerFor(ca({}));
    await expect(signer.sign(new Uint8Array([1]))).rejects.toMatchObject({
      code: "ca_key_unavailable",
    });
    const command = sendMock.mock.calls[0]?.[0] as {
      input: { KeyId: string; EncryptionContext: Record<string, string> };
    };
    expect(command.input.KeyId).toBe(config.payloadKmsKeyArn);
    expect(command.input.EncryptionContext).toEqual({
      service: "hemlig",
      purpose: "pki-ca",
      caId: "ca-test-one",
      environment: "prod",
    });
  });
});
