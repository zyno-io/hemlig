import { loadConfig, loadPkiConfig } from "./config";

const base: NodeJS.ProcessEnv = {
  HEMLIG_ENVIRONMENT: "test",
  CONTROL_TABLE_NAME: "control",
  WORKFLOW_DUE_INDEX: "workflow-due",
  RETENTION_DUE_INDEX: "retention-due",
  CATALOG_PATH_INDEX: "catalog-path",
  CONSUMER_DIRECTORY_INDEX: "consumer-directory",
  CONSUMER_IDENTITY_INDEX: "consumer-identity",
  SECRET_REVISION_INDEX: "secret-revision",
  REVISION_BUCKET_NAME: "revisions",
  TRUSTSTORE_BUCKET_NAME: "truststores",
  TRUSTSTORE_KEY_PREFIX: "truststores",
  PAYLOAD_KMS_KEY_ARN: "arn:aws:kms:us-east-1:111122223333:key/test",
  AUDIT_BUCKET_NAME: "audit",
  AUDIT_PREFIX: "audit",
  DELIVERY_API_CUSTOM_DOMAIN_NAME: "api.example.test",
  DELIVERY_API_HOSTNAME: "api.example.test",
  IOT_ENDPOINT: "iot.example.test",
  IOT_NOTIFICATION_POLICY_NAME: "policy",
  IOT_NOTIFICATION_TOPIC_PREFIX: "prefix",
  ADMIN_JWT_ISSUER: "https://issuer.example.test",
  ADMIN_JWT_AUDIENCE: "hemlig",
  ADMIN_ACTOR_SUBJECT_CLAIM: "sub",
};

describe("PKI configuration", () => {
  it("leaves the PKI fields undefined for the existing Lambdas", () => {
    const config = loadConfig(base);
    expect(config.pkiDirectoryIndex).toBeUndefined();
    expect(config.pkiBucketName).toBeUndefined();
    expect(config.adminPkiCaRole).toBeUndefined();
    expect(config.adminPkiOperatorRole).toBeUndefined();
  });

  it("reads the optional PKI variables", () => {
    const config = loadConfig({
      ...base,
      PKI_DIRECTORY_INDEX: "pki-directory",
      PKI_BUCKET_NAME: "pki",
      ADMIN_PKI_CA_ROLE: "ca-admin",
      ADMIN_PKI_OPERATOR_ROLE: "operator",
    });
    expect(config).toMatchObject({
      pkiDirectoryIndex: "pki-directory",
      pkiBucketName: "pki",
      adminPkiCaRole: "ca-admin",
      adminPkiOperatorRole: "operator",
    });
  });

  it("requires the index and bucket for the PKI Lambdas", () => {
    expect(() => loadPkiConfig(base)).toThrow(
      "PKI_DIRECTORY_INDEX is required.",
    );
    expect(() =>
      loadPkiConfig({ ...base, PKI_DIRECTORY_INDEX: "pki-directory" }),
    ).toThrow("PKI_BUCKET_NAME is required.");
    expect(
      loadPkiConfig({
        ...base,
        PKI_DIRECTORY_INDEX: "pki-directory",
        PKI_BUCKET_NAME: "pki",
      }),
    ).toMatchObject({
      pkiDirectoryIndex: "pki-directory",
      pkiBucketName: "pki",
    });
  });
});

describe("administrator role claim configuration", () => {
  it("is unset by default, keeping the legacy roles claim", () => {
    expect(loadConfig(base).adminRoleClaim).toBeUndefined();
    expect(loadConfig({ ...base, ADMIN_ROLE_CLAIM: "  " }).adminRoleClaim).toBeUndefined();
  });

  it("accepts a claim name or a JSON Pointer", () => {
    expect(loadConfig({ ...base, ADMIN_ROLE_CLAIM: "groups" }).adminRoleClaim).toBe("groups");
    expect(loadConfig({ ...base, ADMIN_ROLE_CLAIM: "/realm_access/roles" }).adminRoleClaim).toBe(
      "/realm_access/roles",
    );
  });

  it("rejects a malformed JSON Pointer at load time", () => {
    expect(() => loadConfig({ ...base, ADMIN_ROLE_CLAIM: "/a~2" })).toThrow("JSON Pointer");
  });
});
