import type { APIGatewayProxyEventV2WithJWTAuthorizer } from "aws-lambda";
import type { AppConfig } from "../aws/config";
import { createHash } from "node:crypto";
import forge from "node-forge";
import type { IdentityRecord } from "../domain/types";
import { consumerActorFromEvent, humanActorFromEvent } from "./actors";

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
  adminJwtAudience: "hemlig-api",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

const jwtEvent = (
  claims: Record<string, string | string[]>,
): APIGatewayProxyEventV2WithJWTAuthorizer =>
  ({
    requestContext: { authorizer: { jwt: { claims, scopes: [] } } },
  }) as unknown as APIGatewayProxyEventV2WithJWTAuthorizer;

describe("humanActorFromEvent", () => {
  beforeEach(() => {
    jest.spyOn(console, "warn").mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("accepts client_id when aud is absent, matching HTTP API JWT authorizers", () => {
    const actor = humanActorFromEvent(
      jwtEvent({
        iss: "https://issuer.example.test",
        client_id: "hemlig-api",
        sub: "external-subject",
      }),
      config,
    );
    expect(actor).toEqual({ type: "human", id: "external-subject" });
  });

  it("records an optional email only as an administrator display label", () => {
    const actor = humanActorFromEvent(
      jwtEvent({
        iss: "https://issuer.example.test",
        aud: "hemlig-api",
        sub: "external-subject",
        email: "admin@example.test",
      }),
      config,
    );

    expect(actor).toEqual({
      type: "human",
      id: "external-subject",
      email: "admin@example.test",
    });
  });

  it("uses aud in preference to client_id when both claims are present", () => {
    expect(() =>
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "another-api",
          client_id: "hemlig-api",
          sub: "external-subject",
        }),
        config,
      ),
    ).toThrow("does not satisfy");
  });

  it("requires the configured administrator scope in either standard claim", () => {
    const scoped = { ...config, adminJwtScope: "hemlig.admin" };
    expect(() =>
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
        }),
        scoped,
      ),
    ).toThrow("does not satisfy");
    expect(
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
          scp: "other hemlig.admin",
        }),
        scoped,
      ),
    ).toMatchObject({ id: "external-subject" });
  });

  it("requires the configured administrator role when one is set", () => {
    const roleScoped = { ...config, adminJwtRole: "Hemlig.Administrator" };
    expect(() =>
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
        }),
        roleScoped,
      ),
    ).toThrow("does not satisfy");
    expect(
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
          roles: ["Reader", "Hemlig.Administrator"],
        }),
        roleScoped,
      ),
    ).toMatchObject({ id: "external-subject" });
  });

  it("accepts a JSON-encoded role array from an HTTP API JWT integration", () => {
    const roleScoped = { ...config, adminJwtRole: "Hemlig.Administrator" };
    expect(
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
          roles: '["Hemlig.Administrator"]',
        }),
        roleScoped,
      ),
    ).toMatchObject({ id: "external-subject" });
  });

  it("accepts a delimiter-encoded role array from an HTTP API JWT integration", () => {
    const roleScoped = { ...config, adminJwtRole: "Hemlig.Administrator" };
    expect(
      humanActorFromEvent(
        jwtEvent({
          iss: "https://issuer.example.test",
          aud: "hemlig-api",
          sub: "external-subject",
          roles: "[Hemlig.Administrator]",
        }),
        roleScoped,
      ),
    ).toMatchObject({ id: "external-subject" });
  });
});

describe("consumerActorFromEvent", () => {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = "01";
  certificate.validity.notBefore = new Date("2026-01-01T00:00:00Z");
  certificate.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  certificate.setSubject([{ name: "commonName", value: "agent" }]);
  certificate.setIssuer([{ name: "commonName", value: "agent" }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(certificate);
  const fingerprint = createHash("sha256")
    .update(
      Buffer.from(
        forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes(),
        "binary",
      ),
    )
    .digest("hex");
  const now = new Date("2026-06-01T00:00:00Z");
  const event = (clientCertPem?: string): APIGatewayProxyEventV2WithJWTAuthorizer =>
    ({
      requestContext: {
        authentication:
          clientCertPem === undefined ? undefined : { clientCert: { clientCertPem } },
      },
    }) as unknown as APIGatewayProxyEventV2WithJWTAuthorizer;
  const identity = (overrides: Partial<IdentityRecord> = {}): IdentityRecord => ({
    pk: `IDENTITY#${fingerprint}`,
    sk: "PROFILE",
    fingerprint,
    consumerId: "agent-a",
    environment: "prod",
    kind: "api",
    status: "ACTIVE",
    notBefore: "2026-01-01T00:00:00.000Z",
    notAfter: "2027-01-01T00:00:00.000Z",
    ...overrides,
  });
  const lookup = (record?: IdentityRecord) => ({
    getIdentity: jest.fn(async () => record),
  });

  it("returns the certificate-fingerprint actor for an active identity", async () => {
    await expect(
      consumerActorFromEvent(event(pem), lookup(identity()), now),
    ).resolves.toEqual({
      type: "consumer",
      id: fingerprint,
      consumerId: "agent-a",
      environment: "prod",
    });
  });

  it.each([
    ["a missing certificate", event(), identity()],
    ["a malformed certificate", event("not a certificate"), identity()],
    ["an unknown identity", event(pem), undefined],
    ["a revoked identity", event(pem), identity({ status: "REVOKED" })],
    ["an expired identity", event(pem), identity({ notAfter: "2026-02-01T00:00:00.000Z" })],
  ])("rejects %s with identity_not_active", async (_name, request, record) => {
    await expect(
      consumerActorFromEvent(request, lookup(record), now),
    ).rejects.toMatchObject({ statusCode: 403, code: "identity_not_active" });
  });
});
