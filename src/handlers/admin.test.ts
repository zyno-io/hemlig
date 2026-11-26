import { bearerFor, testExp } from "../auth/test-support";
import { GenerateDataKeyCommand, type KMSClient } from "@aws-sdk/client-kms";
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import type { Application } from "../app";
import type { AwsClients } from "../aws/clients";
import type { AppConfig } from "../aws/config";
import type { IssuerRecord } from "../domain/types";
import { errorResponse } from "../http/responses";
import type { DynamoRepository } from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import type { AuditWriter } from "../services/audit";
import type { ConsumerService } from "../services/consumers";
import type { CursorService } from "../services/cursor";
import type { EnvironmentService } from "../services/environments";
import type { SecretService } from "../services/secrets";

// admin.ts resolves its Application through getApplication(), a module-level
// singleton in ./shared. Replacing withErrorResponse here -- rather than
// mocking ../app/../aws/config to feed that singleton -- lets each test swap
// in a fresh fake Application without fighting that caching.
jest.mock("./shared", () => ({ withErrorResponse: jest.fn() }));

/* eslint-disable @typescript-eslint/no-var-requires */
const { withErrorResponse } = jest.requireMock("./shared") as {
  withErrorResponse: jest.Mock;
};
import { handler } from "./admin";

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

const buildEvent = (
  method: string,
  rawPath: string,
  headers: Record<string, string> = {},
  queryStringParameters?: Record<string, string>,
): APIGatewayProxyEventV2 =>
  ({
    rawPath,
    headers: {
      authorization: bearerFor({
        iss: config.adminJwtIssuer,
        aud: config.adminJwtAudience,
        sub: "admin-1",
      }),
      ...headers,
    },
    queryStringParameters,
    requestContext: {
      http: { method, sourceIp: "203.0.113.10" },
      requestId: "req-1",
      authorizer: {
        jwt: {
          claims: {
            iss: config.adminJwtIssuer,
            aud: config.adminJwtAudience,
            sub: "admin-1",
            exp: testExp,
          },
        },
      },
    },
  }) as unknown as APIGatewayProxyEventV2;

describe("POST /v1/admin/issuer", () => {
  let storedIssuer: IssuerRecord | undefined;
  let fakeApp: Application;

  beforeEach(() => {
    storedIssuer = undefined;
    const repository = {
      getIssuer: jest.fn(async () => storedIssuer),
      createIssuer: jest.fn(async (issuer: IssuerRecord) => {
        storedIssuer = storedIssuer ?? issuer;
        return storedIssuer;
      }),
      ensureIssuerTruststoreRoot: jest.fn(async () => undefined),
      getTruststoreState: jest.fn(async () => undefined),
      markAuditSucceeded: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    const kms = {
      send: jest.fn(async (command: unknown) => {
        if (command instanceof GenerateDataKeyCommand) {
          return {
            Plaintext: Buffer.alloc(32, 9),
            CiphertextBlob: Buffer.from("wrapped-data-key"),
          };
        }
        throw new Error("Unexpected KMS command");
      }),
    } as unknown as KMSClient;
    fakeApp = {
      config,
      repository,
      objects: {} as unknown as ObjectStore,
      audit: {
        write: jest.fn(async (event: Record<string, unknown>) => ({
          eventId: "evt-1",
          at: "2026-08-23T00:00:00.000Z",
          ...event,
        })),
      } as unknown as AuditWriter,
      auditQueries: {} as Application["auditQueries"],
      agentGrants: {} as Application["agentGrants"],
      agentIdentities: {} as Application["agentIdentities"],
      agentNotifications: {} as Application["agentNotifications"],
      agents: {} as Application["agents"],
      agentSync: {} as Application["agentSync"],
      cursors: {} as unknown as CursorService,
      environments: {} as unknown as EnvironmentService,
      secrets: {} as unknown as SecretService,
      consumers: {} as unknown as ConsumerService,
      clients: { kms } as unknown as AwsClients,
    };
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          app: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(fakeApp, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );
  });

  it("creates the issuing root and returns 201 without leaking the encrypted key", async () => {
    const response = await handler(
      buildEvent("POST", "/v1/admin/issuer", {
        "idempotency-key": "first-request-key",
      }),
    );

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.body as string) as Record<string, unknown>;
    expect(typeof body.rootFingerprint).toBe("string");
    expect(body.encryptedPrivateKey).toBeUndefined();
    expect(response.body as string).not.toContain("encryptedPrivateKey");
  });

  it("is idempotent: a second call returns 200 for the already-created root and still never leaks the key", async () => {
    const first = await handler(
      buildEvent("POST", "/v1/admin/issuer", {
        "idempotency-key": "first-request-key",
      }),
    );
    const second = await handler(
      buildEvent("POST", "/v1/admin/issuer", {
        "idempotency-key": "second-request-key",
      }),
    );

    expect(second.statusCode).toBe(200);
    const firstBody = JSON.parse(first.body as string) as Record<
      string,
      unknown
    >;
    const secondBody = JSON.parse(second.body as string) as Record<
      string,
      unknown
    >;
    expect(secondBody.rootFingerprint).toBe(firstBody.rootFingerprint);
    expect(secondBody.encryptedPrivateKey).toBeUndefined();
    expect(second.body as string).not.toContain("encryptedPrivateKey");
  });
});

describe("GET /v1/admin/secrets", () => {
  let fakeApp: Application;
  let listSecrets: jest.Mock;
  let searchSecrets: jest.Mock;
  let listEnvironments: jest.Mock;
  let createEnvironment: jest.Mock;
  let requireEnvironment: jest.Mock;
  let archiveSecret: jest.Mock;
  let getArchivedControlRevision: jest.Mock;

  beforeEach(() => {
    listSecrets = jest.fn(async () => ({
      secrets: [],
      nextCursor: JSON.stringify({ pk: "SECRET#x", sk: "HEAD" }),
    }));
    searchSecrets = jest.fn(async () => ({ secrets: [], truncated: true }));
    listEnvironments = jest.fn(async () => []);
    createEnvironment = jest.fn(async (input: { readonly name: string }) => ({
      name: input.name,
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
    }));
    requireEnvironment = jest.fn(async () => ({
      name: "test",
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
    }));
    archiveSecret = jest.fn(async (input) => ({
      schemaVersion: 1,
      secretUid: "sec-payments",
      secretId: input.secretId,
      controlVersionId: "ctl-archived",
      environment: input.environment,
      state: "ARCHIVED",
      createdAt: "2026-08-25T00:00:00.000Z",
      createdBy: input.actor,
      metadata: {},
      acl: [],
    }));
    getArchivedControlRevision = jest.fn(async (environment, secretUid) => ({
      schemaVersion: 1,
      secretUid,
      secretId: "payments-api",
      controlVersionId: "ctl-archived",
      environment,
      state: "ARCHIVED",
      createdAt: "2026-08-25T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
      metadata: {},
      acl: [],
    }));
    const repository = {
      listSecrets,
      searchSecrets,
      markAuditSucceeded: jest.fn(async () => undefined),
    } as unknown as DynamoRepository;
    fakeApp = {
      config,
      repository,
      objects: {} as unknown as ObjectStore,
      audit: {
        write: jest.fn(async (event: Record<string, unknown>) => ({
          eventId: "evt-1",
          at: "2026-08-23T00:00:00.000Z",
          ...event,
        })),
      } as unknown as AuditWriter,
      auditQueries: {} as Application["auditQueries"],
      agentGrants: {} as Application["agentGrants"],
      agentIdentities: {} as Application["agentIdentities"],
      agentNotifications: {} as Application["agentNotifications"],
      agents: {} as Application["agents"],
      agentSync: {} as Application["agentSync"],
      cursors: {
        encode: jest.fn(() => "opaque-cursor"),
        decode: jest.fn(() => undefined),
      } as unknown as CursorService,
      environments: {
        list: listEnvironments,
        create: createEnvironment,
        require: requireEnvironment,
      } as unknown as EnvironmentService,
      secrets: {
        archive: archiveSecret,
        getArchivedControlRevision,
      } as unknown as SecretService,
      consumers: {} as unknown as ConsumerService,
      clients: {} as unknown as AwsClients,
    };
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          app: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(fakeApp, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );
  });

  it("returns a bounded, complete-or-truncated page with no nextCursor when q is present", async () => {
    const event = buildEvent(
      "GET",
      "/v1/admin/secrets",
      {},
      { environment: "test", pathPrefix: "payments", q: "stripe" },
    );

    const response = await handler(event);

    expect(searchSecrets).toHaveBeenCalledWith(
      "test",
      "payments",
      {},
      "stripe",
      false,
    );
    expect(listSecrets).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body as string) as Record<string, unknown>;
    expect(body.truncated).toBe(true);
    expect(body.nextCursor).toBeUndefined();
  });

  it("queries only the archive catalog when archived=true", async () => {
    const response = await handler(
      buildEvent(
        "GET",
        "/v1/admin/secrets",
        {},
        { environment: "test", q: "stripe", archived: "true" },
      ),
    );

    expect(searchSecrets).toHaveBeenCalledWith(
      "test",
      undefined,
      {},
      "stripe",
      true,
    );
    expect(response.statusCode).toBe(200);
  });

  it("keeps the existing cursor-paginated behavior unchanged when q is absent", async () => {
    const event = buildEvent(
      "GET",
      "/v1/admin/secrets",
      {},
      { environment: "test" },
    );

    const response = await handler(event);

    expect(listSecrets).toHaveBeenCalled();
    expect(searchSecrets).not.toHaveBeenCalled();
    const body = JSON.parse(response.body as string) as Record<string, unknown>;
    expect(body.nextCursor).toBe("opaque-cursor");
    expect(body.truncated).toBeUndefined();
  });

  it("archives by name with an ETag and returns the immutable archived revision", async () => {
    const response = await handler(
      buildEvent(
        "POST",
        "/v1/admin/secrets/payments-api/archive",
        { "idempotency-key": "archive-payments-api", "if-match": "ctl-1" },
        { environment: "test" },
      ),
    );

    expect(archiveSecret).toHaveBeenCalledWith({
      secretId: "payments-api",
      environment: "test",
      expectedControlVersionId: "ctl-1",
      actor: { type: "human", id: "admin-1" },
      idempotencyKey: "archive-payments-api",
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers?.etag).toBe("ctl-archived");
    expect(JSON.parse(response.body as string)).toMatchObject({
      state: "ARCHIVED",
      acl: [],
    });
  });

  it("reads archive details by UID instead of its reusable secret ID", async () => {
    const response = await handler(
      buildEvent(
        "GET",
        "/v1/admin/archived-secrets/sec-payments-123",
        {},
        { environment: "test" },
      ),
    );

    expect(getArchivedControlRevision).toHaveBeenCalledWith(
      "test",
      "sec-payments-123",
    );
    expect(response.statusCode).toBe(200);
  });

  it("lists administrator-defined environments and creates a new one", async () => {
    listEnvironments.mockResolvedValueOnce([
      {
        name: "prod",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      },
    ]);
    const listResponse = await handler(
      buildEvent("GET", "/v1/admin/environments"),
    );
    const createEvent = {
      ...buildEvent("POST", "/v1/admin/environments"),
      body: JSON.stringify({ name: "staging" }),
    };
    const createResponse = await handler(createEvent);

    expect(listResponse.statusCode).toBe(200);
    expect(JSON.parse(listResponse.body as string)).toMatchObject({
      environments: [{ name: "prod" }],
    });
    expect(createEnvironment).toHaveBeenCalledWith({
      name: "staging",
      actor: { type: "human", id: "admin-1" },
    });
    expect(createResponse.statusCode).toBe(201);
    expect(JSON.parse(createResponse.body as string)).toMatchObject({
      name: "staging",
    });
  });
});

describe("slash-separated admin secret IDs", () => {
  it("decodes a slash-separated ID from the request path", async () => {
    const getControlRevision = jest.fn(async (environment, secretId) => ({
      schemaVersion: 1,
      secretId,
      controlVersionId: "ctl-1",
      environment,
      state: "ACTIVE",
      createdAt: "2026-08-23T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
      metadata: {},
      acl: [],
    }));
    const app = {
      config,
      audit: {
        write: jest.fn(async (event: Record<string, unknown>) => ({
          eventId: "evt-1",
          at: "2026-08-23T00:00:00.000Z",
          ...event,
        })),
      },
      secrets: { getControlRevision },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler(
      buildEvent(
        "GET",
        "/v1/admin/secrets/payments%2Fstripe%2Fapi-key",
        {},
        { environment: "prod" },
      ),
    );

    expect(response.statusCode).toBe(200);
    expect(getControlRevision).toHaveBeenCalledWith(
      "prod",
      "payments/stripe/api-key",
    );
  });

  it("lists agent-managed ACL consumers on the admin control response", async () => {
    const app = {
      config,
      audit: { write: jest.fn(async () => ({})) },
      repository: {
        getAgentGrantForConsumer: jest.fn(async (consumerId: string) =>
          consumerId === "agent-consumer" ? { grantId: "grant-1" } : undefined,
        ),
      },
      secrets: {
        getControlRevision: jest.fn(async (environment, secretId) => ({
          schemaVersion: 1,
          secretId,
          controlVersionId: "ctl-1",
          environment,
          state: "ACTIVE",
          metadata: {},
          acl: [
            { consumerId: "human-consumer", permissions: ["read"] },
            { consumerId: "agent-consumer", permissions: ["read"] },
          ],
        })),
      },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        _event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => action(app, "corr-1", () => undefined),
    );

    const response = await handler(
      buildEvent(
        "GET",
        "/v1/admin/secrets/payments-api",
        {},
        { environment: "prod" },
      ),
    );

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body as string)).toMatchObject({
      agentManagedConsumerIds: ["agent-consumer"],
    });
  });

  it("omits agentManagedConsumerIds from PUT and payload PUT responses", async () => {
    const control = {
      secretId: "payments-api",
      controlVersionId: "ctl-2",
      environment: "prod",
      state: "ACTIVE",
      metadata: {},
      acl: [{ consumerId: "agent-consumer", permissions: ["read"] }],
    };
    const getAgentGrantForConsumer = jest.fn();
    const app = {
      config,
      audit: { write: jest.fn(async () => ({ eventId: "evt-1" })) },
      repository: {
        markAuditSucceeded: jest.fn(async () => undefined),
        getAgentGrantForConsumer,
      },
      secrets: { update: jest.fn(async () => control) },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        _event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => action(app, "corr-1", () => undefined),
    );
    const headers = { "idempotency-key": "key-12345678", "if-match": "ctl-1" };
    const query = { environment: "prod" };
    const withBody = (path: string, body: unknown) => ({
      ...buildEvent("PUT", path, headers, query),
      body: JSON.stringify(body),
    });

    const put = await handler(
      withBody("/v1/admin/secrets/payments-api", { acl: [] }),
    );
    const payload = await handler(
      withBody("/v1/admin/secrets/payments-api/payload", {
        payload: { value: { encoding: "utf8", value: "x" } },
      }),
    );

    expect(put.statusCode).toBe(200);
    expect(payload.statusCode).toBe(200);
    expect(JSON.parse(put.body as string)).not.toHaveProperty(
      "agentManagedConsumerIds",
    );
    expect(JSON.parse(payload.body as string)).not.toHaveProperty(
      "agentManagedConsumerIds",
    );
    expect(getAgentGrantForConsumer).not.toHaveBeenCalled();
  });

  it("validates preserveAgentAcl strictly and keeps the 40-grant cap on the submitted ACL", async () => {
    const update = jest.fn();
    const app = {
      config,
      audit: { write: jest.fn(async () => ({ eventId: "evt-1" })) },
      repository: { markAuditSucceeded: jest.fn() },
      secrets: { update },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        _event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );
    const put = (body: unknown) =>
      handler({
        ...buildEvent(
          "PUT",
          "/v1/admin/secrets/payments-api",
          { "idempotency-key": "key-12345678", "if-match": "ctl-1" },
          { environment: "prod" },
        ),
        body: JSON.stringify(body),
      });
    const rows = (count: number) =>
      Array.from({ length: count }, (_, i) => ({
        consumerId: `human-${i}`,
        permissions: ["read"],
      }));

    expect((await put({ acl: [], preserveAgentAcl: "yes" })).statusCode).toBe(
      400,
    );
    expect(
      (await put({ acl: rows(41), preserveAgentAcl: true })).statusCode,
    ).toBe(400);
    expect(update).not.toHaveBeenCalled();
  });

  it("does not treat the payload route suffix as part of the secret ID", async () => {
    const readAdminPayload = jest.fn(async (environment, secretId) => ({
      controlVersionId: "ctl-1",
      payloadVersionId: "pvl-1",
      environment,
      secretId,
      payload: { value: { encoding: "utf8", value: "test" } },
    }));
    const app = {
      config,
      audit: {
        write: jest.fn(async (event: Record<string, unknown>) => ({
          eventId: "evt-1",
          at: "2026-08-23T00:00:00.000Z",
          ...event,
        })),
      },
      secrets: { readAdminPayload },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler(
      buildEvent(
        "GET",
        "/v1/admin/secrets/platform%2Fstorage%2Fcephfs%2Ftrusted/payload",
        {},
        { environment: "staging" },
      ),
    );

    expect(response.statusCode).toBe(200);
    expect(readAdminPayload).toHaveBeenCalledWith(
      "staging",
      "platform/storage/cephfs/trusted",
    );
  });
});

describe("AgentGrant exact secret permissions", () => {
  it("forwards paired secret permissions and never reintroduces prefix fields", async () => {
    const create = jest.fn(
      async (input: {
        readonly consumerId: string;
        readonly environment: string;
        readonly capabilities: readonly string[];
        readonly secretGrants: readonly {
          readonly secretId: string;
          readonly permissions: readonly string[];
        }[];
        readonly actor: unknown;
      }) => ({
        grantId: "grant-payments",
        consumerId: input.consumerId,
        environment: input.environment,
        capabilities: input.capabilities,
        secretGrants: input.secretGrants.map((scope) => ({
          ...scope,
          secretUid: "sec-payments-stripe-api-key",
        })),
        status: "PENDING",
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: input.actor,
      }),
    );
    const app = {
      config,
      audit: {
        write: jest.fn(async (event: Record<string, unknown>) => ({
          eventId: "evt-1",
          at: "2026-08-23T00:00:00.000Z",
          ...event,
        })),
      },
      agentGrants: { create },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler({
      ...buildEvent("POST", "/v1/admin/agent-grants"),
      body: JSON.stringify({
        consumerId: "payments-agent",
        environment: "prod",
        capabilities: ["read"],
        secretGrants: [
          { secretId: "payments/stripe-api-key", permissions: ["read"] },
        ],
      }),
    });

    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        secretGrants: [
          { secretId: "payments/stripe-api-key", permissions: ["read"] },
        ],
      }),
    );
    const body = JSON.parse(response.body as string) as Record<string, unknown>;
    expect(body).toMatchObject({
      secretGrants: [
        {
          secretId: "payments/stripe-api-key",
          secretUid: "sec-payments-stripe-api-key",
          permissions: ["read"],
        },
      ],
    });
    expect(body.readSecretIdPrefixes).toBeUndefined();
    expect(body.writeSecretIdPrefixes).toBeUndefined();
  });
});

describe("consumer secret grant management", () => {
  it("includes an attached AgentGrant in consumer detail", async () => {
    const getAgentGrantForConsumer = jest.fn(async () => ({
      grantId: "grant-prod-east",
      consumerId: "prod-east",
      environment: "prod",
      capabilities: ["read", "write"],
      secretGrants: [
        {
          secretId: "platform/database/postgres",
          secretUid: "sec-postgres",
          permissions: ["read", "write"],
        },
      ],
      status: "ACTIVE",
      createdAt: "2026-08-25T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
    }));
    const app = {
      config,
      repository: {
        getConsumer: jest.fn(async () => ({
          consumerId: "prod-east",
          environment: "prod",
          status: "ACTIVE",
          subjectUri: "spiffe://hemlig/consumer/prod-east",
          createdAt: "2026-08-25T00:00:00.000Z",
          createdBy: { type: "human", id: "admin-1" },
        })),
        countActiveConsumerApiIdentities: jest.fn(async () => 1),
        getIssuer: jest.fn(async () => undefined),
        getAgentGrantForConsumer,
      },
      audit: { write: jest.fn(async () => undefined) },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler(
      buildEvent("GET", "/v1/admin/consumers/prod-east"),
    );

    expect(response.statusCode).toBe(200);
    expect(getAgentGrantForConsumer).toHaveBeenCalledWith("prod-east");
    expect(JSON.parse(response.body as string)).toMatchObject({
      agentGrant: {
        grantId: "grant-prod-east",
        secretGrants: [
          {
            secretId: "platform/database/postgres",
            secretUid: "sec-postgres",
            permissions: ["read", "write"],
          },
        ],
      },
    });
  });

  it("lists a consumer's effective secret ACL grants", async () => {
    const listConsumerSecretGrants = jest.fn(async () => ({
      grants: [
        {
          secretUid: "sec-postgres",
          secretId: "platform/database/postgres",
          permissions: ["read"],
          controlVersionId: "ctl-postgres",
          state: "ACTIVE",
        },
      ],
    }));
    const app = {
      config,
      repository: {
        getConsumer: jest.fn(async () => ({
          consumerId: "prod-east",
          environment: "prod",
        })),
        listConsumerSecretGrants,
      },
      cursors: {},
      audit: { write: jest.fn(async () => undefined) },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler(
      buildEvent("GET", "/v1/admin/consumers/prod-east/grants"),
    );

    expect(response.statusCode).toBe(200);
    expect(listConsumerSecretGrants).toHaveBeenCalledWith(
      "prod-east",
      "prod",
      undefined,
    );
    expect(JSON.parse(response.body as string)).toMatchObject({
      consumerId: "prod-east",
      environment: "prod",
      grants: [
        expect.objectContaining({
          secretUid: "sec-postgres",
          secretId: "platform/database/postgres",
        }),
      ],
    });
  });

  it("revokes an encoded secret ID through the dedicated consumer grant route", async () => {
    const revokeConsumerSecretGrant = jest.fn(async () => ({
      schemaVersion: 1,
      secretUid: "sec-postgres",
      secretId: "platform/database/postgres",
      controlVersionId: "ctl-revoked",
      environment: "prod",
      state: "ACTIVE",
      createdAt: "2026-08-25T00:00:00.000Z",
      createdBy: { type: "human", id: "admin-1" },
      metadata: {},
      acl: [],
    }));
    const app = {
      config,
      repository: { markAuditSucceeded: jest.fn(async () => undefined) },
      secrets: { revokeConsumerSecretGrant },
      audit: {
        write: jest.fn(async () => ({ eventId: "evt-1" })),
      },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );

    const response = await handler(
      buildEvent(
        "DELETE",
        "/v1/admin/consumers/prod-east/grants/platform%2Fdatabase%2Fpostgres",
        { "idempotency-key": "revoke-consumer-grant" },
      ),
    );

    expect(response.statusCode).toBe(200);
    expect(revokeConsumerSecretGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        consumerId: "prod-east",
        secretId: "platform/database/postgres",
        idempotencyKey: "revoke-consumer-grant",
      }),
    );
  });
});

describe("admin API identity IoT synchronization", () => {
  const fingerprint = "a".repeat(64);
  const issued = {
    consumerId: "prod-east",
    environment: "prod",
    rootFingerprint: "root",
    apiFingerprint: fingerprint,
    apiCertificatePem: "pem-new",
    status: "ACTIVE" as const,
    identityStatus: "ACTIVE" as const,
    shouldWriteTerminalAudit: true,
  };

  const setup = (grantStatus: "ACTIVE" | "PENDING" | undefined) => {
    const provision = jest.fn(async () => undefined);
    const revoke = jest.fn(async () => undefined);
    const rotateApiIdentity = jest.fn(async () => issued);
    const revokeApiIdentity = jest.fn(async () => ({
      ...issued,
      status: "REVOKED" as const,
    }));
    const app = {
      config,
      repository: {
        getAgentGrantForConsumer: jest.fn(async () =>
          grantStatus === undefined ? undefined : { status: grantStatus },
        ),
        markAuditSucceeded: jest.fn(async () => undefined),
        getIdentity: jest.fn(async () => ({ status: "ACTIVE" })),
      },
      consumers: { rotateApiIdentity, revokeApiIdentity },
      agentNotifications: { provision, revoke },
      audit: { write: jest.fn(async () => ({ eventId: "evt-1" })) },
    } as unknown as Application;
    withErrorResponse.mockImplementation(
      async (
        event: APIGatewayProxyEventV2,
        action: (
          application: Application,
          correlationId: string,
          setAuditContext: (context: unknown) => void,
        ) => Promise<APIGatewayProxyStructuredResultV2>,
      ) => {
        try {
          return await action(app, "corr-1", () => undefined);
        } catch (error) {
          return errorResponse(error, "corr-1");
        }
      },
    );
    return { app, provision, revoke, rotateApiIdentity, revokeApiIdentity };
  };

  const issue = () => {
    const event = buildEvent(
      "POST",
      "/v1/admin/consumers/prod-east/api-identities",
      { "idempotency-key": "idem-123456" },
    );
    (event as { body?: string }).body = JSON.stringify({
      apiCertificateSigningRequestPem: "csr",
    });
    return handler(event);
  };
  const revokeCall = () =>
    handler(
      buildEvent(
        "DELETE",
        `/v1/admin/consumers/prod-east/api-identities/${fingerprint}`,
        { "idempotency-key": "idem-654321" },
      ),
    );

  it("registers an admin-issued leaf of an active agent with IoT", async () => {
    const { provision, app } = setup("ACTIVE");
    const response = await issue();
    expect(response.statusCode).toBe(201);
    expect(provision).toHaveBeenCalledWith({
      consumerId: "prod-east",
      certificateFingerprint: fingerprint,
      certificatePem: "pem-new",
    });
    // IoT registration precedes the terminal audit.
    const auditOrders = (app.audit.write as jest.Mock).mock.invocationCallOrder;
    expect(provision.mock.invocationCallOrder[0]).toBeLessThan(
      auditOrders[auditOrders.length - 1] as number,
    );
  });

  it("does not register leaves of non-agent or not-yet-active agents", async () => {
    for (const status of [undefined, "PENDING" as const]) {
      const { provision } = setup(status);
      expect((await issue()).statusCode).toBe(201);
      expect(provision).not.toHaveBeenCalled();
    }
  });

  it("registers again on an idempotent replay", async () => {
    const { provision, rotateApiIdentity } = setup("ACTIVE");
    rotateApiIdentity.mockResolvedValue({
      ...issued,
      shouldWriteTerminalAudit: false,
    });
    await issue();
    await issue();
    expect(provision).toHaveBeenCalledTimes(2);
  });

  it("revokes the IoT certificate if the identity was revoked mid-provision", async () => {
    const { app, revoke } = setup("ACTIVE");
    (app.repository.getIdentity as jest.Mock).mockResolvedValue({
      status: "REVOKED",
    });
    await issue();
    expect(revoke).toHaveBeenCalledWith(fingerprint);
  });

  it("re-applies IoT revocation for an already revoked identity", async () => {
    const { revoke, revokeApiIdentity } = setup("ACTIVE");
    revokeApiIdentity.mockResolvedValue({
      ...issued,
      status: "REVOKED" as const,
      shouldWriteTerminalAudit: true,
    });
    const response = await revokeCall();
    expect(response.statusCode).toBe(200);
    expect(revoke).toHaveBeenCalledWith(fingerprint);
  });

  it("fails the request when IoT registration fails", async () => {
    const { provision } = setup("ACTIVE");
    provision.mockRejectedValue(new Error("iot down"));
    expect((await issue()).statusCode).toBeGreaterThanOrEqual(500);
  });

  it("revokes the IoT certificate for any consumer, including replays", async () => {
    const { revoke, revokeApiIdentity } = setup(undefined);
    expect((await revokeCall()).statusCode).toBe(200);
    expect(revoke).toHaveBeenCalledWith(fingerprint);
    revokeApiIdentity.mockResolvedValue({
      ...issued,
      status: "REVOKED" as const,
      shouldWriteTerminalAudit: false,
    });
    await revokeCall();
    expect(revoke).toHaveBeenCalledTimes(2);
  });
});
