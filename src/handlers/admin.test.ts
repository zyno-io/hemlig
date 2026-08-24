import { GenerateDataKeyCommand, type KMSClient } from "@aws-sdk/client-kms";
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import type { Application } from "../app";
import type { AwsClients } from "../aws/clients";
import type { AppConfig } from "../aws/config";
import { badRequest, conflict, notFound } from "../domain/errors";
import type { IssuerRecord } from "../domain/types";
import { errorResponse } from "../http/responses";
import type { DynamoRepository } from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import type { AuditWriter } from "../services/audit";
import type { ConsumerService } from "../services/consumers";
import type { CursorService } from "../services/cursor";
import type { EnvironmentService } from "../services/environments";
import type { FolderService } from "../services/folders";
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
    headers,
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
      agents: {} as Application["agents"],
      cursors: {} as unknown as CursorService,
      environments: {} as unknown as EnvironmentService,
      folders: {} as unknown as FolderService,
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
    const repository = {
      listSecrets,
      searchSecrets,
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
      agents: {} as Application["agents"],
      cursors: {
        encode: jest.fn(() => "opaque-cursor"),
        decode: jest.fn(() => undefined),
      } as unknown as CursorService,
      environments: {
        list: listEnvironments,
        create: createEnvironment,
        require: requireEnvironment,
      } as unknown as EnvironmentService,
      folders: {} as unknown as FolderService,
      secrets: {} as unknown as SecretService,
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
    );
    expect(listSecrets).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body as string) as Record<string, unknown>;
    expect(body.truncated).toBe(true);
    expect(body.nextCursor).toBeUndefined();
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

describe("/v1/admin/folders", () => {
  let fakeApp: Application;
  let createFolder: jest.Mock;
  let removeFolder: jest.Mock;

  beforeEach(() => {
    createFolder = jest.fn(
      async (input: {
        environment: string;
        path: unknown;
        actor: unknown;
      }) => ({
        environment: input.environment,
        path: input.path,
        createdAt: "2026-08-23T00:00:00.000Z",
        createdBy: { type: "human", id: "admin-1" },
      }),
    );
    removeFolder = jest.fn(async () => undefined);
    fakeApp = {
      config,
      repository: {} as unknown as DynamoRepository,
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
      agents: {} as Application["agents"],
      cursors: {} as unknown as CursorService,
      environments: {} as unknown as EnvironmentService,
      folders: {
        create: createFolder,
        remove: removeFolder,
      } as unknown as FolderService,
      secrets: {} as unknown as SecretService,
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

  it("creates a folder and returns 201", async () => {
    const event = {
      ...buildEvent("POST", "/v1/admin/folders"),
      body: JSON.stringify({ environment: "prod", path: "payments/adyen" }),
    };

    const response = await handler(event);

    expect(createFolder).toHaveBeenCalledWith({
      environment: "prod",
      path: "payments/adyen",
      actor: { type: "human", id: "admin-1" },
    });
    expect(response.statusCode).toBe(201);
    expect(JSON.parse(response.body as string)).toMatchObject({
      environment: "prod",
      path: "payments/adyen",
    });
  });

  it("returns 409 when the folder already exists or the registry is full", async () => {
    createFolder.mockRejectedValueOnce(
      conflict("The folder already exists or the registry is full."),
    );
    const event = {
      ...buildEvent("POST", "/v1/admin/folders"),
      body: JSON.stringify({ environment: "prod", path: "payments" }),
    };

    const response = await handler(event);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.body as string)).toMatchObject({
      error: { code: "conflict" },
    });
  });

  it("rejects an unknown environment the same way other scoped routes do", async () => {
    createFolder.mockRejectedValueOnce(
      notFound("The requested environment is not configured."),
    );
    const event = {
      ...buildEvent("POST", "/v1/admin/folders"),
      body: JSON.stringify({ environment: "missing", path: "payments" }),
    };

    const response = await handler(event);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body as string)).toMatchObject({
      error: { code: "not_found" },
    });
  });

  it("rejects an invalid path", async () => {
    createFolder.mockRejectedValueOnce(
      badRequest(
        "path must be a lowercase slash-delimited path of at most 256 characters.",
      ),
    );
    const event = {
      ...buildEvent("POST", "/v1/admin/folders"),
      body: JSON.stringify({ environment: "prod", path: "Payments" }),
    };

    const response = await handler(event);

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body as string)).toMatchObject({
      error: { code: "bad_request" },
    });
  });

  it("deletes an empty folder and returns 204", async () => {
    const event = buildEvent(
      "DELETE",
      "/v1/admin/folders",
      {},
      { environment: "prod", path: "payments/adyen" },
    );

    const response = await handler(event);

    expect(removeFolder).toHaveBeenCalledWith({
      environment: "prod",
      path: "payments/adyen",
    });
    expect(response.statusCode).toBe(204);
  });

  it("returns 409 when the folder is not empty", async () => {
    removeFolder.mockRejectedValueOnce(
      conflict(
        "The folder is not empty: a secret exists at this path or nested beneath it.",
      ),
    );
    const event = buildEvent(
      "DELETE",
      "/v1/admin/folders",
      {},
      { environment: "prod", path: "payments" },
    );

    const response = await handler(event);

    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.body as string)).toMatchObject({
      error: { code: "conflict" },
    });
  });

  it("returns 404 when the path is only a derived folder, not a record", async () => {
    removeFolder.mockRejectedValueOnce(
      notFound("No folder record exists at this path."),
    );
    const event = buildEvent(
      "DELETE",
      "/v1/admin/folders",
      {},
      { environment: "prod", path: "payments" },
    );

    const response = await handler(event);

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body as string)).toMatchObject({
      error: { code: "not_found" },
    });
  });
});
