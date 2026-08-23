import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import type { Application } from "../app";
import type { AppConfig } from "../aws/config";
import { errorResponse } from "../http/responses";

jest.mock("./shared", () => ({ withErrorResponse: jest.fn() }));

/* eslint-disable @typescript-eslint/no-var-requires */
const { withErrorResponse } = jest.requireMock("./shared") as {
  withErrorResponse: jest.Mock;
};
import { handler } from "./audit-query";

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
  cursorHmacKey: Buffer.alloc(32, 1),
  adminJwtIssuer: "https://issuer.example.test",
  adminJwtAudience: "hemlig",
  adminActorSubjectClaim: "sub",
  maxPayloadBytes: 768000,
};

const buildEvent = (
  queryStringParameters?: Record<string, string>,
): APIGatewayProxyEventV2 =>
  ({
    rawPath: "/v1/admin/audit",
    headers: {},
    queryStringParameters,
    requestContext: {
      http: { method: "GET", sourceIp: "203.0.113.10" },
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

describe("GET /v1/admin/audit", () => {
  const list = jest.fn();
  const encode = jest.fn();
  const decode = jest.fn();
  const write = jest.fn();

  beforeEach(() => {
    list.mockReset();
    list.mockResolvedValue({
      date: "2026-08-23",
      events: [
        {
          eventId: "event-1",
          at: "2026-08-23T10:00:00.000Z",
          correlationId: "corr-previous",
          outcome: "succeeded",
          actor: { type: "human", id: "admin-1" },
          operation: "admin.get:/v1/admin/secrets",
        },
      ],
      nextContinuationToken: "s3-next",
    });
    encode.mockReset();
    encode.mockReturnValue("signed-next");
    decode.mockReset();
    decode.mockReturnValue(undefined);
    write.mockReset();
    write.mockResolvedValue({});
    const app = {
      config,
      audit: { write },
      auditQueries: { list },
      cursors: { encode, decode },
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
  });

  it("reads a signed, date-scoped archive page and records the read", async () => {
    const response = await handler(buildEvent({ date: "2026-08-23" }));

    expect(list).toHaveBeenCalledWith("2026-08-23", undefined);
    expect(encode).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "admin:audit:admin-1:2026-08-23",
        lastEvaluatedKey: { continuationToken: "s3-next" },
      }),
    );
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "attempted",
        operation: "adminget:/v1/admin/audit",
      }),
    );
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "succeeded",
        target: { date: "2026-08-23" },
      }),
    );
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body as string)).toMatchObject({
      date: "2026-08-23",
      nextCursor: "signed-next",
      events: [expect.objectContaining({ eventId: "event-1" })],
    });
  });

  it("rejects an invalid UTC date before reading the archive", async () => {
    const response = await handler(buildEvent({ date: "2026-02-30" }));

    expect(response.statusCode).toBe(400);
    expect(list).not.toHaveBeenCalled();
  });
});
