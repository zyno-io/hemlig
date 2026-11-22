import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";

const mockAuditWrite = jest.fn(async () => undefined);

jest.mock("../app", () => ({
  createApplication: jest.fn(() => ({ audit: { write: mockAuditWrite } })),
}));

jest.mock("../aws/config", () => ({
  loadConfig: jest.fn(() => ({})),
}));

import { createErrorResponder } from "./request";
import { withErrorResponse } from "./shared";

const event = (requestId: string): APIGatewayProxyEventV2 =>
  ({ requestContext: { requestId } }) as APIGatewayProxyEventV2;

describe("withErrorResponse", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("logs an unexpected failure with its correlation ID but no request data", async () => {
    const log = jest.spyOn(console, "error").mockImplementation();

    await withErrorResponse(event("request-123"), async () => {
      throw new Error("temporary backend failure");
    });

    expect(log).toHaveBeenCalledWith(
      "Hemlig request failed unexpectedly",
      expect.objectContaining({
        correlationId: "request-123",
        message: "temporary backend failure",
      }),
    );
  });

  it("does not log expected API errors as server failures", async () => {
    const log = jest.spyOn(console, "error").mockImplementation();

    await withErrorResponse(event("request-456"), async () => {
      throw new ApiError(403, "forbidden", "Denied.");
    });

    expect(log).not.toHaveBeenCalled();
  });
});

describe("failure audit reason", () => {
  const actor = { type: "human" as const, id: "admin" };
  const context = { actor, operation: "test.operation" };

  beforeEach(() => {
    mockAuditWrite.mockClear();
  });
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("uses the error's safeReason", async () => {
    await withErrorResponse(event("r1"), async (_app, _id, setAuditContext) => {
      setAuditContext(context);
      throw new ApiError(403, "issuance_denied", "No.", "name_not_permitted");
    });
    expect(mockAuditWrite).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "failed",
        reasonCode: "name_not_permitted",
      }),
    );
  });

  it("lets an explicit reasonCode win", async () => {
    await withErrorResponse(event("r2"), async (_app, _id, setAuditContext) => {
      setAuditContext({ ...context, reasonCode: "identity_not_active" });
      throw new ApiError(403, "identity_not_active", "No.", "something_else");
    });
    expect(mockAuditWrite).toHaveBeenCalledWith(
      expect.objectContaining({ reasonCode: "identity_not_active" }),
    );
  });

  it("falls back to request_failed without a safeReason or for other errors", async () => {
    jest.spyOn(console, "error").mockImplementation();
    await withErrorResponse(event("r3"), async (_app, _id, setAuditContext) => {
      setAuditContext(context);
      throw new ApiError(403, "forbidden", "No.");
    });
    await withErrorResponse(event("r4"), async (_app, _id, setAuditContext) => {
      setAuditContext(context);
      throw new Error("boom");
    });
    expect(mockAuditWrite).toHaveBeenCalledTimes(2);
    for (const call of mockAuditWrite.mock.calls as unknown as [
      { reasonCode: string },
    ][]) {
      expect(call[0].reasonCode).toBe("request_failed");
    }
  });
});

describe("createErrorResponder", () => {
  it("audits through the factory's own audit writer", async () => {
    const write = jest.fn(async () => ({}) as never);
    const respond = createErrorResponder(() => ({ audit: { write } }));
    const result = await respond(
      event("r5"),
      async (app, _id, setAuditContext) => {
        expect(app.audit.write).toBe(write);
        setAuditContext({
          actor: { type: "consumer", id: "fp" },
          operation: "pki.test",
        });
        throw new ApiError(404, "not_found", "Missing.", "missing");
      },
    );
    expect(result.statusCode).toBe(404);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({ operation: "pki.test", reasonCode: "missing" }),
    );
    expect(mockAuditWrite).not.toHaveBeenCalled();
  });
});
