import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";

jest.mock("../app", () => ({
  createApplication: jest.fn(() => ({})),
}));

jest.mock("../aws/config", () => ({
  loadConfig: jest.fn(() => ({})),
}));

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
