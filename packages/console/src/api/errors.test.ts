import { describe, expect, it } from "vitest";
import { ApiError, errorFromResponse } from "./errors";

const jsonResponse = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("error mapping", () => {
  it("treats a bare 401 as a gateway rejection with no envelope", async () => {
    // API Gateway rejects an expired or wrong-audience token before the Lambda
    // runs, so there is no correlation ID to parse.
    const error = await errorFromResponse(new Response("", { status: 401 }));
    expect(error.code).toBe("unauthorized");
    expect(error.requiresSignIn).toBe(true);
    expect(error.correlationId).toBeUndefined();
  });

  it("keeps 403 distinct from 401 because signing in again would loop", async () => {
    const error = await errorFromResponse(
      jsonResponse(403, {
        error: { code: "forbidden", message: "no", correlationId: "c" },
      }),
    );
    expect(error.code).toBe("forbidden");
    expect(error.requiresSignIn).toBe(false);
  });

  it("marks 500, 503, and network failures as unknown outcomes", () => {
    expect(new ApiError(500, "internal_error", "x").outcomeUnknown).toBe(true);
    expect(new ApiError(503, "service_unavailable", "x").outcomeUnknown).toBe(true);
    expect(new ApiError(0, "network", "x").outcomeUnknown).toBe(true);
  });

  it("does not mark a terminal enrollment failure as an unknown outcome", () => {
    expect(new ApiError(409, "enrollment_failed", "x").outcomeUnknown).toBe(false);
  });

  it("surfaces the correlation ID from the envelope", async () => {
    const error = await errorFromResponse(
      jsonResponse(412, {
        error: { code: "precondition_failed", message: "stale", correlationId: "01J" },
      }),
    );
    expect(error.correlationId).toBe("01J");
  });
});
