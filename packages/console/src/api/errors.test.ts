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

  it("parses details and exposes the reason", async () => {
    const error = await errorFromResponse(
      jsonResponse(409, {
        error: {
          code: "conflict",
          message: "taken",
          correlationId: "c",
          details: { reason: "name_in_use", path: "name", retryAfterSeconds: 3 },
        },
      }),
    );
    expect(error.reason).toBe("name_in_use");
    expect(error.details).toMatchObject({ path: "name" });
    expect(error.retryAfterSeconds).toBe(3);
  });

  it("prefers the Retry-After header over details.retryAfterSeconds", async () => {
    const response = new Response(
      JSON.stringify({
        error: {
          code: "issuance_rate_limited",
          message: "slow",
          correlationId: "c",
          details: { retryAfterSeconds: 3 },
        },
      }),
      { status: 429, headers: { "retry-after": "17" } },
    );
    expect((await errorFromResponse(response)).retryAfterSeconds).toBe(17);
  });

  it("keeps an unknown code and leaves the reason undefined without details", async () => {
    const error = await errorFromResponse(
      jsonResponse(400, {
        error: { code: "something_new", message: "m", correlationId: "c" },
      }),
    );
    expect(error.code).toBe("something_new");
    expect(error.reason).toBeUndefined();
    expect(error.retryAfterSeconds).toBeUndefined();
  });

  it("still maps a 401 to the synthetic unauthorized code", async () => {
    const error = await errorFromResponse(new Response("", { status: 401 }));
    expect(error.code).toBe("unauthorized");
    expect(error.details).toBeUndefined();
  });
});
