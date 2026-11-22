import { ApiError } from "../domain/errors";
import { errorResponse } from "./responses";

const body = (result: ReturnType<typeof errorResponse>) =>
  JSON.parse(result.body ?? "{}") as { error: Record<string, unknown> };

describe("errorResponse", () => {
  it("includes details only when the error carries them", () => {
    const plain = errorResponse(new ApiError(400, "bad_request", "No."), "c1");
    expect(body(plain).error).toEqual({
      code: "bad_request",
      message: "No.",
      correlationId: "c1",
    });
    const detailed = errorResponse(
      new ApiError(400, "chain_invalid", "No.", "r", {
        details: { reason: "r", count: 2, flag: true },
      }),
      "c2",
    );
    expect(body(detailed).error.details).toEqual({
      reason: "r",
      count: 2,
      flag: true,
    });
  });

  it("passes retry-after through", () => {
    const result = errorResponse(
      new ApiError(429, "issuance_rate_limited", "Slow down.", undefined, {
        headers: { "retry-after": "120" },
      }),
      "c3",
    );
    expect(result.statusCode).toBe(429);
    expect(result.headers).toMatchObject({
      "retry-after": "120",
      "content-type": "application/json",
      "cache-control": "no-store",
    });
  });

  it("never lets an error override content-type or cache-control", () => {
    const result = errorResponse(
      new ApiError(400, "bad_request", "No.", undefined, {
        headers: {
          "Content-Type": "text/html",
          "CACHE-CONTROL": "public",
          "x-extra": "1",
        },
      }),
      "c4",
    );
    expect(result.headers).toEqual({
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-extra": "1",
    });
  });
});
