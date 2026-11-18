import { describe, expect, it } from "vitest";
import { safeReturnTo } from "./session";

describe("safeReturnTo", () => {
  it("keeps same-origin paths with their query string", () => {
    expect(safeReturnTo("/cli-login?port=40000&state=abc")).toBe("/cli-login?port=40000&state=abc");
  });
  it.each(["//evil.example.com", "/\\evil.example.com", "https://evil.example.com", "/auth/callback?x", "", undefined, 5])(
    "rejects %s",
    (value) => {
      expect(safeReturnTo(value)).toBeUndefined();
    },
  );
});
