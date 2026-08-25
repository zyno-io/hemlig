import { describe, expect, it } from "vitest";
import { createAppRouter } from "./index";

describe("secret routes", () => {
  it("preserves every slash-separated secret ID segment before a subpage", () => {
    const router = createAppRouter();
    const route = router.resolve(
      "/e/dev/secrets/payments/stripe/api-key/payload",
    );

    expect(route.name).toBe("secret-payload");
    expect(route.params).toMatchObject({
      env: "dev",
      secretId: "payments/stripe/api-key",
    });
  });
});
