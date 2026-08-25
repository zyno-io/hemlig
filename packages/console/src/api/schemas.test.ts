import { describe, expect, it } from "vitest";
import {
  auditPage,
  catalogPage,
  environmentListResponse,
  secretTreePage,
} from "./schemas";

const catalogEntryFixture = {
  secretId: "stripe-api-key",
  environment: "prod",
  controlVersionId: "ctl-1",
  state: "ACTIVE",
  metadata: {},
};

describe("catalogPage", () => {
  it("accepts an ordinary browse page: nextCursor present, truncated absent", () => {
    const page = catalogPage.parse({
      secrets: [catalogEntryFixture],
      nextCursor: "opaque-cursor",
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.nextCursor).toBe("opaque-cursor");
    expect(page.truncated).toBeUndefined();
  });

  it("accepts a `q` search page: truncated present, nextCursor absent", () => {
    const page = catalogPage.parse({
      secrets: [catalogEntryFixture],
      truncated: true,
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.nextCursor).toBeUndefined();
    // `truncated` is the only signal a search scan hit its bound; losing it
    // would make an incomplete result set look like the full answer.
    expect(page.truncated).toBe(true);
  });
});

describe("secretTreePage", () => {
  it("accepts a root response, where pathPrefix is omitted", () => {
    const page = secretTreePage.parse({
      environment: "prod",
      folders: [
        {
          segment: "payments",
          path: "payments",
          secretCount: 3,
          kind: "derived",
        },
      ],
      secrets: [],
      truncated: false,
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.pathPrefix).toBeUndefined();
    expect(page.folders).toHaveLength(1);
  });

  it("accepts a nested level with folders and secrets at that exact path", () => {
    const page = secretTreePage.parse({
      environment: "prod",
      pathPrefix: "payments",
      folders: [
        {
          segment: "stripe",
          path: "payments/stripe",
          secretCount: 12,
          kind: "derived",
        },
      ],
      secrets: [catalogEntryFixture],
      truncated: true,
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.pathPrefix).toBe("payments");
    expect(page.folders[0]).toMatchObject({
      segment: "stripe",
      secretCount: 12,
      kind: "derived",
    });
    expect(page.secrets[0]?.secretId).toBe("stripe-api-key");
    // `truncated` is the only signal a level was capped rather than complete;
    // losing it would make an incomplete list look like the full contents.
    expect(page.truncated).toBe(true);
  });
});

describe("environmentListResponse", () => {
  it("accepts an empty list, the shape a fresh deployment starts with", () => {
    const page = environmentListResponse.parse({
      environments: [],
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.environments).toEqual([]);
  });

  it("requires each definition to record who created it and when", () => {
    const page = environmentListResponse.parse({
      environments: [
        {
          name: "staging",
          createdAt: "2026-08-23T00:00:00.000Z",
          createdBy: { type: "human", id: "admin@example.com" },
        },
      ],
      generatedAt: "2026-08-23T00:00:00.000Z",
    });
    expect(page.environments[0]).toMatchObject({ name: "staging" });

    expect(() =>
      environmentListResponse.parse({
        environments: [
          { name: "staging", createdAt: "2026-08-23T00:00:00.000Z" },
        ],
        generatedAt: "2026-08-23T00:00:00.000Z",
      }),
    ).toThrow();
  });
});

describe("auditPage", () => {
  it("accepts only safe, payload-free evidence fields", () => {
    const page = auditPage.parse({
      date: "2026-08-23",
      events: [
        {
          eventId: "event-1",
          at: "2026-08-23T10:00:00.000Z",
          correlationId: "corr-1",
          outcome: "succeeded",
          actor: {
            type: "human",
            id: "admin-1",
            email: "admin@example.test",
          },
          operation: "adminget:/v1/admin/secrets",
          target: { secretId: "payments-api" },
        },
      ],
      nextCursor: "signed-cursor",
      generatedAt: "2026-08-23T10:00:01.000Z",
    });

    expect(page.events[0]).toMatchObject({
      actor: { email: "admin@example.test" },
      operation: "adminget:/v1/admin/secrets",
      target: { secretId: "payments-api" },
    });
    expect(page.nextCursor).toBe("signed-cursor");
  });
});
