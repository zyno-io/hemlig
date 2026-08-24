import { CursorService, type StoredCursor } from "./cursor";

describe("CursorService", () => {
  it("keeps an opaque cursor bound to its intended scope", async () => {
    const stored = new Map<string, StoredCursor>();
    const service = new CursorService({
      createCursor: jest.fn(async (cursor: StoredCursor) => {
        if (stored.has(cursor.token)) {
          return false;
        }
        stored.set(cursor.token, cursor);
        return true;
      }),
      getCursor: jest.fn(async (token: string) => stored.get(token)),
    });
    const cursor = await service.encode({
      scope: "consumer-one",
      lastEvaluatedKey: { pk: "CONSUMER#consumer-one", sk: "SECRET#sec-one" },
      expiresAt: "2030-01-01T00:00:00.000Z",
    });

    expect(cursor).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(
      service.decode(
        cursor,
        "consumer-one",
        new Date("2029-01-01T00:00:00.000Z"),
      ),
    ).resolves.toMatchObject({
      lastEvaluatedKey: { pk: "CONSUMER#consumer-one", sk: "SECRET#sec-one" },
    });
    await expect(
      service.decode(
        cursor,
        "consumer-two",
        new Date("2029-01-01T00:00:00.000Z"),
      ),
    ).rejects.toThrow("cursor");
  });

  it("rejects malformed, unknown, and expired opaque cursors", async () => {
    const service = new CursorService({
      createCursor: jest.fn(async () => true),
      getCursor: jest.fn(async () => undefined),
    });

    await expect(
      service.decode("not-a-cursor", "consumer-one"),
    ).rejects.toThrow("malformed");
    await expect(
      service.decode("A".repeat(43), "consumer-one"),
    ).rejects.toThrow("no longer valid");

    const expired = "B".repeat(43);
    const expiredService = new CursorService({
      createCursor: jest.fn(async () => true),
      getCursor: jest.fn(async () => ({
        token: expired,
        scope: "consumer-one",
        expiresAt: "2026-01-01T00:00:00.000Z",
        ttl: 1_767_225_600,
      })),
    });
    await expect(
      expiredService.decode(
        expired,
        "consumer-one",
        new Date("2027-01-01T00:00:00.000Z"),
      ),
    ).rejects.toThrow("no longer valid");
  });
});
