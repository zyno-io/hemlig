import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { DynamoCursorStore } from "./cursor-store";

const cursor = {
  token: "A".repeat(43),
  scope: "scope",
  lastEvaluatedKey: { pk: "PKI_CA#x", sk: "PROFILE" },
  expiresAt: "2026-08-23T00:15:00.000Z",
  ttl: 1_787_438_500,
};

const client = (send: jest.Mock) =>
  ({ send }) as unknown as DynamoDBDocumentClient;

describe("DynamoCursorStore", () => {
  it("round-trips PKI_CURSOR# state", async () => {
    const send = jest.fn().mockResolvedValue({});
    const store = new DynamoCursorStore(client(send), "control", "PKI_CURSOR#");
    await expect(store.createCursor(cursor)).resolves.toBe(true);
    const put = send.mock.calls[0]?.[0] as { input: Record<string, any> };
    expect(put.input.Item.pk).toBe(`PKI_CURSOR#${cursor.token}`);
    expect(put.input.Item.sk).toBe("STATE");
    expect(put.input.ConditionExpression).toBe("attribute_not_exists(pk)");

    send.mockResolvedValueOnce({ Item: put.input.Item });
    await expect(store.getCursor(cursor.token)).resolves.toEqual(cursor);
    const get = send.mock.calls[1]?.[0] as { input: Record<string, any> };
    expect(get.input.Key).toEqual({
      pk: `PKI_CURSOR#${cursor.token}`,
      sk: "STATE",
    });
    expect(get.input.ConsistentRead).toBe(true);
  });

  it("reports a collision instead of overwriting", async () => {
    const send = jest.fn().mockRejectedValue(
      Object.assign(new Error("exists"), {
        name: "ConditionalCheckFailedException",
      }),
    );
    const store = new DynamoCursorStore(client(send), "control", "CURSOR#");
    await expect(store.createCursor(cursor)).resolves.toBe(false);
  });

  it("rethrows other errors and ignores malformed items", async () => {
    const send = jest.fn().mockRejectedValueOnce(new Error("down"));
    const store = new DynamoCursorStore(client(send), "control", "CURSOR#");
    await expect(store.createCursor(cursor)).rejects.toThrow("down");
    send.mockResolvedValueOnce({ Item: { scope: 1 } });
    await expect(store.getCursor(cursor.token)).resolves.toBeUndefined();
    send.mockResolvedValueOnce({});
    await expect(store.getCursor(cursor.token)).resolves.toBeUndefined();
  });

  it("does not read a cursor stored under the other prefix", async () => {
    const send = jest.fn().mockResolvedValue({});
    await new DynamoCursorStore(client(send), "control", "CURSOR#").getCursor(
      cursor.token,
    );
    await new DynamoCursorStore(
      client(send),
      "control",
      "PKI_CURSOR#",
    ).getCursor(cursor.token);
    const keys = send.mock.calls.map(
      (call) => (call[0] as { input: { Key: { pk: string } } }).input.Key.pk,
    );
    expect(keys[0]).not.toBe(keys[1]);
  });
});
