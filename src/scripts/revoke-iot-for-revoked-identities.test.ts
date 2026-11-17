import { revokeIotForRevokedIdentities } from "./revoke-iot-for-revoked-identities";

describe("revokeIotForRevokedIdentities", () => {
  const build = () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        Items: [{ fingerprint: "a" }],
        LastEvaluatedKey: { pk: "next" },
      })
      .mockResolvedValueOnce({ Items: [{ fingerprint: "b" }] });
    const revoke = jest.fn(async () => undefined);
    return { send, revoke };
  };

  it("revokes every revoked API identity across pages", async () => {
    const { send, revoke } = build();
    await expect(
      revokeIotForRevokedIdentities({ send } as never, "t", { revoke }, false),
    ).resolves.toBe(2);
    expect(revoke.mock.calls).toEqual([["a"], ["b"]]);
  });

  it("only counts in dry-run mode", async () => {
    const { send, revoke } = build();
    await expect(
      revokeIotForRevokedIdentities({ send } as never, "t", { revoke }, true),
    ).resolves.toBe(2);
    expect(revoke).not.toHaveBeenCalled();
  });
});
