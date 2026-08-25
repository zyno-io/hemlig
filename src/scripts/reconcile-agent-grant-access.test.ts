import { reconcileAgentGrantAccess } from "./reconcile-agent-grant-access";

describe("reconcileAgentGrantAccess", () => {
  it("walks every AgentGrant page and reconciles only active grants", async () => {
    const listAgentGrants = jest
      .fn()
      .mockResolvedValueOnce({
        grants: [
          {
            grantId: "grant-first",
            consumerId: "consumer-first",
            environment: "prod",
            status: "PENDING",
            secretGrants: [],
          },
        ],
        nextKey: { pk: "next", sk: "PROFILE" },
      })
      .mockResolvedValueOnce({
        grants: [
          {
            grantId: "grant-second",
            consumerId: "consumer-second",
            environment: "prod",
            status: "ACTIVE",
            secretGrants: [
              {
                secretId: "platform/second",
                secretUid: "sec-second",
                permissions: ["read"],
              },
            ],
          },
          {
            grantId: "grant-pending",
            consumerId: "consumer-pending",
            environment: "prod",
            status: "PENDING",
            secretGrants: [],
          },
        ],
      });
    const reconcileAgentReadAccess = jest.fn(async () => undefined);
    const application = {
      repository: { listAgentGrants },
      secrets: { reconcileAgentReadAccess },
    };
    const actor = { type: "system" as const, id: "test-maintenance" };

    const reconciled = await reconcileAgentGrantAccess(application, actor);

    expect(reconciled).toBe(1);
    expect(listAgentGrants).toHaveBeenNthCalledWith(1, undefined);
    expect(listAgentGrants).toHaveBeenNthCalledWith(2, {
      pk: "next",
      sk: "PROFILE",
    });
    expect(reconcileAgentReadAccess).toHaveBeenCalledWith({
      consumerId: "consumer-second",
      environment: "prod",
      secretGrants: [
        {
          secretId: "platform/second",
          secretUid: "sec-second",
          permissions: ["read"],
        },
      ],
      actor,
    });
    expect(reconcileAgentReadAccess).not.toHaveBeenCalledWith(
      expect.objectContaining({ consumerId: "consumer-pending" }),
    );
    expect(reconcileAgentReadAccess).toHaveBeenCalledTimes(1);
  });
});
