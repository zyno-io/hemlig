import { UpdateCertificateCommand, type IoTClient } from "@aws-sdk/client-iot";
import { AgentNotificationService, provisionAndVerify } from "./agent-notifications";

describe("AgentNotificationService.revoke", () => {
  const build = (send: jest.Mock) =>
    new AgentNotificationService({ send } as unknown as IoTClient, "policy");

  it("sets the certificate status to REVOKED", async () => {
    const send = jest.fn(async () => ({}));
    await build(send).revoke("fp");
    const command = (send.mock.calls as unknown[][])[0]?.[0] as UpdateCertificateCommand;
    expect(command).toBeInstanceOf(UpdateCertificateCommand);
    expect(command.input).toEqual({ certificateId: "fp", newStatus: "REVOKED" });
  });

  it("treats an unregistered certificate as success", async () => {
    const send = jest.fn(async () => {
      throw Object.assign(new Error("missing"), {
        name: "ResourceNotFoundException",
      });
    });
    await expect(build(send).revoke("fp")).resolves.toBeUndefined();
  });

  it("propagates other IoT failures", async () => {
    const send = jest.fn(async () => {
      throw Object.assign(new Error("slow down"), {
        name: "ThrottlingException",
      });
    });
    await expect(build(send).revoke("fp")).rejects.toThrow("slow down");
  });
});

describe("provisionAndVerify", () => {
  const identity = {
    consumerId: "agent",
    certificateFingerprint: "fp",
    certificatePem: "pem",
  };
  const repositoryWith = (status: string | undefined) => ({
    getIdentity: jest.fn(async () =>
      status === undefined ? undefined : ({ status } as never),
    ),
  });

  it("leaves an identity that is still active registered", async () => {
    const notifications = { provision: jest.fn(async () => {}), revoke: jest.fn(async () => {}) };
    await provisionAndVerify(notifications, repositoryWith("ACTIVE"), identity);
    expect(notifications.revoke).not.toHaveBeenCalled();
  });

  it("revokes when the identity was revoked during provisioning", async () => {
    const notifications = { provision: jest.fn(async () => {}), revoke: jest.fn(async () => {}) };
    await provisionAndVerify(notifications, repositoryWith("REVOKED"), identity);
    expect(notifications.revoke).toHaveBeenCalledWith("fp");
  });

  it("still verifies, then rethrows, when provisioning fails part-way", async () => {
    const failure = new Error("attach failed");
    const notifications = {
      provision: jest.fn(async () => {
        throw failure;
      }),
      revoke: jest.fn(async () => {}),
    };
    await expect(
      provisionAndVerify(notifications, repositoryWith("REVOKED"), identity),
    ).rejects.toBe(failure);
    expect(notifications.revoke).toHaveBeenCalledWith("fp");
  });
});
