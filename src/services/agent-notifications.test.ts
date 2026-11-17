import { UpdateCertificateCommand, type IoTClient } from "@aws-sdk/client-iot";
import { AgentNotificationService } from "./agent-notifications";

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
