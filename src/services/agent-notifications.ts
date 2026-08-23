import {
  AttachPolicyCommand,
  AttachThingPrincipalCommand,
  CreateThingCommand,
  DescribeCertificateCommand,
  IoTClient,
  RegisterCertificateWithoutCACommand,
  UpdateCertificateCommand,
} from "@aws-sdk/client-iot";
import { conflict, serviceUnavailable } from "../domain/errors";

export interface AgentMqttIdentity {
  readonly consumerId: string;
  readonly certificateFingerprint: string;
  readonly certificatePem: string;
}

/**
 * Registers the same mTLS leaf used by the delivery API with AWS IoT Core.
 * Hemlig never asks AWS IoT to create a private key: the agent retains the
 * key it generated locally for its CSR.
 */
export class AgentNotificationService {
  public constructor(
    private readonly iot: IoTClient,
    private readonly policyName: string,
  ) {}

  public async provision(identity: AgentMqttIdentity): Promise<void> {
    const certificate = await this.ensureCertificate(identity);
    await this.ensureThing(identity.consumerId);
    await this.attachPrincipal(identity.consumerId, certificate.certificateArn);
    await this.attachPolicy(certificate.certificateArn);
  }

  private async ensureCertificate(
    identity: AgentMqttIdentity,
  ): Promise<{ readonly certificateArn: string }> {
    try {
      const current = await this.iot.send(
        new DescribeCertificateCommand({ certificateId: identity.certificateFingerprint }),
      );
      const certificateArn = current.certificateDescription?.certificateArn;
      if (certificateArn === undefined) {
        throw serviceUnavailable("AWS IoT returned an incomplete certificate record.");
      }
      if (current.certificateDescription?.status === "REVOKED") {
        throw conflict("The AWS IoT certificate for this agent identity is revoked.");
      }
      if (current.certificateDescription?.status !== "ACTIVE") {
        await this.iot.send(
          new UpdateCertificateCommand({
            certificateId: identity.certificateFingerprint,
            newStatus: "ACTIVE",
          }),
        );
      }
      return { certificateArn };
    } catch (error) {
      if (!isNotFound(error)) {
        throw error;
      }
    }
    try {
      const registered = await this.iot.send(
        new RegisterCertificateWithoutCACommand({
          certificatePem: identity.certificatePem,
          status: "ACTIVE",
        }),
      );
      if (registered.certificateArn === undefined) {
        throw serviceUnavailable("AWS IoT did not return the registered certificate ARN.");
      }
      return { certificateArn: registered.certificateArn };
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
      const current = await this.iot.send(
        new DescribeCertificateCommand({ certificateId: identity.certificateFingerprint }),
      );
      const certificateArn = current.certificateDescription?.certificateArn;
      if (certificateArn === undefined) {
        throw serviceUnavailable("AWS IoT could not recover the registered certificate.");
      }
      return { certificateArn };
    }
  }

  private async ensureThing(consumerId: string): Promise<void> {
    try {
      await this.iot.send(new CreateThingCommand({ thingName: consumerId }));
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
    }
  }

  private async attachPrincipal(thingName: string, principal: string): Promise<void> {
    try {
      await this.iot.send(
        new AttachThingPrincipalCommand({ thingName, principal }),
      );
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
    }
  }

  private async attachPolicy(target: string): Promise<void> {
    try {
      await this.iot.send(
        new AttachPolicyCommand({ policyName: this.policyName, target }),
      );
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
    }
  }
}

const isNotFound = (error: unknown): boolean =>
  error instanceof Error && error.name === "ResourceNotFoundException";

const isAlreadyExists = (error: unknown): boolean =>
  error instanceof Error && error.name === "ResourceAlreadyExistsException";
