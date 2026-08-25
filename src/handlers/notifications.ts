import {
  IoTDataPlaneClient,
  PublishCommand,
} from "@aws-sdk/client-iot-data-plane";
import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import type { DynamoDBStreamEvent } from "aws-lambda";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { createApplication } from "../app";
import { loadConfig } from "../aws/config";
import type { NotificationOutboxRecord } from "../domain/types";

/**
 * Stream records are delivery hints, not state replication. The message has
 * no payload, path, ACL, certificate, or token; agents refetch through their
 * mTLS API after receiving it.
 */
export const handler = async (event: DynamoDBStreamEvent): Promise<void> => {
  const config = loadConfig();
  const app = createApplication(config);
  const publisher = new IoTDataPlaneClient({
    region: config.region,
    endpoint: `https://${config.iotEndpoint}`,
  });
  const records = event.Records.flatMap((record) => {
    // A schema migration can backfill a pending outbox record's environment.
    // That produces MODIFY rather than INSERT; the notification contract is
    // deliberately at-least-once, so deliver the still-pending event.
    if (
      (record.eventName !== "INSERT" && record.eventName !== "MODIFY") ||
      record.dynamodb?.NewImage === undefined
    ) {
      return [];
    }
    const item = unmarshall(
      record.dynamodb.NewImage as Record<string, AttributeValue>,
    ) as NotificationOutboxRecord;
    return item.status === "PENDING" && item.pk.startsWith("NOTIFICATION#")
      ? [item]
      : [];
  });
  for (const record of records) {
    // Deployments can still have PENDING single-recipient outbox records from
    // before grouped fan-out. Deliver those rather than stranding a valid
    // change during the rollout.
    const consumerIds =
      record.consumerIds ??
      (record.consumerId === undefined ? [] : [record.consumerId]);
    const payload = Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        kind: record.kind,
        secretId: record.secretId,
        environment: record.environment,
        controlVersionId: record.controlVersionId,
        ...(record.payloadVersionId === undefined
          ? {}
          : { payloadVersionId: record.payloadVersionId }),
      }),
      "utf8",
    );
    for (const consumerId of consumerIds) {
      await publisher.send(
        new PublishCommand({
          topic: `${config.iotNotificationTopicPrefix}/${consumerId}`,
          qos: 1,
          payload,
        }),
      );
    }
    await app.repository.markNotificationDelivered(record.eventId);
  }
};
