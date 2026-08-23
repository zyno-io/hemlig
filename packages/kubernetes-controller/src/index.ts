import { createHash } from "node:crypto";
import type { SecretPayload } from "@hemlig/client";

/** Metadata fields shared by the controller's Kubernetes resource adapters. */
export interface ObjectMeta {
  readonly name?: string;
  readonly namespace?: string;
  readonly generation?: number;
  readonly resourceVersion?: string;
  readonly labels?: Readonly<Record<string, string>>;
  readonly annotations?: Readonly<Record<string, string>>;
}

export const payloadToKubernetesData = (payload: SecretPayload): Record<string, string> =>
  Object.fromEntries(
    Object.entries(payload).map(([key, entry]) => [
      key,
      entry.encoding === "base64" ? entry.value : Buffer.from(entry.value, "utf8").toString("base64"),
    ]),
  );

export const kubernetesDataToPayload = (
  data: Readonly<Record<string, string | undefined>>,
): SecretPayload =>
  Object.fromEntries(
    Object.entries(data)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([key, value]) => [key, { encoding: "base64", value }]),
  );

/** Stable content identity for an exported Kubernetes Secret's material. */
export const payloadChecksum = (payload: SecretPayload): string =>
  createHash("sha256")
    .update(JSON.stringify(Object.entries(payload).sort(([left], [right]) => left.localeCompare(right))))
    .digest("hex");

/** An imported target is mutable only by the exact importing custom resource. */
export const isOwnedByImport = (metadata: ObjectMeta | undefined, importOwner: string): boolean =>
  metadata?.labels?.["hemlig.io/managed-by"] === "import" &&
  metadata.annotations?.["hemlig.io/import-owner"] === importOwner;
