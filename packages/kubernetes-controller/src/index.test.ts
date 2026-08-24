import assert from "node:assert/strict";
import test from "node:test";
import {
  isOwnedByImport,
  kubernetesDataToPayload,
  payloadChecksum,
  payloadToKubernetesData,
} from "./index";
import { HemligV1BetaController } from "./v1beta";

test("converts UTF-8 and base64 Hemlig entries into Kubernetes Secret data", () => {
  const data = payloadToKubernetesData({
    USERNAME: { encoding: "utf8", value: "service" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
  assert.deepEqual(data, { USERNAME: "c2VydmljZQ==", TOKEN: "AQID" });
  assert.deepEqual(kubernetesDataToPayload(data), {
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
});

test("uses a key-order-independent checksum for exported material", () => {
  const first = payloadChecksum({
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
    TOKEN: { encoding: "base64", value: "AQID" },
  });
  const second = payloadChecksum({
    TOKEN: { encoding: "base64", value: "AQID" },
    USERNAME: { encoding: "base64", value: "c2VydmljZQ==" },
  });
  assert.equal(first, second);
});

test("recognizes only the exact import owner", () => {
  const metadata = {
    labels: { "hemlig.io/managed-by": "import" },
    annotations: { "hemlig.io/import-owner": "payments/payments-api" },
  };
  assert.equal(isOwnedByImport(metadata, "payments/payments-api"), true);
  assert.equal(isOwnedByImport(metadata, "payments/other"), false);
});

test("writes reconciliation status as JSON Patch", async () => {
  const statusPatches: unknown[] = [];
  const custom = {
    async listClusterCustomObject(): Promise<unknown> {
      return { items: [] };
    },
    async listCustomObjectForAllNamespaces(input: { readonly plural: string }): Promise<unknown> {
      return {
        items: input.plural === "hemligconsumers"
          ? [{
              apiVersion: "hemlig.io/v1beta1",
              kind: "HemligConsumer",
              metadata: { generation: 1, name: "sentinel", namespace: "hemlig-sentinel" },
              spec: {
                bootstrapTokenRef: { key: "token", name: "bootstrap" },
                identity: { secretName: "identity" },
                providerRef: "missing",
              },
            }]
          : [],
      };
    },
    async patchNamespacedCustomObjectStatus(input: unknown): Promise<unknown> {
      statusPatches.push(input);
      return {};
    },
  };
  const controller = new HemligV1BetaController(
    {} as never,
    custom as never,
    { intervalMilliseconds: 60_000, sourceDebounceMilliseconds: 250 },
  );

  await controller.reconcileAll();

  assert.equal(statusPatches.length, 1);
  const patch = statusPatches[0] as {
    readonly group: string;
    readonly version: string;
    readonly namespace: string;
    readonly plural: string;
    readonly name: string;
    readonly body: readonly [{
      readonly op: string;
      readonly path: string;
      readonly value: {
        readonly observedGeneration?: number;
        readonly conditions?: readonly [{
          readonly type: string;
          readonly status: string;
          readonly reason: string;
          readonly message: string;
          readonly lastTransitionTime: string;
        }];
      };
    }];
  };
  assert.deepEqual(
    {
      group: patch.group,
      version: patch.version,
      namespace: patch.namespace,
      plural: patch.plural,
      name: patch.name,
      body: patch.body.map(({ op, path, value }) => ({
        op,
        path,
        observedGeneration: value.observedGeneration,
        type: value.conditions?.[0]?.type,
        status: value.conditions?.[0]?.status,
        reason: value.conditions?.[0]?.reason,
        message: value.conditions?.[0]?.message,
      })),
    },
    {
      group: "hemlig.io",
      version: "v1beta1",
      namespace: "hemlig-sentinel",
      plural: "hemligconsumers",
      name: "sentinel",
      body: [{
        op: "add",
        path: "/status",
        observedGeneration: 1,
        type: "Ready",
        status: "False",
        reason: "ProviderNotFound",
        message: "The referenced HemligProvider was not found.",
      }],
    },
  );
  assert.match(patch.body[0].value.conditions?.[0]?.lastTransitionTime ?? "", /^\d{4}-\d{2}-\d{2}T/);
});
