import assert from "node:assert/strict";
import test from "node:test";
import {
  isOwnedByImport,
  kubernetesDataToPayload,
  payloadChecksum,
  payloadToKubernetesData,
} from "./index";

test("converts UTF-8 and base64 Clavis entries into Kubernetes Secret data", () => {
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
    labels: { "clavis.io/managed-by": "import" },
    annotations: { "clavis.io/import-owner": "payments/payments-api" },
  };
  assert.equal(isOwnedByImport(metadata, "payments/payments-api"), true);
  assert.equal(isOwnedByImport(metadata, "payments/other"), false);
});
