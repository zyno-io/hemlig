import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

// Compiled to dist/manifests.test.js, so the package root is one level up.
const root = path.resolve(__dirname, "..");
const read = (relative: string): string =>
  readFileSync(path.join(root, relative), "utf8");

const chart = "chart/hemlig-controller";
const strategy =
  /strategy:\s*\n\s*type:\s*RollingUpdate\s*\n\s*rollingUpdate:\s*\n\s*maxSurge:\s*0\s*\n\s*maxUnavailable:\s*1/;

const controllerRules = [
  `  - apiGroups: ["cert-manager.io"]
    resources: ["certificaterequests"]
    verbs: ["get", "list", "watch"]`,
  `  - apiGroups: ["cert-manager.io"]
    resources: ["certificaterequests/status"]
    verbs: ["get", "update", "patch"]`,
  `  - apiGroups: ["hemlig.zyno.io"]
    resources: ["hemligissuers", "hemligclusterissuers"]
    verbs: ["get", "list", "watch"]`,
  `  - apiGroups: ["hemlig.zyno.io"]
    resources: ["hemligissuers/status", "hemligclusterissuers/status"]
    verbs: ["get", "update", "patch"]`,
];

test("both deployments use a zero-surge rolling update", () => {
  assert.match(read("config/manager.yaml"), strategy);
  assert.match(read(`${chart}/templates/deployment.yaml`), strategy);
});

test("config/crds.yaml is the exact concatenation of the chart CRD files", () => {
  assert.equal(
    read("config/crds.yaml"),
    `${read(`${chart}/crds/hemlig.zyno.io.yaml`)}---\n${read(`${chart}/crds/hemlig.zyno.io-pki.yaml`)}`,
  );
});

test("both RBAC files carry the PKI rules and never approve", () => {
  for (const file of ["config/manager.yaml", `${chart}/templates/rbac.yaml`]) {
    const text = read(file);
    for (const rule of controllerRules)
      assert.ok(text.includes(rule), `${file}: ${rule}`);
    assert.doesNotMatch(text, /approve/, file);
  }
});

test("the chart RBAC rules sit inside the rbac.create block", () => {
  const text = read(`${chart}/templates/rbac.yaml`);
  assert.ok(text.startsWith("{{- if .Values.rbac.create }}"));
  assert.ok(text.trimEnd().endsWith("{{- end }}"));
  assert.doesNotMatch(text, /certManager/);
});

test("the approval template is gated and grants both signer patterns", () => {
  const text = read(`${chart}/templates/cert-manager-approval.yaml`);
  assert.ok(
    text.startsWith(
      "{{- if .Values.certManager.approval.grantDefaultApprover }}",
    ),
  );
  assert.ok(text.trimEnd().endsWith("{{- end }}"));
  assert.match(text, /verbs: \["approve"\]/);
  assert.ok(text.includes("hemligissuers.hemlig.zyno.io/*"));
  assert.ok(text.includes("hemligclusterissuers.hemlig.zyno.io/*"));
});

test("the raw approval manifest grants both signer patterns", () => {
  const text = read("config/cert-manager-approval.yaml");
  assert.match(text, /verbs: \["approve"\]/);
  assert.ok(text.includes("hemligissuers.hemlig.zyno.io/*"));
  assert.ok(text.includes("hemligclusterissuers.hemlig.zyno.io/*"));
});

test("the PKI CRDs define both issuers with immutable specs", () => {
  const text = read(`${chart}/crds/hemlig.zyno.io-pki.yaml`);
  for (const needle of [
    "shortNames: [hmlissuer]",
    "shortNames: [hmlclusterissuer]",
    "name: v1alpha1",
    "subresources: { status: {} }",
    "message: spec is immutable except issuanceGrant",
    "maxProperties: 16",
  ]) {
    assert.ok(text.includes(needle), needle);
  }
  assert.equal(text.match(/x-kubernetes-validations:/g)?.length, 2);
  assert.equal(text.match(/name: CA, type: string/g)?.length, 2);
});

test("the HemligConsumer CRD has allowClusterIssuers", () => {
  assert.ok(
    read(`${chart}/crds/hemlig.zyno.io.yaml`).includes(
      "allowClusterIssuers: { type: boolean }",
    ),
  );
});

test("both deployments set HEMLIG_PKI_CONCURRENCY", () => {
  assert.match(
    read("config/manager.yaml"),
    /HEMLIG_PKI_CONCURRENCY\s*\n\s*value: "4"/,
  );
  assert.match(
    read(`${chart}/templates/deployment.yaml`),
    /HEMLIG_PKI_CONCURRENCY\s*\n\s*value: \{\{ \.Values\.certManager\.maxConcurrentRequests \| quote \}\}/,
  );
});
