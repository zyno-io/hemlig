import assert from "node:assert/strict";
import test from "node:test";
import { HemligSecretProvider, Provider, type ResolvedSecretInputs } from "./index";

test("exports a Pulumi component provider", () => {
  assert.equal(typeof Provider, "function");
});

function inputs(overrides: Partial<ResolvedSecretInputs> = {}): ResolvedSecretInputs {
  return {
    adminUrl: "https://admin.example.com",
    providerSchemaVersion: "2",
    secretId: "platform-hemlig-pulumi-sentinel",
    environment: "staging",
    metadata: { description: "Pulumi provider sentinel", path: "platform/hemlig" },
    acl: [],
    payload: { SENTINEL: { encoding: "utf8", value: "one" } },
    ...overrides,
  };
}

test("does not diff when a legacy state contains only a short-lived administrator token", async () => {
  const provider = new HemligSecretProvider();
  const legacy = { ...inputs(), adminToken: "token-one" } as ResolvedSecretInputs;
  const result = await provider.diff(
    "platform-hemlig-pulumi-sentinel",
    legacy,
    inputs(),
  );

  assert.deepEqual(result, { changes: false, replaces: [] });
});

test("metadata-only updates preserve the current immutable payload revision", async () => {
  let metadataUpdates = 0;
  let payloadWrites = 0;
  const provider = new HemligSecretProvider(() => ({
    createAdminSecret: async () => {
      throw new Error("create must not be called during update");
    },
    getAdminSecret: async () => ({
      secretId: "platform-hemlig-pulumi-sentinel",
      environment: "staging",
      controlVersionId: "ctl-current",
      payloadVersionId: "payload-current",
      payloadKeyCount: 1,
      state: "ACTIVE",
      metadata: { description: "before", path: "platform/hemlig" },
      acl: [],
    }),
    updateAdminSecret: async () => {
      metadataUpdates += 1;
      return {
        secretId: "platform-hemlig-pulumi-sentinel",
        environment: "staging",
        controlVersionId: "ctl-metadata",
        payloadVersionId: "payload-current",
        payloadKeyCount: 1,
        state: "ACTIVE" as const,
        metadata: { description: "after", path: "platform/hemlig" },
        acl: [],
      };
    },
    putAdminPayload: async () => {
      payloadWrites += 1;
      throw new Error("metadata-only update must not write a payload");
    },
  }), () => "token-for-test");
  const result = await provider.update(
    "platform-hemlig-pulumi-sentinel",
    inputs({ metadata: { description: "before", path: "platform/hemlig" } }),
    inputs({
      metadata: { description: "after", path: "platform/hemlig" },
    }),
  );

  assert.equal(metadataUpdates, 1);
  assert.equal(payloadWrites, 0);
  assert.equal(result.outs.payloadVersionId, "payload-current");
  assert.equal(result.outs.controlVersionId, "ctl-metadata");
});

test("payload updates write exactly one new revision", async () => {
  let payloadWrites = 0;
  const provider = new HemligSecretProvider(() => ({
    createAdminSecret: async () => {
      throw new Error("create must not be called during update");
    },
    getAdminSecret: async () => ({
      secretId: "platform-hemlig-pulumi-sentinel",
      environment: "staging",
      controlVersionId: "ctl-current",
      payloadVersionId: "payload-current",
      payloadKeyCount: 1,
      state: "ACTIVE",
      metadata: { description: "Pulumi provider sentinel", path: "platform/hemlig" },
      acl: [],
    }),
    updateAdminSecret: async () => {
      throw new Error("unchanged metadata must not create a control revision");
    },
    putAdminPayload: async () => {
      payloadWrites += 1;
      return {
        secretId: "platform-hemlig-pulumi-sentinel",
        environment: "staging",
        controlVersionId: "ctl-payload",
        payloadVersionId: "payload-next",
        payloadKeyCount: 1,
        state: "ACTIVE" as const,
        metadata: { description: "Pulumi provider sentinel", path: "platform/hemlig" },
        acl: [],
      };
    },
  }), () => "token-for-test");
  const result = await provider.update(
    "platform-hemlig-pulumi-sentinel",
    inputs(),
    inputs({
      payload: { SENTINEL: { encoding: "utf8", value: "two" } },
    }),
  );

  assert.equal(payloadWrites, 1);
  assert.equal(result.outs.payloadVersionId, "payload-next");
  assert.equal(result.outs.controlVersionId, "ctl-payload");
});
