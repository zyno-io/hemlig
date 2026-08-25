import assert from "node:assert/strict";
import test from "node:test";
import * as pulumi from "@pulumi/pulumi";
import {
  HemligAgentGrant,
  HemligAgentGrantProvider,
  HemligSecretProvider,
  Provider,
  type ResolvedAgentGrantInputs,
  type ResolvedSecretInputs,
} from "./index";

test("exports a Pulumi component provider", () => {
  assert.equal(typeof Provider, "function");
});

function inputs(
  overrides: Partial<ResolvedSecretInputs> = {},
): ResolvedSecretInputs {
  return {
    adminUrl: "https://admin.example.com",
    providerSchemaVersion: "2",
    secretId: "platform-hemlig-pulumi-sentinel",
    environment: "staging",
    metadata: { description: "Pulumi provider sentinel" },
    acl: [],
    payload: { SENTINEL: { encoding: "utf8", value: "one" } },
    ...overrides,
  };
}

function agentGrantInputs(
  overrides: Partial<ResolvedAgentGrantInputs> = {},
): ResolvedAgentGrantInputs {
  return {
    adminUrl: "https://admin.example.com",
    providerSchemaVersion: "1",
    consumerId: "staging-hemlig-sentinel",
    environment: "staging",
    capabilities: ["read"],
    readSecretIds: ["platform/hemlig/integration"],
    writeSecretIds: [],
    displayName: "Staging Hemlig Pulumi sentinel",
    bootstrapGeneration: "1",
    ...overrides,
  };
}

test("does not diff when a legacy state contains only a short-lived administrator token", async () => {
  const provider = new HemligSecretProvider();
  const legacy = {
    ...inputs(),
    adminToken: "token-one",
  } as ResolvedSecretInputs;
  const result = await provider.diff(
    "platform-hemlig-pulumi-sentinel",
    legacy,
    inputs(),
  );

  assert.deepEqual(result, { changes: false, replaces: [] });
});

test("treats environment as part of a secret's physical identity", async () => {
  const provider = new HemligSecretProvider();

  const result = await provider.diff(
    "staging:platform-hemlig-pulumi-sentinel",
    inputs(),
    inputs({ environment: "prod" }),
  );

  assert.deepEqual(result, { changes: true, replaces: ["environment"] });
});

test("metadata-only updates preserve the current immutable payload revision", async () => {
  let metadataUpdates = 0;
  let payloadWrites = 0;
  const provider = new HemligSecretProvider(
    () => ({
      createAdminSecret: async () => {
        throw new Error("create must not be called during update");
      },
      getAdminSecret: async () => ({
        secretUid: "sec-pulumi",
        secretId: "platform-hemlig-pulumi-sentinel",
        environment: "staging",
        controlVersionId: "ctl-current",
        payloadVersionId: "payload-current",
        payloadKeyCount: 1,
        state: "ACTIVE",
        metadata: { description: "before" },
        acl: [],
      }),
      updateAdminSecret: async () => {
        metadataUpdates += 1;
        return {
          secretUid: "sec-pulumi",
          secretId: "platform-hemlig-pulumi-sentinel",
          environment: "staging",
          controlVersionId: "ctl-metadata",
          payloadVersionId: "payload-current",
          payloadKeyCount: 1,
          state: "ACTIVE" as const,
          metadata: { description: "after" },
          acl: [],
        };
      },
      putAdminPayload: async () => {
        payloadWrites += 1;
        throw new Error("metadata-only update must not write a payload");
      },
    }),
    () => "token-for-test",
  );
  const result = await provider.update(
    "platform-hemlig-pulumi-sentinel",
    inputs({ metadata: { description: "before" } }),
    inputs({
      metadata: { description: "after" },
    }),
  );

  assert.equal(metadataUpdates, 1);
  assert.equal(payloadWrites, 0);
  assert.equal(result.outs.payloadVersionId, "payload-current");
  assert.equal(result.outs.controlVersionId, "ctl-metadata");
});

test("payload updates write exactly one new revision", async () => {
  let payloadWrites = 0;
  const provider = new HemligSecretProvider(
    () => ({
      createAdminSecret: async () => {
        throw new Error("create must not be called during update");
      },
      getAdminSecret: async () => ({
        secretUid: "sec-pulumi",
        secretId: "platform-hemlig-pulumi-sentinel",
        environment: "staging",
        controlVersionId: "ctl-current",
        payloadVersionId: "payload-current",
        payloadKeyCount: 1,
        state: "ACTIVE",
        metadata: { description: "Pulumi provider sentinel" },
        acl: [],
      }),
      updateAdminSecret: async () => {
        throw new Error(
          "unchanged metadata must not create a control revision",
        );
      },
      putAdminPayload: async () => {
        payloadWrites += 1;
        return {
          secretUid: "sec-pulumi",
          secretId: "platform-hemlig-pulumi-sentinel",
          environment: "staging",
          controlVersionId: "ctl-payload",
          payloadVersionId: "payload-next",
          payloadKeyCount: 1,
          state: "ACTIVE" as const,
          metadata: { description: "Pulumi provider sentinel" },
          acl: [],
        };
      },
    }),
    () => "token-for-test",
  );
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

test("creates one pending agent grant and one bootstrap capability", async () => {
  let grantCreates = 0;
  let capabilityIssues = 0;
  const provider = new HemligAgentGrantProvider(
    () => ({
      createAgentGrant: async () => {
        grantCreates += 1;
        return {
          grantId: "grant-staging-hemlig-sentinel",
          consumerId: "staging-hemlig-sentinel",
          environment: "staging",
          capabilities: ["read"] as const,
          readSecretIds: ["platform/hemlig/integration"],
          readSecretUids: ["sec-platform-hemlig-integration"],
          writeSecretIds: [],
          writeSecretUids: [],
          displayName: "Staging Hemlig Pulumi sentinel",
          status: "PENDING" as const,
          createdAt: "2026-08-23T00:00:00.000Z",
        };
      },
      issueBootstrapCapability: async () => {
        capabilityIssues += 1;
        return {
          grantId: "grant-staging-hemlig-sentinel",
          token: "hmlb_test",
          expiresAt: "2026-08-23T00:30:00.000Z",
        };
      },
      updateAgentGrant: async () => {
        throw new Error("create must not update an AgentGrant");
      },
    }),
    () => "token-for-test",
  );

  const result = await provider.create(agentGrantInputs());

  assert.equal(grantCreates, 1);
  assert.equal(capabilityIssues, 1);
  assert.equal(result.id, "grant-staging-hemlig-sentinel");
  assert.equal(result.outs.bootstrapToken, "hmlb_test");
});

test("only reissues the bootstrap capability when its generation changes", async () => {
  let grantCreates = 0;
  let capabilityIssues = 0;
  const provider = new HemligAgentGrantProvider(
    () => ({
      createAgentGrant: async () => {
        grantCreates += 1;
        throw new Error("create must not be called during bootstrap reissue");
      },
      issueBootstrapCapability: async () => {
        capabilityIssues += 1;
        return {
          grantId: "grant-staging-hemlig-sentinel",
          token: "hmlb_reissued",
          expiresAt: "2026-08-23T01:00:00.000Z",
        };
      },
      updateAgentGrant: async () => {
        throw new Error("a bootstrap reissue must not change policy");
      },
    }),
    () => "token-for-test",
  );
  const oldInputs = {
    ...agentGrantInputs(),
    grantId: "grant-staging-hemlig-sentinel",
    bootstrapToken: "hmlb_old",
    bootstrapExpiresAt: "2026-08-23T00:30:00.000Z",
  };

  const result = await provider.update(
    "grant-staging-hemlig-sentinel",
    oldInputs,
    agentGrantInputs({ bootstrapGeneration: "2" }),
  );

  assert.equal(grantCreates, 0);
  assert.equal(capabilityIssues, 1);
  assert.equal(result.outs.grantId, "grant-staging-hemlig-sentinel");
  assert.equal(result.outs.bootstrapToken, "hmlb_reissued");
});

test("updates an active AgentGrant policy without re-enrolling its consumer", async () => {
  let policyUpdates = 0;
  let capabilityIssues = 0;
  const provider = new HemligAgentGrantProvider(
    () => ({
      createAgentGrant: async () => {
        throw new Error("create must not be called during policy update");
      },
      issueBootstrapCapability: async () => {
        capabilityIssues += 1;
        throw new Error("policy update must not issue a bootstrap capability");
      },
      updateAgentGrant: async (_token, grantId, input) => {
        policyUpdates += 1;
        return {
          grantId,
          consumerId: "staging-hemlig-sentinel",
          environment: "staging",
          capabilities: input.capabilities,
          readSecretIds: input.readSecretIds ?? [],
          readSecretUids: [],
          writeSecretIds: input.writeSecretIds ?? [],
          writeSecretUids: [],
          displayName: input.displayName,
          status: "ACTIVE",
          createdAt: "2026-08-23T00:00:00.000Z",
        };
      },
    }),
    () => "token-for-test",
  );
  const oldInputs = {
    ...agentGrantInputs(),
    grantId: "grant-staging-hemlig-sentinel",
    bootstrapToken: "hmlb_old",
    bootstrapExpiresAt: "2026-08-23T00:30:00.000Z",
  };

  const result = await provider.update(
    "grant-staging-hemlig-sentinel",
    oldInputs,
    agentGrantInputs({
      readSecretIds: [
        "platform/hemlig/integration",
        "platform/gitlab-agents/staging",
      ],
    }),
  );

  assert.equal(policyUpdates, 1);
  assert.equal(capabilityIssues, 0);
  assert.equal(result.outs.grantId, "grant-staging-hemlig-sentinel");
  assert.equal(result.outs.bootstrapToken, "hmlb_old");
});

test("binds agent grant dynamic outputs onto the resource instance", async () => {
  pulumi.runtime.setMocks({
    call: (args) => args.inputs,
    newResource: (args) => ({ id: `${args.name}-id`, state: args.inputs }),
  });

  await pulumi.runtime.runInPulumiStack(async () => {
    const grant = new HemligAgentGrant(
      "sentinel-agent",
      agentGrantInputs(),
      "https://admin.example.com",
    );
    assert.equal(pulumi.Output.isInstance(grant.grantId), true);
    assert.equal(pulumi.Output.isInstance(grant.bootstrapToken), true);
    assert.equal(pulumi.Output.isInstance(grant.bootstrapExpiresAt), true);
  });
});
