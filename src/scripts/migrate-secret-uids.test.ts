import { buildSecretUidMigrationPlan } from "./migrate-secret-uids";

const legacySecret = (secretId = "payments/api-key", environment = "prod") => [
  {
    pk: `SECRET#${environment}#${secretId}`,
    sk: "HEAD",
    secretId,
    environment,
    controlVersionId: "ctl-current",
    controlObjectVersionId: "control-version",
    payloadVersionId: "pay-current",
    payloadObjectVersionId: "payload-version",
    workflowState: "READY",
    state: "ACTIVE",
  },
  {
    pk: `SECRET#${environment}#${secretId}`,
    sk: "CONTROL#ctl-current",
    workflowState: "READY",
    serialized: {
      schemaVersion: 1,
      secretId,
      environment,
      controlVersionId: "ctl-current",
    },
  },
  {
    pk: `SECRET#${environment}#${secretId}`,
    sk: "PAYLOAD#pay-current",
    workflowState: "READY",
    serialized: {
      schemaVersion: 1,
      secretId,
      environment,
      payloadVersionId: "pay-current",
    },
  },
];

describe("buildSecretUidMigrationPlan", () => {
  it("moves secret records under a deterministic UID and retains legacy object locations", () => {
    const plan = buildSecretUidMigrationPlan(legacySecret());

    expect(plan.issues).toEqual([]);
    expect(plan.secretMoves).toHaveLength(3);
    const head = plan.secretMoves.find((move) => move.target.sk === "HEAD");
    expect(head?.target).toEqual(
      expect.objectContaining({
        pk: expect.stringMatching(/^SECRET#sec-/),
        secretUid: expect.stringMatching(/^sec-/),
        controlObjectKey:
          "secrets/prod/payments/api-key/control/ctl-current.json",
        payloadObjectKey:
          "secrets/prod/payments/api-key/payload/pay-current.json",
      }),
    );
    const control = plan.secretMoves.find((move) =>
      String(move.target.sk).startsWith("CONTROL#"),
    );
    expect(control?.target).toEqual(
      expect.objectContaining({
        pk: head?.target.pk,
        revisionPk: head?.target.pk,
        serialized: expect.objectContaining({
          secretUid: head?.target.secretUid,
        }),
      }),
    );
    expect(plan.lookups).toEqual([
      expect.objectContaining({
        key: { pk: "SECRET_NAME#prod#payments/api-key", sk: "LOOKUP" },
        item: expect.objectContaining({ secretUid: head?.target.secretUid }),
      }),
    ]);
  });

  it("moves consumer grants to the UID-keyed access row", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret(),
      {
        pk: "CONSUMER#payments-agent",
        sk: "SECRET#prod#payments/api-key",
        consumerId: "payments-agent",
        environment: "prod",
        secretId: "payments/api-key",
        permissions: ["read"],
      },
    ]);

    expect(plan.accessMoves).toEqual([
      expect.objectContaining({
        sourceKey: {
          pk: "CONSUMER#payments-agent",
          sk: "SECRET#prod#payments/api-key",
        },
        target: expect.objectContaining({
          sk: expect.stringMatching(/^SECRET#prod#sec-/),
          secretUid: expect.stringMatching(/^sec-/),
        }),
      }),
    ]);
  });

  it("snapshots a prefix to paired exact permissions without a lookalike match", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret("payments/api-key"),
      ...legacySecret("payments-prod/api-key"),
      {
        pk: "AGENT_GRANT#grant-payments",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["read"],
        readSecretIdPrefixes: ["payments"],
        writeSecretIdPrefixes: [],
      },
    ]);

    expect(plan.issues).toEqual([]);
    expect(plan.grantUpdates).toEqual([
      expect.objectContaining({
        item: expect.objectContaining({
          secretGrants: [
            {
              secretId: "payments/api-key",
              secretUid: expect.stringMatching(/^sec-/),
              permissions: ["read"],
            },
          ],
        }),
      }),
    ]);
  });

  it("converts an unmatched prefix to no exact permissions instead of future access", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret(),
      {
        pk: "AGENT_GRANT#grant-future",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["write"],
        readSecretIdPrefixes: [],
        writeSecretIdPrefixes: ["future"],
      },
    ]);

    expect(plan.issues).toEqual([]);
    expect(plan.grantUpdates[0]?.item).toEqual(
      expect.objectContaining({
        secretGrants: [],
      }),
    );
  });

  it("converts an exact-ID grant to paired immutable secret records", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret(),
      {
        pk: "AGENT_GRANT#grant-payments",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["read"],
        readSecretIds: ["payments/api-key"],
        writeSecretIds: [],
      },
    ]);

    expect(plan.issues).toEqual([]);
    expect(plan.grantUpdates).toEqual([
      expect.objectContaining({
        item: expect.objectContaining({
          secretGrants: [
            {
              secretId: "payments/api-key",
              secretUid: expect.stringMatching(/^sec-/),
              permissions: ["read"],
            },
          ],
        }),
      }),
    ]);
  });

  it("rebuilds paired records from live heads instead of zipping independently sorted legacy arrays", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret("payments/alpha"),
      ...legacySecret("payments/bravo"),
      {
        pk: "AGENT_GRANT#grant-payments",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["read"],
        readSecretIds: ["payments/alpha", "payments/bravo"],
        // This legacy order is deliberately incompatible with the ID order.
        readSecretUids: ["sec-bravo", "sec-alpha"],
        writeSecretIds: [],
        writeSecretUids: [],
      },
    ]);

    expect(plan.issues).toEqual([]);
    const grants = plan.grantUpdates[0]?.item.secretGrants as readonly {
      readonly secretId: string;
      readonly secretUid: string;
      readonly permissions: readonly string[];
    }[];
    expect(grants).toEqual([
      {
        secretId: "payments/alpha",
        secretUid: expect.stringMatching(/^sec-/),
        permissions: ["read"],
      },
      {
        secretId: "payments/bravo",
        secretUid: expect.stringMatching(/^sec-/),
        permissions: ["read"],
      },
    ]);
    expect(grants[0]?.secretUid).not.toBe("sec-bravo");
    expect(grants[1]?.secretUid).not.toBe("sec-alpha");
    expect(plan.grantUpdates[0]?.item.readSecretIds).toBeUndefined();
    expect(plan.grantUpdates[0]?.item.readSecretUids).toBeUndefined();
  });

  it("keeps an already paired grant while removing all obsolete parallel fields", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret(),
      {
        pk: "AGENT_GRANT#grant-paired",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["read"],
        secretGrants: [
          {
            secretId: "payments/api-key",
            secretUid: "sec-original-pair",
            permissions: ["read"],
          },
        ],
        readSecretIds: ["payments/api-key"],
        readSecretUids: ["sec-wrong-legacy-value"],
      },
    ]);

    expect(plan.issues).toEqual([]);
    expect(plan.grantUpdates[0]?.item).toEqual(
      expect.objectContaining({
        secretGrants: [
          {
            secretId: "payments/api-key",
            secretUid: "sec-original-pair",
            permissions: ["read"],
          },
        ],
      }),
    );
    expect(plan.grantUpdates[0]?.item.readSecretIds).toBeUndefined();
    expect(plan.grantUpdates[0]?.item.readSecretUids).toBeUndefined();
  });

  it("refuses to guess how legacy metadata paths map to exact secret IDs", () => {
    const plan = buildSecretUidMigrationPlan([
      ...legacySecret(),
      {
        pk: "AGENT_GRANT#grant-legacy",
        sk: "PROFILE",
        environment: "prod",
        capabilities: ["read"],
        readPathPrefixes: ["payments"],
        writePathPrefixes: [],
      },
    ]);

    expect(plan.grantUpdates).toEqual([]);
    expect(plan.issues).toEqual([
      "AGENT_GRANT#grant-legacy uses unsupported legacy readPathPrefixes.",
    ]);
  });

  it("is resumable after secret rows have moved but before the name lookup is written", () => {
    const movedHead = {
      pk: "SECRET#sec-migrated",
      sk: "HEAD",
      secretUid: "sec-migrated",
      secretId: "payments/api-key",
      environment: "prod",
      controlVersionId: "ctl-current",
      controlObjectVersionId: "control-version",
      controlObjectKey:
        "secrets/prod/payments/api-key/control/ctl-current.json",
      workflowState: "READY",
      state: "ACTIVE",
    };
    const plan = buildSecretUidMigrationPlan([movedHead]);

    expect(plan.secretMoves).toEqual([]);
    expect(plan.lookups).toEqual([
      expect.objectContaining({
        item: expect.objectContaining({ secretUid: "sec-migrated" }),
      }),
    ]);
  });

  it("keeps an archived UID distinct from a live secret that reuses its ID", () => {
    const plan = buildSecretUidMigrationPlan([
      {
        pk: "SECRET#sec-archived",
        sk: "HEAD",
        secretUid: "sec-archived",
        secretId: "payments/api-key",
        environment: "prod",
        state: "ARCHIVED",
      },
      {
        pk: "SECRET#sec-reused",
        sk: "HEAD",
        secretUid: "sec-reused",
        secretId: "payments/api-key",
        environment: "prod",
        state: "ACTIVE",
      },
    ]);

    expect(plan.secretMoves).toEqual([]);
    expect(plan.issues).toEqual([]);
    expect(plan.lookups).toEqual([
      expect.objectContaining({
        item: expect.objectContaining({ secretUid: "sec-reused" }),
      }),
    ]);
  });
});
