import { runMaintenancePass } from "./maintenance";
import type { CaCrlState, CaRecord, ExternalCaRecord } from "./types";

const now = new Date("2026-11-22T12:00:00.000Z");
const iso = (ms: number) => new Date(now.getTime() + ms).toISOString();
const day = 86_400_000;

const published = (
  overrides: Partial<NonNullable<CaCrlState["published"]>> = {},
) => ({
  number: 1,
  objectKey: "k",
  sha256: "s",
  thisUpdate: iso(-day),
  nextUpdate: iso(6 * day),
  revision: 0,
  entryCount: 0,
  ...overrides,
});
const crlState = (overrides: Partial<CaCrlState> = {}): CaCrlState => ({
  revision: 0,
  lastNumber: 1,
  published: published(),
  sweptThrough: iso(-day),
  ...overrides,
});
const ca = (caId: string, overrides: Partial<CaRecord> = {}): CaRecord =>
  ({
    caId,
    environment: "prod",
    status: "ACTIVE",
    version: "v",
    key: { state: "ACTIVE" },
    policy: {
      crlValiditySeconds: 7 * 86_400,
      capacity: 100,
      maxLeafLifetimeSeconds: 3600,
    },
    maxIssueLifetimeEverSeconds: 3600,
    notAfter: iso(300 * day),
    parent: { type: "external", id: "ext-1" },
    ...overrides,
  }) as CaRecord;

interface World {
  cas: CaRecord[];
  crls?: Record<string, CaCrlState>;
  externals?: ExternalCaRecord[];
  publish?: jest.Mock;
  retireExpired?: jest.Mock;
  disable?: jest.Mock;
  revokeAncestor?: jest.Mock;
  failLoad?: string;
  /** Count returned by the capacity recount; a thrown error when `failCapacity`. */
  counted?: number;
  failCapacity?: string;
}

const run = async (world: World, remainingMs = () => 300_000) => {
  const order: string[] = [];
  const crls = { ...world.crls };
  const publish =
    world.publish ??
    jest.fn(async (target: CaRecord) => {
      order.push(`publish:${target.caId}`);
      crls[target.caId] = crlState({
        published: published({
          number: 2,
          thisUpdate: now.toISOString(),
          nextUpdate: iso(7 * day),
        }),
      });
      return { kind: "published", pointer: { number: 2, entryCount: 0 } };
    });
  const app = {
    config: { environmentName: "test" },
    audit: { write: jest.fn(async () => ({})) },
    pki: {
      queryDirectory: jest.fn(async (partition: string) =>
        partition === "PKI_CAS"
          ? world.cas.map((item) => ({ caId: item.caId }))
          : (world.externals ?? []).map((item) => ({ extId: item.extId })),
      ),
      getCa: jest.fn(async (id: string) => {
        if (id === world.failLoad) {
          throw new Error("boom");
        }
        return world.cas.find((item) => item.caId === id);
      }),
      getCaCrlState: jest.fn(async (id: string) => crls[id]),
      getExternalCa: jest.fn(async (id: string) =>
        world.externals?.find((item) => item.extId === id),
      ),
      expireCarriedRevocations: jest.fn(async (id: string) => {
        order.push(`sweep:${id}`);
        return 0;
      }),
      markCrlSwept: jest.fn(async () => undefined),
    },
    cas: {
      retireExpired:
        world.retireExpired ??
        jest.fn(async (target: CaRecord) => {
          order.push(`retire:${target.caId}`);
          return {
            ...target,
            status: "RETIRED",
            retiredAt: target.notAfter,
            version: "v2",
          };
        }),
      revokeForRevokedAncestor:
        world.revokeAncestor ??
        jest.fn(async (target: CaRecord, parent: CaRecord) => {
          order.push(`ancestor:${target.caId}`);
          return {
            ...target,
            status: "REVOKED",
            revocationEvidence: `ancestor:${parent.caId}`,
            version: "v3",
          };
        }),
      disableDrainedKey:
        world.disable ??
        jest.fn(async (target: CaRecord) => {
          order.push(`drain:${target.caId}`);
          return true;
        }),
    },
    crls: { publish },
    capacity: {
      recount: jest.fn(async (target: CaRecord) => {
        if (target.caId === world.failCapacity) {
          throw new Error("boom");
        }
        order.push(`count:${target.caId}`);
        return world.counted ?? 0;
      }),
    },
  };
  const emit = jest.fn();
  const log = jest.fn();
  let result;
  let error;
  try {
    result = await runMaintenancePass({
      app: app as never,
      now,
      remainingMs,
      correlationId: "c",
      emit,
      log,
    });
  } catch (caught) {
    error = caught as Error;
  }
  return { result, error, app, emit, log, order, publish };
};

const external = (
  overrides: Partial<ExternalCaRecord> = {},
): ExternalCaRecord =>
  ({
    extId: "ext-1",
    dependents: new Set(["ca-a"]),
    environments: new Set(["prod"]),
    createdAt: iso(-2 * day),
    crl: { nextUpdate: iso(60 * day) },
    ...overrides,
  }) as unknown as ExternalCaRecord;

describe("runMaintenancePass", () => {
  it("runs expiry, publish, drain and sweep in order", async () => {
    const expired = ca("ca-exp", { notAfter: iso(-1000) });
    const drain = ca("ca-drain", {
      status: "RETIRED",
      retiredAt: iso(-2 * day),
      maxIssueLifetimeEverSeconds: 3600,
    });
    const sweep = ca("ca-sweep");
    const { order, result } = await run({
      cas: [expired, drain, sweep],
      crls: {
        "ca-exp": crlState(),
        "ca-drain": crlState({
          published: published({ thisUpdate: iso(-day) }),
        }),
        "ca-sweep": crlState({ sweptThrough: iso(-5 * day) }),
      },
    });
    expect(order.indexOf("retire:ca-exp")).toBeLessThan(
      order.indexOf("publish:ca-exp"),
    );
    expect(order.indexOf("publish:ca-exp")).toBeLessThan(
      order.indexOf("drain:ca-exp"),
    );
    expect(order.indexOf("drain:ca-drain")).toBeGreaterThan(-1);
    expect(order).toContain("sweep:ca-sweep");
    expect(order.indexOf("drain:ca-exp")).toBeLessThan(
      order.indexOf("sweep:ca-sweep"),
    );
    expect(result).toMatchObject({ retired: 1, failures: 0 });
  });

  it("isolates a failing CA, finishes the others, and throws at the end", async () => {
    const { error, order, emit, result } = await run({
      cas: [ca("ca-bad"), ca("ca-good", { notAfter: iso(-1000) })],
      crls: { "ca-good": crlState() },
      failLoad: "ca-bad",
    });
    expect(result).toBeUndefined();
    expect(error?.message).toContain("1 failure");
    expect(order).toContain("retire:ca-good");
    expect(emit).toHaveBeenCalled();
  });

  it("publishes the most urgent first and stops when the budget runs out", async () => {
    const worlds = {
      cas: [ca("ca-late"), ca("ca-urgent"), ca("ca-skipped")],
      crls: {
        "ca-late": crlState({
          revision: 1,
          published: published({ nextUpdate: iso(5 * day) }),
        }),
        "ca-urgent": crlState({
          revision: 1,
          published: published({ nextUpdate: iso(1 * day) }),
        }),
        "ca-skipped": crlState({
          revision: 1,
          published: published({ nextUpdate: iso(3 * day) }),
        }),
      },
    };
    const ordered = await run(worlds);
    expect(
      ordered.order.filter((entry) => entry.startsWith("publish")),
    ).toEqual(["publish:ca-urgent", "publish:ca-skipped", "publish:ca-late"]);
    let calls = 0;
    const cut = await run(worlds, () => (calls++ === 0 ? 300_000 : 10_000));
    // Two skipped publications and three skipped capacity recounts.
    expect(cut.result).toMatchObject({ published: 1, skipped: 5 });
    expect(cut.log).toHaveBeenCalledWith(
      expect.objectContaining({ event: "pki_maintenance_budget_exhausted" }),
    );
  });

  it("does not count busy or superseded as failures", async () => {
    for (const kind of ["busy", "superseded"]) {
      const { result } = await run({
        cas: [ca("ca-a")],
        crls: { "ca-a": crlState({ revision: 1 }) },
        publish: jest.fn(async () => ({ kind })),
      });
      expect(result).toMatchObject({ published: 0, failures: 0 });
    }
  });

  it("emits every metric, zeros included, and audits as the system actor", async () => {
    const { emit, app } = await run({
      cas: [ca("ca-a", { notAfter: iso(-1000) })],
      crls: { "ca-a": crlState() },
    });
    expect(emit).toHaveBeenCalledWith("test", {
      GeneratedCrlStale: 0,
      ExternalCrlStale: 0,
      ExternalCrlMissing: 0,
      CaExpiring: 0,
      CrlOverCapacity: 0,
      CaCapacityHigh: 0,
    });
    expect(app.audit.write).toHaveBeenCalledWith(
      expect.objectContaining({
        actor: { type: "system", id: "pki-maintenance" },
        operation: "pki.ca.retire",
        outcome: "succeeded",
        target: expect.objectContaining({ reason: "expired" }),
      }),
    );
  });

  it("counts stale CRLs, expiring CAs and over-capacity CRLs", async () => {
    const { emit } = await run({
      cas: [
        ca("ca-stale", {
          policy: {
            crlValiditySeconds: 7 * 86_400,
            capacity: 100,
          } as CaRecord["policy"],
        }),
        ca("ca-expiring", { notAfter: iso(20 * day) }),
        ca("ca-over"),
      ],
      crls: {
        "ca-stale": crlState({
          published: published({
            thisUpdate: iso(-7 * day + 1000),
            nextUpdate: iso(1000),
          }),
        }),
        "ca-expiring": crlState(),
        "ca-over": crlState({ published: published({ entryCount: 101 }) }),
      },
      publish: jest.fn(async () => ({ kind: "busy" })),
    });
    expect(emit.mock.calls[0]![1]).toMatchObject({
      GeneratedCrlStale: 1,
      CaExpiring: 1,
      CrlOverCapacity: 1,
    });
  });

  it("flags external CAs only while a dependent is live", async () => {
    const live = ca("ca-a");
    const dead = ca("ca-dead", {
      status: "RETIRED",
      key: { state: "DISABLED" } as CaRecord["key"],
      notAfter: iso(300 * day),
    });
    const base = { cas: [live, dead], crls: { "ca-a": crlState() } };
    const missing = await run({
      ...base,
      externals: [external({ crl: undefined })],
    });
    expect(missing.emit.mock.calls[0]![1]).toMatchObject({
      ExternalCrlMissing: 1,
      ExternalCrlStale: 0,
    });
    const young = await run({
      ...base,
      externals: [external({ crl: undefined, createdAt: iso(-3600_000) })],
    });
    expect(young.emit.mock.calls[0]![1]).toMatchObject({
      ExternalCrlMissing: 0,
    });
    const stale = await run({
      ...base,
      externals: [external({ crl: { nextUpdate: iso(20 * day) } as never })],
    });
    expect(stale.emit.mock.calls[0]![1]).toMatchObject({ ExternalCrlStale: 1 });
    const healthy = await run({ ...base, externals: [external()] });
    expect(healthy.emit.mock.calls[0]![1]).toMatchObject({
      ExternalCrlStale: 0,
      ExternalCrlMissing: 0,
    });
    const noLive = await run({
      cas: [dead],
      externals: [
        external({ dependents: new Set(["ca-dead"]), crl: undefined }),
      ],
    });
    expect(noLive.emit.mock.calls[0]![1]).toMatchObject({
      ExternalCrlMissing: 0,
    });
    const revoked = ca("ca-rev", {
      status: "REVOKED",
      notAfter: iso(10 * day),
    });
    const stillLive = await run({
      cas: [revoked],
      externals: [
        external({ dependents: new Set(["ca-rev"]), crl: undefined }),
      ],
    });
    expect(stillLive.emit.mock.calls[0]![1]).toMatchObject({
      ExternalCrlMissing: 1,
    });
  });

  it("clears the stale alarm after a scheduled refresh", async () => {
    const stale = ca("ca-a");
    const crls = {
      "ca-a": crlState({
        published: published({
          thisUpdate: iso(-7 * day + 1000),
          nextUpdate: iso(1000),
        }),
      }),
    };
    const { emit } = await run({ cas: [stale], crls });
    expect(emit.mock.calls[0]![1].GeneratedCrlStale).toBe(0);
  });
});

describe("capacity recount", () => {
  it("runs for ACTIVE CAs only", async () => {
    const { app, result, error } = await run({
      cas: [
        ca("ca-a"),
        ca("ca-b", { status: "RETIRED", retiredAt: iso(-day) }),
        ca("ca-c", { status: "REVOKED" }),
      ],
      crls: { "ca-a": crlState(), "ca-b": crlState() },
    });
    expect(error).toBeUndefined();
    expect(app.capacity.recount).toHaveBeenCalledTimes(1);
    expect(app.capacity.recount).toHaveBeenCalledWith(
      expect.objectContaining({ caId: "ca-a" }),
      expect.anything(),
      now,
    );
    expect(result).toMatchObject({ counted: 1 });
  });

  it.each([
    [81, 1],
    [80, 0],
  ])("emits CaCapacityHigh for a count of %i of 100", async (counted, high) => {
    const { emit } = await run({
      cas: [ca("ca-a")],
      crls: { "ca-a": crlState() },
      counted,
    });
    expect(emit.mock.calls[0]![1]).toMatchObject({ CaCapacityHigh: high });
  });

  it("isolates a failing recount and fails the pass", async () => {
    const { error, emit, app } = await run({
      cas: [ca("ca-a"), ca("ca-b")],
      crls: { "ca-a": crlState(), "ca-b": crlState() },
      failCapacity: "ca-a",
      counted: 90,
    });
    expect(error?.message).toMatch(/1 failure/);
    expect(app.capacity.recount).toHaveBeenCalledTimes(2);
    expect(emit.mock.calls[0]![1]).toMatchObject({ CaCapacityHigh: 1 });
  });

  it("skips the recount when the invocation budget is spent", async () => {
    const { app, result } = await run(
      { cas: [ca("ca-a")], crls: { "ca-a": crlState() } },
      () => 1_000,
    );
    expect(app.capacity.recount).not.toHaveBeenCalled();
    expect(result).toMatchObject({ skipped: expect.any(Number) });
  });
});

describe("runMaintenancePass: Hemlig hierarchy", () => {
  const hemlig = (caId: string, overrides: Partial<CaRecord> = {}) =>
    ca(caId, {
      parent: { type: "ca", id: "ca-root" },
      parentCaId: "ca-root",
      ...overrides,
    });
  const root = (overrides: Partial<CaRecord> = {}) =>
    ca("ca-root", { kind: "ROOT", parent: undefined, ...overrides });

  it("finishes the distrust walk for a child of a REVOKED root, with an audit event", async () => {
    const { result, order, app, publish } = await run({
      cas: [
        root({ status: "REVOKED" }),
        hemlig("ca-a"),
        hemlig("ca-b", { status: "RETIRED", retiredAt: iso(-day) }),
      ],
      crls: { "ca-a": crlState(), "ca-b": crlState() },
    });
    expect(result).toMatchObject({ revoked: 2, failures: 0 });
    expect(order).toEqual(
      expect.arrayContaining(["ancestor:ca-a", "ancestor:ca-b"]),
    );
    expect(app.audit.write).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "pki.ca.revoke",
        actor: { type: "system", id: "pki-maintenance" },
        outcome: "succeeded",
        target: {
          caId: "ca-a",
          environment: "prod",
          parentCaId: "ca-root",
          reason: "ancestor_revoked",
          trigger: "maintenance",
        },
      }),
    );
    // A revoked child's CRL is not published in the same pass.
    expect(publish).not.toHaveBeenCalledWith(
      expect.objectContaining({ caId: "ca-a" }),
      expect.anything(),
    );
  });

  it("leaves a child of a healthy root alone and tolerates a missed race", async () => {
    const { result, app } = await run({
      cas: [root(), hemlig("ca-a")],
      crls: { "ca-root": crlState(), "ca-a": crlState() },
    });
    expect(result).toMatchObject({ revoked: 0, failures: 0 });
    expect(app.audit.write).not.toHaveBeenCalled();
    const missed = await run({
      cas: [root({ status: "REVOKED" }), hemlig("ca-a")],
      crls: { "ca-a": crlState() },
      revokeAncestor: jest.fn(async () => undefined),
    });
    expect(missed.result).toMatchObject({ revoked: 0, failures: 0 });
  });

  it("counts a failed flip as a failure", async () => {
    const { error } = await run({
      cas: [root({ status: "REVOKED" }), hemlig("ca-a")],
      crls: { "ca-a": crlState() },
      revokeAncestor: jest.fn(async () => {
        throw new Error("boom");
      }),
    });
    expect(error?.message).toMatch(/1 failure/);
  });

  it("keeps publishing for a RETIRED root with a live child and does not disable its key before the drain point", async () => {
    const retired = root({
      status: "RETIRED",
      retiredAt: iso(-2 * day),
      maxIssueLifetimeEverSeconds: 365 * 86_400,
      notAfter: iso(3000 * day),
    });
    const { order, result, app } = await run({
      cas: [retired, hemlig("ca-a")],
      crls: {
        "ca-root": crlState({
          revision: 1,
          published: published({ revision: 0 }),
        }),
        "ca-a": crlState(),
      },
    });
    expect(order).toContain("publish:ca-root");
    expect(order).not.toContain("drain:ca-root");
    expect(app.cas.disableDrainedKey).not.toHaveBeenCalled();
    expect(result).toMatchObject({ revoked: 0, drained: 0, failures: 0 });
  });
});
