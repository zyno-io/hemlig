import type { AgentGrantRecord } from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import type { AppConfig } from "../aws/config";
import type { AgentSyncRecord } from "../repositories/agent-sync";
import { CursorService, type StoredCursor } from "./cursor";
import { AgentSyncService } from "./agent-sync";

const grant: AgentGrantRecord = {
  pk: "AGENT_GRANT#g",
  sk: "PROFILE",
  grantId: "g",
  consumerId: "c",
  environment: "prod",
  status: "ACTIVE",
  capabilities: ["read", "write"],
  secretGrants: [
    { secretId: "a", secretUid: "uid-a", permissions: ["read", "write"] },
  ],
  createdAt: "2026-10-07T00:00:00Z",
  createdBy: { type: "human", id: "admin" },
};
const record: AgentSyncRecord = {
  secretUid: "uid-a",
  secretId: "a",
  controlVersionId: "ctl-1",
  payloadVersionId: "pay-1",
  state: "ACTIVE",
  metadata: { description: "safe metadata" },
  readConsumerIds: ["c"],
};

const fixture = () => {
  const stored = new Map<string, StoredCursor>();
  const state = { epoch: "epoch", sequence: 1, ready: true };
  const page = jest.fn(
    async (
      _environment: string,
      _after: number,
      _through: number,
      _lastSk?: string,
    ): Promise<{ records: readonly AgentSyncRecord[]; lastSk?: string }> => ({
      records: [record],
    }),
  );
  const repository = {
    agentSync: { state: jest.fn(async () => state), page },
    createCursor: jest.fn(async (cursor: StoredCursor) => {
      stored.set(cursor.token, cursor);
      return true;
    }),
    getCursor: jest.fn(async (token: string) => stored.get(token)),
  };
  const service = new AgentSyncService(
    repository as unknown as DynamoRepository,
    new CursorService(repository),
    {
      iotEndpoint: "iot.test",
      iotNotificationTopicPrefix: "test",
    } as AppConfig,
  );
  return { service, repository, page, state, stored };
};

it("returns current UID-scoped versions with no ACL or payload and skips outside scope", async () => {
  const f = fixture();
  f.page.mockResolvedValue({
    records: [record, { ...record, secretUid: "other", secretId: "outside" }],
  });
  const result = await f.service.sync("c", "prod", {}, grant);
  expect(result.snapshot).toBe(true);
  expect(result.changes).toEqual([
    {
      secretUid: "uid-a",
      secretId: "a",
      controlVersionId: "ctl-1",
      payloadVersionId: "pay-1",
      state: "ACTIVE",
      permissions: ["read", "write"],
      metadata: record.metadata,
    },
  ]);
  expect(result.syncCursor).toBeDefined();
  expect(result.nextCursor).toBeUndefined();
});

it("reuses an unchanged checkpoint without writing another cursor", async () => {
  const f = fixture();
  const initial = await f.service.sync("c", "prod", {}, grant);
  f.page.mockResolvedValue({ records: [] });
  const result = await f.service.sync(
    "c",
    "prod",
    { syncCursor: initial.syncCursor },
    grant,
  );
  expect(result).toMatchObject({
    snapshot: false,
    syncCursor: initial.syncCursor,
    changes: [],
  });
  expect(f.repository.createCursor).toHaveBeenCalledTimes(1);
  expect(f.page).toHaveBeenLastCalledWith("prod", 1, 1, undefined);
});

it("keeps checkpoints valid when equivalent grant attributes are reordered", async () => {
  const f = fixture();
  const initial = await f.service.sync("c", "prod", {}, grant);
  f.page.mockResolvedValue({ records: [] });
  const result = await f.service.sync(
    "c",
    "prod",
    { syncCursor: initial.syncCursor },
    {
      ...grant,
      capabilities: ["write", "read"],
      secretGrants: [
        { permissions: ["write", "read"], secretUid: "uid-a", secretId: "a" },
      ],
    },
  );
  expect(result.syncCursor).toBe(initial.syncCursor);
});

it("pins a paginated range and catches later concurrent movement in the next delta", async () => {
  const f = fixture();
  f.state.sequence = 10;
  f.page
    .mockResolvedValueOnce({ records: [record], lastSk: "CHANGE#page" })
    .mockResolvedValueOnce({ records: [] });
  const first = await f.service.sync("c", "prod", {}, grant);
  expect(first.syncCursor).toBeUndefined();
  f.state.sequence = 12;
  const final = await f.service.sync(
    "c",
    "prod",
    { cursor: first.nextCursor },
    grant,
  );
  expect(f.page).toHaveBeenLastCalledWith("prod", 0, 10, "CHANGE#page");
  f.page.mockResolvedValue({
    records: [{ ...record, controlVersionId: "ctl-12" }],
  });
  const delta = await f.service.sync(
    "c",
    "prod",
    { syncCursor: final.syncCursor },
    grant,
  );
  expect(f.page).toHaveBeenLastCalledWith("prod", 10, 12, undefined);
  expect(delta.changes[0]?.controlVersionId).toBe("ctl-12");
});

it("keeps cycle deadlines fixed across pages instead of extending retention assumptions", async () => {
  const f = fixture();
  f.page
    .mockResolvedValueOnce({ records: [], lastSk: "CHANGE#page" })
    .mockResolvedValueOnce({ records: [] });
  const first = await f.service.sync("c", "prod", {}, grant);
  const firstState = f.stored.get(first.nextCursor ?? "");
  const final = await f.service.sync(
    "c",
    "prod",
    { cursor: first.nextCursor },
    grant,
  );
  expect(f.stored.get(final.syncCursor ?? "")?.expiresAt).toBe(
    firstState?.lastEvaluatedKey?.checkpointExpiresAt,
  );
});

it("requires fresh snapshots for scope changes, expired tokens, or replaced epochs", async () => {
  const f = fixture();
  const initial = await f.service.sync("c", "prod", {}, grant);
  await expect(
    f.service.sync(
      "c",
      "prod",
      { syncCursor: initial.syncCursor },
      { ...grant, capabilities: ["read"] },
    ),
  ).rejects.toMatchObject({ statusCode: 410, code: "sync_reset_required" });
  f.state.epoch = "replacement";
  await expect(
    f.service.sync("c", "prod", { syncCursor: initial.syncCursor }, grant),
  ).rejects.toMatchObject({ statusCode: 410 });
  f.state.epoch = "epoch";
  const cursor = f.stored.get(initial.syncCursor ?? "");
  if (cursor === undefined) throw new Error("fixture cursor missing");
  f.stored.set(cursor.token, { ...cursor, expiresAt: "2000-01-01T00:00:00Z" });
  await expect(
    f.service.sync("c", "prod", { syncCursor: initial.syncCursor }, grant),
  ).rejects.toMatchObject({ statusCode: 410 });
});

it("rejects malformed, cross-consumer, and conflicting cursor arguments", async () => {
  const f = fixture();
  const initial = await f.service.sync("c", "prod", {}, grant);
  await expect(
    f.service.sync("c", "prod", { syncCursor: "malformed" }, grant),
  ).rejects.toMatchObject({ statusCode: 400 });
  await expect(
    f.service.sync(
      "other",
      "prod",
      { syncCursor: initial.syncCursor },
      { ...grant, consumerId: "other" },
    ),
  ).rejects.toMatchObject({ statusCode: 400 });
  await expect(
    f.service.sync(
      "c",
      "prod",
      { syncCursor: initial.syncCursor, cursor: initial.syncCursor },
      grant,
    ),
  ).rejects.toMatchObject({ statusCode: 400 });
  await expect(
    f.service.sync("c", "prod", { cursor: initial.syncCursor }, grant),
  ).rejects.toMatchObject({ statusCode: 400 });
});

it("revokes a read-only selection when ACL access is removed without leaking metadata or payload versions", async () => {
  const f = fixture();
  f.page.mockResolvedValue({ records: [{ ...record, readConsumerIds: [] }] });
  const result = await f.service.sync(
    "c",
    "prod",
    {},
    {
      ...grant,
      capabilities: ["read"],
      secretGrants: [{ ...grant.secretGrants[0]!, permissions: ["read"] }],
    },
  );
  expect(result.changes[0]).toEqual({
    secretUid: "uid-a",
    secretId: "a",
    controlVersionId: "ctl-1",
    state: "REVOKED",
    permissions: [],
  });
});

it("supports write-only selections independently of read ACL and keeps read metadata private", async () => {
  const f = fixture();
  f.page.mockResolvedValue({ records: [{ ...record, readConsumerIds: [] }] });
  const written = await f.service.sync(
    "c",
    "prod",
    {},
    {
      ...grant,
      capabilities: ["write"],
      secretGrants: [{ ...grant.secretGrants[0]!, permissions: ["write"] }],
    },
  );
  expect(written.changes[0]).toMatchObject({
    state: "ACTIVE",
    permissions: ["write"],
    metadata: record.metadata,
  });
  f.page.mockResolvedValue({ records: [record] });
  const read = await f.service.sync(
    "c",
    "prod",
    {},
    {
      ...grant,
      capabilities: ["read"],
      secretGrants: [{ ...grant.secretGrants[0]!, permissions: ["read"] }],
    },
  );
  expect(read.changes[0]).not.toHaveProperty("metadata");
});

it("archives only the selected UID and never substitutes a reused public name", async () => {
  const f = fixture();
  f.page.mockResolvedValue({
    records: [
      { ...record, state: "ARCHIVED" },
      { ...record, secretUid: "replacement", controlVersionId: "replacement" },
    ],
  });
  const result = await f.service.sync("c", "prod", {}, grant);
  expect(result.changes).toEqual([
    {
      secretUid: "uid-a",
      secretId: "a",
      controlVersionId: "ctl-1",
      state: "REVOKED",
      permissions: [],
    },
  ]);
});

it("allows an empty active grant to remove mirrors but rejects inactive/unscoped identities and unready indexes", async () => {
  const f = fixture();
  const result = await f.service.sync(
    "c",
    "prod",
    {},
    { ...grant, capabilities: [], secretGrants: [] },
  );
  expect(result.changes).toEqual([]);
  await expect(
    f.service.sync("c", "prod", {}, undefined),
  ).rejects.toMatchObject({ statusCode: 403 });
  await expect(
    f.service.sync("c", "prod", {}, { ...grant, status: "PENDING" }),
  ).rejects.toMatchObject({ statusCode: 403 });
  f.state.ready = false;
  await expect(f.service.sync("c", "prod", {}, grant)).rejects.toMatchObject({
    statusCode: 503,
    code: "sync_index_not_ready",
  });
});
