import assert from "node:assert/strict";
import test from "node:test";
import { KeyedWorkQueue, type Outcome, type WorkContext } from "./queue";
import { FakeScheduler, flush } from "./test-fakes";

type Handler = (key: string, ctx: WorkContext) => Promise<Outcome>;
const make = (
  handler: Handler,
  options: { concurrency?: number; groupConcurrency?: number } = {},
) => {
  const scheduler = new FakeScheduler();
  const queue = new KeyedWorkQueue(handler, {
    concurrency: options.concurrency ?? 4,
    groupConcurrency: options.groupConcurrency ?? 2,
    scheduler,
  });
  return { scheduler, queue };
};
const done: Outcome = { kind: "done" };
const gate = () => {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
};

test("three adds of a queued key run once", async () => {
  const runs: string[] = [];
  const hold = gate();
  const { queue } = make(
    async (key) => {
      runs.push(key);
      if (key === "blocker") await hold.promise;
      return done;
    },
    { concurrency: 1 },
  );
  queue.add("blocker");
  queue.add("a");
  queue.add("a");
  queue.add("a");
  hold.open();
  await queue.whenIdle();
  assert.deepEqual(runs, ["blocker", "a"]);
});

test("an add during processing causes exactly one re-run", async () => {
  const hold = gate();
  let runs = 0;
  const { queue } = make(async () => {
    runs += 1;
    if (runs === 1) await hold.promise;
    return done;
  });
  queue.add("a");
  await flush();
  queue.add("a");
  queue.add("a");
  hold.open();
  await queue.whenIdle();
  await flush();
  assert.equal(runs, 2);
});

test("global concurrency caps in-flight runs", async () => {
  let inFlight = 0;
  let peak = 0;
  const hold = gate();
  const { queue } = make(async () => {
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    await hold.promise;
    inFlight -= 1;
    return done;
  });
  for (let i = 0; i < 10; i += 1) queue.add(`k${i}`);
  await flush();
  assert.equal(inFlight, 4);
  hold.open();
  await queue.whenIdle();
  assert.equal(peak, 4);
});

test("group limit parks keys, resumes on release and does not block other groups", async () => {
  const holds = new Map<string, ReturnType<typeof gate>>();
  const finished: string[] = [];
  const releases = new Map<string, () => void>();
  const { queue } = make(
    async (key, ctx) => {
      const group = key.startsWith("b") ? "B" : "A";
      const release = ctx.tryAcquire(group);
      if (release === undefined) return { kind: "defer", group };
      releases.set(key, release);
      holds.set(key, gate());
      await holds.get(key)!.promise;
      release();
      finished.push(key);
      return done;
    },
    { concurrency: 10 },
  );
  for (const key of ["a1", "a2", "a3", "b1"]) queue.add(key);
  await flush();
  assert.deepEqual([...holds.keys()].sort(), ["a1", "a2", "b1"]);
  assert.equal(holds.has("a3"), false);
  holds.get("b1")!.open();
  await flush();
  assert.deepEqual(finished, ["b1"]);
  holds.get("a1")!.open();
  await flush();
  assert.ok(holds.has("a3"));
  holds.get("a2")!.open();
  holds.get("a3")!.open();
  await queue.whenIdle();
  assert.deepEqual(finished.sort(), ["a1", "a2", "a3", "b1"]);
});

test("lost wakeup: a release between tryAcquire failing and the defer return re-queues", async () => {
  let holderRelease: (() => void) | undefined;
  const lateGate = gate();
  let lateRuns = 0;
  let lateAcquired = false;
  const { queue } = make(
    async (key, ctx) => {
      if (key === "holder") {
        holderRelease = ctx.tryAcquire("G");
        return new Promise<Outcome>(() => {});
      }
      lateRuns += 1;
      const release = ctx.tryAcquire("G");
      if (release === undefined) {
        await lateGate.promise;
        return { kind: "defer", group: "G" };
      }
      lateAcquired = true;
      release();
      return done;
    },
    { groupConcurrency: 1 },
  );
  queue.add("holder");
  await flush();
  queue.add("late");
  await flush();
  // The slot frees while "late" is between its failed tryAcquire and its return.
  holderRelease!();
  lateGate.open();
  await flush();
  assert.equal(lateRuns, 2);
  assert.equal(lateAcquired, true);
});

test("retry delays use equal jitter, double, and cap at five minutes", async () => {
  const { queue, scheduler } = make(async () => ({
    kind: "retry",
    policy: "slow",
  }));
  scheduler.randomValue = 0;
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 15_000);
  await scheduler.advance(15_000);
  assert.equal(queue.scheduledDelay("k"), 30_000);
  await scheduler.advance(30_000);
  assert.equal(queue.scheduledDelay("k"), 60_000);
  for (let i = 0; i < 6; i += 1) {
    await scheduler.advance(queue.scheduledDelay("k")!);
  }
  assert.equal(queue.scheduledDelay("k"), 150_000);
  scheduler.randomValue = 0.999999;
  await scheduler.advance(150_000);
  assert.ok(queue.scheduledDelay("k")! <= 300_000);
  assert.ok(queue.scheduledDelay("k")! >= 150_000);
  queue.stop();
});

test("fast policy starts at one second", async () => {
  const { queue, scheduler } = make(async () => ({
    kind: "retry",
    policy: "fast",
  }));
  scheduler.randomValue = 0;
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 500);
  scheduler.randomValue = 1;
  queue.forget("k");
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 1000);
  queue.stop();
});

test("minDelayMs raises the retry delay", async () => {
  const { queue } = make(async () => ({
    kind: "retry",
    policy: "fast",
    minDelayMs: 9_000,
  }));
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 9_000);
  queue.stop();
});

test("retryAfter delay is within [d, d + min(30s, 10%)]", async () => {
  const { queue, scheduler } = make(async () => ({
    kind: "retryAfter",
    delayMs: 120_000,
  }));
  scheduler.randomValue = 1;
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 120_000 + 12_000);
  queue.forget("k");
  scheduler.randomValue = 0;
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 120_000);
  queue.stop();
});

test("add during a timer is a no-op; resetBackoff runs now", async () => {
  let runs = 0;
  const { queue } = make(async () => {
    runs += 1;
    return runs === 1 ? { kind: "retry", policy: "slow" } : done;
  });
  queue.add("k");
  await queue.whenIdle();
  queue.add("k");
  await flush();
  assert.equal(runs, 1);
  queue.add("k", { resetBackoff: true });
  await queue.whenIdle();
  assert.equal(runs, 2);
  assert.equal(queue.scheduledDelay("k"), undefined);
});

test("a retry outcome clears dirty (no hot loop on own status events)", async () => {
  const hold = gate();
  let runs = 0;
  const { queue, scheduler } = make(async () => {
    runs += 1;
    await hold.promise;
    return { kind: "retry", policy: "slow" };
  });
  queue.add("k");
  await flush();
  queue.add("k");
  hold.open();
  await queue.whenIdle();
  await flush();
  assert.equal(runs, 1);
  assert.ok(queue.scheduledDelay("k") !== undefined);
  queue.stop();
  assert.equal(scheduler.pendingTimers, 0);
});

test("done resets attempts", async () => {
  let outcome: Outcome = { kind: "retry", policy: "slow" };
  const { queue, scheduler } = make(async () => outcome);
  scheduler.randomValue = 0;
  queue.add("k");
  await queue.whenIdle();
  await scheduler.advance(15_000);
  assert.equal(queue.scheduledDelay("k"), 30_000);
  outcome = done;
  await scheduler.advance(30_000);
  outcome = { kind: "retry", policy: "slow" };
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 15_000);
  queue.stop();
});

test("a thrown handler is a fast retry", async () => {
  const { queue, scheduler } = make(async () => {
    throw new Error("boom");
  });
  scheduler.randomValue = 0;
  queue.add("k");
  await queue.whenIdle();
  assert.equal(queue.scheduledDelay("k"), 500);
  queue.stop();
});

test("forget cancels the timer and drops a running key's outcome", async () => {
  const hold = gate();
  let calls = 0;
  const { queue, scheduler } = make(async (key) => {
    calls += 1;
    if (key === "running") await hold.promise;
    return { kind: "retry", policy: "slow" };
  });
  queue.add("timed");
  await queue.whenIdle();
  assert.equal(scheduler.pendingTimers, 1);
  queue.forget("timed");
  assert.equal(scheduler.pendingTimers, 0);
  queue.add("running");
  await flush();
  queue.forget("running");
  hold.open();
  await queue.whenIdle();
  await flush();
  assert.equal(scheduler.pendingTimers, 0);
  assert.equal(calls, 2);
});

test("stop clears timers and ignores later adds", async () => {
  let runs = 0;
  const { queue, scheduler } = make(async () => {
    runs += 1;
    return { kind: "retry", policy: "slow" };
  });
  queue.add("k");
  await queue.whenIdle();
  queue.stop();
  assert.equal(scheduler.pendingTimers, 0);
  queue.add("k");
  await flush();
  assert.equal(runs, 1);
});
