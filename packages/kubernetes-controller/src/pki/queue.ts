import { FAST, SLOW, type Scheduler } from "./types";

export type Outcome =
  /** Success, terminal, or wait-for-event. Resets the backoff. */
  | { readonly kind: "done" }
  | {
      readonly kind: "retry";
      readonly policy: "slow" | "fast";
      readonly minDelayMs?: number;
    }
  | { readonly kind: "retryAfter"; readonly delayMs: number }
  /** The group slot was unavailable. */
  | { readonly kind: "defer"; readonly group: string };

export interface WorkContext {
  tryAcquire(group: string): (() => void) | undefined;
}

export interface QueueOptions {
  readonly concurrency: number;
  readonly groupConcurrency: number;
  readonly scheduler: Scheduler;
}

type State = "queued" | "processing" | "timed" | "parked";

/**
 * A keyed work queue: one run per key at a time, global and per-group
 * concurrency limits, and per-key exponential backoff with jitter.
 */
export class KeyedWorkQueue {
  private readonly states = new Map<string, State>();
  private readonly fifo: string[] = [];
  private readonly attempts = new Map<string, number>();
  private readonly dirty = new Set<string>();
  /** An issuer wake-up arrived while the key was running. */
  private readonly resetRequested = new Set<string>();
  private readonly forgotten = new Set<string>();
  private readonly timers = new Map<
    string,
    { readonly handle: unknown; readonly delay: number }
  >();
  private readonly parked = new Map<string, string[]>();
  private readonly parkedGroup = new Map<string, string>();
  private readonly groupUsed = new Map<string, number>();
  private readonly idleWaiters: (() => void)[] = [];
  private running = 0;
  private stopped = false;

  public constructor(
    private readonly handler: (
      key: string,
      context: WorkContext,
    ) => Promise<Outcome>,
    private readonly options: QueueOptions,
  ) {}

  public add(key: string, options: { resetBackoff?: boolean } = {}): void {
    if (this.stopped) return;
    const state = this.states.get(key);
    if (options.resetBackoff === true) this.attempts.delete(key);
    switch (state) {
      case "queued":
      case "parked":
        return;
      case "processing":
        this.dirty.add(key);
        if (options.resetBackoff === true) this.resetRequested.add(key);
        return;
      case "timed":
        if (options.resetBackoff !== true) return;
        this.clearTimer(key);
        this.enqueue(key);
        return;
      default:
        this.enqueue(key);
    }
  }

  public forget(key: string): void {
    this.attempts.delete(key);
    this.dirty.delete(key);
    this.resetRequested.delete(key);
    this.clearTimer(key);
    const index = this.fifo.indexOf(key);
    if (index !== -1) this.fifo.splice(index, 1);
    const group = this.parkedGroup.get(key);
    if (group !== undefined) {
      const list = this.parked.get(group) ?? [];
      const at = list.indexOf(key);
      if (at !== -1) list.splice(at, 1);
      if (list.length === 0) this.parked.delete(group);
      this.parkedGroup.delete(key);
    }
    if (this.states.get(key) === "processing") {
      this.forgotten.add(key);
    } else {
      this.states.delete(key);
    }
    this.notifyIdle();
  }

  public forgetWhere(predicate: (key: string) => boolean): void {
    for (const key of [...this.states.keys()]) {
      if (predicate(key)) this.forget(key);
    }
  }

  public stop(): void {
    this.stopped = true;
    for (const key of [...this.timers.keys()]) this.clearTimer(key);
    this.fifo.length = 0;
    this.parked.clear();
    this.parkedGroup.clear();
    this.attempts.clear();
    this.dirty.clear();
    this.resetRequested.clear();
    for (const [key, state] of [...this.states]) {
      if (state === "processing") this.forgotten.add(key);
      else this.states.delete(key);
    }
    this.notifyIdle();
  }

  /** Resolves when nothing is running or waiting in the FIFO (timers excluded). */
  public whenIdle(): Promise<void> {
    if (this.isIdle()) return Promise.resolve();
    return new Promise((resolve) => {
      this.idleWaiters.push(resolve);
    });
  }

  /** Test introspection: the delay of the key's pending backoff timer. */
  public scheduledDelay(key: string): number | undefined {
    return this.timers.get(key)?.delay;
  }

  private isIdle(): boolean {
    return this.running === 0 && this.fifo.length === 0;
  }

  private notifyIdle(): void {
    if (!this.isIdle()) return;
    for (const resolve of this.idleWaiters.splice(0)) resolve();
  }

  private enqueue(key: string): void {
    this.states.set(key, "queued");
    this.fifo.push(key);
    this.pump();
  }

  private clearTimer(key: string): void {
    const timer = this.timers.get(key);
    if (timer === undefined) return;
    this.options.scheduler.clearTimeout(timer.handle);
    this.timers.delete(key);
    if (this.states.get(key) === "timed") this.states.delete(key);
  }

  private pump(): void {
    while (
      !this.stopped &&
      this.running < this.options.concurrency &&
      this.fifo.length > 0
    ) {
      const key = this.fifo.shift() as string;
      this.states.set(key, "processing");
      this.running += 1;
      void this.run(key);
    }
    this.notifyIdle();
  }

  private release(group: string): void {
    const used = (this.groupUsed.get(group) ?? 1) - 1;
    if (used <= 0) this.groupUsed.delete(group);
    else this.groupUsed.set(group, used);
    const list = this.parked.get(group);
    const next = list?.shift();
    if (list !== undefined && list.length === 0) this.parked.delete(group);
    if (next !== undefined) {
      this.parkedGroup.delete(next);
      this.states.set(next, "queued");
      this.fifo.push(next);
      this.pump();
    }
  }

  private async run(key: string): Promise<void> {
    const releases = new Set<() => void>();
    const context: WorkContext = {
      tryAcquire: (group) => {
        if ((this.groupUsed.get(group) ?? 0) >= this.options.groupConcurrency) {
          return undefined;
        }
        this.groupUsed.set(group, (this.groupUsed.get(group) ?? 0) + 1);
        let released = false;
        const releaseOnce = () => {
          if (released) return;
          released = true;
          releases.delete(releaseOnce);
          this.release(group);
        };
        releases.add(releaseOnce);
        return releaseOnce;
      },
    };
    let outcome: Outcome;
    try {
      outcome = await this.handler(key, context);
    } catch {
      outcome = { kind: "retry", policy: "fast" };
    }
    for (const release of [...releases]) release();
    this.running -= 1;
    this.complete(key, outcome);
    this.pump();
  }

  private complete(key: string, outcome: Outcome): void {
    const wasDirty = this.dirty.delete(key);
    const resetRequested = this.resetRequested.delete(key);
    if (this.forgotten.delete(key)) {
      // The key was forgotten while running: drop the outcome unless it was
      // added again afterwards.
      this.states.delete(key);
      if (wasDirty && !this.stopped) this.enqueue(key);
      return;
    }
    if (this.stopped) {
      this.states.delete(key);
      return;
    }
    switch (outcome.kind) {
      case "done":
        this.attempts.delete(key);
        this.states.delete(key);
        if (wasDirty) this.enqueue(key);
        return;
      case "defer": {
        if (
          (this.groupUsed.get(outcome.group) ?? 0) >=
          this.options.groupConcurrency
        ) {
          const list = this.parked.get(outcome.group) ?? [];
          list.push(key);
          this.parked.set(outcome.group, list);
          this.parkedGroup.set(key, outcome.group);
          this.states.set(key, "parked");
        } else {
          // A release happened between tryAcquire and now: do not sleep.
          this.enqueue(key);
        }
        return;
      }
      case "retry":
      case "retryAfter": {
        if (resetRequested) {
          // An explicit wake-up (issuer became Ready) outranks the backoff.
          // Plain re-adds (our own status events) were cleared above.
          this.attempts.delete(key);
          this.states.delete(key);
          this.enqueue(key);
          return;
        }
        const attempts = (this.attempts.get(key) ?? 0) + 1;
        this.attempts.set(key, attempts);
        const delay = this.delayFor(outcome, attempts);
        this.states.set(key, "timed");
        const handle = this.options.scheduler.setTimeout(() => {
          if (this.timers.get(key)?.handle !== handle) return;
          this.timers.delete(key);
          this.states.delete(key);
          this.enqueue(key);
        }, delay);
        this.timers.set(key, { handle, delay });
        return;
      }
    }
  }

  private delayFor(
    outcome: Extract<Outcome, { kind: "retry" | "retryAfter" }>,
    attempts: number,
  ): number {
    const random = this.options.scheduler.random();
    if (outcome.kind === "retryAfter") {
      return (
        outcome.delayMs +
        Math.round(random * Math.min(30_000, outcome.delayMs * 0.1))
      );
    }
    const { base, max } = outcome.policy === "slow" ? SLOW : FAST;
    const ceiling = Math.min(max, base * 2 ** Math.min(attempts - 1, 30));
    const delay = Math.round(ceiling / 2 + random * (ceiling / 2));
    return Math.max(delay, outcome.minDelayMs ?? 0);
  }
}
