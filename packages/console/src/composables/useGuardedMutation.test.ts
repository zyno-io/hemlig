import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/errors";
import { useGuardedMutation } from "./useGuardedMutation";

const conflict = new ApiError(409, "conflict", "already used", "corr-1");
const unavailable = new ApiError(503, "service_unavailable", "busy", "corr-2");
const stale = new ApiError(412, "precondition_failed", "not current", "corr-3");
const network = new ApiError(0, "network", "unreachable");

describe("useGuardedMutation", () => {
  it("uses one key per submit intent and the same key on retry", async () => {
    const keys: string[] = [];
    const mutate = vi.fn(async (_input: string, key: string) => {
      keys.push(key);
      throw unavailable;
    });
    const mutation = useGuardedMutation<string, string>({
      family: "consumer",
      mutate,
    });

    await mutation.submit("a");
    await mutation.retry();

    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
  });

  it("never retries a stale precondition and keeps the draft", async () => {
    const mutation = useGuardedMutation<string, string>({
      family: "secret",
      mutate: async () => {
        throw stale;
      },
      reconcile: async () => "should-not-be-called",
    });

    await mutation.submit("a");

    expect(mutation.phase.value.kind).toBe("stale");
    expect(mutation.canRetry.value).toBe(false);
  });

  it("reconciles rather than retrying when a secret mutation is ambiguous", async () => {
    // Secret routes hard-conflict on a reused key and never replay, so the
    // only safe recovery is to re-read and compare.
    const reconcile = vi.fn(async () => "applied");
    const mutation = useGuardedMutation<string, string>({
      family: "secret",
      mutate: async () => {
        throw network;
      },
      reconcile,
    });

    await mutation.submit("a");

    expect(reconcile).toHaveBeenCalledOnce();
    expect(mutation.phase.value.kind).toBe("reconciled-applied");
    expect(mutation.canRetry.value).toBe(false);
  });

  it("reports a secret mutation that did not land", async () => {
    const mutation = useGuardedMutation<string, string>({
      family: "secret",
      mutate: async () => {
        throw conflict;
      },
      reconcile: async () => undefined,
    });

    await mutation.submit("a");

    expect(mutation.phase.value.kind).toBe("reconciled-absent");
  });

  it("offers retry for consumer routes, which replay by key", async () => {
    const mutation = useGuardedMutation<string, string>({
      family: "consumer",
      mutate: async () => {
        throw unavailable;
      },
    });

    await mutation.submit("a");

    expect(mutation.phase.value.kind).toBe("unknown");
    expect(mutation.canRetry.value).toBe(true);
  });

  it("treats a terminal enrollment failure as final, not ambiguous", async () => {
    const mutation = useGuardedMutation<string, string>({
      family: "consumer",
      mutate: async () => {
        throw new ApiError(409, "enrollment_failed", "truststore rejected", "corr-4");
      },
    });

    await mutation.submit("a");

    expect(mutation.phase.value.kind).toBe("failed");
    expect(mutation.canRetry.value).toBe(false);
  });
});
