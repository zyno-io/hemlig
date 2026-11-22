import type { Actor } from "../domain/types";
import { emitPkiMetrics, PKI_METRICS } from "./metrics";
import type { PkiApplication } from "./app";
import { evaluateCrl, isDrained, type CrlEvaluation } from "./crl-service";
import type { CaCrlState, CaRecord, ExternalCaRecord } from "./types";

/** Stop starting CRL publications when less than this remains of the invocation. */
export const minimumRemainingMs = 30_000;
const caConcurrency = 8;
const day = 86_400_000;

export const maintenanceActor: Actor = {
  type: "system",
  id: "pki-maintenance",
};

export interface MaintenanceDeps {
  readonly app: Pick<
    PkiApplication,
    "pki" | "cas" | "crls" | "audit" | "config"
  >;
  readonly now: Date;
  readonly remainingMs: () => number;
  readonly correlationId: string;
  readonly emit?: typeof emitPkiMetrics;
  readonly log?: (line: Record<string, unknown>) => void;
}

export interface MaintenanceSummary {
  status: "ok";
  cas: number;
  published: number;
  retired: number;
  drained: number;
  failures: number;
  skipped: number;
}

interface CaState {
  ca: CaRecord;
  crl?: CaCrlState;
}

const errorLabel = (error: unknown): string =>
  error instanceof Error
    ? ((error as { code?: string }).code ?? error.name)
    : typeof error;

const mapLimit = async <T>(
  items: readonly T[],
  limit: number,
  work: (item: T) => Promise<void>,
): Promise<void> => {
  const queue = [...items];
  const worker = async (): Promise<void> => {
    for (let item = queue.shift(); item !== undefined; item = queue.shift()) {
      await work(item);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
};

/** One maintenance pass. Each CA is isolated: a failure is counted, logged, and thrown once the pass is done. */
export const runMaintenancePass = async (
  deps: MaintenanceDeps,
): Promise<MaintenanceSummary> => {
  const { app, now } = deps;
  const emit = deps.emit ?? emitPkiMetrics;
  const log =
    deps.log ??
    ((line) => {
      process.stdout.write(`${JSON.stringify(line)}\n`);
    });
  const nowIso = now.toISOString();
  const summary: MaintenanceSummary = {
    status: "ok",
    cas: 0,
    published: 0,
    retired: 0,
    drained: 0,
    failures: 0,
    skipped: 0,
  };
  const states = new Map<string, CaState>();
  const fail = (caId: string, step: string, error: unknown): void => {
    summary.failures += 1;
    log({
      event: "pki_maintenance_ca_failed",
      caId,
      step,
      error: errorLabel(error),
    });
  };
  const audit = async (
    operation: string,
    target: Record<string, string>,
  ): Promise<void> => {
    await app.audit.write({
      correlationId: deps.correlationId,
      outcome: "succeeded",
      actor: maintenanceActor,
      operation,
      target,
    });
  };
  const loadCrl = async (ca: CaRecord): Promise<CaCrlState | undefined> =>
    ca.status === "ACTIVE" || ca.status === "RETIRED"
      ? app.pki.getCaCrlState(ca.caId)
      : undefined;

  // A. Enumerate.
  const directory = await app.pki.queryDirectory("PKI_CAS");
  const caIds = directory
    .map((item) => item.caId)
    .filter((id): id is string => typeof id === "string");
  summary.cas = caIds.length;
  await mapLimit(caIds, caConcurrency, async (caId) => {
    try {
      const ca = await app.pki.getCa(caId);
      if (ca !== undefined) {
        const crl = await loadCrl(ca);
        states.set(caId, { ca, ...(crl === undefined ? {} : { crl }) });
      }
    } catch (error) {
      fail(caId, "load", error);
    }
  });

  // B. Expiry.
  for (const state of states.values()) {
    const { ca } = state;
    if (
      ca.status !== "ACTIVE" ||
      ca.notAfter === undefined ||
      ca.notAfter > nowIso
    ) {
      continue;
    }
    try {
      const retired = await app.cas.retireExpired(ca);
      if (retired !== undefined) {
        state.ca = retired;
        summary.retired += 1;
        await audit("pki.ca.retire", {
          caId: ca.caId,
          environment: ca.environment,
          version: retired.version,
          reason: "expired",
        });
      }
    } catch (error) {
      fail(ca.caId, "expiry", error);
    }
  }

  // C. Publish the due CRLs, most urgent first.
  const evaluate = (
    state: CaState,
    step: string,
  ): CrlEvaluation | undefined => {
    try {
      return evaluateCrl(state.ca, state.crl, now);
    } catch (error) {
      fail(state.ca.caId, step, error);
      return undefined;
    }
  };
  const due = [...states.values()]
    .map((state) => ({ state, evaluation: evaluate(state, "evaluate") }))
    .filter(
      (entry): entry is { state: CaState; evaluation: CrlEvaluation } =>
        entry.evaluation !== undefined && entry.evaluation.reasons.length > 0,
    )
    .sort((left, right) =>
      (left.state.crl?.published?.nextUpdate ?? "").localeCompare(
        right.state.crl?.published?.nextUpdate ?? "",
      ),
    );
  for (const { state, evaluation } of due) {
    if (deps.remainingMs() < minimumRemainingMs) {
      summary.skipped += 1;
      log({
        event: "pki_maintenance_budget_exhausted",
        caId: state.ca.caId,
      });
      continue;
    }
    try {
      const result = await app.crls.publish(state.ca, {
        trigger: "maintenance",
      });
      if (result.kind === "published") {
        summary.published += 1;
        state.crl = await app.pki.getCaCrlState(state.ca.caId);
        await audit("pki.crl.publish", {
          caId: state.ca.caId,
          environment: state.ca.environment,
          crlNumber: String(result.pointer.number),
          entryCount: String(result.pointer.entryCount),
          trigger: "maintenance",
          reasons: evaluation.reasons.join(","),
        });
      }
    } catch (error) {
      fail(state.ca.caId, "publish", error);
    }
  }

  // D. Disable the keys of drained retired CAs.
  for (const state of states.values()) {
    const { ca, crl } = state;
    if (
      ca.status !== "RETIRED" ||
      ca.key.state !== "ACTIVE" ||
      crl === undefined ||
      !isDrained(ca, crl)
    ) {
      continue;
    }
    try {
      if (await app.cas.disableDrainedKey(ca, crl)) {
        state.ca = { ...ca, key: { ...ca.key, state: "DISABLED" } };
        summary.drained += 1;
        await audit("pki.ca.key-disable", {
          caId: ca.caId,
          environment: ca.environment,
          reason: "drained",
        });
      }
    } catch (error) {
      fail(ca.caId, "drain", error);
    }
  }

  // E. Finish interrupted sweeps of expired carried revocations.
  for (const { ca, crl } of states.values()) {
    const published = crl?.published;
    if (published === undefined || crl?.sweptThrough === published.thisUpdate) {
      continue;
    }
    try {
      await app.pki.expireCarriedRevocations(
        ca.caId,
        published.thisUpdate,
        Math.floor(now.getTime() / 1000) + 86_400,
      );
      await app.pki.markCrlSwept(ca.caId, published.thisUpdate);
    } catch (error) {
      fail(ca.caId, "sweep", error);
    }
  }

  // F. CA metrics.
  let generatedCrlStale = 0;
  let caExpiring = 0;
  let crlOverCapacity = 0;
  for (const state of states.values()) {
    const { ca, crl } = state;
    const evaluation = evaluate(state, "metrics");
    if (evaluation === undefined) {
      continue;
    }
    if (evaluation.stale) {
      generatedCrlStale += 1;
    }
    if (
      ca.status === "ACTIVE" &&
      ca.notAfter !== undefined &&
      now.getTime() >=
        Date.parse(ca.notAfter) -
          ca.policy.maxLeafLifetimeSeconds * 1000 -
          30 * day
    ) {
      caExpiring += 1;
    }
    if (
      evaluation.alarmable &&
      crl?.published !== undefined &&
      crl.published.entryCount > ca.policy.capacity
    ) {
      crlOverCapacity += 1;
    }
  }

  // G. External CAs.
  let externalCrlStale = 0;
  let externalCrlMissing = 0;
  try {
    const extIds = (await app.pki.queryDirectory("PKI_EXTCAS"))
      .map((item) => item.extId)
      .filter((id): id is string => typeof id === "string");
    await mapLimit(extIds, caConcurrency, async (extId) => {
      try {
        const ext = await app.pki.getExternalCa(extId);
        if (ext === undefined) {
          return;
        }
        if (!(await hasLiveDependent(app.pki, ext, states, nowIso))) {
          return;
        }
        if (ext.crl === undefined) {
          if (now.getTime() - Date.parse(ext.createdAt) >= day) {
            externalCrlMissing += 1;
          }
        } else if (now.getTime() >= Date.parse(ext.crl.nextUpdate) - 30 * day) {
          externalCrlStale += 1;
        }
      } catch (error) {
        fail(extId, "external", error);
      }
    });
  } catch (error) {
    fail("external-cas", "external", error);
  }

  // H. Emit every count, zeros included, so alarms clear.
  emit(app.config.environmentName, {
    [PKI_METRICS.generatedCrlStale]: generatedCrlStale,
    [PKI_METRICS.externalCrlStale]: externalCrlStale,
    [PKI_METRICS.externalCrlMissing]: externalCrlMissing,
    [PKI_METRICS.caExpiring]: caExpiring,
    [PKI_METRICS.crlOverCapacity]: crlOverCapacity,
  });

  // I. Finish.
  log({ event: "pki_maintenance_pass", ...summary, status: undefined });
  if (summary.failures > 0) {
    throw new Error(
      `PKI maintenance finished with ${summary.failures} failure(s).`,
    );
  }
  return summary;
};

/** A dependent still able to matter: ACTIVE, RETIRED with a usable key, or REVOKED with an unexpired certificate. */
const hasLiveDependent = async (
  pki: PkiApplication["pki"],
  ext: ExternalCaRecord,
  states: ReadonlyMap<string, CaState>,
  nowIso: string,
): Promise<boolean> => {
  for (const caId of ext.dependents) {
    const ca = states.get(caId)?.ca ?? (await pki.getCa(caId));
    if (ca === undefined) {
      continue;
    }
    if (
      ca.status === "ACTIVE" ||
      (ca.status === "RETIRED" && ca.key.state === "ACTIVE") ||
      (ca.status === "REVOKED" &&
        ca.notAfter !== undefined &&
        ca.notAfter > nowIso)
    ) {
      return true;
    }
  }
  return false;
};
