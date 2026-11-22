import type { PkiApplication } from "../pki/app";
import { runMaintenancePass, type MaintenanceSummary } from "../pki/maintenance";
import { PkiIndexNotReadyError } from "../repositories/pki";
import { getPkiApplication } from "./pki-shared";

export type PkiMaintenanceResult =
  | { status: "idle"; reason?: "index_not_ready" }
  | MaintenanceSummary;

/** The part of the Lambda context the pass uses. */
export interface MaintenanceContext {
  getRemainingTimeInMillis(): number;
  awsRequestId: string;
}

/**
 * Runs every 15 minutes. Until CAs exist it does nothing. A pass that had any failure throws after emitting its
 * metrics, so the Lambda `Errors` metric (and the `pki-maintenance-errors` alarm) count it.
 */
export const createPkiMaintenanceHandler =
  (getApp: () => PkiApplication = getPkiApplication) =>
  async (
    _event?: unknown,
    context?: MaintenanceContext,
  ): Promise<PkiMaintenanceResult> => {
    const app = getApp();
    let anyCa: boolean;
    try {
      anyCa = await app.pki.hasAnyCa();
    } catch (error) {
      // An upgrade adds the index asynchronously; until it is queryable this is idle, not a failure.
      if (error instanceof PkiIndexNotReadyError) {
        process.stdout.write(
          `${JSON.stringify({ event: "pki_maintenance_idle", reason: "index_not_ready" })}\n`,
        );
        return { status: "idle", reason: "index_not_ready" };
      }
      throw error;
    }
    if (!anyCa) {
      process.stdout.write(
        `${JSON.stringify({ event: "pki_maintenance_idle" })}\n`,
      );
      return { status: "idle" };
    }
    return runMaintenancePass({
      app,
      now: app.now(),
      remainingMs: () => context?.getRemainingTimeInMillis() ?? 300_000,
      correlationId: context?.awsRequestId ?? "pki-maintenance",
    });
  };

export const handler = createPkiMaintenanceHandler();
