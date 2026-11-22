import { PkiIndexNotReadyError } from "../repositories/pki";
import { getPkiApplication } from "./pki-shared";

export type PkiMaintenanceResult =
  | { status: "idle"; reason?: "index_not_ready" }
  | { status: "noop" };

/**
 * Runs every 15 minutes. Until CAs exist it does nothing; Phase 3 replaces the `noop` branch. Errors propagate so the
 * Lambda `Errors` metric counts them.
 */
export const handler = async (): Promise<PkiMaintenanceResult> => {
  const app = getPkiApplication();
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
  return { status: "noop" };
};
