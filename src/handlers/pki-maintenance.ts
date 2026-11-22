import { getPkiApplication } from "./pki-shared";

export type PkiMaintenanceResult = { status: "idle" } | { status: "noop" };

/**
 * Runs every 15 minutes. Until CAs exist it does nothing; Phase 3 replaces the `noop` branch. Errors propagate so the
 * Lambda `Errors` metric counts them.
 */
export const handler = async (): Promise<PkiMaintenanceResult> => {
  const app = getPkiApplication();
  if (!(await app.pki.hasAnyCa())) {
    process.stdout.write(
      `${JSON.stringify({ event: "pki_maintenance_idle" })}\n`,
    );
    return { status: "idle" };
  }
  return { status: "noop" };
};
