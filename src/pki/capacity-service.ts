import { serviceUnavailable } from "../domain/errors";
import type { PkiRepository } from "../repositories/pki";
import type { CaCrlState, CaRecord } from "./types";

/** A stored count older than this is recounted by issuance. */
export const CAPACITY_STALE_MS = 30 * 60 * 1000;

/**
 * Where a capacity count starts: certificates that sort before the earliest of "now", the oldest unpublished
 * revocation and the next CRL drop are all either still relevant or already out of the CRL's reach. ISO strings
 * compare lexicographically.
 */
export const countFrom = (
  crl: Pick<CaCrlState, "dirtySince" | "published">,
  now: Date,
): string => {
  let from = now.toISOString();
  for (const candidate of [crl.dirtySince, crl.published?.dropDueAt]) {
    if (candidate !== undefined && candidate < from) {
      from = candidate;
    }
  }
  return from;
};

export class CapacityService {
  public constructor(private readonly pki: PkiRepository) {}

  /** Counts every certificate (all statuses) from `countFrom` and stores the result monotonically. */
  public async recount(
    ca: Pick<CaRecord, "caId">,
    crl: CaCrlState,
    now: Date,
  ): Promise<number> {
    const from = countFrom(crl, now);
    const count = await this.pki.countCertificatesSince(ca.caId, from);
    await this.pki.storeCapacityCount(ca.caId, {
      count,
      countFrom: from,
      countedAt: now.toISOString(),
    });
    return count;
  }

  /** The stored count, or a recount when it is missing or older than 30 minutes. */
  public async current(
    ca: Pick<CaRecord, "caId">,
    crl: CaCrlState | undefined,
    now: Date,
  ): Promise<number> {
    if (crl === undefined) {
      // Activation always creates the CRL item.
      throw serviceUnavailable("The CA's CRL state is missing.");
    }
    if (
      crl.capacity !== undefined &&
      Date.parse(crl.capacity.countedAt) >= now.getTime() - CAPACITY_STALE_MS
    ) {
      return crl.capacity.count;
    }
    return this.recount(ca, crl, now);
  }
}
