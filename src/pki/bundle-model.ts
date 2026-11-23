import { serviceUnavailable } from "../domain/errors";
import { caDrained } from "./ca-model";
import { chainParts } from "./issuance-model";
import type { CaCrlState, CaRecord } from "./types";

/** Phase 7: false for a locally distrusted Hemlig root. */
export const anchorTrusted = (_ca: CaRecord): boolean => true;

/**
 * The consumer trust-bundle view of a CA. The field order is part of the wire contract; do not spread the record.
 * Phase 7: a `ROOT` CA needs `chainPem: ""` and `anchorPem = certificatePem`.
 */
export const caBundleView = (
  ca: CaRecord,
  crl: CaCrlState | undefined,
): Record<string, unknown> => {
  const { chainPem, caPem } = chainParts(ca);
  if (ca.fingerprint === undefined || ca.notAfter === undefined) {
    throw serviceUnavailable("The CA record is incomplete.");
  }
  return {
    caId: ca.caId,
    name: ca.name,
    status: ca.status,
    drained: caDrained(ca, crl),
    fingerprint: ca.fingerprint,
    notAfter: ca.notAfter,
    anchorPem: caPem,
    anchorTrusted: anchorTrusted(ca),
    chainPem,
    crlIssuers: ca.crlIssuers.map((issuer) => ({
      id: issuer.id,
      source: issuer.type === "ca" ? "GENERATED" : "UPLOADED",
    })),
  };
};
