import { serviceUnavailable } from "../domain/errors";
import { caDrained } from "./ca-model";
import { chainParts } from "./issuance-model";
import type { CaCrlState, CaRecord } from "./types";

type ParentStatus = Pick<CaRecord, "status">;

/**
 * Whether relying parties should keep trusting the anchor. A ROOT is distrusted locally when it is REVOKED. An
 * INTERMEDIATE follows its parent's status, never its own: a CA-revoked intermediate keeps a trusted anchor, and the
 * root CRL carries the revocation.
 */
export const anchorTrusted = (ca: CaRecord, parent?: ParentStatus): boolean => {
  if (ca.kind === "ROOT") return ca.status !== "REVOKED";
  if (ca.kind === "INTERMEDIATE") {
    if (parent === undefined) {
      throw serviceUnavailable("The parent CA record is missing.");
    }
    return parent.status !== "REVOKED";
  }
  return true;
};

/**
 * The consumer trust-bundle view of a CA. The field order is part of the wire contract; do not spread the record.
 * A `ROOT` CA has `chainPem: ""` and `anchorPem` equal to its own certificate.
 */
export const caBundleView = (
  ca: CaRecord,
  crl: CaCrlState | undefined,
  parent?: ParentStatus,
): Record<string, unknown> => {
  let chainPem: string;
  let caPem: string;
  if (ca.kind === "ROOT") {
    if (ca.certificatePem === undefined) {
      throw serviceUnavailable("The CA record is incomplete.");
    }
    chainPem = "";
    caPem = ca.certificatePem.trim() + "\n";
  } else {
    ({ chainPem, caPem } = chainParts(ca));
  }
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
    anchorTrusted: anchorTrusted(ca, parent),
    chainPem,
    crlIssuers: ca.crlIssuers.map((issuer) => ({
      id: issuer.id,
      source: issuer.type === "ca" ? "GENERATED" : "UPLOADED",
    })),
  };
};
