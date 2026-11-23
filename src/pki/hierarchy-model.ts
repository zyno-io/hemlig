import { serviceUnavailable } from "../domain/errors";
import {
  parseCertificate,
  verifyCertificateSignature,
  type BuiltTbs,
  type ParsedCertificate,
} from "./asn1/certificate";
import { caStatusReason } from "./ca-model";
import { extendedKeyUsageWithin, nameConstraintsWithin } from "./chain";
import { floorSeconds } from "./crl-service";
import {
  caKeyUnavailable,
  caNotActive,
  pkiBadRequest,
  pkiConflict,
  pkiNotFound,
} from "./errors";
import type { CaRecord, RevocationReason } from "./types";

export const MIN_ROOT_VALIDITY_SECONDS = 7_776_000; // 90 days
export const MIN_INTERMEDIATE_VALIDITY_SECONDS = 2_592_000; // 30 days
export const MAX_CA_VALIDITY_SECONDS = 630_720_000; // 7,300 days (20 years)
export const DEFAULT_ROOT_VALIDITY_SECONDS = 315_360_000;
export const DEFAULT_INTERMEDIATE_VALIDITY_SECONDS = 31_536_000;
export const ROOT_PATH_LEN = 1;
export const MAX_CA_CERTIFICATE_BYTES = 16_384;
const MIN_CHILD_REMAINING_MS = 30 * 86_400_000;
const BACKDATE_MS = 60_000;

export const CA_REVOCATION_REASONS = [
  "unspecified",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
] as const;

export const externalRootRecommended = {
  code: "external_root_recommended",
  message:
    "An external offline root is strongly recommended: this ROOT's key is WRAPPED and online, so a compromised PKI role can copy it, and local distrust only reaches relying parties that use Hemlig trust bundles.",
};

/** The Hemlig CAs above this one that a leaf's validity depends on. */
export const hemligAncestors = (ca: Pick<CaRecord, "parentCaId">): string[] =>
  ca.parentCaId === undefined ? [] : [ca.parentCaId];

// ---------------------------------------------------------------------------------------------------------------------
// Parent checks
// ---------------------------------------------------------------------------------------------------------------------

/** The checks a ROOT must pass before it signs a child CA, in the order they are reported. */
export const assertParentCanIssue = (
  parent: CaRecord | undefined,
  environment: string,
  now: Date,
): CaRecord => {
  if (parent === undefined) {
    throw pkiNotFound("parent_not_found");
  }
  if (parent.environment !== environment) {
    throw pkiConflict("parent_environment_mismatch");
  }
  if (parent.kind !== "ROOT" || !parent.policy.issueSubordinates) {
    throw caNotActive("subordinates_not_permitted");
  }
  if (parent.status !== "ACTIVE") {
    throw caNotActive(caStatusReason[parent.status]);
  }
  if (parent.key.state !== "ACTIVE" || parent.key.wrapped === undefined) {
    throw caKeyUnavailable();
  }
  if (
    parent.notBefore === undefined ||
    parent.notAfter === undefined ||
    Date.parse(parent.notBefore) > now.getTime()
  ) {
    throw caNotActive("not_yet_valid");
  }
  if (Date.parse(parent.notAfter) <= now.getTime()) {
    throw caNotActive("expired");
  }
  if (
    parent.certificatePem === undefined ||
    parent.subjectDer === undefined ||
    parent.subjectKeyIdentifier === undefined
  ) {
    throw serviceUnavailable("The parent CA record has no certificate.");
  }
  return parent;
};

type Constraints = NonNullable<CaRecord["effective"]>;

/**
 * The child's constraints: its own request when it is within the parent's, else the parent's. Nothing is merged: a
 * child that omits a parent exclusion is broader, so it is refused.
 */
export const deriveChildConstraints = (
  parentEffective: CaRecord["effective"],
  requested: CaRecord["requested"],
): {
  nameConstraints?: Constraints["nameConstraints"];
  extendedKeyUsages?: string[];
} => {
  const parentNc = parentEffective?.nameConstraints;
  let nameConstraints = requested.nameConstraints;
  if (nameConstraints === undefined) {
    nameConstraints = parentNc;
  } else if (
    parentNc !== undefined &&
    !nameConstraintsWithin(nameConstraints, parentNc)
  ) {
    throw pkiBadRequest(
      "name_constraints_broader_than_parent",
      "The requested name constraints are broader than the parent's.",
    );
  }
  const parentEku = parentEffective?.extendedKeyUsages;
  let extendedKeyUsages = requested.extendedKeyUsages;
  if (extendedKeyUsages === undefined) {
    extendedKeyUsages = parentEku;
  } else if (
    parentEku !== undefined &&
    !extendedKeyUsageWithin(extendedKeyUsages, parentEku)
  ) {
    throw pkiBadRequest(
      "extended_key_usage_broader_than_parent",
      "The requested extended key usages are broader than the parent's.",
    );
  }
  return {
    ...(nameConstraints === undefined ? {} : { nameConstraints }),
    ...(extendedKeyUsages === undefined ? {} : { extendedKeyUsages }),
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------------------------------------------------

export interface CaValidity {
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly lifetimeSeconds: number;
  readonly clamped: boolean;
}

/**
 * A child's validity, clamped to its parent's. The remaining lifetime is measured from `notBefore`, which is at most a
 * minute before `now`: measuring from `now` would refuse the 30-day minimum validity every time.
 */
export const childValidity = (
  parent: { notBefore: string; notAfter: string },
  requestedSeconds: number,
  now: Date,
): CaValidity => {
  const notBefore = new Date(
    Math.max(
      floorSeconds(now).getTime() - BACKDATE_MS,
      Date.parse(parent.notBefore),
    ),
  );
  const wanted = notBefore.getTime() + requestedSeconds * 1000;
  const parentEnd = Date.parse(parent.notAfter);
  const notAfter = new Date(Math.min(wanted, parentEnd));
  if (notAfter.getTime() - notBefore.getTime() < MIN_CHILD_REMAINING_MS) {
    throw pkiConflict("parent_validity_insufficient");
  }
  return {
    notBefore,
    notAfter,
    lifetimeSeconds: (notAfter.getTime() - notBefore.getTime()) / 1000,
    clamped: wanted > parentEnd,
  };
};

export const rootValidity = (
  validitySeconds: number,
  now: Date,
): CaValidity => {
  const notBefore = new Date(floorSeconds(now).getTime() - BACKDATE_MS);
  return {
    notBefore,
    notAfter: new Date(notBefore.getTime() + validitySeconds * 1000),
    lifetimeSeconds: validitySeconds,
    clamped: false,
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Self-check of a freshly signed CA certificate
// ---------------------------------------------------------------------------------------------------------------------

/** Never logs the DER: only the name of the failed check. */
export const assertBuiltCaCertificate = (
  der: Buffer,
  built: BuiltTbs,
  expected: { issuerSpkiDer: Uint8Array; pathLen: number },
): ParsedCertificate => {
  const fail = (field: string): never => {
    console.error("PKI CA certificate self-check failed", { field });
    throw serviceUnavailable(
      "The generated CA certificate failed verification.",
    );
  };
  let parsed: ParsedCertificate;
  try {
    parsed = parseCertificate(der);
  } catch {
    return fail("parse");
  }
  if (der.length > MAX_CA_CERTIFICATE_BYTES) {
    fail("size");
  }
  if (!parsed.tbsDer.equals(built.tbs)) {
    fail("tbs");
  }
  if (!parsed.signatureAlgorithm.raw.equals(built.signatureAlgorithm)) {
    fail("signatureAlgorithm");
  }
  if (!verifyCertificateSignature(parsed, expected.issuerSpkiDer)) {
    fail("signature");
  }
  const bc = parsed.basicConstraints;
  if (
    bc === undefined ||
    !bc.ca ||
    !bc.critical ||
    bc.pathLen !== expected.pathLen
  ) {
    fail("basicConstraints");
  }
  if (parsed.subjectKeyIdentifier === undefined) {
    fail("subjectKeyIdentifier");
  }
  if (parsed.unrecognizedCritical.length > 0) {
    fail("criticalExtension");
  }
  return parsed;
};

// ---------------------------------------------------------------------------------------------------------------------
// CA revoke request
// ---------------------------------------------------------------------------------------------------------------------

export const parseRevokeCaRequest = (
  body: unknown,
  now: Date,
): {
  raw: Record<string, unknown>;
  reason: RevocationReason;
  invalidityDate?: string;
} => {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw pkiBadRequest("invalid_body", "The request body must be an object.");
  }
  const raw = body as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (key !== "reason" && key !== "invalidityDate") {
      throw pkiBadRequest("unknown_field", "The request has an unknown field.");
    }
  }
  let reason: RevocationReason = "unspecified";
  if (raw.reason !== undefined) {
    if (raw.reason === "keyCompromise") {
      throw pkiBadRequest(
        "invalid_reason",
        "Use caCompromise for a CA certificate.",
      );
    }
    if (
      typeof raw.reason !== "string" ||
      !(CA_REVOCATION_REASONS as readonly string[]).includes(raw.reason)
    ) {
      throw pkiBadRequest(
        "invalid_reason",
        "The revocation reason is invalid.",
      );
    }
    reason = raw.reason as RevocationReason;
  }
  let invalidityDate: string | undefined;
  if (raw.invalidityDate !== undefined) {
    if (reason !== "caCompromise") {
      throw pkiBadRequest(
        "invalidity_date_requires_ca_compromise",
        "invalidityDate requires the caCompromise reason.",
      );
    }
    const parsed =
      typeof raw.invalidityDate === "string"
        ? new Date(raw.invalidityDate)
        : new Date(Number.NaN);
    const year = parsed.getUTCFullYear();
    if (
      Number.isNaN(parsed.getTime()) ||
      parsed.getTime() > now.getTime() ||
      year < 1950 ||
      year > 9999
    ) {
      throw pkiBadRequest(
        "invalid_invalidity_date",
        "invalidityDate must be a time that is not in the future.",
      );
    }
    invalidityDate = parsed.toISOString();
  }
  return {
    raw,
    reason,
    ...(invalidityDate === undefined ? {} : { invalidityDate }),
  };
};
