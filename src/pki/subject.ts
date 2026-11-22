import { createHash } from "node:crypto";
import { ApiError } from "../domain/errors";
import { decodeName, encodeName, type DirectoryStringKind } from "./asn1/names";
import type { CaSubject } from "./types";

/**
 * The restricted subject form and the canonical registry key (see "Subject names and the registry"). It applies to
 * Hemlig CA subjects, the external root's subject and the subject of every returned CA certificate.
 */

export const SUBJECT_OID = {
  C: "2.5.4.6",
  ST: "2.5.4.8",
  L: "2.5.4.7",
  O: "2.5.4.10",
  OU: "2.5.4.11",
  CN: "2.5.4.3",
} as const;

/** Encoding order of Hemlig-built subjects. */
const hemligOrder = ["C", "ST", "L", "O", "OU", "CN"] as const;
const hemligOids: ReadonlySet<string> = new Set(Object.values(SUBJECT_OID));

export type SubjectErrorReason =
  | "malformed_name"
  | "empty_name"
  | "multi_valued_rdn"
  | "unsupported_string_type"
  | "non_ascii"
  | "empty_value"
  | "space_not_allowed"
  | "attribute_not_allowed";

export class SubjectError extends Error {
  public constructor(public readonly reason: SubjectErrorReason) {
    super(`The name is not in the restricted form (${reason}).`);
  }
}

export interface RestrictedName {
  readonly der: Buffer;
  /** Attributes in encoded order, one per RDN. */
  readonly attributes: readonly {
    readonly oid: string;
    readonly value: string;
  }[];
  /** The canonical registry key: lowercase hex SHA-256. */
  readonly key: string;
}

const normalizeValue = (value: string): string =>
  value.toLowerCase().replace(/\s+/g, " ");

/**
 * `sha256` over the ordered `(type OID, ASCII-lowercased value with whitespace runs collapsed)` pairs. For printable
 * ASCII this matches RFC 4518 caseIgnore matching and OpenSSL's canonical comparison.
 */
export const canonicalSubjectKey = (
  attributes: readonly { oid: string; value: string }[],
): string =>
  createHash("sha256")
    .update(
      JSON.stringify(
        attributes.map((attribute) => [
          attribute.oid,
          normalizeValue(attribute.value),
        ]),
      ),
    )
    .digest("hex");

const assertValue = (value: string): void => {
  if (value.length === 0) {
    throw new SubjectError("empty_value");
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new SubjectError("non_ascii");
  }
  if (value.startsWith(" ") || value.endsWith(" ") || value.includes("  ")) {
    throw new SubjectError("space_not_allowed");
  }
};

/**
 * Validates a DER Name against the restricted form. `kind: 'hemlig'` additionally limits the attributes to C, ST, L,
 * O, OU and CN; `'external'` accepts any string-typed attribute (such as DC).
 */
export const parseRestrictedName = (
  der: Uint8Array,
  kind: "hemlig" | "external" = "external",
): RestrictedName => {
  let rdns;
  try {
    rdns = decodeName(der);
  } catch {
    throw new SubjectError("malformed_name");
  }
  if (rdns.length === 0) {
    throw new SubjectError("empty_name");
  }
  const attributes = rdns.map((rdn) => {
    const [attribute, ...more] = rdn;
    if (attribute === undefined || more.length > 0) {
      throw new SubjectError("multi_valued_rdn");
    }
    if (attribute.value === undefined) {
      throw new SubjectError("unsupported_string_type");
    }
    assertValue(attribute.value);
    if (kind === "hemlig" && !hemligOids.has(attribute.oid)) {
      throw new SubjectError("attribute_not_allowed");
    }
    return { oid: attribute.oid, value: attribute.value };
  });
  return {
    der: Buffer.from(der),
    attributes,
    key: canonicalSubjectKey(attributes),
  };
};

const subjectBadRequest = (reason: SubjectErrorReason): ApiError =>
  new ApiError(
    400,
    "bad_request",
    `The CA subject is not in the restricted form (${reason}).`,
    reason,
  );

/** Validates a Hemlig CA subject and encodes it: C as PrintableString, the rest as UTF8String, in the fixed order. */
export const buildCaSubject = (subject: CaSubject): RestrictedName => {
  try {
    const attributes: {
      oid: string;
      value: string;
      kind: DirectoryStringKind;
    }[] = [];
    for (const name of hemligOrder) {
      const value = subject[name];
      if (value === undefined) {
        if (name === "CN") {
          throw new SubjectError("empty_value");
        }
        continue;
      }
      assertValue(value);
      if (name === "C" && !/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(value)) {
        throw new SubjectError("unsupported_string_type");
      }
      attributes.push({
        oid: SUBJECT_OID[name],
        value,
        kind: name === "C" ? "printable" : "utf8",
      });
    }
    const der = encodeName(attributes);
    return { der, attributes, key: canonicalSubjectKey(attributes) };
  } catch (error) {
    throw error instanceof SubjectError
      ? subjectBadRequest(error.reason)
      : error;
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// Layer 6: reserved identities
// ---------------------------------------------------------------------------------------------------------------------

/** The registry key of the identity root's fixed subject, `CN=Hemlig <deployment name> Issuing Root`. */
export const identityRootSubjectKey = (deploymentName: string): string =>
  canonicalSubjectKey([
    { oid: SUBJECT_OID.CN, value: `Hemlig ${deploymentName} Issuing Root` },
  ]);

export interface IdentityRootReference {
  /** Registry key of the stored root's subject. */
  readonly subjectKey?: string;
  readonly spkiSha256?: string;
  readonly fingerprint?: string;
}

/**
 * True when a candidate CA subject, chain certificate or external subject is the identity root. `identity` comes from
 * a strongly consistent read of `SYSTEM#ISSUER`, or is undefined before the root exists, in which case only the fixed
 * subject is compared.
 */
export const matchesIdentityRoot = (
  candidate: {
    readonly subjectKey: string;
    readonly spkiSha256?: string;
    readonly fingerprint?: string;
  },
  deploymentName: string,
  identity?: IdentityRootReference,
): boolean =>
  candidate.subjectKey === identityRootSubjectKey(deploymentName) ||
  (identity?.subjectKey !== undefined &&
    candidate.subjectKey === identity.subjectKey) ||
  (identity?.spkiSha256 !== undefined &&
    candidate.spkiSha256 === identity.spkiSha256) ||
  (identity?.fingerprint !== undefined &&
    candidate.fingerprint === identity.fingerprint);
