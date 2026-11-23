import type { PkiCaKind, PkiCaSubject } from "./pki-schemas";

/**
 * Client-side mirror of the server's restricted subject form and canonical
 * registry key (src/pki/subject.ts) plus the CLI's rollover suggestion
 * (packages/cli/src/pki.ts). The server stays the validator; these checks only
 * stop an obviously reusable or invalid DN before it is submitted.
 */

/** Encoding order of Hemlig-built subjects: C, ST, L, O, OU, CN. */
export const SUBJECT_ORDER = [
  { field: "country", oid: "2.5.4.6", label: "Country (C)" },
  { field: "state", oid: "2.5.4.8", label: "State (ST)" },
  { field: "locality", oid: "2.5.4.7", label: "Locality (L)" },
  { field: "organization", oid: "2.5.4.10", label: "Organization (O)" },
  { field: "organizationalUnit", oid: "2.5.4.11", label: "Organizational unit (OU)" },
  { field: "commonName", oid: "2.5.4.3", label: "Common name (CN)" },
] as const;

export type SubjectField = (typeof SUBJECT_ORDER)[number]["field"];
export type SubjectDraft = Partial<Record<SubjectField, string | undefined>>;

const MAX_VALUE_LENGTH = 64;

const normalizeValue = (value: string): string =>
  value.toLowerCase().replace(/\s+/g, " ");

/**
 * The ordered `(type OID, lowercased value with whitespace runs collapsed)`
 * pairs, as a string. Two subjects with the same canonical string are the same
 * name to the server's registry. Empty values are omitted attributes.
 */
export const canonicalSubject = (subject: SubjectDraft | PkiCaSubject): string =>
  JSON.stringify(
    SUBJECT_ORDER.flatMap(({ field, oid }) => {
      const value = (subject as SubjectDraft)[field];
      return value === undefined || value === ""
        ? []
        : [[oid, normalizeValue(value)] as const];
    }),
  );

/** The first restricted-form problem with a present value, if any. */
export const restrictedValueProblem = (value: string): string | undefined => {
  if (value.length === 0) {
    return "Must not be empty.";
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    return "Use printable ASCII only.";
  }
  if (value.startsWith(" ") || value.endsWith(" ") || value.includes("  ")) {
    return "No leading, trailing or doubled spaces.";
  }
  if (value.length > MAX_VALUE_LENGTH) {
    return `At most ${MAX_VALUE_LENGTH} characters.`;
  }
  return undefined;
};

/**
 * Problems per field. A blank field is an omitted attribute, so only the common
 * name is required. A ROOT or INTERMEDIATE country must be two letters, because
 * Hemlig signs that certificate itself.
 */
export const subjectProblems = (
  subject: SubjectDraft,
  kind: PkiCaKind,
): Partial<Record<SubjectField, string>> => {
  const problems: Partial<Record<SubjectField, string>> = {};
  for (const { field } of SUBJECT_ORDER) {
    const value = subject[field];
    if (value === undefined || value === "") {
      continue;
    }
    const problem = restrictedValueProblem(value);
    if (problem !== undefined) {
      problems[field] = problem;
    }
  }
  if (subject.commonName === undefined || subject.commonName === "") {
    problems.commonName = "Common name is required.";
  }
  if (
    kind !== "EXTERNAL_INTERMEDIATE" &&
    problems.country === undefined &&
    subject.country !== undefined &&
    subject.country !== "" &&
    !/^[A-Za-z]{2}$/.test(subject.country)
  ) {
    problems.country = "Country must be exactly two letters.";
  }
  return problems;
};

/** Increments the trailing integer of a name, keeping zero padding. */
export const incrementTrailingInteger = (value: string): string | undefined => {
  const match = /^(.*?)(\d+)$/.exec(value);
  if (match === null) {
    return undefined;
  }
  const digits = match[2] ?? "";
  const next = String(BigInt(digits) + 1n);
  return `${match[1] ?? ""}${next.padStart(digits.length, "0")}`;
};

/**
 * The next name and common name for a rollover. A name with no trailing
 * integer becomes `name-2` and `CN 2`.
 */
export const rolloverSuggestion = (base: {
  readonly name: string;
  readonly subject: { readonly commonName: string };
}): { name: string; commonName: string } => ({
  name: incrementTrailingInteger(base.name) ?? `${base.name}-2`,
  commonName:
    incrementTrailingInteger(base.subject.commonName) ?? `${base.subject.commonName} 2`,
});
