import { ApiError, badRequest, conflict } from "../domain/errors";
import { sha256Hex, stableJson } from "../util/encoding";
import { decodeName } from "./asn1/names";
import { EKU } from "./asn1/extensions";
import { caIssuanceBudgetExceeded, pkiBadRequest } from "./errors";
import { drainPoint, isDrained } from "./crl-service";
import {
  cidrToString,
  MAX_DNS_NAME_LENGTH,
  normalizeDnsName,
  parseCidr,
  type NameConstraintSet as SubtreeMap,
  type NameConstraintSubtrees,
} from "./names";
import {
  DEFAULT_LEAF_KEY_ALGORITHMS,
  LEAF_KEY_ALGORITHMS,
} from "./policy-types";
import { MAX_LEAF_LIFETIME_SECONDS, type GrantCaContext } from "./grant-policy";
import type { ParsedCertificate } from "./asn1/certificate";
import type { CaPolicyInput as EngineCaPolicyInput } from "./policy-types";
import {
  DEFAULT_INTERMEDIATE_VALIDITY_SECONDS,
  DEFAULT_ROOT_VALIDITY_SECONDS,
  MAX_CA_VALIDITY_SECONDS,
  MIN_INTERMEDIATE_VALIDITY_SECONDS,
  MIN_ROOT_VALIDITY_SECONDS,
  ROOT_PATH_LEN,
} from "./hierarchy-model";
import { buildCaSubject } from "./subject";
import type {
  CaCrlState,
  CaRecord,
  CaSubject,
  ExternalCaRecord,
  LeafKeyAlgorithm,
  NameConstraintEntry,
  NameConstraintSet,
  PkiKeyAlgorithm,
} from "./types";

// ---------------------------------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------------------------------

export const ADMIN_DEFAULT_LIFETIME_SECONDS = 90 * 86_400;
export const MAX_NAME_CONSTRAINT_SUBTREES = 50;
export const MAX_ISSUANCE_BUDGET = 12_000;
export const MAX_CA_PEM_BYTES = 32_768;
export const CA_KEY_ALGORITHMS: readonly PkiKeyAlgorithm[] = [
  "ECDSA_P256",
  "ECDSA_P384",
  "RSA_3072",
  "RSA_4096",
  "ED25519",
];

const nameKeys = [
  "environment",
  "name",
  "kind",
  "keyAlgorithm",
  "subject",
  "requestedConstraints",
  "policy",
  "crl",
  "displayName",
  "parentCaId",
  "validitySeconds",
] as const;
const parentCaIdPattern = /^ca-[a-z0-9-]{3,80}$/;
const namePattern = /^[a-z][a-z0-9-]{2,63}$/;

// ---------------------------------------------------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------------------------------------------------

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const record = (value: unknown, label: string): Json => {
  if (!isRecord(value)) {
    throw badRequest(`${label} must be a JSON object.`);
  }
  return value;
};

const strict = (
  value: Json,
  label: string,
  allowed: readonly string[],
): void => {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw pkiBadRequest("unknown_field", `${label} has an unknown field.`);
    }
  }
};

const text = (
  value: unknown,
  label: string,
  options: { min?: number; max?: number } = {},
): string => {
  if (typeof value !== "string") {
    throw badRequest(`${label} must be a string.`);
  }
  if (
    value.length < (options.min ?? 1) ||
    value.length > (options.max ?? 256)
  ) {
    throw badRequest(`${label} has an invalid length.`);
  }
  return value;
};

const integer = (
  value: unknown,
  label: string,
  min: number,
  max: number,
): number => {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    value > max
  ) {
    throw pkiBadRequest(
      "invalid_policy",
      `${label} must be an integer between ${min} and ${max}.`,
    );
  }
  return value;
};

// ---------------------------------------------------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------------------------------------------------

const subjectFields = [
  ["commonName", "CN"],
  ["organization", "O"],
  ["organizationalUnit", "OU"],
  ["country", "C"],
  ["locality", "L"],
  ["state", "ST"],
] as const;

const parseSubject = (value: unknown): CaSubject => {
  const input = record(value, "subject");
  strict(
    input,
    "subject",
    subjectFields.map(([name]) => name),
  );
  const subject: Partial<CaSubject> = {};
  for (const [apiName, attribute] of subjectFields) {
    if (input[apiName] !== undefined) {
      subject[attribute] = text(input[apiName], `subject.${apiName}`, {
        max: 64,
      });
    }
  }
  if (subject.CN === undefined) {
    throw badRequest("subject.commonName is required.");
  }
  const result = subject as CaSubject;
  buildCaSubject(result); // 400 on restricted-form violations
  return result;
};

/** The API shape of a stored subject. */
export const subjectView = (subject: CaSubject): Json => {
  const view: Json = {};
  for (const [apiName, attribute] of subjectFields) {
    const value = subject[attribute];
    if (value !== undefined) {
      view[apiName] = value;
    }
  }
  return view;
};

const shortNames: Record<string, string> = {
  "2.5.4.6": "C",
  "2.5.4.8": "ST",
  "2.5.4.7": "L",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.3": "CN",
  "0.9.2342.19200300.100.1.25": "DC",
};

/** Attributes in encoded order joined with `", "`; unknown types are dotted OIDs. */
export const subjectDn = (
  attributes: readonly { oid: string; value: string }[],
): string =>
  attributes
    .map(
      (attribute) =>
        `${shortNames[attribute.oid] ?? attribute.oid}=${attribute.value}`,
    )
    .join(", ");

export const subjectAttributesOf = (
  subjectDerBase64: string,
): { oid: string; value: string }[] =>
  decodeName(Buffer.from(subjectDerBase64, "base64")).map((rdn) => {
    const [attribute] = rdn;
    return { oid: attribute?.oid ?? "", value: attribute?.value ?? "" };
  });

// ---------------------------------------------------------------------------------------------------------------------
// Name constraints and EKU
// ---------------------------------------------------------------------------------------------------------------------

const normalizeHostBase = (base: string, label: string): string => {
  if (typeof base !== "string") {
    throw pkiBadRequest("invalid_name_constraint", `${label} must be strings.`);
  }
  const dotted = base.startsWith(".");
  const result = normalizeDnsName(dotted ? base.slice(1) : base, {
    allowWildcard: false,
  });
  if (!result.ok) {
    throw pkiBadRequest(
      "invalid_name_constraint",
      `${label}: ${result.reason}.`,
    );
  }
  return dotted ? `.${result.value}` : result.value;
};

const normalizeCidr = (base: string, label: string): string => {
  const failure = (): ApiError =>
    pkiBadRequest(
      "invalid_name_constraint",
      `${label} is not a valid CIDR with zeroed host bits.`,
    );
  if (typeof base !== "string" || !base.includes("/")) {
    throw failure();
  }
  let parsed = parseCidr(base, { strict: true, convertMapped: false });
  if (!parsed.ok && /\/0$/.test(base)) {
    parsed = parseCidr(base, { strict: false, convertMapped: false });
    if (parsed.ok && !parsed.value.bytes.every((byte) => byte === 0)) {
      throw failure();
    }
    // The address part must itself be the zero network.
    const address = parseCidr(base.slice(0, -2), {
      strict: false,
      convertMapped: false,
    });
    if (!address.ok || !address.value.bytes.every((byte) => byte === 0)) {
      throw failure();
    }
  }
  if (!parsed.ok) {
    throw failure();
  }
  return cidrToString(parsed.value);
};

const parseSubtrees = (
  value: unknown,
  label: string,
  permitted: boolean,
): NameConstraintEntry[] => {
  const input = record(value, label);
  strict(input, label, ["dns", "ip", "uri"]);
  const entries: NameConstraintEntry[] = [];
  for (const type of ["dns", "ip", "uri"] as const) {
    const list = input[type];
    if (list === undefined) {
      continue;
    }
    if (!Array.isArray(list)) {
      throw pkiBadRequest(
        "invalid_name_constraint",
        `${label}.${type} must be an array.`,
      );
    }
    for (const item of list as unknown[]) {
      if (
        typeof item !== "string" ||
        item.length > MAX_DNS_NAME_LENGTH + 1 + 43
      ) {
        throw pkiBadRequest(
          "invalid_name_constraint",
          `${label}.${type} must contain short strings.`,
        );
      }
      const base =
        type === "ip"
          ? normalizeCidr(item, `${label}.${type}`)
          : normalizeHostBase(item, `${label}.${type}`);
      if (
        permitted &&
        type === "uri" &&
        (base === "hemlig" || base === ".hemlig")
      ) {
        throw pkiBadRequest(
          "reserved_name",
          "The URI host hemlig is reserved for Hemlig identities.",
        );
      }
      entries.push({ type, value: base });
    }
  }
  return entries;
};

const dedupe = (entries: NameConstraintEntry[]): NameConstraintEntry[] => {
  const seen = new Set<string>();
  return entries.filter((entry) => {
    const key = `${entry.type}:${entry.value}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
};

/** `{permitted?, excluded?}` of `{dns?, ip?, uri?}`; undefined when empty. */
export const parseNameConstraints = (
  value: unknown,
): NameConstraintSet | undefined => {
  const input = record(value, "nameConstraints");
  strict(input, "nameConstraints", ["permitted", "excluded"]);
  const permitted = dedupe(
    input.permitted === undefined
      ? []
      : parseSubtrees(input.permitted, "nameConstraints.permitted", true),
  );
  const excluded = dedupe(
    input.excluded === undefined
      ? []
      : parseSubtrees(input.excluded, "nameConstraints.excluded", false),
  );
  if (permitted.length + excluded.length > MAX_NAME_CONSTRAINT_SUBTREES) {
    throw pkiBadRequest(
      "invalid_name_constraint",
      `At most ${MAX_NAME_CONSTRAINT_SUBTREES} name constraint subtrees are allowed.`,
    );
  }
  return permitted.length + excluded.length === 0
    ? undefined
    : { permitted, excluded };
};

/** The stored entry list as the policy engine's `{dns?, ip?, uri?}` subtree map. */
export const toSubtreeMap = (set: NameConstraintSet): SubtreeMap => {
  const group = (
    entries: readonly NameConstraintEntry[],
  ): NameConstraintSubtrees => {
    const result: NameConstraintSubtrees = {};
    for (const type of ["dns", "ip", "uri"] as const) {
      const values = entries
        .filter((entry) => entry.type === type)
        .map((entry) => entry.value);
      if (values.length > 0) {
        result[type] = values;
      }
    }
    return result;
  };
  const permitted = group(set.permitted);
  const excluded = group(set.excluded);
  return {
    ...(Object.keys(permitted).length > 0 ? { permitted } : {}),
    ...(Object.keys(excluded).length > 0 ? { excluded } : {}),
  };
};

const ekuOidByName = {
  serverAuth: EKU.serverAuth,
  clientAuth: EKU.clientAuth,
} as const;
const ekuNameByOid: Record<string, string> = {
  [EKU.serverAuth]: "serverAuth",
  [EKU.clientAuth]: "clientAuth",
};

export const ekuNamesToOids = (names: readonly string[]): string[] =>
  names.map((name) => ekuOidByName[name as keyof typeof ekuOidByName]);

export const ekuOidsToNames = (oids: readonly string[]): string[] =>
  oids.map((oid) => ekuNameByOid[oid] ?? oid);

export const caStatusReason: Record<CaRecord["status"], string> = {
  PENDING_CERTIFICATE: "pending_certificate",
  ACTIVE: "active",
  RETIRED: "retired",
  REVOKED: "revoked",
  FAILED: "failed",
};

/**
 * The CA's grant-validation context. It uses the effective constraints, not the requested ones; absent stays absent
 * so the engine reads it as "no constraint".
 */
export const caGrantContext = (ca: CaRecord): GrantCaContext => ({
  leafKeyAlgorithms: ca.policy.leafKeyAlgorithms,
  maxLeafLifetimeSeconds: ca.policy.maxLeafLifetimeSeconds,
  ...(ca.effective?.nameConstraints === undefined
    ? {}
    : { nameConstraints: toSubtreeMap(ca.effective.nameConstraints) }),
  ...(ca.effective?.extendedKeyUsages === undefined
    ? {}
    : { extendedKeyUsages: ekuOidsToNames(ca.effective.extendedKeyUsages) }),
});

export const caPolicyInputOf = (
  ca: CaRecord,
  caCert: ParsedCertificate,
  chain: readonly ParsedCertificate[],
): EngineCaPolicyInput => ({
  ...caGrantContext(ca),
  notBefore: caCert.notBefore,
  earliestChainNotAfter: new Date(
    Math.min(
      caCert.notAfter.getTime(),
      ...chain.map((certificate) => certificate.notAfter.getTime()),
    ),
  ),
});

const parseRequestedConstraints = (value: unknown): CaRecord["requested"] => {
  const input = record(value, "requestedConstraints");
  strict(input, "requestedConstraints", [
    "nameConstraints",
    "extendedKeyUsages",
  ]);
  const nameConstraints =
    input.nameConstraints === undefined
      ? undefined
      : parseNameConstraints(input.nameConstraints);
  let extendedKeyUsages: string[] | undefined;
  if (input.extendedKeyUsages !== undefined) {
    if (!Array.isArray(input.extendedKeyUsages)) {
      throw badRequest(
        "requestedConstraints.extendedKeyUsages must be an array.",
      );
    }
    const names = [...new Set(input.extendedKeyUsages as unknown[])];
    if (names.some((name) => name !== "serverAuth" && name !== "clientAuth")) {
      throw badRequest(
        "requestedConstraints.extendedKeyUsages may contain serverAuth and clientAuth.",
      );
    }
    extendedKeyUsages =
      names.length === 0 ? undefined : ekuNamesToOids(names as string[]);
  }
  return {
    pathLen: 0,
    ...(nameConstraints === undefined ? {} : { nameConstraints }),
    ...(extendedKeyUsages === undefined ? {} : { extendedKeyUsages }),
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------------------------------

export type CaPolicy = CaRecord["policy"];
export type CaPolicyInput = Partial<
  Pick<
    CaPolicy,
    | "maxLeafLifetimeSeconds"
    | "leafKeyAlgorithms"
    | "capacity"
    | "issuancePerHour"
    | "crlValiditySeconds"
  >
>;

const policyKeys = [
  "maxLeafLifetimeSeconds",
  "leafKeyAlgorithms",
  "capacity",
  "issuancePerHour",
  "crlValiditySeconds",
] as const;

export const DEFAULT_CA_POLICY: CaPolicy = {
  issueLeaves: true,
  issueSubordinates: false,
  maxLeafLifetimeSeconds: ADMIN_DEFAULT_LIFETIME_SECONDS,
  leafKeyAlgorithms: [...DEFAULT_LEAF_KEY_ALGORITHMS] as LeafKeyAlgorithm[],
  capacity: 8_000,
  issuancePerHour: 2_000,
  crlValiditySeconds: 604_800,
};

/** A ROOT signs subordinates only; its leaf fields are inert defaults. */
export const DEFAULT_ROOT_POLICY: CaPolicy = {
  ...DEFAULT_CA_POLICY,
  issueLeaves: false,
  issueSubordinates: true,
};

/** Validates the supplied fields only; absent fields stay absent. */
export const parsePolicyInput = (value: unknown): CaPolicyInput => {
  const input = record(value, "policy");
  strict(input, "policy", policyKeys);
  const policy: CaPolicyInput = {};
  if (input.maxLeafLifetimeSeconds !== undefined) {
    policy.maxLeafLifetimeSeconds = integer(
      input.maxLeafLifetimeSeconds,
      "maxLeafLifetimeSeconds",
      300,
      MAX_LEAF_LIFETIME_SECONDS,
    );
  }
  if (input.leafKeyAlgorithms !== undefined) {
    const list = input.leafKeyAlgorithms;
    if (
      !Array.isArray(list) ||
      list.length === 0 ||
      new Set(list as unknown[]).size !== list.length ||
      (list as unknown[]).some(
        (item) => !LEAF_KEY_ALGORITHMS.includes(item as LeafKeyAlgorithm),
      )
    ) {
      throw pkiBadRequest(
        "invalid_policy",
        "leafKeyAlgorithms must be a non-empty list of unique supported algorithms.",
      );
    }
    policy.leafKeyAlgorithms = list as LeafKeyAlgorithm[];
  }
  if (input.capacity !== undefined) {
    policy.capacity = integer(input.capacity, "capacity", 1, 12_000);
  }
  if (input.issuancePerHour !== undefined) {
    policy.issuancePerHour = integer(
      input.issuancePerHour,
      "issuancePerHour",
      1,
      6_000,
    );
  }
  if (input.crlValiditySeconds !== undefined) {
    policy.crlValiditySeconds = integer(
      input.crlValiditySeconds,
      "crlValiditySeconds",
      3_600,
      2_592_000,
    );
  }
  return policy;
};

/** Fills absent fields from `base` (defaults on create, the stored policy on update) and checks the budget. */
export const resolvePolicy = (
  input: CaPolicyInput,
  base: CaPolicy = DEFAULT_CA_POLICY,
): CaPolicy => {
  const policy: CaPolicy = {
    issueLeaves: base.issueLeaves,
    issueSubordinates: base.issueSubordinates,
    maxLeafLifetimeSeconds:
      input.maxLeafLifetimeSeconds ?? base.maxLeafLifetimeSeconds,
    leafKeyAlgorithms: input.leafKeyAlgorithms ?? base.leafKeyAlgorithms,
    capacity: input.capacity ?? base.capacity,
    issuancePerHour: input.issuancePerHour ?? base.issuancePerHour,
    crlValiditySeconds: input.crlValiditySeconds ?? base.crlValiditySeconds,
  };
  if (policy.capacity + 2 * policy.issuancePerHour > MAX_ISSUANCE_BUDGET) {
    throw caIssuanceBudgetExceeded();
  }
  return policy;
};

/** `parseCaPolicy(input, existing?)`: validate, then resolve against defaults or the stored policy. */
export const parseCaPolicy = (value: unknown, existing?: CaPolicy): CaPolicy =>
  resolvePolicy(parsePolicyInput(value), existing);

// ---------------------------------------------------------------------------------------------------------------------
// Request parsers
// ---------------------------------------------------------------------------------------------------------------------

interface CreateCaCommon {
  environment: string;
  name: string;
  keyAlgorithm: PkiKeyAlgorithm;
  subject: CaSubject;
  requested: CaRecord["requested"];
  policy: CaPolicy;
  displayName?: string;
}

/** The EXTERNAL object carries no Phase 7 keys: its idempotency digest must stay byte-identical (T-A7). */
export type CreateCaInput = CreateCaCommon &
  (
    | { kind: "EXTERNAL_INTERMEDIATE" }
    | { kind: "ROOT"; validitySeconds: number }
    | { kind: "INTERMEDIATE"; parentCaId: string; validitySeconds: number }
  );

/** A leaf field that is present and differs from the stored policy is refused on a ROOT. */
export const assertRootPolicyUpdate = (
  input: CaPolicyInput,
  stored: CaPolicy,
): void => {
  if (
    (input.maxLeafLifetimeSeconds !== undefined &&
      input.maxLeafLifetimeSeconds !== stored.maxLeafLifetimeSeconds) ||
    (input.leafKeyAlgorithms !== undefined &&
      stableJson(input.leafKeyAlgorithms) !==
        stableJson(stored.leafKeyAlgorithms))
  ) {
    throw pkiBadRequest("invalid_policy", "A ROOT CA issues no leaves.");
  }
};

const parseDisplayName = (value: unknown): string =>
  text(value, "displayName", { max: 128 });

export const parseCreateCaRequest = (body: unknown): CreateCaInput => {
  const input = record(body, "The request body");
  strict(input, "The request body", nameKeys);
  const environment = text(input.environment, "environment", { max: 128 });
  const name = text(input.name, "name", { max: 64 });
  if (!namePattern.test(name)) {
    throw badRequest(
      "name must be 3-64 lowercase letters, digits and hyphens, starting with a letter.",
    );
  }
  const kind = input.kind;
  if (typeof kind !== "string") {
    throw badRequest("kind must be a string.");
  }
  if (
    kind !== "EXTERNAL_INTERMEDIATE" &&
    kind !== "ROOT" &&
    kind !== "INTERMEDIATE"
  ) {
    throw pkiBadRequest(
      "kind_not_supported",
      "kind must be EXTERNAL_INTERMEDIATE, ROOT or INTERMEDIATE.",
    );
  }
  if (kind === "INTERMEDIATE") {
    if (input.parentCaId === undefined) {
      throw pkiBadRequest(
        "parent_required",
        "parentCaId is required for an INTERMEDIATE.",
      );
    }
  } else if (input.parentCaId !== undefined) {
    throw pkiBadRequest(
      "parent_not_allowed",
      "parentCaId is allowed only for an INTERMEDIATE.",
    );
  }
  if (kind === "EXTERNAL_INTERMEDIATE" && input.validitySeconds !== undefined) {
    throw pkiBadRequest(
      "validity_not_allowed",
      "validitySeconds is not allowed for an EXTERNAL_INTERMEDIATE.",
    );
  }
  const keyAlgorithm = input.keyAlgorithm;
  if (!CA_KEY_ALGORITHMS.includes(keyAlgorithm as PkiKeyAlgorithm)) {
    throw badRequest("keyAlgorithm is not supported.");
  }
  const subject = parseSubject(input.subject);
  // countryName is a two-letter PrintableString in a certificate Hemlig signs itself.
  if (
    kind !== "EXTERNAL_INTERMEDIATE" &&
    subject.C !== undefined &&
    !/^[A-Za-z]{2}$/.test(subject.C)
  ) {
    throw badRequest("subject.country must be exactly two letters.");
  }
  const requested =
    input.requestedConstraints === undefined
      ? ({ pathLen: 0 } as CaRecord["requested"])
      : parseRequestedConstraints(input.requestedConstraints);
  if (kind === "ROOT") {
    requested.pathLen = ROOT_PATH_LEN;
  }
  const policyInput =
    input.policy === undefined ? {} : parsePolicyInput(input.policy);
  if (
    kind === "ROOT" &&
    (policyInput.maxLeafLifetimeSeconds !== undefined ||
      policyInput.leafKeyAlgorithms !== undefined)
  ) {
    throw pkiBadRequest("invalid_policy", "A ROOT CA issues no leaves.");
  }
  if (input.crl !== undefined) {
    const crl = record(input.crl, "crl");
    strict(crl, "crl", ["validitySeconds"]);
    if (crl.validitySeconds !== undefined) {
      const validity = integer(
        crl.validitySeconds,
        "crl.validitySeconds",
        3_600,
        2_592_000,
      );
      if (
        policyInput.crlValiditySeconds !== undefined &&
        policyInput.crlValiditySeconds !== validity
      ) {
        throw pkiBadRequest(
          "invalid_policy",
          "crl.validitySeconds and policy.crlValiditySeconds disagree.",
        );
      }
      policyInput.crlValiditySeconds = validity;
    }
  }
  const common = {
    environment,
    name,
    keyAlgorithm: keyAlgorithm as PkiKeyAlgorithm,
    subject,
    requested,
    policy: resolvePolicy(
      policyInput,
      kind === "ROOT" ? DEFAULT_ROOT_POLICY : DEFAULT_CA_POLICY,
    ),
    ...(input.displayName === undefined
      ? {}
      : { displayName: parseDisplayName(input.displayName) }),
  };
  if (kind === "EXTERNAL_INTERMEDIATE") {
    return { ...common, kind };
  }
  const validitySeconds = parseValidity(
    input.validitySeconds,
    kind === "ROOT"
      ? MIN_ROOT_VALIDITY_SECONDS
      : MIN_INTERMEDIATE_VALIDITY_SECONDS,
    kind === "ROOT"
      ? DEFAULT_ROOT_VALIDITY_SECONDS
      : DEFAULT_INTERMEDIATE_VALIDITY_SECONDS,
  );
  if (kind === "ROOT") {
    return { ...common, kind, validitySeconds };
  }
  if (
    typeof input.parentCaId !== "string" ||
    !parentCaIdPattern.test(input.parentCaId)
  ) {
    throw badRequest("parentCaId is not a CA id.");
  }
  return { ...common, kind, parentCaId: input.parentCaId, validitySeconds };
};

const parseValidity = (
  value: unknown,
  min: number,
  fallback: number,
): number => {
  if (value === undefined) {
    return fallback;
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    value > MAX_CA_VALIDITY_SECONDS
  ) {
    throw pkiBadRequest(
      "invalid_validity",
      `validitySeconds must be an integer between ${min} and ${MAX_CA_VALIDITY_SECONDS}.`,
    );
  }
  return value;
};

export interface UpdateCaInput {
  /** Omitted keeps the stored name; null clears it. */
  displayName?: string | null;
  policy: CaPolicyInput;
}

export const parseUpdateCaRequest = (body: unknown): UpdateCaInput => {
  const input = record(body, "The request body");
  strict(input, "The request body", ["displayName", "policy"]);
  if (input.policy === undefined) {
    throw badRequest("policy is required.");
  }
  return {
    policy: parsePolicyInput(input.policy),
    ...(input.displayName === undefined
      ? {}
      : {
          displayName:
            input.displayName === null
              ? null
              : parseDisplayName(input.displayName),
        }),
  };
};

export interface ActivateCaInput {
  certificatePem: string;
  chainPem: string;
  rootCrl?: string;
  acceptBroaderConstraints: boolean;
}

/** Long enough for the base64 of a maximum-size uploaded CRL with PEM framing. */
const maximumRootCrlText = Math.ceil((512 * 1024) / 3) * 4 * 1.05 + 512;

export const parseActivateRequest = (body: unknown): ActivateCaInput => {
  const input = record(body, "The request body");
  strict(input, "The request body", [
    "certificatePem",
    "chainPem",
    "rootCrl",
    "acceptBroaderConstraints",
  ]);
  const accept = input.acceptBroaderConstraints;
  if (accept !== undefined && typeof accept !== "boolean") {
    throw badRequest("acceptBroaderConstraints must be a boolean.");
  }
  return {
    certificatePem: text(input.certificatePem, "certificatePem", {
      max: MAX_CA_PEM_BYTES,
    }),
    chainPem: text(input.chainPem, "chainPem", { max: MAX_CA_PEM_BYTES }),
    ...(input.rootCrl === undefined
      ? {}
      : {
          rootCrl: text(input.rootCrl, "rootCrl", {
            max: Math.floor(maximumRootCrlText),
          }),
        }),
    acceptBroaderConstraints: accept === true,
  };
};

export const parseUploadCrlRequest = (body: unknown): { crl: string } => {
  const input = record(body, "The request body");
  strict(input, "The request body", ["crl"]);
  return {
    crl: text(input.crl, "crl", { max: Math.floor(maximumRootCrlText) }),
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Digests and replay
// ---------------------------------------------------------------------------------------------------------------------

/** `sha256(stableJson({op, ...normalized}))`: independent of key order. */
export const requestDigest = (op: string, normalized: object): string =>
  sha256Hex(stableJson({ op, ...normalized }));

export const assertHumanReplay = (
  stored: Record<string, unknown>,
  operationType: string,
  digest: string,
): void => {
  if (
    stored.operationType !== operationType ||
    stored.requestDigest !== digest
  ) {
    throw conflict(
      "This idempotency key has already been used for a different operation.",
    );
  }
};

export const replayOutcome = (
  stored: Record<string, unknown>,
): { result: Record<string, unknown>; shouldWriteTerminalAudit: boolean } => ({
  result: (isRecord(stored.result) ? stored.result : {}) as Record<
    string,
    unknown
  >,
  shouldWriteTerminalAudit: stored.status !== "SUCCEEDED",
});

// ---------------------------------------------------------------------------------------------------------------------
// CRL reasons
// ---------------------------------------------------------------------------------------------------------------------

const reasonNames: Record<number, string> = {
  0: "unspecified",
  1: "keyCompromise",
  2: "caCompromise",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  6: "certificateHold",
  9: "privilegeWithdrawn",
  10: "aACompromise",
};

export const crlReasonName = (code?: number): string =>
  code === undefined ? "unspecified" : (reasonNames[code] ?? `code:${code}`);

// ---------------------------------------------------------------------------------------------------------------------
// Response mappers
// ---------------------------------------------------------------------------------------------------------------------

export type CurrencyState = "MISSING" | "STALE" | "CURRENT";

export const rootCrlState = (
  crl: { nextUpdate: string } | undefined,
  now: Date,
): CurrencyState =>
  crl === undefined
    ? "MISSING"
    : now.toISOString() >= crl.nextUpdate
      ? "STALE"
      : "CURRENT";

const constraintsView = (
  value: CaRecord["requested"] | CaRecord["effective"] | undefined,
): Json | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const view: Json = {};
  if (value.nameConstraints !== undefined) {
    const map = toSubtreeMap(value.nameConstraints);
    if (Object.keys(map).length > 0) {
      view.nameConstraints = map;
    }
  }
  if (value.extendedKeyUsages !== undefined) {
    view.extendedKeyUsages = ekuOidsToNames(value.extendedKeyUsages);
  }
  return view;
};

export const caSummary = (ca: CaRecord): Json => ({
  caId: ca.caId,
  environment: ca.environment,
  name: ca.name,
  ...(ca.displayName === undefined ? {} : { displayName: ca.displayName }),
  kind: ca.kind,
  status: ca.status,
  version: ca.version,
  keyAlgorithm: ca.key.algorithm,
  keyState: ca.key.state,
  ...(ca.fingerprint === undefined ? {} : { fingerprint: ca.fingerprint }),
  ...(ca.notAfter === undefined ? {} : { notAfter: ca.notAfter }),
  createdAt: ca.createdAt,
});

export const crlView = (crl: CaCrlState, now: Date): Json | undefined => {
  const published = crl.published;
  if (published === undefined) {
    return undefined;
  }
  return {
    number: published.number,
    thisUpdate: published.thisUpdate,
    nextUpdate: published.nextUpdate,
    entryCount: published.entryCount,
    sha256: published.sha256,
    revision: crl.revision,
    pendingRevocations: Math.max(0, crl.revision - published.revision),
    ...(crl.dirtySince === undefined ? {} : { dirtySince: crl.dirtySince }),
    state: rootCrlState(published, now),
  };
};

export const capacityView = (ca: CaRecord, crl?: CaCrlState): Json => ({
  capacity: ca.policy.capacity,
  issuancePerHour: ca.policy.issuancePerHour,
  ...(crl?.capacity === undefined
    ? {}
    : {
        count: crl.capacity.count,
        countFrom: crl.capacity.countFrom,
        countedAt: crl.capacity.countedAt,
      }),
});

/** True once a RETIRED CA has published a CRL covering its drain point. */
export const caDrained = (
  ca: CaRecord,
  crl: CaCrlState | undefined,
): boolean => {
  const retiredDrain =
    ca.status === "RETIRED" &&
    ca.notAfter !== undefined &&
    ca.retiredAt !== undefined;
  return (
    ca.status === "RETIRED" &&
    crl?.published !== undefined &&
    retiredDrain &&
    isDrained(ca, { ...crl, published: crl.published })
  );
};

export const caDetail = (
  ca: CaRecord,
  options: {
    crl?: CaCrlState;
    external?: ExternalCaRecord;
    now: Date;
    warnings?: { code: string; message: string }[];
  },
): Json => {
  const { crl, external, now } = options;
  const requested = constraintsView(ca.requested);
  const effective = constraintsView(ca.effective);
  const retiredDrain =
    ca.status === "RETIRED" &&
    ca.notAfter !== undefined &&
    ca.retiredAt !== undefined;
  const drained = caDrained(ca, crl);
  const view: Json = {
    ...caSummary(ca),
    capacity: capacityView(ca, crl),
    key: {
      custody: ca.key.custody,
      algorithm: ca.key.algorithm,
      spkiSha256: ca.key.spkiSha256,
      state: ca.key.state,
    },
    subject: subjectView(ca.subject),
    subjectDn: subjectDn(buildCaSubject(ca.subject).attributes),
    requestedConstraints: requested ?? {},
    ...(effective === undefined ? {} : { effectiveConstraints: effective }),
    ...(ca.acceptBroaderConstraints === undefined
      ? {}
      : { acceptBroaderConstraints: ca.acceptBroaderConstraints }),
    ...(ca.csrPem === undefined ? {} : { csrPem: ca.csrPem }),
    ...(ca.certificatePem === undefined
      ? {}
      : { certificatePem: ca.certificatePem }),
    ...(ca.chainPem === undefined ? {} : { chainPem: ca.chainPem }),
    ...(ca.serial === undefined ? {} : { serial: ca.serial }),
    ...(ca.notBefore === undefined ? {} : { notBefore: ca.notBefore }),
    ...(ca.parent === undefined ? {} : { parent: ca.parent }),
    ...(ca.parentCaId === undefined ? {} : { parentCaId: ca.parentCaId }),
    crlIssuers: ca.crlIssuers,
    policy: ca.policy,
    maxIssueLifetimeEverSeconds: ca.maxIssueLifetimeEverSeconds,
    createdBy: ca.createdBy,
    ...(ca.activatedAt === undefined ? {} : { activatedAt: ca.activatedAt }),
    ...(ca.retiredAt === undefined ? {} : { retiredAt: ca.retiredAt }),
    ...(ca.revokedAt === undefined ? {} : { revokedAt: ca.revokedAt }),
    ...(ca.revocationReason === undefined
      ? {}
      : { revocationReason: ca.revocationReason }),
    ...(ca.revocationSource === undefined
      ? {}
      : { revocationSource: ca.revocationSource }),
    ...(ca.revocationEvidence === undefined
      ? {}
      : { revocationEvidence: ca.revocationEvidence }),
    drained,
    ...(retiredDrain ? { drainAt: drainPoint(ca) } : {}),
  };
  const crlSummary = crl === undefined ? undefined : crlView(crl, now);
  if (crlSummary !== undefined) {
    view.crl = crlSummary;
  }
  if (ca.parent?.type === "external") {
    view.rootCrl = {
      extId: ca.parent.id,
      state: rootCrlState(external?.crl, now),
      ...(external?.crl === undefined
        ? {}
        : {
            numberHex: external.crl.numberHex,
            thisUpdate: external.crl.thisUpdate,
            nextUpdate: external.crl.nextUpdate,
          }),
    };
  }
  if (options.warnings !== undefined && options.warnings.length > 0) {
    view.warnings = options.warnings;
  }
  return view;
};

export const externalCaDetail = (ext: ExternalCaRecord, now: Date): Json => ({
  extId: ext.extId,
  certificatePem: ext.certificatePem,
  fingerprint: ext.fingerprint,
  spkiSha256: ext.spkiSha256,
  subjectDn: subjectDn(ext.subjectAttributes),
  subjectKeyIdentifier: ext.subjectKeyIdentifier,
  notAfter: ext.notAfter,
  dependents: [...ext.dependents].sort(),
  environments: [...ext.environments].sort(),
  version: ext.version,
  createdAt: ext.createdAt,
  ...(ext.crl === undefined
    ? {}
    : {
        crl: {
          numberHex: ext.crl.numberHex,
          thisUpdate: ext.crl.thisUpdate,
          nextUpdate: ext.crl.nextUpdate,
          sha256: ext.crl.sha256,
          uploadedAt: ext.crl.uploadedAt,
        },
      }),
  crlState: rootCrlState(ext.crl, now),
});

export const externalCaSummary = (ext: ExternalCaRecord, now: Date): Json => {
  const detail = externalCaDetail(ext, now);
  delete detail.certificatePem;
  return detail;
};
