/**
 * Input and output types for the pure issuance policy engine. These are
 * deliberately self-contained: they do not depend on `src/pki/types.ts`.
 */
import type { NameConstraintSet } from "./names";

export type { NameConstraintSet, NameConstraintSubtrees } from "./names";

export type LeafKeyAlgorithm =
  | "ECDSA_P256"
  | "ECDSA_P384"
  | "ECDSA_P521"
  | "ED25519"
  | "RSA_2048"
  | "RSA_3072"
  | "RSA_4096"
  | "RSA_8192";

export const LEAF_KEY_ALGORITHMS: readonly LeafKeyAlgorithm[] = [
  "ECDSA_P256",
  "ECDSA_P384",
  "ECDSA_P521",
  "ED25519",
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "RSA_8192",
];

/** Allowed without being listed. P-521 and Ed25519 must be listed explicitly. */
export const DEFAULT_LEAF_KEY_ALGORITHMS: readonly LeafKeyAlgorithm[] = [
  "ECDSA_P256",
  "ECDSA_P384",
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "RSA_8192",
];

export type KeyUsageName = "digitalSignature" | "keyEncipherment";
export const KEY_USAGES: readonly KeyUsageName[] = [
  "digitalSignature",
  "keyEncipherment",
];

export type ExtendedKeyUsageName = "serverAuth" | "clientAuth";
export const EXTENDED_KEY_USAGES: readonly ExtendedKeyUsageName[] = [
  "serverAuth",
  "clientAuth",
];

/** Subject attributes in encoding order (C, ST, L, O, OU); the common name follows them. */
export type SubjectAttribute =
  "country" | "state" | "locality" | "organization" | "organizationalUnit";
export const SUBJECT_ATTRIBUTES: readonly SubjectAttribute[] = [
  "country",
  "state",
  "locality",
  "organization",
  "organizationalUnit",
];

export interface SubjectEntry {
  type: SubjectAttribute | "commonName";
  value: string;
}

export type DenialReason =
  | "name_not_permitted"
  | "wildcard_not_permitted"
  | "reserved_name"
  | "common_name_not_permitted"
  | "subject_not_permitted"
  | "key_algorithm_not_permitted"
  | "key_usage_not_permitted"
  | "extended_key_usage_not_permitted"
  | "ca_not_permitted"
  | "too_many_names"
  | "certificate_too_large"
  | "lifetime_too_short"
  | "name_constraint_violation";

export interface Denial {
  reason: DenialReason;
  detail: string;
}

export interface SanSet {
  dns: string[];
  ip: string[];
  uri: string[];
}

/** Normalized issuance request. Names are raw strings; the engine canonicalizes them. */
export interface PolicyRequest {
  source: "consumer" | "admin";
  /** A LeafKeyAlgorithm name; anything else is `key_algorithm_not_permitted`. */
  keyAlgorithm: string;
  sans: SanSet;
  commonName?: string;
  /** Requested subject attributes other than the common name. */
  subject: SubjectEntry[];
  /**
   * Requested usages: cert-manager strings (`digital signature`, `server auth`, ...)
   * or the Hemlig names (`digitalSignature`, `serverAuth`, ...).
   */
  usages: string[];
  /** Requested lifetime; the grant default (admin: 90 days) when omitted. */
  durationSeconds?: number;
  isCA: boolean;
}

export interface NameRuleLists {
  allow?: string[];
  deny?: string[];
}

export interface GrantNames {
  dns?: NameRuleLists & { allowWildcardNames?: boolean };
  ip?: NameRuleLists;
  uri?: NameRuleLists;
  commonName?: { mode?: "san" | "forbid"; addToSans?: boolean };
  maxSans?: number;
}

/** The policy body of an IssuanceGrant ("Entitlements → Shape" minus name, caId, displayName, expiresAt). */
export interface GrantPolicy {
  names: GrantNames;
  subject?: { allow?: Partial<Record<SubjectAttribute, string[]>> };
  /** Exactly the listed algorithms; the default set when omitted. */
  keyAlgorithms?: LeafKeyAlgorithm[];
  keyUsages: KeyUsageName[];
  extendedKeyUsages: {
    allow: ExtendedKeyUsageName[];
    default: ExtendedKeyUsageName[];
  };
  lifetime: { defaultSeconds: number; maxSeconds: number; minSeconds?: number };
  forced?: {
    subject?: Partial<Record<SubjectAttribute, string>>;
    sans?: Partial<SanSet>;
    certificatePolicies?: string[];
  };
  quotas?: { perHour?: number; perDay?: number };
}

/** The slice of a CA record the engine needs. */
export interface CaPolicyInput {
  leafKeyAlgorithms: LeafKeyAlgorithm[];
  maxLeafLifetimeSeconds: number;
  /** The chain's effective constraints. */
  nameConstraints?: NameConstraintSet;
  /** The chain's effective EKU constraint (names, or the anyExtendedKeyUsage OID/name). */
  extendedKeyUsages?: string[];
  /** The issuing CA certificate's notBefore. */
  notBefore: Date;
  /** The earliest notAfter in the chain, including the CA certificate itself. */
  earliestChainNotAfter: Date;
}

export interface PolicyInput {
  request: PolicyRequest;
  /** Required for `consumer`; omitted for `admin` (ceilings only). */
  grant?: GrantPolicy;
  ca: CaPolicyInput;
  now: Date;
}

export interface IssuancePlan {
  keyAlgorithm: LeafKeyAlgorithm;
  /** Final deduplicated SANs, including CN-derived and forced entries. */
  sans: SanSet;
  /** Ordered C, ST, L, O, OU, then CN. */
  subject: SubjectEntry[];
  commonName?: string;
  /** SAN must be marked critical (empty subject). */
  sanCritical: boolean;
  keyUsages: KeyUsageName[];
  extendedKeyUsages: ExtendedKeyUsageName[];
  certificatePolicies: string[];
  notBefore: Date;
  notAfter: Date;
  lifetimeClamped: boolean;
}

export interface TraceStep {
  /** Step number in the plan's "Evaluation order". */
  step: number;
  name: string;
  outcome: "pass" | "deny" | "skipped";
  detail?: string;
}

export type PolicyOutcome =
  | { ok: true; plan: IssuancePlan; trace: TraceStep[] }
  | { ok: false; denial: Denial; trace: TraceStep[] };
