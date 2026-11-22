import { createHash } from "node:crypto";
import { badRequest, serviceUnavailable } from "../domain/errors";
import { sha256Hex, stableJson } from "../util/encoding";
import {
  assembleCertificate,
  buildLeafTbs,
  generateSerial,
  parseCertificate,
  verifyCertificateSignature,
  type ParsedCertificate,
} from "./asn1/certificate";
import {
  decodeCertificatePolicies,
  EKU,
  EXT,
  keyIdentifierFromSpki,
} from "./asn1/extensions";
import { decodeSubjectAltName, encodeName } from "./asn1/names";
import { fromPem, PemError } from "./asn1/pem";
import { ekuNamesToOids, requestDigest } from "./ca-model";
import { maximumCsrBytes, type ParsedCsr } from "./csr";
import { csrInvalid, issuanceDenied, pkiBadRequest } from "./errors";
import type {
  Denial,
  IssuancePlan,
  PolicyRequest,
  SubjectAttribute,
  SubjectEntry,
} from "./policy-types";
import { SUBJECT_OID } from "./subject";
import type { CaRecord, IssuedCertificateRecord } from "./types";

type Json = Record<string, unknown>;

/** The TBS limit leaves 1 KiB for the signature and algorithm under the 16 KiB DER limit. */
export const MAX_TBS_BYTES = 15_360;
export const MAX_CERTIFICATE_BYTES = 16_384;
export const ADMIN_ISSUANCE_PER_HOUR = 100;
export const MAX_ADMIN_SANS = 100;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const unknownField = () =>
  pkiBadRequest("unknown_field", "The request has an unknown field.");

const strictKeys = (value: Json, allowed: readonly string[]): void => {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw unknownField();
    }
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------------------------------------------------

export interface KubernetesRequester {
  namespace: string;
  name: string;
  uid: string;
  certificateName?: string;
  revision?: string;
}

interface CommonIssueInput {
  certificateSigningRequestPem: string;
  durationSeconds?: number;
  usages: string[];
  isCA: boolean;
}

export interface ConsumerIssueInput extends CommonIssueInput {
  requester?: { kubernetes?: KubernetesRequester };
}

export interface AdminIssueInput extends CommonIssueInput {
  useCsrNames: boolean;
  sans?: { dns?: string[]; ip?: string[]; uri?: string[] };
  subject?: AdminSubject;
}

export interface AdminSubject {
  commonName?: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  locality?: string;
  state?: string;
}

const csrField = (value: unknown): string => {
  if (typeof value !== "string") {
    throw badRequest("certificateSigningRequestPem must be a string.");
  }
  return value;
};

const durationField = (value: unknown): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw pkiBadRequest(
      "invalid_duration",
      "durationSeconds must be a positive integer.",
    );
  }
  return value;
};

const usagesField = (value: unknown): string[] => {
  if (value === undefined) {
    return [];
  }
  if (
    !Array.isArray(value) ||
    value.length > 16 ||
    value.some((usage) => typeof usage !== "string" || usage.length > 64)
  ) {
    throw pkiBadRequest(
      "invalid_usages",
      "usages must be at most 16 strings of at most 64 characters.",
    );
  }
  return value as string[];
};

const isCaField = (value: unknown): boolean => {
  if (value === undefined) {
    return false;
  }
  if (typeof value !== "boolean") {
    throw badRequest("isCA must be a boolean.");
  }
  return value;
};

const requesterPatterns = {
  namespace: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/,
  name: /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/,
  uid: /^[0-9A-Fa-f-]{1,64}$/,
  revision: /^\d{1,10}$/,
} as const;

const invalidRequester = () =>
  pkiBadRequest("invalid_requester", "The requester metadata is invalid.");

const parseRequester = (
  value: unknown,
): ConsumerIssueInput["requester"] | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw invalidRequester();
  }
  strictKeys(value, ["kubernetes"]);
  if (value.kubernetes === undefined) {
    return {};
  }
  const k = value.kubernetes;
  if (!isRecord(k)) {
    throw invalidRequester();
  }
  strictKeys(k, ["namespace", "name", "uid", "certificateName", "revision"]);
  const text = (field: unknown, pattern: RegExp, max: number): string => {
    if (
      typeof field !== "string" ||
      field.length === 0 ||
      field.length > max ||
      !pattern.test(field)
    ) {
      throw invalidRequester();
    }
    return field;
  };
  const kubernetes: KubernetesRequester = {
    namespace: text(k.namespace, requesterPatterns.namespace, 63),
    name: text(k.name, requesterPatterns.name, 253),
    uid: text(k.uid, requesterPatterns.uid, 64),
    ...(k.certificateName === undefined
      ? {}
      : {
          certificateName: text(
            k.certificateName,
            requesterPatterns.name,
            253,
          ),
        }),
    ...(k.revision === undefined
      ? {}
      : { revision: text(k.revision, requesterPatterns.revision, 10) }),
  };
  return { kubernetes };
};

const consumerKeys = [
  "certificateSigningRequestPem",
  "durationSeconds",
  "usages",
  "isCA",
  "requester",
] as const;

/** Step 1 for a consumer: strict body, then the `isCA` denial. */
export const parseConsumerIssueRequest = (body: unknown): ConsumerIssueInput => {
  if (!isRecord(body)) {
    throw badRequest("The request body must be a JSON object.");
  }
  if (body.sans !== undefined || body.subject !== undefined) {
    throw pkiBadRequest(
      "names_from_csr_only",
      "Names come from the CSR only.",
    );
  }
  strictKeys(body, consumerKeys);
  const requester = parseRequester(body.requester);
  const input: ConsumerIssueInput = {
    certificateSigningRequestPem: csrField(body.certificateSigningRequestPem),
    ...(durationField(body.durationSeconds) === undefined
      ? {}
      : { durationSeconds: durationField(body.durationSeconds) as number }),
    usages: usagesField(body.usages),
    isCA: isCaField(body.isCA),
    ...(requester === undefined ? {} : { requester }),
  };
  if (input.isCA) {
    throw issuanceDenied("ca_not_permitted", "CA certificates cannot be requested.");
  }
  return input;
};

const adminKeys = [
  "certificateSigningRequestPem",
  "useCsrNames",
  "sans",
  "subject",
  "durationSeconds",
  "usages",
  "isCA",
] as const;
const adminSubjectKeys = [
  "commonName",
  "organization",
  "organizationalUnit",
  "country",
  "locality",
  "state",
] as const;

const nameList = (value: unknown, label: string): string[] | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (
    !Array.isArray(value) ||
    value.length > MAX_ADMIN_SANS ||
    value.some((name) => typeof name !== "string" || name.length > 2048)
  ) {
    throw pkiBadRequest(
      "invalid_sans",
      `${label} must be at most ${MAX_ADMIN_SANS} strings.`,
    );
  }
  return value as string[];
};

export const parseAdminIssueRequest = (body: unknown): AdminIssueInput => {
  if (!isRecord(body)) {
    throw badRequest("The request body must be a JSON object.");
  }
  strictKeys(body, adminKeys);
  if (body.useCsrNames !== undefined && typeof body.useCsrNames !== "boolean") {
    throw badRequest("useCsrNames must be a boolean.");
  }
  const useCsrNames = body.useCsrNames === true;
  if (useCsrNames && (body.sans !== undefined || body.subject !== undefined)) {
    throw pkiBadRequest(
      "names_conflict",
      "useCsrNames cannot be combined with sans or subject.",
    );
  }
  let sans: AdminIssueInput["sans"];
  if (body.sans !== undefined) {
    if (!isRecord(body.sans)) {
      throw badRequest("sans must be an object.");
    }
    strictKeys(body.sans, ["dns", "ip", "uri"]);
    sans = {
      ...(nameList(body.sans.dns, "sans.dns") === undefined
        ? {}
        : { dns: nameList(body.sans.dns, "sans.dns") as string[] }),
      ...(nameList(body.sans.ip, "sans.ip") === undefined
        ? {}
        : { ip: nameList(body.sans.ip, "sans.ip") as string[] }),
      ...(nameList(body.sans.uri, "sans.uri") === undefined
        ? {}
        : { uri: nameList(body.sans.uri, "sans.uri") as string[] }),
    };
  }
  let subject: AdminSubject | undefined;
  if (body.subject !== undefined) {
    if (!isRecord(body.subject)) {
      throw badRequest("subject must be an object.");
    }
    strictKeys(body.subject, adminSubjectKeys);
    subject = {};
    for (const key of adminSubjectKeys) {
      const value = body.subject[key];
      if (value !== undefined) {
        if (typeof value !== "string" || value.length === 0 || value.length > 256) {
          throw badRequest(`subject.${key} must be a string.`);
        }
        subject[key] = value;
      }
    }
  }
  const duration = durationField(body.durationSeconds);
  const input: AdminIssueInput = {
    certificateSigningRequestPem: csrField(body.certificateSigningRequestPem),
    useCsrNames,
    ...(sans === undefined ? {} : { sans }),
    ...(subject === undefined ? {} : { subject }),
    ...(duration === undefined ? {} : { durationSeconds: duration }),
    usages: usagesField(body.usages),
    isCA: isCaField(body.isCA),
  };
  if (input.isCA) {
    throw issuanceDenied("ca_not_permitted", "CA certificates cannot be requested.");
  }
  return input;
};

// ---------------------------------------------------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------------------------------------------------

/** `sha256` of the CSR's DER; a PEM error is `invalid_csr` before any replay lookup. */
export const csrDerSha256 = (pem: string): string => {
  try {
    return sha256Hex(fromPem(pem, "CERTIFICATE REQUEST", maximumCsrBytes));
  } catch (error) {
    throw csrInvalid(error instanceof PemError ? error.reason : "malformed");
  }
};

const sortedUsages = (usages: readonly string[]): string[] =>
  [...new Set(usages)].sort();

export const consumerIssueDigest = (
  consumerId: string,
  grantName: string,
  csrSha256: string,
  input: Pick<ConsumerIssueInput, "durationSeconds" | "usages" | "isCA">,
): string =>
  sha256Hex(
    stableJson({
      op: "pki.certificate.issue",
      consumerId,
      grantName,
      csrDerSha256: csrSha256,
      durationSeconds: input.durationSeconds ?? null,
      sortedUsages: sortedUsages(input.usages),
      isCA: input.isCA === true,
    }),
  );

export const adminIssueDigest = (
  caId: string,
  csrSha256: string,
  input: AdminIssueInput,
): string =>
  requestDigest("pki.certificate.issue", {
    caId,
    csrDerSha256: csrSha256,
    useCsrNames: input.useCsrNames,
    sans: input.sans ?? null,
    subject: input.subject ?? null,
    durationSeconds: input.durationSeconds ?? null,
    sortedUsages: sortedUsages(input.usages),
    isCA: input.isCA === true,
  });

// ---------------------------------------------------------------------------------------------------------------------
// CSR to policy request
// ---------------------------------------------------------------------------------------------------------------------

const subjectAttributeByOid: Record<string, SubjectAttribute> = {
  [SUBJECT_OID.C]: "country",
  [SUBJECT_OID.ST]: "state",
  [SUBJECT_OID.L]: "locality",
  [SUBJECT_OID.O]: "organization",
  [SUBJECT_OID.OU]: "organizationalUnit",
};

const denial = (
  reason: Denial["reason"],
  detail: string,
  denied?: Denial["denied"],
): { ok: false; denial: Denial } => ({
  ok: false,
  denial: { reason, detail, ...(denied === undefined ? {} : { denied }) },
});

export type CsrMapping =
  | { ok: true; request: PolicyRequest }
  | { ok: false; denial: Denial };

export const csrToPolicyRequest = (
  parsed: ParsedCsr,
  input: Pick<ConsumerIssueInput, "durationSeconds" | "usages" | "isCA">,
  source: "consumer" | "admin",
  explicit?: Pick<AdminIssueInput, "sans" | "subject">,
): CsrMapping => {
  const names = explicit === undefined ? "csr" : "explicit";
  let sans = { dns: [] as string[], ip: [] as string[], uri: [] as string[] };
  let commonName: string | undefined;
  const subject: SubjectEntry[] = [];
  if (names === "csr") {
    if (parsed.san.email.length > 0) {
      return denial("name_not_permitted", "email SANs are not issued", {
        type: "subject",
        value: "email",
      });
    }
    if (parsed.san.unsupported.length > 0) {
      return denial("name_not_permitted", "this SAN type is not issued", {
        type: "subject",
        value: "other",
      });
    }
    sans = {
      dns: [...parsed.san.dns],
      ip: [...parsed.san.ip],
      uri: [...parsed.san.uri],
    };
    for (const attribute of parsed.subject) {
      if (attribute.oid === SUBJECT_OID.CN) {
        if (commonName !== undefined) {
          return denial(
            "subject_not_permitted",
            "the subject has more than one common name",
            { type: "subject", value: `CN=${attribute.value}` },
          );
        }
        commonName = attribute.value;
        continue;
      }
      const type = subjectAttributeByOid[attribute.oid];
      if (type === undefined) {
        return denial(
          "subject_not_permitted",
          "the subject has an unsupported attribute",
          { type: "subject", value: `${attribute.oid}=${attribute.value}` },
        );
      }
      subject.push({ type, value: attribute.value });
    }
  } else {
    sans = {
      dns: [...(explicit?.sans?.dns ?? [])],
      ip: [...(explicit?.sans?.ip ?? [])],
      uri: [...(explicit?.sans?.uri ?? [])],
    };
    const given = explicit?.subject ?? {};
    commonName = given.commonName;
    for (const type of [
      "country",
      "state",
      "locality",
      "organization",
      "organizationalUnit",
    ] as const) {
      const value = given[type];
      if (value !== undefined) {
        subject.push({ type, value });
      }
    }
  }

  let usages = [...input.usages];
  if (usages.length === 0) {
    for (const usage of parsed.keyUsage ?? []) {
      if (usage !== "digitalSignature" && usage !== "keyEncipherment") {
        return denial(
          "key_usage_not_permitted",
          `usage "${usage}" is not supported`,
        );
      }
      usages.push(usage);
    }
    for (const oid of parsed.extendedKeyUsage ?? []) {
      if (oid === EKU.serverAuth) {
        usages.push("serverAuth");
      } else if (oid === EKU.clientAuth) {
        usages.push("clientAuth");
      } else {
        return denial(
          "extended_key_usage_not_permitted",
          "the CSR requests an unsupported extended key usage",
        );
      }
    }
  }
  usages = [...new Set(usages)];

  return {
    ok: true,
    request: {
      source,
      keyAlgorithm: parsed.keyAlgorithm,
      sans,
      ...(commonName === undefined ? {} : { commonName }),
      subject,
      usages,
      ...(input.durationSeconds === undefined
        ? {}
        : { durationSeconds: input.durationSeconds }),
      isCA: input.isCA === true || parsed.basicConstraints?.ca === true,
    },
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Plan to certificate
// ---------------------------------------------------------------------------------------------------------------------

/** X.509 times are whole seconds; the engine carries milliseconds. */
export const floorToSecond = (date: Date): Date =>
  new Date(Math.floor(date.getTime() / 1000) * 1000);

const oidOfSubject: Record<SubjectEntry["type"], string> = {
  country: SUBJECT_OID.C,
  state: SUBJECT_OID.ST,
  locality: SUBJECT_OID.L,
  organization: SUBJECT_OID.O,
  organizationalUnit: SUBJECT_OID.OU,
  commonName: SUBJECT_OID.CN,
};

export const planSubjectDer = (plan: IssuancePlan): Buffer =>
  encodeName(
    plan.subject.map((entry) => ({
      oid: oidOfSubject[entry.type],
      value: entry.value,
      kind: entry.type === "country" ? ("printable" as const) : ("utf8" as const),
    })),
  );

export interface LeafToSign {
  readonly serial: Buffer;
  readonly serialHex: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly subjectDer: Buffer;
  readonly tbs: Buffer;
  readonly signatureAlgorithm: Buffer;
}

/** The TBSCertificate for a plan; throws `certificate_too_large` over 15,360 bytes. */
export const buildLeafToSign = (
  plan: IssuancePlan,
  caCert: ParsedCertificate,
  spkiDer: Buffer,
): LeafToSign => {
  const serial = generateSerial();
  const notBefore = floorToSecond(plan.notBefore);
  const notAfter = floorToSecond(plan.notAfter);
  const subjectDer = planSubjectDer(plan);
  const built = buildLeafTbs({
    issuer: caCert,
    serial,
    notBefore,
    notAfter,
    subjectDer,
    spkiDer,
    keyUsage: plan.keyUsages,
    extendedKeyUsage: ekuNamesToOids(plan.extendedKeyUsages),
    san: plan.sans,
    subjectEmpty: plan.subject.length === 0,
    ...(plan.certificatePolicies.length === 0
      ? {}
      : { policies: plan.certificatePolicies }),
  });
  if (built.tbs.length > MAX_TBS_BYTES) {
    throw issuanceDenied("certificate_too_large");
  }
  return {
    serial,
    serialHex: serial.toString("hex"),
    notBefore,
    notAfter,
    subjectDer,
    tbs: built.tbs,
    signatureAlgorithm: built.signatureAlgorithm,
  };
};

export const assembleLeaf = (
  built: LeafToSign,
  signature: Uint8Array,
): Buffer =>
  assembleCertificate(built.tbs, built.signatureAlgorithm, signature);

const selfCheckFailed = (field: string): never => {
  // The field name only: never the certificate.
  console.error("PKI issued certificate self-check failed", { field });
  throw serviceUnavailable("The generated certificate failed verification.");
};

const sameSet = (left: readonly string[], right: readonly string[]): boolean =>
  left.length === right.length &&
  [...left].sort().every((value, index) => value === [...right].sort()[index]);

/**
 * Re-parses the signed bytes and compares every field with what was planned. Any mismatch is a 503 that names the
 * field only. Returns the parsed certificate.
 */
export const assertLeafMatchesPlan = (
  der: Buffer,
  expected: {
    readonly built: LeafToSign;
    readonly plan: IssuancePlan;
    readonly caCert: ParsedCertificate;
    readonly spkiDer: Buffer;
  },
): ParsedCertificate => {
  const { built, plan, caCert, spkiDer } = expected;
  let leaf: ParsedCertificate;
  try {
    leaf = parseCertificate(der);
  } catch {
    return selfCheckFailed("parse");
  }
  if (der.length > MAX_CERTIFICATE_BYTES) {
    selfCheckFailed("size");
  }
  if (leaf.version !== 2) {
    selfCheckFailed("version");
  }
  if (!verifyCertificateSignature(leaf, caCert.spkiDer)) {
    selfCheckFailed("signature");
  }
  if (leaf.serialHex !== built.serialHex) {
    selfCheckFailed("serial");
  }
  if (!leaf.issuerDer.equals(caCert.subjectDer)) {
    selfCheckFailed("issuer");
  }
  if (!leaf.subjectDer.equals(built.subjectDer)) {
    selfCheckFailed("subject");
  }
  if (!leaf.spkiDer.equals(spkiDer)) {
    selfCheckFailed("spki");
  }
  if (
    leaf.notBefore.getTime() !== built.notBefore.getTime() ||
    leaf.notAfter.getTime() !== built.notAfter.getTime()
  ) {
    selfCheckFailed("validity");
  }
  if (leaf.basicConstraints?.critical !== true || leaf.basicConstraints.ca) {
    selfCheckFailed("basicConstraints");
  }
  if (
    leaf.keyUsageCritical !== true ||
    !sameSet(leaf.keyUsage ?? [], plan.keyUsages)
  ) {
    selfCheckFailed("keyUsage");
  }
  if (!sameSet(leaf.extendedKeyUsage ?? [], ekuNamesToOids(plan.extendedKeyUsages))) {
    selfCheckFailed("extendedKeyUsage");
  }
  const sanExtension = leaf.extensions.find(
    (extension) => extension.oid === EXT.subjectAltName,
  );
  const planned = plan.sans.dns.length + plan.sans.ip.length + plan.sans.uri.length;
  if (sanExtension === undefined) {
    if (planned > 0) {
      selfCheckFailed("subjectAltName");
    }
  } else {
    let decoded;
    try {
      decoded = decodeSubjectAltName(sanExtension.value);
    } catch {
      return selfCheckFailed("subjectAltName");
    }
    if (
      !sameSet(decoded.dns, plan.sans.dns) ||
      !sameSet(decoded.ip, plan.sans.ip) ||
      !sameSet(decoded.uri, plan.sans.uri) ||
      decoded.email.length > 0 ||
      decoded.unsupported.length > 0 ||
      sanExtension.critical !== (plan.subject.length === 0)
    ) {
      selfCheckFailed("subjectAltName");
    }
  }
  if (
    leaf.subjectKeyIdentifier === undefined ||
    !leaf.subjectKeyIdentifier.equals(keyIdentifierFromSpki(spkiDer))
  ) {
    selfCheckFailed("subjectKeyIdentifier");
  }
  if (
    leaf.authorityKeyIdentifier === undefined ||
    caCert.subjectKeyIdentifier === undefined ||
    !leaf.authorityKeyIdentifier.equals(caCert.subjectKeyIdentifier)
  ) {
    selfCheckFailed("authorityKeyIdentifier");
  }
  const policyExtension = leaf.extensions.find(
    (extension) => extension.oid === EXT.certificatePolicies,
  );
  let emitted: string[] = [];
  if (policyExtension !== undefined) {
    try {
      emitted = decodeCertificatePolicies(policyExtension.value);
    } catch {
      return selfCheckFailed("certificatePolicies");
    }
  }
  if (
    (policyExtension !== undefined) !== plan.certificatePolicies.length > 0 ||
    emitted.length !== plan.certificatePolicies.length ||
    emitted.some((oid, index) => oid !== plan.certificatePolicies[index])
  ) {
    selfCheckFailed("certificatePolicies");
  }
  if (leaf.unrecognizedCritical.length > 0) {
    selfCheckFailed("criticalExtensions");
  }
  return leaf;
};

// ---------------------------------------------------------------------------------------------------------------------
// Chain and responses
// ---------------------------------------------------------------------------------------------------------------------

export const pemBlocks = (pem: string): string[] =>
  (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (block) => `${block.trim()}\n`,
  );

/** `caPem` is the anchor (the last block of the stored chain); `chainPem` is the CA certificate plus its non-anchor ancestors. */
export const chainParts = (
  ca: Pick<CaRecord, "certificatePem" | "chainPem">,
): { chainPem: string; caPem: string } => {
  const blocks = pemBlocks(ca.chainPem ?? "");
  const anchor = blocks[blocks.length - 1];
  if (ca.certificatePem === undefined || anchor === undefined) {
    throw serviceUnavailable("The CA record is incomplete.");
  }
  return {
    chainPem: [ca.certificatePem.trim() + "\n", ...blocks.slice(0, -1)].join(""),
    caPem: anchor,
  };
};

export const issueResponse = (
  cert: Pick<
    IssuedCertificateRecord,
    | "caId"
    | "serial"
    | "fingerprint"
    | "certificatePem"
    | "notBefore"
    | "notAfter"
    | "lifetimeClamped"
  >,
  ca: Pick<CaRecord, "certificatePem" | "chainPem">,
  grantName?: string,
): Json => {
  const { chainPem, caPem } = chainParts(ca);
  return {
    caId: cert.caId,
    serial: cert.serial,
    fingerprint: cert.fingerprint,
    certificatePem: cert.certificatePem,
    chainPem,
    caPem,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    lifetimeClamped: cert.lifetimeClamped === true,
    ...(grantName === undefined ? {} : { issuanceGrant: grantName }),
  };
};

export const certificateFingerprint = (der: Uint8Array): string =>
  createHash("sha256").update(der).digest("hex");
