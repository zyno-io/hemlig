import { z } from "zod";
import { actor } from "./schemas";

/**
 * Wire shapes of the PKI administration routes (openapi/consumer-secrets.yaml
 * 0.8.0, `Pki*` components). The console mirrors the client's PKI types rather
 * than importing them: see packages/console/README.md. Enums use `z.enum`, so
 * an unknown value fails loudly instead of rendering as an unstyled string.
 */

// ---------------------------------------------------------------- CAs

export const pkiCaStatus = z.enum([
  "PENDING_CERTIFICATE",
  "ACTIVE",
  "RETIRED",
  "REVOKED",
  "FAILED",
]);
export type PkiCaStatus = z.infer<typeof pkiCaStatus>;

export const pkiKeyState = z.enum(["ACTIVE", "DISABLED", "DESTROYED"]);
export type PkiKeyState = z.infer<typeof pkiKeyState>;

export const pkiCaKind = z.enum(["EXTERNAL_INTERMEDIATE", "ROOT", "INTERMEDIATE"]);
export type PkiCaKind = z.infer<typeof pkiCaKind>;

/** Algorithms a CA key can use (`PkiCreateCaRequest.keyAlgorithm`). */
export const pkiKeyAlgorithm = z.enum([
  "ECDSA_P256",
  "ECDSA_P384",
  "RSA_3072",
  "RSA_4096",
  "ED25519",
]);
export type PkiKeyAlgorithm = z.infer<typeof pkiKeyAlgorithm>;

/** Algorithms a leaf key can use. */
export const pkiLeafKeyAlgorithm = z.enum([
  "ECDSA_P256",
  "ECDSA_P384",
  "ECDSA_P521",
  "ED25519",
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "RSA_8192",
]);
export type PkiLeafKeyAlgorithm = z.infer<typeof pkiLeafKeyAlgorithm>;

export const pkiCrlState = z.enum(["MISSING", "CURRENT", "STALE"]);
export type PkiCrlState = z.infer<typeof pkiCrlState>;

const pkiEku = z.enum(["serverAuth", "clientAuth"]);

export const pkiCaSubject = z.object({
  commonName: z.string(),
  organization: z.string().optional(),
  organizationalUnit: z.string().optional(),
  country: z.string().optional(),
  locality: z.string().optional(),
  state: z.string().optional(),
});
export type PkiCaSubject = z.infer<typeof pkiCaSubject>;

export const pkiNameSubtrees = z.object({
  dns: z.array(z.string()).optional(),
  ip: z.array(z.string()).optional(),
  uri: z.array(z.string()).optional(),
});
export type PkiNameSubtrees = z.infer<typeof pkiNameSubtrees>;

export const pkiRequestedConstraints = z.object({
  nameConstraints: z
    .object({
      permitted: pkiNameSubtrees.optional(),
      excluded: pkiNameSubtrees.optional(),
    })
    .optional(),
  extendedKeyUsages: z.array(pkiEku).optional(),
});
export type PkiRequestedConstraints = z.infer<typeof pkiRequestedConstraints>;

export const pkiCaPolicy = z.object({
  issueLeaves: z.boolean(),
  issueSubordinates: z.boolean(),
  maxLeafLifetimeSeconds: z.number().int(),
  leafKeyAlgorithms: z.array(z.string()),
  capacity: z.number().int(),
  issuancePerHour: z.number().int(),
  crlValiditySeconds: z.number().int(),
});
export type PkiCaPolicy = z.infer<typeof pkiCaPolicy>;

export const pkiCrlView = z.object({
  number: z.number().int(),
  thisUpdate: z.string(),
  nextUpdate: z.string(),
  entryCount: z.number().int(),
  sha256: z.string(),
  revision: z.number().int(),
  pendingRevocations: z.number().int().min(0),
  dirtySince: z.string().optional(),
  state: pkiCrlState,
});
export type PkiCrlView = z.infer<typeof pkiCrlView>;

export const pkiRootCrlView = z.object({
  extId: z.string(),
  state: pkiCrlState,
  numberHex: z.string().optional(),
  thisUpdate: z.string().optional(),
  nextUpdate: z.string().optional(),
});
export type PkiRootCrlView = z.infer<typeof pkiRootCrlView>;

export const pkiCaCapacityView = z.object({
  count: z.number().int().min(0).optional(),
  capacity: z.number().int(),
  issuancePerHour: z.number().int(),
  countedAt: z.string().optional(),
  countFrom: z.string().optional(),
});
export type PkiCaCapacityView = z.infer<typeof pkiCaCapacityView>;

export const pkiWarning = z.object({ code: z.string(), message: z.string() });
export type PkiWarning = z.infer<typeof pkiWarning>;

export const pkiCaSummary = z.object({
  caId: z.string(),
  environment: z.string(),
  name: z.string(),
  displayName: z.string().optional(),
  kind: pkiCaKind,
  status: pkiCaStatus,
  version: z.string(),
  keyAlgorithm: pkiKeyAlgorithm,
  keyState: pkiKeyState,
  fingerprint: z.string().optional(),
  notAfter: z.string().optional(),
  createdAt: z.string(),
});
export type PkiCaSummary = z.infer<typeof pkiCaSummary>;

export const pkiCaDetail = pkiCaSummary.extend({
  key: z.object({
    custody: z.string(),
    algorithm: z.string(),
    spkiSha256: z.string(),
    state: pkiKeyState,
  }),
  subject: pkiCaSubject,
  subjectDn: z.string(),
  requestedConstraints: pkiRequestedConstraints,
  // Passthrough: EKUs outside serverAuth/clientAuth appear as OIDs.
  effectiveConstraints: z.object({}).passthrough().optional(),
  acceptBroaderConstraints: z.boolean().optional(),
  csrPem: z.string().optional(),
  certificatePem: z.string().optional(),
  chainPem: z.string().optional(),
  serial: z.string().optional(),
  notBefore: z.string().optional(),
  parent: z
    .object({
      type: z.enum(["ca", "external"]),
      id: z.string(),
    })
    .optional(),
  parentCaId: z.string().optional(),
  crlIssuers: z.array(
    z.object({ type: z.enum(["ca", "external"]), id: z.string() }),
  ),
  policy: pkiCaPolicy,
  maxIssueLifetimeEverSeconds: z.number().int(),
  createdBy: actor,
  activatedAt: z.string().optional(),
  retiredAt: z.string().optional(),
  revokedAt: z.string().optional(),
  revocationReason: z.string().optional(),
  revocationSource: z.enum(["EXTERNAL", "HEMLIG"]).optional(),
  revocationEvidence: z.string().optional(),
  drained: z.boolean(),
  drainAt: z.string().optional(),
  capacity: pkiCaCapacityView.optional(),
  crl: pkiCrlView.optional(),
  rootCrl: pkiRootCrlView.optional(),
  warnings: z.array(pkiWarning).optional(),
});
export type PkiCaDetail = z.infer<typeof pkiCaDetail>;

/** `csrPem` is present for `EXTERNAL_INTERMEDIATE` only. */
export const pkiCreateCaResponse = pkiCaDetail;
export type PkiCreateCaResponse = PkiCaDetail;

export const pkiCaListPage = z.object({
  cas: z.array(pkiCaSummary),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});
export type PkiCaListPage = z.infer<typeof pkiCaListPage>;

export const pkiCrlPublishResponse = z.object({
  caId: z.string(),
  crl: pkiCrlView,
});
export type PkiCrlPublishResponse = z.infer<typeof pkiCrlPublishResponse>;

// ------------------------------------------------------- External CAs

export const pkiExternalCaCrlPointer = z.object({
  numberHex: z.string().optional(),
  thisUpdate: z.string().optional(),
  nextUpdate: z.string().optional(),
  sha256: z.string().optional(),
  uploadedAt: z.string().optional(),
});
export type PkiExternalCaCrlPointer = z.infer<typeof pkiExternalCaCrlPointer>;

export const pkiExternalCaSummary = z.object({
  extId: z.string(),
  fingerprint: z.string(),
  spkiSha256: z.string(),
  subjectDn: z.string(),
  subjectKeyIdentifier: z.string(),
  notAfter: z.string(),
  dependents: z.array(z.string()),
  environments: z.array(z.string()),
  version: z.string(),
  createdAt: z.string(),
  crl: pkiExternalCaCrlPointer.optional(),
  crlState: pkiCrlState,
});
export type PkiExternalCaSummary = z.infer<typeof pkiExternalCaSummary>;

export const pkiExternalCaListPage = z.object({
  externalCas: z.array(pkiExternalCaSummary),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});
export type PkiExternalCaListPage = z.infer<typeof pkiExternalCaListPage>;

export const pkiUploadCrlResponse = z.object({
  extId: z.string(),
  crl: z.record(z.unknown()).optional(),
  changed: z.boolean(),
  revokedCaIds: z.array(z.string()),
});
export type PkiUploadCrlResponse = z.infer<typeof pkiUploadCrlResponse>;

// ------------------------------------------------------------- Grants

const ruleList = z
  .object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  })
  .strict();

/**
 * Mirrors `PkiGrantPolicyFields` with every object strict. The editor parses a
 * stored policy with this to decide whether it can be edited losslessly: a
 * `PUT` replaces the whole grant, so a field this form cannot represent would
 * be destroyed by a save.
 */
export const pkiGrantPolicyStrict = z
  .object({
    names: z
      .object({
        dns: z
          .object({
            allow: z.array(z.string()).optional(),
            deny: z.array(z.string()).optional(),
            allowWildcardNames: z.boolean().optional(),
          })
          .strict()
          .optional(),
        ip: ruleList.optional(),
        uri: ruleList.optional(),
        commonName: z
          .object({
            mode: z.enum(["san", "forbid"]).optional(),
            addToSans: z.boolean().optional(),
          })
          .strict()
          .optional(),
        maxSans: z.number().int().min(1).max(100).optional(),
      })
      .strict(),
    subject: z
      .object({
        allow: z
          .object({
            country: z.array(z.string()).optional(),
            state: z.array(z.string()).optional(),
            locality: z.array(z.string()).optional(),
            organization: z.array(z.string()).optional(),
            organizationalUnit: z.array(z.string()).optional(),
          })
          .strict()
          .optional(),
      })
      .strict()
      .optional(),
    keyAlgorithms: z.array(pkiLeafKeyAlgorithm).optional(),
    keyUsages: z.array(z.enum(["digitalSignature", "keyEncipherment"])),
    extendedKeyUsages: z
      .object({
        allow: z.array(pkiEku).optional(),
        default: z.array(pkiEku).optional(),
      })
      .strict(),
    lifetime: z
      .object({
        defaultSeconds: z.number().int().min(1),
        maxSeconds: z.number().int().min(1),
        minSeconds: z.number().int().min(1).optional(),
      })
      .strict(),
    forced: z
      .object({
        subject: z
          .object({
            country: z.string().optional(),
            state: z.string().optional(),
            locality: z.string().optional(),
            organization: z.string().optional(),
            organizationalUnit: z.string().optional(),
          })
          .strict()
          .optional(),
        sans: z
          .object({
            dns: z.array(z.string()).optional(),
            ip: z.array(z.string()).optional(),
            uri: z.array(z.string()).optional(),
          })
          .strict()
          .optional(),
        certificatePolicies: z.array(z.string()).optional(),
      })
      .strict()
      .optional(),
    quotas: z
      .object({
        perHour: z.number().int().min(1).max(1_000_000).optional(),
        perDay: z.number().int().min(1).max(1_000_000).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();
export type PkiGrantPolicyStrict = z.infer<typeof pkiGrantPolicyStrict>;

export const pkiGrantIssue = z.object({
  code: z.string(),
  path: z.string(),
  message: z.string(),
});
export type PkiGrantIssue = z.infer<typeof pkiGrantIssue>;

export const pkiIssuanceGrant = z.object({
  consumerId: z.string(),
  environment: z.string(),
  name: z.string(),
  uid: z.string(),
  caId: z.string(),
  status: z.enum(["ACTIVE", "DISABLED", "DELETED"]),
  expired: z.boolean(),
  displayName: z.string().optional(),
  expiresAt: z.string().optional(),
  // Loose on purpose: a future policy field must not break the lists. The
  // editor re-parses with `pkiGrantPolicyStrict`.
  policy: z.record(z.unknown()),
  policyDigest: z.string(),
  quotas: z.object({ perHour: z.number().int(), perDay: z.number().int() }),
  version: z.string(),
  createdAt: z.string(),
  createdBy: actor,
  updatedAt: z.string(),
  updatedBy: actor,
  deletedAt: z.string().optional(),
  deletedBy: actor.optional(),
  warnings: z.array(pkiGrantIssue).optional(),
});
export type PkiIssuanceGrant = z.infer<typeof pkiIssuanceGrant>;

export const pkiIssuanceGrantListPage = z.object({
  grants: z.array(pkiIssuanceGrant),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});
export type PkiIssuanceGrantListPage = z.infer<typeof pkiIssuanceGrantListPage>;

export const pkiGrantValidationResult = z.object({
  valid: z.boolean(),
  errors: z.array(pkiGrantIssue),
  warnings: z.array(pkiGrantIssue),
  policyDigest: z.string().optional(),
});
export type PkiGrantValidationResult = z.infer<typeof pkiGrantValidationResult>;

// ----------------------------------------------------------- Evaluate

export const pkiTraceStep = z.object({
  step: z.number().int(),
  name: z.string(),
  outcome: z.string(),
  detail: z.string().optional(),
});
export type PkiTraceStep = z.infer<typeof pkiTraceStep>;

const sanLists = z.object({
  dns: z.array(z.string()).optional(),
  ip: z.array(z.string()).optional(),
  uri: z.array(z.string()).optional(),
});

export const pkiIssuancePlan = z.object({
  keyAlgorithm: z.string(),
  sans: sanLists,
  subject: z.string(),
  keyUsages: z.array(z.string()),
  extendedKeyUsages: z.array(z.string()),
  certificatePolicies: z.array(z.string()),
  notBefore: z.string(),
  notAfter: z.string(),
  lifetimeClamped: z.boolean(),
  sanCritical: z.boolean(),
});
export type PkiIssuancePlan = z.infer<typeof pkiIssuancePlan>;

const quotaUse = z.object({ count: z.number().int(), limit: z.number().int() });

export const pkiEvaluateResponse = z.object({
  decision: z.enum(["allow", "deny"]),
  denial: z
    .object({
      reason: z.string(),
      detail: z.string(),
      deniedNameType: z
        .enum(["dns", "ip", "uri", "commonName", "subject"])
        .optional(),
      deniedName: z.string().optional(),
    })
    .optional(),
  trace: z.array(pkiTraceStep),
  plan: pkiIssuancePlan.optional(),
  context: z.object({
    grant: z.object({
      status: z.enum(["ACTIVE", "DISABLED"]),
      expired: z.boolean(),
    }),
    ca: z.object({ status: z.string(), keyState: z.string() }),
    capacity: z.object({
      count: z.number().int().optional(),
      capacity: z.number().int(),
      countedAt: z.string().optional(),
    }),
    quotas: z.object({
      grantHour: quotaUse,
      grantDay: quotaUse,
      caHour: quotaUse,
    }),
  }),
});
export type PkiEvaluateResponse = z.infer<typeof pkiEvaluateResponse>;

// ------------------------------------------------------- Certificates

const requesterKubernetes = z.object({
  namespace: z.string(),
  name: z.string(),
  uid: z.string(),
  certificateName: z.string().optional(),
  revision: z.string().optional(),
});

export const pkiCertificateRequester = z.object({
  type: z.enum(["consumer", "human"]),
  id: z.string(),
  consumerId: z.string().optional(),
  issuanceGrant: z
    .object({
      name: z.string().optional(),
      uid: z.string().optional(),
      version: z.string().optional(),
    })
    .optional(),
  asserted: z.object({ kubernetes: requesterKubernetes.optional() }).optional(),
});
export type PkiCertificateRequester = z.infer<typeof pkiCertificateRequester>;

export const pkiCertificateRevocation = z.object({
  at: z.string(),
  reason: z.string(),
  invalidityDate: z.string().optional(),
  upgradedAt: z.string().optional(),
  by: actor.optional(),
});
export type PkiCertificateRevocation = z.infer<typeof pkiCertificateRevocation>;

export const pkiCertificateSummary = z.object({
  caId: z.string(),
  serial: z.string(),
  status: z.enum(["ISSUED", "REVOKED", "EXPIRED", "CA_REVOKED"]),
  storedStatus: z.enum(["ISSUED", "REVOKED"]),
  fingerprint: z.string(),
  subject: z.string(),
  sans: sanLists,
  keyAlgorithm: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  issuedAt: z.string(),
  isCa: z.boolean().optional(),
  childCaId: z.string().optional(),
  requester: pkiCertificateRequester,
  revocation: pkiCertificateRevocation.optional(),
});
export type PkiCertificateSummary = z.infer<typeof pkiCertificateSummary>;

export const pkiCertificateDetail = pkiCertificateSummary.extend({
  certificatePem: z.string(),
  spkiSha256: z.string(),
  keyUsages: z.array(z.string()),
  extendedKeyUsages: z.array(z.string()),
  lifetimeClamped: z.boolean().optional(),
});
export type PkiCertificateDetail = z.infer<typeof pkiCertificateDetail>;

export const pkiCertificateListPage = z.object({
  certificates: z.array(pkiCertificateSummary),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});
export type PkiCertificateListPage = z.infer<typeof pkiCertificateListPage>;

export const pkiRevokeCertificateResponse = z.object({
  certificate: pkiCertificateDetail,
  crlEntry: z.boolean(),
  crlPublished: z.boolean(),
  crlNumber: z.number().int().optional(),
  changed: z.boolean(),
  crl: z.object({
    number: z.number().int(),
    pendingRevocations: z.number().int().min(0),
  }),
});
export type PkiRevokeCertificateResponse = z.infer<
  typeof pkiRevokeCertificateResponse
>;

export const pkiBulkRevokeResponse = z.object({
  consumerId: z.string(),
  issuanceGrant: z.string().optional(),
  complete: z.boolean(),
  revoked: z.number().int().min(0),
  alreadyRevoked: z.number().int().min(0),
  caIds: z.array(z.string()),
  crls: z.array(
    z.object({
      caId: z.string(),
      crlPublished: z.boolean(),
      crlNumber: z.number().int().optional(),
    }),
  ),
});
export type PkiBulkRevokeResponse = z.infer<typeof pkiBulkRevokeResponse>;

// ------------------------------------------------------ Request inputs

export type PkiLeafRevocationReason =
  | "unspecified"
  | "keyCompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "privilegeWithdrawn";

export interface PkiCaPolicyInput {
  maxLeafLifetimeSeconds?: number;
  leafKeyAlgorithms?: PkiLeafKeyAlgorithm[];
  capacity?: number;
  issuancePerHour?: number;
  crlValiditySeconds?: number;
}

export interface PkiCreateCaInput {
  environment: string;
  name: string;
  kind: PkiCaKind;
  keyAlgorithm: PkiKeyAlgorithm;
  subject: PkiCaSubject;
  parentCaId?: string;
  validitySeconds?: number;
  requestedConstraints?: PkiRequestedConstraints;
  policy?: PkiCaPolicyInput;
  crl?: { validitySeconds?: number };
  displayName?: string;
}

export interface PkiActivateCaInput {
  certificatePem: string;
  chainPem: string;
  /** PEM (`X509 CRL`) or base64 DER. */
  rootCrl?: string;
  acceptBroaderConstraints?: boolean;
}

/** Policy fields of a grant plus its envelope (`PkiIssuanceGrantInput`). */
export interface PkiGrantInput {
  caId: string;
  displayName?: string;
  status?: "ACTIVE" | "DISABLED";
  expiresAt?: string;
  names: PkiGrantPolicyStrict["names"];
  subject?: PkiGrantPolicyStrict["subject"];
  keyAlgorithms?: PkiLeafKeyAlgorithm[];
  keyUsages: PkiGrantPolicyStrict["keyUsages"];
  extendedKeyUsages: PkiGrantPolicyStrict["extendedKeyUsages"];
  lifetime: PkiGrantPolicyStrict["lifetime"];
  forced?: PkiGrantPolicyStrict["forced"];
  quotas?: PkiGrantPolicyStrict["quotas"];
}

export interface PkiCreateGrantInput extends PkiGrantInput {
  name: string;
}

export interface PkiEvaluateInput {
  certificateSigningRequestPem?: string;
  keyAlgorithm?: PkiLeafKeyAlgorithm;
  sans?: { dns?: string[]; ip?: string[]; uri?: string[] };
  commonName?: string;
  subject?: {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    locality?: string;
    state?: string;
  };
  durationSeconds?: number;
  usages?: string[];
  isCA?: boolean;
}

export interface PkiBulkRevokeInput {
  reason?: PkiLeafRevocationReason;
  invalidityDate?: string;
  issuanceGrant?: string;
  issuanceGrantUid?: string;
}
