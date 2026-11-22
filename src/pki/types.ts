import type { Actor } from "../domain/types";

export type CaKind = "EXTERNAL_INTERMEDIATE" | "ROOT" | "INTERMEDIATE"; // v1 creates EXTERNAL_INTERMEDIATE only
export type CaStatus =
  "PENDING_CERTIFICATE" | "ACTIVE" | "RETIRED" | "REVOKED" | "FAILED";
export type IssuerRef =
  { type: "ca"; id: string } | { type: "external"; id: string }; // ca-... | ext-...
export type PkiKeyAlgorithm =
  "ECDSA_P256" | "ECDSA_P384" | "RSA_3072" | "RSA_4096" | "ED25519";
export type LeafKeyAlgorithm =
  | "ECDSA_P256"
  | "ECDSA_P384"
  | "ECDSA_P521"
  | "ED25519"
  | "RSA_2048"
  | "RSA_3072"
  | "RSA_4096"
  | "RSA_8192"; // P-521 and Ed25519 only when listed

export type RevocationReason =
  | "unspecified"
  | "keyCompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "privilegeWithdrawn"
  | "caCompromise"; // caCompromise: Phase 7, CA certificates only

export type KeyUsageName =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";

/**
 * One NameConstraints subtree base. `dns` is a domain (`example.com` permits the name and its subdomains), `ip` is a
 * CIDR (`10.0.0.0/8`, `fd00::/8`) and `uri` is a host (`example.com`).
 */
export interface NameConstraintEntry {
  readonly type: "dns" | "ip" | "uri";
  readonly value: string;
}

export interface NameConstraintSet {
  permitted: NameConstraintEntry[];
  excluded: NameConstraintEntry[];
}

/** Hemlig-built CA subject. Encoded in the order C, ST, L, O, OU, CN. */
export interface CaSubject {
  C?: string;
  ST?: string;
  L?: string;
  O?: string;
  OU?: string;
  CN: string;
}

export interface CaRecord {
  // PKI_CA#caId / PROFILE
  caId: string;
  environment: string;
  name: string;
  displayName?: string;
  kind: CaKind;
  status: CaStatus;
  version: string; // ETag, bumped by status and policy changes
  parent?: IssuerRef; // issuer of this CA's certificate; absent for a ROOT
  parentCaId?: string; // Hemlig parent (Phase 7)
  crlIssuers: IssuerRef[]; // [self, parent, ...]: the CRL slots for this CA's leaves
  key: {
    custody: "WRAPPED";
    algorithm: PkiKeyAlgorithm;
    spkiSha256: string;
    state: "ACTIVE" | "DISABLED" | "DESTROYED";
    wrapped?: WrappedKey;
  };
  subject: CaSubject;
  subjectKey: string; // restricted form; registry hash
  requested: {
    pathLen: 0;
    nameConstraints?: NameConstraintSet;
    extendedKeyUsages?: string[];
  };
  acceptBroaderConstraints?: boolean;
  csrPem?: string;
  certificatePem?: string;
  chainPem?: string; // chain: ancestors up to and including the anchor
  serial?: string;
  fingerprint?: string;
  subjectDer?: string; // base64 DER: the byte-exact copy of the certificate's subject Name used as the CRL issuer
  subjectKeyIdentifier?: string; // lowercase hex
  notBefore?: string;
  notAfter?: string;
  effective?: {
    nameConstraints?: NameConstraintSet;
    extendedKeyUsages?: string[];
  };
  policy: {
    issueLeaves: boolean;
    issueSubordinates: boolean; // v1: true, false
    maxLeafLifetimeSeconds: number;
    leafKeyAlgorithms: LeafKeyAlgorithm[];
    capacity: number;
    issuancePerHour: number; // per-CA hourly issuance counter limit (the "rate")
    crlValiditySeconds: number;
  }; // 8,000; 2,000; 604,800
  maxIssueLifetimeEverSeconds: number; // monotone; sets the drain point
  createdAt: string;
  createdBy: Actor;
  retiredAt?: string;
  revokedAt?: string;
  revocationReason?: string;
  revocationSource?: "EXTERNAL" | "HEMLIG";
  revocationEvidence?: string;
  activatedAt?: string;
  failedAt?: string;
  drainedAt?: string;
  keyDestroyedAt?: string;
}

/** `key.wrapped`: the same shape as `IssuerKeyEnvelope`. */
export interface WrappedKey {
  algorithm: "AES-256-GCM";
  encryptedDataKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface CaCrlState {
  // PKI_CA#caId / CRL
  revision: number;
  lastNumber: number;
  dirtySince?: string;
  lease?: { owner: string; expiresAt: string };
  published?: {
    number: number;
    objectKey: string;
    sha256: string;
    thisUpdate: string;
    nextUpdate: string;
    revision: number;
    entryCount: number;
    dropDueAt?: string;
  };
  /** `published.thisUpdate` whose TTL sweep of expired carried revocations completed. */
  sweptThrough?: string;
  capacity?: { count: number; countFrom: string; countedAt: string };
}

export interface ExternalCaRecord {
  // PKI_EXTCA#extId / PROFILE; extId = "ext-" + first 40 hex of sha256(canonical SPKI)
  extId: string;
  certificatePem: string;
  fingerprint: string;
  spkiSha256: string;
  subjectDer: string; // base64 DER
  subjectAttributes: { oid: string; value: string }[];
  subjectKey: string;
  subjectKeyIdentifier: string; // lowercase hex
  notAfter: string;
  createdAt: string;
  dependents: Set<string>;
  environments: Set<string>;
  version: string;
  crl?: {
    numberHex: string;
    thisUpdate: string;
    nextUpdate: string;
    sha256: string;
    objectKey: string;
    uploadedAt: string;
    uploadedBy: Actor;
  }; // numberHex: 40 hex digits, zero-padded
}

/** PKI_CA#caId / REVOKED#serial. Written by Phase 4; read by Phase 3. */
export interface RevocationEntryRecord {
  caId: string;
  serial: string;
  revokedAt: string;
  reason: RevocationReason;
  invalidityDate?: string;
  notAfter: string;
  ttl?: number;
}

export interface IssuedCertificateRecord {
  // PKI_CERT#caId#serial / PROFILE
  caId: string;
  environment: string;
  serial: string;
  status: "ISSUED" | "REVOKED";
  certificatePem: string;
  fingerprint: string;
  spkiSha256: string;
  subject: string;
  sans: { dns: string[]; ip: string[]; uri: string[] };
  keyAlgorithm: string;
  keyUsages: string[];
  extendedKeyUsages: string[];
  isCa: boolean;
  childCaId?: string; // CA certificates, Phase 7
  notBefore: string;
  notAfter: string;
  issuedAt: string;
  requester: {
    type: "consumer" | "human";
    id: string;
    consumerId?: string;
    issuanceGrant?: { name: string; uid: string; version: string };
    asserted?: {
      kubernetes?: {
        namespace: string;
        name: string;
        uid: string;
        certificateName?: string;
        revision?: string;
      };
    };
  };
  revocation?: {
    at: string;
    reason: RevocationReason;
    invalidityDate?: string;
    by: Actor;
  };
}

export interface ReplayRecord {
  // PKI_IDEMPOTENCY#consumerId / REQUEST#key
  requestDigest: string;
  caId: string;
  serial: string;
  notAfter: string;
  grantUid: string;
}
