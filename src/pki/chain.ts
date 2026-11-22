import { parseCidr, type IpNetwork } from "./asn1/names";
import { DerError } from "./asn1/der";
import { fromPem, PemError } from "./asn1/pem";
import {
  parseCertificate,
  policyExtensions,
  verifyCertificateSignature,
  type ParsedCertificate,
} from "./asn1/certificate";
import { EKU } from "./asn1/extensions";
import { chainInvalid } from "./errors";
import {
  matchesIdentityRoot,
  parseRestrictedName,
  SubjectError,
  type IdentityRootReference,
  type RestrictedName,
} from "./subject";
import type { CaRecord, NameConstraintEntry, NameConstraintSet } from "./types";

const day = 24 * 60 * 60 * 1000;
export const minimumCaValidityDays = 30;
const maximumCertificateBytes = 32_768;

// ---------------------------------------------------------------------------------------------------------------------
// Constraint subset logic
// ---------------------------------------------------------------------------------------------------------------------

/** True when `inner` (a subtree base) lies inside `outer`. Both are the same type. */
const covers = (
  outer: NameConstraintEntry,
  inner: NameConstraintEntry,
): boolean => {
  if (outer.type !== inner.type) {
    return false;
  }
  if (outer.type === "ip") {
    let outerNet: IpNetwork;
    let innerNet: IpNetwork;
    try {
      outerNet = parseCidr(outer.value);
      innerNet = parseCidr(inner.value);
    } catch {
      return false;
    }
    if (
      outerNet.address.length !== innerNet.address.length ||
      outerNet.prefix > innerNet.prefix
    ) {
      return false;
    }
    for (let bit = 0; bit < outerNet.prefix; bit += 1) {
      const mask = 0x80 >> (bit & 7);
      if (
        ((outerNet.address[bit >> 3] as number) & mask) !==
        ((innerNet.address[bit >> 3] as number) & mask)
      ) {
        return false;
      }
    }
    return true;
  }
  if (outer.type === "uri") {
    // RFC 5280 4.2.1.10 (and OpenSSL's nc_uri): a base without a leading dot is exactly that host; with a leading
    // dot it is every strictly subordinate host.
    const outerHost = outer.value.toLowerCase();
    const innerHost = inner.value.toLowerCase();
    if (!outerHost.startsWith(".")) {
      return innerHost === outerHost;
    }
    return innerHost.startsWith(".")
      ? innerHost === outerHost || innerHost.endsWith(outerHost)
      : innerHost.endsWith(outerHost);
  }
  // dns bases are hosts. `example.com` permits itself and every subdomain; `.example.com` only subdomains.
  const outerValue = outer.value.toLowerCase();
  const innerValue = inner.value.toLowerCase();
  const outerBare = outerValue.replace(/^\./, "");
  const innerBare = innerValue.replace(/^\./, "");
  const innerDotted = innerValue.startsWith(".");
  if (outerValue.startsWith(".")) {
    return (
      innerBare.endsWith(`.${outerBare}`) ||
      (innerBare === outerBare && innerDotted)
    );
  }
  return innerBare === outerBare || innerBare.endsWith(`.${outerBare}`);
};

const ofType = (
  entries: readonly NameConstraintEntry[],
  type: NameConstraintEntry["type"],
): NameConstraintEntry[] => entries.filter((entry) => entry.type === type);

/**
 * True when `actual` is no broader than `requested`: for every type the request permits, the certificate permits
 * only subtrees inside the request's (and permits something), and every requested exclusion is excluded too.
 */
export const nameConstraintsWithin = (
  actual: NameConstraintSet | undefined,
  requested: NameConstraintSet | undefined,
): boolean => {
  if (requested === undefined) {
    return true;
  }
  for (const type of ["dns", "ip", "uri"] as const) {
    const wanted = ofType(requested.permitted, type);
    if (wanted.length > 0) {
      const granted = ofType(actual?.permitted ?? [], type);
      if (
        granted.length === 0 ||
        !granted.every((entry) => wanted.some((outer) => covers(outer, entry)))
      ) {
        return false;
      }
    }
  }
  return requested.excluded.every((entry) =>
    (actual?.excluded ?? []).some((outer) => covers(outer, entry)),
  );
};

/** True when `actual` EKU is no broader than `requested`. A missing certificate EKU is broader than any request. */
export const extendedKeyUsageWithin = (
  actual: readonly string[] | undefined,
  requested: readonly string[] | undefined,
): boolean => {
  if (requested === undefined) {
    return true;
  }
  if (actual === undefined) {
    return false;
  }
  return actual.every(
    (usage) => requested.includes(usage) || requested.includes(EKU.any),
  );
};

const intersectExtendedKeyUsage = (
  left: readonly string[] | undefined,
  right: readonly string[] | undefined,
): string[] | undefined => {
  if (left === undefined || left.includes(EKU.any)) {
    return right === undefined ? undefined : [...right];
  }
  if (right === undefined || right.includes(EKU.any)) {
    return [...left];
  }
  return left.filter((usage) => right.includes(usage));
};

// ---------------------------------------------------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------------------------------------------------

export interface ActivationInput {
  readonly certificatePem: string;
  /** The self-signed root: exactly one certificate. */
  readonly chainPem: string;
  readonly now: Date;
  /** SPKI DER of the CA key Hemlig holds. */
  readonly caSpkiDer: Uint8Array;
  /** Registry key of the subject Hemlig requested. */
  readonly requestedSubjectKey: string;
  readonly requested: CaRecord["requested"];
  readonly acceptBroaderConstraints?: boolean;
  /** The deployment name used in the identity root's fixed subject (layer 6). */
  readonly deploymentName: string;
  readonly identity?: IdentityRootReference;
}

export interface ActivationResult {
  readonly certificate: ParsedCertificate;
  readonly root: ParsedCertificate;
  readonly certificateSubject: RestrictedName;
  readonly rootSubject: RestrictedName;
  /** Constraints in force for leaves: the CA certificate's, narrowed by the root's EKU. */
  readonly effective: {
    nameConstraints?: NameConstraintSet;
    extendedKeyUsages?: string[];
  };
  /** The certificate is broader than requested; it was accepted only because `acceptBroaderConstraints` is set. */
  readonly broaderThanRequested: boolean;
}

const loadCertificate = (pem: string, reason: string): ParsedCertificate => {
  try {
    return parseCertificate(
      fromPem(pem, "CERTIFICATE", maximumCertificateBytes),
    );
  } catch (error) {
    if (error instanceof PemError && error.reason === "multiple_blocks") {
      throw chainInvalid(`${reason}_multiple_blocks`);
    }
    if (error instanceof PemError || error instanceof DerError) {
      throw chainInvalid(`${reason}_malformed`);
    }
    throw error;
  }
};

const restricted = (der: Uint8Array, reason: string): RestrictedName => {
  try {
    return parseRestrictedName(der, "external");
  } catch (error) {
    if (error instanceof SubjectError) {
      throw chainInvalid(reason);
    }
    throw error;
  }
};

const assertNoPolicyExtensions = (certificate: ParsedCertificate): void => {
  if (
    certificate.extensions.some((extension) =>
      policyExtensions.includes(extension.oid),
    )
  ) {
    throw chainInvalid("policy_extension_present");
  }
  if (certificate.unrecognizedCritical.length > 0) {
    throw chainInvalid("unrecognized_critical_extension");
  }
};

/**
 * The checks of "Activation" (items 1 to 6) on the returned certificate and its one-certificate chain. Item 7, the
 * root CRL, is `crl-verify.ts`. Throws `400 chain_invalid` with a `safeReason`.
 */
export const verifyActivationChain = (
  input: ActivationInput,
): ActivationResult => {
  const root = loadCertificate(input.chainPem, "chain");
  const certificate = loadCertificate(input.certificatePem, "certificate");
  const now = input.now.getTime();

  // 1. The chain is exactly one self-signed root.
  const rootSubject = restricted(root.subjectDer, "issuer_name_unsupported");
  const rootIssuer = restricted(root.issuerDer, "issuer_name_unsupported");
  if (rootSubject.key !== rootIssuer.key) {
    throw chainInvalid("root_not_self_signed");
  }
  if (!verifyCertificateSignature(root, root.spkiDer)) {
    throw chainInvalid("root_signature_invalid");
  }
  if (now < root.notBefore.getTime() || now > root.notAfter.getTime()) {
    throw chainInvalid("root_not_valid");
  }
  if (root.version !== 2 || root.basicConstraints?.ca !== true) {
    throw chainInvalid("root_not_ca");
  }
  if (!root.basicConstraints.critical) {
    throw chainInvalid("root_basic_constraints_not_critical");
  }
  if (
    root.keyUsage === undefined ||
    !root.keyUsage.includes("keyCertSign") ||
    !root.keyUsage.includes("cRLSign")
  ) {
    throw chainInvalid("root_key_usage");
  }
  if (root.subjectKeyIdentifier === undefined) {
    throw chainInvalid("root_missing_ski");
  }
  // No leaf could validate under an intermediate below a root that allows no CAs beneath it.
  if (
    root.basicConstraints.pathLen !== undefined &&
    root.basicConstraints.pathLen < 1
  ) {
    throw chainInvalid("root_path_len");
  }
  if (root.nameConstraints !== undefined) {
    throw chainInvalid("root_name_constraints_unsupported");
  }

  // 2. The CA certificate verifies under the root and is bound to it and to Hemlig's key.
  const issuer = restricted(certificate.issuerDer, "issuer_name_unsupported");
  if (issuer.key !== rootSubject.key) {
    throw chainInvalid("issuer_mismatch");
  }
  if (!verifyCertificateSignature(certificate, root.spkiDer)) {
    throw chainInvalid("signature_invalid");
  }
  // AKI is required (as under -x509_strict) and must be the root's SKI.
  if (certificate.authorityKeyIdentifier === undefined) {
    throw chainInvalid("missing_aki");
  }
  if (!certificate.authorityKeyIdentifier.equals(root.subjectKeyIdentifier)) {
    throw chainInvalid("aki_mismatch");
  }
  // authorityCertIssuer and authorityCertSerialNumber, when present, must name the root certificate.
  if (
    certificate.authorityCertSerialHex !== undefined &&
    certificate.authorityCertSerialHex !== root.serialHex
  ) {
    throw chainInvalid("aki_mismatch");
  }
  if (certificate.authorityCertIssuer !== undefined) {
    const names = certificate.authorityCertIssuer;
    const matches =
      names.length > 0 &&
      names.every((name) => {
        if (name.tag !== 0xa4) {
          return false;
        }
        try {
          return (
            parseRestrictedName(name.value, "external").key === rootSubject.key
          );
        } catch {
          return false;
        }
      });
    if (!matches) {
      throw chainInvalid("aki_mismatch");
    }
  }
  if (!certificate.spkiDer.equals(Buffer.from(input.caSpkiDer))) {
    throw chainInvalid("spki_mismatch");
  }
  if (certificate.subjectKeyIdentifier === undefined) {
    throw chainInvalid("missing_ski");
  }

  // 3. CA basics and remaining validity.
  if (certificate.version !== 2 || certificate.basicConstraints?.ca !== true) {
    throw chainInvalid("not_ca");
  }
  if (!certificate.basicConstraints.critical) {
    throw chainInvalid("basic_constraints_not_critical");
  }
  if (
    certificate.keyUsage === undefined ||
    !certificate.keyUsage.includes("keyCertSign") ||
    !certificate.keyUsage.includes("cRLSign")
  ) {
    throw chainInvalid("key_usage");
  }
  if (now < certificate.notBefore.getTime()) {
    throw chainInvalid("not_yet_valid");
  }
  if (certificate.notAfter.getTime() - now < minimumCaValidityDays * day) {
    throw chainInvalid("validity_too_short");
  }

  // 4. Subject and constraints.
  const certificateSubject = restricted(
    certificate.subjectDer,
    "ca_subject_unsupported",
  );
  if (certificateSubject.key !== input.requestedSubjectKey) {
    throw chainInvalid("subject_mismatch");
  }
  if (certificate.nameConstraintsUnsupported) {
    throw chainInvalid("unsupported_name_constraint");
  }
  const broader =
    certificate.basicConstraints.pathLen === undefined ||
    certificate.basicConstraints.pathLen > input.requested.pathLen ||
    !nameConstraintsWithin(
      certificate.nameConstraints,
      input.requested.nameConstraints,
    ) ||
    !extendedKeyUsageWithin(
      certificate.extendedKeyUsage,
      input.requested.extendedKeyUsages,
    );
  if (broader && input.acceptBroaderConstraints !== true) {
    throw chainInvalid("constraints_broader");
  }

  // 5. Policy extensions and unknown critical extensions.
  assertNoPolicyExtensions(root);
  assertNoPolicyExtensions(certificate);

  // 6. The identity root never appears in a PKI chain.
  for (const candidate of [
    {
      subjectKey: rootSubject.key,
      spkiSha256: root.spkiSha256,
      fingerprint: root.fingerprint,
    },
    {
      subjectKey: certificateSubject.key,
      spkiSha256: certificate.spkiSha256,
      fingerprint: certificate.fingerprint,
    },
  ]) {
    if (matchesIdentityRoot(candidate, input.deploymentName, input.identity)) {
      throw chainInvalid("identity_root_reserved");
    }
  }

  const nameConstraints =
    certificate.nameConstraints !== undefined &&
    certificate.nameConstraints.permitted.length +
      certificate.nameConstraints.excluded.length >
      0
      ? certificate.nameConstraints
      : undefined;
  const extendedKeyUsages = intersectExtendedKeyUsage(
    certificate.extendedKeyUsage,
    root.extendedKeyUsage,
  );
  return {
    certificate,
    root,
    certificateSubject,
    rootSubject,
    effective: {
      ...(nameConstraints === undefined ? {} : { nameConstraints }),
      ...(extendedKeyUsages === undefined ? {} : { extendedKeyUsages }),
    },
    broaderThanRequested: broader,
  };
};

// ---------------------------------------------------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------------------------------------------------

export interface LeafValidityInput {
  readonly now: Date;
  /** The requested lifetime, or the default when none was requested. */
  readonly requestedSeconds: number;
  /** Ceilings that clamp the request: the grant's maximum, the CA's maximum and the global maximum. */
  readonly ceilingsSeconds: readonly number[];
  readonly caNotBefore: Date;
  /** `notAfter` of every certificate in the chain, the CA certificate included. */
  readonly chainNotAfters: readonly Date[];
}

export interface LeafValidity {
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly durationSeconds: number;
  /** The lifetime ended up shorter than requested. */
  readonly clamped: boolean;
  /** The chain's earliest `notAfter` is what limited it. */
  readonly limitedByChain: boolean;
}

export const earliestNotAfter = (
  certificates: readonly { readonly notAfter: Date }[],
): Date =>
  new Date(
    Math.min(
      ...certificates.map((certificate) => certificate.notAfter.getTime()),
    ),
  );

/**
 * `notBefore = max(now - 60 s, CA notBefore)` and `notAfter = min(notBefore + requested, notBefore + each ceiling,
 * earliest notAfter in the chain)`. Lifetimes are clamped, never denied: below-minimum checks belong to the policy.
 */
export const computeLeafValidity = (input: LeafValidityInput): LeafValidity => {
  const wholeSecond = (milliseconds: number): number =>
    Math.floor(milliseconds / 1000) * 1000;
  const notBefore = Math.max(
    wholeSecond(input.now.getTime()) - 60_000,
    wholeSecond(input.caNotBefore.getTime()),
  );
  const wanted = Math.min(input.requestedSeconds, ...input.ceilingsSeconds);
  const byDuration = notBefore + wanted * 1000;
  const chainLimit = Math.min(
    ...input.chainNotAfters.map((date) => date.getTime()),
  );
  const notAfter = Math.min(byDuration, chainLimit);
  return {
    notBefore: new Date(notBefore),
    notAfter: new Date(notAfter),
    durationSeconds: Math.floor((notAfter - notBefore) / 1000),
    clamped: notAfter < notBefore + input.requestedSeconds * 1000,
    limitedByChain: chainLimit < byDuration,
  };
};
