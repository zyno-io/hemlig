import { EzError } from "./ez-error";
import { assertRestrictedName, encodeSubject, type Subject } from "./ez-name";
import { EZ_DEFAULTS } from "./ez-profile";
import { signBatch, type RootSigner, type SignConfirmation, type SignEvents, type SignItem } from "./ez-signer";
import {
  assembleCertificate,
  assembleCrl,
  buildCrlTbs,
  buildIntermediateTbs,
  buildRootTbs,
  computeIntermediateValidity,
  DAY_MS,
  floorSeconds,
  selfCheckCertificate,
  selfCheckCrl,
  toPem,
  type CrlEntry,
  type IntermediateValidity,
  type IssuerReference,
  type ParsedCertificate,
  type ParsedCrl,
  type ValidatedCsr,
} from "./ez-x509";

/**
 * Prepare / sign / assemble. A `Prepared<T>` carries the exact bytes to sign and a function that builds the finished
 * artifact (assemble, then self-check) from the signature. A command prepares everything it needs, signs the whole
 * batch once (`signPrepared`), then finishes each artifact; nothing is released without passing `selfCheck*`.
 */
export interface Prepared<T> {
  readonly item: SignItem;
  finish(signature: Buffer): T;
}

export interface IssuedCertificate {
  readonly der: Buffer;
  readonly pem: string;
  readonly certificate: ParsedCertificate;
}

export interface IssuedCrl {
  readonly der: Buffer;
  readonly pem: string;
  readonly crl: ParsedCrl;
}

export const issuerReference = (root: ParsedCertificate): IssuerReference & { readonly spkiDer: Buffer } => {
  if (root.subjectKeyIdentifier === undefined) {
    throw new EzError(5, "root_profile_invalid", "The root certificate has no SubjectKeyIdentifier.", { reasons: ["root_missing_ski"] });
  }
  return { subjectDer: root.subjectDer, subjectKeyIdentifier: root.subjectKeyIdentifier, spkiDer: root.spkiDer };
};

/** I5: the signer must hold the root certificate's key before anything is signed. */
export const assertSignerMatchesRoot = (signer: RootSigner, root: { readonly spkiDer: Buffer }): void => {
  if (!signer.spkiDer.equals(root.spkiDer)) {
    throw new EzError(5, "key_mismatch", "The signing key is not the root certificate's key.");
  }
};

export interface PrepareRootOptions {
  readonly subject: Subject | Buffer;
  readonly now: Date;
  readonly validityDays?: number;
  /** An exact end date (re-issuing an adopted root keeps its original); wins over `validityDays`. */
  readonly notAfter?: Date;
  readonly pathLen?: number;
  /** Re-issuing an adopted root keeps its SKI. */
  readonly subjectKeyIdentifier?: Buffer;
  readonly serial?: Buffer;
}

export const prepareRoot = (signer: RootSigner, options: PrepareRootOptions): Prepared<IssuedCertificate> => {
  const now = floorSeconds(options.now);
  const subjectDer = Buffer.isBuffer(options.subject) ? options.subject : encodeSubject(options.subject);
  const built = buildRootTbs({
    subjectDer,
    spkiDer: signer.spkiDer,
    signatureAlgorithm: signer.signatureAlgorithm,
    notBefore: new Date(now.getTime() - EZ_DEFAULTS.backdateMs),
    notAfter: options.notAfter ?? new Date(now.getTime() + (options.validityDays ?? EZ_DEFAULTS.rootValidityDays) * DAY_MS),
    pathLen: options.pathLen,
    subjectKeyIdentifier: options.subjectKeyIdentifier,
    serial: options.serial,
  });
  return {
    item: { id: "root-certificate", description: `Self-signed root certificate, serial ${built.serialHex}`, data: built.tbs },
    finish: (signature) => {
      const der = assembleCertificate(built.tbs, built.algorithmIdentifier, signature);
      const certificate = selfCheckCertificate(der, signer.spkiDer, { kind: "root" });
      return { der, pem: toPem(der, "CERTIFICATE"), certificate };
    },
  };
};

export interface PrepareIntermediateOptions {
  readonly now: Date;
  readonly validityDays?: number;
  readonly minimumDays?: number;
  readonly serial?: Buffer;
  /** Pre-computed validity (so the journal records exactly what is signed); otherwise derived from `now`. */
  readonly validity?: IntermediateValidity;
}

export const prepareIntermediate = (
  signer: RootSigner,
  root: ParsedCertificate,
  csr: ValidatedCsr,
  options: PrepareIntermediateOptions,
): Prepared<IssuedCertificate> => {
  assertSignerMatchesRoot(signer, root);
  const issuer = issuerReference(root);
  if (assertRestrictedName(root.subjectDer, "external").key === csr.subject.key) {
    throw new EzError(5, "csr_subject_is_root", "The intermediate's subject must differ from the root's.");
  }
  const validity =
    options.validity ??
    computeIntermediateValidity({
      now: options.now,
      days: options.validityDays ?? EZ_DEFAULTS.intermediateValidityDays,
      root,
      minimumDays: options.minimumDays ?? EZ_DEFAULTS.intermediateMinimumDays,
    });
  const built = buildIntermediateTbs({
    root: issuer,
    csr,
    signatureAlgorithm: signer.signatureAlgorithm,
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    serial: options.serial,
  });
  return {
    item: {
      id: "intermediate-certificate",
      description: `Intermediate certificate, serial ${built.serialHex}, valid to ${validity.notAfter.toISOString()}`,
      data: built.tbs,
    },
    finish: (signature) => {
      const der = assembleCertificate(built.tbs, built.algorithmIdentifier, signature);
      const certificate = selfCheckCertificate(der, signer.spkiDer, {
        kind: "intermediate",
        issuerSubjectDer: root.subjectDer,
        issuerSki: issuer.subjectKeyIdentifier,
      });
      return { der, pem: toPem(der, "CERTIFICATE"), certificate };
    },
  };
};

export interface PrepareCrlOptions {
  readonly number: bigint | number;
  readonly thisUpdate: Date;
  readonly validityDays?: number;
  readonly entries: readonly CrlEntry[];
}

export const prepareCrl = (signer: RootSigner, root: ParsedCertificate, options: PrepareCrlOptions): Prepared<IssuedCrl> => {
  assertSignerMatchesRoot(signer, root);
  const issuer = issuerReference(root);
  const thisUpdate = floorSeconds(options.thisUpdate);
  const nextUpdate = new Date(thisUpdate.getTime() + (options.validityDays ?? EZ_DEFAULTS.crlValidityDays) * DAY_MS);
  const number = BigInt(options.number);
  const built = buildCrlTbs({ issuer, signatureAlgorithm: signer.signatureAlgorithm, number, thisUpdate, nextUpdate, entries: options.entries });
  return {
    item: {
      id: "crl",
      description: `Root CRL number ${number}, ${options.entries.length} revoked, next update ${nextUpdate.toISOString()}`,
      data: built.tbs,
    },
    finish: (signature) => {
      const der = assembleCrl(built.tbs, built.algorithmIdentifier, signature);
      const crl = selfCheckCrl(der, issuer);
      return { der, pem: toPem(der, "X509 CRL"), crl };
    },
  };
};

/** Signs prepared artifacts as one batch (one device session, one PIN) and finishes each in order. */
export const signPrepared = async <T extends readonly Prepared<unknown>[]>(
  signer: RootSigner,
  prepared: T,
  options: { readonly confirm?: SignConfirmation; readonly events?: SignEvents } = {},
): Promise<{ [K in keyof T]: T[K] extends Prepared<infer R> ? R : never }> => {
  const signatures = await signBatch(
    signer,
    prepared.map((p) => p.item),
    options,
  );
  return prepared.map((p, i) => p.finish(signatures[i] as Buffer)) as never;
};
