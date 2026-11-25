import { assertRestrictedName, describeName } from "./ez-name";
import { displaySafe, summarizeCsr, type CrlReasonName, type ParsedCertificate, type ValidatedCsr } from "./ez-x509";

/**
 * What the operator reads before typing `confirm`. Every value that did not come from this program's own constants is
 * passed through `displaySafe`, so a hostile CSR or server value cannot move the cursor or forge a line.
 */

const row = (label: string, value: string): string => `  ${`${label}:`.padEnd(20)}${value}`;

export interface SignReview {
  readonly caId: string;
  readonly environment: string;
  /** Where the CSR came from: the server, or a file (offline). */
  readonly source: string;
  readonly csr: ValidatedCsr;
  readonly serial: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly root: { readonly subjectDn: string; readonly fingerprint: string };
  readonly crl?: { readonly number: number; readonly nextUpdate: Date };
  readonly expectedSpki: boolean;
}

export const renderSignReview = (review: SignReview): string => {
  const summary = summarizeCsr(review.csr);
  const nc = summary.nameConstraints;
  const lines = [
    "",
    "=== Review: this will sign an intermediate CA certificate ===",
    row("CA ID", displaySafe(review.caId)),
    row("Environment", displaySafe(review.environment)),
    row("CSR source", displaySafe(review.source)),
    row("Subject", summary.subject),
    row("Key", `${displaySafe(summary.keyAlgorithm)}, SPKI SHA-256 ${summary.spkiSha256}`),
    row("Name constraints", nc === undefined ? "NONE (this CA may issue for any name)" : ""),
    ...(nc === undefined
      ? []
      : [
          ...nc.permitted.map((entry) => row("  permitted", entry)),
          ...nc.excluded.map((entry) => row("  excluded", entry)),
        ]),
    row("Extended key usage", summary.extendedKeyUsages.length === 0 ? "none" : summary.extendedKeyUsages.join(", ")),
    row("Path length", "0 (issues leaf certificates only)"),
    row("Validity", `${review.notBefore.toISOString()} to ${review.notAfter.toISOString()}`),
    row("Serial", review.serial),
    row("Signed by root", `${displaySafe(review.root.subjectDn)} (SHA-256 ${review.root.fingerprint})`),
    ...(review.crl === undefined ? [] : [row("Also signs", `root CRL number ${review.crl.number}, next update about ${review.crl.nextUpdate.toISOString()}`)]),
    ...(review.expectedSpki ? [] : [row("WARNING", "the key is not pinned: pass --expect-spki-sha256 from the console to bind the CSR to the CA")]),
    ...summary.warnings.filter((w) => w !== "csr_unbound").map((w) => row("Warning", displaySafe(w))),
    "",
  ];
  return `${lines.join("\n")}\n`;
};

export interface RevokeReview {
  readonly caId: string | null;
  readonly environment: string | null;
  readonly subjectDn: string;
  readonly serial: string;
  readonly reason: CrlReasonName;
  readonly invalidityDate?: Date;
  readonly root: { readonly subjectDn: string; readonly fingerprint: string };
  readonly crl: { readonly number: number; readonly nextUpdate: Date };
  readonly alreadyRevoked: boolean;
  /** Serials recorded earlier but not yet in a signed CRL; this CRL lists them too. */
  readonly alsoListed?: readonly string[];
}

export const renderRevokeReview = (review: RevokeReview): string => {
  const lines = [
    "",
    "=== Review: this will REVOKE an intermediate CA certificate ===",
    row("CA ID", displaySafe(review.caId ?? "(unknown)")),
    row("Environment", displaySafe(review.environment ?? "(unknown)")),
    row("Subject", displaySafe(review.subjectDn)),
    row("Serial revoked", review.serial),
    row("Reason", review.reason),
    ...(review.invalidityDate === undefined ? [] : [row("Invalidity date", review.invalidityDate.toISOString())]),
    row("Effect", "every certificate this CA issued stops being trusted once the new root CRL is uploaded; revocation is permanent"),
    row("Root", `${displaySafe(review.root.subjectDn)} (SHA-256 ${review.root.fingerprint})`),
    row("Signs", `root CRL number ${review.crl.number}, next update about ${review.crl.nextUpdate.toISOString()}`),
    ...(review.alsoListed === undefined || review.alsoListed.length === 0
      ? []
      : [row("Also lists", `${review.alsoListed.join(", ")} (recorded earlier, not yet in a CRL)`)]),
    ...(review.alreadyRevoked ? [row("Note", "already recorded as revoked locally; this re-signs it into a CRL")] : []),
    "",
  ];
  return `${lines.join("\n")}\n`;
};

export const rootLabel = (root: ParsedCertificate): { subjectDn: string; fingerprint: string } => ({
  subjectDn: describeNameSafe(root),
  fingerprint: root.fingerprint,
});

const describeNameSafe = (root: ParsedCertificate): string => {
  try {
    return describeName(assertRestrictedName(root.subjectDer, "external"));
  } catch {
    return "(unreadable subject)";
  }
};

/** A rerun whose certificate is already signed but whose root CRL is due. */
export const renderCrlReview = (input: {
  readonly root: { readonly subjectDn: string; readonly fingerprint: string };
  readonly crl: { readonly number: number; readonly nextUpdate: Date };
  readonly why: string;
}): string =>
  `${[
    "",
    "=== Review: this will sign a root CRL ===",
    row("Root", `${displaySafe(input.root.subjectDn)} (SHA-256 ${input.root.fingerprint})`),
    row("CRL number", String(input.crl.number)),
    row("Next update", `about ${input.crl.nextUpdate.toISOString()}`),
    row("Why", input.why),
    "",
  ].join("\n")}\n`;
