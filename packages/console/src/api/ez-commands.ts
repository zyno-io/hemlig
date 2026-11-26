/**
 * Shell-safe `hemlig pki ez` commands for the console's EZ tabs. The flags
 * mirror packages/cli/src/ez.ts. Values are validated identifiers, and are
 * still quoted defensively. A value that fails validation yields `undefined`,
 * so the caller falls back to the Manual tab.
 */

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const EXT_ID = /^ext-[0-9a-f]{40}$/;
const SPKI_SHA256 = /^[0-9a-fA-F]{64}$/;
const BARE = /^[A-Za-z0-9._/:=@-]+$/;

/** Bare when it is plainly safe, otherwise single-quoted with `'\''`. */
export const shellArg = (value: string): string =>
  BARE.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;

/** A file-name stem for a CA name: never empty, no path or shell characters. */
export const fileStem = (name: string): string => {
  const slug = name.replaceAll(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+/, "");
  return slug === "" ? "ca" : slug.slice(0, 64);
};

export interface EzCaInput {
  readonly caId: string;
  readonly environment: string;
  readonly name: string;
  readonly spkiSha256: string;
}

export interface EzActivationCommands {
  readonly login: string;
  readonly sign: string;
  readonly csrFile: string;
  readonly offlineSign: string;
  readonly activate: string;
}

export const ezActivationCommands = (
  ca: EzCaInput,
  origin: string,
): EzActivationCommands | undefined => {
  if (
    !IDENTIFIER.test(ca.caId) ||
    !IDENTIFIER.test(ca.environment) ||
    !SPKI_SHA256.test(ca.spkiSha256)
  ) {
    return undefined;
  }
  const id = shellArg(ca.caId);
  const env = shellArg(ca.environment);
  const stem = fileStem(ca.name);
  const csrFile = `${stem}.csr.pem`;
  const certFile = `${stem}.pem`;
  return {
    login: `hemlig login --console-url ${shellArg(origin)}`,
    sign: `hemlig pki ez sign-cert ${id} --environment ${env}`,
    csrFile,
    offlineSign:
      `hemlig pki ez sign-cert ${id} --offline --csr ${shellArg(csrFile)}` +
      ` --expect-spki-sha256 ${ca.spkiSha256.toLowerCase()}` +
      ` --out ${shellArg(certFile)}`,
    activate:
      `hemlig pki ez activate ${id} --environment ${env}` +
      ` --certificate ${shellArg(certFile)} --chain root.pem --crl root.crl.pem`,
  };
};

export interface EzRenewCrlCommands {
  readonly renew: string;
  readonly upload: string;
  readonly offlineRenew: string;
  readonly offlineUpload: string;
}

export const ezRenewCrlCommands = (extId: string): EzRenewCrlCommands | undefined => {
  if (!EXT_ID.test(extId)) {
    return undefined;
  }
  const ext = shellArg(extId);
  return {
    renew: `hemlig pki ez renew-crl --if-due --expect-ext-id ${ext}`,
    upload: `hemlig pki ez upload-crl --expect-ext-id ${ext}`,
    offlineRenew: "hemlig pki ez renew-crl --offline --crl-out root.crl.pem",
    offlineUpload: `hemlig pki ez upload-crl --crl root.crl.pem --root-cert root.pem --expect-ext-id ${ext}`,
  };
};
