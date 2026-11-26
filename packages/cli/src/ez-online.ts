import { createHash } from "node:crypto";
import {
  HemligClient,
  HemligError,
  type HemligTransport,
  type PkiCaDetail,
  type PkiExternalCaDetail,
  type PkiUploadCrlResponse,
} from "@zyno-io/hemlig-client";
import { createTransport, resolveAdminSession, type CliDependencies, type SessionValues } from "./common";
import { defaultConfigDir } from "./login";
import { EzError } from "./ez-error";
import { EZ_DEFAULTS } from "./ez-profile";
import { assertCrlFromRoot } from "./ez-adopt";
import type { ServerRootView } from "./ez-state";
import { parseCrl, type ParsedCertificate, type ParsedCrl } from "./ez-x509";

/** Server side of the EZ commands: session, external-root lookup, CRL upload and activation, with deterministic keys. */

export interface OnlineSession {
  readonly client: HemligClient;
  readonly token: string;
  readonly origin: URL;
  /** The server's clock as last seen in a `Date` response header. */
  serverTime(): Date | undefined;
}

export const MAX_EXTERNAL_PAGES = 10;

export const openSession = async (
  values: SessionValues,
  dependencies: CliDependencies,
  timeoutMs: number,
): Promise<OnlineSession> => {
  const env = dependencies.env ?? process.env;
  const { origin, token } = await resolveAdminSession(values, env, {
    configDir: dependencies.configDir ?? defaultConfigDir(env),
    now: dependencies.now ?? Date.now,
  });
  const inner = createTransport(dependencies, timeoutMs);
  let seen: Date | undefined;
  const transport: HemligTransport = {
    async request(request) {
      const response = await inner.request(request);
      const header = response.headers.date ?? response.headers.Date;
      const parsed = header === undefined ? undefined : new Date(header);
      if (parsed !== undefined && !Number.isNaN(parsed.getTime())) seen = parsed;
      return response;
    },
  };
  return { client: new HemligClient(origin, transport), token, origin, serverTime: () => seen };
};

/**
 * Exits 5 `clock_skew` when this machine and the server disagree by more than the profile allows. Call it after the first
 * server response: with no server time seen it fails closed (`clock_unchecked`), so a misplaced call cannot skip the check.
 */
export const assertClockSkew = (session: OnlineSession, now: Date): void => {
  const server = session.serverTime();
  if (server === undefined) {
    throw new EzError(5, "clock_unchecked", "The server's clock could not be read (no Date header), so this machine's clock could not be checked; nothing was signed.");
  }
  const skew = Math.abs(server.getTime() - now.getTime()) / 1000;
  if (skew > EZ_DEFAULTS.clockSkewSeconds) {
    throw new EzError(5, "clock_skew", `This machine's clock differs from the server's by ${Math.round(skew)} s; fix the clock first.`, {
      skewSeconds: Math.round(skew),
    });
  }
};

const digest = (prefix: string, ...parts: string[]): string =>
  `${prefix}${createHash("sha256").update(parts.join("\n")).digest("hex").slice(0, 40)}`;

/** Activation key: a rerun with the same certificate replays instead of conflicting. */
export const activationKey = (caId: string, certificateSha256: string): string => digest("ez-act-", caId, certificateSha256);
/** CRL upload key. */
export const crlUploadKey = (extId: string, crlSha256: string): string => digest("ez-crl-", extId, crlSha256);

export const fetchCa = (session: OnlineSession, caId: string): Promise<PkiCaDetail> => session.client.getPkiCa(session.token, caId);

/**
 * The external root record for a root: first the derived id, then a search by fingerprint (up to 10 pages). Returns
 * undefined when the root is not registered. A record with another fingerprint exits 5 `root_mismatch`.
 */
export const findExternalRoot = async (
  session: OnlineSession,
  root: { readonly spkiSha256: string; readonly fingerprint: string },
): Promise<PkiExternalCaDetail | undefined> => {
  const hint = `ext-${root.spkiSha256.slice(0, 40)}`;
  let detail: PkiExternalCaDetail | undefined;
  try {
    detail = await session.client.getExternalCa(session.token, hint);
  } catch (error) {
    if (!(error instanceof HemligError) || error.status !== 404) throw error;
  }
  if (detail === undefined) {
    let cursor: string | undefined;
    for (let page = 0; page < MAX_EXTERNAL_PAGES && detail === undefined; page += 1) {
      const result = await session.client.listExternalCas(session.token, { cursor });
      const match = result.externalCas.find((entry) => entry.fingerprint === root.fingerprint);
      if (match !== undefined) detail = await session.client.getExternalCa(session.token, match.extId);
      cursor = result.nextCursor;
      if (cursor === undefined) break;
    }
  }
  if (detail !== undefined && detail.fingerprint !== root.fingerprint) {
    throw new EzError(5, "root_mismatch", "The server has a different certificate for this root key.", {
      server: detail.fingerprint,
      local: root.fingerprint,
    });
  }
  return detail;
};

export const serverViewOf = (detail: PkiExternalCaDetail | undefined): ServerRootView =>
  detail === undefined
    ? {}
    : {
        fingerprint: detail.fingerprint,
        ...(detail.crl === undefined ? {} : { crl: { numberHex: detail.crl.numberHex, sha256: detail.crl.sha256 } }),
      };

export const uploadRootCrl = (
  session: OnlineSession,
  extId: string,
  crl: { readonly pem: string; readonly sha256: string },
): Promise<PkiUploadCrlResponse> => session.client.uploadExternalCaCrl(session.token, extId, crl.pem, crlUploadKey(extId, crl.sha256));

export interface ActivationResult {
  readonly detail: PkiCaDetail;
  readonly alreadyActive: boolean;
}

/**
 * Activates with the deterministic key. A `409 ca_not_pending` whose CA is already ACTIVE with this certificate is
 * success (`alreadyActive`); ACTIVE with another certificate exits 5 `ca_activated_elsewhere`.
 */
export const activateWithCertificate = async (
  session: OnlineSession,
  input: {
    readonly caId: string;
    readonly certificatePem: string;
    readonly chainPem: string;
    readonly certificateFingerprint: string;
    readonly rootCrlPem?: string;
  },
): Promise<ActivationResult> => {
  try {
    const detail = await session.client.activatePkiCa(
      session.token,
      input.caId,
      {
        certificatePem: input.certificatePem,
        chainPem: input.chainPem,
        ...(input.rootCrlPem === undefined ? {} : { rootCrl: input.rootCrlPem }),
      },
      activationKey(input.caId, input.certificateFingerprint),
    );
    return { detail, alreadyActive: false };
  } catch (error) {
    if (!(error instanceof HemligError) || error.status !== 409) throw error;
    const current = await fetchCa(session, input.caId);
    if (current.status === "ACTIVE") {
      if (current.fingerprint === input.certificateFingerprint) return { detail: current, alreadyActive: true };
      throw new EzError(5, "ca_activated_elsewhere", "The CA is already active with a different certificate.", {
        serverFingerprint: current.fingerprint ?? "",
        ourFingerprint: input.certificateFingerprint,
      });
    }
    throw error;
  }
};

/**
 * The server's stored root CRL for a registered external root, the same download as `pki ca crl get <ext-id>`: DER bytes
 * whose `ETag`, when present, is their SHA-256. The caller verifies the CRL under the root.
 */
export const downloadRootCrl = async (session: OnlineSession, extId: string): Promise<Buffer> => {
  const result = await session.client.getAdminCrl(session.token, extId);
  if (result.status !== 200) throw new EzError(7, "invalid_response", "The server's root CRL download was not a CRL.");
  const bytes = Buffer.from(result.bytes);
  const typeOk = (result.contentType ?? "").trim().toLowerCase().startsWith("application/pkix-crl");
  if (!(typeOk || bytes[0] === 0x30) || (result.etag !== undefined && result.etag !== createHash("sha256").update(bytes).digest("hex"))) {
    throw new EzError(7, "invalid_response", "The server's root CRL failed verification.");
  }
  return bytes;
};

/** The server's stored root CRL, verified under the root with exactly the server's own profile (any reason code but 8). */
export const fetchServerCrl = async (session: OnlineSession, detail: PkiExternalCaDetail | undefined, root: ParsedCertificate): Promise<ParsedCrl | undefined> => {
  if (detail?.crl === undefined) return undefined;
  const crl = parseCrl(await downloadRootCrl(session, detail.extId));
  assertCrlFromRoot(crl, root, "The server's root CRL", true);
  return crl;
};

/** A CRL about to be uploaded must list every serial the server's CRL lists, or it would un-revoke them. */
export const assertCarriesServerRevocations = (ours: ParsedCrl, server: ParsedCrl | undefined): void => {
  if (server === undefined) return;
  const have = new Set(ours.entries.map((e) => e.serial));
  const missing = server.entries.map((e) => e.serial).filter((serial) => !have.has(serial));
  if (missing.length > 0) {
    throw new EzError(5, "state_behind_server", "The server's root CRL revokes serials this CRL does not list; uploading it would un-revoke them. Nothing was uploaded.", { serials: missing });
  }
};

/**
 * The server view for the state cross-checks, with the serials its stored root CRL revokes: the CRL is downloaded and
 * verified under the root, so a state that lacks a revocation the server already lists is caught (`state_behind_server`)
 * before anything is uploaded.
 */
export const fetchServerView = async (session: OnlineSession, detail: PkiExternalCaDetail | undefined, root: ParsedCertificate): Promise<ServerRootView> => {
  const view = serverViewOf(detail);
  const crl = await fetchServerCrl(session, detail, root);
  if (crl === undefined || view.crl === undefined) return view;
  return { ...view, crl: { ...view.crl, serials: crl.entries.map((e) => e.serial) } };
};
