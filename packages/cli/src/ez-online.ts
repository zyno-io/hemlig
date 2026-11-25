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
import type { ServerRootView } from "./ez-state";

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

/** Exits 5 `clock_skew` when this machine and the server disagree by more than the profile allows (no header: skipped). */
export const assertClockSkew = (session: OnlineSession, now: Date): void => {
  const server = session.serverTime();
  if (server === undefined) return;
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
