import { badRequest } from "../domain/errors";
import { pkiBadRequest } from "./errors";
import { requestDigest } from "./ca-model";
import type { GrantPolicy } from "./policy-types";
import type { CaRecord, GrantStatus, IssuanceGrantRecord } from "./types";

type Json = Record<string, unknown>;

export const DEFAULT_GRANT_PER_HOUR = 100;
export const DEFAULT_GRANT_PER_DAY = 1000;
export const MAX_LIVE_GRANTS_PER_CONSUMER = 20;

/** The eight policy keys of `grant-policy.ts`; every other top-level key is part of the envelope or unknown. */
export const GRANT_POLICY_KEYS = [
  "names",
  "subject",
  "keyAlgorithms",
  "keyUsages",
  "extendedKeyUsages",
  "lifetime",
  "forced",
  "quotas",
] as const;

const createEnvelopeKeys = [
  "name",
  "caId",
  "displayName",
  "status",
  "expiresAt",
] as const;
const updateEnvelopeKeys = ["caId", "displayName", "status", "expiresAt"] as const;

const namePattern = /^[a-z][a-z0-9-]{2,63}$/;
const caIdPattern = /^ca-[a-z0-9-]{3,80}$/;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export interface GrantEnvelope {
  name?: string;
  caId: string;
  displayName?: string;
  /** Absent on a PUT keeps the current status; absent on a create is ACTIVE. */
  status?: Exclude<GrantStatus, "DELETED">;
  expiresAt?: string;
}

export interface ParsedGrantRequest {
  envelope: GrantEnvelope;
  /** The policy keys present in the body, untouched. */
  policyFields: Json;
}

export const parseGrantRequest = (
  body: unknown,
  kind: "create" | "update",
  now: Date,
  pathName?: string,
): ParsedGrantRequest => {
  if (!isRecord(body)) {
    throw badRequest("The request body must be a JSON object.");
  }
  const envelopeKeys: readonly string[] =
    kind === "create" ? createEnvelopeKeys : [...updateEnvelopeKeys, "name"];
  for (const key of Object.keys(body)) {
    if (
      !envelopeKeys.includes(key) &&
      !(GRANT_POLICY_KEYS as readonly string[]).includes(key)
    ) {
      throw pkiBadRequest("unknown_field", "The request has an unknown field.");
    }
  }
  const envelope: GrantEnvelope = { caId: "" };
  if (kind === "create") {
    if (typeof body.name !== "string" || !namePattern.test(body.name)) {
      throw pkiBadRequest(
        "invalid_name",
        "name must be 3-64 lowercase letters, digits and hyphens, starting with a letter.",
      );
    }
    envelope.name = body.name;
  } else if (body.name !== undefined && body.name !== pathName) {
    throw pkiBadRequest("name_mismatch", "name must equal the path name.");
  }
  if (typeof body.caId !== "string" || !caIdPattern.test(body.caId)) {
    throw pkiBadRequest("invalid_ca_id", "caId must be a CA identifier.");
  }
  envelope.caId = body.caId;
  if (body.displayName !== undefined) {
    if (
      typeof body.displayName !== "string" ||
      body.displayName.length < 1 ||
      body.displayName.length > 128
    ) {
      throw badRequest("displayName must be 1-128 characters.");
    }
    envelope.displayName = body.displayName;
  }
  if (body.status !== undefined) {
    if (body.status !== "ACTIVE" && body.status !== "DISABLED") {
      throw pkiBadRequest(
        "invalid_status",
        "status must be ACTIVE or DISABLED.",
      );
    }
    envelope.status = body.status;
  }
  if (body.expiresAt !== undefined) {
    const parsed =
      typeof body.expiresAt === "string"
        ? new Date(body.expiresAt)
        : new Date(Number.NaN);
    if (Number.isNaN(parsed.getTime()) || parsed.getTime() <= now.getTime()) {
      throw pkiBadRequest(
        "invalid_expiry",
        "expiresAt must be a time in the future.",
      );
    }
    envelope.expiresAt = parsed.toISOString();
  }
  const policyFields: Json = {};
  for (const key of GRANT_POLICY_KEYS) {
    if (body[key] !== undefined) {
      policyFields[key] = body[key];
    }
  }
  return { envelope, policyFields };
};

export const grantCreateDigest = (consumerId: string, body: unknown): string =>
  requestDigest("pki.grant.create", { consumerId, body: body as object });

export const grantUpdateDigest = (
  consumerId: string,
  name: string,
  ifMatch: string,
  body: unknown,
): string =>
  requestDigest("pki.grant.update", {
    consumerId,
    name,
    ifMatch,
    body: body as object,
  });

export const grantDeleteDigest = (
  consumerId: string,
  name: string,
  ifMatch: string,
): string =>
  requestDigest("pki.grant.delete", { consumerId, name, ifMatch });

export const resolvedQuotas = (
  policy: GrantPolicy,
): { perHour: number; perDay: number } => ({
  perHour: policy.quotas?.perHour ?? DEFAULT_GRANT_PER_HOUR,
  perDay: policy.quotas?.perDay ?? DEFAULT_GRANT_PER_DAY,
});

export const grantExpired = (
  grant: Pick<IssuanceGrantRecord, "expiresAt">,
  now: Date,
): boolean =>
  grant.expiresAt !== undefined && Date.parse(grant.expiresAt) <= now.getTime();

export const adminGrantView = (g: IssuanceGrantRecord, now: Date): Json => ({
  consumerId: g.consumerId,
  environment: g.environment,
  name: g.name,
  uid: g.uid,
  caId: g.caId,
  status: g.status,
  expired: grantExpired(g, now),
  ...(g.displayName === undefined ? {} : { displayName: g.displayName }),
  ...(g.expiresAt === undefined ? {} : { expiresAt: g.expiresAt }),
  policy: g.policy,
  policyDigest: g.policyDigest,
  quotas: resolvedQuotas(g.policy),
  version: g.version,
  createdAt: g.createdAt,
  createdBy: g.createdBy,
  updatedAt: g.updatedAt,
  updatedBy: g.updatedBy,
  ...(g.deletedAt === undefined ? {} : { deletedAt: g.deletedAt }),
  ...(g.deletedBy === undefined ? {} : { deletedBy: g.deletedBy }),
});

export const consumerGrantView = (
  g: IssuanceGrantRecord,
  ca: CaRecord | undefined,
  now: Date,
): Json => ({
  name: g.name,
  uid: g.uid,
  status: g.status,
  expired: grantExpired(g, now),
  version: g.version,
  ...(g.expiresAt === undefined ? {} : { expiresAt: g.expiresAt }),
  policy: g.policy,
  quotas: resolvedQuotas(g.policy),
  ca: {
    caId: g.caId,
    ...(ca === undefined
      ? { status: "UNKNOWN" }
      : {
          name: ca.name,
          ...(ca.fingerprint === undefined
            ? {}
            : { fingerprint: ca.fingerprint }),
          ...(ca.notAfter === undefined ? {} : { notAfter: ca.notAfter }),
          status: ca.status,
        }),
  },
});
