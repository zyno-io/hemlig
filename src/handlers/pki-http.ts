import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { hasRequiredRole } from "../auth/actors";
import type { PkiConfig } from "../aws/config";
import { badRequest } from "../domain/errors";
import { empty } from "../http/responses";
import { pkiBadRequest, pkiRoleRequired } from "../pki/errors";
import type { PkiRole } from "./pki-routes";

export const maximumBodyBytes = 1024 * 1024;

/** The JSON object body, decoded when API Gateway base64-encoded it. Over 1 MiB is `400 body_too_large`. */
export const parseObjectBody = (
  event: Partial<Pick<APIGatewayProxyEventV2, "body" | "isBase64Encoded">>,
): Record<string, unknown> => {
  if (event.body === undefined || event.body.length === 0) {
    return {};
  }
  const text =
    event.isBase64Encoded === true
      ? Buffer.from(event.body, "base64").toString("utf8")
      : event.body;
  if (Buffer.byteLength(text, "utf8") > maximumBodyBytes) {
    throw pkiBadRequest("body_too_large", "The request body is too large.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw badRequest("The request body must be valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badRequest("The request body must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
};

export const requireIdempotencyKey = (value: string | undefined): string => {
  if (value === undefined || value.length < 8 || value.length > 128) {
    throw badRequest(
      "Idempotency-Key is required and must be 8-128 characters.",
    );
  }
  return value;
};

const stripEntityTag = (value: string): string =>
  value.trim().replace(/^W\//, "").replaceAll('"', "");

export const requireIfMatch = (value: string | undefined): string => {
  if (value === undefined || value.trim().length === 0) {
    throw badRequest("If-Match is required.");
  }
  return stripEntityTag(value);
};

/** The entity tags of `If-None-Match`, quotes and `W/` removed; `*` stays as is. */
export const parseIfNoneMatch = (value: string | undefined): string[] =>
  value === undefined
    ? []
    : value
        .split(",")
        .map(stripEntityTag)
        .filter((tag) => tag.length > 0);

export interface CrlHeaderMetadata {
  readonly number: string;
  readonly thisUpdate: string;
  readonly nextUpdate: string;
}

const crlHeaders = (crl?: CrlHeaderMetadata): Record<string, string> =>
  crl === undefined
    ? {}
    : {
        "hemlig-crl-number": crl.number,
        "hemlig-crl-this-update": crl.thisUpdate,
        "hemlig-crl-next-update": crl.nextUpdate,
      };

export const binaryResponse = (
  der: Buffer,
  fileName: string,
  sha256: string,
  crl?: CrlHeaderMetadata,
): APIGatewayProxyStructuredResultV2 => ({
  statusCode: 200,
  isBase64Encoded: true,
  body: der.toString("base64"),
  headers: {
    "content-type": "application/pkix-crl",
    "cache-control": "no-store",
    etag: sha256,
    "content-disposition": `attachment; filename="${fileName}"`,
    ...crlHeaders(crl),
  },
});

export const notModified = (
  sha256: string,
  crl?: CrlHeaderMetadata,
): APIGatewayProxyStructuredResultV2 =>
  empty(304, { etag: sha256, ...crlHeaders(crl) });

/** `read` needs only the administrator JWT; the other roles map to the optional configured role claims. */
export const assertPkiRole = (
  claims: Record<string, string | number | boolean | string[]> | undefined,
  config: Pick<PkiConfig, "adminPkiCaRole" | "adminPkiOperatorRole">,
  role: PkiRole,
): void => {
  if (role === "read") {
    return;
  }
  const required =
    role === "ca-admin" ? config.adminPkiCaRole : config.adminPkiOperatorRole;
  if (!hasRequiredRole(claims ?? {}, required)) {
    throw pkiRoleRequired(role);
  }
};
