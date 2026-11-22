import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import { badRequest } from "../domain/errors";
import { json } from "../http/responses";
import type { MutationResult } from "../pki/service-types";
import { pkiBadRequest } from "../pki/errors";
import { humanOperation } from "../services/operations";
import type { PkiAdminContext, PkiAdminRoute } from "./pki-admin";
import {
  binaryResponse,
  notModified,
  parseIfNoneMatch,
  parseObjectBody,
  requireIdempotencyKey,
  requireIfMatch,
} from "./pki-http";
import type { PkiRole, PkiRouteMethod } from "./pki-routes";

const CA = "(ca-[a-z0-9-]{3,80})";
const EXT = "(ext-[0-9a-f]{40})";

const route = (
  method: PkiRouteMethod,
  suffix: string,
  operation: string,
  role: PkiRole,
  handle: PkiAdminRoute["handle"],
): PkiAdminRoute => ({
  method,
  pattern: new RegExp(`^/v1/admin/pki${suffix}$`),
  operation,
  role,
  handle,
});

const sourceIp = (context: PkiAdminContext): string =>
  context.event.requestContext.http.sourceIp;

const idempotencyKeyOf = (context: PkiAdminContext): string =>
  requireIdempotencyKey(context.event.headers["idempotency-key"]);

/** A mutation: the terminal audit event is written once, and a replay of an already-audited request writes none. */
const respondMutation = async (
  context: PkiAdminContext,
  key: string,
  result: MutationResult,
): Promise<APIGatewayProxyStructuredResultV2> => {
  const response = () =>
    json(
      result.status,
      result.body,
      result.etag === undefined ? {} : { etag: result.etag },
    );
  if (!result.shouldWriteTerminalAudit) {
    return response();
  }
  return humanOperation(
    context.app,
    context.actor,
    key,
    context.correlationId,
    context.operation,
    sourceIp(context),
    result.auditTarget,
    response,
  );
};

/** A read writes one `succeeded` audit event with `permission: "read"`. */
const auditRead = async (
  context: PkiAdminContext,
  target: Record<string, string>,
): Promise<void> => {
  await context.app.audit.write({
    correlationId: context.correlationId,
    outcome: "succeeded",
    actor: context.actor,
    operation: context.operation,
    target,
    permission: "read",
    sourceIp: sourceIp(context),
  });
};

const requireEmptyBody = (context: PkiAdminContext): void => {
  if (Object.keys(parseObjectBody(context.event)).length > 0) {
    throw pkiBadRequest("unknown_field", "This request takes no body.");
  }
};

export const pkiAdminRoutes: PkiAdminRoute[] = [
  route("GET", "/cas", "pki.ca.list", "read", async (context) => {
    const environment = context.event.queryStringParameters?.environment;
    if (
      environment === undefined ||
      environment.length === 0 ||
      environment.length > 128
    ) {
      throw badRequest(
        "environment is required and must be at most 128 characters.",
      );
    }
    const page = await context.app.cas.list(
      context.actor,
      environment,
      context.event.queryStringParameters?.cursor,
    );
    await auditRead(context, { environment });
    return json(200, page);
  }),
  route("POST", "/cas", "pki.ca.create", "ca-admin", async (context) => {
    const key = idempotencyKeyOf(context);
    const result = await context.app.cas.create(
      context.actor,
      key,
      parseObjectBody(context.event),
    );
    return respondMutation(context, key, result);
  }),
  route("GET", `/cas/${CA}`, "pki.ca.get", "read", async (context, params) => {
    const caId = params[0] as string;
    const { body, etag } = await context.app.cas.get(caId);
    await auditRead(context, { caId });
    return json(200, body, { etag });
  }),
  route(
    "PUT",
    `/cas/${CA}`,
    "pki.ca.update",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      const ifMatch = requireIfMatch(context.event.headers["if-match"]);
      const result = await context.app.cas.update(
        context.actor,
        key,
        params[0] as string,
        ifMatch,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "DELETE",
    `/cas/${CA}`,
    "pki.ca.delete",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      const ifMatch = requireIfMatch(context.event.headers["if-match"]);
      const result = await context.app.cas.abandon(
        context.actor,
        key,
        params[0] as string,
        ifMatch,
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "POST",
    `/cas/${CA}/certificate`,
    "pki.ca.activate",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      const result = await context.app.cas.activate(
        context.actor,
        key,
        params[0] as string,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "POST",
    `/cas/${CA}/retire`,
    "pki.ca.retire",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      requireEmptyBody(context);
      const result = await context.app.cas.retire(
        context.actor,
        key,
        params[0] as string,
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "POST",
    `/cas/${CA}/destroy-key`,
    "pki.ca.destroy-key",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      requireEmptyBody(context);
      const result = await context.app.cas.destroyKey(
        context.actor,
        key,
        params[0] as string,
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "POST",
    `/cas/${CA}/crl`,
    "pki.crl.publish",
    "operator",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      requireEmptyBody(context);
      const result = await context.app.cas.forcePublish(
        context.actor,
        key,
        params[0] as string,
      );
      return respondMutation(context, key, result);
    },
  ),
  route(
    "GET",
    `/crls/(${CA.slice(1, -1)}|${EXT.slice(1, -1)})`,
    "pki.crl.get",
    "read",
    async (context, params) => {
      const id = params[0] as string;
      const download = await context.app.crls.download(
        id,
        parseIfNoneMatch(context.event.headers["if-none-match"]),
      );
      await auditRead(
        context,
        id.startsWith("ext-") ? { extId: id } : { caId: id },
      );
      if (download.kind === "notModified") {
        return notModified(download.sha256);
      }
      return binaryResponse(
        download.der,
        `${id}-${download.numberText}.crl`,
        download.sha256,
      );
    },
  ),
  route(
    "GET",
    "/external-cas",
    "pki.external-ca.list",
    "read",
    async (context) => {
      const page = await context.app.externalCas.list(
        context.actor,
        context.event.queryStringParameters?.cursor,
      );
      await auditRead(context, {});
      return json(200, page);
    },
  ),
  route(
    "GET",
    `/external-cas/${EXT}`,
    "pki.external-ca.get",
    "read",
    async (context, params) => {
      const extId = params[0] as string;
      const { body, etag } = await context.app.externalCas.get(extId);
      await auditRead(context, { extId });
      return json(200, body, { etag });
    },
  ),
  route(
    "POST",
    `/external-cas/${EXT}/crl`,
    "pki.external-ca.upload-crl",
    "ca-admin",
    async (context, params) => {
      const key = idempotencyKeyOf(context);
      const result = await context.app.externalCas.uploadCrl(
        context.actor,
        key,
        params[0] as string,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
  ),
];
