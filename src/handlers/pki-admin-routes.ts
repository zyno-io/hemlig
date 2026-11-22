import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import { ApiError, badRequest } from "../domain/errors";
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
const CONSUMER = "([a-z][a-z0-9-]{2,63})";
const NAME = "([a-z][a-z0-9-]{2,63})";
const SERIAL = "([0-9a-f]{2,40})";

const route = (
  method: PkiRouteMethod,
  suffix: string,
  operation: string,
  role: PkiRole,
  handle: PkiAdminRoute["handle"],
  auditTarget?: PkiAdminRoute["auditTarget"],
): PkiAdminRoute => ({
  method,
  pattern: new RegExp(`^/v1/admin/pki${suffix}$`),
  operation,
  role,
  handle,
  ...(auditTarget === undefined ? {} : { auditTarget }),
});

const consumerTarget = (params: string[]): Record<string, string> => ({
  consumerId: params[0] as string,
});
const grantTarget = (params: string[]): Record<string, string> => ({
  consumerId: params[0] as string,
  issuanceGrant: params[1] as string,
});
const caTarget = (params: string[]): Record<string, string> => ({
  caId: params[0] as string,
});
const certificateTarget = (params: string[]): Record<string, string> => ({
  caId: params[0] as string,
  serial: params[1] as string,
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
  options: { operation?: string; reasonCode?: string } = {},
): Promise<void> => {
  await context.app.audit.write({
    correlationId: context.correlationId,
    outcome: "succeeded",
    actor: context.actor,
    operation: options.operation ?? context.operation,
    target,
    permission: "read",
    sourceIp: sourceIp(context),
    ...(options.reasonCode === undefined
      ? {}
      : { reasonCode: options.reasonCode }),
  });
};

/** True for `?name=true`. */
const flag = (context: PkiAdminContext, name: string): boolean =>
  context.event.queryStringParameters?.[name] === "true";

/**
 * A failed denial names the denied name in the audit target; the base target (and the CA the service resolved) is
 * already on the context.
 */
const withDeniedTarget = async <T>(
  context: PkiAdminContext,
  target: Record<string, string>,
  work: () => Promise<T>,
): Promise<T> => {
  try {
    return await work();
  } catch (error) {
    if (error instanceof ApiError) {
      const type = error.details?.deniedNameType;
      const name = error.details?.deniedName;
      if (typeof type === "string" && typeof name === "string") {
        context.setAuditContext({
          actor: context.actor,
          operation: context.operation,
          sourceIp: sourceIp(context),
          target: { ...target, deniedNameType: type, deniedName: name },
        });
      }
    }
    throw error;
  }
};

/** `validateOnly` calls are reads: relabel the context and write one read event. */
const relabelValidate = (
  context: PkiAdminContext,
  target: Record<string, string>,
): void => {
  context.setAuditContext({
    actor: context.actor,
    operation: "pki.grant.validate",
    sourceIp: sourceIp(context),
    permission: "read",
    target,
  });
};

const statusOf = (
  value: string | undefined,
): "ISSUED" | "REVOKED" | "EXPIRED" | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (value !== "ISSUED" && value !== "REVOKED" && value !== "EXPIRED") {
    throw pkiBadRequest("invalid_status", "status is not supported.");
  }
  return value;
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
  route(
    "GET",
    `/cas/${CA}/issuance-grants`,
    "pki.grant.list",
    "read",
    async (context, params) => {
      const caId = params[0] as string;
      const page = await context.app.grants.listForCa(
        context.actor,
        caId,
        context.event.queryStringParameters?.cursor,
      );
      await auditRead(context, { caId });
      return json(200, page);
    },
    caTarget,
  ),
  route(
    "GET",
    `/consumers/${CONSUMER}/issuance-grants`,
    "pki.grant.list",
    "read",
    async (context, params) => {
      const consumerId = params[0] as string;
      const page = await context.app.grants.listForConsumer(
        context.actor,
        consumerId,
        {
          includeDeleted: flag(context, "includeDeleted"),
          ...(context.event.queryStringParameters?.cursor === undefined
            ? {}
            : { cursor: context.event.queryStringParameters.cursor }),
        },
      );
      await auditRead(context, { consumerId });
      return json(200, page);
    },
    consumerTarget,
  ),
  route(
    "POST",
    `/consumers/${CONSUMER}/issuance-grants`,
    "pki.grant.create",
    "operator",
    async (context, params) => {
      const consumerId = params[0] as string;
      if (flag(context, "validateOnly")) {
        relabelValidate(context, { consumerId });
        const result = await context.app.grants.validateCreate(
          consumerId,
          parseObjectBody(context.event),
        );
        await auditRead(context, { consumerId }, {
          operation: "pki.grant.validate",
        });
        return json(200, result);
      }
      const key = idempotencyKeyOf(context);
      const result = await context.app.grants.create(
        context.actor,
        key,
        consumerId,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
    consumerTarget,
  ),
  route(
    "GET",
    `/consumers/${CONSUMER}/issuance-grants/${NAME}`,
    "pki.grant.get",
    "read",
    async (context, params) => {
      const [consumerId, name] = params as [string, string];
      const { body, etag } = await context.app.grants.get(consumerId, name);
      await auditRead(context, { consumerId, issuanceGrant: name });
      return json(200, body, { etag });
    },
    grantTarget,
  ),
  route(
    "PUT",
    `/consumers/${CONSUMER}/issuance-grants/${NAME}`,
    "pki.grant.update",
    "operator",
    async (context, params) => {
      const [consumerId, name] = params as [string, string];
      const ifMatch = requireIfMatch(context.event.headers["if-match"]);
      if (flag(context, "validateOnly")) {
        relabelValidate(context, { consumerId, issuanceGrant: name });
        const result = await context.app.grants.validateUpdate(
          consumerId,
          name,
          ifMatch,
          parseObjectBody(context.event),
        );
        await auditRead(
          context,
          { consumerId, issuanceGrant: name },
          { operation: "pki.grant.validate" },
        );
        return json(200, result);
      }
      const key = idempotencyKeyOf(context);
      const result = await context.app.grants.update(
        context.actor,
        key,
        consumerId,
        name,
        ifMatch,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
    grantTarget,
  ),
  route(
    "DELETE",
    `/consumers/${CONSUMER}/issuance-grants/${NAME}`,
    "pki.grant.delete",
    "operator",
    async (context, params) => {
      const [consumerId, name] = params as [string, string];
      const key = idempotencyKeyOf(context);
      const ifMatch = requireIfMatch(context.event.headers["if-match"]);
      const result = await context.app.grants.delete(
        context.actor,
        key,
        consumerId,
        name,
        ifMatch,
      );
      return respondMutation(context, key, result);
    },
    grantTarget,
  ),
  route(
    "POST",
    `/consumers/${CONSUMER}/issuance-grants/${NAME}/evaluate`,
    "pki.grant.evaluate",
    "read",
    async (context, params) => {
      const [consumerId, name] = params as [string, string];
      const result = await context.app.issuance.evaluate(
        consumerId,
        name,
        parseObjectBody(context.event),
      );
      const denial = result.denial as { reason?: string } | undefined;
      await auditRead(
        context,
        {
          consumerId,
          issuanceGrant: name,
          decision: String(result.decision),
        },
        denial?.reason === undefined ? {} : { reasonCode: denial.reason },
      );
      return json(200, result);
    },
    grantTarget,
  ),
  route(
    "GET",
    `/cas/${CA}/certificates`,
    "pki.certificate.list",
    "read",
    async (context, params) => {
      const caId = params[0] as string;
      const query = context.event.queryStringParameters ?? {};
      const status = statusOf(query.status);
      const page = await context.app.certificates.list(context.actor, caId, {
        ...(status === undefined ? {} : { status }),
        ...(query.expiringBefore === undefined
          ? {}
          : { expiringBefore: query.expiringBefore }),
        ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
      });
      await auditRead(context, { caId });
      return json(200, page);
    },
    caTarget,
  ),
  route(
    "POST",
    `/cas/${CA}/certificates`,
    "pki.certificate.issue",
    "operator",
    async (context, params) => {
      const caId = params[0] as string;
      const key = idempotencyKeyOf(context);
      const result = await withDeniedTarget(context, { caId }, () =>
        context.app.issuance.issueForAdmin(
          context.actor,
          key,
          caId,
          parseObjectBody(context.event),
        ),
      );
      return respondMutation(context, key, result);
    },
    caTarget,
  ),
  route(
    "GET",
    `/cas/${CA}/certificates/${SERIAL}`,
    "pki.certificate.get",
    "read",
    async (context, params) => {
      const [caId, serial] = params as [string, string];
      const body = await context.app.certificates.get(caId, serial);
      await auditRead(context, { caId, serial });
      return json(200, body);
    },
    certificateTarget,
  ),
  route(
    "POST",
    `/cas/${CA}/certificates/${SERIAL}/revoke`,
    "pki.certificate.revoke",
    "operator",
    async (context, params) => {
      const [caId, serial] = params as [string, string];
      const key = idempotencyKeyOf(context);
      const result = await context.app.certificates.revoke(
        context.actor,
        key,
        caId,
        serial,
        parseObjectBody(context.event),
      );
      return respondMutation(context, key, result);
    },
    certificateTarget,
  ),
  route(
    "GET",
    `/consumers/${CONSUMER}/certificates`,
    "pki.certificate.list",
    "read",
    async (context, params) => {
      const consumerId = params[0] as string;
      const query = context.event.queryStringParameters ?? {};
      const page = await context.app.certificates.listForConsumer(
        context.actor,
        consumerId,
        {
          ...(query.issuanceGrant === undefined
            ? {}
            : { issuanceGrant: query.issuanceGrant }),
          includeExpired: query.includeExpired === "true",
          ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
        },
      );
      await auditRead(context, { consumerId });
      return json(200, page);
    },
    consumerTarget,
  ),
  route(
    "POST",
    `/consumers/${CONSUMER}/certificates/revoke`,
    "pki.certificate.revoke",
    "operator",
    async (context, params) => {
      const consumerId = params[0] as string;
      const key = idempotencyKeyOf(context);
      const result = await context.app.certificates.bulkRevoke(
        context.actor,
        key,
        consumerId,
        parseObjectBody(context.event),
      );
      if (!result.complete) {
        // No idempotency record exists, so `humanOperation` (which marks one) must not run.
        await context.app.audit.write({
          correlationId: context.correlationId,
          outcome: "succeeded",
          actor: context.actor,
          operation: context.operation,
          target: result.auditTarget,
          sourceIp: sourceIp(context),
        });
        return json(result.status, result.body);
      }
      return respondMutation(context, key, result);
    },
    consumerTarget,
  ),
];
