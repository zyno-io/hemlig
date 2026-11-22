import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import { ApiError } from "../domain/errors";
import { json } from "../http/responses";
import { consumerGrantView } from "../pki/grant-model";
import { issuanceGrantNotFound } from "../pki/errors";
import { sha256Hex, stableJson } from "../util/encoding";
import { parseObjectBody, requireIdempotencyKey } from "./pki-http";
import type { PkiIssuerContext, PkiIssuerRoute } from "./pki-issuer";
import type { PkiRouteMethod } from "./pki-routes";

const NAME = "([a-z][a-z0-9-]{2,63})";
const suppressionWindowSeconds = 10 * 60;
const maxListedGrants = 20;

interface RouteState {
  readonly target: Record<string, string>;
  readonly grantName?: string;
}

/**
 * Wraps a consumer route: a provisional audit context first (so any failure is recorded), the denied name merged
 * on a failure, and at most one identical failure event per identity, grant and reason every ten minutes. The
 * limiter fails open.
 */
const consumerRoute = (
  method: PkiRouteMethod,
  suffix: string,
  operation: string,
  handle: (
    context: PkiIssuerContext,
    params: string[],
    state: {
      readonly target: Record<string, string>;
      readonly update: (extra: Record<string, string>) => void;
    },
  ) => Promise<APIGatewayProxyStructuredResultV2>,
): PkiIssuerRoute => ({
  method,
  pattern: new RegExp(`^/v1/pki/issuance-grants${suffix}$`),
  operation,
  handle: async (context, params) => {
    const grantName = params[0];
    const target: Record<string, string> = {
      consumerId: context.consumerId,
      environment: context.environment,
      ...(grantName === undefined ? {} : { issuanceGrant: grantName }),
    };
    const publish = (): void =>
      context.setAuditContext({
        actor: context.actor,
        operation,
        sourceIp: context.event.requestContext.http.sourceIp,
        target: { ...target },
      });
    publish();
    const state: RouteState & {
      readonly update: (extra: Record<string, string>) => void;
    } = {
      target,
      ...(grantName === undefined ? {} : { grantName }),
      update: (extra) => {
        Object.assign(target, extra);
        publish();
      },
    };
    try {
      return await handle(context, params, state);
    } catch (error) {
      if (error instanceof ApiError) {
        const type = error.details?.deniedNameType;
        const name = error.details?.deniedName;
        if (typeof type === "string" && typeof name === "string") {
          state.update({ deniedNameType: type, deniedName: name });
        }
        const scope = `PKI#${sha256Hex(
          stableJson([operation, grantName ?? "", error.safeReason ?? error.code]),
        ).slice(0, 32)}`;
        const claimed = await context.app.repository
          .claimAuditSuppression(
            context.actor.id,
            scope,
            suppressionWindowSeconds,
          )
          .catch(() => true);
        if (!claimed) {
          context.setAuditContext(undefined);
        }
      }
      throw error;
    }
  },
});

export const pkiIssuerRoutes: PkiIssuerRoute[] = [
  consumerRoute("GET", "", "pki.grant.list", async (context) => {
    const { app, consumerId, environment } = context;
    const now = app.now();
    const page = await app.pki.listGrantsPage(consumerId, {
      includeDeleted: false,
      limit: 100,
    });
    const grants = page.grants
      .filter((grant) => grant.environment === environment)
      .slice(0, maxListedGrants);
    const cas = new Map(
      await Promise.all(
        [...new Set(grants.map((grant) => grant.caId))].map(
          async (caId) => [caId, await app.pki.getCa(caId)] as const,
        ),
      ),
    );
    return json(200, {
      grants: grants.map((grant) =>
        consumerGrantView(grant, cas.get(grant.caId), now),
      ),
      generatedAt: now.toISOString(),
    });
  }),
  consumerRoute("GET", `/${NAME}`, "pki.grant.get", async (context, params) => {
    const { app, consumerId, environment } = context;
    const grant = await app.pki.getGrant(consumerId, params[0] as string);
    if (
      grant === undefined ||
      grant.status === "DELETED" ||
      grant.environment !== environment
    ) {
      throw issuanceGrantNotFound();
    }
    const ca = await app.pki.getCa(grant.caId);
    return json(200, consumerGrantView(grant, ca, app.now()));
  }),
  consumerRoute(
    "POST",
    `/${NAME}/certificates`,
    "pki.certificate.issue",
    async (context, params, state) => {
      const { app } = context;
      const key = requireIdempotencyKey(
        context.event.headers["idempotency-key"],
      );
      const result = await app.issuance.issueForConsumer({
        actor: context.actor,
        consumerId: context.consumerId,
        environment: context.environment,
        grantName: params[0] as string,
        idempotencyKey: key,
        body: parseObjectBody(context.event),
        onTarget: (target) => state.update(target),
      });
      // Record before release: a failed write fails the request, and the retry replays and audits.
      await app.audit.write({
        correlationId: context.correlationId,
        outcome: "succeeded",
        actor: context.actor,
        operation: "pki.certificate.issue",
        target: result.auditTarget,
        sourceIp: context.event.requestContext.http.sourceIp,
      });
      return json(result.status, result.body);
    },
  ),
];
