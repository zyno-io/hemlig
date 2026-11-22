import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { forbidden } from "../domain/errors";
import type { Actor } from "../domain/types";
import type { PkiApplication } from "../pki/app";
import { resolveConsumerActor } from "./consumer-actor";
import { pkiIssuerRoutes } from "./pki-issuer-routes";
import { withPkiErrorResponse } from "./pki-shared";
import {
  matchPkiRoute,
  pkiRouteNotAvailable,
  type PkiRoute,
} from "./pki-routes";
import { createErrorResponder, type RequestAuditContext } from "./request";

export interface PkiIssuerContext {
  readonly event: APIGatewayProxyEventV2;
  readonly app: PkiApplication;
  readonly actor: Actor;
  readonly consumerId: string;
  readonly environment: string;
  readonly correlationId: string;
  readonly setAuditContext: (context: RequestAuditContext | undefined) => void;
}

export type PkiIssuerRoute = PkiRoute<PkiIssuerContext>;

export const createPkiIssuerHandler =
  (
    routes: readonly PkiIssuerRoute[],
    respond: ReturnType<
      typeof createErrorResponder<PkiApplication>
    > = withPkiErrorResponse,
  ) =>
  async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyStructuredResultV2> =>
    respond(event, async (app, correlationId, setAuditContext) => {
      const matched = matchPkiRoute(
        routes,
        event.requestContext.http.method,
        event.rawPath,
      );
      // Identity rejections stay audited and rate-limited; a 404 is never audited.
      const actor = await resolveConsumerActor(
        event,
        app,
        matched?.route.operation ?? "pki.unrouted",
        (context) => {
          if (matched !== undefined || context.reasonCode !== undefined) {
            setAuditContext(context);
          }
        },
      );
      const { consumerId, environment } = actor;
      if (consumerId === undefined || environment === undefined) {
        throw forbidden();
      }
      if (matched === undefined) {
        throw pkiRouteNotAvailable();
      }
      return matched.route.handle(
        {
          event,
          app,
          actor,
          consumerId,
          environment,
          correlationId,
          setAuditContext,
        },
        matched.params,
      );
    });

export const handler = createPkiIssuerHandler(pkiIssuerRoutes);
