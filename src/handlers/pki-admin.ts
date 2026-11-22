import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyEventV2WithJWTAuthorizer,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { humanActorFromEvent } from "../auth/actors";
import type { Actor } from "../domain/types";
import type { PkiApplication } from "../pki/app";
import { getPkiApplication, withPkiErrorResponse } from "./pki-shared";
import {
  matchPkiRoute,
  pkiRouteNotAvailable,
  type PkiRoute,
} from "./pki-routes";
import { createErrorResponder, type RequestAuditContext } from "./request";

export interface PkiAdminContext {
  readonly event: APIGatewayProxyEventV2;
  readonly app: PkiApplication;
  readonly actor: Actor;
  readonly correlationId: string;
  readonly setAuditContext: (context: RequestAuditContext) => void;
}

export type PkiAdminRoute = PkiRoute<PkiAdminContext>;

// Routes arrive in later phases; until then every path authenticates and returns a distinctive 404.
export const createPkiAdminHandler =
  (
    routes: readonly PkiAdminRoute[],
    respond: ReturnType<
      typeof createErrorResponder<PkiApplication>
    > = withPkiErrorResponse,
  ) =>
  async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyStructuredResultV2> =>
    respond(event, async (app, correlationId, setAuditContext) => {
      // A bad JWT configuration is a 403 with no audit, as in admin.ts.
      const actor = humanActorFromEvent(
        event as APIGatewayProxyEventV2WithJWTAuthorizer,
        app.config,
      );
      const matched = matchPkiRoute(
        routes,
        event.requestContext.http.method,
        event.rawPath,
      );
      // An unrouted path is not an operation, so it is never audited.
      if (matched === undefined) {
        throw pkiRouteNotAvailable();
      }
      setAuditContext({
        actor,
        operation: matched.route.operation,
        sourceIp: event.requestContext.http.sourceIp,
      });
      return matched.route.handle(
        { event, app, actor, correlationId, setAuditContext },
        matched.params,
      );
    });

export const handler = createPkiAdminHandler([]);
