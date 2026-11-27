import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyEventV2WithJWTAuthorizer,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { adminTokenFromEvent } from "../auth/admin-token";
import type { Actor } from "../domain/types";
import type { PkiApplication } from "../pki/app";
import { withPkiErrorResponse } from "./pki-shared";
import { pkiAdminRoutes } from "./pki-admin-routes";
import { assertPkiRole } from "./pki-http";
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
  readonly operation: string;
  readonly correlationId: string;
  readonly setAuditContext: (context: RequestAuditContext | undefined) => void;
}

export type PkiAdminRoute = PkiRoute<PkiAdminContext>;

// Every path authenticates first; an unrouted path returns a distinctive 404 and is never audited.
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
      const { actor, roleValues } = adminTokenFromEvent(
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
      const subject = matched.params[0];
      const target =
        matched.route.auditTarget?.(matched.params) ??
        (subject === undefined
          ? undefined
          : subject.startsWith("ext-")
            ? { extId: subject }
            : { caId: subject });
      setAuditContext({
        actor,
        operation: matched.route.operation,
        sourceIp: event.requestContext.http.sourceIp,
        ...(target === undefined ? {} : { target }),
      });
      // After the audit context is set, so a missing role is an audited failure with reason `pki_role_required`.
      assertPkiRole(
        roleValues,
        app.config,
        matched.route.role ?? "read",
      );
      return matched.route.handle(
        {
          event,
          app,
          actor,
          operation: matched.route.operation,
          correlationId,
          setAuditContext,
        },
        matched.params,
      );
    });

export const handler = createPkiAdminHandler(pkiAdminRoutes);
