import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { ApiError } from "../domain/errors";
import type { Actor } from "../domain/types";
import { errorResponse } from "../http/responses";
import type { AuditWriter } from "../services/audit";
import { newId } from "../util/encoding";

// Shared by the generic and PKI Lambdas. This module must not import ../app,
// which builds every service (including the IoT and API Gateway clients).

export interface AuditingApplication {
  readonly audit: Pick<AuditWriter, "write">;
}

export interface RequestAuditContext {
  readonly actor: Actor;
  readonly operation: string;
  readonly target?: Readonly<Record<string, string>>;
  readonly permission?: "read";
  readonly sourceIp?: string;
  readonly reasonCode?: string;
}

export const idempotencyKey = (
  event: APIGatewayProxyEventV2,
): string | undefined => event.headers["idempotency-key"];

export const createErrorResponder =
  <A extends AuditingApplication>(getApp: () => A) =>
  async (
    event: APIGatewayProxyEventV2,
    action: (
      app: A,
      correlationId: string,
      setAuditContext: (context: RequestAuditContext | undefined) => void,
    ) => Promise<APIGatewayProxyStructuredResultV2>,
  ): Promise<APIGatewayProxyStructuredResultV2> => {
    const correlationId = event.requestContext.requestId || newId();
    let app: A | undefined;
    let auditContext: RequestAuditContext | undefined;
    try {
      app = getApp();
      return await action(app, correlationId, (context) => {
        auditContext = context;
      });
    } catch (error) {
      // Never log the request body or headers: bootstrap capabilities and secret
      // values can appear there.  A correlation ID plus the error is sufficient
      // to diagnose an unexpected 5xx from its Lambda log stream.
      if (!(error instanceof ApiError)) {
        console.error("Hemlig request failed unexpectedly", {
          correlationId,
          name: error instanceof Error ? error.name : typeof error,
          message: error instanceof Error ? error.message : String(error),
          ...(error instanceof Error && error.stack !== undefined
            ? { stack: error.stack }
            : {}),
        });
      }
      if (app !== undefined && auditContext !== undefined) {
        try {
          await app.audit.write({
            correlationId,
            outcome: "failed",
            actor: auditContext.actor,
            operation: auditContext.operation,
            target: auditContext.target,
            permission: auditContext.permission,
            sourceIp: auditContext.sourceIp,
            reasonCode:
              auditContext.reasonCode ??
              (error instanceof ApiError ? error.safeReason : undefined) ??
              "request_failed",
          });
        } catch {
          // The original request failure is more useful to the caller than an audit delivery failure.
        }
      }
      return errorResponse(error, correlationId);
    }
  };
