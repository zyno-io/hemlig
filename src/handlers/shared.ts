import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { createApplication, type Application } from "../app";
import { loadConfig } from "../aws/config";
import { errorResponse } from "../http/responses";
import { newId } from "../util/encoding";
import type { Actor } from "../domain/types";

let application: Application | undefined;

export const getApplication = (): Application => {
  if (application === undefined) {
    application = createApplication(loadConfig());
  }
  return application;
};

export const withErrorResponse = async (
  event: APIGatewayProxyEventV2,
  action: (
    app: Application,
    correlationId: string,
    setAuditContext: (context: RequestAuditContext) => void,
  ) => Promise<APIGatewayProxyStructuredResultV2>,
): Promise<APIGatewayProxyStructuredResultV2> => {
  const correlationId = event.requestContext.requestId || newId();
  let app: Application | undefined;
  let auditContext: RequestAuditContext | undefined;
  try {
    app = getApplication();
    return await action(app, correlationId, (context) => {
      auditContext = context;
    });
  } catch (error) {
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
          reasonCode: "request_failed",
        });
      } catch {
        // The original request failure is more useful to the caller than an audit delivery failure.
      }
    }
    return errorResponse(error, correlationId);
  }
};

interface RequestAuditContext {
  readonly actor: Actor;
  readonly operation: string;
  readonly target?: Readonly<Record<string, string>>;
  readonly permission?: "read";
  readonly sourceIp?: string;
}

export const idempotencyKey = (
  event: APIGatewayProxyEventV2,
): string | undefined => event.headers["idempotency-key"];
