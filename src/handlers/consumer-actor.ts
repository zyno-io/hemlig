import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { consumerActorFromEvent } from "../auth/actors";
import { IdentityRejectedError } from "../domain/errors";
import type { Actor } from "../domain/types";
import type { Application } from "../app";
import type { RequestAuditContext } from "./shared";

/** One rejected-identity event per fingerprint per window; see the repository. */
const identityRejectionAuditWindowSeconds = 10 * 60;

/**
 * Resolves the consumer actor and sets a provisional audit context at once, so
 * a later failure is recorded. A rejected certificate that parsed is audited
 * with its fingerprint and the `identity_not_active` reason; the original
 * error then propagates unchanged.
 */
export const resolveConsumerActor = async (
  event: APIGatewayProxyEventV2,
  app: Application,
  operation: string,
  setAuditContext: (context: RequestAuditContext) => void,
): Promise<Actor> => {
  const sourceIp = event.requestContext.http.sourceIp;
  let actor: Actor;
  try {
    actor = await consumerActorFromEvent(event, app.repository);
  } catch (error) {
    if (
      error instanceof IdentityRejectedError &&
      (await mayAuditRejection(app, error.actor.id))
    ) {
      setAuditContext({
        actor: error.actor,
        operation,
        sourceIp,
        reasonCode: "identity_not_active",
      });
    }
    throw error;
  }
  setAuditContext({ actor, operation, sourceIp });
  return actor;
};

// Fails open: if the limiter itself errors, the event is still recorded.
const mayAuditRejection = async (
  app: Application,
  fingerprint: string,
): Promise<boolean> => {
  try {
    return await app.repository.claimIdentityRejectionAudit(
      fingerprint,
      identityRejectionAuditWindowSeconds,
    );
  } catch {
    return true;
  }
};
