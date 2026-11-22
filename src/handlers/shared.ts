import { createApplication, type Application } from "../app";
import { loadConfig } from "../aws/config";
import { createErrorResponder } from "./request";

let application: Application | undefined;

export const getApplication = (): Application => {
  if (application === undefined) {
    application = createApplication(loadConfig());
  }
  return application;
};

export const withErrorResponse = createErrorResponder(getApplication);

export { idempotencyKey, type RequestAuditContext } from "./request";
