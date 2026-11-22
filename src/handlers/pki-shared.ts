import { loadPkiConfig } from "../aws/config";
import { createPkiApplication, type PkiApplication } from "../pki/app";
import { createErrorResponder } from "./request";

let application: PkiApplication | undefined;

export const getPkiApplication = (): PkiApplication =>
  (application ??= createPkiApplication(loadPkiConfig()));

export const withPkiErrorResponse = createErrorResponder(getPkiApplication);
