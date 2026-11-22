import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import { notFound } from "../domain/errors";

export type PkiRouteMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface PkiRoute<Context> {
  readonly method: PkiRouteMethod;
  /** Anchored; matched against the raw path. Capture groups become `params`. */
  readonly pattern: RegExp;
  /** The audit operation name, for example `pki.ca.create`. */
  readonly operation: string;
  readonly handle: (
    context: Context,
    params: string[],
  ) => Promise<APIGatewayProxyStructuredResultV2>;
}

export const matchPkiRoute = <Context>(
  routes: readonly PkiRoute<Context>[],
  method: string,
  rawPath: string,
): { route: PkiRoute<Context>; params: string[] } | undefined => {
  for (const route of routes) {
    if (route.method !== method) {
      continue;
    }
    const match = route.pattern.exec(rawPath);
    if (match !== null) {
      return { route, params: match.slice(1) };
    }
  }
  return undefined;
};

/**
 * The distinct message lets an operator tell this 404 (the request reached a PKI Lambda) from the `$default`
 * Lambdas' 404.
 */
export const pkiRouteNotAvailable = () =>
  notFound("This PKI route is not available.");
