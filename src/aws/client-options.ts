import type { AppConfig } from "./config";

/**
 * Shared by the full and PKI client factories. It lives apart from clients.ts so
 * the PKI Lambdas never import the IoT and API Gateway SDKs.
 */
export const awsClientOptions = (config: AppConfig) =>
  config.awsEndpointUrl === undefined
    ? { region: config.region }
    : {
        region: config.region,
        endpoint: config.awsEndpointUrl,
        forcePathStyle: true,
      };
