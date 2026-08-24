// Pure by design: this has zero aws-cdk-lib imports so a test can call it directly
// alongside packages/console/src/config.ts's parseRuntimeConfig and catch a shape
// drift between the two at unit-test time instead of at browser boot.
export interface ConsoleRuntimeConfigInput {
  readonly deploymentName: string;
  readonly adminFqdn: string;
  readonly oidcIssuer: string;
  readonly oidcClientId: string;
  /** Resource-qualified scope the browser requests from the identity provider. */
  readonly oidcConsoleAccessScope: string;
}

export const consoleRuntimeConfig = (input: ConsoleRuntimeConfigInput) => ({
  deploymentName: input.deploymentName,
  adminApiUrl: `https://${input.adminFqdn}`,
  auth: {
    mode: "oidc" as const,
    authority: input.oidcIssuer,
    clientId: input.oidcClientId,
    // `email` is a display-only claim. The API continues to authorize and
    // persist the configured immutable subject claim, normally `sub`.
    scopes: ["openid", "profile", "email", input.oidcConsoleAccessScope],
  },
});
