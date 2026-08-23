import { z } from "zod";

/**
 * Runtime configuration is fetched rather than compiled in, so one immutable
 * bundle deploys to every environment. It is a JSON document rather than an
 * inline script tag specifically so the published Content-Security-Policy can
 * forbid inline script entirely.
 */
const oidcConfig = z.object({
  mode: z.literal("oidc"),
  authority: z.string().url(),
  clientId: z.string().min(1),
  scopes: z.array(z.string().min(1)).min(1),
});

/**
 * Local development against MiniStack, where there is no API Gateway and no
 * identity provider. The dev bridge injects the subject directly. This mode is
 * refused unless the admin API is a loopback address.
 */
const devBridgeConfig = z.object({
  mode: z.literal("dev-bridge"),
  subject: z.string().min(1),
});

const runtimeConfig = z.object({
  deploymentName: z.string().min(1),
  adminApiUrl: z.string().url(),
  environments: z.array(z.string().min(1)).min(1),
  auth: z.discriminatedUnion("mode", [oidcConfig, devBridgeConfig]),
});

export type RuntimeConfig = z.infer<typeof runtimeConfig>;
export type OidcConfig = z.infer<typeof oidcConfig>;

const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export const parseRuntimeConfig = (value: unknown): RuntimeConfig => {
  const parsed = runtimeConfig.parse(value);
  const url = new URL(parsed.adminApiUrl);
  if (parsed.auth.mode === "dev-bridge" && !loopbackHosts.has(url.hostname)) {
    throw new Error(
      "auth.mode 'dev-bridge' is only permitted against a loopback adminApiUrl.",
    );
  }
  if (parsed.auth.mode === "oidc" && url.protocol !== "https:") {
    throw new Error("adminApiUrl must be HTTPS when auth.mode is 'oidc'.");
  }
  return parsed;
};

/**
 * A malformed or missing document is a hard boot failure. A half-configured
 * console would present an administrator with forms that silently target the
 * wrong deployment.
 */
export const loadRuntimeConfig = async (
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<RuntimeConfig> => {
  const response = await fetchImpl("/config.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`config.json could not be loaded (${response.status}).`);
  }
  return parseRuntimeConfig(await response.json());
};
