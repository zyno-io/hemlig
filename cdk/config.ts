export interface DeploymentConfig {
  readonly environmentName: string;
  readonly adminFqdn: string;
  /** Public mTLS secret-delivery API endpoint. */
  readonly apiFqdn: string;
  /** Exact HTTPS console origin at this zone, when browser access is enabled. */
  readonly consoleFqdn?: string;
  /** ACM certificate ARN in us-east-1 for the console distribution. */
  readonly consoleCertificateArn?: string;
  readonly zoneDomain: string;
  readonly oidcIssuer: string;
  /**
   * Exact access-token `aud`. Defaults to oidcClientId (one app registration),
   * which then requires oidcAdminScope. Set it for a split API and console app
   * or an API-only deployment without oidcClientId.
   */
  readonly oidcAudience?: string;
  readonly oidcSubjectClaim: string;
  /** Required administrator OAuth scope when the console origin is enabled. */
  readonly oidcAdminScope?: string;
  /**
   * Resource-qualified OAuth scope requested by the console SPA, for example
   * `api://<application-id>/hemlig.admin` on Microsoft Entra. This differs
   * from oidcAdminScope, the short value enforced from the access token's
   * `scp` claim by API Gateway. Defaults, when oidcAdminScope and
   * oidcClientId are set, to `api://<audience>/<oidcAdminScope>` on Microsoft
   * Entra issuers and to oidcAdminScope as-is on any other issuer.
   */
  readonly oidcConsoleAccessScope?: string;
  /** Optional external IdP role required by the Lambda after JWT validation. */
  readonly oidcAdminRole?: string;
  /** Optional IdP role additionally required for PKI CA lifecycle and root CRL upload. */
  readonly oidcPkiCaAdminRole?: string;
  /** Optional IdP role additionally required for grants, admin issuance, revocation and CRL force-publish. */
  readonly oidcPkiOperatorRole?: string;
  /** Stage throttle on POST /v1/pki/{proxy+} (requests/s). Default 20. */
  readonly pkiIssuanceRateLimit?: number;
  /** Stage burst on POST /v1/pki/{proxy+}. Default 40. */
  readonly pkiIssuanceBurstLimit?: number;
  /** OAuth client id the console SPA authenticates as; required when consoleFqdn is configured. */
  readonly oidcClientId?: string;
  readonly existingHostedZoneId?: string;
  /** Existing Hemlig application CMK to adopt instead of creating a new key. */
  readonly existingApplicationKeyArn?: string;
  /**
   * CDK bootstrap qualifier to reuse for the optional sibling console-certificate
   * stack. Supply this whenever the parent stack uses a non-default synthesizer.
   */
  readonly bootstrapQualifier?: string;
  /**
   * Turn on AWS X-Ray active tracing for every Lambda function. Off by default:
   * the functions carry no X-Ray instrumentation beyond the invoke segment, and
   * stored traces can be the largest line on a small deployment's bill.
   * Errors are still visible through CloudWatch Logs and Lambda metrics.
   */
  readonly tracing?: boolean;
}

/** Entra cloud hosts whose resource-qualified scopes take the `api://<app>/<scope>` form. */
const ENTRA_ISSUER_HOSTS: ReadonlySet<string> = new Set([
  "login.microsoftonline.com",
  "login.microsoftonline.us",
  "login.chinacloudapi.cn",
]);

const isEntraIssuer = (issuer: string): boolean => {
  try {
    return ENTRA_ISSUER_HOSTS.has(new URL(issuer).hostname.toLowerCase());
  } catch {
    return false;
  }
};

/** The console scope derived for one app: `api://<audience>/<scope>` on Entra, the bare scope elsewhere. */
export const deriveConsoleAccessScope = (
  issuer: string,
  audience: string,
  adminScope: string,
): string => (isEntraIssuer(issuer) ? `api://${audience}/${adminScope}` : adminScope);

/** The OIDC fields that resolveOidcDefaults fills in. */
export interface OidcDefaultsInput {
  readonly oidcIssuer: string;
  readonly oidcAudience?: string;
  readonly oidcClientId?: string;
  readonly oidcAdminScope?: string;
  readonly oidcConsoleAccessScope?: string;
}

const present = (value: string | undefined): string | undefined =>
  value === undefined || value.trim() === "" ? undefined : value;

/**
 * Applies the one-app OIDC defaults, so a deployment names its client ID once:
 * `oidcAudience` defaults to `oidcClientId`, and `oidcConsoleAccessScope` is
 * derived from `oidcAdminScope` (see deriveConsoleAccessScope). Explicit values
 * always win. A derived audience requires `oidcAdminScope`: with one app an ID
 * token carries the same `aud`, and the `scp` check is what rejects it.
 * HemligStack applies this to its props; deploymentConfigFromContext applies
 * the same rules with context-named errors.
 */
export const resolveOidcDefaults = <T extends OidcDefaultsInput>(
  config: T,
): T & { readonly oidcAudience: string } => {
  // A blank value that was set (an unset variable, say) must not quietly become
  // the client ID: that could point a split-app deployment at the wrong app.
  for (const [name, value] of [
    ["oidcAudience", config.oidcAudience],
    ["oidcConsoleAccessScope", config.oidcConsoleAccessScope],
  ] as const) {
    if (value !== undefined && present(value) === undefined) {
      throw new Error(`${name} must not be blank; omit it to use the default.`);
    }
  }
  const explicitAudience = present(config.oidcAudience);
  const clientId = present(config.oidcClientId);
  const adminScope = present(config.oidcAdminScope);
  const audience = explicitAudience ?? clientId;
  if (audience === undefined) {
    throw new Error(
      "set oidcClientId (or oidcAudience for an API-only deployment without the console)",
    );
  }
  if (explicitAudience === undefined && adminScope === undefined) {
    throw new Error(
      "oidcAdminScope is required when oidcAudience is omitted (it defaults to oidcClientId, and the scope check is what rejects ID tokens issued to the same app).",
    );
  }
  const consoleAccessScope =
    present(config.oidcConsoleAccessScope) ??
    (adminScope !== undefined && clientId !== undefined
      ? deriveConsoleAccessScope(config.oidcIssuer, audience, adminScope)
      : undefined);
  return {
    ...config,
    oidcAudience: audience,
    ...(consoleAccessScope === undefined ? {} : { oidcConsoleAccessScope: consoleAccessScope }),
  };
};

export const DEFAULT_PKI_ISSUANCE_RATE_LIMIT = 20;
export const DEFAULT_PKI_ISSUANCE_BURST_LIMIT = 40;

export const assertPkiIssuanceThrottle = (
  rate: number,
  burst: number,
): void => {
  if (!Number.isInteger(rate) || rate < 1 || rate > 5000) {
    throw new Error("pkiIssuanceRateLimit must be an integer from 1 to 5000.");
  }
  if (!Number.isInteger(burst) || burst < 1 || burst > 5000) {
    throw new Error("pkiIssuanceBurstLimit must be an integer from 1 to 5000.");
  }
  if (burst < rate) {
    throw new Error(
      "pkiIssuanceBurstLimit must be at least pkiIssuanceRateLimit.",
    );
  }
};

export const deploymentConfigFromContext = (context: {
  tryGetContext(name: string): unknown;
}): DeploymentConfig => {
  const environmentName = (
    optionalContext(context, "environment") ?? "dev"
  ).toLowerCase();
  const adminFqdn = requiredContext(context, "adminFqdn").toLowerCase();
  const apiFqdn = requiredContext(context, "apiFqdn").toLowerCase();
  const consoleFqdn = optionalContext(context, "consoleFqdn")?.toLowerCase();
  const consoleCertificateArn = optionalContext(
    context,
    "consoleCertificateArn",
  );
  const zoneDomain = requiredContext(context, "zoneDomain").toLowerCase();
  const oidcIssuer = requiredContext(context, "oidcIssuer");
  const oidcSubjectClaim =
    optionalContext(context, "oidcSubjectClaim") ?? "sub";
  const oidcAdminScope = optionalContext(context, "oidcAdminScope");
  const explicitConsoleAccessScope = optionalContext(
    context,
    "oidcConsoleAccessScope",
  );
  const oidcAdminRole = optionalContext(context, "oidcAdminRole");
  const oidcPkiCaAdminRole = optionalContext(context, "oidcPkiCaAdminRole");
  const oidcPkiOperatorRole = optionalContext(context, "oidcPkiOperatorRole");
  const pkiIssuanceRateLimit = optionalIntegerContext(
    context,
    "pkiIssuanceRateLimit",
  );
  const pkiIssuanceBurstLimit = optionalIntegerContext(
    context,
    "pkiIssuanceBurstLimit",
  );
  const oidcClientId = optionalContext(context, "oidcClientId");
  const explicitAudience = optionalContext(context, "oidcAudience");
  const oidcAudience = explicitAudience ?? oidcClientId;
  if (oidcAudience === undefined) {
    throw new Error(
      "set oidcClientId (or oidcAudience for an API-only deployment without the console)",
    );
  }
  const oidcConsoleAccessScope =
    explicitConsoleAccessScope ??
    (oidcAdminScope !== undefined && oidcClientId !== undefined
      ? deriveConsoleAccessScope(oidcIssuer, oidcAudience, oidcAdminScope)
      : undefined);
  const existingHostedZoneId = optionalContext(context, "existingHostedZoneId");
  const existingApplicationKeyArn = optionalContext(
    context,
    "existingApplicationKeyArn",
  );
  const bootstrapQualifier = optionalContext(context, "bootstrapQualifier");
  const tracingContext = context.tryGetContext("tracing");
  if (
    tracingContext !== undefined &&
    tracingContext !== true &&
    tracingContext !== false &&
    tracingContext !== "true" &&
    tracingContext !== "false"
  ) {
    throw new Error('context tracing must be "true" or "false".');
  }
  const tracing = tracingContext === true || tracingContext === "true";
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(environmentName)) {
    throw new Error("context environment must match ^[a-z][a-z0-9-]{1,31}$");
  }
  for (const [name, value] of Object.entries({
    adminFqdn,
    apiFqdn,
    zoneDomain,
    consoleFqdn,
  })) {
    if (value === undefined) {
      continue;
    }
    if (!isFqdn(value)) {
      throw new Error(`context ${name} must be a lowercase FQDN.`);
    }
  }
  const configuredFqdns =
    consoleFqdn === undefined
      ? [adminFqdn, apiFqdn]
      : [adminFqdn, apiFqdn, consoleFqdn];
  if (new Set(configuredFqdns).size !== configuredFqdns.length) {
    throw new Error("adminFqdn, apiFqdn, and consoleFqdn must be different.");
  }
  if (
    !isInZone(adminFqdn, zoneDomain) ||
    !isInZone(apiFqdn, zoneDomain) ||
    (consoleFqdn !== undefined && !isInZone(consoleFqdn, zoneDomain))
  ) {
    throw new Error(
      "adminFqdn, apiFqdn, and consoleFqdn must be within zoneDomain.",
    );
  }
  if (!isHttpsUrl(oidcIssuer)) {
    throw new Error("context oidcIssuer must be an HTTPS issuer URL.");
  }
  if (oidcAudience.length > 512) {
    throw new Error("context oidcAudience must be at most 512 characters.");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(oidcSubjectClaim)) {
    throw new Error("context oidcSubjectClaim is not a valid JWT claim name.");
  }
  // With one app, an Entra ID token has aud == client ID. The scp check is what
  // rejects it, so a derived audience must come with an enforced admin scope.
  if (explicitAudience === undefined && oidcAdminScope === undefined) {
    throw new Error(
      "context oidcAdminScope is required when oidcAudience is omitted (it defaults to oidcClientId, and the scope check is what rejects ID tokens issued to the same app).",
    );
  }
  if (consoleFqdn !== undefined && oidcAdminScope === undefined) {
    throw new Error(
      "context oidcAdminScope is required when consoleFqdn is configured.",
    );
  }
  if (consoleFqdn !== undefined && oidcClientId === undefined) {
    throw new Error(
      "context oidcClientId is required when consoleFqdn is configured.",
    );
  }
  if (consoleFqdn !== undefined && oidcConsoleAccessScope === undefined) {
    throw new Error(
      "context oidcConsoleAccessScope is required when consoleFqdn is configured.",
    );
  }
  if (
    oidcAdminScope !== undefined &&
    !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcAdminScope)
  ) {
    throw new Error("context oidcAdminScope must be one OAuth scope token.");
  }
  if (
    oidcConsoleAccessScope !== undefined &&
    !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcConsoleAccessScope)
  ) {
    throw new Error(
      "context oidcConsoleAccessScope must be one OAuth scope token.",
    );
  }
  if (
    oidcAdminRole !== undefined &&
    !/^[A-Za-z0-9._:/-]{1,256}$/.test(oidcAdminRole)
  ) {
    throw new Error("context oidcAdminRole must be one role token.");
  }
  for (const [name, value] of Object.entries({
    oidcPkiCaAdminRole,
    oidcPkiOperatorRole,
  })) {
    if (value !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) {
      throw new Error(`context ${name} must be one role token.`);
    }
  }
  assertPkiIssuanceThrottle(
    pkiIssuanceRateLimit ?? DEFAULT_PKI_ISSUANCE_RATE_LIMIT,
    pkiIssuanceBurstLimit ?? DEFAULT_PKI_ISSUANCE_BURST_LIMIT,
  );
  if (consoleCertificateArn !== undefined && consoleFqdn === undefined) {
    throw new Error(
      "context consoleCertificateArn must not be supplied unless consoleFqdn is configured.",
    );
  }
  if (
    bootstrapQualifier !== undefined &&
    !/^[a-z0-9]{1,10}$/.test(bootstrapQualifier)
  ) {
    throw new Error(
      "context bootstrapQualifier must contain 1-10 lowercase letters or digits.",
    );
  }
  if (
    existingApplicationKeyArn !== undefined &&
    !/^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/.test(
      existingApplicationKeyArn,
    )
  ) {
    throw new Error(
      "context existingApplicationKeyArn must be a complete KMS key ARN.",
    );
  }
  // CloudFront only accepts certificates issued in us-east-1, regardless of which
  // region the rest of the stack deploys to.
  if (
    consoleCertificateArn !== undefined &&
    !isUsEast1CertificateArn(consoleCertificateArn)
  ) {
    throw new Error(
      "context consoleCertificateArn must be an ACM certificate ARN in us-east-1, because CloudFront only accepts certificates from that region.",
    );
  }
  return {
    environmentName,
    adminFqdn,
    apiFqdn,
    ...(consoleFqdn === undefined ? {} : { consoleFqdn }),
    ...(consoleCertificateArn === undefined ? {} : { consoleCertificateArn }),
    zoneDomain,
    oidcIssuer,
    oidcAudience,
    oidcSubjectClaim,
    ...(oidcAdminScope === undefined ? {} : { oidcAdminScope }),
    ...(oidcConsoleAccessScope === undefined ? {} : { oidcConsoleAccessScope }),
    ...(oidcAdminRole === undefined ? {} : { oidcAdminRole }),
    ...(oidcPkiCaAdminRole === undefined ? {} : { oidcPkiCaAdminRole }),
    ...(oidcPkiOperatorRole === undefined ? {} : { oidcPkiOperatorRole }),
    ...(pkiIssuanceRateLimit === undefined ? {} : { pkiIssuanceRateLimit }),
    ...(pkiIssuanceBurstLimit === undefined ? {} : { pkiIssuanceBurstLimit }),
    ...(oidcClientId === undefined ? {} : { oidcClientId }),
    ...(existingHostedZoneId === undefined ? {} : { existingHostedZoneId }),
    ...(existingApplicationKeyArn === undefined
      ? {}
      : { existingApplicationKeyArn }),
    ...(bootstrapQualifier === undefined ? {} : { bootstrapQualifier }),
    ...(tracing ? { tracing } : {}),
  };
};

/**
 * CloudFront only accepts ACM certificates issued in us-east-1. Exported so both
 * the CDK-context path (above) and library installers constructing HemligStack
 * directly (cdk/stack.ts) reject a wrong-region ARN at synth time rather than
 * discovering it as a CloudFormation deployment failure.
 */
export const isUsEast1CertificateArn = (value: string): boolean =>
  /^arn:aws[a-zA-Z-]*:acm:us-east-1:\d{12}:certificate\/[0-9a-f-]{36}$/.test(
    value,
  );

const requiredContext = (
  context: { tryGetContext(name: string): unknown },
  name: string,
): string => {
  const value = optionalContext(context, name);
  if (value === undefined) {
    throw new Error(`Missing CDK context value: ${name}`);
  }
  return value;
};

const optionalContext = (
  context: { tryGetContext(name: string): unknown },
  name: string,
): string | undefined => {
  const value = context.tryGetContext(name);
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
};

const optionalIntegerContext = (
  context: { tryGetContext(name: string): unknown },
  name: string,
): number | undefined => {
  const value = context.tryGetContext(name);
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return value;
  }
  if (typeof value === "string" && /^[0-9]{1,6}$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (parsed > 0) {
      return parsed;
    }
  }
  throw new Error(`context ${name} must be a positive integer.`);
};

const isFqdn = (value: string): boolean =>
  value.length <= 253 &&
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(
    value,
  );

const isInZone = (fqdn: string, zone: string): boolean =>
  fqdn === zone || fqdn.endsWith(`.${zone}`);

const isHttpsUrl = (value: string): boolean => {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
};
