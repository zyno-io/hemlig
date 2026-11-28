// Pure by design (no aws-cdk-lib import): validation and encoding for the
// provider-neutral OIDC fields. config.ts applies it to CDK context and to
// HemligStack props alike, so both paths enforce the same rules.

export type StringOrList = string | readonly string[];

/** The OIDC fields this module validates. */
export interface OidcExtrasInput {
  readonly oidcAudience?: StringOrList;
  readonly oidcClientId?: string;
  readonly oidcAdminScope?: string;
  readonly oidcAdminRole?: StringOrList;
  readonly oidcPkiCaAdminRole?: StringOrList;
  readonly oidcPkiOperatorRole?: StringOrList;
  readonly oidcRoleClaim?: string;
  readonly oidcAuthorizeParams?: Readonly<Record<string, string>>;
  readonly oidcProviderOrigins?: readonly string[];
}

export interface OidcExtras {
  readonly audiences: readonly string[] | undefined;
  readonly adminRoles: readonly string[] | undefined;
  readonly pkiCaRoles: readonly string[] | undefined;
  readonly pkiOperatorRoles: readonly string[] | undefined;
  readonly roleClaim: string | undefined;
  readonly authorizeParams: Readonly<Record<string, string>> | undefined;
  readonly providerOrigins: readonly string[];
}

/** A list-valued field collapses back to a bare string when it has one entry. */
export const collapse = (values: readonly string[]): string | readonly string[] =>
  values.length === 1 ? (values[0] as string) : values;

export const asList = (value: StringOrList | undefined): readonly string[] =>
  value === undefined ? [] : typeof value === "string" ? [value] : value;

/** Comma-joined form read by the Lambdas (`ADMIN_JWT_AUDIENCE`, `ADMIN_JWT_ROLE`, ...). */
export const joinEnv = (values: readonly string[]): string => values.join(",");

/**
 * Splits a comma-separated context string; an all-string array passes through.
 * An unset (undefined or null) value is `undefined`. Anything else, such as a
 * number or an array holding a non-string, throws: dropping it silently would
 * turn a role or audience restriction off.
 */
export const splitContextList = (
  name: string,
  value: unknown,
): readonly string[] | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (Array.isArray(value)) {
    if (!value.every((entry) => typeof entry === "string")) {
      throw new Error(`context ${name} must be a string or a list of strings.`);
    }
    return value as string[];
  }
  if (typeof value !== "string") {
    throw new Error(`context ${name} must be a string or a list of strings.`);
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    return undefined;
  }
  return trimmed.split(",").map((entry) => entry.trim());
};

const MAX_AUDIENCES = 8;
const MAX_ROLES = 16;
const MAX_ENV_LIST_LENGTH = 1024;
const MAX_POINTER_SEGMENTS = 8;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

const RESERVED_AUTHORIZE_PARAMS: ReadonlySet<string> = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "response_mode",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "request",
  "request_uri",
  "prompt",
]);

const fail = (prefix: string, message: string): never => {
  throw new Error(`${prefix}${message}`);
};

/** Props-path guard: a list field must be a string or an array of strings. */
const assertStringOrList = (
  name: string,
  value: unknown,
  prefix: string,
): void => {
  const ok =
    typeof value === "string" ||
    (Array.isArray(value) && value.every((entry) => typeof entry === "string"));
  if (!ok) {
    fail(prefix, `${name} must be a string or a list of strings.`);
  }
};

// Lambda's environment is limited to 4 KiB in total. The stack's other
// variables use roughly 1.3 KiB on the PKI admin function, so the OIDC
// variables that vary with these fields share a conservative 1.5 KiB.
const MAX_OIDC_ENV_BYTES = 1536;

/** V2: 1-8 audiences, each 1-512 characters, no whitespace or comma, not starting with `[`. */
const normaliseAudiences = (
  value: StringOrList,
  prefix: string,
): readonly string[] => {
  assertStringOrList("oidcAudience", value, prefix);
  const entries = asList(value);
  if (entries.length < 1 || entries.length > MAX_AUDIENCES) {
    fail(prefix, `oidcAudience must list 1 to ${MAX_AUDIENCES} audiences.`);
  }
  for (const entry of entries) {
    if (entry.length === 0) {
      fail(prefix, "oidcAudience must not contain a blank value.");
    }
    if (entry.length > 512) {
      fail(prefix, "oidcAudience must be at most 512 characters.");
    }
    if (/[\s,]/.test(entry) || entry.startsWith("[")) {
      fail(
        prefix,
        "oidcAudience values must not contain whitespace or commas, or start with '['.",
      );
    }
  }
  const unique = [...new Set(entries)];
  if (unique.length > 1 && joinEnv(unique).length > MAX_ENV_LIST_LENGTH) {
    fail(prefix, `oidcAudience list must encode to at most ${MAX_ENV_LIST_LENGTH} characters.`);
  }
  return unique;
};

/**
 * V7: 1-16 role values, each 1-256 printable characters with no comma (the
 * Lambda splits on commas), no leading or trailing space, not starting with
 * `[`. Spaces inside a value are fine ("Hemlig Admins").
 */
const normaliseRoles = (
  name: string,
  value: StringOrList,
  prefix: string,
): readonly string[] => {
  assertStringOrList(name, value, prefix);
  const entries = asList(value);
  if (entries.length < 1 || entries.length > MAX_ROLES) {
    fail(prefix, `${name} must list 1 to ${MAX_ROLES} roles.`);
  }
  for (const entry of entries) {
    if (typeof value === "string" && entry.includes(",")) {
      fail(
        prefix,
        `${name} must be one role value (no comma); pass a list for several roles.`,
      );
    }
    if (
      entry.length < 1 ||
      entry.length > 256 ||
      entry !== entry.trim() ||
      entry.includes(",") ||
      entry.startsWith("[") ||
      CONTROL_CHARACTERS.test(entry)
    ) {
      fail(
        prefix,
        `${name} values must be 1-256 printable characters with no comma, no leading or trailing space, and not starting with '['.`,
      );
    }
  }
  const unique = [...new Set(entries)];
  if (joinEnv(unique).length > MAX_ENV_LIST_LENGTH) {
    fail(prefix, `${name} must encode to at most ${MAX_ENV_LIST_LENGTH} characters.`);
  }
  return unique;
};

/**
 * V6: a top-level claim name (no whitespace, at most 256 characters, not
 * starting with `/`), or an RFC 6901 JSON Pointer of at most 8 non-empty
 * segments whose `~` is always `~0` or `~1`. Same rules as the runtime's
 * assertRoleClaim, plus the length and segment limits.
 */
export const assertRoleClaimSyntax = (claim: string, prefix: string): void => {
  if (claim.length === 0 || claim.length > 256) {
    fail(prefix, "oidcRoleClaim must be 1-256 characters.");
  }
  if (/\s/.test(claim) || CONTROL_CHARACTERS.test(claim)) {
    fail(prefix, "oidcRoleClaim must not contain whitespace.");
  }
  if (!claim.startsWith("/")) {
    return;
  }
  const segments = claim.slice(1).split("/");
  if (segments.length > MAX_POINTER_SEGMENTS) {
    fail(prefix, `oidcRoleClaim JSON Pointer must have at most ${MAX_POINTER_SEGMENTS} segments.`);
  }
  for (const segment of segments) {
    if (segment.length === 0) {
      fail(prefix, "oidcRoleClaim JSON Pointer must not have an empty segment.");
    }
    if (/~(?![01])/.test(segment)) {
      fail(prefix, "oidcRoleClaim is not a valid JSON Pointer ('~' must be '~0' or '~1').");
    }
  }
};

/** V10: at most 8 keys matching `^[a-z_]{1,64}$`, values 1-512 characters, no reserved keys. */
const normaliseAuthorizeParams = (
  value: Readonly<Record<string, string>>,
  prefix: string,
): Readonly<Record<string, string>> | undefined => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(prefix, "oidcAuthorizeParams must be an object of string values.");
  }
  const entries = Object.entries(value);
  if (entries.length === 0) {
    return undefined;
  }
  if (entries.length > 8) {
    fail(prefix, "oidcAuthorizeParams must have at most 8 keys.");
  }
  for (const [key, param] of entries) {
    if (!/^[a-z_]{1,64}$/.test(key)) {
      fail(prefix, `oidcAuthorizeParams key "${key}" must match ^[a-z_]{1,64}$.`);
    }
    if (RESERVED_AUTHORIZE_PARAMS.has(key)) {
      fail(prefix, `oidcAuthorizeParams must not set "${key}"; the console sets it.`);
    }
    if (typeof param !== "string" || param.length < 1 || param.length > 512) {
      fail(prefix, `oidcAuthorizeParams value for "${key}" must be a string of 1-512 characters.`);
    }
  }
  return Object.fromEntries(entries);
};

/** V11: at most 4 bare HTTPS origins (scheme, host and optional port; no path, query or trailing slash). */
const normaliseProviderOrigins = (
  value: readonly string[],
  prefix: string,
): readonly string[] => {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    fail(prefix, "oidcProviderOrigins must be a list of HTTPS origins.");
  }
  if (value.length > 4) {
    fail(prefix, "oidcProviderOrigins must have at most 4 origins.");
  }
  const origins = value.map((origin) => {
    let parsed: URL | undefined;
    try {
      parsed = new URL(origin);
    } catch {
      parsed = undefined;
    }
    if (
      parsed === undefined ||
      parsed.protocol !== "https:" ||
      parsed.origin !== origin ||
      // The origin goes straight into a CSP source list, so reject anything
      // but a plain DNS host and optional port (no `;`, `,`, quotes, `*`).
      !/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?$/.test(origin)
    ) {
      fail(
        prefix,
        `oidcProviderOrigins entry "${origin}" must be a bare HTTPS origin such as https://host.example.com.`,
      );
    }
    return origin;
  });
  return [...new Set(origins)];
};

/**
 * Validates and normalizes the list-valued and console-facing OIDC fields.
 * `prefix` is "context " on the CDK-context path and "" on the props path, so
 * errors name the thing the caller actually set.
 */
export const normaliseOidcExtras = (
  input: OidcExtrasInput,
  prefix: string,
): OidcExtras => {
  const audiences =
    input.oidcAudience === undefined
      ? undefined
      : normaliseAudiences(input.oidcAudience, prefix);
  const adminRoles =
    input.oidcAdminRole === undefined
      ? undefined
      : normaliseRoles("oidcAdminRole", input.oidcAdminRole, prefix);
  const pkiCaRoles =
    input.oidcPkiCaAdminRole === undefined
      ? undefined
      : normaliseRoles("oidcPkiCaAdminRole", input.oidcPkiCaAdminRole, prefix);
  const pkiOperatorRoles =
    input.oidcPkiOperatorRole === undefined
      ? undefined
      : normaliseRoles("oidcPkiOperatorRole", input.oidcPkiOperatorRole, prefix);
  if (input.oidcRoleClaim !== undefined) {
    assertRoleClaimSyntax(input.oidcRoleClaim, prefix);
    // The runtime refuses a claim with no admin role to look for: a role claim
    // alone would enforce nothing, so catch it at synth.
    if (adminRoles === undefined) {
      fail(prefix, "oidcRoleClaim requires oidcAdminRole.");
    }
  }
  // V4 (I1): an audience that is the client ID also accepts the console's ID
  // token, so the scope check must be enforced.
  if (
    input.oidcClientId !== undefined &&
    audiences?.includes(input.oidcClientId) === true &&
    input.oidcAdminScope === undefined
  ) {
    fail(
      prefix,
      "oidcAdminScope is required when an oidcAudience equals oidcClientId (an ID token issued to the same app would otherwise be accepted).",
    );
  }
  const envBytes = [
    audiences ?? (input.oidcClientId === undefined ? [] : [input.oidcClientId]),
    adminRoles ?? [],
    pkiCaRoles ?? [],
    pkiOperatorRoles ?? [],
    input.oidcRoleClaim === undefined ? [] : [input.oidcRoleClaim],
  ].reduce((sum, list) => sum + Buffer.byteLength(joinEnv(list), "utf8"), 0);
  if (envBytes > MAX_OIDC_ENV_BYTES) {
    fail(
      prefix,
      `the audience, role and role-claim values encode to ${envBytes} bytes of Lambda environment; the combined limit is ${MAX_OIDC_ENV_BYTES} (Lambda allows 4096 bytes in total). Shorten or remove some.`,
    );
  }
  return {
    audiences,
    adminRoles,
    pkiCaRoles,
    pkiOperatorRoles,
    roleClaim: input.oidcRoleClaim,
    authorizeParams:
      input.oidcAuthorizeParams === undefined
        ? undefined
        : normaliseAuthorizeParams(input.oidcAuthorizeParams, prefix),
    providerOrigins:
      input.oidcProviderOrigins === undefined
        ? []
        : normaliseProviderOrigins(input.oidcProviderOrigins, prefix),
  };
};
