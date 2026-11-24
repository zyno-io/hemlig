import { randomUUID } from "node:crypto";
import * as pulumi from "@pulumi/pulumi";
import {
  HemligClient,
  HemligError,
  type PkiCaDetail,
  type PkiCaKind,
  type PkiCaPolicy,
  type PkiCaPolicyInput,
  type PkiCaSubject,
  type PkiCaSummary,
  type PkiCreateCaRequest,
  type PkiCreateIssuanceGrantRequest,
  type PkiGrantNames,
  type PkiGrantPolicyFields,
  type PkiGrantQuotas,
  type PkiIssuanceGrant,
  type PkiIssuanceGrantInput,
  type PkiKeyAlgorithm,
  type PkiLeafKeyAlgorithm,
  type PkiRequestedConstraints,
  type PkiWarning,
} from "@zyno-io/hemlig-client";
import { NodeHttpsTransport } from "@zyno-io/hemlig-client/node";

// This module must not import "./index": index imports this module to expose
// the factory methods, and a cycle would leave one of them half-initialized.

/**
 * The only client methods the PKI providers can reach. Destroy-key, abandon,
 * CA revocation, bulk revocation and root CRL upload are deliberately absent,
 * so automation can never perform them: this is enforced at compile time.
 */
export type HemligCaClient = Pick<
  HemligClient,
  | "listPkiCas"
  | "getPkiCa"
  | "createPkiCa"
  | "updatePkiCa"
  | "activatePkiCa"
  | "retirePkiCa"
  | "listCaIssuanceGrants"
  | "getAdminIssuanceGrant"
>;

export type HemligGrantClient = Pick<
  HemligClient,
  | "getAdminIssuanceGrant"
  | "createIssuanceGrant"
  | "updateIssuanceGrant"
  | "deleteIssuanceGrant"
>;

type CaClientFactory = (inputs: {
  readonly adminUrl: string;
}) => HemligCaClient;
type GrantClientFactory = (inputs: {
  readonly adminUrl: string;
}) => HemligGrantClient;
type AdminTokenSource = () => string;

const ROLLOVER_MESSAGE =
  "Create a new CertificateAuthority with a new name and DN, migrate grants, then remove this one (rollover). CA names and DNs are never reused.";

const DEFAULT_RETRY_DELAYS_MS: readonly number[] = [250, 1000];

// ---------------------------------------------------------------------------
// Shared mechanics
// ---------------------------------------------------------------------------

/**
 * Read inside every method, never at module or constructor scope: Pulumi
 * serializes the provider closure into state, so a captured token would land
 * there.
 */
const adminTokenFromEnvironment = (): string => {
  const token = process.env.HEMLIG_ADMIN_TOKEN;
  if (!token) {
    throw new Error(
      "HEMLIG_ADMIN_TOKEN is required for Hemlig control-plane mutations.",
    );
  }
  return token;
};

const caClientFor: CaClientFactory = (inputs) =>
  new HemligClient(new URL(inputs.adminUrl), new NodeHttpsTransport());

const grantClientFor: GrantClientFactory = (inputs) =>
  new HemligClient(new URL(inputs.adminUrl), new NodeHttpsTransport());

const isUnknown = (value: unknown): boolean =>
  value === pulumi.runtime.unknownValue;

const containsUnknown = (value: unknown): boolean => {
  if (isUnknown(value)) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.some(containsUnknown);
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value).some(containsUnknown);
  }
  return false;
};

const stableJson = (value: unknown): string =>
  JSON.stringify(value, (_key, inner: unknown) => {
    if (inner !== null && typeof inner === "object" && !Array.isArray(inner)) {
      const sorted: Record<string, unknown> = {};
      for (const key of Object.keys(inner).sort()) {
        sorted[key] = (inner as Record<string, unknown>)[key];
      }
      return sorted;
    }
    return inner;
  });

/** Drops undefined members (deeply) so absent optionals are never sent. */
const clean = <T>(value: T): T =>
  JSON.parse(JSON.stringify(value) ?? "null") as T;

const sameJson = (a: unknown, b: unknown): boolean =>
  stableJson(clean(a)) === stableJson(clean(b));

const sortedSet = (values: readonly string[]): string =>
  JSON.stringify([...new Set(values)].sort());

/** Compares PEM text by its base64 bodies, ignoring labels and whitespace. */
export const pemBodiesEqual = (
  a: string | undefined,
  b: string | undefined,
): boolean => {
  if (a === undefined || b === undefined) {
    return a === b;
  }
  const body = (pem: string): string =>
    pem.replace(/-----(BEGIN|END)[^-]*-----/g, "").replace(/\s+/g, "");
  return body(a) === body(b);
};

const describeError = (error: unknown): string => {
  if (error instanceof HemligError) {
    const reason = error.details?.reason;
    const code = error.code ?? `http_${error.status}`;
    return `${code}${reason === undefined ? "" : `/${String(reason)}`}: ${error.message}`;
  }
  return error instanceof Error ? error.message : String(error);
};

/** Strips the administrator token from any message before it can escape. */
const redact = (text: string): string => {
  const token = process.env.HEMLIG_ADMIN_TOKEN;
  return token ? text.split(token).join("[redacted]") : text;
};

const failure = (context: string, error: unknown): Error =>
  new Error(redact(`${context}: ${describeError(error)}`));

const plainError = (message: string): Error => new Error(redact(message));

const hasStatus = (error: unknown, status: number): boolean =>
  error instanceof HemligError && error.status === status;

const hasReason = (error: unknown, code: string, reason?: string): boolean =>
  error instanceof HemligError &&
  error.code === code &&
  (reason === undefined || error.details?.reason === reason);

const isAmbiguous = (error: unknown): boolean =>
  !(error instanceof HemligError) || [500, 502, 503, 504].includes(error.status);

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Runs `op` with a fresh random idempotency key. A key is reused only to retry
 * an ambiguous failure (network error or 5xx), at most three attempts in
 * total. Anything that changes the request, such as a new `If-Match`, must
 * start a new `withKey` call. Keys are never derived from request content,
 * because PKI replay records have no TTL.
 */
export const withKey = async <T>(
  prefix: string,
  op: (key: string) => Promise<T>,
  delaysMs: readonly number[] = DEFAULT_RETRY_DELAYS_MS,
): Promise<T> => {
  const key = `pulumi-${prefix}-${randomUUID()}`;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await op(key);
    } catch (error) {
      if (attempt >= 3 || !isAmbiguous(error)) {
        throw error;
      }
      await delay(delaysMs[attempt - 1] ?? 0);
    }
  }
};

// Built at runtime so the serialized provider source (`__provider`) never
// contains the literal marker, and a stack export stays free of it.
// A function, not a constant: the serializer would inline a constant's value.
const pkMarker = (): string => ["PRIVATE", "KEY-----"].join(" ");

const rejectPrivateKeys = (
  inputs: Record<string, unknown>,
  keys: readonly string[],
): string[] =>
  JSON.stringify(clean(pick(inputs, keys))).includes(pkMarker())
    ? ["Inputs must never contain private key material."]
    : [];

const listAllCas = async (
  client: HemligCaClient,
  token: string,
  environment: string,
): Promise<readonly PkiCaSummary[]> => {
  // A single page: an environment holds at most 50 CAs.
  const page = await client.listPkiCas(token, { environment });
  return page.cas;
};

// ---------------------------------------------------------------------------
// hemlig.CertificateAuthority
// ---------------------------------------------------------------------------

export interface HemligCertificateAuthorityArgs {
  readonly environment: pulumi.Input<string>;
  readonly name: pulumi.Input<string>;
  readonly kind: pulumi.Input<PkiCaKind>;
  readonly keyAlgorithm: pulumi.Input<PkiKeyAlgorithm>;
  readonly subject: pulumi.Input<PkiCaSubject>;
  /** INTERMEDIATE only (required there). */
  readonly parentCaId?: pulumi.Input<string>;
  /** ROOT and INTERMEDIATE only; used at create. */
  readonly validitySeconds?: pulumi.Input<number>;
  readonly requestedConstraints?: pulumi.Input<PkiRequestedConstraints>;
  /** Updated in place. An omitted key keeps the stored value. */
  readonly policy?: pulumi.Input<PkiCaPolicyInput>;
  readonly displayName?: pulumi.Input<string>;
  /** EXTERNAL_INTERMEDIATE only. Write-once, with `chainPem`. */
  readonly signedCertificatePem?: pulumi.Input<string>;
  readonly chainPem?: pulumi.Input<string>;
  readonly acceptBroaderConstraints?: pulumi.Input<boolean>;
}

export interface ResolvedCertificateAuthorityInputs {
  readonly adminUrl: string;
  readonly providerSchemaVersion: string;
  readonly environment: string;
  readonly name: string;
  readonly kind: PkiCaKind;
  readonly keyAlgorithm: PkiKeyAlgorithm;
  readonly subject: PkiCaSubject;
  readonly parentCaId?: string;
  readonly validitySeconds?: number;
  readonly requestedConstraints?: PkiRequestedConstraints;
  readonly policy?: PkiCaPolicyInput;
  readonly displayName?: string;
  readonly signedCertificatePem?: string;
  readonly chainPem?: string;
  readonly acceptBroaderConstraints?: boolean;
}

export interface ResolvedCertificateAuthorityState
  extends ResolvedCertificateAuthorityInputs {
  readonly caId: string;
  readonly status: string;
  readonly version: string;
  readonly keyState: string;
  readonly subjectDn: string;
  readonly csrPem?: string;
  readonly certificatePem?: string;
  readonly issuerChainPem?: string;
  readonly fingerprint?: string;
  readonly serial?: string;
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly rootCrlExtId?: string;
  readonly rootCrlState?: string;
  readonly warnings?: readonly PkiWarning[];
}

const CA_INPUT_KEYS = [
  "adminUrl",
  "providerSchemaVersion",
  "environment",
  "name",
  "kind",
  "keyAlgorithm",
  "subject",
  "parentCaId",
  "validitySeconds",
  "requestedConstraints",
  "policy",
  "displayName",
  "signedCertificatePem",
  "chainPem",
  "acceptBroaderConstraints",
] as const;

const POLICY_KEYS = [
  "maxLeafLifetimeSeconds",
  "leafKeyAlgorithms",
  "capacity",
  "issuancePerHour",
  "crlValiditySeconds",
] as const satisfies readonly (keyof PkiCaPolicyInput)[];

const pick = <T extends object>(
  source: T,
  keys: readonly string[],
): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const value = (source as Record<string, unknown>)[key];
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
};

const policyValueDiffers = (
  key: (typeof POLICY_KEYS)[number],
  declared: unknown,
  actual: unknown,
): boolean =>
  key === "leafKeyAlgorithms"
    ? sortedSet(declared as readonly string[]) !==
      sortedSet((actual as readonly string[] | undefined) ?? [])
    : declared !== actual;

/** Key-wise: only keys the program declares can differ from the other side. */
const declaredPolicyDiffers = (
  declared: PkiCaPolicyInput | undefined,
  actual: Partial<PkiCaPolicy> | PkiCaPolicyInput | undefined,
): boolean =>
  POLICY_KEYS.some((key) => {
    const value = declared?.[key];
    return (
      value !== undefined &&
      policyValueDiffers(
        key,
        value,
        (actual as Record<string, unknown> | undefined)?.[key],
      )
    );
  });

const emptyToUndefined = <T extends object>(value: T | undefined) =>
  value !== undefined && Object.keys(clean(value)).length === 0
    ? undefined
    : value;

/** Immutable properties whose value differs. Unknown new values are skipped. */
const changedImmutables = (
  olds: Partial<ResolvedCertificateAuthorityInputs>,
  news: Partial<ResolvedCertificateAuthorityInputs>,
): string[] => {
  const changed: string[] = [];
  const scalars = ["environment", "name", "kind", "keyAlgorithm", "parentCaId"] as const;
  for (const key of scalars) {
    if (containsUnknown(news[key])) {
      continue;
    }
    if (olds[key] !== news[key]) {
      changed.push(key);
    }
  }
  if (
    !containsUnknown(news.subject) &&
    !sameJson(olds.subject, news.subject)
  ) {
    changed.push("subject");
  }
  if (
    !containsUnknown(news.requestedConstraints) &&
    !sameJson(
      emptyToUndefined(olds.requestedConstraints),
      emptyToUndefined(news.requestedConstraints),
    )
  ) {
    changed.push("requestedConstraints");
  }
  // An imported CA cannot know the validity it was created with.
  if (
    olds.validitySeconds !== undefined &&
    !containsUnknown(news.validitySeconds) &&
    olds.validitySeconds !== news.validitySeconds
  ) {
    changed.push("validitySeconds");
  }
  return changed;
};

const activationAdded = (
  olds: Partial<ResolvedCertificateAuthorityInputs>,
  news: Partial<ResolvedCertificateAuthorityInputs>,
): boolean =>
  news.signedCertificatePem !== undefined &&
  news.chainPem !== undefined &&
  (olds.signedCertificatePem === undefined || olds.chainPem === undefined);

export class HemligCertificateAuthorityProvider
  implements pulumi.dynamic.ResourceProvider
{
  public constructor(
    private readonly createClient: CaClientFactory = caClientFor,
    private readonly adminTokenFor: AdminTokenSource = adminTokenFromEnvironment,
    private readonly retryDelaysMs: readonly number[] = DEFAULT_RETRY_DELAYS_MS,
  ) {}

  public async check(
    olds: Partial<ResolvedCertificateAuthorityInputs>,
    news: Partial<ResolvedCertificateAuthorityInputs>,
  ): Promise<pulumi.dynamic.CheckResult> {
    const failures: { property: string; reason: string }[] = [];
    const fail = (property: string, reason: string): void => {
      failures.push({ property, reason });
    };
    const exists = typeof olds?.name === "string";
    const kind = containsUnknown(news.kind) ? undefined : news.kind;

    for (const key of ["environment", "name", "kind", "keyAlgorithm", "subject"] as const) {
      if (news[key] === undefined) {
        fail(key, `${key} is required.`);
      }
    }
    for (const reason of rejectPrivateKeys(news as Record<string, unknown>, CA_INPUT_KEYS)) {
      fail("inputs", reason);
    }

    if (exists) {
      const changed = changedImmutables(olds, news);
      for (const property of changed) {
        fail(property, `${property} cannot change. ${ROLLOVER_MESSAGE}`);
      }
    }

    if (kind === "INTERMEDIATE" && news.parentCaId === undefined) {
      fail("parentCaId", "parentCaId is required for an INTERMEDIATE CA.");
    }
    if (kind !== undefined && kind !== "INTERMEDIATE" && news.parentCaId !== undefined) {
      fail("parentCaId", "parentCaId is only allowed for an INTERMEDIATE CA.");
    }
    if (kind === "EXTERNAL_INTERMEDIATE" && news.validitySeconds !== undefined) {
      fail("validitySeconds", "validitySeconds is not allowed for an EXTERNAL_INTERMEDIATE CA.");
    }
    if (
      kind === "ROOT" &&
      (news.policy?.maxLeafLifetimeSeconds !== undefined ||
        news.policy?.leafKeyAlgorithms !== undefined)
    ) {
      fail("policy", "A ROOT CA issues no leaves: remove maxLeafLifetimeSeconds and leafKeyAlgorithms.");
    }

    const signed = news.signedCertificatePem;
    const chain = news.chainPem;
    if (
      signed !== undefined ||
      chain !== undefined ||
      olds?.signedCertificatePem !== undefined
    ) {
      if (kind !== undefined && kind !== "EXTERNAL_INTERMEDIATE") {
        fail("signedCertificatePem", "signedCertificatePem and chainPem apply to an EXTERNAL_INTERMEDIATE only.");
      } else if (containsUnknown(signed) || containsUnknown(chain)) {
        // Unknown in a preview: validated again when resolved.
      } else if (!exists) {
        if (signed !== undefined || chain !== undefined) {
          fail("signedCertificatePem", "Set signedCertificatePem and chainPem after the first apply: the first apply produces csrPem, which the root signs offline.");
        }
      } else {
        if ((signed === undefined) !== (chain === undefined)) {
          fail("signedCertificatePem", "signedCertificatePem and chainPem must be set together.");
        }
        if (olds.signedCertificatePem !== undefined) {
          if (!pemBodiesEqual(olds.signedCertificatePem, signed)) {
            fail("signedCertificatePem", `signedCertificatePem is write-once and cannot change or be removed. ${ROLLOVER_MESSAGE}`);
          }
          if (!pemBodiesEqual(olds.chainPem, chain)) {
            fail("chainPem", "chainPem is write-once and cannot change or be removed.");
          }
          if (
            !containsUnknown(news.acceptBroaderConstraints) &&
            (olds.acceptBroaderConstraints ?? false) !==
              (news.acceptBroaderConstraints ?? false)
          ) {
            fail("acceptBroaderConstraints", "acceptBroaderConstraints is write-once; it applies only to activation.");
          }
        }
      }
    }

    return failures.length > 0 ? { failures } : { inputs: news };
  }

  public async create(
    inputs: ResolvedCertificateAuthorityInputs,
  ): Promise<pulumi.dynamic.CreateResult> {
    const client = this.createClient(inputs);
    const token = this.adminTokenFor();
    const body: PkiCreateCaRequest = clean({
      environment: inputs.environment,
      name: inputs.name,
      kind: inputs.kind,
      parentCaId: inputs.parentCaId,
      validitySeconds: inputs.validitySeconds,
      keyAlgorithm: inputs.keyAlgorithm,
      subject: inputs.subject,
      requestedConstraints: inputs.requestedConstraints,
      policy: inputs.policy,
      displayName: inputs.displayName,
    });
    let created;
    try {
      created = await withKey(
        "ca-create",
        (key) => client.createPkiCa(token, body, key),
        this.retryDelaysMs,
      );
    } catch (error) {
      if (hasReason(error, "conflict", "name_in_use")) {
        throw await this.nameInUse(client, token, inputs, error);
      }
      if (hasReason(error, "ca_subject_in_use")) {
        throw failure(
          `The subject DN of CA ${inputs.name} is already claimed. Subject DNs are never reused; choose a new DN`,
          error,
        );
      }
      throw failure(`Creating CA ${inputs.name} failed`, error);
    }
    return {
      id: created.caId,
      outs: caState(inputs, created, created.warnings),
    };
  }

  private async nameInUse(
    client: HemligCaClient,
    token: string,
    inputs: ResolvedCertificateAuthorityInputs,
    original: unknown,
  ): Promise<Error> {
    let existing: PkiCaSummary | undefined;
    try {
      existing = (await listAllCas(client, token, inputs.environment)).find(
        (ca) => ca.name === inputs.name,
      );
    } catch {
      existing = undefined;
    }
    if (existing === undefined) {
      return failure(
        `A CA named ${inputs.name} already exists in ${inputs.environment}. Choose a new name and DN`,
        original,
      );
    }
    return plainError(
      `A CA named ${inputs.name} already exists (${existing.caId}, status ${existing.status}). CA names and DNs are never reused. If an interrupted run created it, abandon it (hemlig pki ca delete ${existing.caId} --environment ${inputs.environment} --if-match current, while PENDING_CERTIFICATE) or retire it (hemlig pki ca retire ${existing.caId} --environment ${inputs.environment}, while ACTIVE), then choose a new name and DN.`,
    );
  }

  public async diff(
    _id: string,
    olds: ResolvedCertificateAuthorityState,
    news: ResolvedCertificateAuthorityInputs,
  ): Promise<pulumi.dynamic.DiffResult> {
    const policyChanged = POLICY_KEYS.some((key) => {
      const declared = news.policy?.[key];
      return (
        declared !== undefined &&
        (olds.policy?.[key] === undefined ||
          policyValueDiffers(key, declared, olds.policy[key]))
      );
    });
    const displayNameChanged =
      news.displayName !== undefined && news.displayName !== olds.displayName;
    const activationChanged =
      activationAdded(olds, news) ||
      (news.signedCertificatePem !== undefined &&
        !pemBodiesEqual(olds.signedCertificatePem, news.signedCertificatePem)) ||
      (news.chainPem !== undefined &&
        !pemBodiesEqual(olds.chainPem, news.chainPem));
    const changes =
      policyChanged ||
      displayNameChanged ||
      activationChanged ||
      olds.adminUrl !== news.adminUrl;
    // A CA is never replaced: replacement would retire an ACTIVE CA before its
    // successor is signed, and a CA name and DN can never be reused.
    return { changes, replaces: [] };
  }

  public async update(
    id: string,
    olds: ResolvedCertificateAuthorityState,
    news: ResolvedCertificateAuthorityInputs,
  ): Promise<pulumi.dynamic.UpdateResult> {
    const immutable = changedImmutables(olds, news);
    if (immutable.length > 0) {
      throw plainError(
        `${immutable.join(", ")} cannot change. ${ROLLOVER_MESSAGE}`,
      );
    }
    const client = this.createClient(news);
    const token = this.adminTokenFor();
    let ca: PkiCaDetail;
    try {
      ca = await client.getPkiCa(token, id);
    } catch (error) {
      throw failure(`Reading CA ${id} failed`, error);
    }

    if (activationAdded(olds, news)) {
      const signed = news.signedCertificatePem as string;
      if (ca.status === "PENDING_CERTIFICATE") {
        const request = clean({
          certificatePem: signed,
          chainPem: news.chainPem as string,
          acceptBroaderConstraints: news.acceptBroaderConstraints,
        });
        try {
          ca = await withKey(
            "ca-activate",
            (key) => client.activatePkiCa(token, id, request, key),
            this.retryDelaysMs,
          );
        } catch (error) {
          throw failure(`Activating CA ${news.name} failed${activationHint(error)}`, error);
        }
      } else if (ca.status === "ACTIVE") {
        // Out-of-band activation, or a lost response: nothing to do when the
        // certificate is the one declared.
        if (!pemBodiesEqual(ca.certificatePem, signed)) {
          throw plainError(
            `CA ${news.name} is already ACTIVE with a different certificate than signedCertificatePem. ${ROLLOVER_MESSAGE}`,
          );
        }
      } else {
        throw plainError(
          `CA ${news.name} is ${ca.status} and cannot be activated.`,
        );
      }
    }

    if (
      declaredPolicyDiffers(news.policy, ca.policy) ||
      (news.displayName !== undefined && news.displayName !== ca.displayName)
    ) {
      ca = await this.updateInPlace(client, token, id, news, ca);
    }

    return { outs: caState(news, ca, olds.warnings, olds.csrPem) };
  }

  private async updateInPlace(
    client: HemligCaClient,
    token: string,
    caId: string,
    news: ResolvedCertificateAuthorityInputs,
    first: PkiCaDetail,
  ): Promise<PkiCaDetail> {
    let fresh = first;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      if (fresh.status !== "PENDING_CERTIFICATE" && fresh.status !== "ACTIVE") {
        throw plainError(
          `ca_not_active: CA ${news.name} is ${fresh.status}; policy and display name can only change while it is PENDING_CERTIFICATE or ACTIVE.`,
        );
      }
      if (
        !declaredPolicyDiffers(news.policy, fresh.policy) &&
        (news.displayName === undefined || news.displayName === fresh.displayName)
      ) {
        return fresh;
      }
      const body = clean({
        policy: news.policy ?? {},
        displayName: news.displayName,
      });
      const version = fresh.version;
      try {
        return await withKey(
          "ca-update",
          (key) => client.updatePkiCa(token, caId, version, body, key),
          this.retryDelaysMs,
        );
      } catch (error) {
        if (!hasStatus(error, 412)) {
          throw failure(`Updating CA ${news.name} failed`, error);
        }
      }
      try {
        fresh = await client.getPkiCa(token, caId);
      } catch (error) {
        throw failure(`Re-reading CA ${news.name} failed`, error);
      }
    }
    throw plainError(
      `CA ${news.name} changed concurrently three times in a row (412 precondition failed). Run the update again.`,
    );
  }

  public async read(
    id: string,
    props: Partial<ResolvedCertificateAuthorityState>,
  ): Promise<pulumi.dynamic.ReadResult> {
    const adminUrl = props.adminUrl;
    if (adminUrl === undefined) {
      throw plainError("adminUrl is required to read a CA.");
    }
    const client = this.createClient({ adminUrl });
    const token = this.adminTokenFor();
    let ca: PkiCaDetail;
    try {
      ca = await client.getPkiCa(token, id);
    } catch (error) {
      if (hasStatus(error, 404)) {
        throw plainError(
          `CA ${id} not found at ${adminUrl}. CA records are never deleted, so check adminUrl and the environment.`,
        );
      }
      throw failure(`Reading CA ${id} failed`, error);
    }

    if (props.version === undefined) {
      const inputs = importedInputs(adminUrl, props.providerSchemaVersion, ca);
      return {
        id: ca.caId,
        props: caState(inputs, ca, ca.warnings),
        inputs,
      } as pulumi.dynamic.ReadResult;
    }

    // Refresh: keep the declared inputs and surface only real drift.
    const state = props as ResolvedCertificateAuthorityState;
    let policy = state.policy;
    if (policy !== undefined) {
      const next: Record<string, unknown> = { ...policy };
      for (const key of POLICY_KEYS) {
        const declared = policy[key];
        if (
          declared !== undefined &&
          policyValueDiffers(key, declared, ca.policy[key])
        ) {
          next[key] = ca.policy[key];
        }
      }
      policy = next as PkiCaPolicyInput;
    }
    const displayName =
      state.displayName !== undefined && state.displayName !== ca.displayName
        ? ca.displayName
        : state.displayName;
    const declared = clean({ ...pick(state, CA_INPUT_KEYS), policy, displayName }) as ResolvedCertificateAuthorityInputs;
    return {
      id: ca.caId,
      props: caState(declared, ca, state.warnings, state.csrPem),
      inputs: declared,
    } as pulumi.dynamic.ReadResult;
  }

  /**
   * Delete means retire, and only for an ACTIVE CA with no live grants. Any
   * other status makes no remote call: a pending CA keeps its key so an
   * accidental removal can be undone with `import`, and abandoning it is a
   * human action. Destroy-key, abandon and revoke are unreachable from here.
   */
  public async delete(
    id: string,
    props: Partial<ResolvedCertificateAuthorityState>,
  ): Promise<void> {
    const adminUrl = props.adminUrl;
    if (adminUrl === undefined) {
      throw plainError("adminUrl is required to delete a CA.");
    }
    const client = this.createClient({ adminUrl });
    const token = this.adminTokenFor();
    let ca: PkiCaDetail;
    try {
      ca = await client.getPkiCa(token, id);
    } catch (error) {
      if (hasStatus(error, 404)) {
        return;
      }
      throw failure(`Reading CA ${id} failed`, error);
    }
    if (ca.status !== "ACTIVE") {
      return;
    }

    const remaining = await this.liveGrants(client, token, id, ca.name);
    if (remaining.length > 0) {
      throw plainError(
        `CA ${ca.name} still has issuance grants: ${remaining.slice(0, 10).join(", ")}${remaining.length > 10 ? ", ..." : ""}. Migrate (change caId) or delete them first; to retire anyway, use the console or CLI.`,
      );
    }
    try {
      await withKey(
        "ca-retire",
        (key) => client.retirePkiCa(token, id, key),
        this.retryDelaysMs,
      );
    } catch (error) {
      if (hasReason(error, "ca_not_active")) {
        const current = await client.getPkiCa(token, id);
        if (current.status === "RETIRED" || current.status === "REVOKED") {
          return;
        }
      }
      throw failure(`Retiring CA ${ca.name} failed`, error);
    }
  }

  /**
   * The CA's grant index is eventually consistent, so every listed grant is
   * re-read (strongly consistent) and only grants that are still live and
   * still point at this CA count. That tolerates the lag after Pulumi itself
   * just deleted or migrated grants.
   */
  private async liveGrants(
    client: HemligCaClient,
    token: string,
    caId: string,
    caName: string,
  ): Promise<string[]> {
    const listed: PkiIssuanceGrant[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 5; page += 1) {
      const result = await client.listCaIssuanceGrants(token, caId, { cursor });
      listed.push(...result.grants);
      cursor = result.nextCursor;
      if (cursor === undefined) {
        break;
      }
    }
    if (listed.length > 20 || cursor !== undefined) {
      throw plainError(
        `CA ${caName} lists more than 20 issuance grants. Migrate or delete them first; to retire anyway, use the console or CLI.`,
      );
    }
    const remaining: string[] = [];
    for (const grant of listed) {
      let fresh: PkiIssuanceGrant;
      try {
        fresh = await client.getAdminIssuanceGrant(
          token,
          grant.consumerId,
          grant.name,
        );
      } catch (error) {
        if (hasStatus(error, 404)) {
          continue;
        }
        throw failure(`Re-reading grant ${grant.consumerId}/${grant.name} failed`, error);
      }
      if (fresh.status !== "DELETED" && fresh.caId === caId) {
        remaining.push(`${fresh.consumerId}/${fresh.name}`);
      }
    }
    return remaining;
  }
}

const activationHint = (error: unknown): string => {
  if (hasReason(error, "chain_invalid", "constraints_broader")) {
    return " (set acceptBroaderConstraints: true if the broader constraints are intended)";
  }
  return "";
};

const importedInputs = (
  adminUrl: string,
  providerSchemaVersion: string | undefined,
  ca: PkiCaDetail,
): ResolvedCertificateAuthorityInputs => {
  const leafPolicy: PkiCaPolicyInput = {
    ...(ca.kind === "ROOT"
      ? {}
      : {
          maxLeafLifetimeSeconds: ca.policy.maxLeafLifetimeSeconds,
          leafKeyAlgorithms: ca.policy.leafKeyAlgorithms,
        }),
    capacity: ca.policy.capacity,
    issuancePerHour: ca.policy.issuancePerHour,
    crlValiditySeconds: ca.policy.crlValiditySeconds,
  };
  const activated = ca.kind === "EXTERNAL_INTERMEDIATE" && ca.certificatePem !== undefined && ca.chainPem !== undefined;
  return clean({
    adminUrl,
    providerSchemaVersion: providerSchemaVersion ?? "1",
    environment: ca.environment,
    name: ca.name,
    kind: ca.kind,
    keyAlgorithm: ca.keyAlgorithm,
    subject: ca.subject,
    parentCaId: ca.parentCaId,
    requestedConstraints: ca.requestedConstraints,
    policy: leafPolicy,
    displayName: ca.displayName,
    signedCertificatePem: activated ? ca.certificatePem : undefined,
    chainPem: activated ? ca.chainPem : undefined,
    acceptBroaderConstraints: activated ? ca.acceptBroaderConstraints : undefined,
  }) as ResolvedCertificateAuthorityInputs;
};

/** Inputs plus the public outputs. Everything here is public material. */
const caState = (
  inputs: ResolvedCertificateAuthorityInputs,
  ca: PkiCaDetail,
  warnings: readonly PkiWarning[] | undefined,
  previousCsr?: string,
): Record<string, unknown> =>
  clean({
    ...pick(inputs, CA_INPUT_KEYS),
    caId: ca.caId,
    status: ca.status,
    version: ca.version,
    keyState: ca.keyState,
    subjectDn: ca.subjectDn,
    csrPem: ca.csrPem ?? previousCsr,
    certificatePem: ca.certificatePem,
    issuerChainPem: ca.chainPem,
    fingerprint: ca.fingerprint,
    serial: ca.serial,
    notBefore: ca.notBefore,
    notAfter: ca.notAfter,
    rootCrlExtId: ca.rootCrl?.extId,
    rootCrlState: ca.rootCrl?.state,
    warnings,
  });

export class HemligCertificateAuthority extends pulumi.dynamic.Resource {
  declare public readonly caId: pulumi.Output<string>;
  declare public readonly status: pulumi.Output<string>;
  declare public readonly version: pulumi.Output<string>;
  declare public readonly keyState: pulumi.Output<string>;
  declare public readonly subjectDn: pulumi.Output<string>;
  declare public readonly csrPem: pulumi.Output<string | undefined>;
  declare public readonly certificatePem: pulumi.Output<string | undefined>;
  declare public readonly issuerChainPem: pulumi.Output<string | undefined>;
  declare public readonly fingerprint: pulumi.Output<string | undefined>;
  declare public readonly serial: pulumi.Output<string | undefined>;
  declare public readonly notBefore: pulumi.Output<string | undefined>;
  declare public readonly notAfter: pulumi.Output<string | undefined>;
  declare public readonly rootCrlExtId: pulumi.Output<string | undefined>;
  declare public readonly rootCrlState: pulumi.Output<string | undefined>;
  declare public readonly warnings: pulumi.Output<
    readonly PkiWarning[] | undefined
  >;

  public constructor(
    name: string,
    args: HemligCertificateAuthorityArgs,
    adminUrl: pulumi.Input<string>,
    opts?: pulumi.CustomResourceOptions,
  ) {
    super(
      new HemligCertificateAuthorityProvider(),
      name,
      {
        ...args,
        adminUrl,
        providerSchemaVersion: "1",
        // Dynamic-provider outputs need placeholders so Pulumi transfers them
        // onto the resource instance after registration.
        caId: undefined,
        status: undefined,
        version: undefined,
        keyState: undefined,
        subjectDn: undefined,
        csrPem: undefined,
        certificatePem: undefined,
        issuerChainPem: undefined,
        fingerprint: undefined,
        serial: undefined,
        notBefore: undefined,
        notAfter: undefined,
        rootCrlExtId: undefined,
        rootCrlState: undefined,
        warnings: undefined,
      },
      opts,
    );
  }
}

// ---------------------------------------------------------------------------
// hemlig.IssuanceGrant
// ---------------------------------------------------------------------------

export interface HemligIssuanceGrantArgs {
  readonly consumerId: pulumi.Input<string>;
  readonly name: pulumi.Input<string>;
  /** Changing it migrates the grant to another CA. */
  readonly caId: pulumi.Input<string>;
  readonly displayName?: pulumi.Input<string>;
  readonly status?: pulumi.Input<"ACTIVE" | "DISABLED">;
  readonly expiresAt?: pulumi.Input<string>;
  readonly names: pulumi.Input<PkiGrantNames>;
  readonly keyUsages: pulumi.Input<readonly string[]>;
  readonly extendedKeyUsages: pulumi.Input<{
    readonly allow: readonly string[];
    readonly default: readonly string[];
  }>;
  readonly lifetime: pulumi.Input<{
    readonly defaultSeconds: number;
    readonly maxSeconds: number;
    readonly minSeconds?: number;
  }>;
  readonly subject?: pulumi.Input<
    NonNullable<PkiGrantPolicyFields["subject"]>
  >;
  readonly keyAlgorithms?: pulumi.Input<readonly PkiLeafKeyAlgorithm[]>;
  readonly forced?: pulumi.Input<NonNullable<PkiGrantPolicyFields["forced"]>>;
  readonly quotas?: pulumi.Input<NonNullable<PkiGrantPolicyFields["quotas"]>>;
}

export interface ResolvedIssuanceGrantInputs {
  readonly adminUrl: string;
  readonly providerSchemaVersion: string;
  readonly consumerId: string;
  readonly name: string;
  readonly caId: string;
  readonly displayName?: string;
  readonly status?: "ACTIVE" | "DISABLED";
  readonly expiresAt?: string;
  readonly names: PkiGrantNames;
  readonly keyUsages: readonly string[];
  readonly extendedKeyUsages: {
    readonly allow: readonly string[];
    readonly default: readonly string[];
  };
  readonly lifetime: {
    readonly defaultSeconds: number;
    readonly maxSeconds: number;
    readonly minSeconds?: number;
  };
  readonly subject?: PkiGrantPolicyFields["subject"];
  readonly keyAlgorithms?: readonly PkiLeafKeyAlgorithm[];
  readonly forced?: PkiGrantPolicyFields["forced"];
  readonly quotas?: PkiGrantPolicyFields["quotas"];
}

export interface ResolvedIssuanceGrantState
  extends ResolvedIssuanceGrantInputs {
  readonly uid: string;
  readonly version: string;
  readonly environment: string;
  readonly expired: boolean;
  readonly policyDigest: string;
  readonly resolvedQuotas: PkiGrantQuotas;
}

const GRANT_POLICY_KEYS = [
  "names",
  "keyUsages",
  "extendedKeyUsages",
  "lifetime",
  "subject",
  "keyAlgorithms",
  "forced",
  "quotas",
] as const;

const GRANT_INPUT_KEYS = [
  "adminUrl",
  "providerSchemaVersion",
  "consumerId",
  "name",
  "caId",
  "displayName",
  "status",
  "expiresAt",
  ...GRANT_POLICY_KEYS,
] as const;

const grantPolicyOf = (
  value: Partial<ResolvedIssuanceGrantInputs>,
): Record<string, unknown> => clean(pick(value, GRANT_POLICY_KEYS));

const grantExistsMessage = (consumerId: string, name: string): string =>
  `Grant ${consumerId}/${name} exists. If an interrupted run created it, delete it (hemlig pki grant delete ${consumerId} ${name} --if-match current) and re-run.`;

const sameInstant = (a: string | undefined, b: string | undefined): boolean =>
  a === undefined || b === undefined
    ? a === b
    : Date.parse(a) === Date.parse(b);

const grantBody = (
  inputs: ResolvedIssuanceGrantInputs,
): PkiIssuanceGrantInput =>
  clean({
    caId: inputs.caId,
    displayName: inputs.displayName,
    status: inputs.status ?? "ACTIVE",
    expiresAt: inputs.expiresAt,
    ...grantPolicyOf(inputs),
  });

const grantState = (
  inputs: Partial<ResolvedIssuanceGrantInputs>,
  grant: PkiIssuanceGrant,
): Record<string, unknown> =>
  clean({
    ...pick(inputs, GRANT_INPUT_KEYS),
    uid: grant.uid,
    version: grant.version,
    environment: grant.environment,
    expired: grant.expired,
    policyDigest: grant.policyDigest,
    resolvedQuotas: grant.quotas,
  });

export class HemligIssuanceGrantProvider
  implements pulumi.dynamic.ResourceProvider
{
  public constructor(
    private readonly createClient: GrantClientFactory = grantClientFor,
    private readonly adminTokenFor: AdminTokenSource = adminTokenFromEnvironment,
    private readonly retryDelaysMs: readonly number[] = DEFAULT_RETRY_DELAYS_MS,
  ) {}

  public async check(
    _olds: Partial<ResolvedIssuanceGrantInputs>,
    news: Partial<ResolvedIssuanceGrantInputs>,
  ): Promise<pulumi.dynamic.CheckResult> {
    const failures: { property: string; reason: string }[] = [];
    for (const key of [
      "consumerId",
      "name",
      "caId",
      "names",
      "keyUsages",
      "extendedKeyUsages",
      "lifetime",
    ] as const) {
      if (news[key] === undefined) {
        failures.push({ property: key, reason: `${key} is required.` });
      }
    }
    for (const reason of rejectPrivateKeys(news as Record<string, unknown>, GRANT_INPUT_KEYS)) {
      failures.push({ property: "inputs", reason });
    }
    if (failures.length > 0) {
      return { failures };
    }
    return { inputs: { ...news, status: news.status ?? "ACTIVE" } };
  }

  public async create(
    inputs: ResolvedIssuanceGrantInputs,
  ): Promise<pulumi.dynamic.CreateResult> {
    const client = this.createClient(inputs);
    const token = this.adminTokenFor();
    const { consumerId, name } = inputs;
    let existing: PkiIssuanceGrant | undefined;
    try {
      existing = await client.getAdminIssuanceGrant(token, consumerId, name);
    } catch (error) {
      if (!hasStatus(error, 404)) {
        throw failure(`Reading grant ${consumerId}/${name} failed`, error);
      }
    }
    if (existing !== undefined && existing.status !== "DELETED") {
      throw plainError(grantExistsMessage(consumerId, name));
    }
    const request: PkiCreateIssuanceGrantRequest = { name, ...grantBody(inputs) };
    let grant: PkiIssuanceGrant;
    try {
      grant = await withKey(
        "grant-create",
        (key) => client.createIssuanceGrant(token, consumerId, request, key),
        this.retryDelaysMs,
      );
    } catch (error) {
      if (hasReason(error, "conflict", "grant_exists")) {
        throw plainError(grantExistsMessage(consumerId, name));
      }
      throw failure(`Creating grant ${consumerId}/${name} failed`, error);
    }
    return {
      id: `${consumerId}/${name}`,
      outs: grantState({ ...inputs, status: inputs.status ?? "ACTIVE" }, grant),
    };
  }

  public async diff(
    _id: string,
    olds: ResolvedIssuanceGrantState,
    news: ResolvedIssuanceGrantInputs,
  ): Promise<pulumi.dynamic.DiffResult> {
    const replaces = (["consumerId", "name"] as const).filter(
      (key) => olds[key] !== news[key],
    );
    const changes =
      replaces.length > 0 ||
      olds.adminUrl !== news.adminUrl ||
      olds.caId !== news.caId ||
      olds.displayName !== news.displayName ||
      (olds.status ?? "ACTIVE") !== (news.status ?? "ACTIVE") ||
      !sameInstant(olds.expiresAt, news.expiresAt) ||
      stableJson(grantPolicyOf(olds)) !== stableJson(grantPolicyOf(news));
    return { changes, replaces, deleteBeforeReplace: false };
  }

  public async update(
    id: string,
    olds: ResolvedIssuanceGrantState,
    news: ResolvedIssuanceGrantInputs,
  ): Promise<pulumi.dynamic.UpdateResult> {
    const client = this.createClient(news);
    const token = this.adminTokenFor();
    const { consumerId, name } = news;
    const body = grantBody(news);
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      let fresh: PkiIssuanceGrant;
      try {
        fresh = await client.getAdminIssuanceGrant(token, consumerId, name);
      } catch (error) {
        if (hasStatus(error, 404)) {
          throw plainError(
            `Grant ${id} was deleted outside Pulumi: run pulumi refresh.`,
          );
        }
        throw failure(`Reading grant ${id} failed`, error);
      }
      if (fresh.status === "DELETED") {
        throw plainError(
          `Grant ${id} was deleted outside Pulumi: run pulumi refresh.`,
        );
      }
      // A different uid means the tracked generation was replaced.
      if (olds.uid !== undefined && fresh.uid !== olds.uid) {
        throw plainError(
          `Grant ${id} was deleted and recreated outside Pulumi; run pulumi refresh.`,
        );
      }
      // Never silently undo an out-of-band emergency disable or migration.
      if (
        fresh.status === "DISABLED" &&
        (olds.status ?? "ACTIVE") === "ACTIVE" &&
        (news.status ?? "ACTIVE") === "ACTIVE"
      ) {
        throw plainError(
          `Grant ${id} status changed outside Pulumi (it is DISABLED). Run pulumi refresh and update your program.`,
        );
      }
      if (fresh.caId !== olds.caId && news.caId === olds.caId) {
        throw plainError(
          `Grant ${id} caId changed outside Pulumi (it is now ${fresh.caId}). Run pulumi refresh and update your program.`,
        );
      }
      const version = fresh.version;
      try {
        const updated = await withKey(
          "grant-update",
          (key) =>
            client.updateIssuanceGrant(token, consumerId, name, version, body, key),
          this.retryDelaysMs,
        );
        return {
          outs: grantState({ ...news, status: news.status ?? "ACTIVE" }, updated),
        };
      } catch (error) {
        // A 412 means someone saved first: re-read and retry with a new key,
        // because the update digest covers If-Match.
        if (!hasStatus(error, 412)) {
          throw failure(`Updating grant ${id} failed`, error);
        }
      }
    }
    throw plainError(
      `Grant ${id} changed concurrently three times in a row (412 precondition failed). Run the update again.`,
    );
  }

  public async read(
    id: string,
    props: Partial<ResolvedIssuanceGrantState>,
  ): Promise<pulumi.dynamic.ReadResult> {
    const adminUrl = props.adminUrl;
    const separator = id.indexOf("/");
    const consumerId = props.consumerId ?? id.slice(0, Math.max(separator, 0));
    const name = props.name ?? id.slice(separator + 1);
    if (adminUrl === undefined) {
      throw plainError("adminUrl is required to read a grant.");
    }
    const client = this.createClient({ adminUrl });
    const token = this.adminTokenFor();
    let server: PkiIssuanceGrant;
    try {
      server = await client.getAdminIssuanceGrant(token, consumerId, name);
    } catch (error) {
      if (hasStatus(error, 404)) {
        throw plainError(
          `Grant ${id} not found at ${adminUrl}. Grants are never hard-deleted, so check adminUrl.`,
        );
      }
      throw failure(`Reading grant ${id} failed`, error);
    }
    if (server.status === "DELETED") {
      return {};
    }
    // The tracked generation is gone if the name now holds a different grant.
    if (props.uid !== undefined && server.uid !== props.uid) {
      return {};
    }

    // On refresh the state's status and caId stay put, so update's drift
    // guard still sees an out-of-band disable or migration.
    const refreshing =
      props.version !== undefined &&
      props.status !== undefined &&
      props.caId !== undefined;
    const envelope = {
      consumerId,
      name,
      caId: refreshing ? (props.caId as string) : server.caId,
      displayName: server.displayName,
      status: (refreshing ? props.status : server.status) as "ACTIVE" | "DISABLED",
      expiresAt:
        sameInstant(props.expiresAt, server.expiresAt) &&
        props.expiresAt !== undefined
          ? props.expiresAt
          : server.expiresAt,
    };
    const keepDeclared =
      props.version !== undefined && server.policyDigest === props.policyDigest;
    const declared = clean({
      adminUrl,
      providerSchemaVersion: props.providerSchemaVersion ?? "1",
      ...envelope,
      ...(keepDeclared ? grantPolicyOf(props) : server.policy),
    }) as ResolvedIssuanceGrantInputs;
    return {
      id: `${consumerId}/${name}`,
      props: grantState(declared, server),
      inputs: declared,
    } as pulumi.dynamic.ReadResult;
  }

  /** Delete never revokes certificates; it leaves a tombstone. */
  public async delete(
    id: string,
    props: Partial<ResolvedIssuanceGrantState>,
  ): Promise<void> {
    const adminUrl = props.adminUrl;
    const separator = id.indexOf("/");
    const consumerId = props.consumerId ?? id.slice(0, Math.max(separator, 0));
    const name = props.name ?? id.slice(separator + 1);
    if (adminUrl === undefined) {
      throw plainError("adminUrl is required to delete a grant.");
    }
    const client = this.createClient({ adminUrl });
    const token = this.adminTokenFor();
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      let fresh: PkiIssuanceGrant;
      try {
        fresh = await client.getAdminIssuanceGrant(token, consumerId, name);
      } catch (error) {
        if (hasStatus(error, 404)) {
          return;
        }
        throw failure(`Reading grant ${id} failed`, error);
      }
      if (fresh.status === "DELETED") {
        return;
      }
      // A different uid means the tracked generation is gone; never delete its replacement.
      if (props.uid !== undefined && fresh.uid !== props.uid) {
        return;
      }
      const version = fresh.version;
      try {
        await withKey(
          "grant-delete",
          (key) =>
            client.deleteIssuanceGrant(token, consumerId, name, version, key),
          this.retryDelaysMs,
        );
        return;
      } catch (error) {
        if (hasStatus(error, 404)) {
          return;
        }
        if (!hasStatus(error, 412)) {
          throw failure(`Deleting grant ${id} failed`, error);
        }
      }
    }
    throw plainError(
      `Grant ${id} changed concurrently three times in a row (412 precondition failed). Run the destroy again.`,
    );
  }
}

export class HemligIssuanceGrant extends pulumi.dynamic.Resource {
  declare public readonly uid: pulumi.Output<string>;
  declare public readonly version: pulumi.Output<string>;
  declare public readonly environment: pulumi.Output<string>;
  declare public readonly expired: pulumi.Output<boolean>;
  declare public readonly policyDigest: pulumi.Output<string>;
  declare public readonly resolvedQuotas: pulumi.Output<PkiGrantQuotas>;

  public constructor(
    name: string,
    args: HemligIssuanceGrantArgs,
    adminUrl: pulumi.Input<string>,
    opts?: pulumi.CustomResourceOptions,
  ) {
    super(
      new HemligIssuanceGrantProvider(),
      name,
      {
        ...args,
        adminUrl,
        providerSchemaVersion: "1",
        // Dynamic-provider outputs need placeholders so Pulumi transfers them
        // onto the resource instance after registration.
        uid: undefined,
        version: undefined,
        environment: undefined,
        expired: undefined,
        policyDigest: undefined,
        resolvedQuotas: undefined,
      },
      opts,
    );
  }
}
