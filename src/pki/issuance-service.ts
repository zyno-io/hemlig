import {
  identityNotActive,
  serviceUnavailable,
  ApiError,
} from "../domain/errors";
import type { Actor } from "../domain/types";
import {
  pkiKeys,
  quotaRetryAfterSeconds,
  quotaWindows,
  type AdminIssuanceCommit,
  type ConsumerIssuanceCommit,
  type IssuanceCommit,
  type PkiRepository,
  type QuotaSlot,
} from "../repositories/pki";
import { parseCertificate, type ParsedCertificate } from "./asn1/certificate";
import { fromPem, toPem } from "./asn1/pem";
import {
  assertHumanReplay,
  caPolicyInputOf,
  caStatusReason,
  subjectDn,
} from "./ca-model";
import type { CapacityService } from "./capacity-service";
import { parseCsr, type ParsedCsr } from "./csr";
import {
  agentGrantInactive,
  caCapacityExceeded,
  caKeyUnavailable,
  caNotActive,
  idempotencyKeyReused,
  deniedNameFields,
  issuanceDenied,
  issuanceExpired,
  issuanceGrantInactive,
  issuanceGrantNotFound,
  issuanceRateLimited,
  issuanceRevoked,
  pkiBadRequest,
  pkiNotFound,
  type RateLimitReason,
} from "./errors";
import { grantExpired, resolvedQuotas } from "./grant-model";
import { hemligAncestors } from "./hierarchy-model";
import {
  ADMIN_ISSUANCE_PER_HOUR,
  adminIssueDigest,
  assembleLeaf,
  assertLeafMatchesPlan,
  buildLeafToSign,
  consumerIssueDigest,
  csrDerSha256,
  csrToPolicyRequest,
  issueResponse,
  parseAdminIssueRequest,
  parseConsumerIssueRequest,
  pemBlocks,
  type AdminIssueInput,
  type ConsumerIssueInput,
} from "./issuance-model";
import { emitPkiMetrics, PKI_METRICS } from "./metrics";
import { evaluateIssuance } from "./policy";
import type {
  Denial,
  GrantPolicy,
  IssuancePlan,
  PolicyOutcome,
  PolicyRequest,
  SubjectEntry,
  TraceStep,
} from "./policy-types";
import type { MutationResult, PkiServiceDeps } from "./service-types";
import type { CaRecord, IssuedCertificateRecord } from "./types";

type Json = Record<string, unknown>;

const resultMargin = 60_000;
const inventoryRetentionMs = 90 * 86_400_000;
const maxAttempts = 2;
const maxSerialAttempts = 3;

export interface ConsumerIssueContext {
  readonly actor: Actor;
  readonly consumerId: string;
  readonly environment: string;
  readonly grantName: string;
  readonly idempotencyKey: string;
  readonly body: unknown;
  readonly onTarget?: (target: {
    caId: string;
    issuanceGrantUid: string;
  }) => void;
}

export interface ConsumerIssueResult {
  readonly status: 201;
  readonly body: Json;
  readonly replayed: boolean;
  readonly auditTarget: Record<string, string>;
}

/** What a stored replay record says, whichever store it came from. */
interface Replayed {
  readonly caId: string;
  readonly serial: string;
  readonly notAfter: string;
  readonly grantUid?: string;
  /** Admin only: the record was not yet marked audited. */
  readonly terminalAudit: boolean;
}

type CommitResult =
  | { kind: "issued"; record: IssuedCertificateRecord }
  | { kind: "replay"; replayed: Replayed }
  | { kind: "rerun" };

interface CaMaterial {
  readonly caCert: ParsedCertificate;
  readonly chain: ParsedCertificate[];
}

const reasonOfSlot: Record<QuotaSlot, RateLimitReason> = {
  grantHour: "grant_hour",
  grantDay: "grant_day",
  adminHour: "admin_hour",
  caHour: "ca_hour",
};

/** `grant_day` if present, else the first of grantHour, adminHour, caHour. */
export const reasonOfQuotas = (slots: readonly QuotaSlot[]): RateLimitReason => {
  if (slots.includes("grantDay")) {
    return "grant_day";
  }
  for (const slot of ["grantHour", "adminHour", "caHour"] as const) {
    if (slots.includes(slot)) {
      return reasonOfSlot[slot];
    }
  }
  return "ca_hour";
};

export class IssuanceService {
  private readonly emit: typeof emitPkiMetrics;

  public constructor(
    private readonly deps: PkiServiceDeps,
    private readonly capacity: CapacityService,
  ) {
    this.emit = deps.emit ?? emitPkiMetrics;
  }

  private get pki(): PkiRepository {
    return this.deps.pki;
  }

  private now(): Date {
    return this.deps.now();
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Shared reads
  // -----------------------------------------------------------------------------------------------------------------

  private material(ca: CaRecord): CaMaterial {
    if (ca.certificatePem === undefined || ca.chainPem === undefined) {
      throw serviceUnavailable("The CA record has no certificate.");
    }
    try {
      return {
        caCert: parseCertificate(fromPem(ca.certificatePem, "CERTIFICATE")),
        chain: pemBlocks(ca.chainPem).map((block) =>
          parseCertificate(fromPem(block, "CERTIFICATE")),
        ),
      };
    } catch {
      throw serviceUnavailable("The CA record is malformed.");
    }
  }

  /** The CA checks of step 3. */
  private assertCaUsable(
    ca: CaRecord | undefined,
    environment: string,
    now: Date,
  ): CaRecord {
    if (ca === undefined) {
      throw caNotActive("not_found");
    }
    if (ca.environment !== environment) {
      throw caNotActive("environment_mismatch");
    }
    if (ca.status !== "ACTIVE") {
      throw caNotActive(caStatusReason[ca.status]);
    }
    if (!ca.policy.issueLeaves) {
      throw caNotActive("leaves_not_permitted");
    }
    if (ca.key.state !== "ACTIVE" || ca.key.wrapped === undefined) {
      throw caKeyUnavailable();
    }
    if (ca.notBefore !== undefined && Date.parse(ca.notBefore) > now.getTime()) {
      throw caNotActive("not_yet_valid");
    }
    if (ca.notAfter === undefined || Date.parse(ca.notAfter) <= now.getTime()) {
      throw caNotActive("expired");
    }
    return ca;
  }

  /** A Hemlig CA under a REVOKED ancestor issues nothing: the ancestor's distrust covers the whole subtree at once. */
  private async assertAncestorsUsable(ca: CaRecord): Promise<void> {
    for (const ancestorId of hemligAncestors(ca)) {
      const ancestor = await this.pki.getCa(ancestorId);
      if (ancestor === undefined) {
        throw serviceUnavailable("The ancestor CA record is missing.");
      }
      if (ancestor.status === "REVOKED") {
        throw caNotActive("ancestor_revoked");
      }
    }
  }

  private denialError(denial: Denial): ApiError {
    return issuanceDenied(
      denial.reason,
      undefined,
      denial.denied === undefined
        ? undefined
        : { type: denial.denied.type, value: denial.denied.value },
    );
  }

  private runEngine(
    mapping: ReturnType<typeof csrToPolicyRequest>,
    ca: CaRecord,
    material: CaMaterial,
    grant: GrantPolicy | undefined,
    now: Date,
  ): { plan: IssuancePlan } {
    if (!mapping.ok) {
      throw this.denialError(mapping.denial);
    }
    let outcome: PolicyOutcome;
    try {
      outcome = evaluateIssuance({
        request: mapping.request,
        ...(grant === undefined ? {} : { grant }),
        ca: caPolicyInputOf(ca, material.caCert, material.chain),
        now,
      });
    } catch {
      // A stored policy that no longer compiles.
      throw serviceUnavailable("The policy could not be evaluated.");
    }
    if (!outcome.ok) {
      throw this.denialError(outcome.denial);
    }
    return { plan: outcome.plan };
  }

  private async quotaCandidate(
    slots: readonly {
      slot: QuotaSlot;
      key: ReturnType<typeof pkiKeys.caQuota>;
      limit: number;
    }[],
  ): Promise<{ failing: QuotaSlot[] }> {
    const counts = await Promise.all(
      slots.map((entry) => this.pki.getQuotaCount(entry.key)),
    );
    return {
      failing: slots
        .filter((entry, index) => (counts[index] as number) >= entry.limit)
        .map((entry) => entry.slot),
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Replay
  // -----------------------------------------------------------------------------------------------------------------

  /** The replay checks every path that returns stored bytes passes (plan 5.4, steps 2 to 6). */
  private async replayChecked(replayed: Replayed): Promise<{
    cert: IssuedCertificateRecord;
    ca: CaRecord;
  }> {
    const now = this.now();
    if (Date.parse(replayed.notAfter) + inventoryRetentionMs <= now.getTime()) {
      throw issuanceExpired("inventory_expired");
    }
    const [cert, ca] = await Promise.all([
      this.pki.getCertificate(replayed.caId, replayed.serial),
      this.pki.getCa(replayed.caId),
    ]);
    if (cert === undefined || ca === undefined) {
      throw serviceUnavailable("The stored certificate is unavailable.");
    }
    if (cert.status === "REVOKED") {
      throw issuanceRevoked("certificate_revoked");
    }
    if (ca.status === "REVOKED") {
      throw issuanceRevoked("ca_revoked");
    }
    for (const ancestorId of hemligAncestors(ca)) {
      const ancestor = await this.pki.getCa(ancestorId);
      if (ancestor === undefined) {
        throw serviceUnavailable("The ancestor CA record is missing.");
      }
      if (ancestor.status === "REVOKED") {
        throw issuanceRevoked("ancestor_revoked");
      }
    }
    if (Date.parse(cert.notAfter) <= now.getTime() + resultMargin) {
      throw issuanceExpired("result_expiring");
    }
    return { cert, ca };
  }

  private consumerTarget(
    ctx: ConsumerIssueContext,
    cert: IssuedCertificateRecord,
    uid: string,
    replayed: boolean,
  ): Record<string, string> {
    const k8s = cert.requester.asserted?.kubernetes;
    return {
      consumerId: ctx.consumerId,
      environment: ctx.environment,
      issuanceGrant: ctx.grantName,
      issuanceGrantUid: uid,
      caId: cert.caId,
      serial: cert.serial,
      fingerprint: cert.fingerprint,
      notAfter: cert.notAfter,
      replayed: String(replayed),
      lifetimeClamped: String(cert.lifetimeClamped === true),
      ...(k8s === undefined ? {} : { k8sNamespace: k8s.namespace }),
    };
  }

  private async consumerReplay(
    ctx: ConsumerIssueContext,
    replayed: Replayed,
  ): Promise<ConsumerIssueResult> {
    ctx.onTarget?.({
      caId: replayed.caId,
      issuanceGrantUid: replayed.grantUid ?? "",
    });
    const { cert, ca } = await this.replayChecked(replayed);
    return {
      status: 201,
      body: issueResponse(cert, ca, ctx.grantName),
      replayed: true,
      auditTarget: this.consumerTarget(
        ctx,
        cert,
        replayed.grantUid ?? "",
        true,
      ),
    };
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Signing and committing
  // -----------------------------------------------------------------------------------------------------------------

  private reportSigning(error: unknown): void {
    if (!(error instanceof ApiError)) {
      return;
    }
    if (error.code === "ca_key_unavailable") {
      this.emit(this.deps.config.environmentName, {
        [PKI_METRICS.caKeyUnavailable]: 1,
      });
    } else if (error.safeReason === "kms_access_denied") {
      this.emit(this.deps.config.environmentName, {
        [PKI_METRICS.kmsAccessDenied]: 1,
      });
    }
  }

  private async signAndCommit(args: {
    ca: CaRecord;
    material: CaMaterial;
    parsed: ParsedCsr;
    plan: IssuancePlan;
    now: Date;
    requester: IssuedCertificateRecord["requester"];
    commit: (certificate: IssuedCertificateRecord) => IssuanceCommit;
    readReplay: () => Promise<Replayed | undefined>;
  }): Promise<CommitResult> {
    const { ca, material, parsed, plan, now } = args;
    const signer = this.deps.signerFor(ca);
    const replayOr503 = async (): Promise<CommitResult> => {
      const replayed = await args.readReplay();
      if (replayed === undefined) {
        throw serviceUnavailable("The certificate could not be confirmed.");
      }
      return { kind: "replay", replayed };
    };
    for (let serialAttempt = 0; serialAttempt < maxSerialAttempts; serialAttempt += 1) {
      const built = buildLeafToSign(plan, material.caCert, parsed.spkiDer);
      let signature: Uint8Array;
      try {
        signature = await signer.sign(built.tbs);
      } catch (error) {
        this.reportSigning(error);
        throw error;
      }
      const der = assembleLeaf(built, signature);
      const leaf = assertLeafMatchesPlan(der, {
        built,
        plan,
        caCert: material.caCert,
        spkiDer: parsed.spkiDer,
      });
      if (leaf.notAfter.getTime() <= this.now().getTime() + resultMargin) {
        throw issuanceExpired("issuance_expired");
      }
      const record: IssuedCertificateRecord = {
        caId: ca.caId,
        environment: ca.environment,
        serial: built.serialHex,
        status: "ISSUED",
        certificatePem: toPem(der, "CERTIFICATE"),
        fingerprint: leaf.fingerprint,
        spkiSha256: parsed.spkiSha256,
        subject: subjectDn(
          plan.subject.map((entry) => ({
            oid: shortOid[entry.type] as string,
            value: entry.value,
          })),
        ),
        sans: {
          dns: [...plan.sans.dns],
          ip: [...plan.sans.ip],
          uri: [...plan.sans.uri],
        },
        keyAlgorithm: plan.keyAlgorithm,
        keyUsages: [...plan.keyUsages],
        extendedKeyUsages: [...plan.extendedKeyUsages],
        isCa: false,
        lifetimeClamped: plan.lifetimeClamped,
        notBefore: leaf.notBefore.toISOString(),
        notAfter: leaf.notAfter.toISOString(),
        issuedAt: now.toISOString(),
        requester: args.requester,
      };
      const outcome = await this.pki.commitIssuance(args.commit(record));
      switch (outcome.kind) {
        case "committed":
          // An earlier send had an unknown outcome: the certificate may have been revoked since.
          if (outcome.ambiguous === true) {
            return replayOr503();
          }
          return { kind: "issued", record };
        case "replayExists":
          // The local certificate is discarded and not charged.
          return replayOr503();
        case "quotaExhausted": {
          const replayed = await args.readReplay();
          if (replayed !== undefined) {
            return { kind: "replay", replayed };
          }
          throw issuanceRateLimited(
            reasonOfQuotas(outcome.quotas),
            outcome.retryAfterSeconds,
          );
        }
        case "preconditionFailed":
        case "unclassified":
          return { kind: "rerun" };
        case "serialCollision":
          continue;
        case "conflict":
          throw serviceUnavailable("The certificate could not be committed.");
        case "ambiguous":
          return replayOr503();
      }
    }
    throw serviceUnavailable("The certificate could not be committed.");
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Consumer issuance
  // -----------------------------------------------------------------------------------------------------------------

  public async issueForConsumer(
    ctx: ConsumerIssueContext,
  ): Promise<ConsumerIssueResult> {
    const input: ConsumerIssueInput = parseConsumerIssueRequest(ctx.body);
    const csrSha = csrDerSha256(input.certificateSigningRequestPem);
    const digest = consumerIssueDigest(
      ctx.consumerId,
      ctx.grantName,
      csrSha,
      input,
    );
    const readReplay = async (): Promise<Replayed | undefined> => {
      const record = await this.pki.getReplayRecord(
        ctx.consumerId,
        ctx.idempotencyKey,
      );
      if (record === undefined) {
        return undefined;
      }
      if (record.requestDigest !== digest) {
        throw idempotencyKeyReused();
      }
      return {
        caId: record.caId,
        serial: record.serial,
        notAfter: record.notAfter,
        grantUid: record.grantUid,
        terminalAudit: false,
      };
    };

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      // Step 2: a replay record decides everything; no quota or capacity is read.
      const prior = await readReplay();
      if (prior !== undefined) {
        return this.consumerReplay(ctx, prior);
      }

      // Step 3: preconditions, read strongly on every attempt.
      const now = this.now();
      const [identity, agentGrantId, grant] = await Promise.all([
        this.deps.repository.getIdentity(ctx.actor.id),
        this.deps.repository.getAgentGrantIdForConsumer(ctx.consumerId),
        this.pki.getGrant(ctx.consumerId, ctx.grantName),
      ]);
      if (
        identity === undefined ||
        identity.kind !== "api" ||
        identity.status !== "ACTIVE" ||
        Date.parse(identity.notBefore) > now.getTime() ||
        Date.parse(identity.notAfter) <= now.getTime() ||
        identity.consumerId !== ctx.consumerId ||
        identity.environment !== ctx.environment
      ) {
        throw identityNotActive();
      }
      if (agentGrantId !== undefined) {
        const agent = await this.deps.repository.getAgentGrant(agentGrantId);
        if (
          agent === undefined ||
          agent.status !== "ACTIVE" ||
          agent.environment !== ctx.environment ||
          agent.consumerId !== ctx.consumerId
        ) {
          throw agentGrantInactive();
        }
      }
      if (
        grant === undefined ||
        grant.status === "DELETED" ||
        grant.environment !== ctx.environment
      ) {
        throw issuanceGrantNotFound();
      }
      ctx.onTarget?.({ caId: grant.caId, issuanceGrantUid: grant.uid });
      if (grant.status === "DISABLED") {
        throw issuanceGrantInactive("grant_disabled");
      }
      if (grantExpired(grant, now)) {
        throw issuanceGrantInactive("grant_expired");
      }
      const ca = this.assertCaUsable(
        await this.pki.getCa(grant.caId),
        grant.environment,
        now,
      );
      await this.assertAncestorsUsable(ca);

      // Step 4: capacity, then quota, then one more look for a winner.
      const windows = quotaWindows(now);
      const quotas = resolvedQuotas(grant.policy);
      const [count, quotaState] = await Promise.all([
        this.pki
          .getCaCrlState(ca.caId)
          .then((crl) => this.capacity.current(ca, crl, now)),
        this.quotaCandidate([
          {
            slot: "grantHour",
            key: pkiKeys.grantQuota(grant.uid, windows.hourSk),
            limit: quotas.perHour,
          },
          {
            slot: "grantDay",
            key: pkiKeys.grantQuota(grant.uid, windows.daySk),
            limit: quotas.perDay,
          },
          {
            slot: "caHour",
            key: pkiKeys.caQuota(ca.caId, windows.hourSk),
            limit: ca.policy.issuancePerHour,
          },
        ]),
      ]);
      let candidate: ApiError | undefined;
      if (count >= ca.policy.capacity) {
        candidate = caCapacityExceeded();
      } else if (quotaState.failing.length > 0) {
        candidate = issuanceRateLimited(
          reasonOfQuotas(quotaState.failing),
          quotaRetryAfterSeconds(quotaState.failing, now),
        );
      }
      if (candidate !== undefined) {
        const winner = await readReplay();
        if (winner !== undefined) {
          return this.consumerReplay(ctx, winner);
        }
        throw candidate;
      }

      // Steps 5 to 10.
      const parsed = parseCsr(input.certificateSigningRequestPem);
      const material = this.material(ca);
      const { plan } = this.runEngine(
        csrToPolicyRequest(parsed, input, "consumer"),
        ca,
        material,
        grant.policy,
        now,
      );

      // Steps 11 and 12.
      const requester: IssuedCertificateRecord["requester"] = {
        type: "consumer",
        id: ctx.actor.id,
        consumerId: ctx.consumerId,
        issuanceGrant: {
          name: grant.name,
          uid: grant.uid,
          version: grant.version,
        },
        ...(input.requester?.kubernetes === undefined
          ? {}
          : { asserted: { kubernetes: input.requester.kubernetes } }),
      };
      const result = await this.signAndCommit({
        ca,
        material,
        parsed,
        plan,
        now,
        requester,
        readReplay,
        commit: (certificate): ConsumerIssuanceCommit => ({
          path: "consumer",
          now,
          idempotencyKey: ctx.idempotencyKey,
          requestDigest: digest,
          certificate,
          ca: {
            caId: ca.caId,
            version: ca.version,
            issuancePerHour: ca.policy.issuancePerHour,
          },
          ancestors: hemligAncestors(ca),
          consumerId: ctx.consumerId,
          identityFingerprint: ctx.actor.id,
          grant: {
            name: grant.name,
            uid: grant.uid,
            version: grant.version,
            perHour: quotas.perHour,
            perDay: quotas.perDay,
          },
          ...(agentGrantId === undefined
            ? {}
            : {
                agentGrant: {
                  grantId: agentGrantId,
                  environment: ctx.environment,
                },
              }),
        }),
      });
      if (result.kind === "issued") {
        return {
          status: 201,
          body: issueResponse(result.record, ca, ctx.grantName),
          replayed: false,
          auditTarget: this.consumerTarget(
            ctx,
            result.record,
            grant.uid,
            false,
          ),
        };
      }
      if (result.kind === "replay") {
        return this.consumerReplay(ctx, result.replayed);
      }
    }
    throw serviceUnavailable(
      "The certificate could not be issued; retry with the same Idempotency-Key.",
    );
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Admin issuance
  // -----------------------------------------------------------------------------------------------------------------

  private adminTarget(
    cert: IssuedCertificateRecord,
    replayed: boolean,
  ): Record<string, string> {
    return {
      caId: cert.caId,
      environment: cert.environment,
      serial: cert.serial,
      fingerprint: cert.fingerprint,
      notAfter: cert.notAfter,
      replayed: String(replayed),
    };
  }

  private async adminReplay(replayed: Replayed): Promise<MutationResult> {
    const { cert, ca } = await this.replayChecked(replayed);
    return {
      body: issueResponse(cert, ca),
      status: 201,
      shouldWriteTerminalAudit: replayed.terminalAudit,
      auditTarget: this.adminTarget(cert, true),
    };
  }

  public async issueForAdmin(
    actor: Actor,
    key: string,
    caId: string,
    body: unknown,
  ): Promise<MutationResult> {
    const input: AdminIssueInput = parseAdminIssueRequest(body);
    const csrSha = csrDerSha256(input.certificateSigningRequestPem);
    const digest = adminIssueDigest(caId, csrSha, input);
    const readReplay = async (): Promise<Replayed | undefined> => {
      const stored = await this.deps.repository.getIdempotency(actor, key);
      if (stored === undefined) {
        return undefined;
      }
      assertHumanReplay(stored, "pki.certificate.issue", digest);
      const result = stored.result as Json | undefined;
      if (
        typeof result?.caId !== "string" ||
        typeof result.serial !== "string" ||
        typeof result.notAfter !== "string"
      ) {
        throw serviceUnavailable("The stored idempotency record is incomplete.");
      }
      return {
        caId: result.caId,
        serial: result.serial,
        notAfter: result.notAfter,
        terminalAudit: stored.status !== "SUCCEEDED",
      };
    };

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const prior = await readReplay();
      if (prior !== undefined) {
        return this.adminReplay(prior);
      }
      const now = this.now();
      const found = await this.pki.getCa(caId);
      if (found === undefined) {
        throw pkiNotFound("ca_not_found");
      }
      const ca = this.assertCaUsable(found, found.environment, now);
      await this.assertAncestorsUsable(ca);

      const windows = quotaWindows(now);
      const [count, quotaState] = await Promise.all([
        this.pki
          .getCaCrlState(ca.caId)
          .then((crl) => this.capacity.current(ca, crl, now)),
        this.quotaCandidate([
          {
            slot: "adminHour",
            key: pkiKeys.adminQuota(ca.caId, windows.hourSk),
            limit: ADMIN_ISSUANCE_PER_HOUR,
          },
          {
            slot: "caHour",
            key: pkiKeys.caQuota(ca.caId, windows.hourSk),
            limit: ca.policy.issuancePerHour,
          },
        ]),
      ]);
      let candidate: ApiError | undefined;
      if (count >= ca.policy.capacity) {
        candidate = caCapacityExceeded();
      } else if (quotaState.failing.length > 0) {
        candidate = issuanceRateLimited(
          reasonOfQuotas(quotaState.failing),
          quotaRetryAfterSeconds(quotaState.failing, now),
        );
      }
      if (candidate !== undefined) {
        const winner = await readReplay();
        if (winner !== undefined) {
          return this.adminReplay(winner);
        }
        throw candidate;
      }

      const parsed = parseCsr(input.certificateSigningRequestPem);
      const material = this.material(ca);
      const { plan } = this.runEngine(
        csrToPolicyRequest(
          parsed,
          input,
          "admin",
          input.useCsrNames
            ? undefined
            : {
                ...(input.sans === undefined ? {} : { sans: input.sans }),
                ...(input.subject === undefined
                  ? {}
                  : { subject: input.subject }),
              },
        ),
        ca,
        material,
        undefined,
        now,
      );
      const result = await this.signAndCommit({
        ca,
        material,
        parsed,
        plan,
        now,
        requester: { type: "human", id: actor.id },
        readReplay,
        commit: (certificate): AdminIssuanceCommit => ({
          path: "admin",
          now,
          idempotencyKey: key,
          requestDigest: digest,
          certificate,
          ca: {
            caId: ca.caId,
            version: ca.version,
            issuancePerHour: ca.policy.issuancePerHour,
          },
          ancestors: hemligAncestors(ca),
          actor,
          adminPerHour: ADMIN_ISSUANCE_PER_HOUR,
        }),
      });
      if (result.kind === "issued") {
        return {
          body: issueResponse(result.record, ca),
          status: 201,
          shouldWriteTerminalAudit: true,
          auditTarget: this.adminTarget(result.record, false),
        };
      }
      if (result.kind === "replay") {
        return this.adminReplay(result.replayed);
      }
    }
    throw serviceUnavailable(
      "The certificate could not be issued; retry with the same Idempotency-Key.",
    );
  }

  // -----------------------------------------------------------------------------------------------------------------
  // Evaluate
  // -----------------------------------------------------------------------------------------------------------------

  public async evaluate(
    consumerId: string,
    name: string,
    body: unknown,
  ): Promise<Json> {
    const input = parseEvaluateRequest(body);
    const grant = await this.pki.getGrant(consumerId, name);
    if (grant === undefined || grant.status === "DELETED") {
      throw issuanceGrantNotFound();
    }
    const found = await this.pki.getCa(grant.caId);
    if (found === undefined) {
      throw caNotActive("not_found");
    }
    if (found.certificatePem === undefined || found.chainPem === undefined) {
      throw caNotActive("pending_certificate");
    }
    const ca = found;
    const material = this.material(ca);
    const now = this.now();

    const trace: TraceStep[] = [];
    let outcome: PolicyOutcome | undefined;
    let denial: Denial | undefined;
    let request: PolicyRequest | undefined;
    if (input.csr !== undefined) {
      let parsed: ParsedCsr | undefined;
      try {
        parsed = parseCsr(input.csr);
        trace.push({ step: 5, name: "csr", outcome: "pass" });
      } catch (error) {
        if (error instanceof ApiError && error.code === "issuance_denied") {
          denial = {
            reason: (error.safeReason ?? "key_algorithm_not_permitted") as Denial["reason"],
            detail: "the CSR key is not issuable",
          };
          trace.push({
            step: 5,
            name: "csr",
            outcome: "deny",
            detail: error.safeReason ?? "denied",
          });
        } else {
          throw error;
        }
      }
      if (parsed !== undefined) {
        const mapping = csrToPolicyRequest(parsed, input, "consumer");
        if (mapping.ok) {
          request = mapping.request;
        } else {
          denial = mapping.denial;
          trace.push({
            step: 5,
            name: "csr",
            outcome: "deny",
            detail: mapping.denial.reason,
          });
        }
      }
    } else {
      trace.push({
        step: 5,
        name: "csr",
        outcome: "skipped",
        detail: "no CSR supplied",
      });
      request = {
        source: "consumer",
        keyAlgorithm: input.keyAlgorithm as string,
        sans: {
          dns: input.sans?.dns ?? [],
          ip: input.sans?.ip ?? [],
          uri: input.sans?.uri ?? [],
        },
        ...(input.commonName === undefined
          ? {}
          : { commonName: input.commonName }),
        subject: input.subject ?? [],
        usages: input.usages,
        ...(input.durationSeconds === undefined
          ? {}
          : { durationSeconds: input.durationSeconds }),
        isCA: input.isCA,
      };
    }
    if (request !== undefined) {
      try {
        outcome = evaluateIssuance({
          request,
          grant: grant.policy,
          ca: caPolicyInputOf(ca, material.caCert, material.chain),
          now,
        });
      } catch {
        throw serviceUnavailable("The policy could not be evaluated.");
      }
      trace.push(...outcome.trace);
      if (!outcome.ok) {
        denial = outcome.denial;
      }
    }
    trace.sort((left, right) => left.step - right.step);

    const windows = quotaWindows(now);
    const quotas = resolvedQuotas(grant.policy);
    const [crl, grantHour, grantDay, caHour] = await Promise.all([
      ca.status === "ACTIVE" || ca.status === "RETIRED"
        ? this.pki.getCaCrlState(ca.caId)
        : Promise.resolve(undefined),
      this.pki.getQuotaCount(pkiKeys.grantQuota(grant.uid, windows.hourSk)),
      this.pki.getQuotaCount(pkiKeys.grantQuota(grant.uid, windows.daySk)),
      this.pki.getQuotaCount(pkiKeys.caQuota(ca.caId, windows.hourSk)),
    ]);
    const plan = outcome?.ok === true ? outcome.plan : undefined;
    return {
      decision: denial === undefined && plan !== undefined ? "allow" : "deny",
      ...(denial === undefined
        ? {}
        : {
            denial: {
              reason: denial.reason,
              detail: denial.detail,
              ...(denial.denied === undefined
                ? {}
                : {
                    ...deniedNameFields(denial.denied),
                  }),
            },
          }),
      trace,
      ...(plan === undefined ? {} : { plan: planView(plan) }),
      context: {
        grant: {
          status: grant.status,
          expired: grantExpired(grant, now),
        },
        ca: { status: ca.status, keyState: ca.key.state },
        capacity: {
          capacity: ca.policy.capacity,
          ...(crl?.capacity === undefined
            ? {}
            : {
                count: crl.capacity.count,
                countedAt: crl.capacity.countedAt,
              }),
        },
        quotas: {
          grantHour: { count: grantHour, limit: quotas.perHour },
          grantDay: { count: grantDay, limit: quotas.perDay },
          caHour: { count: caHour, limit: ca.policy.issuancePerHour },
        },
      },
    };
  }
}

const shortOid: Record<string, string> = {
  country: "2.5.4.6",
  state: "2.5.4.8",
  locality: "2.5.4.7",
  organization: "2.5.4.10",
  organizationalUnit: "2.5.4.11",
  commonName: "2.5.4.3",
};

const planView = (plan: IssuancePlan): Json => ({
  keyAlgorithm: plan.keyAlgorithm,
  sans: plan.sans,
  subject: subjectDn(
    plan.subject.map((entry) => ({
      oid: shortOid[entry.type] as string,
      value: entry.value,
    })),
  ),
  keyUsages: plan.keyUsages,
  extendedKeyUsages: plan.extendedKeyUsages,
  certificatePolicies: plan.certificatePolicies,
  notBefore: plan.notBefore.toISOString(),
  notAfter: plan.notAfter.toISOString(),
  lifetimeClamped: plan.lifetimeClamped,
  sanCritical: plan.sanCritical,
});

// ---------------------------------------------------------------------------------------------------------------------
// Evaluate request
// ---------------------------------------------------------------------------------------------------------------------

export interface EvaluateInput {
  csr?: string;
  keyAlgorithm?: string;
  sans?: { dns?: string[]; ip?: string[]; uri?: string[] };
  commonName?: string;
  subject?: SubjectEntry[];
  durationSeconds?: number;
  usages: string[];
  isCA: boolean;
}

const evaluateKeys = [
  "certificateSigningRequestPem",
  "keyAlgorithm",
  "sans",
  "commonName",
  "subject",
  "durationSeconds",
  "usages",
  "isCA",
] as const;
const evaluateSubjectKeys = [
  "organization",
  "organizationalUnit",
  "country",
  "locality",
  "state",
] as const;

export const parseEvaluateRequest = (body: unknown): EvaluateInput => {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw pkiBadRequest("evaluate_input", "The request body must be an object.");
  }
  const raw = body as Json;
  for (const key of Object.keys(raw)) {
    if (!(evaluateKeys as readonly string[]).includes(key)) {
      throw pkiBadRequest("unknown_field", "The request has an unknown field.");
    }
  }
  const hasCsr = raw.certificateSigningRequestPem !== undefined;
  const hasNames =
    raw.sans !== undefined ||
    raw.commonName !== undefined ||
    raw.subject !== undefined;
  if (hasCsr === (raw.keyAlgorithm !== undefined) || (hasCsr && hasNames)) {
    throw pkiBadRequest(
      "evaluate_input",
      "Supply either a CSR, or a key algorithm with names.",
    );
  }
  if (!hasCsr && !hasNames) {
    throw pkiBadRequest(
      "evaluate_input",
      "Supply either a CSR, or a key algorithm with names.",
    );
  }
  const list = (value: unknown, label: string): string[] | undefined => {
    if (value === undefined) {
      return undefined;
    }
    if (
      !Array.isArray(value) ||
      value.length > 100 ||
      value.some((entry) => typeof entry !== "string" || entry.length > 2048)
    ) {
      throw pkiBadRequest("evaluate_input", `${label} must be a list of strings.`);
    }
    return value as string[];
  };
  const input: EvaluateInput = { usages: [], isCA: false };
  if (hasCsr) {
    if (typeof raw.certificateSigningRequestPem !== "string") {
      throw pkiBadRequest("evaluate_input", "The CSR must be a string.");
    }
    input.csr = raw.certificateSigningRequestPem;
  } else {
    if (typeof raw.keyAlgorithm !== "string") {
      throw pkiBadRequest("evaluate_input", "keyAlgorithm must be a string.");
    }
    input.keyAlgorithm = raw.keyAlgorithm;
  }
  if (raw.sans !== undefined) {
    const sans = raw.sans as Json;
    if (typeof sans !== "object" || sans === null || Array.isArray(sans)) {
      throw pkiBadRequest("evaluate_input", "sans must be an object.");
    }
    for (const key of Object.keys(sans)) {
      if (!["dns", "ip", "uri"].includes(key)) {
        throw pkiBadRequest("unknown_field", "The request has an unknown field.");
      }
    }
    input.sans = {
      ...(list(sans.dns, "sans.dns") === undefined
        ? {}
        : { dns: list(sans.dns, "sans.dns") as string[] }),
      ...(list(sans.ip, "sans.ip") === undefined
        ? {}
        : { ip: list(sans.ip, "sans.ip") as string[] }),
      ...(list(sans.uri, "sans.uri") === undefined
        ? {}
        : { uri: list(sans.uri, "sans.uri") as string[] }),
    };
  }
  if (raw.commonName !== undefined) {
    if (typeof raw.commonName !== "string") {
      throw pkiBadRequest("evaluate_input", "commonName must be a string.");
    }
    input.commonName = raw.commonName;
  }
  if (raw.subject !== undefined) {
    const subject = raw.subject as Json;
    if (typeof subject !== "object" || subject === null || Array.isArray(subject)) {
      throw pkiBadRequest("evaluate_input", "subject must be an object.");
    }
    const entries: SubjectEntry[] = [];
    if (subject.commonName !== undefined) {
      if (typeof subject.commonName !== "string" || raw.commonName !== undefined) {
        throw pkiBadRequest("evaluate_input", "commonName is given twice.");
      }
      input.commonName = subject.commonName;
    }
    for (const key of Object.keys(subject)) {
      if (key === "commonName") {
        continue;
      }
      if (!(evaluateSubjectKeys as readonly string[]).includes(key)) {
        throw pkiBadRequest("unknown_field", "The request has an unknown field.");
      }
      if (typeof subject[key] !== "string") {
        throw pkiBadRequest("evaluate_input", "subject values must be strings.");
      }
      entries.push({
        type: key as SubjectEntry["type"],
        value: subject[key] as string,
      });
    }
    input.subject = entries;
  }
  if (raw.durationSeconds !== undefined) {
    if (
      typeof raw.durationSeconds !== "number" ||
      !Number.isSafeInteger(raw.durationSeconds) ||
      raw.durationSeconds <= 0
    ) {
      throw pkiBadRequest(
        "invalid_duration",
        "durationSeconds must be a positive integer.",
      );
    }
    input.durationSeconds = raw.durationSeconds;
  }
  if (raw.usages !== undefined) {
    if (
      !Array.isArray(raw.usages) ||
      raw.usages.length > 16 ||
      raw.usages.some((usage) => typeof usage !== "string" || usage.length > 64)
    ) {
      throw pkiBadRequest("invalid_usages", "usages is invalid.");
    }
    input.usages = raw.usages as string[];
  }
  if (raw.isCA !== undefined) {
    if (typeof raw.isCA !== "boolean") {
      throw pkiBadRequest("evaluate_input", "isCA must be a boolean.");
    }
    input.isCA = raw.isCA;
  }
  return input;
};

