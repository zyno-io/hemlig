import {
  pkiKeys,
  quotaWindows,
  type CreateIntermediateTransaction,
  type DistrustRootTransaction,
  type HumanIdempotencyWrite,
  type RevokeIntermediateTransaction,
  type TransactOutcome,
} from "../../repositories/pki";
import { CaService } from "../ca-service";
import { WrappedCaSigner } from "../signer";
import type {
  CaCrlState,
  CaRecord,
  IssuedCertificateRecord,
  RevocationEntryRecord,
} from "../types";
import { mockKms } from "./testkit";

export const admin = { type: "human" as const, id: "admin-1" };

export const rootBody = (extra: Record<string, unknown> = {}) => ({
  environment: "prod",
  name: "hemlig-root",
  kind: "ROOT",
  keyAlgorithm: "ECDSA_P384",
  subject: { commonName: "Hemlig Root CA", organization: "Example Corp" },
  requestedConstraints: {
    nameConstraints: { permitted: { dns: ["example.com"] } },
    extendedKeyUsages: ["serverAuth"],
  },
  ...extra,
});

export const childBody = (
  parentCaId: string,
  extra: Record<string, unknown> = {},
) => ({
  environment: "prod",
  name: "hemlig-issuing-1",
  kind: "INTERMEDIATE",
  parentCaId,
  keyAlgorithm: "ECDSA_P256",
  subject: { commonName: "Hemlig Issuing CA 1", organization: "Example Corp" },
  ...extra,
});

type Outcome = { kind: string; [key: string]: unknown };

/**
 * An in-memory `pki` double for the Hemlig hierarchy: CA records, CRL states, inventory rows, revocation entries,
 * quota counters and claims, with the conditions the real transactions enforce. Every method is a `jest.fn`, so
 * tests inspect or override it. Queued `createOutcomes` replace the next `createIntermediateCa` result.
 */
export const hierarchyHarness = (options: { now?: Date } = {}) => {
  const clock = { now: options.now ?? new Date() };
  const kms = mockKms();
  const state = {
    cas: new Map<string, CaRecord>(),
    crls: new Map<string, CaCrlState>(),
    certs: new Map<string, IssuedCertificateRecord>(),
    entries: new Map<string, RevocationEntryRecord>(),
    quotas: new Map<string, number>(),
    names: new Set<string>(),
    subjects: new Map<string, Record<string, unknown>>(),
    human: new Map<string, Record<string, unknown>>(),
    objects: new Map<string, Buffer>(),
    createOutcomes: [] as Outcome[],
    certificatesSince: 0,
  };
  const certKey = (caId: string, serial: string): string => `${caId}#${serial}`;
  const quotaKey = (key: { pk: string; sk: string }): string =>
    `${key.pk}|${key.sk}`;
  const idempotent = (write: HumanIdempotencyWrite): void => {
    state.human.set(write.idempotencyKey, {
      operationType: write.operationType,
      requestDigest: write.requestDigest,
      status: "COMMITTED",
      result: write.result,
    });
  };
  const patch = (caId: string, fields: Partial<CaRecord>): CaRecord => {
    const next = { ...state.cas.get(caId)!, ...fields } as CaRecord;
    state.cas.set(caId, next);
    return next;
  };

  const pki = {
    getCa: jest.fn(async (id: string) => state.cas.get(id)),
    getCaCrlState: jest.fn(async (id: string) => state.crls.get(id)),
    getExternalCa: jest.fn(async () => undefined),
    getCaNameClaim: jest.fn(async (environment: string, name: string) =>
      state.names.has(`${environment}#${name}`) ? { name } : undefined,
    ),
    getSubjectClaim: jest.fn(async (key: string) => state.subjects.get(key)),
    queryDirectory: jest.fn(
      async (_partition: string, options: { sortPrefix?: string } = {}) =>
        [...state.cas.values()].filter((ca) =>
          `${ca.environment}#`.startsWith(
            options.sortPrefix ?? `${ca.environment}#`,
          ),
        ) as unknown as Record<string, unknown>[],
    ),
    hasGrantsForCa: jest.fn(async () => false),
    getQuotaCount: jest.fn(
      async (key: { pk: string; sk: string }) =>
        state.quotas.get(quotaKey(key)) ?? 0,
    ),
    countCertificatesSince: jest.fn(async () => state.certificatesSince),
    storeCapacityCount: jest.fn(
      async (
        id: string,
        count: { count: number; countFrom: string; countedAt: string },
      ) => {
        const crl = state.crls.get(id);
        if (crl !== undefined) {
          state.crls.set(id, { ...crl, capacity: count });
        }
      },
    ),
    getCertificate: jest.fn(async (caId: string, serial: string) =>
      state.certs.get(certKey(caId, serial)),
    ),
    getRevocationEntry: jest.fn(async (caId: string, serial: string) =>
      state.entries.get(certKey(caId, serial)),
    ),
    createCa: jest.fn(
      async (input: {
        idempotency: HumanIdempotencyWrite;
        ca: CaRecord;
        crl?: CaCrlState;
      }) => {
        if (state.human.has(input.idempotency.idempotencyKey)) {
          return { kind: "replay" };
        }
        const { ca } = input;
        if (state.names.has(`${ca.environment}#${ca.name}`)) {
          return { kind: "nameInUse" };
        }
        if (state.subjects.has(ca.subjectKey)) {
          return { kind: "subjectInUse" };
        }
        state.names.add(`${ca.environment}#${ca.name}`);
        state.subjects.set(ca.subjectKey, {
          ownerType: "ca",
          caId: ca.caId,
        });
        state.cas.set(ca.caId, ca);
        if (input.crl !== undefined) {
          state.crls.set(ca.caId, input.crl);
        }
        idempotent(input.idempotency);
        return { kind: "created" };
      },
    ),
    createIntermediateCa: jest.fn(
      async (input: CreateIntermediateTransaction) => {
        const queued = state.createOutcomes.shift();
        if (queued !== undefined) {
          return queued;
        }
        if (state.human.has(input.idempotency.idempotencyKey)) {
          return { kind: "replay" };
        }
        const parent = state.cas.get(input.parent.caId)!;
        const lifetime = input.parent.childLifetimeSeconds;
        const grows = lifetime > input.parent.loadedMaxIssueLifetimeEverSeconds;
        if (
          parent.version !== input.parent.version ||
          parent.status !== "ACTIVE" ||
          parent.key.state !== "ACTIVE" ||
          (grows && parent.maxIssueLifetimeEverSeconds > lifetime)
        ) {
          return { kind: "parentChanged" };
        }
        const { ca } = input;
        if (state.names.has(`${ca.environment}#${ca.name}`)) {
          return { kind: "nameInUse" };
        }
        if (state.subjects.has(ca.subjectKey)) {
          return { kind: "subjectInUse" };
        }
        const { hourSk } = quotaWindows(input.now);
        const admin = pkiKeys.adminQuota(parent.caId, hourSk);
        const perCa = pkiKeys.caQuota(parent.caId, hourSk);
        const quotas: ("adminHour" | "caHour")[] = [];
        if ((state.quotas.get(quotaKey(admin)) ?? 0) >= input.adminPerHour) {
          quotas.push("adminHour");
        }
        if (
          (state.quotas.get(quotaKey(perCa)) ?? 0) >=
          input.parent.issuancePerHour
        ) {
          quotas.push("caHour");
        }
        if (quotas.length > 0) {
          return { kind: "quotaExhausted", quotas, retryAfterSeconds: 60 };
        }
        const rowKey = certKey(parent.caId, input.certificate.serial);
        if (state.certs.has(rowKey)) {
          return { kind: "serialCollision" };
        }
        state.names.add(`${ca.environment}#${ca.name}`);
        state.subjects.set(ca.subjectKey, { ownerType: "ca", caId: ca.caId });
        state.cas.set(ca.caId, ca);
        state.crls.set(ca.caId, input.crl);
        state.certs.set(rowKey, input.certificate);
        for (const key of [admin, perCa]) {
          state.quotas.set(
            quotaKey(key),
            (state.quotas.get(quotaKey(key)) ?? 0) + 1,
          );
        }
        if (grows) {
          patch(parent.caId, { maxIssueLifetimeEverSeconds: lifetime });
        }
        idempotent(input.idempotency);
        return { kind: "created" };
      },
    ),
    updateCaPolicy: jest.fn(
      async (input: {
        caId: string;
        loadedVersion: string;
        newVersion: string;
        policy: CaRecord["policy"];
        maxIssueLifetimeEverSeconds?: number;
        idempotency: HumanIdempotencyWrite;
      }) => {
        const ca = state.cas.get(input.caId)!;
        if (
          ca.version !== input.loadedVersion ||
          (ca.status !== "ACTIVE" && ca.status !== "PENDING_CERTIFICATE")
        ) {
          return { kind: "conditionFailed" };
        }
        patch(input.caId, {
          policy: input.policy,
          version: input.newVersion,
          ...(input.maxIssueLifetimeEverSeconds === undefined
            ? {}
            : {
                maxIssueLifetimeEverSeconds: input.maxIssueLifetimeEverSeconds,
              }),
        });
        idempotent(input.idempotency);
        return { kind: "committed" };
      },
    ),
    retireCa: jest.fn(
      async (input: {
        caId: string;
        loadedVersion: string;
        newVersion: string;
        now: string;
        idempotency: HumanIdempotencyWrite;
      }) => {
        const ca = state.cas.get(input.caId)!;
        if (ca.version !== input.loadedVersion || ca.status !== "ACTIVE") {
          return { kind: "conditionFailed" };
        }
        patch(input.caId, {
          status: "RETIRED",
          retiredAt: input.now,
          version: input.newVersion,
        });
        idempotent(input.idempotency);
        return { kind: "committed" };
      },
    ),
    putHumanIdempotency: jest.fn(async (write: HumanIdempotencyWrite) => {
      if (state.human.has(write.idempotencyKey)) {
        return "replay" as const;
      }
      idempotent(write);
      return "committed" as const;
    }),
    revokeIntermediateCa: jest.fn(
      async (
        input: RevokeIntermediateTransaction,
      ): Promise<TransactOutcome> => {
        if (state.human.has(input.idempotency.idempotencyKey)) {
          return { kind: "canceled", failed: ["idempotency"] };
        }
        const ca = state.cas.get(input.ca.caId)!;
        if (
          (ca.status !== "ACTIVE" && ca.status !== "RETIRED") ||
          ca.version !== input.ca.version
        ) {
          return { kind: "canceled", failed: ["profile"] };
        }
        const parentCaId = ca.parentCaId!;
        const rowKey = certKey(parentCaId, ca.serial!);
        if (input.row !== undefined) {
          const row = state.certs.get(rowKey);
          const expired =
            Date.parse(input.row.notAfter) <= Date.parse(input.now);
          if (
            row?.status !== "ISSUED" ||
            (input.row.mode === "entry" && expired) ||
            (input.row.mode === "expired" && !expired)
          ) {
            return { kind: "canceled", failed: ["certificate"] };
          }
          state.certs.set(rowKey, {
            ...row,
            status: "REVOKED",
            revocation: { at: input.now, reason: input.reason, by: input.by },
          });
          if (input.row.mode === "entry") {
            state.entries.set(rowKey, {
              caId: parentCaId,
              serial: ca.serial!,
              revokedAt: input.now,
              reason: input.reason,
              notAfter: input.row.notAfter,
            });
            const crl = state.crls.get(parentCaId)!;
            state.crls.set(parentCaId, {
              ...crl,
              revision: crl.revision + 1,
              dirtySince: crl.dirtySince ?? input.now,
            });
          }
        }
        patch(ca.caId, {
          status: "REVOKED",
          revokedAt: input.now,
          revocationReason: input.reason,
          revocationSource: "HEMLIG",
          revocationEvidence: input.evidence,
          version: input.newVersion,
          key: {
            ...ca.key,
            state: ca.key.state === "ACTIVE" ? "DISABLED" : ca.key.state,
          },
        });
        idempotent(input.idempotency);
        return { kind: "committed" };
      },
    ),
    distrustRootCa: jest.fn(async (input: DistrustRootTransaction) => {
      if (state.human.has(input.idempotency.idempotencyKey)) {
        return { kind: "replay" };
      }
      const ca = state.cas.get(input.ca.caId)!;
      if (
        (ca.status !== "ACTIVE" && ca.status !== "RETIRED") ||
        ca.version !== input.ca.version
      ) {
        return { kind: "conditionFailed" };
      }
      patch(ca.caId, {
        status: "REVOKED",
        revokedAt: input.now,
        revocationReason: input.reason,
        revocationSource: "HEMLIG",
        revocationEvidence: input.evidence,
        version: input.newVersion,
        key: {
          ...ca.key,
          state: ca.key.state === "ACTIVE" ? "DISABLED" : ca.key.state,
        },
      });
      idempotent(input.idempotency);
      return { kind: "committed" };
    }),
    revokeForRevokedAncestor: jest.fn(
      async (
        child: CaRecord,
        revocation: { revokedAt: string; reason: string; evidence: string },
        ancestorCaId: string,
      ) => {
        const ca = state.cas.get(child.caId)!;
        if (
          (ca.status !== "ACTIVE" && ca.status !== "RETIRED") ||
          ca.parentCaId !== ancestorCaId ||
          ca.key.state !== child.key.state
        ) {
          return undefined;
        }
        return patch(ca.caId, {
          status: "REVOKED",
          revokedAt: revocation.revokedAt,
          revocationReason: revocation.reason,
          revocationSource: "HEMLIG",
          revocationEvidence: revocation.evidence,
          version: `pkv-${ca.caId}-revoked`,
          key: {
            ...ca.key,
            state: ca.key.state === "ACTIVE" ? "DISABLED" : ca.key.state,
          },
        });
      },
    ),
  };
  const repository = {
    getIdempotency: jest.fn(async (_actor: unknown, key: string) =>
      state.human.get(key),
    ),
    getIssuer: jest.fn(async () => undefined),
    requireEnvironment: jest.fn(async () => ({})),
  };
  const put = jest.fn(async (_bucket: string, key: string, bytes: Buffer) => {
    state.objects.set(key, bytes);
    return {};
  });
  const crls = {
    publish: jest.fn(async (ca: CaRecord) => {
      const crl = state.crls.get(ca.caId)!;
      const published = {
        number: (crl.published?.number ?? 1) + 1,
        objectKey: `crl/${ca.caId}/published`,
        sha256: "0".repeat(64),
        thisUpdate: clock.now.toISOString(),
        nextUpdate: new Date(clock.now.getTime() + 86_400_000).toISOString(),
        revision: crl.revision,
        entryCount: state.entries.size,
      };
      state.crls.set(ca.caId, {
        ...crl,
        published,
        lastNumber: published.number,
      });
      return { kind: "published" as const, pointer: published };
    }),
  };
  const emit = jest.fn();
  const deps = {
    pki,
    repository,
    objects: { putImmutableOrGet: put, getBytes: jest.fn() },
    kms: kms.kms,
    cursors: { encode: jest.fn(), decode: jest.fn() },
    signerFor: (ca: CaRecord) =>
      new WrappedCaSigner({
        kms: kms.kms,
        kmsKeyId: "arn:key",
        caId: ca.caId,
        environment: ca.environment,
        algorithm: ca.key.algorithm,
        wrapped: ca.key.wrapped!,
      }),
    config: {
      pkiBucketName: "pki",
      payloadKmsKeyArn: "arn:key",
      environmentName: "test",
    },
    now: () => clock.now,
    emit,
  };
  const service = new CaService(deps as never, crls as never);
  let sequence = 0;
  const key = (): string => `idem-key-${String(++sequence).padStart(4, "0")}`;
  const call = async (work: Promise<{ body: Record<string, unknown> }>) =>
    (await work).body;
  return {
    clock,
    kms,
    state,
    pki,
    repository,
    put,
    crls,
    emit,
    deps,
    service,
    key,
    /** Creates a ROOT through the service and returns its record. */
    createRoot: async (extra: Record<string, unknown> = {}) => {
      const body = await call(service.create(admin, key(), rootBody(extra)));
      return state.cas.get(body.caId as string)!;
    },
    /** Creates an INTERMEDIATE through the service and returns its record. */
    createChild: async (
      parentCaId: string,
      extra: Record<string, unknown> = {},
    ) => {
      const body = await call(
        service.create(admin, key(), childBody(parentCaId, extra)),
      );
      return state.cas.get(body.caId as string)!;
    },
  };
};

export type HierarchyHarness = ReturnType<typeof hierarchyHarness>;
