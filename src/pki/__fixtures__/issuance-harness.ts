import { randomUUID } from "node:crypto";
import type { PkiRepository, IssuanceCommit } from "../../repositories/pki";
import { encodeSubjectAltName } from "../asn1/names";
import { EXT, extension } from "../asn1/extensions";
import { toPem } from "../asn1/pem";
import { DEFAULT_CA_POLICY } from "../ca-model";
import { CapacityService } from "../capacity-service";
import { CertificateService } from "../certificate-service";
import { CrlService } from "../crl-service";
import { GrantService } from "../grant-service";
import { IssuanceService } from "../issuance-service";
import { WrappedCaSigner } from "../signer";
import type {
  CaCrlState,
  CaRecord,
  IssuanceGrantRecord,
  IssuedCertificateRecord,
  ReplayRecord,
} from "../types";
import { policyDigest } from "../grant-policy";
import type { GrantPolicy } from "../policy-types";
import { wrapCaKey } from "../wrapped-keys";
import {
  csrPem,
  leafKey,
  makeCsrDer,
  makeIntermediate,
  makeRoot,
  mockKms,
  newKey,
  subjectDer,
  type LeafKey,
} from "./testkit";

export const consumerId = "consumer-one";
export const environment = "prod";
export const caId = "ca-test-one";
export const identityId = "a".repeat(64);
export const actor = {
  type: "consumer" as const,
  id: identityId,
  consumerId,
  environment,
};
export const admin = { type: "human" as const, id: "admin-1" };

export const samplePolicy = (
  extra: Record<string, unknown> = {},
): GrantPolicy =>
  ({
    names: { dns: { allow: ["*.example.com", "example.com"] }, maxSans: 10 },
    keyUsages: ["digitalSignature", "keyEncipherment"],
    extendedKeyUsages: {
      allow: ["serverAuth", "clientAuth"],
      default: ["serverAuth"],
    },
    lifetime: { defaultSeconds: 3600, maxSeconds: 86_400, minSeconds: 600 },
    ...extra,
  }) as GrantPolicy;

export interface CsrOptions {
  readonly dns?: string[];
  readonly ip?: string[];
  readonly uri?: string[];
  readonly cn?: string;
  readonly key?: LeafKey;
  readonly extensions?: Buffer[];
}

export const makeCsr = (options: CsrOptions = {}): string => {
  const key = options.key ?? leafKey({ type: "ec", curve: "prime256v1" });
  const names = {
    dns: options.dns ?? ["web.example.com"],
    ip: options.ip ?? [],
    uri: options.uri ?? [],
  };
  const hasNames = names.dns.length + names.ip.length + names.uri.length > 0;
  return csrPem(
    makeCsrDer({
      key,
      subject: subjectDer(options.cn ?? "web.example.com"),
      extensions: [
        ...(hasNames
          ? [
              extension(
                EXT.subjectAltName,
                false,
                encodeSubjectAltName(names),
              ),
            ]
          : []),
        ...(options.extensions ?? []),
      ],
    }),
  );
};

export interface HarnessOptions {
  readonly policy?: GrantPolicy;
  readonly caPolicy?: Partial<CaRecord["policy"]>;
  readonly grant?: Partial<IssuanceGrantRecord>;
  readonly agentGrantId?: string;
  readonly now?: Date;
}

/**
 * An activated CA (testkit root and intermediate, key wrapped with the mock KMS), a grant, an identity and a
 * `pki` double backed by a Map. Every method is a `jest.fn`, so tests override or inspect them.
 */
export const issuanceHarness = async (options: HarnessOptions = {}) => {
  const clock = { now: options.now ?? new Date() };
  const root = await makeRoot();
  const caKey = await newKey("ECDSA_P256");
  const cert = await makeIntermediate(root, { key: caKey });
  const kms = mockKms();
  const wrapped = await wrapCaKey(kms.kms, "arn:key", caKey.pkcs8, {
    caId,
    environment,
  });
  const ca: CaRecord = {
    caId,
    environment,
    name: "prod-issuing-1",
    kind: "EXTERNAL_INTERMEDIATE",
    status: "ACTIVE",
    version: "pkv-ca-1",
    crlIssuers: [],
    key: {
      custody: "WRAPPED",
      algorithm: "ECDSA_P256",
      spkiSha256: "00".repeat(32),
      state: "ACTIVE",
      wrapped,
    },
    subject: { CN: "Test Issuing CA 1" },
    subjectKey: "00".repeat(32),
    requested: { pathLen: 0 },
    certificatePem: cert.pem,
    chainPem: root.pem,
    subjectDer: cert.cert.subjectDer.toString("base64"),
    subjectKeyIdentifier: cert.cert.subjectKeyIdentifier!.toString("hex"),
    notBefore: cert.cert.notBefore.toISOString(),
    notAfter: cert.cert.notAfter.toISOString(),
    policy: { ...DEFAULT_CA_POLICY, ...options.caPolicy },
    maxIssueLifetimeEverSeconds: DEFAULT_CA_POLICY.maxLeafLifetimeSeconds,
    createdAt: clock.now.toISOString(),
    createdBy: admin,
  };
  const policy = options.policy ?? samplePolicy();
  const grant: IssuanceGrantRecord = {
    uid: "pkg-uid-0001",
    consumerId,
    environment,
    name: "web",
    caId,
    status: "ACTIVE",
    policy,
    policyDigest: policyDigest(policy),
    version: "pkv-grant-1",
    createdAt: clock.now.toISOString(),
    createdBy: admin,
    updatedAt: clock.now.toISOString(),
    updatedBy: admin,
    ...options.grant,
  };

  const state = {
    ca,
    crl: {
      revision: 0,
      lastNumber: 1,
    } as CaCrlState | undefined,
    grants: new Map<string, IssuanceGrantRecord>([[grant.name, grant]]),
    certificates: new Map<string, IssuedCertificateRecord>(),
    replays: new Map<string, ReplayRecord>(),
    human: new Map<string, Record<string, unknown>>(),
    quotas: new Map<string, number>(),
    commits: [] as IssuanceCommit[],
    /** Queued outcomes for `commitIssuance`; empty means "apply and commit". */
    outcomes: [] as { kind: string; [key: string]: unknown }[],
    certificatesSince: 0,
    identity: {
      pk: `IDENTITY#${identityId}`,
      sk: "PROFILE",
      fingerprint: identityId,
      consumerId,
      environment,
      kind: "api",
      status: "ACTIVE",
      notBefore: new Date(clock.now.getTime() - 3_600_000).toISOString(),
      notAfter: new Date(clock.now.getTime() + 86_400_000).toISOString(),
    } as Record<string, unknown> | undefined,
    agentGrant: undefined as Record<string, unknown> | undefined,
  };
  if (options.agentGrantId !== undefined) {
    state.agentGrant = {
      grantId: options.agentGrantId,
      consumerId,
      environment,
      status: "ACTIVE",
    };
  }

  const pki = {
    getCa: jest.fn(async (id: string) => (id === caId ? state.ca : undefined)),
    getCaCrlState: jest.fn(async () => state.crl),
    getGrant: jest.fn(async (_consumer: string, name: string) =>
      state.grants.get(name),
    ),
    getReplayRecord: jest.fn(async (_consumer: string, key: string) =>
      state.replays.get(key),
    ),
    getQuotaCount: jest.fn(
      async (key: { pk: string; sk: string }) =>
        state.quotas.get(`${key.pk}|${key.sk}`) ?? 0,
    ),
    getCertificate: jest.fn(async (_ca: string, serial: string) =>
      state.certificates.get(serial),
    ),
    countCertificatesSince: jest.fn(async () => state.certificatesSince),
    storeCapacityCount: jest.fn(
      async (
        _ca: string,
        count: { count: number; countFrom: string; countedAt: string },
      ) => {
        if (state.crl !== undefined) {
          state.crl = { ...state.crl, capacity: count };
        }
      },
    ),
    commitIssuance: jest.fn(async (commit: IssuanceCommit) => {
      state.commits.push(commit);
      const queued = state.outcomes.shift();
      if (queued !== undefined) {
        return queued;
      }
      state.certificates.set(commit.certificate.serial, commit.certificate);
      if (commit.path === "consumer") {
        state.replays.set(commit.idempotencyKey, {
          requestDigest: commit.requestDigest,
          caId: commit.ca.caId,
          serial: commit.certificate.serial,
          notAfter: commit.certificate.notAfter,
          grantUid: commit.grant.uid,
        });
      } else {
        state.human.set(commit.idempotencyKey, {
          operationType: "pki.certificate.issue",
          requestDigest: commit.requestDigest,
          status: "COMMITTED",
          result: {
            caId: commit.ca.caId,
            serial: commit.certificate.serial,
            notAfter: commit.certificate.notAfter,
          },
        });
      }
      return { kind: "committed" };
    }),
  };
  const repository = {
    getIdentity: jest.fn(async () => state.identity),
    getAgentGrantIdForConsumer: jest.fn(
      async () => state.agentGrant?.grantId as string | undefined,
    ),
    getAgentGrant: jest.fn(async () => state.agentGrant),
    getIdempotency: jest.fn(async (_actor: unknown, key: string) =>
      state.human.get(key),
    ),
    getConsumer: jest.fn(async () => ({
      consumerId,
      environment,
      status: "ACTIVE",
    })),
    getIssuer: jest.fn(async () => undefined),
    requireEnvironment: jest.fn(async () => ({})),
  };
  const emit = jest.fn();
  const deps = {
    pki,
    repository,
    objects: { putImmutableOrGet: jest.fn(), getBytes: jest.fn() },
    kms: kms.kms,
    cursors: {
      encode: jest.fn(async () => "cursor"),
      decode: jest.fn(async () => ({ lastEvaluatedKey: undefined })),
    },
    signerFor: (record: CaRecord) =>
      new WrappedCaSigner({
        kms: kms.kms,
        kmsKeyId: "arn:key",
        caId: record.caId,
        environment: record.environment,
        algorithm: record.key.algorithm,
        wrapped: record.key.wrapped!,
      }),
    config: {
      pkiBucketName: "pki",
      payloadKmsKeyArn: "arn:key",
      environmentName: "test",
    },
    now: () => clock.now,
    emit,
  };
  const defaultCsr = makeCsr();
  const capacity = new CapacityService(pki as unknown as PkiRepository);
  const crls = new CrlService(deps as never, async () => undefined);
  return {
    clock,
    root,
    cert,
    ca,
    grant,
    state,
    pki,
    repository,
    deps,
    emit,
    kms,
    crls,
    capacity,
    issuance: new IssuanceService(deps as never, capacity),
    grants: new GrantService(deps as never),
    certificates: new CertificateService(deps as never, crls),
    ctx: (
      overrides: Partial<{
        idempotencyKey: string;
        body: unknown;
        grantName: string;
      }> = {},
    ) => ({
      actor,
      consumerId,
      environment,
      grantName: overrides.grantName ?? "web",
      idempotencyKey: overrides.idempotencyKey ?? `key-${randomUUID()}`,
      body: overrides.body ?? { certificateSigningRequestPem: defaultCsr },
    }),
    defaultCsr,
    pem: toPem,
  };
};

export type Harness = Awaited<ReturnType<typeof issuanceHarness>>;

export const errorOf = async (
  work: Promise<unknown>,
): Promise<{
  statusCode: number;
  code: string;
  safeReason?: string;
  details?: Record<string, unknown>;
  headers?: Record<string, string>;
}> => {
  try {
    await work;
  } catch (error) {
    return error as never;
  }
  throw new Error("expected an error");
};
