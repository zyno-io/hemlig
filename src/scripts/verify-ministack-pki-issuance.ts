import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { ApiError } from "../domain/errors";
import type { Actor } from "../domain/types";
import { parseCrl } from "../pki/asn1/crl";
import { parseRawCsr } from "../pki/asn1/csr";
import { fromPem } from "../pki/asn1/pem";
import { CaService } from "../pki/ca-service";
import { CapacityService } from "../pki/capacity-service";
import { CertificateService } from "../pki/certificate-service";
import { CrlService } from "../pki/crl-service";
import { GrantService } from "../pki/grant-service";
import { IssuanceService } from "../pki/issuance-service";
import { runMaintenancePass } from "../pki/maintenance";
import type { PkiServiceDeps } from "../pki/service-types";
import { WrappedCaSigner } from "../pki/signer";
import type { CaRecord, IssuanceGrantRecord } from "../pki/types";
import { DynamoCursorStore } from "../repositories/cursor-store";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { pkiKeys, PkiRepository, quotaWindows } from "../repositories/pki";
import { CursorService } from "../services/cursor";
import {
  makeIntermediate,
  makeLeafCsr,
  makeRoot,
  type TestCert,
  type TestKey,
} from "./pki-fixtures";
import type { PkiLifecycleOptions } from "./verify-ministack-pki-lifecycle";
import { rootConfig } from "./verify-ministack-pki-lifecycle";

/**
 * The Phase 4 suite against MiniStack: grants, issuance, replay, quota, capacity and revocation through the real
 * repository, services, KMS, S3 and DynamoDB, with injected clocks. Races wrap the repository in a Proxy that runs
 * the competing operation before (or instead of) one chosen method; there are no production hooks.
 */
const check = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(`PKI issuance verification failed: ${message}`);
  }
};

type Hook = (...args: never[]) => Promise<unknown>;

/** Runs each hook once, immediately before the first call of the named method. */
const hooked = <T extends object>(
  target: T,
  hooks: Record<string, Hook>,
): T => {
  const used = new Set<string>();
  return new Proxy(target, {
    get(object, property) {
      const value = Reflect.get(object, property, object) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      const hook = typeof property === "string" ? hooks[property] : undefined;
      if (hook === undefined || used.has(property as string)) {
        return (value as (...a: unknown[]) => unknown).bind(object);
      }
      return async (...args: unknown[]) => {
        used.add(property as string);
        await (hook as (...a: unknown[]) => Promise<unknown>)(...args);
        return (value as (...a: unknown[]) => unknown).apply(object, args);
      };
    },
  });
};

/** Replaces the first call of `method` with `replacement`'s result; later calls go through. */
const stubFirst = <T extends object>(
  target: T,
  method: string,
  replacement: (...args: never[]) => Promise<unknown>,
): T => {
  let used = false;
  return new Proxy(target, {
    get(object, property) {
      const value = Reflect.get(object, property, object) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      if (property !== method || used) {
        return (value as (...a: unknown[]) => unknown).bind(object);
      }
      return async (...args: unknown[]) => {
        used = true;
        return (replacement as (...a: unknown[]) => Promise<unknown>)(...args);
      };
    },
  });
};

const eventually = async (
  condition: () => Promise<boolean>,
  message: string,
): Promise<void> => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (await condition()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`PKI issuance verification failed: ${message}`);
};

interface Consumer {
  readonly consumerId: string;
  readonly fingerprint: string;
  readonly agentGrantId?: string;
}

export const verifyPkiIssuanceOnMiniStack = async (
  options: PkiLifecycleOptions,
): Promise<void> => {
  const { table, bucket, config } = options;
  const doc = DynamoDBDocumentClient.from(options.dynamo, {
    marshallOptions: { removeUndefinedValues: true },
  });
  const objects = new ObjectStore(options.s3);
  const repository = new DynamoRepository(doc, config);
  const repositoryOptions = {
    tableName: table,
    directoryIndex: config.pkiDirectoryIndex,
    sleep: async () => undefined,
  };
  const pki = new PkiRepository(doc, repositoryOptions);
  const cursors = new CursorService(
    new DynamoCursorStore(doc, table, "PKI_CURSOR#"),
  );
  const suffix = randomBytes(4).toString("hex");
  const environment = "ministack";
  const admin: Actor = { type: "human", id: `issuance-admin-${suffix}` };
  const auditEvents: unknown[] = [];
  const audit = {
    write: async (event: Record<string, unknown>) => {
      auditEvents.push(event);
      return { ...event, eventId: randomUUID(), at: new Date().toISOString() };
    },
  } as never;
  let cases = 0;
  const done = (name: string): void => {
    cases += 1;
    process.stdout.write(`PKI issuance ok: ${name}\n`);
  };
  const idem = (): string => `idem-${randomUUID()}`;

  await doc.send(
    new PutCommand({
      TableName: table,
      Item: {
        pk: "SYSTEM#ENVIRONMENTS",
        sk: `ENVIRONMENT#${environment}`,
        name: environment,
        createdAt: new Date().toISOString(),
        createdBy: { type: "system", id: "ministack-verify" },
      },
    }),
  );

  const signerFor: PkiServiceDeps["signerFor"] = ({
    caId,
    environment: env,
    key,
  }) =>
    new WrappedCaSigner({
      kms: options.kms,
      kmsKeyId: options.keyArn,
      caId,
      environment: env,
      algorithm: key.algorithm,
      wrapped: key.wrapped as never,
    });
  const build = (
    overrides: {
      pki?: PkiRepository;
      now?: () => Date;
      crls?: Pick<CrlService, "publish">;
    } = {},
  ) => {
    const deps: PkiServiceDeps = {
      pki: overrides.pki ?? pki,
      repository,
      objects,
      signerFor,
      kms: options.kms,
      cursors,
      config,
      now: overrides.now ?? (() => new Date()),
      emit: () => undefined,
    };
    const crls = new CrlService(deps, async () => undefined);
    const capacity = new CapacityService(deps.pki);
    return {
      deps,
      crls,
      capacity,
      cas: new CaService(deps, crls),
      grants: new GrantService(deps),
      issuance: new IssuanceService(deps, capacity),
      certificates: new CertificateService(
        deps,
        (overrides.crls ?? crls) as CrlService,
      ),
    };
  };
  const svc = build();

  const expectApi = async (
    work: () => Promise<unknown>,
    expected: { status: number; code: string; reason?: string },
    label: string,
  ): Promise<ApiError> => {
    try {
      await work();
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.statusCode === expected.status &&
        error.code === expected.code &&
        (expected.reason === undefined ||
          error.details?.reason === expected.reason)
      ) {
        return error;
      }
      throw new Error(
        `PKI issuance verification failed: ${label} threw ${
          error instanceof ApiError
            ? `${error.statusCode} ${error.code} ${error.details?.reason}`
            : String(error)
        }`,
      );
    }
    throw new Error(`PKI issuance verification failed: ${label} did not throw`);
  };

  // ---- Fixtures --------------------------------------------------------------------------------
  let nextSerial = 0x300;
  let counter = 0;
  const uniqueName = (label: string): string =>
    `${label}-${randomBytes(3).toString("hex")}`;
  const root: TestCert = await makeRoot({
    subject: { O: "Ministack Corp", CN: `Ministack Issuance Root ${suffix}` },
  });
  const reload = async (caId: string): Promise<CaRecord> => {
    const ca = await pki.getCa(caId);
    check(ca !== undefined, `CA ${caId} is missing`);
    return ca as CaRecord;
  };
  const createActiveCa = async (
    label: string,
    policy: Record<string, unknown> = {},
  ): Promise<CaRecord> => {
    const name = uniqueName(label);
    const created = await svc.cas.create(admin, idem(), {
      environment,
      name,
      kind: "EXTERNAL_INTERMEDIATE",
      keyAlgorithm: "ECDSA_P256",
      subject: { organization: "Ministack Corp", commonName: `Ministack ${name}` },
      policy,
    });
    const ca = await reload(created.body.caId as string);
    const spki = parseRawCsr(
      fromPem(ca.csrPem ?? "", "CERTIFICATE REQUEST"),
    ).spkiDer;
    const cert = await makeIntermediate(root, {
      key: { spkiDer: spki } as unknown as TestKey,
      subject: ca.subject,
      serial: Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, nextSerial++ & 0xff, nextSerial & 0xff]),
    });
    await svc.cas.activate(admin, idem(), ca.caId, {
      certificatePem: cert.pem,
      chainPem: root.pem,
    });
    return reload(ca.caId);
  };
  const putConsumer = async (
    kind: "direct" | "agent",
    status = "ACTIVE",
  ): Promise<Consumer> => {
    counter += 1;
    const consumerId = `cons-${suffix}-${counter}`;
    const fingerprint = randomBytes(32).toString("hex");
    const now = new Date();
    const createdBy = { type: "system", id: "ministack-verify" };
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `CONSUMER#${consumerId}`,
          sk: "PROFILE",
          consumerId,
          environment,
          subjectUri: `spiffe://hemlig/${consumerId}`,
          status,
          createdAt: now.toISOString(),
          createdBy,
        },
      }),
    );
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `IDENTITY#${fingerprint}`,
          sk: "PROFILE",
          fingerprint,
          consumerId,
          environment,
          kind: "api",
          status: "ACTIVE",
          notBefore: new Date(now.getTime() - 3_600_000).toISOString(),
          notAfter: new Date(now.getTime() + 86_400_000).toISOString(),
        },
      }),
    );
    if (kind === "direct") {
      return { consumerId, fingerprint };
    }
    const agentGrantId = `grant-${randomUUID()}`;
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `AGENT_GRANT#${agentGrantId}`,
          sk: "PROFILE",
          grantId: agentGrantId,
          consumerId,
          environment,
          capabilities: ["read"],
          secretGrants: [],
          status: "ACTIVE",
          createdAt: now.toISOString(),
          createdBy,
        },
      }),
    );
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `CONSUMER#${consumerId}`,
          sk: "AGENT_GRANT",
          grantId: agentGrantId,
        },
      }),
    );
    return { consumerId, fingerprint, agentGrantId };
  };
  const policyBody = (
    caId: string,
    extra: Record<string, unknown> = {},
  ): Record<string, unknown> => ({
    caId,
    names: { dns: { allow: ["*.acc.example.com", "*.example.com"] }, maxSans: 10 },
    keyUsages: ["digitalSignature", "keyEncipherment"],
    extendedKeyUsages: {
      allow: ["serverAuth", "clientAuth"],
      default: ["serverAuth"],
    },
    lifetime: { defaultSeconds: 3600, maxSeconds: 86_400, minSeconds: 600 },
    ...extra,
  });
  const createGrant = async (
    consumer: Consumer,
    name: string,
    caId: string,
    extra: Record<string, unknown> = {},
    service = svc,
  ): Promise<IssuanceGrantRecord> => {
    await service.grants.create(admin, idem(), consumer.consumerId, {
      name,
      ...policyBody(caId, extra),
    });
    return getGrant(consumer, name);
  };
  const getGrant = async (
    consumer: Consumer,
    name: string,
  ): Promise<IssuanceGrantRecord> => {
    const grant = await pki.getGrant(consumer.consumerId, name);
    check(grant !== undefined, `grant ${name} is missing`);
    return grant as IssuanceGrantRecord;
  };
  const newCsr = (dns = "web.example.com"): string =>
    makeLeafCsr({ commonName: dns, dns: [dns] }).pem;
  const issueFor = (
    consumer: Consumer,
    grantName: string,
    key: string,
    csr: string,
    extra: Record<string, unknown> = {},
    service = svc,
  ) =>
    service.issuance.issueForConsumer({
      actor: {
        type: "consumer",
        id: consumer.fingerprint,
        consumerId: consumer.consumerId,
        environment,
      },
      consumerId: consumer.consumerId,
      environment,
      grantName,
      idempotencyKey: key,
      body: { certificateSigningRequestPem: csr, ...extra },
    });
  const rawGet = async (key: { pk: string; sk: string }) =>
    (
      await doc.send(
        new GetCommand({
          TableName: table,
          Key: { pk: key.pk, sk: key.sk },
          ConsistentRead: true,
        }),
      )
    ).Item;
  const hourCount = (uid: string, at = new Date()): Promise<number> =>
    pki.getQuotaCount(pkiKeys.grantQuota(uid, quotaWindows(at).hourSk));
  const caHourCount = (caId: string, at = new Date()): Promise<number> =>
    pki.getQuotaCount(pkiKeys.caQuota(caId, quotaWindows(at).hourSk));
  const pointerCount = async (consumer: Consumer): Promise<number> =>
    (
      await pki.listConsumerPointersPage(consumer.consumerId, {
        newestFirst: true,
        limit: 100,
      })
    ).pointers.length;
  const crlOf = async (caId: string) => {
    const state = await pki.getCaCrlState(caId);
    check(state !== undefined, `CRL state of ${caId} is missing`);
    return state as NonNullable<typeof state>;
  };
  const updateRaw = (
    key: { pk: string; sk: string },
    expression: string,
    names: Record<string, string>,
    values: Record<string, unknown>,
  ) =>
    doc.send(
      new UpdateCommand({
        TableName: table,
        Key: key,
        UpdateExpression: expression,
        ExpressionAttributeNames: names,
        ExpressionAttributeValues: values,
      }),
    );

  // ---- Agent and direct consumers issue ---------------------------------------------------------
  {
    const ca = await createActiveCa("issue");
    for (const kind of ["agent", "direct"] as const) {
      const consumer = await putConsumer(kind);
      const grant = await createGrant(consumer, "web", ca.caId);
      const key = idem();
      const csr = newCsr();
      const first = await issueFor(consumer, "web", key, csr);
      check(first.status === 201 && first.replayed === false, `${kind} issues`);
      const serial = first.body.serial as string;
      check(
        (await rawGet(pkiKeys.certificate(ca.caId, serial))) !== undefined,
        `${kind}: the certificate item is written`,
      );
      check(
        (await pki.getReplayRecord(consumer.consumerId, key))?.serial === serial,
        `${kind}: the replay record is written`,
      );
      check(
        (await pointerCount(consumer)) === 1,
        `${kind}: the consumer pointer is written`,
      );
      check(
        (await hourCount(grant.uid)) === 1,
        `${kind}: the grant hour counter is 1`,
      );
      await eventually(
        async () =>
          (await pki.queryCertificatesPage(ca.caId, { limit: 100 })).certificates.some(
            (certificate) => certificate.serial === serial,
          ),
        `${kind}: the GSI must list the certificate`,
      );
      const caBefore = await caHourCount(ca.caId);
      const replay = await issueFor(consumer, "web", key, csr);
      check(
        replay.replayed === true && replay.body.serial === serial,
        `${kind}: the same key replays the same serial`,
      );
      check(
        (await hourCount(grant.uid)) === 1 &&
          (await caHourCount(ca.caId)) === caBefore &&
          (await pointerCount(consumer)) === 1,
        `${kind}: a replay leaves every counter unchanged`,
      );
    }
  }
  done("agent and direct consumers issue; a replay returns the same serial");

  // ---- Replay-record race ---------------------------------------------------------------------
  {
    const ca = await createActiveCa("race");
    const consumer = await putConsumer("direct");
    const grant = await createGrant(consumer, "web", ca.caId);
    const key = idem();
    const csr = newCsr();
    const results = await Promise.allSettled([
      issueFor(consumer, "web", key, csr),
      issueFor(consumer, "web", key, csr),
    ]);
    const serials = results.map((result) =>
      result.status === "fulfilled" ? (result.value.body.serial as string) : "",
    );
    check(
      serials[0] !== "" && serials[0] === serials[1],
      `two concurrent issues with one key must return one serial (${results
        .map((result) => result.status)
        .join(",")})`,
    );
    check((await pointerCount(consumer)) === 1, "one certificate in inventory");
    check((await hourCount(grant.uid)) === 1, "the grant hour count is 1");
  }
  done("a replay-record race yields one serial and one charge");

  // ---- Own-ambiguous last slot ----------------------------------------------------------------
  {
    const ca = await createActiveCa("ambiguous");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId, { quotas: { perHour: 1 } });
    const k = idem();
    const csr = newCsr();
    const first = await issueFor(consumer, "web", k, csr);
    const blind = build({
      pki: stubFirst(pki, "getReplayRecord", async () => undefined),
    });
    const retried = await issueFor(consumer, "web", k, csr, {}, blind);
    check(
      retried.replayed === true && retried.body.serial === first.body.serial,
      "the retry of the committed key must replay, not 429",
    );
    const error = await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr()),
      { status: 429, code: "issuance_rate_limited", reason: "grant_hour" },
      "a new key on the exhausted grant",
    );
    const seconds = Number(error.headers?.["retry-after"]);
    check(
      seconds >= 1 && seconds <= 3600,
      `Retry-After must be 1..3600 (${seconds})`,
    );
  }
  done("an own-ambiguous last slot replays; a new key gets 429 grant_hour");

  // ---- Winner between step 2 and step 4 --------------------------------------------------------
  {
    const ca = await createActiveCa("winner");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId, { quotas: { perHour: 1 } });
    const k = idem();
    const csr = newCsr();
    // The first getReplayRecord of the service under test runs a competing same-key issue, then reports none.
    const racing = build({
      pki: stubFirst(pki, "getReplayRecord", async () => {
        await issueFor(consumer, "web", k, csr, {}, svc);
        return undefined;
      }),
    });
    const result = await issueFor(consumer, "web", k, csr, {}, racing);
    check(result.replayed === true, "a winner after step 2 must replay, not 429");

    // The same with capacity exhausted.
    const ca2 = await createActiveCa("winner-capacity");
    const consumer2 = await putConsumer("direct");
    await createGrant(consumer2, "web", ca2.caId);
    const k2 = idem();
    const csr2 = newCsr();
    const racing2 = build({
      pki: stubFirst(pki, "getReplayRecord", async () => {
        await issueFor(consumer2, "web", k2, csr2, {}, svc);
        await updateRaw(
          pkiKeys.caCrl(ca2.caId),
          "SET #capacity = :c",
          { "#capacity": "capacity" },
          {
            ":c": {
              count: ca2.policy.capacity,
              countFrom: new Date().toISOString(),
              countedAt: new Date().toISOString(),
            },
          },
        );
        return undefined;
      }),
    });
    check(
      (await issueFor(consumer2, "web", k2, csr2, {}, racing2)).replayed === true,
      "a winner after step 2 must replay, not ca_capacity_exceeded",
    );
  }
  done("a winner between step 2 and the pre-check replays");

  // ---- Replay checks after commit --------------------------------------------------------------
  {
    const ca = await createActiveCa("replay-checks");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    const k = idem();
    const csr = newCsr();
    const first = await issueFor(consumer, "web", k, csr);
    const certificate = (await pki.getCertificate(
      ca.caId,
      first.body.serial as string,
    )) as NonNullable<Awaited<ReturnType<typeof pki.getCertificate>>>;
    const late = build({
      now: () => new Date(Date.parse(certificate.notAfter) - 30_000),
    });
    await expectApi(
      () => issueFor(consumer, "web", k, csr, {}, late),
      { status: 409, code: "issuance_expired", reason: "result_expiring" },
      "a replay 30 seconds before notAfter",
    );
    await svc.certificates.revoke(
      admin,
      idem(),
      ca.caId,
      certificate.serial,
      {},
    );
    await expectApi(
      () => issueFor(consumer, "web", k, csr),
      { status: 409, code: "issuance_revoked", reason: "certificate_revoked" },
      "a replay after revocation",
    );
  }
  done("replay checks: revoked and about to expire");

  // ---- Grant changed between read and commit ---------------------------------------------------
  {
    const ca = await createActiveCa("grant-race");
    const update = async (
      consumer: Consumer,
      change: (grant: IssuanceGrantRecord) => Record<string, unknown>,
    ) => {
      const grant = await getGrant(consumer, "web");
      await svc.grants.update(
        admin,
        idem(),
        consumer.consumerId,
        "web",
        grant.version,
        { caId: grant.caId, ...grant.policy, ...change(grant) },
      );
    };
    // Narrowed allow rule.
    const narrowed = await putConsumer("direct");
    await createGrant(narrowed, "web", ca.caId);
    const narrowing = build({
      pki: hooked(pki, {
        commitIssuance: () =>
          update(narrowed, () => ({
            names: { dns: { allow: ["*.other.example.com"] }, maxSans: 10 },
          })),
      }),
    });
    await expectApi(
      () => issueFor(narrowed, "web", idem(), newCsr(), {}, narrowing),
      { status: 403, code: "issuance_denied", reason: "name_not_permitted" },
      "a grant narrowed before the commit",
    );
    check((await pointerCount(narrowed)) === 0, "nothing was delivered");
    // Disabled.
    const disabled = await putConsumer("direct");
    await createGrant(disabled, "web", ca.caId);
    const disabling = build({
      pki: hooked(pki, {
        commitIssuance: () => update(disabled, () => ({ status: "DISABLED" })),
      }),
    });
    await expectApi(
      () => issueFor(disabled, "web", idem(), newCsr(), {}, disabling),
      { status: 403, code: "issuance_grant_inactive", reason: "grant_disabled" },
      "a grant disabled before the commit",
    );
    // Deleted and recreated: the certificate carries the new uid.
    const recreated = await putConsumer("direct");
    const original = await createGrant(recreated, "web", ca.caId);
    const recreating = build({
      pki: hooked(pki, {
        commitIssuance: async () => {
          const grant = await getGrant(recreated, "web");
          await svc.grants.delete(
            admin,
            idem(),
            recreated.consumerId,
            "web",
            grant.version,
          );
          await createGrant(recreated, "web", ca.caId);
        },
      }),
    });
    const issued = await issueFor(recreated, "web", idem(), newCsr(), {}, recreating);
    const certificate = await pki.getCertificate(
      ca.caId,
      issued.body.serial as string,
    );
    const current = await getGrant(recreated, "web");
    check(
      certificate?.requester.issuanceGrant?.uid === current.uid &&
        current.uid !== original.uid,
      "a recreated grant must stamp the new uid",
    );
  }
  done("a grant changed between read and commit is re-evaluated");

  // ---- CA retired or revoked between sign and commit ---------------------------------------------
  {
    for (const flip of ["retired", "revoked"] as const) {
      const ca = await createActiveCa(`ca-${flip}`);
      const consumer = await putConsumer("direct");
      await createGrant(consumer, "web", ca.caId);
      const before = (await pki.queryCertificatesPage(ca.caId, { limit: 100 }))
        .certificates.length;
      const racing = build({
        pki: hooked(pki, {
          commitIssuance:
            flip === "retired"
              ? () => svc.cas.retire(admin, idem(), ca.caId)
              : () =>
                  updateRaw(
                    pkiKeys.caProfile(ca.caId),
                    "SET #status = :revoked, #version = :v",
                    { "#status": "status", "#version": "version" },
                    { ":revoked": "REVOKED", ":v": `pkv-${randomUUID()}` },
                  ),
        }),
      });
      await expectApi(
        () => issueFor(consumer, "web", idem(), newCsr(), {}, racing),
        { status: 409, code: "ca_not_active", reason: flip },
        `a CA ${flip} before the commit`,
      );
      check((await pointerCount(consumer)) === 0, `${flip}: no pointer`);
      check(
        (await pki.queryCertificatesPage(ca.caId, { limit: 100 })).certificates
          .length === before,
        `${flip}: the GSI count is unchanged`,
      );
    }
  }
  done("a CA retired or revoked before the commit delivers nothing");

  // ---- Identity revoked between read and commit --------------------------------------------------
  {
    const ca = await createActiveCa("identity");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    const racing = build({
      pki: hooked(pki, {
        commitIssuance: () =>
          updateRaw(
            { pk: `IDENTITY#${consumer.fingerprint}`, sk: "PROFILE" },
            "SET #status = :revoked",
            { "#status": "status" },
            { ":revoked": "REVOKED" },
          ),
      }),
    });
    await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr(), {}, racing),
      { status: 403, code: "identity_not_active" },
      "an identity revoked before the commit",
    );
    check((await pointerCount(consumer)) === 0, "no certificate was delivered");
  }
  done("an identity revoked before the commit delivers nothing");

  // ---- Concurrency ----------------------------------------------------------------------------
  {
    const ca = await createActiveCa("concurrency");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () =>
        issueFor(consumer, "web", idem(), newCsr()),
      ),
    );
    const serials: string[] = [];
    for (const result of results) {
      if (result.status === "fulfilled") {
        serials.push(result.value.body.serial as string);
      } else {
        check(
          result.reason instanceof ApiError && result.reason.statusCode === 503,
          `a concurrent issue may only fail with 503 (${String(result.reason)})`,
        );
      }
    }
    check(
      new Set(serials).size === serials.length,
      "concurrent issues must never share a serial",
    );
    check(
      (await caHourCount(ca.caId)) === serials.length,
      `the CA hour counter (${await caHourCount(ca.caId)}) must equal the committed count (${serials.length})`,
    );
  }
  done("ten concurrent issues: unique serials, one charge each");

  // ---- Ambiguous commit ------------------------------------------------------------------------
  {
    const ca = await createActiveCa("commit-ambiguous");
    const consumer = await putConsumer("direct");
    const grant = await createGrant(consumer, "web", ca.caId);
    let thrown = false;
    const flaky = new Proxy(doc, {
      get(target, property) {
        if (property !== "send") {
          return Reflect.get(target, property, target) as unknown;
        }
        return async (command: unknown) => {
          const result = await target.send(command as never);
          if (command instanceof TransactWriteCommand && !thrown) {
            thrown = true;
            throw Object.assign(new Error("timed out"), { name: "TimeoutError" });
          }
          return result;
        };
      },
    });
    const flakyPki = new PkiRepository(flaky as never, repositoryOptions);
    const result = await issueFor(
      consumer,
      "web",
      idem(),
      newCsr(),
      {},
      build({ pki: flakyPki }),
    );
    check(thrown, "the first transaction must have been interrupted");
    check(
      (await pointerCount(consumer)) === 1 &&
        (await hourCount(grant.uid)) === 1 &&
        (await rawGet(pkiKeys.certificate(ca.caId, result.body.serial as string))) !==
          undefined,
      "an ambiguous commit returns the committed serial, charged once",
    );
  }
  done("an ambiguous commit returns the committed serial");

  // ---- Capacity ---------------------------------------------------------------------------------
  {
    const ca = await createActiveCa("capacity", { capacity: 2, issuancePerHour: 50 });
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    const first = await issueFor(consumer, "web", idem(), newCsr());
    await issueFor(consumer, "web", idem(), newCsr());
    const pass = (clock: () => Date) => {
      const s = build({ now: clock });
      return runMaintenancePass({
        app: {
          pki,
          cas: s.cas,
          crls: s.crls,
          capacity: s.capacity,
          audit,
          config,
        },
        now: clock(),
        remainingMs: () => 300_000,
        correlationId: "issuance",
        emit: () => undefined,
        log: () => undefined,
      });
    };
    await pass(() => new Date());
    const counted = await crlOf(ca.caId);
    check(
      counted.capacity?.count === 2,
      `the maintenance pass must count 2 certificates (${counted.capacity?.count})`,
    );
    await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr()),
      { status: 409, code: "ca_capacity_exceeded" },
      "a third certificate at capacity 2",
    );
    // A stale count of zero is recounted by issuance.
    const stale = new Date(Date.now() - 31 * 60_000).toISOString();
    await updateRaw(
      pkiKeys.caCrl(ca.caId),
      "SET #capacity = :c",
      { "#capacity": "capacity" },
      { ":c": { count: 0, countFrom: stale, countedAt: stale } },
    );
    await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr()),
      { status: 409, code: "ca_capacity_exceeded" },
      "a stale count recounted by issuance",
    );
    const recounted = await crlOf(ca.caId);
    check(
      recounted.capacity?.count === 2 &&
        (recounted.capacity?.countedAt ?? "") > stale,
      "issuance must store its recount",
    );
    // After a revoke the count starts from dirtySince.
    const quiet = build({ crls: { publish: async () => ({ kind: "busy" }) } });
    await quiet.certificates.revoke(
      admin,
      idem(),
      ca.caId,
      first.body.serial as string,
      {},
    );
    const dirty = await crlOf(ca.caId);
    check(dirty.dirtySince !== undefined, "an unpublished revocation is dirty");
    await pass(() => new Date());
    const after = await crlOf(ca.caId);
    check(
      after.capacity?.countFrom === dirty.dirtySince,
      `countFrom (${after.capacity?.countFrom}) must equal dirtySince (${dirty.dirtySince})`,
    );
  }
  done("capacity: maintenance count, refusal, stale recount and countFrom");

  // ---- Per-CA counter ---------------------------------------------------------------------------
  {
    const ca = await createActiveCa("ca-rate", { issuancePerHour: 2 });
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    await issueFor(consumer, "web", idem(), newCsr());
    await issueFor(consumer, "web", idem(), newCsr());
    const grant = await getGrant(consumer, "web");
    await svc.grants.delete(admin, idem(), consumer.consumerId, "web", grant.version);
    await createGrant(consumer, "web", ca.caId);
    await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr()),
      { status: 429, code: "issuance_rate_limited", reason: "ca_hour" },
      "a recreated grant under an exhausted CA",
    );
    const adminCa = await createActiveCa("admin-rate");
    await svc.issuance.issueForAdmin(admin, idem(), adminCa.caId, {
      certificateSigningRequestPem: newCsr("admin.example.com"),
      useCsrNames: true,
    });
    check(
      (await caHourCount(adminCa.caId)) === 1,
      "an admin issue must increment the CA hour counter",
    );
  }
  done("the per-CA hourly counter outlives grant recreation; admin issue counts");

  // ---- Revocation and CRL -----------------------------------------------------------------------
  {
    const ca = await createActiveCa("revocation");
    const consumer = await putConsumer("direct");
    await createGrant(consumer, "web", ca.caId);
    const issue = async () =>
      (await issueFor(consumer, "web", idem(), newCsr())).body.serial as string;
    const serial = await issue();
    const invalidity = new Date(Date.now() - 3_600_000).toISOString();
    const revoked = await svc.certificates.revoke(
      admin,
      idem(),
      ca.caId,
      serial,
      { reason: "keyCompromise", invalidityDate: invalidity },
    );
    check(
      revoked.body.crlPublished === true && revoked.body.crlEntry === true,
      "a keyCompromise revoke publishes inline",
    );
    const download = await svc.crls.download(ca.caId);
    check(download.kind === "bytes", "the CRL downloads");
    const crl = parseCrl((download as { der: Buffer }).der);
    const entry = crl.entries.find(
      (candidate) => candidate.serialHex === serial,
    );
    check(
      entry?.reason === 1 && entry.extensions.some((e) => e.oid === "2.5.29.24"),
      "the CRL must carry the serial with reason 1 and an invalidity date",
    );
    // An expired revoke is inventory only.
    const expiring = await issue();
    const certificate = (await pki.getCertificate(ca.caId, expiring)) as NonNullable<
      Awaited<ReturnType<typeof pki.getCertificate>>
    >;
    const revisionBefore = (await crlOf(ca.caId)).revision;
    const future = build({
      now: () => new Date(Date.parse(certificate.notAfter) + 1000),
    });
    const expired = await future.certificates.revoke(
      admin,
      idem(),
      ca.caId,
      expiring,
      {},
    );
    check(
      expired.body.crlEntry === false &&
        (await crlOf(ca.caId)).revision === revisionBefore,
      "an expired certificate is revoked in inventory without an entry or a revision bump",
    );
    // Bulk revoke of three.
    const bulkConsumer = await putConsumer("direct");
    await createGrant(bulkConsumer, "web", ca.caId);
    for (let i = 0; i < 3; i += 1) {
      await issueFor(bulkConsumer, "web", idem(), newCsr());
    }
    const entriesBefore = (await crlOf(ca.caId)).published?.entryCount ?? 0;
    const numberBefore = (await crlOf(ca.caId)).published?.number ?? 0;
    const bulk = await svc.certificates.bulkRevoke(
      admin,
      idem(),
      bulkConsumer.consumerId,
      { reason: "superseded" },
    );
    check(
      bulk.complete && bulk.body.revoked === 3,
      "the bulk revoke completes with three certificates",
    );
    const state = await crlOf(ca.caId);
    check(
      state.published?.number === numberBefore + 1 &&
        (state.published?.entryCount ?? 0) === entriesBefore + 3,
      `one publication with 3 new entries (${state.published?.number}, ${state.published?.entryCount})`,
    );
  }
  done("revocation: keyCompromise CRL, expired inventory-only, bulk revoke");

  // ---- Audit hygiene ----------------------------------------------------------------------------
  check(
    !JSON.stringify(auditEvents).includes("-----BEGIN"),
    "no audit event may contain PEM",
  );
  done("no audit event carries key or certificate material");

  // ---- PKI-4 local equivalent -------------------------------------------------------------------
  await verifyOpenSslRecipe();

  process.stdout.write(
    `PKI issuance MiniStack verification passed (${cases} checks).\n`,
  );

  async function verifyOpenSslRecipe(): Promise<void> {
    const have = spawnSync("openssl", ["version"]).status === 0;
    if (!have) {
      if (process.env.GITHUB_ACTIONS !== undefined) {
        throw new Error(
          "PKI issuance verification failed: openssl is required under GITHUB_ACTIONS.",
        );
      }
      process.stdout.write(
        "PKI notice: openssl is not on PATH; skipping the PKI-4 recipe check.\n",
      );
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "hemlig-pki4-"));
    try {
      const file = (name: string): string => join(dir, name);
      const text = (name: string): string => readFileSync(file(name), "utf8");
      const openssl = (
        args: string[],
        allowFailure = false,
      ): { status: number; output: string } => {
        const result = spawnSync("openssl", args, {
          cwd: dir,
          encoding: "utf8",
        });
        const output = `${result.stdout}${result.stderr}`;
        if (result.status !== 0 && !allowFailure) {
          throw new Error(
            `PKI issuance verification failed: openssl ${args.join(" ")}:\n${output}`,
          );
        }
        return { status: result.status ?? -1, output };
      };
      mkdirSync(join(dir, "certs"));
      mkdirSync(join(dir, "private"));
      writeFileSync(file("root-ca.cnf"), rootConfig(dir));
      writeFileSync(file("index.txt"), "");
      writeFileSync(file("crlnumber"), "01\n");
      writeFileSync(
        file("serial"),
        `${openssl(["rand", "-hex", "16"]).output.trim()}\n`,
      );
      openssl([
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-384",
        "-pkeyopt",
        "ec_param_enc:named_curve",
        "-out",
        "private/root.key",
      ]);
      openssl([
        "req",
        "-config",
        "root-ca.cnf",
        "-new",
        "-x509",
        "-key",
        "private/root.key",
        "-days",
        "3650",
        "-out",
        "root.pem",
      ]);
      const created = await svc.cas.create(admin, idem(), {
        environment,
        name: uniqueName("pki4"),
        kind: "EXTERNAL_INTERMEDIATE",
        keyAlgorithm: "ECDSA_P256",
        subject: {
          organization: "Example Corp",
          commonName: `MiniStack PKI-4 Issuing ${suffix}`,
        },
        requestedConstraints: {
          nameConstraints: { permitted: { dns: ["example.com"] } },
        },
      });
      const caId = created.body.caId as string;
      writeFileSync(file("issuing.csr"), created.body.csrPem as string);
      openssl([
        "ca",
        "-config",
        "root-ca.cnf",
        "-batch",
        "-in",
        "issuing.csr",
        "-out",
        "issuing.pem",
        "-notext",
      ]);
      openssl([
        "ca",
        "-config",
        "root-ca.cnf",
        "-gencrl",
        "-out",
        "root.crl.pem",
      ]);
      await svc.cas.activate(admin, idem(), caId, {
        certificatePem: text("issuing.pem"),
        chainPem: text("root.pem"),
        rootCrl: text("root.crl.pem"),
      });
      const consumer = await putConsumer("direct");
      await createGrant(consumer, "acc-web", caId, {
        names: { dns: { allow: ["*.acc.example.com"] }, maxSans: 10 },
      });
      openssl([
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "leaf.key",
        "-subj",
        "/CN=web.acc.example.com",
        "-addext",
        "subjectAltName=DNS:web.acc.example.com",
        "-out",
        "leaf.csr",
      ]);
      const issued = await issueFor(
        consumer,
        "acc-web",
        idem(),
        text("leaf.csr"),
        { usages: ["digital signature", "key encipherment", "server auth"] },
      );
      writeFileSync(file("leaf.pem"), issued.body.certificatePem as string);
      writeFileSync(file("chain.pem"), issued.body.chainPem as string);
      check(
        fromPem(text("root.pem"), "CERTIFICATE").equals(
          fromPem(issued.body.caPem as string, "CERTIFICATE"),
        ),
        "caPem must be the anchor",
      );
      const verified = openssl([
        "verify",
        "-x509_strict",
        "-purpose",
        "sslserver",
        "-CAfile",
        "root.pem",
        "-untrusted",
        "chain.pem",
        "leaf.pem",
      ]);
      check(verified.output.includes("OK"), `openssl verify: ${verified.output}`);
      await svc.certificates.revoke(
        admin,
        idem(),
        caId,
        issued.body.serial as string,
        { reason: "keyCompromise" },
      );
      const download = await svc.crls.download(caId);
      check(download.kind === "bytes", "the CRL downloads");
      writeFileSync(file("issuing.crl"), (download as { der: Buffer }).der);
      openssl([
        "crl",
        "-inform",
        "DER",
        "-in",
        "issuing.crl",
        "-out",
        "issuing.crl.pem",
      ]);
      const revoked = openssl(
        [
          "verify",
          "-crl_check_all",
          "-CAfile",
          "root.pem",
          "-untrusted",
          "chain.pem",
          "-CRLfile",
          "issuing.crl.pem",
          "-CRLfile",
          "root.crl.pem",
          "leaf.pem",
        ],
        true,
      );
      check(
        revoked.output.includes("certificate revoked"),
        `openssl must report the leaf revoked: ${revoked.output}`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    done("PKI-4 equivalent: OpenSSL root, issue, verify, revoke and CRL check");
  }
};
