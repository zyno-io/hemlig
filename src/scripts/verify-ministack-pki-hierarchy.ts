import { spawnSync } from "node:child_process";
import {
  createHash,
  randomBytes,
  randomUUID,
  X509Certificate,
} from "node:crypto";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";
import { ApiError } from "../domain/errors";
import type { Actor } from "../domain/types";
import { parseCertificate } from "../pki/asn1/certificate";
import { canonicalSerialHex } from "../pki/asn1/der";
import { parseCrl, verifyCrlSignature } from "../pki/asn1/crl";
import { fromPem } from "../pki/asn1/pem";
import { CaService } from "../pki/ca-service";
import { CapacityService } from "../pki/capacity-service";
import { CertificateService } from "../pki/certificate-service";
import { CrlService, drainPoint, isDrained } from "../pki/crl-service";
import { ExternalCaService } from "../pki/external-ca-service";
import { GrantService } from "../pki/grant-service";
import { IssuanceService } from "../pki/issuance-service";
import { runMaintenancePass } from "../pki/maintenance";
import type { PkiServiceDeps } from "../pki/service-types";
import { WrappedCaSigner } from "../pki/signer";
import { buildCaSubject } from "../pki/subject";
import type { CaRecord, IssuanceGrantRecord } from "../pki/types";
import { parseRawCsr } from "../pki/asn1/csr";
import { createPkiIssuerHandler } from "../handlers/pki-issuer";
import { pkiIssuerRoutes } from "../handlers/pki-issuer-routes";
import { createErrorResponder } from "../handlers/request";
import type { PkiApplication } from "../pki/app";
import { DynamoCursorStore } from "../repositories/cursor-store";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { pkiKeys, PkiRepository, quotaWindows } from "../repositories/pki";
import { CursorService } from "../services/cursor";
import {
  makeIntermediate,
  makeLeafCsr,
  makeRoot,
  type TestKey,
} from "./pki-fixtures";
import type { PkiLifecycleOptions } from "./verify-ministack-pki-lifecycle";

/**
 * The Phase 7 suite against MiniStack: Hemlig ROOT and INTERMEDIATE creation, issuance under a child, CA revoke,
 * retirement, and local distrust with the maintenance finisher, through the real repository, services, KMS, S3 and
 * DynamoDB. Races wrap the repository in a Proxy that runs the competing operation before one method; there are no
 * production hooks. Its environment is its own, so the maintenance pass sees only the CAs this suite made.
 */
const check = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(`PKI hierarchy verification failed: ${message}`);
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

/** Lists only this suite's CAs for the maintenance pass, and no external roots. */
const scoped = <T extends object>(target: T, environment: string): T =>
  new Proxy(target, {
    get(object, property) {
      const value = Reflect.get(object, property, object) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      if (property !== "queryDirectory") {
        return (value as (...a: unknown[]) => unknown).bind(object);
      }
      return async (
        partition: string,
        options?: Record<string, unknown>,
      ): Promise<Record<string, unknown>[]> => {
        if (partition !== "PKI_CAS") {
          return [];
        }
        const items = (await (
          value as (...a: unknown[]) => Promise<Record<string, unknown>[]>
        ).call(object, partition, options)) as Record<string, unknown>[];
        return items.filter((item) => item.environment === environment);
      };
    },
  });

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
  throw new Error(`PKI hierarchy verification failed: ${message}`);
};

interface Consumer {
  readonly consumerId: string;
  readonly fingerprint: string;
}

const day = 86_400_000;

export const verifyPkiHierarchyOnMiniStack = async (
  options: PkiLifecycleOptions,
): Promise<void> => {
  const { table, config } = options;
  const doc = DynamoDBDocumentClient.from(options.dynamo, {
    marshallOptions: { removeUndefinedValues: true },
  });
  const objects = new ObjectStore(options.s3);
  const repository = new DynamoRepository(doc, config);
  const pki = new PkiRepository(doc, {
    tableName: table,
    directoryIndex: config.pkiDirectoryIndex,
    sleep: async () => undefined,
  });
  const cursors = new CursorService(
    new DynamoCursorStore(doc, table, "PKI_CURSOR#"),
  );
  const suffix = randomBytes(4).toString("hex");
  const environment = "ministack-p7";
  const otherEnvironment = "ministack-p7-other";
  const admin: Actor = { type: "human", id: `hierarchy-admin-${suffix}` };
  const auditEvents: Record<string, unknown>[] = [];
  // The audit targets human CA create and revoke return: the admin handler would write them, this suite calls the
  // service directly, so they are collected here and scanned with the events.
  const humanTargets: { operation: string; target: unknown }[] = [];
  const recordTargets = (cas: CaService): CaService =>
    new Proxy(cas, {
      get(object, property) {
        const value = Reflect.get(object, property, object) as unknown;
        if (typeof value !== "function") {
          return value;
        }
        if (property === "create" || property === "revoke") {
          return async (...args: unknown[]) => {
            const result = (await (
              value as (...a: unknown[]) => Promise<{ auditTarget: unknown }>
            ).apply(object, args)) as { auditTarget: unknown };
            humanTargets.push({
              operation:
                property === "create" ? "pki.ca.create" : "pki.ca.revoke",
              target: result.auditTarget,
            });
            return result;
          };
        }
        return (value as (...a: unknown[]) => unknown).bind(object);
      },
    });
  const audit = {
    write: async (event: Record<string, unknown>) => {
      auditEvents.push(event);
      return { ...event, eventId: randomUUID(), at: new Date().toISOString() };
    },
  } as never;
  let cases = 0;
  const done = (name: string): void => {
    cases += 1;
    process.stdout.write(`PKI hierarchy ok: ${name}\n`);
  };
  const idem = (): string => `idem-${randomUUID()}`;

  for (const name of [environment, otherEnvironment]) {
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: "SYSTEM#ENVIRONMENTS",
          sk: `ENVIRONMENT#${name}`,
          name,
          createdAt: new Date().toISOString(),
          createdBy: { type: "system", id: "ministack-verify" },
        },
      }),
    );
  }

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
  const build = (overrides: { pki?: PkiRepository; now?: () => Date } = {}) => {
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
      cas: recordTargets(new CaService(deps, crls)),
      externalCas: new ExternalCaService(deps),
      grants: new GrantService(deps),
      issuance: new IssuanceService(deps, capacity),
      certificates: new CertificateService(deps, crls),
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
        `PKI hierarchy verification failed: ${label} threw ${
          error instanceof ApiError
            ? `${error.statusCode} ${error.code} ${error.details?.reason}`
            : String(error)
        }`,
      );
    }
    throw new Error(
      `PKI hierarchy verification failed: ${label} did not throw`,
    );
  };

  // ---- Fixtures --------------------------------------------------------------------------------
  let counter = 0;
  const unique = (label: string): string => {
    counter += 1;
    return `${label}-${randomBytes(3).toString("hex")}`;
  };
  const reload = async (caId: string): Promise<CaRecord> => {
    const ca = await pki.getCa(caId);
    check(ca !== undefined, `CA ${caId} is missing`);
    return ca as CaRecord;
  };
  const certOf = (ca: CaRecord) =>
    parseCertificate(fromPem(ca.certificatePem ?? "", "CERTIFICATE"));
  const createRoot = async (
    label: string,
    extra: Record<string, unknown> = {},
    service = svc,
  ): Promise<CaRecord> => {
    const name = unique(label);
    const created = await service.cas.create(admin, idem(), {
      environment,
      name,
      kind: "ROOT",
      keyAlgorithm: "ECDSA_P384",
      subject: {
        organization: "Ministack P7",
        commonName: `P7 Root ${name} ${suffix}`,
      },
      requestedConstraints: {
        nameConstraints: { permitted: { dns: ["example.com"] } },
      },
      ...extra,
    });
    return reload(created.body.caId as string);
  };
  const createChild = async (
    parent: CaRecord,
    label: string,
    extra: Record<string, unknown> = {},
    service = svc,
  ): Promise<CaRecord> => {
    const name = unique(label);
    const created = await service.cas.create(admin, idem(), {
      environment,
      name,
      kind: "INTERMEDIATE",
      parentCaId: parent.caId,
      keyAlgorithm: "ECDSA_P256",
      subject: {
        organization: "Ministack P7",
        commonName: `P7 Issuing ${name} ${suffix}`,
      },
      ...extra,
    });
    return reload(created.body.caId as string);
  };
  const putConsumer = async (): Promise<Consumer> => {
    counter += 1;
    const consumerId = `cons-p7-${suffix}-${counter}`;
    const fingerprint = randomBytes(32).toString("hex");
    const now = new Date();
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `CONSUMER#${consumerId}`,
          sk: "PROFILE",
          consumerId,
          environment,
          subjectUri: `spiffe://hemlig/${consumerId}`,
          status: "ACTIVE",
          createdAt: now.toISOString(),
          createdBy: { type: "system", id: "ministack-verify" },
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
    return { consumerId, fingerprint };
  };
  const createGrant = async (
    consumer: Consumer,
    name: string,
    caId: string,
  ): Promise<IssuanceGrantRecord> => {
    await svc.grants.create(admin, idem(), consumer.consumerId, {
      name,
      caId,
      names: { dns: { allow: ["*.example.com"] }, maxSans: 10 },
      keyUsages: ["digitalSignature", "keyEncipherment"],
      extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
      lifetime: { defaultSeconds: 3600, maxSeconds: 86_400, minSeconds: 600 },
    });
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
      body: { certificateSigningRequestPem: csr },
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
  const crlOf = async (caId: string) => {
    const state = await pki.getCaCrlState(caId);
    check(state !== undefined, `CRL state of ${caId} is missing`);
    return state as NonNullable<typeof state>;
  };
  const downloadCrl = async (caId: string): Promise<Buffer> => {
    const download = await svc.crls.download(caId);
    check(download.kind === "bytes", `the CRL of ${caId} downloads`);
    return (download as { der: Buffer }).der;
  };
  const lifetimeOf = (ca: CaRecord): number =>
    Math.ceil(
      (Date.parse(ca.notAfter ?? "") - Date.parse(ca.notBefore ?? "")) / 1000,
    );
  const maintenance = (service: ReturnType<typeof build>) =>
    runMaintenancePass({
      app: {
        pki: scoped(service.deps.pki, environment),
        cas: service.cas,
        crls: service.crls,
        capacity: service.capacity,
        audit,
        config,
      },
      now: new Date(),
      remainingMs: () => 300_000,
      correlationId: "hierarchy",
      emit: () => undefined,
      log: () => undefined,
    });

  const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
  if (!haveOpenssl) {
    if (
      process.env.CI !== undefined ||
      process.env.GITHUB_ACTIONS !== undefined
    ) {
      throw new Error(
        "PKI hierarchy verification failed: openssl is required when CI is set.",
      );
    }
    process.stdout.write(
      "PKI notice: openssl is not on PATH; skipping the hierarchy OpenSSL checks.\n",
    );
  }
  const withOpenssl = async (
    work: (tools: {
      write: (name: string, data: string | Uint8Array) => void;
      openssl: (
        args: string[],
        allowFailure?: boolean,
      ) => { status: number; output: string };
    }) => Promise<void>,
  ): Promise<void> => {
    if (!haveOpenssl) {
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "hemlig-pki7-"));
    try {
      await work({
        write: (name, data) => writeFileSync(join(dir, name), data),
        openssl: (args, allowFailure = false) => {
          const result = spawnSync("openssl", args, {
            cwd: dir,
            encoding: "utf8",
          });
          const output = `${result.stdout}${result.stderr}`;
          if (result.status !== 0 && !allowFailure) {
            throw new Error(
              `PKI hierarchy verification failed: openssl ${args.join(" ")}:\n${output}`,
            );
          }
          return { status: result.status ?? -1, output };
        },
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  // ---- 1. Create a ROOT -------------------------------------------------------------------------
  const rootA = await createRoot("p7-root");
  {
    check(
      rootA.status === "ACTIVE" && rootA.kind === "ROOT",
      "the ROOT is ACTIVE",
    );
    check(rootA.maxIssueLifetimeEverSeconds === 0, "a new ROOT's maximum is 0");
    check(
      rootA.chainPem === rootA.certificatePem,
      "the ROOT's chain is its own certificate",
    );
    const claim = await pki.getSubjectClaim(rootA.subjectKey);
    check(claim?.ownerType === "ca", "the subject claim is owned by a CA");
    const rootCert = certOf(rootA);
    const crl = parseCrl(await downloadCrl(rootA.caId));
    check(
      verifyCrlSignature(crl, rootCert.spkiDer) && crl.entries.length === 0,
      "CRL #1 of the ROOT verifies under its key",
    );
    const key = idem();
    const body = {
      environment,
      name: unique("p7-replay"),
      kind: "ROOT",
      keyAlgorithm: "ECDSA_P256",
      subject: {
        organization: "Ministack P7",
        commonName: `P7 Replay Root ${suffix}`,
      },
    };
    const first = await svc.cas.create(admin, key, body);
    const again = await svc.cas.create(admin, key, body);
    check(
      again.body.caId === first.body.caId,
      "an idempotent replay returns the same caId",
    );
    // A subject an external root already claimed.
    const claimed = {
      organization: "Ministack P7",
      commonName: `P7 Claimed ${suffix}`,
    };
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          ...pkiKeys.subject(
            buildCaSubject({ O: "Ministack P7", CN: claimed.commonName }).key,
          ),
          ownerType: "external",
          claimedAt: new Date().toISOString(),
        },
      }),
    );
    await expectApi(
      () =>
        svc.cas.create(admin, idem(), {
          environment,
          name: unique("p7-claimed"),
          kind: "ROOT",
          keyAlgorithm: "ECDSA_P256",
          subject: claimed,
        }),
      { status: 409, code: "ca_subject_in_use", reason: "subject_claimed" },
      "a ROOT with an externally claimed subject",
    );
    done(
      "ROOT creation: ACTIVE, claimed subject, CRL #1, replay, claimed subject refused",
    );
  }

  // ---- 2. Create an INTERMEDIATE ----------------------------------------------------------------
  const childA = await createChild(rootA, "p7-child");
  {
    const rootNow = await reload(rootA.caId);
    const row = await pki.getCertificate(rootA.caId, childA.serial as string);
    check(
      row?.isCa === true &&
        row.childCaId === childA.caId &&
        row.status === "ISSUED",
      "the root's inventory row records the child",
    );
    // The window the commit charged: the child's stored creation time, not the clock now.
    const { hourSk } = quotaWindows(new Date(childA.createdAt));
    check(
      (await pki.getQuotaCount(pkiKeys.adminQuota(rootA.caId, hourSk))) === 1 &&
        (await pki.getQuotaCount(pkiKeys.caQuota(rootA.caId, hourSk))) === 1,
      "creation charges both of the root's counters",
    );
    check(
      rootNow.maxIssueLifetimeEverSeconds === lifetimeOf(childA),
      "the root's maximum equals the child's lifetime",
    );
    check(
      rootNow.version === rootA.version,
      "raising the maximum does not bump the root's version",
    );
    check(
      childA.chainPem === `${(rootA.certificatePem ?? "").trim()}\n` &&
        childA.parentCaId === rootA.caId,
      "the child's chain is the root",
    );
    check(
      JSON.stringify(childA.effective?.nameConstraints) ===
        JSON.stringify(rootA.effective?.nameConstraints),
      "the child inherits the root's NameConstraints",
    );
    await expectApi(
      () =>
        svc.cas.create(admin, idem(), {
          environment,
          name: unique("p7-wide"),
          kind: "INTERMEDIATE",
          parentCaId: rootA.caId,
          keyAlgorithm: "ECDSA_P256",
          subject: {
            organization: "Ministack P7",
            commonName: `P7 Wide ${suffix}`,
          },
          requestedConstraints: {
            nameConstraints: { permitted: { dns: ["example.org"] } },
          },
        }),
      {
        status: 400,
        code: "bad_request",
        reason: "name_constraints_broader_than_parent",
      },
      "broader NameConstraints",
    );
    const retiredRoot = await createRoot("p7-retired-root");
    await svc.cas.retire(admin, idem(), retiredRoot.caId);
    await expectApi(
      () => createChild(retiredRoot, "p7-orphan"),
      { status: 409, code: "ca_not_active", reason: "retired" },
      "a retired parent",
    );
    await expectApi(
      () =>
        svc.cas.create(admin, idem(), {
          environment: otherEnvironment,
          name: unique("p7-foreign"),
          kind: "INTERMEDIATE",
          parentCaId: rootA.caId,
          keyAlgorithm: "ECDSA_P256",
          subject: {
            organization: "Ministack P7",
            commonName: `P7 Foreign ${suffix}`,
          },
        }),
      { status: 409, code: "conflict", reason: "parent_environment_mismatch" },
      "a parent in another environment",
    );
    done(
      "INTERMEDIATE creation: inventory row, quotas, maximum, inheritance and refusals",
    );
  }

  // ---- 3. A concurrent parent policy change ------------------------------------------------------
  {
    const root = await createRoot("p7-race-root");
    const racing = build({
      pki: hooked(pki, {
        createIntermediateCa: async () => {
          await svc.cas.update(admin, idem(), root.caId, root.version, {
            policy: { issuancePerHour: 1500 },
          });
        },
      }),
    });
    const child = await createChild(root, "p7-race-child", {}, racing);
    const updated = await reload(root.caId);
    check(
      updated.version !== root.version,
      "the policy change bumped the root's version",
    );
    check(updated.policy.issuancePerHour === 1500, "the policy change stuck");
    check(
      child.status === "ACTIVE" && child.parentCaId === root.caId,
      "the child exists after the rerun",
    );
    check(
      (await pki.getQuotaCount(
        pkiKeys.caQuota(
          root.caId,
          quotaWindows(new Date(child.createdAt)).hourSk,
        ),
      )) === 1,
      "the CA counter was charged once",
    );
    await eventually(
      async () =>
        (await pki.queryCertificatesPage(root.caId, { limit: 100 }))
          .certificates.length === 1,
      "the root lists exactly one new row",
    );
    done("a concurrent parent policy change reruns once and creates one child");
  }

  // ---- 4. Leaves under a child, and OpenSSL ------------------------------------------------------
  const consumerA = await putConsumer();
  await createGrant(consumerA, "web", childA.caId);
  const leafKey = idem();
  const leafCsr = newCsr("a.example.com");
  const leaf = await issueFor(consumerA, "web", leafKey, leafCsr);
  {
    check(leaf.status === 201, "a consumer grant on the child issues a leaf");
    const adminLeaf = await svc.issuance.issueForAdmin(
      admin,
      idem(),
      childA.caId,
      {
        certificateSigningRequestPem: newCsr("b.example.com"),
        useCsrNames: true,
      },
    );
    check(
      adminLeaf.status === 201,
      "an administrator issues a leaf under the child",
    );
    await withOpenssl(async ({ write, openssl }) => {
      write("root.pem", rootA.certificatePem ?? "");
      write("child.pem", childA.certificatePem ?? "");
      write("leaf.pem", leaf.body.certificatePem as string);
      write("root.der", await downloadCrl(rootA.caId));
      write("child.der", await downloadCrl(childA.caId));
      openssl(["crl", "-inform", "DER", "-in", "root.der", "-out", "root.crl"]);
      openssl([
        "crl",
        "-inform",
        "DER",
        "-in",
        "child.der",
        "-out",
        "child.crl",
      ]);
      const verify = (checkCrls: boolean) =>
        openssl(
          [
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            ...(checkCrls
              ? [
                  "-crl_check_all",
                  "-CRLfile",
                  "child.crl",
                  "-CRLfile",
                  "root.crl",
                ]
              : []),
            "-CAfile",
            "root.pem",
            "-untrusted",
            "child.pem",
            "leaf.pem",
          ],
          true,
        );
      check(
        verify(false).output.includes("leaf.pem: OK"),
        "OpenSSL verifies the chain",
      );
      check(
        verify(true).output.includes("leaf.pem: OK"),
        "OpenSSL verifies the chain with both CRLs",
      );
    });
    done("leaves under a Hemlig intermediate verify with OpenSSL");
  }

  // ---- 5. CA revoke ------------------------------------------------------------------------------
  {
    const revoked = await svc.cas.revoke(admin, idem(), childA.caId, {
      reason: "caCompromise",
    });
    check(
      revoked.body.crlEntry === true &&
        revoked.body.crlPublished === true &&
        revoked.body.changed === true &&
        (revoked.body.revokedCaIds as string[])[0] === childA.caId,
      `the revoke publishes the root's CRL: ${JSON.stringify(revoked.body.crlNumber)}`,
    );
    const rootCrl = parseCrl(await downloadCrl(rootA.caId));
    const entry = rootCrl.entries.find(
      (item) => canonicalSerialHex(item.serialHex) === childA.serial,
    );
    check(
      entry?.reason === 2,
      "the root CRL lists the child with reason caCompromise",
    );
    const after = await reload(childA.caId);
    check(
      after.status === "REVOKED" &&
        after.key.state === "DISABLED" &&
        after.revocationEvidence === `parent:${rootA.caId}`,
      "the child is REVOKED with its key DISABLED",
    );
    check(
      (await pki.getCertificate(rootA.caId, childA.serial as string))
        ?.status === "REVOKED",
      "the root's row is REVOKED",
    );
    await expectApi(
      () => issueFor(consumerA, "web", idem(), newCsr("c.example.com")),
      { status: 409, code: "ca_not_active", reason: "revoked" },
      "issuing under the revoked child",
    );
    await expectApi(
      () => issueFor(consumerA, "web", leafKey, leafCsr),
      { status: 409, code: "issuance_revoked", reason: "ca_revoked" },
      "replaying a leaf under the revoked child",
    );
    await expectApi(
      () =>
        svc.certificates.revoke(
          admin,
          idem(),
          rootA.caId,
          childA.serial as string,
          {},
        ),
      { status: 409, code: "conflict", reason: "use_ca_revoke" },
      "revoking the child's row as a leaf",
    );
    await withOpenssl(async ({ write, openssl }) => {
      write("root.pem", rootA.certificatePem ?? "");
      write("child.pem", childA.certificatePem ?? "");
      write("leaf.pem", leaf.body.certificatePem as string);
      write("root.der", await downloadCrl(rootA.caId));
      write("child.der", await downloadCrl(childA.caId));
      openssl(["crl", "-inform", "DER", "-in", "root.der", "-out", "root.crl"]);
      openssl([
        "crl",
        "-inform",
        "DER",
        "-in",
        "child.der",
        "-out",
        "child.crl",
      ]);
      const rejected = openssl(
        [
          "verify",
          "-x509_strict",
          "-purpose",
          "sslserver",
          "-crl_check_all",
          "-CRLfile",
          "child.crl",
          "-CRLfile",
          "root.crl",
          "-CAfile",
          "root.pem",
          "-untrusted",
          "child.pem",
          "leaf.pem",
        ],
        true,
      );
      check(
        rejected.status !== 0 &&
          /at 1 depth/.test(rejected.output) &&
          rejected.output.includes("certificate revoked"),
        `OpenSSL rejects the leaf at depth 1: ${rejected.output}`,
      );
    });
    const again = await svc.cas.revoke(admin, idem(), childA.caId, {});
    check(again.body.changed === false, "a second revoke is a no-op");

    // An expired child: no entry, no revision bump, no publication.
    const past = build({ now: () => new Date(Date.now() - 40 * day) });
    const oldRoot = await createRoot("p7-old-root", {}, past);
    const oldChild = await createChild(
      oldRoot,
      "p7-old-child",
      { validitySeconds: 2_592_000 },
      past,
    );
    const revisionBefore = (await crlOf(oldRoot.caId)).revision;
    const expired = await svc.cas.revoke(admin, idem(), oldChild.caId, {});
    check(
      expired.body.changed === true &&
        expired.body.crlEntry === false &&
        expired.body.crlPublished === false,
      "an expired child is revoked without a CRL entry",
    );
    check(
      (await rawGet(
        pkiKeys.revocation(oldRoot.caId, oldChild.serial as string),
      )) === undefined,
      "no REVOKED# item exists for the expired child",
    );
    check(
      (await crlOf(oldRoot.caId)).revision === revisionBefore,
      "the root's revision is unchanged",
    );
    check(
      (await reload(oldChild.caId)).status === "REVOKED" &&
        (await pki.getCertificate(oldRoot.caId, oldChild.serial as string))
          ?.status === "REVOKED",
      "the expired child and its row are REVOKED",
    );
    done(
      "CA revoke: CRL entry, inline publish, issuance and replay refusals, OpenSSL depth 1, expired child",
    );
  }

  // ---- 6. Retire and drain -----------------------------------------------------------------------
  {
    const root = await createRoot("p7-drain-root");
    const child = await createChild(root, "p7-drain-child");
    const consumer = await putConsumer();
    await createGrant(consumer, "web", child.caId);
    await svc.cas.retire(admin, idem(), root.caId);
    const retired = await reload(root.caId);
    check(retired.status === "RETIRED", "the root is RETIRED");
    check(
      Date.parse(drainPoint(retired)) >= Date.parse(child.notAfter ?? ""),
      "the root drains no earlier than its child",
    );
    const issued = await issueFor(
      consumer,
      "web",
      idem(),
      newCsr("d.example.com"),
    );
    check(
      issued.status === 201,
      "a leaf under a child of a retired root still issues",
    );
    await svc.cas.forcePublish(admin, idem(), root.caId);
    const crl = await crlOf(root.caId);
    check(
      (await svc.cas.disableDrainedKey(retired, crl)) === false,
      "the root's key is not disabled before the drain point",
    );
    check(
      !isDrained(retired, { ...crl, published: crl.published as never }),
      "the root is not drained",
    );
    done(
      "a retired root keeps issuing for its children and does not drain early",
    );
  }

  // ---- 7. Distrust --------------------------------------------------------------------------------
  {
    const rootB = await createRoot("p7-distrust-root");
    const a1 = await createChild(rootB, "p7-a1");
    const a2 = await createChild(rootB, "p7-a2");
    const consumer = await putConsumer();
    await createGrant(consumer, "web", a1.caId);
    const replayKey = idem();
    const replayCsr = newCsr("e.example.com");
    await issueFor(consumer, "web", replayKey, replayCsr);
    // The walk finds no children: the ancestor checks alone must hold.
    const missed = build({
      pki: stubFirst(pki, "queryDirectory", async () => []),
    });
    const revoked = await missed.cas.revoke(admin, idem(), rootB.caId, {
      reason: "caCompromise",
    });
    check(
      revoked.body.changed === true && revoked.body.complete === true,
      "the root is distrusted",
    );
    const rootAfter = await reload(rootB.caId);
    check(
      rootAfter.status === "REVOKED" &&
        rootAfter.key.state === "DISABLED" &&
        rootAfter.revocationEvidence === "local-distrust",
      "the root is REVOKED with its key DISABLED",
    );
    check(
      (await reload(a1.caId)).status === "ACTIVE" &&
        (await reload(a2.caId)).status === "ACTIVE",
      "the children are still ACTIVE after the missed walk",
    );
    await expectApi(
      () => issueFor(consumer, "web", idem(), newCsr("f.example.com")),
      { status: 409, code: "ca_not_active", reason: "ancestor_revoked" },
      "issuing under a child of a distrusted root",
    );
    await expectApi(
      () => issueFor(consumer, "web", replayKey, replayCsr),
      { status: 409, code: "issuance_revoked", reason: "ancestor_revoked" },
      "replaying a leaf under a child of a distrusted root",
    );
    const summary = await maintenance(svc);
    check(
      summary.revoked >= 2,
      `the maintenance pass flips both children (${summary.revoked})`,
    );
    for (const child of [a1, a2]) {
      const flipped = await reload(child.caId);
      check(
        flipped.status === "REVOKED" &&
          flipped.key.state === "DISABLED" &&
          flipped.revocationEvidence === `ancestor:${rootB.caId}`,
        `child ${child.caId} is REVOKED by the finisher`,
      );
      check(
        auditEvents.some(
          (event) =>
            event.operation === "pki.ca.revoke" &&
            (event.target as Record<string, string>).caId === child.caId &&
            (event.target as Record<string, string>).trigger === "maintenance",
        ),
        `the finisher audited ${child.caId}`,
      );
    }
    await expectApi(
      () => issueFor(consumer, "web", replayKey, replayCsr),
      { status: 409, code: "issuance_revoked", reason: "ca_revoked" },
      "replaying after the finisher",
    );

    // Without the hook the walk finishes in the request.
    const rootC = await createRoot("p7-walk-root");
    const c1 = await createChild(rootC, "p7-c1");
    const c2 = await createChild(rootC, "p7-c2");
    await eventually(
      async () =>
        (
          await pki.queryDirectory("PKI_CAS", { sortPrefix: `${environment}#` })
        ).filter((item) => item.parentCaId === rootC.caId).length === 2,
      "the directory lists both children",
    );
    const walked = await svc.cas.revoke(admin, idem(), rootC.caId, {});
    check(
      walked.body.complete === true &&
        JSON.stringify(walked.body.revokedCaIds) ===
          JSON.stringify([c1.caId, c2.caId].sort()),
      `the walk reports both children: ${JSON.stringify(walked.body.revokedCaIds)}`,
    );
    done(
      "local distrust: ancestor checks hold, the finisher flips the children, the walk completes",
    );
  }

  // ---- 8. The subject registry across kinds -------------------------------------------------------
  {
    const root = await createRoot("p7-registry-root");
    const external = await makeRoot({
      subject: { O: "Ministack P7", CN: root.subject.CN },
    });
    const name = unique("p7-ext");
    const created = await svc.cas.create(admin, idem(), {
      environment,
      name,
      kind: "EXTERNAL_INTERMEDIATE",
      keyAlgorithm: "ECDSA_P256",
      subject: {
        organization: "Ministack P7",
        commonName: `P7 External ${name} ${suffix}`,
      },
    });
    const pending = await reload(created.body.caId as string);
    const spki = parseRawCsr(
      fromPem(pending.csrPem ?? "", "CERTIFICATE REQUEST"),
    ).spkiDer;
    const cert = await makeIntermediate(external, {
      key: { spkiDer: spki } as unknown as TestKey,
      subject: pending.subject,
    });
    await expectApi(
      () =>
        svc.cas.activate(admin, idem(), pending.caId, {
          certificatePem: cert.pem,
          chainPem: external.pem,
        }),
      {
        status: 409,
        code: "ca_subject_in_use",
        reason: "root_subject_claimed",
      },
      "activating an external CA under a root with a Hemlig ROOT's subject",
    );
    done("an external root cannot take a Hemlig ROOT's subject");
  }

  // ---- 10. The consumer bundle route --------------------------------------------------------------
  {
    const app = {
      repository,
      pki,
      crls: svc.crls,
      audit,
      now: () => new Date(),
    } as unknown as PkiApplication;
    const handler = createPkiIssuerHandler(
      pkiIssuerRoutes,
      createErrorResponder(() => app),
    );
    const consumer = await makeRoot({
      subject: { CN: `p7 consumer ${suffix}` },
    });
    const fingerprint = createHash("sha256")
      .update(new X509Certificate(consumer.pem).raw)
      .digest("hex");
    await doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          pk: `IDENTITY#${fingerprint}`,
          sk: "PROFILE",
          fingerprint,
          consumerId: `p7-bundle-${suffix}`,
          environment,
          kind: "api",
          status: "ACTIVE",
          notBefore: new Date(Date.now() - 3_600_000).toISOString(),
          notAfter: new Date(Date.now() + 86_400_000).toISOString(),
        },
      }),
    );
    const bundleOf = async (caId: string): Promise<Record<string, any>> => {
      const result = await handler({
        rawPath: `/v1/pki/cas/${caId}/bundle`,
        headers: {},
        requestContext: {
          requestId: randomUUID(),
          http: { method: "GET", sourceIp: "203.0.113.9" },
          authentication: { clientCert: { clientCertPem: consumer.pem } },
        },
      } as unknown as APIGatewayProxyEventV2);
      check(
        result.statusCode === 200,
        `bundle of ${caId}: ${result.statusCode}`,
      );
      return JSON.parse(result.body ?? "{}") as Record<string, any>;
    };
    const der = (pem: string): Buffer => fromPem(pem, "CERTIFICATE");
    const root = await createRoot("p7-bundle-root");
    const child = await createChild(root, "p7-bundle-child");
    const childBundle = await bundleOf(child.caId);
    const rootBundle = await bundleOf(root.caId);
    check(
      der(childBundle.anchorPem).equals(der(root.certificatePem ?? "")),
      "the child's anchor is the root certificate",
    );
    check(
      der(
        `${childBundle.chainPem.split("-----END CERTIFICATE-----")[0]}-----END CERTIFICATE-----\n`,
      ).equals(der(child.certificatePem ?? "")),
      "the first chain block is the child",
    );
    check(
      JSON.stringify(childBundle.crlIssuers) ===
        JSON.stringify([
          { id: child.caId, source: "GENERATED" },
          { id: root.caId, source: "GENERATED" },
        ]) && childBundle.anchorTrusted === true,
      `the child's CRL issuers and trust: ${JSON.stringify(childBundle.crlIssuers)}`,
    );
    check(
      rootBundle.chainPem === "" &&
        rootBundle.anchorTrusted === true &&
        der(rootBundle.anchorPem).equals(der(root.certificatePem ?? "")) &&
        JSON.stringify(rootBundle.crlIssuers) ===
          JSON.stringify([{ id: root.caId, source: "GENERATED" }]),
      "the ROOT's own bundle has an empty chain",
    );
    // A distrust whose walk is missed: both bundles already show the anchor as untrusted.
    const missed = build({
      pki: stubFirst(pki, "queryDirectory", async () => []),
    });
    await missed.cas.revoke(admin, idem(), root.caId, {});
    check(
      (await reload(child.caId)).status === "ACTIVE",
      "the child is still ACTIVE",
    );
    const childAfter = await bundleOf(child.caId);
    const rootAfter = await bundleOf(root.caId);
    check(
      childAfter.anchorTrusted === false &&
        rootAfter.anchorTrusted === false &&
        childAfter.status === "ACTIVE" &&
        rootAfter.status === "REVOKED",
      "both bundles show the anchor as untrusted",
    );
    done(
      "the bundle route for a ROOT and an INTERMEDIATE, before and after a missed distrust walk",
    );
  }

  // ---- 9. Audit hygiene --------------------------------------------------------------------------
  check(
    humanTargets.some((entry) => entry.operation === "pki.ca.create") &&
      humanTargets.some((entry) => entry.operation === "pki.ca.revoke"),
    "a human create and a human revoke target were scanned",
  );
  check(
    !JSON.stringify([auditEvents, humanTargets]).includes("-----BEGIN"),
    "no audit event or human audit target contains PEM",
  );
  done("no audit event contains PEM");

  process.stdout.write(
    `PKI hierarchy MiniStack verification passed (${cases} checks).\n`,
  );
};
