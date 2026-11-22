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
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { KMSClient } from "@aws-sdk/client-kms";
import type { S3Client } from "@aws-sdk/client-s3";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { PkiConfig } from "../aws/config";
import { ApiError } from "../domain/errors";
import type { Actor } from "../domain/types";
import { parseCrl, verifyCrlSignature } from "../pki/asn1/crl";
import { parseRawCsr } from "../pki/asn1/csr";
import { EXT, extension, keyIdentifierValue } from "../pki/asn1/extensions";
import { fromPem, toPem } from "../pki/asn1/pem";
import { CaService } from "../pki/ca-service";
import { CrlService, evaluateCrl, pkiObjectRead } from "../pki/crl-service";
import { ExternalCaService } from "../pki/external-ca-service";
import { runMaintenancePass } from "../pki/maintenance";
import type { PkiMetricName } from "../pki/metrics";
import type { PkiServiceDeps } from "../pki/service-types";
import { WrappedCaSigner } from "../pki/signer";
import { buildCaSubject } from "../pki/subject";
import type { CaRecord } from "../pki/types";
import { DynamoCursorStore } from "../repositories/cursor-store";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { pkiKeys, PkiRepository, type PkiKey } from "../repositories/pki";
import { CursorService } from "../services/cursor";
import { sha256Hex } from "../util/encoding";
import {
  crlPem,
  days,
  hours,
  makeCert,
  makeCrl,
  makeIntermediate,
  makeRoot,
  rawReasonExtension,
  rootExtensions,
  type TestCert,
  type TestKey,
} from "./pki-fixtures";

/**
 * The Phase 3 lifecycle suite against MiniStack: the real repository, services, KMS, S3 and DynamoDB. Clocks are
 * injected per service. Races are created by wrapping the repository in a Proxy that runs the competing operation
 * before delegating one chosen method; there are no production hooks.
 */
export interface PkiLifecycleOptions {
  readonly dynamo: DynamoDBClient;
  readonly kms: KMSClient;
  readonly s3: S3Client;
  readonly keyArn: string;
  readonly table: string;
  readonly bucket: string;
  readonly config: PkiConfig;
}

const check = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(`PKI lifecycle verification failed: ${message}`);
  }
};

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

type Hook = (...args: never[]) => Promise<void>;

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
        await (hook as (...a: unknown[]) => Promise<void>)(...args);
        return (value as (...a: unknown[]) => unknown).apply(object, args);
      };
    },
  });
};

const serialOf = (n: number): Buffer =>
  Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, n]);

export const verifyPkiLifecycleOnMiniStack = async (
  options: PkiLifecycleOptions,
): Promise<void> => {
  const { table, bucket, config } = options;
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
  const environment = "ministack";
  const admin: Actor = { type: "human", id: `lifecycle-admin-${suffix}` };
  const auditEvents: { operation: string; target?: Record<string, string> }[] =
    [];
  const audit = {
    write: async (event: {
      operation: string;
      target?: Readonly<Record<string, string>>;
    }) => {
      auditEvents.push({
        operation: event.operation,
        ...(event.target === undefined ? {} : { target: { ...event.target } }),
      });
      return { ...event, eventId: randomUUID(), at: new Date().toISOString() };
    },
  } as never;
  const emitted: Partial<Record<PkiMetricName, number>>[] = [];
  let cases = 0;
  const done = (name: string): void => {
    cases += 1;
    process.stdout.write(`PKI lifecycle ok: ${name}\n`);
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
      emit: (_deployment, values) => {
        emitted.push(values);
      },
    };
    const crls = new CrlService(deps, async () => undefined);
    return {
      deps,
      crls,
      cas: new CaService(deps, crls),
      externalCas: new ExternalCaService(deps),
    };
  };
  const svc = build();

  const expectApi = async (
    work: () => Promise<unknown>,
    expected: { status: number; code: string; reason?: string },
    label: string,
  ): Promise<void> => {
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
        return;
      }
      throw new Error(
        `PKI lifecycle verification failed: ${label} threw ${
          error instanceof ApiError
            ? `${error.statusCode} ${error.code} ${error.details?.reason}`
            : String(error)
        }`,
      );
    }
    throw new Error(
      `PKI lifecycle verification failed: ${label} did not throw`,
    );
  };

  // ---- Helpers -------------------------------------------------------------
  let nextSerial = 1;
  let crlNumber = 0;
  const subject = (cn: string) => ({
    organization: "Ministack Corp",
    commonName: cn,
  });
  const createBody = (
    name: string,
    cn: string,
    extra: Record<string, unknown> = {},
  ) => ({
    environment,
    name,
    kind: "EXTERNAL_INTERMEDIATE",
    keyAlgorithm: "ECDSA_P256",
    subject: subject(cn),
    ...extra,
  });
  const uniqueName = (label: string): string =>
    `${label}-${randomBytes(3).toString("hex")}`;
  const createCa = async (
    label: string,
    extra: Record<string, unknown> = {},
    service = svc,
  ): Promise<CaRecord> => {
    const name = uniqueName(label);
    const result = await service.cas.create(
      admin,
      idem(),
      createBody(name, `Ministack ${name}`, extra),
    );
    const ca = await pki.getCa(result.body.caId as string);
    check(ca !== undefined, "the created CA is missing");
    return ca as CaRecord;
  };
  const signCa = (
    root: TestCert,
    ca: CaRecord,
    options: { notAfter?: Date; serial?: number } = {},
  ): Promise<TestCert> => {
    const spki = parseRawCsr(
      fromPem(ca.csrPem ?? "", "CERTIFICATE REQUEST"),
    ).spkiDer;
    return makeIntermediate(root, {
      key: { spkiDer: spki } as unknown as TestKey,
      subject: ca.subject,
      serial: serialOf(options.serial ?? nextSerial++),
      ...(options.notAfter === undefined ? {} : { notAfter: options.notAfter }),
    });
  };
  const rootCrl = (
    root: TestCert,
    entries: { cert: TestCert; hold?: boolean }[] = [],
    number = ++crlNumber,
  ): string => {
    const thisUpdate = new Date(Date.now() - hours(100) + number * hours(1));
    return crlPem(
      makeCrl({
        ca: root,
        number: BigInt(number),
        thisUpdate,
        nextUpdate: new Date(Date.now() + days(60)),
        entries: entries.map((entry) => ({
          serialHex: entry.cert.cert.serialHex,
          date: thisUpdate,
          ...(entry.hold === true
            ? { extensions: [rawReasonExtension(6)] }
            : {}),
        })),
      }),
    );
  };
  const activate = async (
    ca: CaRecord,
    cert: TestCert,
    root: TestCert,
    extra: Record<string, unknown> = {},
    service = svc,
  ) =>
    service.cas.activate(admin, idem(), ca.caId, {
      certificatePem: cert.pem,
      chainPem: root.pem,
      ...extra,
    });
  const reload = async (caId: string): Promise<CaRecord> => {
    const ca = await pki.getCa(caId);
    check(ca !== undefined, `CA ${caId} is missing`);
    return ca as CaRecord;
  };
  const rawGet = async (key: PkiKey) =>
    (
      await doc.send(
        new GetCommand({
          TableName: table,
          Key: { pk: key.pk, sk: key.sk },
          ConsistentRead: true,
        }),
      )
    ).Item;
  const extIdOf = (root: TestCert): string =>
    `ext-${root.cert.spkiSha256.slice(0, 40)}`;
  const newRoot = (label: string, algorithm?: "ECDSA_P384") =>
    makeRoot({
      subject: { O: "Ministack Corp", CN: `Ministack ${label} ${suffix}` },
      ...(algorithm === undefined ? {} : { algorithm }),
    });
  const seedRevocation = (
    caId: string,
    serial: string,
    notAfter: Date,
  ): Promise<unknown> =>
    doc.send(
      new PutCommand({
        TableName: table,
        Item: {
          ...pkiKeys.revocation(caId, serial),
          caId,
          serial,
          revokedAt: new Date().toISOString(),
          reason: "keyCompromise",
          notAfter: notAfter.toISOString(),
        },
      }),
    );
  const bumpRevision = (caId: string): Promise<unknown> =>
    doc.send(
      new UpdateCommand({
        TableName: table,
        Key: { ...pkiKeys.caCrl(caId) },
        UpdateExpression:
          "SET #revision = #revision + :one, #dirtySince = if_not_exists(#dirtySince, :now)",
        ExpressionAttributeNames: {
          "#revision": "revision",
          "#dirtySince": "dirtySince",
        },
        ExpressionAttributeValues: {
          ":one": 1,
          ":now": new Date().toISOString(),
        },
      }),
    );
  const crlOf = async (caId: string) => {
    const state = await pki.getCaCrlState(caId);
    check(state !== undefined, `CRL state of ${caId} is missing`);
    return state as NonNullable<typeof state>;
  };
  const activeCa = async (label: string, root: TestCert, extra = {}) => {
    const ca = await createCa(label, extra);
    const cert = await signCa(root, ca);
    await activate(ca, cert, root);
    return { ca: await reload(ca.caId), cert };
  };
  const pass = (clock: () => Date, remaining = () => 300_000) =>
    runMaintenancePass({
      app: {
        pki,
        cas: build({ now: clock }).cas,
        crls: build({ now: clock }).crls,
        audit,
        config,
      },
      now: clock(),
      remainingMs: remaining,
      correlationId: "lifecycle",
      emit: (_deployment, values) => {
        emitted.push(values);
      },
      log: () => undefined,
    });

  // ---- Create ---------------------------------------------------------------
  const duplicateName = uniqueName("dup");
  const duplicateKey = idem();
  const first = await svc.cas.create(
    admin,
    duplicateKey,
    createBody(duplicateName, `Ministack ${duplicateName}`),
  );
  check(
    first.status === 201 &&
      typeof first.body.caId === "string" &&
      typeof first.body.csrPem === "string",
    "create must return 201 with the CA and its CSR",
  );
  const again = await svc.cas.create(
    admin,
    duplicateKey,
    createBody(duplicateName, `Ministack ${duplicateName}`),
  );
  check(
    again.status === 201 &&
      again.body.caId === first.body.caId &&
      again.body.csrPem === first.body.csrPem,
    "a retry with the same key must return the same CA and CSR",
  );
  await expectApi(
    () =>
      svc.cas.create(
        admin,
        duplicateKey,
        createBody(duplicateName, `Ministack changed ${suffix}`),
      ),
    { status: 409, code: "conflict" },
    "the same key with a different body",
  );
  const claim = await pki.getCaNameClaim(environment, duplicateName);
  check(claim?.caId === first.body.caId, "the name claim must point at the CA");
  const duplicateSubjectKey = buildCaSubject({
    O: "Ministack Corp",
    CN: `Ministack ${duplicateName}`,
  }).key;
  check(
    (await pki.getSubjectClaim(duplicateSubjectKey))?.caId === first.body.caId,
    "the subject claim must point at the CA",
  );
  done("create is idempotent and claims the name and subject once");

  await expectApi(
    () =>
      svc.cas.create(
        admin,
        idem(),
        createBody(uniqueName("other"), `Ministack ${duplicateName}`),
      ),
    {
      status: 409,
      code: "ca_subject_in_use",
      reason: "subject_claimed",
    },
    "a duplicate subject",
  );
  await expectApi(
    () =>
      svc.cas.create(
        admin,
        idem(),
        createBody(duplicateName, `Ministack second ${suffix}`),
      ),
    { status: 409, code: "conflict", reason: "name_in_use" },
    "a duplicate name",
  );
  await expectApi(
    () =>
      svc.cas.create(
        admin,
        idem(),
        createBody(uniqueName("idroot"), "unused", {
          subject: {
            commonName: `Hemlig ${config.environmentName} Issuing Root`,
          },
        }),
      ),
    {
      status: 409,
      code: "ca_subject_in_use",
      reason: "identity_root_reserved",
    },
    "the identity root subject",
  );
  done("duplicate subject, duplicate name and the identity-root subject");

  {
    const ca = await createCa("pending");
    const result = await svc.cas.abandon(admin, idem(), ca.caId, ca.version);
    check(result.body.status === "FAILED", "DELETE must mark the CA FAILED");
    const failed = await reload(ca.caId);
    check(
      failed.key.wrapped === undefined && failed.key.state === "DESTROYED",
      "DELETE must destroy the wrapped key",
    );
    await expectApi(
      () =>
        svc.cas.create(
          admin,
          idem(),
          createBody(uniqueName("reuse"), `Ministack ${ca.name}`),
        ),
      { status: 409, code: "ca_subject_in_use" },
      "reusing the DN of an abandoned CA",
    );
    await expectApi(
      () =>
        svc.cas.create(
          admin,
          idem(),
          createBody(ca.name, `Ministack x ${suffix}`),
        ),
      { status: 409, code: "conflict", reason: "name_in_use" },
      "reusing the name of an abandoned CA",
    );
  }
  done("an abandoned CA keeps its name and subject claims");

  // ---- Two intermediates under one root -------------------------------------
  const rootR = await newRoot("Root R");
  const extR = extIdOf(rootR);
  const caA = await createCa("a");
  const certA = await signCa(rootR, caA);
  const c1 = rootCrl(rootR);
  const activatedA = await activate(caA, certA, rootR, { rootCrl: c1 });
  check(activatedA.body.status === "ACTIVE", "A must activate");
  {
    const ext = await pki.getExternalCa(extR);
    check(
      ext !== undefined && ext.crl?.numberHex.endsWith("01") === true,
      "activation must create the external record seeded with C1",
    );
    check(
      ext?.dependents.has(caA.caId) === true,
      "A must be a dependent of the root",
    );
    const state = await crlOf(caA.caId);
    check(
      state.published?.number === 1 && state.published.entryCount === 0,
      "the initial CRL is number 1 and empty",
    );
    const object = await pkiObjectRead(
      objects,
      bucket,
      state.published?.objectKey ?? "",
    );
    check(object.length < 1024 * 1024, "the initial CRL must stay under 1 MiB");
    check(
      sha256Hex(object) === state.published?.sha256 &&
        state.published.objectKey.startsWith(`crl/${caA.caId}/1-`),
      "the initial CRL object must match its pointer",
    );
    const parsed = parseCrl(object);
    check(
      verifyCrlSignature(parsed, certA.cert.spkiDer) &&
        parsed.issuerDer.equals(certA.cert.subjectDer),
      "the initial CRL must verify under A with A's exact subject as issuer",
    );
  }
  const caB = await createCa("b");
  const certB = await signCa(rootR, caB);
  const c2 = rootCrl(rootR, [{ cert: certA }]);
  await expectApi(
    () => activate(caB, certB, rootR, { rootCrl: c2 }),
    { status: 400, code: "crl_invalid", reason: "upload_first" },
    "activating B with an unseen newer root CRL",
  );
  check((await reload(caA.caId)).status === "ACTIVE", "A is still ACTIVE");
  const uploadC2 = await svc.externalCas.uploadCrl(admin, idem(), extR, {
    crl: c2,
  });
  check(
    JSON.stringify(uploadC2.body.revokedCaIds) === JSON.stringify([caA.caId]) &&
      uploadC2.body.changed === true,
    "uploading C2 must revoke A",
  );
  {
    const revoked = await reload(caA.caId);
    check(
      revoked.status === "REVOKED" &&
        revoked.key.state === "DISABLED" &&
        revoked.revocationSource === "EXTERNAL" &&
        revoked.revocationEvidence?.startsWith("crl:") === true &&
        revoked.revocationEvidence.endsWith("02"),
      "A must be REVOKED by the root CRL with its key disabled",
    );
  }
  await activate(caB, certB, rootR);
  {
    const ext = await pki.getExternalCa(extR);
    check(
      ext?.dependents.has(caA.caId) === true &&
        ext.dependents.has(caB.caId) === true &&
        (await reload(caB.caId)).status === "ACTIVE",
      "B must activate and join the dependents",
    );
  }
  done("two intermediates under one root: upload_first, the flip and the join");

  // ---- external_ca_mismatch ---------------------------------------------------
  {
    const caM = await createCa("mismatch");
    const otherDn = await makeCert({
      key: rootR.key,
      subject: buildCaSubject({ O: "Ministack Corp", CN: `Other DN ${suffix}` })
        .der,
      extensions: rootExtensions(rootR.key),
    });
    const certM = await signCa(otherDn, caM);
    await expectApi(
      () => activate(caM, certM, otherDn),
      { status: 400, code: "chain_invalid", reason: "external_ca_mismatch" },
      "a root with the same key and another DN",
    );
    const otherSki = makeCert({
      key: rootR.key,
      subject: rootR.cert.subjectDer,
      extensions: [
        ...rootExtensions(rootR.key).slice(0, 2),
        extension(
          EXT.subjectKeyIdentifier,
          false,
          keyIdentifierValue(Buffer.alloc(20, 7)),
        ),
      ],
    });
    const certS = await signCa(otherSki, caM);
    await expectApi(
      () => activate(caM, certS, otherSki),
      { status: 400, code: "chain_invalid", reason: "external_ca_mismatch" },
      "a root with the same key and DN but another SKI",
    );
  }
  done("external_ca_mismatch for a different DN and a different SKI");

  // ---- Subject registry cross-checks ------------------------------------------
  await expectApi(
    () =>
      svc.cas.create(admin, idem(), {
        environment,
        name: uniqueName("rootdn"),
        kind: "EXTERNAL_INTERMEDIATE",
        keyAlgorithm: "ECDSA_P256",
        subject: subject(`Ministack Root R ${suffix}`),
      }),
    { status: 409, code: "ca_subject_in_use", reason: "subject_claimed" },
    "creating a CA with the root's DN",
  );
  {
    const sharedDn = `Ministack Shared ${suffix}`;
    const early = await svc.cas.create(
      admin,
      idem(),
      createBody(uniqueName("early"), sharedDn),
    );
    check(typeof early.body.caId === "string", "the early CA must be created");
    const root2 = await makeRoot({
      subject: { O: "Ministack Corp", CN: sharedDn },
    });
    const caC = await createCa("c");
    const certC = await signCa(root2, caC);
    await expectApi(
      () => activate(caC, certC, root2),
      {
        status: 409,
        code: "ca_subject_in_use",
        reason: "root_subject_claimed",
      },
      "activating under a root whose DN a Hemlig CA holds",
    );
    check(
      (await reload(caC.caId)).status === "PENDING_CERTIFICATE",
      "the failed activation must leave the CA pending",
    );
  }
  done("the subject registry rejects a root and a CA with the same DN");

  // ---- Activation racing an upload ----------------------------------------------
  {
    const caD = await createCa("d");
    const certD = await signCa(rootR, caD);
    const c3 = rootCrl(rootR, [{ cert: certA }, { cert: certD }]);
    let activationHook = false;
    const racing = build({
      pki: hooked(pki, {
        commitExternalCrl: async () => {
          activationHook = true;
          await activate(caD, certD, rootR);
        },
      }),
    });
    const upload = await racing.externalCas.uploadCrl(admin, idem(), extR, {
      crl: c3,
    });
    check(activationHook, "the activation must run inside the upload");
    check(
      (upload.body.revokedCaIds as string[]).includes(caD.caId) &&
        (await reload(caD.caId)).status === "REVOKED",
      "the upload must flip the CA activated mid-upload",
    );
  }
  {
    const caE = await createCa("e");
    const certE = await signCa(rootR, caE);
    const c4 = rootCrl(rootR, [{ cert: certA }, { cert: certE }]);
    const racing = build({
      pki: hooked(pki, {
        activateCa: async () => {
          await svc.externalCas.uploadCrl(admin, idem(), extR, { crl: c4 });
        },
      }),
    });
    await expectApi(
      () => activate(caE, certE, rootR, {}, racing),
      { status: 409, code: "ca_not_active", reason: "revoked_by_parent" },
      "an activation racing an upload that revokes it",
    );
    check(
      (await reload(caE.caId)).status === "PENDING_CERTIFICATE",
      "the revoked activation must leave the CA pending",
    );
  }
  done("activation versus upload resolves in both orders");

  // ---- Uploads --------------------------------------------------------------------
  {
    const latest = (await pki.getExternalCa(extR))?.crl;
    check(latest !== undefined, "the root must hold a CRL");
    const caF = await createCa("f");
    const certF = await signCa(rootR, caF);
    await activate(caF, certF, rootR);
    const crlF = rootCrl(rootR, [{ cert: certA }, { cert: certF, hold: true }]);
    const key = idem();
    const firstUpload = await svc.externalCas.uploadCrl(admin, key, extR, {
      crl: crlF,
    });
    check(
      (firstUpload.body.revokedCaIds as string[]).includes(caF.caId),
      "a certificateHold entry must flip the CA",
    );
    const flipped = await reload(caF.caId);
    check(
      flipped.status === "REVOKED" &&
        flipped.revocationReason === "certificateHold",
      "the hold reason must be recorded",
    );
    const replay = await svc.externalCas.uploadCrl(admin, key, extR, {
      crl: crlF,
    });
    check(
      replay.status === 200 && replay.body.changed === true,
      "an identical retry with the same key must replay",
    );
    const unchanged = await svc.externalCas.uploadCrl(admin, idem(), extR, {
      crl: crlF,
    });
    check(
      unchanged.body.changed === false &&
        (unchanged.body.revokedCaIds as string[]).length === 0,
      "an identical CRL under a new key is unchanged",
    );
    await expectApi(
      () => svc.externalCas.uploadCrl(admin, idem(), extR, { crl: c1 }),
      { status: 409, code: "crl_not_newer" },
      "uploading an older CRL",
    );
    const sameNumber = rootCrl(rootR, [{ cert: certA }], crlNumber);
    await expectApi(
      () => svc.externalCas.uploadCrl(admin, idem(), extR, { crl: sameNumber }),
      { status: 409, code: "crl_not_newer" },
      "uploading a CRL with the stored number",
    );
  }
  done("root CRL uploads: replay, unchanged, not newer and certificateHold");

  // ---- CRL publication ---------------------------------------------------------------
  const rootL = await newRoot("Root L");
  {
    const { ca } = await (async () => {
      const created = await createCa("lease");
      const cert = await signCa(rootL, created);
      await activate(created, cert, rootL, { rootCrl: rootCrl(rootL) });
      return { ca: await reload(created.caId) };
    })();
    // Two concurrent publications: one wins, one is busy.
    const slow = build({
      pki: hooked(pki, {
        allocateCrlNumber: async () => sleep(400),
      }),
    });
    const [left, right] = await Promise.all([
      slow.crls.publish(ca, { trigger: "force" }),
      slow.crls.publish(ca, { trigger: "force" }),
    ]);
    const kinds = [left.kind, right.kind].sort();
    check(
      kinds.join() === "busy,published",
      `concurrent publications must give one busy, got ${kinds.join()}`,
    );
    done("two concurrent publications: one publishes, one is busy");

    // A revocation landing mid-generation keeps dirtySince.
    const before = await crlOf(ca.caId);
    const dirty = build({
      pki: hooked(pki, {
        listRevocationsSince: async () => {
          await bumpRevision(ca.caId);
        },
      }),
    });
    const published = await dirty.crls.publish(ca, { trigger: "force" });
    check(published.kind === "published", "the dirty-race publication commits");
    const after = await crlOf(ca.caId);
    check(
      after.dirtySince !== undefined &&
        after.revision === before.revision + 1 &&
        (after.published?.revision ?? 99) === before.revision &&
        evaluateCrl(ca, after, new Date()).reasons.includes("dirty"),
      "a mid-generation revocation must keep dirtySince and stay dirty",
    );
    done("a revocation mid-generation keeps the CRL dirty");

    // A stale generator can never commit.
    const g1Base = await crlOf(ca.caId);
    const g2 = build({ now: () => new Date(Date.now() + 61_000) });
    const g1 = build({
      pki: hooked(pki, {
        listRevocationsSince: async () => {
          const result = await g2.crls.publish(ca, { trigger: "force" });
          check(result.kind === "published", "G2 must publish");
        },
      }),
    });
    const stale = await g1.crls.publish(ca, { trigger: "force" });
    const afterStale = await crlOf(ca.caId);
    check(stale.kind === "superseded", "G1 must be superseded");
    check(
      afterStale.published?.number === g1Base.lastNumber + 2,
      "the pointer must stay at G2's number",
    );
    done("a stale generator is superseded");

    // A crash after the object write only skips a number.
    const owner = "crl-crashed";
    check(
      (await pki.acquireCrlLease(
        ca.caId,
        owner,
        new Date(Date.now() - 120_000),
      )) === "acquired",
      "the crashed generator takes the lease",
    );
    const allocation = await pki.allocateCrlNumber(ca.caId, owner);
    check(allocation !== "lost", "the crashed generator allocates a number");
    const crashedNumber = allocation === "lost" ? 0 : allocation.number;
    const next = await svc.crls.publish(ca, { trigger: "force" });
    check(
      next.kind === "published" && next.pointer.number > crashedNumber,
      "the next publication must use a higher number",
    );
    done("a crash after allocation only skips a CRL number");

    // A crash after the commit is finished by maintenance.
    const sweptEntry = `${randomBytes(6).toString("hex")}`;
    await seedRevocation(ca.caId, sweptEntry, new Date(Date.now() - days(2)));
    const crashing = build({
      pki: hooked(pki, {
        expireCarriedRevocations: async () => {
          throw new Error("simulated crash");
        },
      }),
    });
    // `thisUpdate` has one-second resolution: the sweep marker must differ from the previous publication's.
    await sleep(1100);
    const crashed = await crashing.crls.publish(ca, { trigger: "force" });
    check(
      crashed.kind === "published",
      "the publication commits before the sweep",
    );
    const unswept = await crlOf(ca.caId);
    check(
      unswept.sweptThrough !== unswept.published?.thisUpdate,
      "the sweep must be left unfinished",
    );
    await pass(() => new Date());
    const swept = await crlOf(ca.caId);
    const entry = await rawGet(pkiKeys.revocation(ca.caId, sweptEntry));
    check(
      swept.sweptThrough === swept.published?.thisUpdate &&
        typeof entry?.ttl === "number",
      "maintenance must finish the sweep and set the TTL",
    );
    done("maintenance finishes a sweep interrupted after the commit");
  }

  // ---- A CA revoked while a publication is in flight --------------------------------------
  {
    const disable = (caId: string): Promise<unknown> =>
      doc.send(
        new UpdateCommand({
          TableName: table,
          Key: { ...pkiKeys.caProfile(caId) },
          UpdateExpression: "SET #status = :revoked, #key.#state = :disabled",
          ExpressionAttributeNames: {
            "#status": "status",
            "#key": "key",
            "#state": "state",
          },
          ExpressionAttributeValues: {
            ":revoked": "REVOKED",
            ":disabled": "DISABLED",
          },
        }),
      );
    // Stale record handed to publish: caught by the re-read under the lease.
    const { ca: stale } = await activeCa("stale-record", rootL);
    await disable(stale.caId);
    const before = await crlOf(stale.caId);
    const refused = await svc.crls.publish(stale, { trigger: "maintenance" });
    check(
      refused.kind === "superseded" &&
        (await crlOf(stale.caId)).published?.number ===
          before.published?.number,
      "a publication with a stale CA record must be superseded without signing",
    );
    // A change after the re-read: caught by the profile check in the commit.
    const { ca: racing } = await activeCa("racing-record", rootL);
    const raced = build({
      pki: hooked(pki, {
        listRevocationsSince: async () => {
          await disable(racing.caId);
        },
      }),
    });
    const outcome = await raced.crls.publish(racing, { trigger: "force" });
    const racedState = await crlOf(racing.caId);
    check(
      outcome.kind === "superseded" && racedState.published?.number === 1,
      "a CA revoked mid-generation must not get a new pointer",
    );
  }
  done(
    "a CA revoked before or during a publication never gets a new CRL pointer",
  );

  // ---- Retention across an outage ------------------------------------------------------
  {
    const { ca } = await activeCa("retention", rootL);
    const t0 = new Date(Math.floor(Date.now() / 1000) * 1000);
    const serial = randomBytes(6).toString("hex");
    await seedRevocation(ca.caId, serial, new Date(t0.getTime() + hours(1)));
    const at = (ms: number) =>
      build({ now: () => new Date(t0.getTime() + ms) });
    const first0 = await at(0).crls.publish(ca, { trigger: "force" });
    check(
      first0.kind === "published" &&
        first0.pointer.entryCount === 1 &&
        first0.pointer.dropDueAt ===
          new Date(t0.getTime() + hours(1)).toISOString(),
      "the first CRL includes E1 with dropDueAt = notAfter",
    );
    const state = await crlOf(ca.caId);
    check(
      evaluateCrl(
        ca,
        state,
        new Date(t0.getTime() + hours(1) + 1000),
      ).reasons.includes("drop"),
      "after the drop time evaluateCrl must ask for a republish",
    );
    const late = await at(days(10)).crls.publish(ca, { trigger: "force" });
    check(
      late.kind === "published" && late.pointer.entryCount === 1,
      "after the outage the CRL still carries E1",
    );
    const entry = await rawGet(pkiKeys.revocation(ca.caId, serial));
    check(typeof entry?.ttl === "number", "E1 must get a TTL once carried");
    const after = await at(days(10) + 5000).crls.publish(ca, {
      trigger: "force",
    });
    check(
      after.kind === "published" && after.pointer.entryCount === 0,
      "the next CRL must exclude E1",
    );
  }
  done("a revocation survives an outage and is dropped one CRL later");

  // ---- Retire, drain, destroy ---------------------------------------------------------
  {
    const { ca } = await activeCa("drain", rootL, {
      policy: { maxLeafLifetimeSeconds: 3600 },
    });
    const retired = await svc.cas.retire(admin, idem(), ca.caId);
    check(retired.body.status === "RETIRED", "retire must succeed");
    const retiredAt = Date.parse((await reload(ca.caId)).retiredAt ?? "");
    await expectApi(
      () => svc.cas.destroyKey(admin, idem(), ca.caId),
      { status: 409, code: "conflict", reason: "key_not_disabled" },
      "destroying an ACTIVE key",
    );
    const clock = () => new Date(retiredAt + hours(1) + 1000);
    const summary = await pass(clock);
    check(summary.published >= 1 && summary.drained >= 1, "the pass drains");
    const drained = await reload(ca.caId);
    check(drained.key.state === "DISABLED", "the drained key must be DISABLED");
    const second = await pass(clock);
    check(second.published === 0, "the next pass publishes nothing");
    const destroyed = await svc.cas.destroyKey(admin, idem(), ca.caId);
    check(
      destroyed.body.status === "RETIRED" &&
        (await reload(ca.caId)).key.state === "DESTROYED" &&
        (await reload(ca.caId)).key.wrapped === undefined,
      "destroy-key must succeed after the drain",
    );
  }
  done("retire, drain, key disable and destroy");

  // ---- Metrics -----------------------------------------------------------------------------
  {
    // Healthy: every root CRL is valid for 60 days.
    emitted.length = 0;
    await pass(() => new Date());
    const healthy = emitted.at(-1) ?? {};
    check(
      healthy.ExternalCrlMissing === 0 &&
        healthy.ExternalCrlStale === 0 &&
        healthy.GeneratedCrlStale === 0 &&
        healthy.CaExpiring === 0 &&
        healthy.CrlOverCapacity === 0,
      `a healthy table must emit all zeros, got ${JSON.stringify(healthy)}`,
    );
    // Missing: an external CA with no CRL, created 25 hours ago.
    const rootM = await newRoot("Root M");
    const caM = await createCa("missing");
    await activate(caM, await signCa(rootM, caM), rootM);
    await doc.send(
      new UpdateCommand({
        TableName: table,
        Key: { ...pkiKeys.externalCa(extIdOf(rootM)) },
        UpdateExpression: "SET #createdAt = :old",
        ExpressionAttributeNames: { "#createdAt": "createdAt" },
        ExpressionAttributeValues: {
          ":old": new Date(Date.now() - hours(25)).toISOString(),
        },
      }),
    );
    await pass(() => new Date());
    check(
      emitted.at(-1)?.ExternalCrlMissing === 1,
      "a root without a CRL for 25 hours must count as missing",
    );
    // Stale: a root CRL whose nextUpdate is 20 days away.
    const rootS = await newRoot("Root S");
    const caS = await createCa("stale");
    const certS = await signCa(rootS, caS);
    const thisUpdate = new Date(Date.now() - hours(1));
    await activate(caS, certS, rootS, {
      rootCrl: crlPem(
        makeCrl({
          ca: rootS,
          number: 1n,
          thisUpdate,
          nextUpdate: new Date(Date.now() + days(20)),
        }),
      ),
    });
    await pass(() => new Date());
    check(
      emitted.at(-1)?.ExternalCrlStale === 1 &&
        emitted.at(-1)?.ExternalCrlMissing === 1,
      "a root CRL expiring in 20 days must count as stale",
    );
  }
  done("maintenance metrics: healthy, missing and stale");

  // ---- Auto-retire (last: it moves the clock far ahead) -----------------------------------
  {
    const rootT = await newRoot("Root T");
    const created = await createCa("expiring");
    // Certificates carry whole seconds.
    const notAfter = new Date(
      Math.floor((Date.now() + days(31)) / 1000) * 1000,
    );
    const cert = await signCa(rootT, created, { notAfter });
    await activate(created, cert, rootT);
    const clock = () => new Date(notAfter.getTime() + 1000);
    await pass(clock);
    const retired = await reload(created.caId);
    check(
      retired.status === "RETIRED" &&
        retired.retiredAt === notAfter.toISOString() &&
        retired.key.state === "DISABLED",
      "an expired CA must retire, publish and disable its key in one pass",
    );
    const state = await crlOf(created.caId);
    check(
      (state.published?.thisUpdate ?? "") > notAfter.toISOString(),
      "the drain CRL must be published after the drain point",
    );
    check(
      auditEvents.some(
        (event) =>
          event.operation === "pki.ca.retire" &&
          event.target?.caId === created.caId &&
          event.target.reason === "expired",
      ),
      "the automatic retirement must be audited",
    );
  }
  done("an expired CA retires, publishes and drains in one pass");

  // ---- PKI-2 local equivalent ------------------------------------------------------------------
  await verifyOpenSslRecipe();

  process.stdout.write(
    `PKI lifecycle MiniStack verification passed (${cases + 1} checks).\n`,
  );

  // The recipe root, OpenSSL signing the Hemlig CSR, and every acceptance command of Gate PKI-2.
  async function verifyOpenSslRecipe(): Promise<void> {
    const have = spawnSync("openssl", ["version"]).status === 0;
    if (!have) {
      if (process.env.CI !== undefined) {
        throw new Error(
          "PKI lifecycle verification failed: openssl is required when CI is set.",
        );
      }
      process.stdout.write(
        "PKI notice: openssl is not on PATH; skipping the PKI-2 recipe check.\n",
      );
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "hemlig-pki2-"));
    try {
      const file = (name: string): string => join(dir, name);
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
            `PKI lifecycle verification failed: openssl ${args.join(" ")}:\n${output}`,
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
        name: uniqueName("openssl"),
        kind: "EXTERNAL_INTERMEDIATE",
        keyAlgorithm: "ECDSA_P256",
        subject: {
          organization: "Example Corp",
          commonName: `MiniStack OpenSSL Issuing ${suffix}`,
        },
        requestedConstraints: {
          nameConstraints: { permitted: { dns: ["example.com"] } },
        },
      });
      writeFileSync(file("issuing.csr"), created.body.csrPem as string);
      check(
        /verify OK/i.test(
          openssl(["req", "-in", "issuing.csr", "-noout", "-verify"]).output,
        ),
        "openssl must verify the Hemlig CSR",
      );
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
      const text = (name: string): string => readFileSync(file(name), "utf8");
      const activated = await svc.cas.activate(
        admin,
        idem(),
        created.body.caId as string,
        {
          certificatePem: text("issuing.pem"),
          chainPem: text("root.pem"),
          rootCrl: text("root.crl.pem"),
        },
      );
      check(
        activated.body.status === "ACTIVE",
        "the OpenSSL-signed CA activates",
      );
      const caState = await crlOf(created.body.caId as string);
      const initial = await pkiObjectRead(
        objects,
        bucket,
        caState.published?.objectKey ?? "",
      );
      writeFileSync(file("issuing.crl"), initial);
      writeFileSync(
        file("chain-and-root.pem"),
        text("issuing.pem") + text("root.pem"),
      );
      check(
        openssl([
          "verify",
          "-x509_strict",
          "-CAfile",
          "root.pem",
          "issuing.pem",
        ]).output.includes("OK"),
        "openssl verify -x509_strict",
      );
      check(
        openssl([
          "verify",
          "-crl_check",
          "-CAfile",
          "root.pem",
          "-CRLfile",
          "root.crl.pem",
          "issuing.pem",
        ]).output.includes("OK"),
        "openssl verify -crl_check",
      );
      check(
        /verify OK/i.test(
          openssl([
            "crl",
            "-inform",
            "DER",
            "-in",
            "issuing.crl",
            "-CAfile",
            "chain-and-root.pem",
            "-noout",
            "-verify",
          ]).output,
        ),
        "openssl must verify the initial CRL under the issuing CA",
      );
      // A second root CRL uploads.
      openssl([
        "ca",
        "-config",
        "root-ca.cnf",
        "-gencrl",
        "-out",
        "root2.crl.pem",
      ]);
      const extId = (activated.body.parent as { id: string }).id;
      const upload = await svc.externalCas.uploadCrl(admin, idem(), extId, {
        crl: text("root2.crl.pem"),
      });
      check(
        upload.body.changed === true,
        "the second OpenSSL root CRL must upload",
      );
      // A corrupted signature.
      const der = Buffer.from(
        text("root2.crl.pem")
          .replace(/-----[A-Z0-9 ]+-----/g, "")
          .replace(/\s+/g, ""),
        "base64",
      );
      der[der.length - 1] = (der[der.length - 1] as number) ^ 1;
      await expectApi(
        () =>
          svc.externalCas.uploadCrl(admin, idem(), extId, {
            crl: toPem(der, "X509 CRL"),
          }),
        { status: 400, code: "crl_invalid", reason: "bad_signature" },
        "a corrupted root CRL",
      );
      // Another key under the same DN.
      const impostor = await makeRoot({
        subject: { O: "Example Corp", CN: "Example Offline Root CA 1" },
      });
      await expectApi(
        () =>
          svc.externalCas.uploadCrl(admin, idem(), extId, {
            crl: crlPem(
              makeCrl({
                ca: impostor,
                number: 9n,
                nextUpdate: new Date(Date.now() + days(60)),
              }),
            ),
          }),
        { status: 400, code: "crl_invalid", reason: "bad_signature" },
        "a CRL from another key with the same DN",
      );
      await expectApi(
        () =>
          svc.externalCas.uploadCrl(admin, idem(), extId, {
            crl: text("root.crl.pem"),
          }),
        { status: 409, code: "crl_not_newer" },
        "the first OpenSSL CRL again",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    done("PKI-2 equivalent: OpenSSL root, CSR, activation, CRLs and uploads");
  }
};

/** The offline root recipe's configuration from the PKI plan, with an absolute `dir`. */
const rootConfig = (dir: string): string => `
[ ca ]
default_ca = root_ca

[ root_ca ]
dir              = ${dir}
database         = $dir/index.txt
new_certs_dir    = $dir/certs
serial           = $dir/serial
crlnumber        = $dir/crlnumber
certificate      = $dir/root.pem
private_key      = $dir/private/root.key
default_md       = sha384
default_days     = 730
default_crl_days = 180
policy           = policy_hemlig
preserve         = yes
unique_subject   = no
copy_extensions  = copyall
x509_extensions  = intermediate_ext
crl_extensions   = crl_ext

[ policy_hemlig ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ intermediate_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ req ]
prompt             = no
default_md         = sha384
string_mask        = utf8only
distinguished_name = root_dn
x509_extensions    = root_ext

[ root_dn ]
O  = Example Corp
CN = Example Offline Root CA 1

[ root_ext ]
basicConstraints     = critical, CA:true
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
`;
