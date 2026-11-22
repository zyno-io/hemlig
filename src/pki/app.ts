import { createPkiAwsClients, type PkiAwsClients } from "../aws/pki-clients";
import type { PkiConfig } from "../aws/config";
import { DynamoCursorStore } from "../repositories/cursor-store";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { PkiRepository } from "../repositories/pki";
import type { AuditingApplication } from "../handlers/request";
import { AuditWriter } from "../services/audit";
import { CursorService } from "../services/cursor";
import { CaService } from "./ca-service";
import { CapacityService } from "./capacity-service";
import { CertificateService } from "./certificate-service";
import { CrlService } from "./crl-service";
import { caKeyUnavailable } from "./errors";
import { ExternalCaService } from "./external-ca-service";
import { GrantService } from "./grant-service";
import { IssuanceService } from "./issuance-service";
import { WrappedCaSigner, type CaSigner } from "./signer";
import type { CaRecord } from "./types";

/**
 * The PKI Lambdas' application: DynamoDB, KMS and S3 only. It never builds IssuerService, ConsumerService,
 * SecretService or the IoT and API Gateway clients.
 */
export interface PkiApplication extends AuditingApplication {
  readonly config: PkiConfig;
  readonly clients: PkiAwsClients;
  /** Reads its roles allow (IDENTITY#, CONSUMER#, AGENT_GRANT#, SYSTEM#ISSUER/ENVIRONMENTS) plus AUDIT_SUPPRESS# and IDEMPOTENCY#human# writes; anything else is AccessDenied by design. */
  readonly repository: DynamoRepository;
  readonly pki: PkiRepository;
  readonly objects: ObjectStore;
  readonly audit: AuditWriter;
  readonly cursors: CursorService;
  readonly signerFor: (
    ca: Pick<CaRecord, "caId" | "environment" | "key">,
  ) => CaSigner;
  /** The clock every PKI service reads; tests inject their own. */
  readonly now: () => Date;
  readonly cas: CaService;
  readonly crls: CrlService;
  readonly externalCas: ExternalCaService;
  readonly grants: GrantService;
  readonly issuance: IssuanceService;
  readonly certificates: CertificateService;
  readonly capacity: CapacityService;
}

export const createPkiApplication = (
  config: PkiConfig,
  options: { now?: () => Date } = {},
): PkiApplication => {
  const clients = createPkiAwsClients(config);
  const objects = new ObjectStore(clients.s3);
  const now = options.now ?? (() => new Date());
  const repository = new DynamoRepository(clients.dynamo, config);
  const pki = new PkiRepository(clients.dynamo, {
    tableName: config.controlTableName,
    directoryIndex: config.pkiDirectoryIndex,
  });
  const cursors = new CursorService(
    new DynamoCursorStore(
      clients.dynamo,
      config.controlTableName,
      "PKI_CURSOR#",
    ),
  );
  const signerFor: PkiApplication["signerFor"] = ({
    caId,
    environment,
    key,
  }) => {
    if (key.state !== "ACTIVE" || key.wrapped === undefined) {
      throw caKeyUnavailable();
    }
    return new WrappedCaSigner({
      kms: clients.kms,
      kmsKeyId: config.payloadKmsKeyArn,
      caId,
      environment,
      algorithm: key.algorithm,
      wrapped: key.wrapped,
    });
  };
  const deps = {
    pki,
    repository,
    objects,
    signerFor,
    kms: clients.kms,
    cursors,
    config,
    now,
  };
  const crls = new CrlService(deps);
  const capacity = new CapacityService(pki);
  return {
    config,
    clients,
    repository,
    pki,
    objects,
    audit: new AuditWriter(objects, config),
    cursors,
    signerFor,
    now,
    cas: new CaService(deps, crls),
    crls,
    externalCas: new ExternalCaService(deps),
    grants: new GrantService(deps),
    issuance: new IssuanceService(deps, capacity),
    certificates: new CertificateService(deps, crls),
    capacity,
  };
};
