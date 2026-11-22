import { createPkiAwsClients, type PkiAwsClients } from "../aws/pki-clients";
import type { PkiConfig } from "../aws/config";
import { DynamoCursorStore } from "../repositories/cursor-store";
import { DynamoRepository } from "../repositories/dynamo";
import { ObjectStore } from "../repositories/object-store";
import { PkiRepository } from "../repositories/pki";
import type { AuditingApplication } from "../handlers/request";
import { AuditWriter } from "../services/audit";
import { CursorService } from "../services/cursor";
import { caKeyUnavailable } from "./errors";
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
}

export const createPkiApplication = (config: PkiConfig): PkiApplication => {
  const clients = createPkiAwsClients(config);
  const objects = new ObjectStore(clients.s3);
  return {
    config,
    clients,
    repository: new DynamoRepository(clients.dynamo, config),
    pki: new PkiRepository(clients.dynamo, {
      tableName: config.controlTableName,
      directoryIndex: config.pkiDirectoryIndex,
    }),
    objects,
    audit: new AuditWriter(objects, config),
    cursors: new CursorService(
      new DynamoCursorStore(
        clients.dynamo,
        config.controlTableName,
        "PKI_CURSOR#",
      ),
    ),
    signerFor: ({ caId, environment, key }) => {
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
    },
  };
};
