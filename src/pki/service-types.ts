import type { PkiConfig } from "../aws/config";
import type { DynamoRepository } from "../repositories/dynamo";
import type { ObjectStore } from "../repositories/object-store";
import type { PkiRepository } from "../repositories/pki";
import type { CursorService } from "../services/cursor";
import type { emitPkiMetrics } from "./metrics";
import type { PkiApplication } from "./app";
import type { PkiKmsClient } from "./wrapped-keys";

/** What the PKI services need from the application. Services never reach beyond this. */
export interface PkiServiceDeps {
  readonly pki: PkiRepository;
  readonly repository: Pick<
    DynamoRepository,
    | "getIdempotency"
    | "getIssuer"
    | "requireEnvironment"
    | "getIdentity"
    | "getConsumer"
    | "getAgentGrant"
    | "getAgentGrantIdForConsumer"
  >;
  readonly objects: Pick<ObjectStore, "putImmutableOrGet" | "getBytes">;
  readonly signerFor: PkiApplication["signerFor"];
  readonly kms: PkiKmsClient;
  readonly cursors: Pick<CursorService, "encode" | "decode">;
  readonly config: Pick<
    PkiConfig,
    "pkiBucketName" | "payloadKmsKeyArn" | "environmentName"
  >;
  readonly now: () => Date;
  readonly emit?: typeof emitPkiMetrics;
}

/** A mutation's outcome; the handler turns it into a response and, when needed, a terminal audit event. */
export interface MutationResult {
  readonly body: Record<string, unknown>;
  readonly status: number;
  readonly shouldWriteTerminalAudit: boolean;
  readonly auditTarget: Record<string, string>;
  readonly etag?: string;
}
