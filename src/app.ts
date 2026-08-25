import type { AppConfig } from "./aws/config";
import { createAwsClients, type AwsClients } from "./aws/clients";
import { EnvelopeCrypto } from "./crypto/envelope";
import { DynamoRepository } from "./repositories/dynamo";
import { ObjectStore } from "./repositories/object-store";
import { AuditQueryService, AuditWriter } from "./services/audit";
import { AgentGrantService } from "./services/agent-grants";
import { AgentNotificationService } from "./services/agent-notifications";
import { AgentService } from "./services/agents";
import { ConsumerService } from "./services/consumers";
import { CursorService } from "./services/cursor";
import { EnvironmentService } from "./services/environments";
import { IssuerService } from "./services/issuer";
import { SecretService } from "./services/secrets";

export interface Application {
  readonly config: AppConfig;
  readonly repository: DynamoRepository;
  readonly objects: ObjectStore;
  readonly audit: AuditWriter;
  readonly auditQueries: AuditQueryService;
  readonly agentGrants: AgentGrantService;
  readonly agents: AgentService;
  readonly cursors: CursorService;
  readonly environments: EnvironmentService;
  readonly secrets: SecretService;
  readonly consumers: ConsumerService;
  readonly clients: AwsClients;
}

export const createApplication = (config: AppConfig): Application => {
  const clients = createAwsClients(config);
  const repository = new DynamoRepository(clients.dynamo, config);
  const objects = new ObjectStore(clients.s3);
  const crypto = new EnvelopeCrypto(clients.kms, config);
  const issuer = new IssuerService(repository, clients.kms, config);
  const environments = new EnvironmentService(repository);
  const secrets = new SecretService(
    repository,
    objects,
    crypto,
    config,
    environments,
  );
  const consumers = new ConsumerService(
    repository,
    objects,
    clients.apiGateway,
    issuer,
    config,
    environments,
  );
  const agentNotifications = new AgentNotificationService(
    clients.iot,
    config.iotNotificationPolicyName,
  );
  return {
    config,
    repository,
    objects,
    audit: new AuditWriter(objects, config),
    auditQueries: new AuditQueryService(objects, config),
    cursors: new CursorService(repository),
    environments,
    secrets,
    consumers,
    agents: new AgentService(repository, secrets),
    agentGrants: new AgentGrantService(
      repository,
      consumers,
      environments,
      agentNotifications,
      secrets,
    ),
    clients,
  };
};
