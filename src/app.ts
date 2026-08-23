import type { AppConfig } from './aws/config';
import { createAwsClients, type AwsClients } from './aws/clients';
import { EnvelopeCrypto } from './crypto/envelope';
import { DynamoRepository } from './repositories/dynamo';
import { ObjectStore } from './repositories/object-store';
import { AuditWriter } from './services/audit';
import { ConsumerService } from './services/consumers';
import { CursorCodec } from './services/cursor';
import { IssuerService } from './services/issuer';
import { SecretService } from './services/secrets';

export interface Application {
    readonly config: AppConfig;
    readonly repository: DynamoRepository;
    readonly objects: ObjectStore;
    readonly audit: AuditWriter;
    readonly cursors: CursorCodec;
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
    return {
        config,
        repository,
        objects,
        audit: new AuditWriter(objects, config),
        cursors: new CursorCodec(config.cursorHmacKey),
        secrets: new SecretService(repository, objects, crypto, config),
        consumers: new ConsumerService(repository, objects, clients.apiGateway, issuer, config),
        clients,
    };
};
