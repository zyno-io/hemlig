import type { Actor, EnvironmentRecord } from '../domain/types';
import { assertEnvironmentName } from '../domain/validation';
import type { DynamoRepository } from '../repositories/dynamo';
import { isoNow } from '../util/encoding';

export interface CreateEnvironmentInput {
    readonly name: string;
    readonly actor: Actor;
}

export class EnvironmentService {
    public constructor(private readonly repository: DynamoRepository) {}

    public async list(): Promise<readonly EnvironmentRecord[]> {
        return this.repository.listEnvironments();
    }

    public async require(name: string): Promise<EnvironmentRecord> {
        assertEnvironmentName(name);
        return this.repository.requireEnvironment(name);
    }

    public async create(input: CreateEnvironmentInput): Promise<EnvironmentRecord> {
        assertEnvironmentName(input.name);
        const environment: EnvironmentRecord = {
            pk: 'SYSTEM#ENVIRONMENTS',
            sk: `ENVIRONMENT#${input.name}`,
            name: input.name,
            createdAt: isoNow(),
            createdBy: input.actor,
        };
        await this.repository.createEnvironment(environment);
        return environment;
    }
}
