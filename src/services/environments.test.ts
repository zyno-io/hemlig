import type { DynamoRepository } from '../repositories/dynamo';
import { EnvironmentService } from './environments';

describe('EnvironmentService', () => {
    it('validates and persists an administrator-defined environment', async () => {
        const repository = {
            createEnvironment: jest.fn(async () => undefined),
        } as unknown as DynamoRepository;
        const service = new EnvironmentService(repository);

        const environment = await service.create({
            name: 'staging',
            actor: { type: 'human', id: 'admin-1' },
        });

        expect(environment).toMatchObject({
            pk: 'SYSTEM#ENVIRONMENTS',
            sk: 'ENVIRONMENT#staging',
            name: 'staging',
            createdBy: { type: 'human', id: 'admin-1' },
        });
        expect(repository.createEnvironment).toHaveBeenCalledWith(environment);
    });

    it('rejects an invalid environment name before accessing storage', async () => {
        const repository = {
            createEnvironment: jest.fn(async () => undefined),
        } as unknown as DynamoRepository;
        const service = new EnvironmentService(repository);

        await expect(service.create({
            name: 'Staging',
            actor: { type: 'human', id: 'admin-1' },
        })).rejects.toMatchObject({ code: 'bad_request' });
        expect(repository.createEnvironment).not.toHaveBeenCalled();
    });
});
