import { notFound } from '../domain/errors';
import type { DynamoRepository } from '../repositories/dynamo';
import type { EnvironmentService } from './environments';
import { FolderService } from './folders';

describe('FolderService', () => {
    describe('create', () => {
        it('validates the environment and path, then persists an administrator-defined folder', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = { createFolder: jest.fn(async () => undefined) } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            const folder = await service.create({
                environment: 'prod',
                path: 'payments/adyen',
                actor: { type: 'human', id: 'admin-1' },
            });

            expect(environments.require).toHaveBeenCalledWith('prod');
            expect(folder).toMatchObject({
                pk: 'FOLDER#prod',
                sk: 'PATH#payments/adyen',
                environment: 'prod',
                path: 'payments/adyen',
                createdBy: { type: 'human', id: 'admin-1' },
            });
            expect(repository.createFolder).toHaveBeenCalledWith(folder);
        });

        it('rejects an unknown environment before creating a record', async () => {
            const environments = {
                require: jest.fn(async () => { throw notFound('The requested environment is not configured.'); }),
            } as unknown as EnvironmentService;
            const repository = { createFolder: jest.fn(async () => undefined) } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.create({
                environment: 'missing',
                path: 'payments',
                actor: { type: 'human', id: 'admin-1' },
            })).rejects.toMatchObject({ code: 'not_found' });
            expect(repository.createFolder).not.toHaveBeenCalled();
        });

        it('rejects an invalid path before creating a record', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = { createFolder: jest.fn(async () => undefined) } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.create({
                environment: 'prod',
                path: 'Payments',
                actor: { type: 'human', id: 'admin-1' },
            })).rejects.toMatchObject({ code: 'bad_request' });
            expect(repository.createFolder).not.toHaveBeenCalled();
        });

        it('propagates the repository conflict for a duplicate path or a full registry', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = {
                createFolder: jest.fn(async () => { throw { code: 'conflict' }; }),
            } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.create({
                environment: 'prod',
                path: 'payments',
                actor: { type: 'human', id: 'admin-1' },
            })).rejects.toMatchObject({ code: 'conflict' });
        });
    });

    describe('remove', () => {
        it('deletes an empty folder record', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = {
                getFolder: jest.fn(async () => ({
                    pk: 'FOLDER#prod',
                    sk: 'PATH#payments',
                    environment: 'prod',
                    path: 'payments',
                    createdAt: '2026-08-23T00:00:00.000Z',
                    createdBy: { type: 'human', id: 'admin-1' },
                })),
                hasSecretsAtOrBeneathPath: jest.fn(async () => false),
                deleteFolder: jest.fn(async () => undefined),
            } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await service.remove({ environment: 'prod', path: 'payments' });

            expect(repository.deleteFolder).toHaveBeenCalledWith('prod', 'payments');
        });

        it('refuses to delete a path that is only derived, reporting it is not a record', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = {
                getFolder: jest.fn(async () => undefined),
                hasSecretsAtOrBeneathPath: jest.fn(async () => true),
                deleteFolder: jest.fn(async () => undefined),
            } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.remove({ environment: 'prod', path: 'payments' }))
                .rejects.toMatchObject({ code: 'not_found' });
            expect(repository.hasSecretsAtOrBeneathPath).not.toHaveBeenCalled();
            expect(repository.deleteFolder).not.toHaveBeenCalled();
        });

        it('refuses to delete a non-empty folder as a conflict naming the occupancy', async () => {
            const environments = { require: jest.fn(async () => undefined) } as unknown as EnvironmentService;
            const repository = {
                getFolder: jest.fn(async () => ({
                    pk: 'FOLDER#prod',
                    sk: 'PATH#payments',
                    environment: 'prod',
                    path: 'payments',
                    createdAt: '2026-08-23T00:00:00.000Z',
                    createdBy: { type: 'human', id: 'admin-1' },
                })),
                hasSecretsAtOrBeneathPath: jest.fn(async () => true),
                deleteFolder: jest.fn(async () => undefined),
            } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.remove({ environment: 'prod', path: 'payments' }))
                .rejects.toMatchObject({ code: 'conflict' });
            expect(repository.deleteFolder).not.toHaveBeenCalled();
        });

        it('rejects an unknown environment before looking up anything else', async () => {
            const environments = {
                require: jest.fn(async () => { throw notFound('The requested environment is not configured.'); }),
            } as unknown as EnvironmentService;
            const repository = {
                getFolder: jest.fn(async () => undefined),
                hasSecretsAtOrBeneathPath: jest.fn(async () => false),
                deleteFolder: jest.fn(async () => undefined),
            } as unknown as DynamoRepository;
            const service = new FolderService(repository, environments);

            await expect(service.remove({ environment: 'missing', path: 'payments' }))
                .rejects.toMatchObject({ code: 'not_found' });
            expect(repository.getFolder).not.toHaveBeenCalled();
        });
    });
});
