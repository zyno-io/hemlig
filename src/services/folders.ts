import { conflict, notFound } from '../domain/errors';
import type { Actor, FolderRecord } from '../domain/types';
import { assertFolderPath } from '../domain/validation';
import type { DynamoRepository } from '../repositories/dynamo';
import { isoNow } from '../util/encoding';
import type { EnvironmentService } from './environments';

export interface CreateFolderInput {
    readonly environment: string;
    readonly path: unknown;
    readonly actor: Actor;
}

export interface DeleteFolderInput {
    readonly environment: string;
    readonly path: unknown;
}

/**
 * A folder is otherwise only a path prefix derived from the secrets that
 * happen to live under it: an empty one cannot exist, so laying out an
 * organizational structure before filling it is impossible. FolderService
 * closes that gap with a bounded registry of administrator-defined records,
 * modeled directly on EnvironmentService/EnvironmentRecord.
 */
export class FolderService {
    public constructor(
        private readonly repository: DynamoRepository,
        private readonly environments: EnvironmentService,
    ) {}

    public async create(input: CreateFolderInput): Promise<FolderRecord> {
        await this.environments.require(input.environment);
        const path = assertFolderPath(input.path);
        // Only the exact path named is ever stored. Creating "a/b/c" must not
        // also materialise "a" and "a/b": GET /v1/admin/secrets/tree already
        // derives every intermediate segment from the paths it observes (both
        // secret paths and folder-record paths), so a second, explicit record
        // for the same intermediate folder would be a second source of truth
        // for it that could drift from the derived one.
        const folder: FolderRecord = {
            pk: `FOLDER#${input.environment}`,
            sk: `PATH#${path}`,
            environment: input.environment,
            path,
            createdAt: isoNow(),
            createdBy: input.actor,
        };
        await this.repository.createFolder(folder);
        return folder;
    }

    public async remove(input: DeleteFolderInput): Promise<void> {
        await this.environments.require(input.environment);
        const path = assertFolderPath(input.path);
        const folder = await this.repository.getFolder(input.environment, path);
        if (folder === undefined) {
            // Distinct from a generic 404: the path may still be visible in
            // the tree as a derived folder (implied by a secret's
            // metadata.path). There is simply no record here to delete, so
            // silently succeeding would be misleading about what changed.
            throw notFound(
                'No folder record exists at this path. It may still appear in the tree because folders are also derived from secret paths; there is nothing to delete.',
            );
        }
        const occupied = await this.repository.hasSecretsAtOrBeneathPath(input.environment, path);
        if (occupied) {
            // Deleting the record here would not remove the folder from the
            // tree: it would still be derived from the secret occupying it.
            // Refusing, rather than silently succeeding, keeps the operator
            // from being confused about why the folder reappears.
            throw conflict(
                'The folder is not empty: a secret exists at this path or nested beneath it. Deleting the record would not remove the folder from the tree, since it would still be derived from that secret.',
            );
        }
        await this.repository.deleteFolder(input.environment, path);
    }
}
