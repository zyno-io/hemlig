import type { AppConfig } from '../aws/config';
import type { Actor } from '../domain/types';
import { isoNow, newId, stableJson } from '../util/encoding';
import type { ObjectStore } from '../repositories/object-store';

export type AuditOutcome = 'attempted' | 'authorized' | 'succeeded' | 'failed';

export interface AuditEvent {
    readonly eventId: string;
    readonly at: string;
    readonly correlationId: string;
    readonly outcome: AuditOutcome;
    readonly actor: Actor;
    readonly operation: string;
    readonly target?: Readonly<Record<string, string>>;
    readonly permission?: 'read';
    readonly sourceIp?: string;
    readonly reasonCode?: string;
}

export class AuditWriter {
    public constructor(
        private readonly objectStore: ObjectStore,
        private readonly config: AppConfig,
    ) {}

    public async write(event: Omit<AuditEvent, 'eventId' | 'at'> & Partial<Pick<AuditEvent, 'eventId' | 'at'>>): Promise<AuditEvent> {
        const completed: AuditEvent = {
            ...event,
            eventId: event.eventId ?? newId(),
            at: event.at ?? isoNow(),
        };
        const date = completed.at.slice(0, 10).replaceAll('-', '/');
        const prefix = this.config.auditPrefix.replace(/\/$/, '');
        const key = `${prefix}/${date}/${completed.eventId}.json`;
        const body = Buffer.from(stableJson(completed), 'utf8');
        await this.objectStore.putImmutable(this.config.auditBucketName, key, body);
        return completed;
    }
}
