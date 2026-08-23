import { createHmac, timingSafeEqual } from 'node:crypto';
import { badRequest } from '../domain/errors';
import { stableJson } from '../util/encoding';

interface CursorPayload {
    readonly clusterId: string;
    readonly lastEvaluatedKey?: Record<string, string>;
    readonly expiresAt: string;
}

export class CursorCodec {
    public constructor(private readonly key: Buffer) {}

    public encode(payload: CursorPayload): string {
        const encoded = Buffer.from(stableJson(payload), 'utf8').toString('base64url');
        const signature = this.signature(encoded);
        return `${encoded}.${signature}`;
    }

    public decode(cursor: string, clusterId: string, now: Date = new Date()): CursorPayload {
        const [encoded, signature, extra] = cursor.split('.');
        if (encoded === undefined || signature === undefined || extra !== undefined) {
            throw badRequest('cursor is malformed.');
        }
        const expected = this.signature(encoded);
        const givenBytes = Buffer.from(signature, 'base64url');
        const expectedBytes = Buffer.from(expected, 'base64url');
        if (givenBytes.length !== expectedBytes.length || !timingSafeEqual(givenBytes, expectedBytes)) {
            throw badRequest('cursor signature is invalid.');
        }
        let parsed: CursorPayload;
        try {
            parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as CursorPayload;
        } catch {
            throw badRequest('cursor payload is invalid.');
        }
        if (parsed.clusterId !== clusterId || new Date(parsed.expiresAt).getTime() <= now.getTime()) {
            throw badRequest('cursor is no longer valid for this cluster.');
        }
        return parsed;
    }

    private signature(encoded: string): string {
        return createHmac('sha256', this.key).update(encoded).digest('base64url');
    }
}
