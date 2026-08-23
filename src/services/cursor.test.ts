import { CursorCodec } from './cursor';

describe('CursorCodec', () => {
    it('binds cursors to the intended cluster', () => {
        const codec = new CursorCodec(Buffer.alloc(32, 4));
        const cursor = codec.encode({
            clusterId: 'cluster-one',
            lastEvaluatedKey: { pk: 'CLUSTER#cluster-one', sk: 'SECRET#sec-one' },
            expiresAt: '2030-01-01T00:00:00.000Z',
        });
        const decoded = codec.decode(cursor, 'cluster-one', new Date('2029-01-01T00:00:00.000Z'));
        expect(decoded.lastEvaluatedKey).toEqual({ pk: 'CLUSTER#cluster-one', sk: 'SECRET#sec-one' });
        expect(() => codec.decode(cursor, 'cluster-two', new Date('2029-01-01T00:00:00.000Z'))).toThrow('cursor');
    });

    it('rejects tampering and expiry', () => {
        const codec = new CursorCodec(Buffer.alloc(32, 5));
        const cursor = codec.encode({ clusterId: 'cluster-one', expiresAt: '2026-01-01T00:00:00.000Z' });
        expect(() => codec.decode(`${cursor}x`, 'cluster-one', new Date('2025-01-01T00:00:00.000Z'))).toThrow('cursor');
        expect(() => codec.decode(cursor, 'cluster-one', new Date('2027-01-01T00:00:00.000Z'))).toThrow('cursor');
    });
});
