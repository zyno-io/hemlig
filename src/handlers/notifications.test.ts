import { PublishCommand } from '@aws-sdk/client-iot-data-plane';
import { marshall } from '@aws-sdk/util-dynamodb';
import type { DynamoDBStreamEvent } from 'aws-lambda';

const mockSend = jest.fn();
const mockMarkDelivered = jest.fn(async () => true);

jest.mock('@aws-sdk/client-iot-data-plane', () => ({
    IoTDataPlaneClient: jest.fn(() => ({ send: mockSend })),
    PublishCommand: jest.requireActual('@aws-sdk/client-iot-data-plane').PublishCommand,
}));
jest.mock('../aws/config', () => ({
    loadConfig: jest.fn(() => ({
        region: 'us-east-1',
        iotEndpoint: 'iot.example.test',
        iotNotificationTopicPrefix: 'hemlig/test/consumers',
    })),
}));
jest.mock('../app', () => ({
    createApplication: jest.fn(() => ({
        repository: { markNotificationDelivered: mockMarkDelivered },
    })),
}));

import { handler } from './notifications';

describe('notification publisher', () => {
    beforeEach(() => {
        mockSend.mockReset();
        mockSend.mockResolvedValue({});
        mockMarkDelivered.mockClear();
    });

    it('fans one grouped secret-change event out in the background', async () => {
        const event = {
            Records: [{
                eventName: 'INSERT',
                dynamodb: {
                    NewImage: marshall({
                        pk: 'NOTIFICATION#event-1',
                        sk: 'EVENT',
                        eventId: 'event-1',
                        consumerIds: ['prod-east', 'prod-west'],
                        secretId: 'payments-api',
                        controlVersionId: 'ctl-next',
                        payloadVersionId: 'pay-next',
                        kind: 'secret.changed',
                        createdAt: '2026-08-23T00:00:00.000Z',
                        status: 'PENDING',
                    }),
                },
            }],
        } as unknown as DynamoDBStreamEvent;

        await handler(event);

        expect(mockSend).toHaveBeenCalledTimes(2);
        const published = mockSend.mock.calls.map(([command]) =>
            (command as PublishCommand).input,
        );
        expect(published.map((input) => input.topic)).toEqual([
            'hemlig/test/consumers/prod-east',
            'hemlig/test/consumers/prod-west',
        ]);
        expect(JSON.parse(Buffer.from(published[0]?.payload as Uint8Array).toString('utf8'))).toEqual({
            schemaVersion: 1,
            kind: 'secret.changed',
            secretId: 'payments-api',
            controlVersionId: 'ctl-next',
            payloadVersionId: 'pay-next',
        });
        expect(mockMarkDelivered).toHaveBeenCalledWith('event-1');
    });

    it('delivers a pending notification when migration backfills its environment', async () => {
        const event = {
            Records: [{
                eventName: 'MODIFY',
                dynamodb: {
                    NewImage: marshall({
                        pk: 'NOTIFICATION#event-2',
                        sk: 'EVENT',
                        eventId: 'event-2',
                        consumerIds: ['staging-east'],
                        secretId: 'payments-api',
                        environment: 'staging',
                        controlVersionId: 'ctl-next',
                        kind: 'secret.changed',
                        createdAt: '2026-08-25T00:00:00.000Z',
                        status: 'PENDING',
                    }),
                },
            }],
        } as unknown as DynamoDBStreamEvent;

        await handler(event);

        const command = mockSend.mock.calls[0]?.[0] as PublishCommand;
        expect(JSON.parse(Buffer.from(command.input.payload as Uint8Array).toString('utf8'))).toEqual({
            schemaVersion: 1,
            kind: 'secret.changed',
            secretId: 'payments-api',
            environment: 'staging',
            controlVersionId: 'ctl-next',
        });
        expect(mockMarkDelivered).toHaveBeenCalledWith('event-2');
    });
});
