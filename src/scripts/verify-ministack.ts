import { CreateTableCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { CreateKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import {
    CreateBucketCommand,
    DeleteObjectCommand,
    PutObjectCommand,
    PutObjectLockConfigurationCommand,
    S3Client,
} from '@aws-sdk/client-s3';
import { DynamoDBDocumentClient, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import { EnvelopeCrypto } from '../crypto/envelope';
import type { AppConfig } from '../aws/config';
import { ObjectStore } from '../repositories/object-store';
import { DynamoRepository } from '../repositories/dynamo';
import { stableJson } from '../util/encoding';

const endpoint = process.env.AWS_ENDPOINT_URL ?? 'http://localhost:4566';
const region = process.env.AWS_REGION ?? 'us-east-1';
const credentials = { accessKeyId: 'test', secretAccessKey: 'test' };
const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
const bucket = `secrets-manager-${suffix}`;
const table = `secrets-manager-${suffix}`;

const run = async (): Promise<void> => {
    const s3 = new S3Client({ endpoint, region, credentials, forcePathStyle: true });
    const kms = new KMSClient({ endpoint, region, credentials });
    const dynamo = new DynamoDBClient({ endpoint, region, credentials });
    const document = DynamoDBDocumentClient.from(dynamo);
    const createBucket = new CreateBucketCommand({ Bucket: bucket, ObjectLockEnabledForBucket: true });
    await s3.send(createBucket);
    const lock = new PutObjectLockConfigurationCommand({
        Bucket: bucket,
        ObjectLockConfiguration: {
            ObjectLockEnabled: 'Enabled',
            Rule: { DefaultRetention: { Mode: 'COMPLIANCE', Days: 1 } },
        },
    });
    await s3.send(lock);
    const keyResponse = await kms.send(new CreateKeyCommand({ Description: 'MiniStack test key' }));
    const keyId = keyResponse.KeyMetadata?.Arn;
    if (keyId === undefined) {
        throw new Error('MiniStack KMS did not return a key ARN.');
    }
    const createTable = new CreateTableCommand({
        TableName: table,
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
            { AttributeName: 'pk', AttributeType: 'S' },
            { AttributeName: 'sk', AttributeType: 'S' },
            { AttributeName: 'catalogPk', AttributeType: 'S' },
            { AttributeName: 'catalogSk', AttributeType: 'S' },
            { AttributeName: 'consumerDirectoryPk', AttributeType: 'S' },
            { AttributeName: 'consumerDirectorySk', AttributeType: 'S' },
            { AttributeName: 'identityConsumerPk', AttributeType: 'S' },
            { AttributeName: 'identityConsumerSk', AttributeType: 'S' },
            { AttributeName: 'revisionPk', AttributeType: 'S' },
            { AttributeName: 'revisionSk', AttributeType: 'S' },
        ],
        KeySchema: [
            { AttributeName: 'pk', KeyType: 'HASH' },
            { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
        GlobalSecondaryIndexes: [
            {
                IndexName: 'catalog-path',
                KeySchema: [
                    { AttributeName: 'catalogPk', KeyType: 'HASH' },
                    { AttributeName: 'catalogSk', KeyType: 'RANGE' },
                ],
                Projection: { ProjectionType: 'ALL' },
            },
            {
                IndexName: 'consumer-directory',
                KeySchema: [
                    { AttributeName: 'consumerDirectoryPk', KeyType: 'HASH' },
                    { AttributeName: 'consumerDirectorySk', KeyType: 'RANGE' },
                ],
                Projection: { ProjectionType: 'ALL' },
            },
            {
                IndexName: 'consumer-identity',
                KeySchema: [
                    { AttributeName: 'identityConsumerPk', KeyType: 'HASH' },
                    { AttributeName: 'identityConsumerSk', KeyType: 'RANGE' },
                ],
                Projection: { ProjectionType: 'ALL' },
            },
            {
                IndexName: 'secret-revision',
                KeySchema: [
                    { AttributeName: 'revisionPk', KeyType: 'HASH' },
                    { AttributeName: 'revisionSk', KeyType: 'RANGE' },
                ],
                Projection: { ProjectionType: 'ALL' },
            },
        ],
    });
    await dynamo.send(createTable);
    const config = testConfig(keyId);
    const crypto = new EnvelopeCrypto(kms, config);
    const revision = await crypto.encrypt(
        { API_TOKEN: { encoding: 'utf8', value: 'not-logged' } },
        { environment: 'local', secretId: 'sec-local', payloadVersionId: 'pay-local' },
        { type: 'system', id: 'ministack-verify' },
        '2026-08-22T00:00:00.000Z',
    );
    const objects = new ObjectStore(s3);
    const bytes = Buffer.from(stableJson(revision), 'utf8');
    const object = await objects.putImmutable(bucket, 'secrets/sec-local/payload/pay-local.json', bytes);
    const existingObject = await objects.putImmutableOrGet(bucket, object.key, bytes);
    if (existingObject.versionId !== object.versionId) {
        throw new Error('Immutable object retry did not return the existing version.');
    }
    const stored = await objects.getJson<typeof revision>(bucket, object.key, object.versionId);
    const decrypted = await crypto.decrypt(stored);
    if (decrypted.API_TOKEN?.value !== 'not-logged') {
        throw new Error('Envelope decryption did not preserve the payload.');
    }
    const transaction = new TransactWriteCommand({
        TransactItems: [{
            Put: {
                TableName: table,
                Item: {
                    pk: 'SECRET#sec-local',
                    sk: 'HEAD',
                    secretId: 'sec-local',
                    environment: 'local',
                    controlVersionId: 'ctl-local',
                    state: 'ACTIVE',
                    workflowState: 'READY',
                    metadata: { description: 'Local MiniStack secret', path: 'testing/ministack', tags: { owner: 'platform' } },
                    catalogPk: 'CATALOG#local',
                    catalogSk: 'PATH#testing/ministack/SECRET#sec-local',
                    catalogTags: { owner: 'platform' },
                },
                ConditionExpression: 'attribute_not_exists(pk)',
            },
        }, {
            Put: {
                TableName: table,
                Item: {
                    pk: 'CONSUMER#local-east',
                    sk: 'PROFILE',
                    consumerId: 'local-east',
                    environment: 'local',
                    subjectUri: 'spiffe://hemlig/consumer/local-east',
                    status: 'ACTIVE',
                    createdAt: '2026-08-22T00:00:00.000Z',
                    createdBy: { type: 'human', id: 'ministack-verify' },
                    consumerDirectoryPk: 'CONSUMERS#local',
                    consumerDirectorySk: 'local-east',
                },
            },
        }, {
            Put: {
                TableName: table,
                Item: {
                    pk: 'IDENTITY#local-fingerprint',
                    sk: 'PROFILE',
                    fingerprint: 'local-fingerprint',
                    consumerId: 'local-east',
                    environment: 'local',
                    kind: 'api',
                    status: 'ACTIVE',
                    notBefore: '2026-08-22T00:00:00.000Z',
                    notAfter: '2027-08-22T00:00:00.000Z',
                    identityConsumerPk: 'CONSUMER#local-east',
                    identityConsumerSk: '2027-08-22T00:00:00.000Z#local-fingerprint',
                },
            },
        }, {
            Put: {
                TableName: table,
                Item: {
                    pk: 'SECRET#sec-local',
                    sk: 'CONTROL#ctl-local',
                    workflowState: 'READY',
                    revisionPk: 'SECRET#sec-local',
                    revisionSk: '2026-08-22T00:00:00.000Z#ctl-local',
                    serialized: {
                        schemaVersion: 1,
                        secretId: 'sec-local',
                        controlVersionId: 'ctl-local',
                        payloadKeyCount: 1,
                        environment: 'local',
                        state: 'ACTIVE',
                        createdAt: '2026-08-22T00:00:00.000Z',
                        createdBy: { type: 'system', id: 'ministack-verify' },
                        metadata: { description: 'Local MiniStack secret' },
                        acl: [],
                    },
                },
            },
        }],
    });
    await document.send(transaction);
    const repository = new DynamoRepository(document, config);
    const catalog = await repository.listSecrets('local', 'testing', { owner: 'platform' });
    if (catalog.secrets.length !== 1 || catalog.secrets[0]?.secretId !== 'sec-local') {
        throw new Error('Catalog path/tag query did not return the expected secret.');
    }
    const consumers = await repository.listConsumers('local');
    if (consumers.consumers[0]?.consumerId !== 'local-east') {
        throw new Error('Consumer directory index did not return the expected consumer.');
    }
    const identities = await repository.listConsumerApiIdentities('local-east');
    if (identities.identities[0]?.fingerprint !== 'local-fingerprint') {
        throw new Error('Consumer identity index did not return the expected API leaf.');
    }
    const revisions = await repository.listRecentControlRevisions('sec-local');
    if (revisions.revisions[0]?.serialized.controlVersionId !== 'ctl-local') {
        throw new Error('Secret revision index did not return the expected control revision.');
    }
    let deleteDenied = false;
    try {
        const deleteObject = new DeleteObjectCommand({ Bucket: bucket, Key: object.key, VersionId: object.versionId });
        await s3.send(deleteObject);
    } catch {
        deleteDenied = true;
    }
    if (!deleteDenied) {
        throw new Error('MiniStack allowed deletion of a Compliance-retained object.');
    }
    process.stdout.write(`MiniStack verification passed for ${bucket}.\n`);
};

const testConfig = (payloadKmsKeyArn: string): AppConfig => ({
    region,
    environmentName: 'ministack',
    controlTableName: table,
    workflowDueIndex: 'workflow-due',
    retentionDueIndex: 'retention-due',
    catalogPathIndex: 'catalog-path',
    consumerDirectoryIndex: 'consumer-directory',
    consumerIdentityIndex: 'consumer-identity',
    secretRevisionIndex: 'secret-revision',
    revisionBucketName: bucket,
    truststoreBucketName: bucket,
    truststoreKeyPrefix: 'truststores',
    payloadKmsKeyArn,
    auditBucketName: bucket,
    auditPrefix: 'audit',
    deliveryApiCustomDomainName: 'api.local.test',
    deliveryApiHostname: 'api.local.test',
    iotEndpoint: 'localhost',
    iotNotificationPolicyName: 'ministack-notifications',
    iotNotificationTopicPrefix: 'hemlig/ministack/consumers',
    cursorHmacKey: Buffer.alloc(32, 1),
    adminJwtIssuer: 'https://issuer.local.test',
    adminJwtAudience: 'local-audience',
    adminActorSubjectClaim: 'sub',
    maxPayloadBytes: 768000,
    awsEndpointUrl: endpoint,
});

void run();
