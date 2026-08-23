import { ApiGatewayV2Client } from '@aws-sdk/client-apigatewayv2';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type { AppConfig } from './config';

export interface AwsClients {
    readonly dynamo: DynamoDBDocumentClient;
    readonly kms: KMSClient;
    readonly s3: S3Client;
    readonly apiGateway: ApiGatewayV2Client;
}

export const createAwsClients = (config: AppConfig): AwsClients => {
    const common = config.awsEndpointUrl === undefined
        ? { region: config.region }
        : { region: config.region, endpoint: config.awsEndpointUrl, forcePathStyle: true };
    const dynamoClient = new DynamoDBClient(common);
    return {
        dynamo: DynamoDBDocumentClient.from(dynamoClient, {
            marshallOptions: { removeUndefinedValues: true },
        }),
        kms: new KMSClient(common),
        s3: new S3Client(common),
        apiGateway: new ApiGatewayV2Client(common),
    };
};
