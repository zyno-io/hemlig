import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { KMSClient } from "@aws-sdk/client-kms";
import { S3Client } from "@aws-sdk/client-s3";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { awsClientOptions } from "./client-options";
import type { AppConfig } from "./config";

/** DynamoDB, KMS and S3 only: the PKI Lambdas hold no IoT or API Gateway permissions. */
export interface PkiAwsClients {
  readonly dynamo: DynamoDBDocumentClient;
  readonly kms: KMSClient;
  readonly s3: S3Client;
}

export const createPkiAwsClients = (config: AppConfig): PkiAwsClients => {
  const common = awsClientOptions(config);
  return {
    dynamo: DynamoDBDocumentClient.from(new DynamoDBClient(common), {
      marshallOptions: { removeUndefinedValues: true },
    }),
    kms: new KMSClient(common),
    s3: new S3Client(common),
  };
};
