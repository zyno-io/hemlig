import { badRequest } from "../domain/errors";

export interface AppConfig {
  readonly region: string;
  /** Stable deployment name used in the Hemlig issuing-root subject. */
  readonly environmentName: string;
  readonly controlTableName: string;
  readonly workflowDueIndex: string;
  readonly retentionDueIndex: string;
  readonly catalogPathIndex: string;
  readonly consumerDirectoryIndex: string;
  readonly consumerIdentityIndex: string;
  readonly secretRevisionIndex: string;
  readonly revisionBucketName: string;
  readonly truststoreBucketName: string;
  readonly truststoreKeyPrefix: string;
  readonly payloadKmsKeyArn: string;
  readonly auditBucketName: string;
  readonly auditPrefix: string;
  readonly deliveryApiCustomDomainName: string;
  readonly deliveryApiHostname: string;
  /** Account-specific AWS IoT Data-ATS endpoint for agent change hints. */
  readonly iotEndpoint: string;
  /** Shared IoT policy attached only to Hemlig agent certificates. */
  readonly iotNotificationPolicyName: string;
  /** Prefix below which each agent receives its own private topic. */
  readonly iotNotificationTopicPrefix: string;
  readonly adminJwtIssuer: string;
  readonly adminJwtAudience: string;
  readonly adminActorSubjectClaim: string;
  /** Required only when the deployment enables a browser console origin. */
  readonly adminJwtScope?: string;
  /** Optional IdP application role required in addition to the OAuth scope. */
  readonly adminJwtRole?: string;
  readonly adminActorTenantClaim?: string;
  readonly adminExpectedTenantId?: string;
  readonly maxPayloadBytes: number;
  readonly awsEndpointUrl?: string;
}

export const loadConfig = (
  environment: NodeJS.ProcessEnv = process.env,
): AppConfig => {
  const maxPayloadBytes = Number.parseInt(
    environment.MAX_PAYLOAD_BYTES ?? "768000",
    10,
  );
  if (
    !Number.isSafeInteger(maxPayloadBytes) ||
    maxPayloadBytes <= 0 ||
    maxPayloadBytes > 768000
  ) {
    throw badRequest(
      "MAX_PAYLOAD_BYTES must be an integer between 1 and 768000.",
    );
  }
  return {
    region: environment.AWS_REGION ?? "us-east-1",
    environmentName: required(environment, "HEMLIG_ENVIRONMENT"),
    controlTableName: required(environment, "CONTROL_TABLE_NAME"),
    workflowDueIndex: required(environment, "WORKFLOW_DUE_INDEX"),
    retentionDueIndex: required(environment, "RETENTION_DUE_INDEX"),
    catalogPathIndex: required(environment, "CATALOG_PATH_INDEX"),
    consumerDirectoryIndex: required(environment, "CONSUMER_DIRECTORY_INDEX"),
    consumerIdentityIndex: required(environment, "CONSUMER_IDENTITY_INDEX"),
    secretRevisionIndex: required(environment, "SECRET_REVISION_INDEX"),
    revisionBucketName: required(environment, "REVISION_BUCKET_NAME"),
    truststoreBucketName: required(environment, "TRUSTSTORE_BUCKET_NAME"),
    truststoreKeyPrefix: required(environment, "TRUSTSTORE_KEY_PREFIX"),
    payloadKmsKeyArn: required(environment, "PAYLOAD_KMS_KEY_ARN"),
    auditBucketName: required(environment, "AUDIT_BUCKET_NAME"),
    auditPrefix: required(environment, "AUDIT_PREFIX"),
    deliveryApiCustomDomainName: required(
      environment,
      "DELIVERY_API_CUSTOM_DOMAIN_NAME",
    ),
    deliveryApiHostname: required(environment, "DELIVERY_API_HOSTNAME"),
    iotEndpoint: required(environment, "IOT_ENDPOINT"),
    iotNotificationPolicyName: required(
      environment,
      "IOT_NOTIFICATION_POLICY_NAME",
    ),
    iotNotificationTopicPrefix: required(
      environment,
      "IOT_NOTIFICATION_TOPIC_PREFIX",
    ),
    adminJwtIssuer: required(environment, "ADMIN_JWT_ISSUER"),
    adminJwtAudience: required(environment, "ADMIN_JWT_AUDIENCE"),
    adminActorSubjectClaim: required(environment, "ADMIN_ACTOR_SUBJECT_CLAIM"),
    adminJwtScope: optional(environment, "ADMIN_JWT_SCOPE"),
    adminJwtRole: optional(environment, "ADMIN_JWT_ROLE"),
    adminActorTenantClaim: optional(environment, "ADMIN_ACTOR_TENANT_CLAIM"),
    adminExpectedTenantId: optional(environment, "ADMIN_EXPECTED_TENANT_ID"),
    maxPayloadBytes,
    awsEndpointUrl: optional(environment, "AWS_ENDPOINT_URL"),
  };
};

const required = (environment: NodeJS.ProcessEnv, name: string): string => {
  const value = environment[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
};

const optional = (
  environment: NodeJS.ProcessEnv,
  name: string,
): string | undefined => {
  const value = environment[name];
  return value === undefined || value.trim().length === 0 ? undefined : value;
};
