import { existsSync } from "node:fs";
import * as path from "node:path";
import {
  Arn,
  CfnOutput,
  Duration,
  Fn,
  RemovalPolicy,
  DefaultStackSynthesizer,
  Stack,
  type StackProps,
  Token,
} from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import { HttpJwtAuthorizer } from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as iot from "aws-cdk-lib/aws-iot";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as sqs from "aws-cdk-lib/aws-sqs";
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
  PhysicalResourceId,
} from "aws-cdk-lib/custom-resources";
import type { Construct } from "constructs";
import { isUsEast1CertificateArn, type DeploymentConfig } from "./config";
import { consoleRuntimeConfig } from "./console-runtime-config";

const workflowDueIndex = "workflow-due";
const retentionDueIndex = "retention-due";
const catalogPathIndex = "catalog-path";
const consumerDirectoryIndex = "consumer-directory";
const consumerIdentityIndex = "consumer-identity";
const secretRevisionIndex = "secret-revision";
const auditPrefix = "audit";
const truststoreKeyPrefix = "truststores";

export class HemligStack extends Stack {
  public constructor(
    scope: Construct,
    id: string,
    props: DeploymentConfig & StackProps,
  ) {
    super(scope, id, {
      ...props,
      // resolveConsoleCertificate() may create a sibling us-east-1 stack to hold the
      // CloudFront certificate; consuming its certificate here requires both stacks to
      // opt in to cross-region references. A caller who already passed their own
      // crossRegionReferences wins over this default.
      crossRegionReferences:
        props.crossRegionReferences ?? props.consoleFqdn !== undefined,
    });

    if (props.consoleFqdn !== undefined && props.oidcAdminScope === undefined) {
      throw new Error(
        "oidcAdminScope is required when consoleFqdn enables browser access.",
      );
    }
    if (
      props.consoleFqdn !== undefined &&
      props.oidcConsoleAccessScope === undefined
    ) {
      throw new Error(
        "oidcConsoleAccessScope is required when consoleFqdn enables browser access.",
      );
    }
    if (props.consoleFqdn !== undefined && props.oidcClientId === undefined) {
      throw new Error(
        "oidcClientId is required when consoleFqdn enables browser access.",
      );
    }
    // deploymentConfigFromContext() already rejects a wrong-region ARN from the CDK
    // CLI path; an installer constructing HemligStack directly needs the same guard,
    // or a bad ARN surfaces only as a CloudFormation deployment failure.
    if (
      props.consoleCertificateArn !== undefined &&
      !isUsEast1CertificateArn(props.consoleCertificateArn)
    ) {
      throw new Error(
        "consoleCertificateArn must be an ACM certificate ARN in us-east-1, because CloudFront only accepts certificates from that region.",
      );
    }

    const prefix = `hml-${props.environmentName}`;
    const zone =
      props.existingHostedZoneId === undefined
        ? new route53.PublicHostedZone(this, "Zone", {
            zoneName: props.zoneDomain,
          })
        : route53.HostedZone.fromHostedZoneAttributes(this, "Zone", {
            hostedZoneId: props.existingHostedZoneId,
            zoneName: props.zoneDomain,
          });
    const revisionBucket = immutableBucket(
      this,
      "RevisionBucket",
      `${prefix}-revision`,
      Duration.days(90),
    );
    const auditBucket = immutableBucket(
      this,
      "AuditBucket",
      `${prefix}-audit`,
      Duration.days(365 * 7),
    );
    const truststoreBucket = new s3.Bucket(this, "TruststoreBucket", {
      bucketNamePrefix: `${prefix}-truststore`,
      bucketNamespace: s3.BucketNamespace.ACCOUNT_REGIONAL,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
    const table = new dynamodb.Table(this, "ControlTable", {
      tableName: `${prefix}-control`,
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
      timeToLiveAttribute: "ttl",
      stream: dynamodb.StreamViewType.NEW_IMAGE,
    });
    table.addGlobalSecondaryIndex({
      indexName: workflowDueIndex,
      partitionKey: {
        name: "workflowDuePk",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: { name: "workflowDueSk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: consumerDirectoryIndex,
      partitionKey: {
        name: "consumerDirectoryPk",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "consumerDirectorySk",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: consumerIdentityIndex,
      partitionKey: {
        name: "identityConsumerPk",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "identityConsumerSk",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: secretRevisionIndex,
      partitionKey: {
        name: "revisionPk",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "revisionSk",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: catalogPathIndex,
      partitionKey: { name: "catalogPk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "catalogSk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: retentionDueIndex,
      partitionKey: {
        name: "retentionDuePk",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: { name: "retentionDueSk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    // One customer-managed key for all Hemlig envelope material. Payloads and
    // the online issuer key remain cryptographically separated by their KMS
    // encryption contexts; this is intentionally not a second issuer CMK.
    const applicationKey =
      props.existingApplicationKeyArn === undefined
        ? new kms.Key(this, "ApplicationKey", {
            description: `Application envelope key for ${prefix}`,
            enableKeyRotation: true,
            removalPolicy: RemovalPolicy.RETAIN,
          })
        : kms.Key.fromKeyArn(
            this,
            "ApplicationKey",
            props.existingApplicationKeyArn,
          );
    const notificationTopicPrefix = `hemlig/${props.environmentName}/consumers`;
    const notificationPolicyName = `${prefix}-agent-notifications`;
    const iotEndpoint = new AwsCustomResource(this, "IotDataEndpoint", {
      onCreate: {
        service: "Iot",
        action: "describeEndpoint",
        parameters: { endpointType: "iot:Data-ATS" },
        physicalResourceId: PhysicalResourceId.of(`${prefix}-iot-data-ats`),
      },
      onUpdate: {
        service: "Iot",
        action: "describeEndpoint",
        parameters: { endpointType: "iot:Data-ATS" },
        physicalResourceId: PhysicalResourceId.of(`${prefix}-iot-data-ats`),
      },
      policy: AwsCustomResourcePolicy.fromSdkCalls({
        resources: AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    }).getResponseField("endpointAddress");
    const iotArnPrefix = `arn:${this.partition}:iot:${this.region}:${this.account}`;
    const attachedThingName = "${iot:Connection.Thing.ThingName}";
    const notificationPolicy = new iot.CfnPolicy(
      this,
      "AgentNotificationPolicy",
      {
        policyName: notificationPolicyName,
        policyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["iot:Connect"],
              Resource: [`${iotArnPrefix}:client/${attachedThingName}`],
              Condition: {
                Bool: { "iot:Connection.Thing.IsAttached": "true" },
              },
            },
            {
              Effect: "Allow",
              Action: ["iot:Subscribe"],
              Resource: [
                `${iotArnPrefix}:topicfilter/${notificationTopicPrefix}/${attachedThingName}`,
              ],
            },
            {
              Effect: "Allow",
              Action: ["iot:Receive"],
              Resource: [
                `${iotArnPrefix}:topic/${notificationTopicPrefix}/${attachedThingName}`,
              ],
            },
          ],
        },
      },
    );
    new kms.Alias(this, "ApplicationKeyAlias", {
      aliasName: `alias/${prefix}-application`,
      targetKey: applicationKey,
    });
    const certificate = new acm.Certificate(this, "ApiCertificate", {
      domainName: props.adminFqdn,
      subjectAlternativeNames: [props.apiFqdn],
      validation: acm.CertificateValidation.fromDnsMultiZone({
        [props.adminFqdn]: zone,
        [props.apiFqdn]: zone,
      }),
    });
    const adminDomain = new apigatewayv2.DomainName(this, "AdminDomain", {
      domainName: props.adminFqdn,
      certificate,
      securityPolicy: apigatewayv2.SecurityPolicy.TLS_1_2,
    });
    // The domain starts without mTLS. The enrollment flow publishes the first
    // versioned CA bundle, then atomically enables the domain truststore.
    const consumerDomain = new apigatewayv2.DomainName(this, "ConsumerDomain", {
      domainName: props.apiFqdn,
      certificate,
      securityPolicy: apigatewayv2.SecurityPolicy.TLS_1_2,
    });
    const environment = {
      CONTROL_TABLE_NAME: table.tableName,
      WORKFLOW_DUE_INDEX: workflowDueIndex,
      RETENTION_DUE_INDEX: retentionDueIndex,
      CATALOG_PATH_INDEX: catalogPathIndex,
      CONSUMER_DIRECTORY_INDEX: consumerDirectoryIndex,
      CONSUMER_IDENTITY_INDEX: consumerIdentityIndex,
      SECRET_REVISION_INDEX: secretRevisionIndex,
      REVISION_BUCKET_NAME: revisionBucket.bucketName,
      TRUSTSTORE_BUCKET_NAME: truststoreBucket.bucketName,
      TRUSTSTORE_KEY_PREFIX: truststoreKeyPrefix,
      PAYLOAD_KMS_KEY_ARN: applicationKey.keyArn,
      HEMLIG_ENVIRONMENT: props.environmentName,
      AUDIT_BUCKET_NAME: auditBucket.bucketName,
      AUDIT_PREFIX: auditPrefix,
      DELIVERY_API_CUSTOM_DOMAIN_NAME: props.apiFqdn,
      DELIVERY_API_HOSTNAME: props.apiFqdn,
      IOT_ENDPOINT: iotEndpoint,
      IOT_NOTIFICATION_POLICY_NAME: notificationPolicyName,
      IOT_NOTIFICATION_TOPIC_PREFIX: notificationTopicPrefix,
      ADMIN_JWT_ISSUER: props.oidcIssuer,
      ADMIN_JWT_AUDIENCE: props.oidcAudience,
      ADMIN_ACTOR_SUBJECT_CLAIM: props.oidcSubjectClaim,
      ...(props.oidcAdminScope === undefined
        ? {}
        : { ADMIN_JWT_SCOPE: props.oidcAdminScope }),
      ...(props.oidcAdminRole === undefined
        ? {}
        : { ADMIN_JWT_ROLE: props.oidcAdminRole }),
      MAX_PAYLOAD_BYTES: "768000",
    };
    const adminFunction = this.function(
      "AdminFunction",
      `${prefix}-admin`,
      "src/handlers/admin.ts",
      environment,
    );
    // Archive reads are deliberately isolated from the normal write-capable
    // administrator handler. Both routes use the same administrator JWT.
    const auditQueryFunction = this.function(
      "AuditQueryFunction",
      `${prefix}-audit-query`,
      "src/handlers/audit-query.ts",
      environment,
    );
    const consumerFunction = this.function(
      "ConsumerFunction",
      `${prefix}-consumer`,
      "src/handlers/consumer.ts",
      environment,
    );
    const bootstrapFunction = this.function(
      "BootstrapFunction",
      `${prefix}-bootstrap`,
      "src/handlers/bootstrap.ts",
      environment,
    );
    const notificationPublisherFunction = this.function(
      "NotificationPublisherFunction",
      `${prefix}-notification-publisher`,
      "src/handlers/notifications.ts",
      environment,
    );
    const recoveryFunction = this.function(
      "RecoveryFunction",
      `${prefix}-recovery`,
      "src/handlers/recovery.ts",
      environment,
    );
    const retentionFunction = this.function(
      "RetentionFunction",
      `${prefix}-retention`,
      "src/handlers/retention.ts",
      environment,
    );

    table.grantReadWriteData(adminFunction);
    table.grantReadWriteData(consumerFunction);
    table.grantReadWriteData(bootstrapFunction);
    table.grantReadWriteData(notificationPublisherFunction);
    table.grantReadWriteData(recoveryFunction);
    table.grantReadWriteData(retentionFunction);
    // The audit-query Lambda otherwise reads only the immutable audit bucket.
    // It receives the minimum table access required for its own opaque
    // pagination state and cannot read or write the rest of Hemlig's control
    // plane.
    auditQueryFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:GetItem", "dynamodb:PutItem"],
        resources: [table.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["CURSOR#*"],
          },
        },
      }),
    );
    grantRevisionMutation(adminFunction, revisionBucket);
    grantRevisionMutation(consumerFunction, revisionBucket);
    revisionBucket.grantRead(consumerFunction);
    grantRevisionMutation(recoveryFunction, revisionBucket);
    grantTruststorePublisher(recoveryFunction, truststoreBucket, props.apiFqdn);
    retentionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:DeleteObjectVersion", "s3:GetObjectRetention"],
        resources: [revisionBucket.arnForObjects("*")],
      }),
    );
    // Do not use Key.grant() here: it would allow a function to mint data
    // keys for any encryption context.  The one shared CMK is safe only if
    // each caller is still constrained to its explicit application purpose.
    grantEnvelopeDataKey(adminFunction, applicationKey, [
      "issuer-ca",
      "secret-payload",
    ]);
    grantEnvelopeDataKey(consumerFunction, applicationKey, ["secret-payload"]);
    grantEnvelopeDataKey(bootstrapFunction, applicationKey, ["issuer-ca"]);
    // The admin Lambda uses this same application CMK to unwrap only the
    // issuing-root envelope. Consumer functions remain decrypt-only for
    // payload envelopes and cannot use the issuer encryption context.
    adminFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "hemlig",
            "kms:EncryptionContext:purpose": "issuer-ca",
          },
        },
      }),
    );
    bootstrapFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "hemlig",
            "kms:EncryptionContext:purpose": "issuer-ca",
          },
        },
      }),
    );
    // Administrators may read the current plaintext payload through the
    // administrator API. Keep that decryption limited to payload envelopes;
    // it does not broaden access to the issuer's private-key envelope.
    adminFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "hemlig",
            "kms:EncryptionContext:purpose": "secret-payload",
          },
        },
      }),
    );
    consumerFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "hemlig",
            "kms:EncryptionContext:purpose": "secret-payload",
          },
        },
      }),
    );
    auditBucket.grantPut(adminFunction, `${auditPrefix}/*`);
    // Bucket.grantRead() also grants broad s3:List* and s3:GetBucket* access
    // to the entire bucket. The audit query needs only one prefix, so keep
    // its IAM role aligned with the handler's date-derived prefix.
    auditQueryFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:ListBucket"],
        resources: [auditBucket.bucketArn],
        conditions: { StringLike: { "s3:prefix": [`${auditPrefix}/*`] } },
      }),
    );
    auditQueryFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject"],
        resources: [auditBucket.arnForObjects(`${auditPrefix}/*`)],
      }),
    );
    auditQueryFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:PutObject"],
        resources: [auditBucket.arnForObjects(`${auditPrefix}/*`)],
      }),
    );
    auditBucket.grantPut(consumerFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(bootstrapFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(recoveryFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(retentionFunction, `${auditPrefix}/*`);
    grantTruststorePublisher(adminFunction, truststoreBucket, props.apiFqdn);
    grantTruststorePublisher(
      bootstrapFunction,
      truststoreBucket,
      props.apiFqdn,
    );
    bootstrapFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "iot:AttachPolicy",
          "iot:AttachThingPrincipal",
          "iot:CreateThing",
          "iot:DescribeCertificate",
          "iot:RegisterCertificateWithoutCA",
          "iot:UpdateCertificate",
        ],
        resources: ["*"],
      }),
    );
    const notificationDeadLetterQueue = new sqs.Queue(
      this,
      "NotificationDeadLetterQueue",
      {
        queueName: `${prefix}-notification-dlq`,
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        retentionPeriod: Duration.days(14),
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    new cloudwatch.Alarm(this, "NotificationDeadLetterAlarm", {
      alarmName: `${prefix}-notification-dlq-not-empty`,
      metric:
        notificationDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
          period: Duration.minutes(5),
        }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    notificationPublisherFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["iot:Publish"],
        resources: [`${iotArnPrefix}:topic/${notificationTopicPrefix}/*`],
      }),
    );
    notificationPublisherFunction.addEventSource(
      new lambdaEventSources.DynamoEventSource(table, {
        startingPosition: lambda.StartingPosition.TRIM_HORIZON,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 5,
        onFailure: new lambdaEventSources.SqsDlq(notificationDeadLetterQueue),
        filters: [
          lambda.FilterCriteria.filter({
            eventName: ["INSERT"],
            dynamodb: {
              NewImage: {
                pk: { S: [{ prefix: "NOTIFICATION#" }] },
                status: { S: ["PENDING"] },
              },
            },
          }),
        ],
      }),
    );
    truststoreBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal("apigateway.amazonaws.com")],
        actions: ["s3:GetObject", "s3:GetObjectVersion"],
        resources: [truststoreBucket.arnForObjects(`${truststoreKeyPrefix}/*`)],
        conditions: { StringEquals: { "aws:SourceAccount": this.account } },
      }),
    );

    const authorizer = new HttpJwtAuthorizer(
      "AdminAuthorizer",
      props.oidcIssuer,
      {
        authorizerName: `${prefix}-admin`,
        jwtAudience: [props.oidcAudience],
      },
    );
    const adminIntegration = new HttpLambdaIntegration(
      "AdminIntegration",
      adminFunction,
    );
    const auditQueryIntegration = new HttpLambdaIntegration(
      "AuditQueryIntegration",
      auditQueryFunction,
    );
    const bootstrapIntegration = new HttpLambdaIntegration(
      "BootstrapIntegration",
      bootstrapFunction,
    );
    const adminApi = new apigatewayv2.HttpApi(this, "AdminApi", {
      apiName: `${prefix}-admin`,
      defaultAuthorizer: authorizer,
      defaultAuthorizationScopes:
        props.oidcAdminScope === undefined ? undefined : [props.oidcAdminScope],
      defaultIntegration: adminIntegration,
      createDefaultStage: false,
      disableExecuteApiEndpoint: true,
      corsPreflight:
        props.consoleFqdn === undefined
          ? undefined
          : {
              allowOrigins: [`https://${props.consoleFqdn}`],
              allowMethods: [
                apigatewayv2.CorsHttpMethod.GET,
                apigatewayv2.CorsHttpMethod.POST,
                apigatewayv2.CorsHttpMethod.PUT,
                apigatewayv2.CorsHttpMethod.DELETE,
              ],
              allowHeaders: [
                "authorization",
                "content-type",
                "idempotency-key",
                "if-match",
              ],
              exposeHeaders: ["etag"],
              allowCredentials: false,
              maxAge: Duration.minutes(10),
            },
    });
    if (props.consoleFqdn !== undefined) {
      adminApi.addRoutes({
        path: "/{proxy+}",
        methods: [apigatewayv2.HttpMethod.OPTIONS],
        integration: adminIntegration,
        authorizer: new apigatewayv2.HttpNoneAuthorizer(),
        // addRoutes inherits defaultAuthorizationScopes unless this is given
        // explicitly, which would attach the administrator scope to the
        // unauthenticated preflight route.
        authorizationScopes: [],
      });
    }
    adminApi.addRoutes({
      path: "/v1/admin/audit",
      methods: [apigatewayv2.HttpMethod.GET],
      integration: auditQueryIntegration,
    });
    adminApi.addRoutes({
      path: "/v1/bootstrap/redeem",
      methods: [apigatewayv2.HttpMethod.POST],
      integration: bootstrapIntegration,
      authorizer: new apigatewayv2.HttpNoneAuthorizer(),
      authorizationScopes: [],
    });
    const consumerApi = new apigatewayv2.HttpApi(this, "ConsumerApi", {
      apiName: `${prefix}-consumer`,
      defaultIntegration: new HttpLambdaIntegration(
        "ConsumerIntegration",
        consumerFunction,
      ),
      createDefaultStage: false,
      disableExecuteApiEndpoint: true,
    });
    const adminAccessLogs = accessLogGroup(
      this,
      "AdminAccessLogs",
      `${prefix}-admin-access`,
    );
    const consumerAccessLogs = accessLogGroup(
      this,
      "ConsumerAccessLogs",
      `${prefix}-consumer-access`,
    );
    const adminStage = new apigatewayv2.HttpStage(this, "AdminStage", {
      httpApi: adminApi,
      // HttpStage does not auto-deploy unless explicitly requested. Without
      // this, API Gateway retains the routes in its control plane but the
      // custom domain serves only 404s from an empty stage.
      autoDeploy: true,
      accessLogSettings: accessLogSettings(adminAccessLogs),
    });
    // Includes the bootstrap route. Its capability is already high entropy and
    // short lived, but a modest stage limit also bounds unauthenticated Lambda
    // work without giving the bootstrap endpoint a less protected path.
    const adminCfnStage = adminStage.node.defaultChild as apigatewayv2.CfnStage;
    adminCfnStage.defaultRouteSettings = {
      throttlingBurstLimit: 100,
      throttlingRateLimit: 50,
    };
    const consumerStage = new apigatewayv2.HttpStage(this, "ConsumerStage", {
      httpApi: consumerApi,
      autoDeploy: true,
      accessLogSettings: accessLogSettings(consumerAccessLogs),
    });
    new apigatewayv2.ApiMapping(this, "AdminMapping", {
      api: adminApi,
      domainName: adminDomain,
      stage: adminStage,
    });
    new apigatewayv2.ApiMapping(this, "ConsumerMapping", {
      api: consumerApi,
      domainName: consumerDomain,
      stage: consumerStage,
    });
    aliasRecord(
      this,
      "AdminAlias",
      zone,
      props.adminFqdn,
      props.zoneDomain,
      adminDomain,
    );
    aliasRecord(
      this,
      "ConsumerAlias",
      zone,
      props.apiFqdn,
      props.zoneDomain,
      consumerDomain,
    );
    new events.Rule(this, "RecoverySchedule", {
      ruleName: `${prefix}-recovery`,
      schedule: events.Schedule.rate(Duration.minutes(5)),
      targets: [new eventTargets.LambdaFunction(recoveryFunction)],
    });
    new events.Rule(this, "RetentionSchedule", {
      ruleName: `${prefix}-retention`,
      schedule: events.Schedule.rate(Duration.days(1)),
      targets: [new eventTargets.LambdaFunction(retentionFunction)],
    });

    new CfnOutput(this, "AdminUrl", { value: `https://${props.adminFqdn}` });
    new CfnOutput(this, "ApiUrl", {
      value: `https://${props.apiFqdn}`,
    });
    new CfnOutput(this, "IotEndpoint", { value: iotEndpoint });
    new CfnOutput(this, "AdminOidcIssuer", { value: props.oidcIssuer });
    new CfnOutput(this, "AdminOidcAudience", { value: props.oidcAudience });
    if (props.oidcAdminScope !== undefined) {
      new CfnOutput(this, "AdminOidcScope", { value: props.oidcAdminScope });
    }
    if (props.oidcAdminRole !== undefined) {
      new CfnOutput(this, "AdminOidcRole", { value: props.oidcAdminRole });
    }
    new CfnOutput(this, "RevisionBucketName", {
      value: revisionBucket.bucketName,
    });
    new CfnOutput(this, "AuditBucketName", { value: auditBucket.bucketName });
    if (props.existingHostedZoneId === undefined) {
      new CfnOutput(this, "CreatedHostedZoneNameServers", {
        value: Fn.join(
          ",",
          (zone as route53.PublicHostedZone).hostedZoneNameServers ?? [],
        ),
      });
    }

    if (props.consoleFqdn !== undefined) {
      this.configureConsole(zone, prefix, props);
    }
  }

  // Static hosting for the browser console: S3 origin behind CloudFront, with the
  // response headers and cache behaviors an SPA served cross-origin from the admin
  // API needs. Created only when consoleFqdn opts a deployment into browser access.
  private configureConsole(
    zone: route53.IHostedZone,
    prefix: string,
    props: DeploymentConfig,
  ): void {
    const consoleFqdn = props.consoleFqdn;
    if (consoleFqdn === undefined) {
      return;
    }
    // These OIDC console values are already required by the constructor whenever
    // consoleFqdn is set; narrow them here once so every read below (in particular
    // the config.json payload) is compiler-checked as a string rather than relying
    // on a runtime guard deep in Source.jsonData.
    const { oidcAdminScope, oidcConsoleAccessScope, oidcClientId } = props;
    if (
      oidcAdminScope === undefined ||
      oidcConsoleAccessScope === undefined ||
      oidcClientId === undefined
    ) {
      throw new Error(
        "oidcAdminScope, oidcConsoleAccessScope, and oidcClientId are required when consoleFqdn is configured.",
      );
    }
    const consoleProps: DeploymentConfig & {
      consoleFqdn: string;
      oidcAdminScope: string;
      oidcConsoleAccessScope: string;
      oidcClientId: string;
    } = {
      ...props,
      consoleFqdn,
      oidcAdminScope,
      oidcConsoleAccessScope,
      oidcClientId,
    };

    const certificate = this.resolveConsoleCertificate(
      zone,
      consoleFqdn,
      consoleProps.consoleCertificateArn,
      consoleProps.existingHostedZoneId !== undefined,
      consoleProps.bootstrapQualifier,
    );
    const consoleBucket = new s3.Bucket(this, "ConsoleBucket", {
      bucketNamePrefix: `${prefix}-console`,
      bucketNamespace: s3.BucketNamespace.ACCOUNT_REGIONAL,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      // Static assets, not evidence: unlike the revision/audit buckets, no Object Lock.
      removalPolicy: RemovalPolicy.RETAIN,
      // Versioned with prune: false, so a superseded asset version is never deleted
      // by the deployment itself; without this it accumulates forever.
      lifecycleRules: [{ noncurrentVersionExpiration: Duration.days(30) }],
    });

    const api = `https://${consoleProps.adminFqdn}`;
    const idp = new URL(consoleProps.oidcIssuer).origin;
    const sharedSecurityHeadersBehavior: cloudfront.ResponseSecurityHeadersBehavior =
      {
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(730),
          includeSubdomains: true,
          preload: true,
          override: true,
        },
        contentTypeOptions: { override: true },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
          override: true,
        },
      };
    // Factored so the three response-headers policies below cannot drift apart:
    // each supplies only the axis that legitimately differs (frame-ancestors/
    // X-Frame-Options for the silent-renew document, Cache-Control for assets).
    const securityHeadersFor = (
      frameAncestors: string,
      frameOption: cloudfront.HeadersFrameOption,
    ): cloudfront.ResponseSecurityHeadersBehavior => ({
      ...sharedSecurityHeadersBehavior,
      contentSecurityPolicy: {
        contentSecurityPolicy: consoleContentSecurityPolicy(
          frameAncestors,
          api,
          idp,
        ),
        override: true,
      },
      frameOptions: { frameOption, override: true },
    });
    const customHeadersFor = (
      cacheControl: string,
    ): cloudfront.ResponseCustomHeadersBehavior => ({
      customHeaders: [
        // Browsers cache heuristically with no Cache-Control at all; CACHING_DISABLED
        // below governs only the CloudFront edge, not the viewer.
        { header: "Cache-Control", value: cacheControl, override: true },
        {
          header: "Permissions-Policy",
          value: "camera=(), microphone=(), geolocation=()",
          override: true,
        },
      ],
    });
    const consoleHeaders = new cloudfront.ResponseHeadersPolicy(
      this,
      "ConsoleHeaders",
      {
        responseHeadersPolicyName: `${prefix}-console`,
        securityHeadersBehavior: securityHeadersFor(
          "'none'",
          cloudfront.HeadersFrameOption.DENY,
        ),
        customHeadersBehavior: customHeadersFor("no-store"),
      },
    );
    // The identity provider's silent-renew redirect lands back on the console's own
    // /silent.html, so that document is framed by the console itself. `frame-ancestors
    // 'none'` (Policy A, above) would block every token renewal and silently degrade
    // each session to a full redirect, so only this document gets a same-origin
    // framing allowance.
    const consoleSilentRenewHeaders = new cloudfront.ResponseHeadersPolicy(
      this,
      "ConsoleSilentRenewHeaders",
      {
        responseHeadersPolicyName: `${prefix}-console-silent-renew`,
        securityHeadersBehavior: securityHeadersFor(
          "'self'",
          cloudfront.HeadersFrameOption.SAMEORIGIN,
        ),
        customHeadersBehavior: customHeadersFor("no-store"),
      },
    );
    // Vite content-hashes every filename under /assets/, so this is the only path
    // safe to cache for a year; otherwise identical security headers to ConsoleHeaders.
    const consoleAssetHeaders = new cloudfront.ResponseHeadersPolicy(
      this,
      "ConsoleAssetHeaders",
      {
        responseHeadersPolicyName: `${prefix}-console-assets`,
        securityHeadersBehavior: securityHeadersFor(
          "'none'",
          cloudfront.HeadersFrameOption.DENY,
        ),
        customHeadersBehavior: customHeadersFor(
          "public, max-age=31536000, immutable",
        ),
      },
    );

    const origin =
      origins.S3BucketOrigin.withOriginAccessControl(consoleBucket);
    const noCacheBehavior = (
      responseHeadersPolicy: cloudfront.ResponseHeadersPolicy,
    ): cloudfront.BehaviorOptions => ({
      origin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      responseHeadersPolicy,
    });
    const consoleDistribution = new cloudfront.Distribution(
      this,
      "ConsoleDistribution",
      {
        // CloudFront selects a cache behavior from the viewer request URI *before*
        // defaultRootObject is applied, so "/" -- and every unmatched SPA deep link --
        // matches this default behavior, not the "/index.html" one below. It must stay
        // uncached or the app shell gets pinned in the edge cache for 24h.
        defaultBehavior: noCacheBehavior(consoleHeaders),
        additionalBehaviors: {
          "/assets/*": {
            origin,
            viewerProtocolPolicy:
              cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
            responseHeadersPolicy: consoleAssetHeaders,
          },
          "/silent.html": noCacheBehavior(consoleSilentRenewHeaders),
          "/config.json": noCacheBehavior(consoleHeaders),
          "/index.html": noCacheBehavior(consoleHeaders),
        },
        domainNames: [consoleFqdn],
        certificate,
        defaultRootObject: "index.html",
        httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
        minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
        // SPA client-side routing: an unknown path is neither a real S3 key (404) nor
        // accessible via OAC before the bucket policy propagates (403); both should
        // still render the app shell so the router can take over. ttl: 0 keeps this
        // rewrite itself from being edge-cached on top of the CACHING_DISABLED behaviors
        // above (CloudFront's error-response cache is a separate, additive TTL).
        errorResponses: [
          {
            httpStatus: 403,
            responseHttpStatus: 200,
            responsePagePath: "/index.html",
            ttl: Duration.seconds(0),
          },
          {
            httpStatus: 404,
            responseHttpStatus: 200,
            responsePagePath: "/index.html",
            ttl: Duration.seconds(0),
          },
        ],
      },
    );

    const consoleTarget = route53.RecordTarget.fromAlias(
      new route53Targets.CloudFrontTarget(consoleDistribution),
    );
    new route53.ARecord(this, "ConsoleAliasA", {
      zone,
      recordName: relativeRecordName(consoleFqdn, consoleProps.zoneDomain),
      target: consoleTarget,
    });
    new route53.AaaaRecord(this, "ConsoleAliasAAAA", {
      zone,
      recordName: relativeRecordName(consoleFqdn, consoleProps.zoneDomain),
      target: consoleTarget,
    });

    const consoleDistSourceEntry = path.resolve(
      __dirname,
      "..",
      "packages/console/dist",
    );
    const consoleDistPackagedEntry = path.resolve(
      __dirname,
      "..",
      "console-dist",
    );
    const consoleDist = existsSync(consoleDistSourceEntry)
      ? consoleDistSourceEntry
      : existsSync(consoleDistPackagedEntry)
        ? consoleDistPackagedEntry
        : undefined;
    const runtimeConfig = consoleRuntimeConfig({
      deploymentName: prefix,
      adminFqdn: consoleProps.adminFqdn,
      oidcIssuer: consoleProps.oidcIssuer,
      oidcClientId: consoleProps.oidcClientId,
      oidcConsoleAccessScope: consoleProps.oidcConsoleAccessScope,
    });
    if (consoleDist === undefined) {
      // An installer may build and publish the console output as a separate pipeline
      // step; an absent build output at synth time isn't a failure.
      new CfnOutput(this, "ConsoleAssetsPending", {
        value:
          "packages/console/dist was not found at synth time; publish it to ConsoleBucketName separately.",
      });
    } else {
      new s3deploy.BucketDeployment(this, "ConsoleAssets", {
        destinationBucket: consoleBucket,
        distribution: consoleDistribution,
        distributionPaths: ["/index.html", "/config.json", "/silent.html"],
        sources: [
          // The build output could ship its own config.json; excluding it here means
          // the generated one below always wins regardless of source array order.
          s3deploy.Source.asset(consoleDist, { exclude: ["config.json"] }),
          s3deploy.Source.jsonData("config.json", runtimeConfig),
        ],
        prune: false,
      });
    }

    new CfnOutput(this, "ConsoleUrl", { value: `https://${consoleFqdn}` });
    new CfnOutput(this, "ConsoleBucketName", {
      value: consoleBucket.bucketName,
    });
    new CfnOutput(this, "ConsoleDistributionId", {
      value: consoleDistribution.distributionId,
    });
  }

  private resolveConsoleCertificate(
    zone: route53.IHostedZone,
    consoleFqdn: string,
    certificateArn: string | undefined,
    hostedZoneIsImported: boolean,
    bootstrapQualifier: string | undefined,
  ): acm.ICertificate {
    if (certificateArn !== undefined) {
      return acm.Certificate.fromCertificateArn(
        this,
        "ConsoleCertificate",
        certificateArn,
      );
    }
    // CloudFront requires the certificate in us-east-1. This stack's own region is
    // whatever the caller deploys to, and the existing ApiCertificate is regional and
    // covers only adminFqdn/apiFqdn, so neither can be reused. A NestedStack would
    // inherit this stack's region rather than hosting the certificate where CloudFront
    // needs it, so the certificate lives in a sibling top-level stack instead. That
    // requires crossRegionReferences, which in turn requires a concrete environment to
    // synthesize the cross-stack reference against.
    if (Token.isUnresolved(this.region)) {
      throw new Error(
        "consoleFqdn requires either consoleCertificateArn or a concrete stack region: " +
          "cross-region references cannot resolve against an unspecified environment. " +
          "Set env on the stack, or supply consoleCertificateArn directly.",
      );
    }
    // The sibling stack validates the certificate by importing this stack's hosted
    // zone by id. If this stack also created that zone, its id is a token tied to a
    // resource in this stack, so the sibling would depend on this stack for the zone
    // while this stack depends on the sibling for the certificate -- an unresolvable
    // cycle across stacks. An imported zone's id is a plain string, which breaks the
    // cycle.
    if (!hostedZoneIsImported) {
      throw new Error(
        "consoleFqdn cannot create a cross-region certificate stack against a hosted " +
          "zone this stack also creates: set existingHostedZoneId (create the zone in " +
          "a prior deploy), or supply consoleCertificateArn directly.",
      );
    }
    const certificateStack = new Stack(
      this.node.scope as Construct,
      `${this.node.id}-console-certificate`,
      {
        env: { account: this.account, region: "us-east-1" },
        crossRegionReferences: true,
        // Synthesizers cannot be shared by two Stack instances. Make a new
        // instance with the supplied qualifier so this sibling publishes to
        // the same deliberately scoped bootstrap roles and asset bucket.
        ...(bootstrapQualifier === undefined
          ? {}
          : {
              synthesizer: new DefaultStackSynthesizer({
                qualifier: bootstrapQualifier,
              }),
            }),
      },
    );
    const certificateZone = route53.HostedZone.fromHostedZoneAttributes(
      certificateStack,
      "Zone",
      { hostedZoneId: zone.hostedZoneId, zoneName: zone.zoneName },
    );
    return new acm.Certificate(certificateStack, "ConsoleCertificate", {
      domainName: consoleFqdn,
      validation: acm.CertificateValidation.fromDns(certificateZone),
    });
  }

  private function(
    id: string,
    functionName: string,
    entry: string,
    environment: Record<string, string>,
  ): NodejsFunction {
    const sourceEntry = path.resolve(__dirname, "..", entry);
    const packagedEntry = path.resolve(__dirname, "..", "..", entry);
    return new NodejsFunction(this, id, {
      functionName,
      description: `Hemlig ${id}`,
      entry: existsSync(sourceEntry) ? sourceEntry : packagedEntry,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: "handler",
      memorySize: 512,
      timeout: Duration.seconds(29),
      tracing: lambda.Tracing.ACTIVE,
      environment,
      bundling: { minify: true, sourceMap: true, target: "node24" },
    });
  }
}

const immutableBucket = (
  scope: Construct,
  id: string,
  prefix: string,
  retention: Duration,
): s3.Bucket =>
  new s3.Bucket(scope, id, {
    bucketNamePrefix: prefix,
    bucketNamespace: s3.BucketNamespace.ACCOUNT_REGIONAL,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED,
    enforceSSL: true,
    objectLockDefaultRetention: s3.ObjectLockRetention.compliance(retention),
    objectLockEnabled: true,
    removalPolicy: RemovalPolicy.RETAIN,
    versioned: true,
  });

const grantRevisionMutation = (
  function_: lambda.Function,
  bucket: s3.IBucket,
): void => {
  function_.addToRolePolicy(
    new iam.PolicyStatement({
      actions: [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectRetention",
        "s3:PutObject",
        "s3:PutObjectRetention",
      ],
      resources: [bucket.arnForObjects("*")],
    }),
  );
};

const grantEnvelopeDataKey = (
  function_: lambda.Function,
  key: kms.IKey,
  purposes: readonly string[],
): void => {
  function_.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ["kms:GenerateDataKey"],
      resources: [key.keyArn],
      conditions: {
        StringEquals: {
          "kms:EncryptionContext:service": "hemlig",
          "kms:EncryptionContext:purpose": purposes,
        },
      },
    }),
  );
};

const grantTruststorePublisher = (
  function_: lambda.Function,
  bucket: s3.IBucket,
  domainName: string,
): void => {
  function_.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ["s3:GetObject", "s3:PutObject"],
      resources: [bucket.arnForObjects(`${truststoreKeyPrefix}/*`)],
    }),
  );
  function_.addToRolePolicy(
    new iam.PolicyStatement({
      actions: [
        "apigateway:GET",
        "apigateway:PATCH",
        "apigateway:AddCertificateToDomain",
        "apigateway:RemoveCertificateFromDomain",
      ],
      resources: [
        Arn.format(
          {
            service: "apigateway",
            resource: `/domainnames/${domainName}`,
            account: "",
          },
          function_.stack,
        ),
      ],
    }),
  );
};

const aliasRecord = (
  scope: Construct,
  id: string,
  zone: route53.IHostedZone,
  fqdn: string,
  zoneDomain: string,
  domain: apigatewayv2.IDomainName,
): void => {
  new route53.ARecord(scope, id, {
    zone,
    recordName: relativeRecordName(fqdn, zoneDomain),
    target: route53.RecordTarget.fromAlias(
      new route53Targets.ApiGatewayv2DomainProperties(
        domain.regionalDomainName,
        domain.regionalHostedZoneId,
      ),
    ),
  });
};

const accessLogGroup = (
  scope: Construct,
  id: string,
  logGroupName: string,
): logs.LogGroup =>
  new logs.LogGroup(scope, id, {
    logGroupName,
    retention: logs.RetentionDays.ONE_YEAR,
    removalPolicy: RemovalPolicy.RETAIN,
  });

const accessLogSettings = (
  logGroup: logs.ILogGroup,
): apigatewayv2.IAccessLogSettings => ({
  destination: {
    bind: () => ({ destinationArn: logGroup.logGroupArn }),
  },
  format: apigateway.AccessLogFormat.custom(
    JSON.stringify({
      requestId: "$context.requestId",
      status: "$context.status",
      error: "$context.error.message",
      authorizerError: "$context.authorizer.error",
    }),
  ),
});

const relativeRecordName = (
  fqdn: string,
  zoneDomain: string,
): string | undefined =>
  fqdn === zoneDomain ? undefined : fqdn.slice(0, -(zoneDomain.length + 1));

// The console and the admin API are deliberately cross-origin, so connect-src must
// name the admin API explicitly. frame-src must allow 'self' in addition to the
// identity provider: oidc-client-ts's silent renew points a hidden iframe at the
// IdP, which then redirects that same iframe back to the console's own
// /silent.html -- CSP re-checks frame-src against that redirect target, so
// omitting 'self' here blocks every token renewal even though frame-ancestors
// 'self' (below) separately permits the document to be framed. frameAncestors is
// the one axis that differs between the default (`'none'`) and silent-renew
// (`'self'`) response headers policies.
const consoleContentSecurityPolicy = (
  frameAncestors: string,
  api: string,
  idp: string,
): string =>
  [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${api} ${idp}`,
    `frame-src 'self' ${idp}`,
    "form-action 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    `frame-ancestors ${frameAncestors}`,
  ].join("; ");
