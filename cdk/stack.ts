import { existsSync } from "node:fs";
import * as path from "node:path";
import {
  Arn,
  CfnOutput,
  Duration,
  Fn,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import { HttpJwtAuthorizer } from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import type { Construct } from "constructs";
import type { DeploymentConfig } from "./config";

const workflowDueIndex = "workflow-due";
const retentionDueIndex = "retention-due";
const catalogPathIndex = "catalog-path";
const auditPrefix = "audit";
const truststoreKeyPrefix = "truststores";

export class ClavisStack extends Stack {
  public constructor(
    scope: Construct,
    id: string,
    props: DeploymentConfig & StackProps,
  ) {
    super(scope, id, props);

    const prefix = `clv-${props.environmentName}`;
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
    // One customer-managed key for all Clavis envelope material. Payloads and
    // the online issuer key remain cryptographically separated by their KMS
    // encryption contexts; this is intentionally not a second issuer CMK.
    const applicationKey = new kms.Key(this, "ApplicationKey", {
      alias: `alias/${prefix}-application`,
      description: `Application envelope key for ${prefix}`,
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const cursorKey = new secretsmanager.Secret(this, "CursorKey", {
      secretName: `${prefix}/cursor-hmac`,
      description: "Opaque cursor integrity key for Clavis.",
      generateSecretString: {
        excludePunctuation: true,
        passwordLength: 64,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const certificate = new acm.Certificate(this, "ApiCertificate", {
      domainName: props.adminFqdn,
      subjectAlternativeNames: [props.clusterFqdn],
      validation: acm.CertificateValidation.fromDnsMultiZone({
        [props.adminFqdn]: zone,
        [props.clusterFqdn]: zone,
      }),
    });
    const adminDomain = new apigatewayv2.DomainName(this, "AdminDomain", {
      domainName: props.adminFqdn,
      certificate,
      securityPolicy: apigatewayv2.SecurityPolicy.TLS_1_2,
    });
    // The domain starts without mTLS. The enrollment flow publishes the first
    // versioned CA bundle, then atomically enables the domain truststore.
    const clusterDomain = new apigatewayv2.DomainName(this, "ClusterDomain", {
      domainName: props.clusterFqdn,
      certificate,
      securityPolicy: apigatewayv2.SecurityPolicy.TLS_1_2,
    });
    const environment = {
      CONTROL_TABLE_NAME: table.tableName,
      WORKFLOW_DUE_INDEX: workflowDueIndex,
      RETENTION_DUE_INDEX: retentionDueIndex,
      CATALOG_PATH_INDEX: catalogPathIndex,
      REVISION_BUCKET_NAME: revisionBucket.bucketName,
      TRUSTSTORE_BUCKET_NAME: truststoreBucket.bucketName,
      TRUSTSTORE_KEY_PREFIX: truststoreKeyPrefix,
      PAYLOAD_KMS_KEY_ARN: applicationKey.keyArn,
      CLAVIS_ENVIRONMENT: props.environmentName,
      AUDIT_BUCKET_NAME: auditBucket.bucketName,
      AUDIT_PREFIX: auditPrefix,
      CLUSTER_CUSTOM_DOMAIN_NAME: props.clusterFqdn,
      CLUSTER_API_HOSTNAME: props.clusterFqdn,
      CURSOR_HMAC_KEY: cursorKey.secretValue.unsafeUnwrap(),
      ADMIN_JWT_ISSUER: props.oidcIssuer,
      ADMIN_JWT_AUDIENCE: props.oidcAudience,
      ADMIN_ACTOR_SUBJECT_CLAIM: props.oidcSubjectClaim,
      MAX_PAYLOAD_BYTES: "768000",
    };
    const adminFunction = this.function(
      "AdminFunction",
      `${prefix}-admin`,
      "src/handlers/admin.ts",
      environment,
    );
    const clusterFunction = this.function(
      "ClusterFunction",
      `${prefix}-cluster`,
      "src/handlers/cluster.ts",
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
    table.grantReadData(clusterFunction);
    table.grantReadWriteData(recoveryFunction);
    table.grantReadWriteData(retentionFunction);
    grantRevisionMutation(adminFunction, revisionBucket);
    revisionBucket.grantRead(clusterFunction);
    grantRevisionMutation(recoveryFunction, revisionBucket);
    grantTruststorePublisher(
      recoveryFunction,
      truststoreBucket,
      props.clusterFqdn,
    );
    retentionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:DeleteObjectVersion", "s3:GetObjectRetention"],
        resources: [revisionBucket.arnForObjects("*")],
      }),
    );
    applicationKey.grant(
      adminFunction,
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    );
    // The admin Lambda uses this same application CMK to unwrap only the
    // issuing-root envelope. Cluster functions remain decrypt-only for
    // payload envelopes and cannot use the issuer encryption context.
    adminFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "clavis",
            "kms:EncryptionContext:purpose": "issuer-ca",
          },
        },
      }),
    );
    clusterFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: [applicationKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:service": "clavis",
            "kms:EncryptionContext:purpose": "secret-payload",
          },
        },
      }),
    );
    auditBucket.grantPut(adminFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(clusterFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(recoveryFunction, `${auditPrefix}/*`);
    auditBucket.grantPut(retentionFunction, `${auditPrefix}/*`);
    grantTruststorePublisher(
      adminFunction,
      truststoreBucket,
      props.clusterFqdn,
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
    const adminApi = new apigatewayv2.HttpApi(this, "AdminApi", {
      apiName: `${prefix}-admin`,
      defaultAuthorizer: authorizer,
      defaultIntegration: new HttpLambdaIntegration(
        "AdminIntegration",
        adminFunction,
      ),
      createDefaultStage: false,
      disableExecuteApiEndpoint: true,
    });
    const clusterApi = new apigatewayv2.HttpApi(this, "ClusterApi", {
      apiName: `${prefix}-cluster`,
      defaultIntegration: new HttpLambdaIntegration(
        "ClusterIntegration",
        clusterFunction,
      ),
      createDefaultStage: false,
      disableExecuteApiEndpoint: true,
    });
    const adminAccessLogs = accessLogGroup(
      this,
      "AdminAccessLogs",
      `${prefix}-admin-access`,
    );
    const clusterAccessLogs = accessLogGroup(
      this,
      "ClusterAccessLogs",
      `${prefix}-cluster-access`,
    );
    const adminStage = new apigatewayv2.HttpStage(this, "AdminStage", {
      httpApi: adminApi,
      accessLogSettings: accessLogSettings(adminAccessLogs),
    });
    const clusterStage = new apigatewayv2.HttpStage(this, "ClusterStage", {
      httpApi: clusterApi,
      accessLogSettings: accessLogSettings(clusterAccessLogs),
    });
    new apigatewayv2.ApiMapping(this, "AdminMapping", {
      api: adminApi,
      domainName: adminDomain,
      stage: adminStage,
    });
    new apigatewayv2.ApiMapping(this, "ClusterMapping", {
      api: clusterApi,
      domainName: clusterDomain,
      stage: clusterStage,
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
      "ClusterAlias",
      zone,
      props.clusterFqdn,
      props.zoneDomain,
      clusterDomain,
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
    new CfnOutput(this, "ClusterUrl", {
      value: `https://${props.clusterFqdn}`,
    });
    new CfnOutput(this, "AdminOidcIssuer", { value: props.oidcIssuer });
    new CfnOutput(this, "AdminOidcAudience", { value: props.oidcAudience });
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
      description: `Clavis ${id}`,
      entry: existsSync(sourceEntry) ? sourceEntry : packagedEntry,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "handler",
      memorySize: 512,
      timeout: Duration.seconds(29),
      tracing: lambda.Tracing.ACTIVE,
      environment,
      bundling: { minify: true, sourceMap: true, target: "node22" },
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
