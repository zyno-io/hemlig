import { App } from "aws-cdk-lib";
import { Annotations, Match, Template } from "aws-cdk-lib/assertions";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import { PKI_METRICS } from "../src/pki/metrics";
import { deploymentConfigFromContext } from "./config";
import { existingIndexKeyAttributes, HemligStack } from "./stack";

const defaultCsp =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "font-src 'self'; connect-src 'self' https://admin.test.example.com https://login.example.com; " +
  "frame-src 'self' https://login.example.com; form-action http://127.0.0.1:*; base-uri 'none'; " +
  "object-src 'none'; frame-ancestors 'none'";
const silentRenewCsp = defaultCsp.replace(
  "frame-ancestors 'none'",
  "frame-ancestors 'self'",
);

type Statement = Record<string, unknown>;

const templateHelpers = (template: Template) => {
  const functions = template.findResources("AWS::Lambda::Function");
  const roleOf = (name: string): string => {
    const entry = Object.values(functions).find(
      (resource) => resource.Properties.FunctionName === name,
    );
    expect(entry).toBeDefined();
    return entry?.Properties.Role["Fn::GetAtt"][0] as string;
  };
  const statementsFor = (roleLogicalId: string): Statement[] =>
    Object.values(template.findResources("AWS::IAM::Policy"))
      .filter((policy) =>
        (policy.Properties.Roles as { Ref: string }[]).some(
          (role) => role.Ref === roleLogicalId,
        ),
      )
      .flatMap(
        (policy) => policy.Properties.PolicyDocument.Statement as Statement[],
      );
  const actionsOf = (statements: Statement[]): string[] =>
    statements.flatMap((statement) =>
      [statement.Action]
        .flat()
        .filter((a): a is string => typeof a === "string"),
    );
  const logicalIdOf = (
    type: string,
    match: Record<string, unknown>,
  ): string => {
    const found = Object.entries(
      template.findResources(type, { Properties: match }),
    );
    expect(found).toHaveLength(1);
    return (found[0] as [string, unknown])[0];
  };
  /** The Lambda logical ID an HTTP API route key invokes. */
  const targetFunctionOf = (routeKey: string): string => {
    const routes = Object.values(
      template.findResources("AWS::ApiGatewayV2::Route", {
        Properties: { RouteKey: routeKey },
      }),
    );
    expect(routes).toHaveLength(1);
    const target = JSON.stringify(
      (routes[0] as { Properties: { Target: unknown } }).Properties.Target,
    );
    const integrationId = /"Ref":"([^"]+)"/.exec(target)?.[1] as string;
    const integration = template.toJSON().Resources[integrationId] as {
      Properties: { IntegrationUri: { "Fn::GetAtt": string[] } };
    };
    return integration.Properties.IntegrationUri["Fn::GetAtt"][0] as string;
  };
  return { roleOf, statementsFor, actionsOf, logicalIdOf, targetFunctionOf };
};

describe("HemligStack", () => {
  it("creates hml-prefixed durable state and custom-domain APIs", () => {
    const app = new App();
    const stack = new HemligStack(app, "hml-test", {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      consoleFqdn: "console.test.example.com",
      consoleCertificateArn:
        "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
      oidcAdminScope: "hemlig.admin",
      oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
      oidcClientId: "console-client",
    });
    const template = Template.fromStack(stack);
    template.hasResourceProperties("AWS::DynamoDB::Table", {
      TableName: "hml-test-control",
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      GlobalSecondaryIndexes: Match.arrayWith([
        Match.objectLike({
          IndexName: "catalog-path",
          KeySchema: [
            { AttributeName: "catalogPk", KeyType: "HASH" },
            { AttributeName: "catalogSk", KeyType: "RANGE" },
          ],
        }),
      ]),
    });
    for (const [indexName, partitionKey, sortKey] of [
      ["consumer-directory", "consumerDirectoryPk", "consumerDirectorySk"],
      ["consumer-identity", "identityConsumerPk", "identityConsumerSk"],
      ["secret-revision", "revisionPk", "revisionSk"],
    ]) {
      template.hasResourceProperties("AWS::DynamoDB::Table", {
        GlobalSecondaryIndexes: Match.arrayWith([
          Match.objectLike({
            IndexName: indexName,
            KeySchema: [
              { AttributeName: partitionKey, KeyType: "HASH" },
              { AttributeName: sortKey, KeyType: "RANGE" },
            ],
          }),
        ]),
      });
    }
    template.resourceCountIs("AWS::S3::Bucket", 5);
    template.resourceCountIs("AWS::KMS::Key", 1);
    const resources = template.toJSON().Resources as Record<
      string,
      {
        readonly DeletionPolicy?: string;
        readonly UpdateReplacePolicy?: string;
      }
    >;
    const retainedResources = Object.entries(resources).filter(
      ([, resource]) =>
        resource.DeletionPolicy === "Retain" ||
        resource.UpdateReplacePolicy === "Retain",
    );
    expect(retainedResources).toEqual([]);
    template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
      DisableExecuteApiEndpoint: true,
    });
    template.resourceCountIs("AWS::Cognito::UserPool", 0);
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      JwtConfiguration: {
        Audience: ["hemlig-api"],
        Issuer: "https://login.example.com/tenant/v2.0",
      },
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
      CorsConfiguration: {
        AllowOrigins: ["https://console.test.example.com"],
        AllowHeaders: [
          "authorization",
          "content-type",
          "idempotency-key",
          "if-match",
          "if-none-match",
        ],
        AllowMethods: ["GET", "POST", "PUT", "DELETE"],
        AllowCredentials: false,
        ExposeHeaders: ["etag", "retry-after"],
        MaxAge: 600,
      },
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "OPTIONS /{proxy+}",
      AuthorizationType: "NONE",
    });
    // The Lambda binds the bearer in this header to the authorizer's claims.
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      AuthorizerType: "JWT",
      IdentitySource: ["$request.header.Authorization"],
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "$default",
      AuthorizationScopes: ["hemlig.admin"],
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "GET /v1/admin/audit",
      AuthorizationType: "JWT",
      AuthorizationScopes: ["hemlig.admin"],
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "s3:ListBucket",
            Condition: { StringLike: { "s3:prefix": ["audit/*"] } },
          }),
          Match.objectLike({ Action: "s3:GetObject" }),
          Match.objectLike({ Action: "s3:PutObject" }),
        ]),
      },
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "POST /v1/bootstrap/redeem",
      AuthorizationType: "NONE",
    });
    template.hasResourceProperties("AWS::IoT::Policy", {
      PolicyName: "hml-test-agent-notifications",
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Action: ["iot:Connect"] }),
          Match.objectLike({ Action: ["iot:Subscribe"] }),
          Match.objectLike({ Action: ["iot:Receive"] }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::Lambda::EventSourceMapping", {
      StartingPosition: "TRIM_HORIZON",
      FilterCriteria: Match.objectLike({
        Filters: Match.arrayWith([
          Match.objectLike({ Pattern: Match.stringLikeRegexp("NOTIFICATION") }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::SQS::Queue", {
      QueueName: "hml-test-notification-dlq",
      SqsManagedSseEnabled: true,
    });
    template.hasResourceProperties("AWS::Events::Rule", {
      Name: "hml-test-recovery",
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "hml-test-admin-access",
      RetentionInDays: 365,
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "hml-test-consumer-access",
      RetentionInDays: 365,
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Stage", {
      AutoDeploy: true,
      DefaultRouteSettings: {
        ThrottlingBurstLimit: 100,
        ThrottlingRateLimit: 50,
      },
      AccessLogSettings: Match.objectLike({
        DestinationArn: Match.anyValue(),
        Format: Match.anyValue(),
      }),
    });
    template.hasOutput("ApiUrl", {
      Value: "https://api.test.example.com",
    });
    // Every truststore publisher must be able to read the exact bundle
    // version it passes to UpdateDomainName.
    const truststorePublisherPolicies = Object.values(
      template.findResources("AWS::IAM::Policy"),
    ).filter((policy) =>
      JSON.stringify(policy).includes("apigateway:AddCertificateToDomain"),
    );
    expect(truststorePublisherPolicies).toHaveLength(3);
    for (const policy of truststorePublisherPolicies) {
      expect(
        policy.Properties.PolicyDocument.Statement.some(
          (statement: { Action?: unknown }) =>
            Array.isArray(statement.Action) &&
            ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"].every(
              (action) => (statement.Action as string[]).includes(action),
            ),
        ),
      ).toBe(true);
    }
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith([
              "apigateway:GET",
              "apigateway:PATCH",
              "apigateway:AddCertificateToDomain",
              "apigateway:RemoveCertificateFromDomain",
            ]),
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::S3::BucketPolicy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: { Service: "apigateway.amazonaws.com" },
            Action: ["s3:GetObject", "s3:GetObjectVersion"],
            Condition: Match.absent(),
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "kms:GenerateDataKey",
            Condition: {
              StringEquals: {
                "kms:EncryptionContext:service": "hemlig",
                "kms:EncryptionContext:purpose": Match.arrayWith([
                  "secret-payload",
                ]),
              },
            },
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "kms:Decrypt",
            Condition: {
              StringEquals: {
                "kms:EncryptionContext:service": "hemlig",
                "kms:EncryptionContext:purpose": "secret-payload",
              },
            },
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "kms:Decrypt",
            Condition: {
              StringEquals: {
                "kms:EncryptionContext:service": "hemlig",
                "kms:EncryptionContext:purpose": "issuer-ca",
              },
            },
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith(["s3:GetObjectVersion"]),
          }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      Roles: Match.arrayWith([
        {
          Ref: Match.stringLikeRegexp("^BootstrapFunctionServiceRole"),
        },
      ]),
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: [
              "s3:GetObject",
              "s3:GetObjectVersion",
              "s3:GetObjectRetention",
              "s3:PutObject",
              "s3:PutObjectRetention",
            ],
          }),
        ]),
      }),
    });

    template.resourceCountIs("AWS::CloudFront::Distribution", 1);
    template.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Aliases: ["console.test.example.com"],
        DefaultRootObject: "index.html",
        CustomErrorResponses: Match.arrayWith([
          Match.objectLike({
            ErrorCode: 403,
            ResponseCode: 200,
            ResponsePagePath: "/index.html",
            ErrorCachingMinTTL: 0,
          }),
          Match.objectLike({
            ErrorCode: 404,
            ResponseCode: 200,
            ResponsePagePath: "/index.html",
            ErrorCachingMinTTL: 0,
          }),
        ]),
      }),
    });
    template.resourceCountIs("AWS::CloudFront::ResponseHeadersPolicy", 3);
    // Match.stringLikeRegexp is an unanchored partial match: appending
    // " https://evil.example.com" to connect-src, or a stray '.' matching any
    // character, would still pass it. Assert the exact string instead, and
    // separately assert no directive is ever a wildcard.
    template.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        Name: "hml-test-console",
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: {
            ContentSecurityPolicy: defaultCsp,
            Override: true,
          },
          FrameOptions: { FrameOption: "DENY", Override: true },
          StrictTransportSecurity: {
            AccessControlMaxAgeSec: 63072000,
            IncludeSubdomains: true,
            Override: true,
            Preload: true,
          },
        }),
        CustomHeadersConfig: {
          Items: Match.arrayWith([
            { Header: "Cache-Control", Value: "no-store", Override: true },
            {
              Header: "Permissions-Policy",
              Value: "camera=(), microphone=(), geolocation=()",
              Override: true,
            },
          ]),
        },
      }),
    });
    template.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        Name: "hml-test-console-silent-renew",
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: {
            ContentSecurityPolicy: silentRenewCsp,
            Override: true,
          },
          FrameOptions: { FrameOption: "SAMEORIGIN", Override: true },
        }),
        CustomHeadersConfig: {
          Items: Match.arrayWith([
            { Header: "Cache-Control", Value: "no-store", Override: true },
          ]),
        },
      }),
    });
    template.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        Name: "hml-test-console-assets",
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: {
            ContentSecurityPolicy: defaultCsp,
            Override: true,
          },
        }),
        CustomHeadersConfig: {
          Items: Match.arrayWith([
            {
              Header: "Cache-Control",
              Value: "public, max-age=31536000, immutable",
              Override: true,
            },
          ]),
        },
      }),
    });

    const headersPolicies = template.findResources(
      "AWS::CloudFront::ResponseHeadersPolicy",
    );
    for (const [, policy] of Object.entries(headersPolicies)) {
      const csp = policy.Properties.ResponseHeadersPolicyConfig
        .SecurityHeadersConfig.ContentSecurityPolicy
        .ContentSecurityPolicy as string;
      // The only wildcard is the loopback port in form-action (hemlig login relay).
      expect(csp).toContain("form-action http://127.0.0.1:*;");
      expect(csp.replace("http://127.0.0.1:*", "")).not.toContain("*");
    }

    // Nothing else binds a response-headers policy to a behavior: swapping the
    // policy assigned to the default behavior vs. a path pattern would put
    // frame-ancestors 'self' on the whole site with every other assertion above
    // still passing, since they only check that *some* behavior uses each policy.
    const logicalIdForPolicyName = (name: string): string => {
      const entry = Object.entries(headersPolicies).find(
        ([, resource]) =>
          resource.Properties.ResponseHeadersPolicyConfig.Name === name,
      );
      if (entry === undefined) {
        throw new Error(`no ResponseHeadersPolicy named ${name}`);
      }
      return entry[0];
    };
    const consoleHeadersId = logicalIdForPolicyName("hml-test-console");
    const silentRenewHeadersId = logicalIdForPolicyName(
      "hml-test-console-silent-renew",
    );
    const assetHeadersId = logicalIdForPolicyName("hml-test-console-assets");

    const distributions = template.findResources(
      "AWS::CloudFront::Distribution",
    );
    const distributionConfig = Object.values(distributions)[0]?.Properties
      .DistributionConfig as {
      DefaultCacheBehavior: {
        CachePolicyId: string;
        ResponseHeadersPolicyId: { Ref: string };
      };
      CacheBehaviors: Array<{
        PathPattern: string;
        CachePolicyId: string;
        ResponseHeadersPolicyId: { Ref: string };
      }>;
    };
    const behaviorFor = (pathPattern: string) => {
      const behavior = distributionConfig.CacheBehaviors.find(
        (candidate) => candidate.PathPattern === pathPattern,
      );
      if (behavior === undefined) {
        throw new Error(`no CacheBehaviors entry for ${pathPattern}`);
      }
      return behavior;
    };

    // CloudFront matches a behavior from the request URI before defaultRootObject
    // is applied, so "/" and every unmatched SPA route hit the default behavior:
    // it must be uncached (fix for the app shell getting pinned in the edge cache).
    expect(distributionConfig.DefaultCacheBehavior.CachePolicyId).toBe(
      cloudfront.CachePolicy.CACHING_DISABLED.cachePolicyId,
    );
    expect(
      distributionConfig.DefaultCacheBehavior.ResponseHeadersPolicyId,
    ).toEqual({
      Ref: consoleHeadersId,
    });

    expect(behaviorFor("/assets/*").CachePolicyId).toBe(
      cloudfront.CachePolicy.CACHING_OPTIMIZED.cachePolicyId,
    );
    expect(behaviorFor("/assets/*").ResponseHeadersPolicyId).toEqual({
      Ref: assetHeadersId,
    });
    expect(behaviorFor("/silent.html").CachePolicyId).toBe(
      cloudfront.CachePolicy.CACHING_DISABLED.cachePolicyId,
    );
    expect(behaviorFor("/silent.html").ResponseHeadersPolicyId).toEqual({
      Ref: silentRenewHeadersId,
    });
    expect(behaviorFor("/config.json").ResponseHeadersPolicyId).toEqual({
      Ref: consoleHeadersId,
    });
    expect(behaviorFor("/index.html").ResponseHeadersPolicyId).toEqual({
      Ref: consoleHeadersId,
    });

    const buckets = template.findResources("AWS::S3::Bucket");
    const consoleBucket = Object.entries(buckets).find(([id]) =>
      id.startsWith("ConsoleBucket"),
    )?.[1];
    expect(consoleBucket).toBeDefined();
    expect(consoleBucket?.Properties.PublicAccessBlockConfiguration).toEqual({
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    });
    // Versioned with prune: false, so a superseded asset version is never deleted
    // by the deployment itself and would otherwise accumulate forever.
    expect(consoleBucket?.Properties.LifecycleConfiguration).toEqual({
      Rules: [
        {
          NoncurrentVersionExpiration: { NoncurrentDays: 30 },
          Status: "Enabled",
        },
      ],
    });
  });

  it("does not create a Secrets Manager secret for pagination", () => {
    const app = new App();
    const stack = new HemligStack(app, "hml-no-cursor-secret", {
      environmentName: "prod",
      adminFqdn: "admin.example.com",
      apiFqdn: "api.example.com",
      zoneDomain: "example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
    });
    const template = Template.fromStack(stack);
    template.resourceCountIs("AWS::SecretsManager::Secret", 0);
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: ["dynamodb:GetItem", "dynamodb:PutItem"],
            Condition: {
              "ForAllValues:StringLike": {
                "dynamodb:LeadingKeys": ["CURSOR#*"],
              },
            },
          }),
        ]),
      }),
    });
  });

  it("isolates agent identity rotation in a least-privilege Lambda", () => {
    const app = new App();
    const stack = new HemligStack(app, "hml-test", {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
    });
    const template = Template.fromStack(stack);
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "POST /v1/agent/identities/rotate",
      AuthorizationType: "NONE",
    });
    template.hasResourceProperties("AWS::Lambda::Permission", {
      FunctionName: Match.anyValue(),
      SourceArn: Match.objectLike({
        "Fn::Join": Match.arrayWith([
          Match.arrayWith([
            Match.stringLikeRegexp("/v1/agent/identities/rotate$"),
          ]),
        ]),
      }),
    });

    const { roleOf, statementsFor, actionsOf } = templateHelpers(template);

    const rotation = statementsFor(roleOf("hml-test-identity-rotation"));
    const rotationActions = actionsOf(rotation);
    expect(rotation).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Action: "kms:Decrypt",
          Condition: {
            StringEquals: {
              "kms:EncryptionContext:service": "hemlig",
              "kms:EncryptionContext:purpose": "issuer-ca",
            },
          },
        }),
      ]),
    );
    expect(rotationActions).toEqual(
      expect.arrayContaining([
        "iot:AttachPolicy",
        "iot:AttachThingPrincipal",
        "iot:CreateThing",
        "iot:DescribeCertificate",
        "iot:RegisterCertificateWithoutCA",
        "iot:UpdateCertificate",
      ]),
    );
    expect(actionsOf(statementsFor(roleOf("hml-test-admin")))).toEqual(
      expect.arrayContaining([
        "iot:RegisterCertificateWithoutCA",
        "iot:UpdateCertificate",
      ]),
    );
    expect(
      rotationActions.some((action) =>
        action.startsWith("kms:GenerateDataKey"),
      ),
    ).toBe(false);
    expect(
      rotationActions.some((action) => action.startsWith("apigateway:")),
    ).toBe(false);
    // Only the audit prefix may be written to; no revision or truststore bucket access.
    const s3Resources = JSON.stringify(
      rotation.filter((statement) =>
        [statement.Action]
          .flat()
          .some((a) => typeof a === "string" && a.startsWith("s3:")),
      ),
    );
    expect(s3Resources).not.toContain("RevisionBucket");
    expect(s3Resources).not.toContain("Truststore");
    expect(JSON.stringify(rotation)).not.toContain("secret-payload");

    const consumerStatements = statementsFor(roleOf("hml-test-consumer"));
    expect(JSON.stringify(consumerStatements)).not.toContain("issuer-ca");
  });

  it("adopts an explicitly supplied application key while still creating its alias", () => {
    const app = new App();
    const stack = new HemligStack(app, "hml-adopted-key", {
      environmentName: "prod",
      adminFqdn: "admin.example.com",
      apiFqdn: "api.example.com",
      zoneDomain: "example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
      existingApplicationKeyArn:
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    });
    const template = Template.fromStack(stack);
    template.resourceCountIs("AWS::KMS::Key", 0);
    template.resourceCountIs("AWS::KMS::Alias", 1);
  });

  it("leaves X-Ray tracing off unless tracing is enabled", () => {
    const base = {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
    };
    const off = Template.fromStack(
      new HemligStack(new App(), "hml-test-trace-off", base),
    );
    const offFunctions = Object.values(
      off.findResources("AWS::Lambda::Function"),
    ) as { Properties: { TracingConfig?: unknown } }[];
    expect(offFunctions.length).toBeGreaterThan(0);
    for (const fn of offFunctions) {
      expect(fn.Properties.TracingConfig).toBeUndefined();
    }
    expect(JSON.stringify(off.toJSON())).not.toContain("xray:PutTraceSegments");

    const on = Template.fromStack(
      new HemligStack(new App(), "hml-test-trace-on", {
        ...base,
        tracing: true,
      }),
    );
    // Only Hemlig's own functions; CDK helper Lambdas are not affected.
    const onFunctions = (
      Object.values(on.findResources("AWS::Lambda::Function")) as {
        Properties: {
          Description?: unknown;
          TracingConfig?: { Mode?: string };
        };
      }[]
    ).filter((fn) =>
      JSON.stringify(fn.Properties.Description ?? "").includes("Hemlig "),
    );
    expect(onFunctions).toHaveLength(11);
    for (const fn of onFunctions) {
      expect(fn.Properties.TracingConfig).toEqual({ Mode: "Active" });
    }
  });

  it("skips console hosting entirely when consoleFqdn is not configured", () => {
    const app = new App();
    const stack = new HemligStack(app, "hml-test-no-console", {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
    });
    const template = Template.fromStack(stack);
    template.resourceCountIs("AWS::CloudFront::Distribution", 0);
    template.resourceCountIs("AWS::CloudFront::ResponseHeadersPolicy", 0);
    template.resourceCountIs("AWS::S3::Bucket", 4);
  });

  describe("console certificate resolution", () => {
    const baseProps = {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      consoleFqdn: "console.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
      oidcAdminScope: "hemlig.admin",
      oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
      oidcClientId: "console-client",
    };

    it("throws the dependency-cycle guard when the stack creates its own hosted zone and supplies no consoleCertificateArn", () => {
      const app = new App();
      expect(
        () =>
          new HemligStack(app, "hml-test", {
            ...baseProps,
            env: { account: "123456789012", region: "us-west-2" },
          }),
      ).toThrow(/hosted zone this stack also creates/);
    });

    it("throws the unresolved-region guard when the stack is region-agnostic and supplies no consoleCertificateArn", () => {
      const app = new App();
      expect(() => new HemligStack(app, "hml-test", { ...baseProps })).toThrow(
        /concrete stack region/,
      );
    });

    it("creates a sibling us-east-1 certificate stack for an imported hosted zone, a concrete env, and no consoleCertificateArn", () => {
      const app = new App();
      new HemligStack(app, "hml-test", {
        ...baseProps,
        existingHostedZoneId: "Z0123456789ABCDEF",
        env: { account: "123456789012", region: "us-west-2" },
      });
      const assembly = app.synth();
      expect(assembly.stacks).toHaveLength(2);
      const certificateStack = assembly.stacks.find(
        (candidate) => candidate.stackName !== "hml-test",
      );
      expect(certificateStack).toBeDefined();
      expect(certificateStack?.environment.region).toBe("us-east-1");
    });
  });
  describe("PKI", () => {
    const pkiProps = {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      consoleFqdn: "console.test.example.com",
      consoleCertificateArn:
        "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
      oidcAdminScope: "hemlig.admin",
      oidcConsoleAccessScope: "api://hemlig-api/hemlig.admin",
      oidcClientId: "console-client",
    };
    const plainProps = {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      apiFqdn: "api.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "hemlig-api",
      oidcSubjectClaim: "sub",
    };
    let template: Template;
    let helpers: ReturnType<typeof templateHelpers>;
    let tableId: string;
    let keyId: string;
    let pkiBucketId: string;
    let tableArn: unknown;
    let indexArn: unknown;
    let keyArn: unknown;

    beforeAll(() => {
      template = Template.fromStack(
        new HemligStack(new App(), "hml-test", {
          ...pkiProps,
          oidcPkiCaAdminRole: "hemlig-pki-ca-admin",
          oidcPkiOperatorRole: "hemlig-pki-operator",
        }),
      );
      helpers = templateHelpers(template);
      tableId = helpers.logicalIdOf("AWS::DynamoDB::Table", {
        TableName: "hml-test-control",
      });
      keyId = Object.keys(template.findResources("AWS::KMS::Key"))[0] as string;
      pkiBucketId = helpers.logicalIdOf("AWS::S3::Bucket", {
        BucketNamePrefix: "hml-test-pki",
      });
      tableArn = { "Fn::GetAtt": [tableId, "Arn"] };
      indexArn = {
        "Fn::Join": ["", [tableArn, "/index/pki-directory"]],
      };
      keyArn = { "Fn::GetAtt": [keyId, "Arn"] };
    }, 120_000);

    const lambdaProps = (name: string): Record<string, any> => {
      const entry = Object.values(
        template.findResources("AWS::Lambda::Function"),
      ).find((resource) => resource.Properties.FunctionName === name);
      expect(entry).toBeDefined();
      return (entry as { Properties: Record<string, any> }).Properties;
    };
    const roleStatements = (name: string): Statement[] =>
      helpers.statementsFor(helpers.roleOf(name));
    const leading = (
      operator: "ForAllValues:StringLike" | "ForAnyValue:StringLike",
      keys: string[],
    ) => ({ [operator]: { "dynamodb:LeadingKeys": keys } });
    const allow = (
      actions: string[],
      resources: unknown[],
      keys: string[],
    ): Statement => ({
      Action: actions.length === 1 ? actions[0] : actions,
      Condition: leading("ForAllValues:StringLike", keys),
      Effect: "Allow",
      Resource: resources.length === 1 ? resources[0] : resources,
    });
    const identityDeny = (): Statement => ({
      Action: [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
      ],
      Condition: leading("ForAnyValue:StringLike", [
        "IDENTITY#*",
        "CONSUMER#*",
        "AGENT_GRANT#*",
        "TRUSTSTORE#*",
        "SYSTEM#*",
        "ENROLLMENT#*",
        "BOOTSTRAP#*",
      ]),
      Effect: "Deny",
      Resource: tableArn,
    });
    const attributeDeny = (attributes: string[]): Statement => ({
      Action: [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:BatchWriteItem",
      ],
      Condition: {
        "ForAnyValue:StringEquals": { "dynamodb:Attributes": attributes },
      },
      Effect: "Deny",
      Resource: tableArn,
    });
    const kmsStatement = (actions: string[]): Statement => ({
      Action: actions.length === 1 ? actions[0] : actions,
      Condition: {
        StringEquals: {
          "kms:EncryptionContext:service": "hemlig",
          "kms:EncryptionContext:purpose": "pki-ca",
        },
        "ForAllValues:StringEquals": {
          "kms:EncryptionContextKeys": [
            "service",
            "purpose",
            "caId",
            "environment",
          ],
        },
        Null: {
          "kms:EncryptionContext:caId": "false",
          "kms:EncryptionContext:environment": "false",
        },
      },
      Effect: "Allow",
      Resource: keyArn,
    });
    const crlObjects = () => ({
      "Fn::Join": ["", [{ "Fn::GetAtt": [pkiBucketId, "Arn"] }, "/crl/*"]],
    });
    const tableStatements = (
      reads: string[],
      pointReads: string[],
      writes: string[],
      checks: string[],
    ): Statement[] => [
      allow(
        ["dynamodb:GetItem", "dynamodb:Query"],
        [tableArn, indexArn],
        reads,
      ),
      ...(pointReads.length === 0
        ? []
        : [allow(["dynamodb:GetItem"], [tableArn], pointReads)]),
      allow(["dynamodb:PutItem", "dynamodb:UpdateItem"], [tableArn], writes),
      allow(["dynamodb:ConditionCheckItem"], [tableArn], checks),
      identityDeny(),
      attributeDeny(existingIndexKeyAttributes),
    ];
    const sorted = (statements: Statement[]): string[] =>
      statements.map((statement) => JSON.stringify(statement)).sort();

    it("adds the sparse pki-directory index", () => {
      template.hasResourceProperties("AWS::DynamoDB::Table", {
        TableName: "hml-test-control",
        GlobalSecondaryIndexes: Match.arrayWith([
          {
            IndexName: "pki-directory",
            KeySchema: [
              { AttributeName: "pkiDirectoryPk", KeyType: "HASH" },
              { AttributeName: "pkiDirectorySk", KeyType: "RANGE" },
            ],
            Projection: { ProjectionType: "ALL" },
          },
        ]),
        AttributeDefinitions: Match.arrayWith([
          { AttributeName: "pkiDirectoryPk", AttributeType: "S" },
          { AttributeName: "pkiDirectorySk", AttributeType: "S" },
        ]),
      });
    });

    it("denies PKI roles the key attributes of every existing index", () => {
      const table = template.toJSON().Resources[tableId] as {
        Properties: {
          GlobalSecondaryIndexes: {
            IndexName: string;
            KeySchema: { AttributeName: string }[];
          }[];
        };
      };
      const actual = table.Properties.GlobalSecondaryIndexes.filter(
        (index) => index.IndexName !== "pki-directory",
      ).flatMap((index) => index.KeySchema.map((key) => key.AttributeName));
      expect(actual).toHaveLength(12);
      expect([...existingIndexKeyAttributes].sort()).toEqual(actual.sort());
    });

    it("creates the three PKI Lambdas with PKI-only environment", () => {
      for (const kind of ["admin", "issuer", "maintenance"]) {
        const props = lambdaProps(`hml-test-pki-${kind}`);
        expect(props.Runtime).toBe("nodejs24.x");
        // CRL self-verification of up to 12,000 entries needs more than 512 MB.
        expect(props.MemorySize).toBe(1024);
        // Maintenance publishes CRLs and runs up to five minutes; the request Lambdas stay at 29 s.
        expect(props.Timeout).toBe(kind === "maintenance" ? 300 : 29);
        const variables = props.Environment.Variables;
        expect(variables.PKI_DIRECTORY_INDEX).toBe("pki-directory");
        expect(variables.PKI_BUCKET_NAME).toEqual({ Ref: pkiBucketId });
        if (kind === "admin") {
          expect(variables.ADMIN_PKI_CA_ROLE).toBe("hemlig-pki-ca-admin");
          expect(variables.ADMIN_PKI_OPERATOR_ROLE).toBe("hemlig-pki-operator");
        } else {
          expect(variables).not.toHaveProperty("ADMIN_PKI_CA_ROLE");
          expect(variables).not.toHaveProperty("ADMIN_PKI_OPERATOR_ROLE");
        }
      }
      for (const resource of Object.values(
        template.findResources("AWS::Lambda::Function"),
      )) {
        const name = resource.Properties.FunctionName as string | undefined;
        if (
          name !== undefined &&
          !/-pki-(admin|issuer|maintenance)$/.test(name)
        ) {
          expect(
            resource.Properties.Environment?.Variables ?? {},
          ).not.toHaveProperty("PKI_BUCKET_NAME");
          expect(
            resource.Properties.Environment?.Variables ?? {},
          ).not.toHaveProperty("PKI_DIRECTORY_INDEX");
        }
      }
    });

    it("omits the PKI role variables unless configured", () => {
      const plain = Template.fromStack(
        new HemligStack(new App(), "hml-test-plain", plainProps),
      );
      const admin = Object.values(
        plain.findResources("AWS::Lambda::Function"),
      ).find(
        (resource) => resource.Properties.FunctionName === "hml-test-pki-admin",
      );
      expect(admin?.Properties.Environment.Variables).not.toHaveProperty(
        "ADMIN_PKI_CA_ROLE",
      );
    }, 120_000);

    it("routes PKI paths with explicit methods and never ANY", () => {
      const routes = Object.values(
        template.findResources("AWS::ApiGatewayV2::Route"),
      ).map(
        (route) =>
          route.Properties as {
            RouteKey: string;
            AuthorizationType: string;
            AuthorizationScopes?: string[];
          },
      );
      const adminKeys = ["GET", "POST", "PUT", "DELETE"].map(
        (method) => `${method} /v1/admin/pki/{proxy+}`,
      );
      for (const key of adminKeys) {
        const route = routes.find((candidate) => candidate.RouteKey === key);
        expect(route?.AuthorizationType).toBe("JWT");
        expect(route?.AuthorizationScopes).toEqual(["hemlig.admin"]);
        expect(helpers.targetFunctionOf(key)).toBe(
          helpers.logicalIdOf("AWS::Lambda::Function", {
            FunctionName: "hml-test-pki-admin",
          }),
        );
      }
      for (const key of ["GET /v1/pki/{proxy+}", "POST /v1/pki/{proxy+}"]) {
        const route = routes.find((candidate) => candidate.RouteKey === key);
        expect(route?.AuthorizationType).toBe("NONE");
        expect(helpers.targetFunctionOf(key)).toBe(
          helpers.logicalIdOf("AWS::Lambda::Function", {
            FunctionName: "hml-test-pki-issuer",
          }),
        );
      }
      expect(
        routes.filter((route) => route.RouteKey.includes("/pki/")),
      ).toHaveLength(6);
      expect(
        routes.find((route) => route.RouteKey === "OPTIONS /{proxy+}"),
      ).toBeDefined();
      expect(
        routes.filter((route) => route.RouteKey.startsWith("ANY ")),
      ).toEqual([]);
    });

    it("throttles issuance on the consumer stage", () => {
      const stages = Object.values(
        template.findResources("AWS::ApiGatewayV2::Stage"),
      ) as { Properties: Record<string, unknown>; DependsOn?: string[] }[];
      const withSettings = stages.filter(
        (stage) => stage.Properties.RouteSettings !== undefined,
      );
      expect(withSettings).toHaveLength(1);
      const [stage] = withSettings as [(typeof withSettings)[0]];
      expect(stage.Properties.RouteSettings).toEqual({
        "POST /v1/pki/{proxy+}": {
          ThrottlingRateLimit: 20,
          ThrottlingBurstLimit: 40,
        },
      });
      expect(stage.DependsOn ?? []).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^ConsumerApiPOSTv1pki/),
        ]),
      );
    });

    it("propagates a custom throttle and rejects invalid ones", () => {
      const custom = Template.fromStack(
        new HemligStack(new App(), "hml-test-throttle", {
          ...plainProps,
          pkiIssuanceRateLimit: 5,
          pkiIssuanceBurstLimit: 10,
        }),
      );
      const stage = Object.values(
        custom.findResources("AWS::ApiGatewayV2::Stage"),
      ).find((candidate) => candidate.Properties.RouteSettings !== undefined);
      expect(stage?.Properties.RouteSettings).toEqual({
        "POST /v1/pki/{proxy+}": {
          ThrottlingRateLimit: 5,
          ThrottlingBurstLimit: 10,
        },
      });
      expect(
        () =>
          new HemligStack(new App(), "hml-test-bad-rate", {
            ...plainProps,
            pkiIssuanceRateLimit: 0,
          }),
      ).toThrow("pkiIssuanceRateLimit must be an integer from 1 to 5000.");
      expect(
        () =>
          new HemligStack(new App(), "hml-test-bad-burst", {
            ...plainProps,
            pkiIssuanceRateLimit: 50,
            pkiIssuanceBurstLimit: 10,
          }),
      ).toThrow("pkiIssuanceBurstLimit must be at least pkiIssuanceRateLimit.");
    }, 120_000);

    it("creates a private, versioned PKI bucket", () => {
      template.hasResourceProperties("AWS::S3::Bucket", {
        BucketNamePrefix: "hml-test-pki",
        BucketNamespace: "account-regional",
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            { ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } },
          ],
        },
        VersioningConfiguration: { Status: "Enabled" },
      });
      const bucket = template.toJSON().Resources[pkiBucketId] as {
        DeletionPolicy?: string;
        UpdateReplacePolicy?: string;
      };
      expect(bucket.DeletionPolicy).toBe("Delete");
      const policy = Object.values(
        template.findResources("AWS::S3::BucketPolicy", {
          Properties: { Bucket: { Ref: pkiBucketId } },
        }),
      )[0] as { Properties: { PolicyDocument: { Statement: Statement[] } } };
      expect(policy.Properties.PolicyDocument.Statement).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            Effect: "Deny",
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          }),
        ]),
      );
      template.hasOutput("PkiBucketName", { Value: { Ref: pkiBucketId } });
    });

    it("runs maintenance every 15 minutes", () => {
      template.hasResourceProperties("AWS::Events::Rule", {
        Name: "hml-test-pki-maintenance",
        ScheduleExpression: "rate(15 minutes)",
        Targets: [
          Match.objectLike({
            Arn: {
              "Fn::GetAtt": [
                helpers.logicalIdOf("AWS::Lambda::Function", {
                  FunctionName: "hml-test-pki-maintenance",
                }),
                "Arn",
              ],
            },
          }),
        ],
      });
    });

    it("defines the PKI alarms", () => {
      const alarms = Object.values(
        template.findResources("AWS::CloudWatch::Alarm"),
      ).map((alarm) => alarm.Properties as Record<string, any>);
      expect(alarms).toHaveLength(11);
      const pki = alarms.filter((alarm) =>
        String(alarm.AlarmName).startsWith("hml-test-pki-"),
      );
      expect(pki).toHaveLength(10);
      const missed = pki.find(
        (alarm) => alarm.AlarmName === "hml-test-pki-maintenance-missed",
      );
      expect(missed).toMatchObject({
        MetricName: "Invocations",
        Namespace: "AWS/Lambda",
        Period: 900,
        EvaluationPeriods: 3,
        DatapointsToAlarm: 3,
        ComparisonOperator: "LessThanThreshold",
        TreatMissingData: "breaching",
        Threshold: 1,
      });
      for (const alarm of pki.filter((candidate) => candidate !== missed)) {
        expect(alarm).toMatchObject({
          Threshold: 1,
          ComparisonOperator: "GreaterThanOrEqualToThreshold",
          EvaluationPeriods: 1,
          TreatMissingData: "notBreaching",
        });
        expect(alarm.AlarmActions).toBeUndefined();
      }
      expect(
        pki.find((a) => a.AlarmName === "hml-test-pki-maintenance-errors"),
      ).toMatchObject({ MetricName: "Errors", Period: 900, Statistic: "Sum" });
      const custom = pki.filter((alarm) => alarm.Namespace === "Hemlig/PKI");
      expect(custom.map((alarm) => alarm.MetricName).sort()).toEqual(
        Object.values(PKI_METRICS).sort(),
      );
      for (const alarm of custom) {
        expect(alarm.Dimensions).toEqual([
          { Name: "Deployment", Value: "test" },
        ]);
      }
    });

    it("grants each PKI role exactly the explicit statements", () => {
      const auditPut = (statements: Statement[]): Statement[] =>
        statements.filter((statement) =>
          JSON.stringify(statement).includes("audit/*"),
        );
      const admin = roleStatements("hml-test-pki-admin");
      const issuer = roleStatements("hml-test-pki-issuer");
      const maintenance = roleStatements("hml-test-pki-maintenance");
      const withoutAudit = (statements: Statement[]): Statement[] =>
        statements.filter(
          (statement) =>
            !JSON.stringify(statement).includes("audit/*") &&
            !JSON.stringify(statement).includes("xray") &&
            !JSON.stringify(statement).includes("logs:"),
        );
      const objects = (write: boolean): Statement => ({
        Action: write
          ? ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
          : ["s3:GetObject", "s3:GetObjectVersion"],
        Effect: "Allow",
        Resource: crlObjects(),
      });
      expect(sorted(withoutAudit(admin))).toEqual(
        sorted([
          ...tableStatements(
            ["PKI_*", "IDEMPOTENCY#human#*"],
            [
              "CONSUMER#*",
              "AGENT_GRANT#*",
              "SYSTEM#ISSUER",
              "SYSTEM#ENVIRONMENTS",
            ],
            ["PKI_*", "IDEMPOTENCY#human#*"],
            ["PKI_*"],
          ),
          kmsStatement(["kms:GenerateDataKey", "kms:Decrypt"]),
          objects(true),
        ]),
      );
      expect(sorted(withoutAudit(issuer))).toEqual(
        sorted([
          ...tableStatements(
            ["PKI_*"],
            ["CONSUMER#*", "IDENTITY#*", "AGENT_GRANT#*"],
            ["PKI_*", "AUDIT_SUPPRESS#*"],
            ["PKI_*", "IDENTITY#*", "AGENT_GRANT#*"],
          ),
          kmsStatement(["kms:Decrypt"]),
          objects(false),
        ]),
      );
      expect(sorted(withoutAudit(maintenance))).toEqual(
        sorted([
          ...tableStatements(["PKI_*"], [], ["PKI_*"], ["PKI_*"]),
          kmsStatement(["kms:Decrypt"]),
          objects(true),
        ]),
      );
      for (const statements of [admin, issuer, maintenance]) {
        expect(auditPut(statements).length).toBeGreaterThan(0);
      }
    });

    it("keeps PKI roles inside their guardrails", () => {
      const forbidden = [
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:GetRecords",
        "dynamodb:DescribeTable",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:*",
      ];
      for (const name of [
        "hml-test-pki-admin",
        "hml-test-pki-issuer",
        "hml-test-pki-maintenance",
      ]) {
        const statements = roleStatements(name);
        const allowed = statements.filter(
          (statement) => statement.Effect === "Allow",
        );
        const actions = helpers.actionsOf(allowed);
        for (const action of actions) {
          expect(forbidden).not.toContain(action);
          expect(action).not.toMatch(/^(iot|apigateway):/);
          expect(action).not.toMatch(/^dynamodb:PartiQL/);
        }
        for (const statement of allowed) {
          const dynamoActions = helpers
            .actionsOf([statement])
            .filter((action) => action.startsWith("dynamodb:"));
          if (dynamoActions.length > 0) {
            expect(statement.Condition).toHaveProperty([
              "ForAllValues:StringLike",
              "dynamodb:LeadingKeys",
            ]);
            for (const action of dynamoActions) {
              expect([
                "dynamodb:GetItem",
                "dynamodb:Query",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:ConditionCheckItem",
              ]).toContain(action);
            }
          }
        }
        const json = JSON.stringify(statements);
        expect(json).not.toContain("issuer-ca");
        expect(json).not.toContain("secret-payload");
        for (const bucket of ["TruststoreBucket", "RevisionBucket"]) {
          expect(json).not.toContain(bucket);
        }
      }
      const kmsActions = (name: string): string[] =>
        helpers.actionsOf(
          roleStatements(name).filter((statement) =>
            helpers.actionsOf([statement]).some((a) => a.startsWith("kms:")),
          ),
        );
      expect(kmsActions("hml-test-pki-issuer")).toEqual(["kms:Decrypt"]);
      expect(kmsActions("hml-test-pki-maintenance")).toEqual(["kms:Decrypt"]);
      expect(
        JSON.stringify(roleStatements("hml-test-pki-issuer")).includes(
          "pki-ca",
        ),
      ).toBe(true);
      // The issuer holds no PKI bucket write: its only s3:PutObject is the audit put.
      expect(
        roleStatements("hml-test-pki-issuer").filter(
          (statement) =>
            JSON.stringify(statement).includes("/crl/*") &&
            helpers.actionsOf([statement]).includes("s3:PutObject"),
        ),
      ).toEqual([]);
    });

    it("denies every existing role PKI_* writes and never grants pki-ca", () => {
      for (const name of [
        "admin",
        "audit-query",
        "consumer",
        "bootstrap",
        "identity-rotation",
        "notification-publisher",
        "recovery",
        "retention",
      ]) {
        const statements = roleStatements(`hml-test-${name}`);
        expect(statements).toEqual(
          expect.arrayContaining([
            {
              Action: [
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:BatchWriteItem",
              ],
              Condition: leading("ForAnyValue:StringLike", ["PKI_*"]),
              Effect: "Deny",
              Resource: tableArn,
            },
            attributeDeny(["pkiDirectoryPk", "pkiDirectorySk"]),
          ]),
        );
        const json = JSON.stringify(statements);
        expect(json).not.toContain("pki-ca");
        expect(json).not.toContain(pkiBucketId);
        for (const statement of statements) {
          if (
            statement.Effect !== "Deny" &&
            helpers.actionsOf([statement]).some((a) => a.startsWith("kms:"))
          ) {
            expect(statement.Condition).toHaveProperty([
              "StringEquals",
              "kms:EncryptionContext:purpose",
            ]);
          }
        }
      }
      const everything = JSON.stringify(template.toJSON());
      const policies = Object.values(
        template.findResources("AWS::IAM::Policy"),
      );
      const carrying = policies.filter((policy) =>
        JSON.stringify(policy).includes("pki-ca"),
      );
      expect(carrying).toHaveLength(3);
      expect(everything).toContain("pki-ca");
    });
  });
});

describe("OIDC context defaults reach the synthesized template", () => {
  const base: Record<string, string> = {
    environment: "test",
    adminFqdn: "admin.test.example.com",
    apiFqdn: "api.test.example.com",
    consoleFqdn: "console.test.example.com",
    consoleCertificateArn:
      "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
    zoneDomain: "test.example.com",
    oidcIssuer: "https://login.microsoftonline.com/tenant/v2.0",
    oidcSubjectClaim: "oid",
    oidcAdminScope: "hemlig.admin",
    oidcAdminRole: "Hemlig.Administrator",
  };
  const synth = (values: Record<string, string>): unknown => {
    const config = deploymentConfigFromContext({
      tryGetContext: (name: string) => values[name],
    });
    return Template.fromStack(
      new HemligStack(new App(), "hml-test", config),
    ).toJSON();
  };

  it("one-app context minus the derivable fields is byte-identical to the explicit one", () => {
    const explicit = synth({
      ...base,
      oidcAudience: "app-id",
      oidcConsoleAccessScope: "api://app-id/hemlig.admin",
      oidcClientId: "app-id",
    });
    const derived = synth({ ...base, oidcClientId: "app-id" });
    expect(JSON.stringify(derived)).toBe(JSON.stringify(explicit));
  });

  it("two-app explicit context equals the template built from the literal props, as on main", () => {
    const explicit = synth({
      ...base,
      oidcAudience: "api-id",
      oidcConsoleAccessScope: "api://api-id/hemlig.admin",
      oidcClientId: "console-id",
    });
    const literal = Template.fromStack(
      new HemligStack(new App(), "hml-test", {
        environmentName: "test",
        adminFqdn: "admin.test.example.com",
        apiFqdn: "api.test.example.com",
        consoleFqdn: "console.test.example.com",
        consoleCertificateArn: base.consoleCertificateArn as string,
        zoneDomain: "test.example.com",
        oidcIssuer: "https://login.microsoftonline.com/tenant/v2.0",
        oidcAudience: "api-id",
        oidcSubjectClaim: "oid",
        oidcAdminScope: "hemlig.admin",
        oidcConsoleAccessScope: "api://api-id/hemlig.admin",
        oidcAdminRole: "Hemlig.Administrator",
        oidcClientId: "console-id",
      }),
    ).toJSON();
    expect(JSON.stringify(explicit)).toBe(JSON.stringify(literal));
  });

  it("an audience-only API deployment with no console still synthesizes", () => {
    const template = synth({
      environment: "test",
      adminFqdn: base.adminFqdn as string,
      apiFqdn: base.apiFqdn as string,
      zoneDomain: "test.example.com",
      oidcIssuer: base.oidcIssuer as string,
      oidcAudience: "api-id",
    }) as { Outputs: Record<string, { Value: string }> };
    expect(template.Outputs.AdminOidcAudience?.Value).toBe("api-id");
  });
});

describe("OIDC defaults on the library path (HemligStack props)", () => {
  const props = {
    environmentName: "test",
    adminFqdn: "admin.test.example.com",
    apiFqdn: "api.test.example.com",
    consoleFqdn: "console.test.example.com",
    consoleCertificateArn:
      "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
    zoneDomain: "test.example.com",
    oidcIssuer: "https://login.microsoftonline.com/tenant/v2.0",
    oidcSubjectClaim: "oid",
    oidcAdminScope: "hemlig.admin",
    oidcAdminRole: "Hemlig.Administrator",
  };
  const synth = (
    extra: Partial<ConstructorParameters<typeof HemligStack>[2]>,
  ): string =>
    JSON.stringify(
      Template.fromStack(
        new HemligStack(new App(), "hml-test", { ...props, ...extra }),
      ).toJSON(),
    );

  it("one client ID gives the same template as the explicit one-app props", () => {
    const explicit = synth({
      oidcAudience: "app-id",
      oidcConsoleAccessScope: "api://app-id/hemlig.admin",
      oidcClientId: "app-id",
    });
    expect(synth({ oidcClientId: "app-id" })).toBe(explicit);
  });

  it("explicit two-app props are left as they are", () => {
    const template = JSON.parse(
      synth({
        oidcAudience: "api-id",
        oidcConsoleAccessScope: "api://api-id/hemlig.admin",
        oidcClientId: "console-id",
      }),
    ) as { Outputs: Record<string, { Value: string }> };
    expect(template.Outputs.AdminOidcAudience?.Value).toBe("api-id");
  });

  it("refuses a derived audience without an admin scope, and no client ID or audience", () => {
    const { consoleFqdn: _c, consoleCertificateArn: _a, oidcAdminScope: _s, ...apiOnly } = props;
    expect(
      () => new HemligStack(new App(), "hml-test", { ...apiOnly, oidcClientId: "app-id" }),
    ).toThrow("oidcAdminScope is required when oidcAudience is omitted");
    expect(() => new HemligStack(new App(), "hml-test", { ...apiOnly })).toThrow(
      "set oidcClientId (or oidcAudience",
    );
    expect(
      () =>
        new HemligStack(new App(), "hml-test", {
          ...props,
          oidcAudience: "  ",
          oidcClientId: "console-id",
        }),
    ).toThrow("oidcAudience must not be blank");
  });
});

describe("provider-neutral OIDC config surface", () => {
  const legacy = {
    environmentName: "test",
    adminFqdn: "admin.test.example.com",
    apiFqdn: "api.test.example.com",
    consoleFqdn: "console.test.example.com",
    consoleCertificateArn:
      "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
    zoneDomain: "test.example.com",
    oidcIssuer: "https://login.microsoftonline.com/tenant/v2.0",
    oidcAudience: "api-id",
    oidcSubjectClaim: "oid",
    oidcAdminScope: "hemlig.admin",
    oidcConsoleAccessScope: "api://api-id/hemlig.admin",
    oidcAdminRole: "Hemlig.Administrator",
    oidcClientId: "console-id",
  };
  const entraCsp = defaultCsp.replaceAll(
    "https://login.example.com",
    "https://login.microsoftonline.com",
  );
  type Props = ConstructorParameters<typeof HemligStack>[2];
  const stackFor = (extra: Partial<Props>) =>
    new HemligStack(new App(), "hml-test", { ...legacy, ...extra });
  const templateFor = (extra: Partial<Props>) =>
    Template.fromStack(stackFor(extra));
  const lambdaEnv = (template: Template, name: string) => {
    const fn = Object.values(template.findResources("AWS::Lambda::Function")).find(
      (resource) => resource.Properties.FunctionName === name,
    );
    return fn?.Properties.Environment.Variables as Record<string, string>;
  };

  it("legacy props: list forms of the same values give a byte-identical template", () => {
    const base = JSON.stringify(templateFor({}).toJSON());
    expect(
      JSON.stringify(
        templateFor({
          oidcAudience: ["api-id"],
          oidcAdminRole: ["Hemlig.Administrator"],
          oidcProviderOrigins: [],
          oidcAuthorizeParams: {},
        }).toJSON(),
      ),
    ).toBe(base);
  });

  it("legacy context: the same values as context strings give that same template", () => {
    const values: Record<string, string> = {
      environment: "test",
      adminFqdn: legacy.adminFqdn,
      apiFqdn: legacy.apiFqdn,
      consoleFqdn: legacy.consoleFqdn,
      consoleCertificateArn: legacy.consoleCertificateArn,
      zoneDomain: legacy.zoneDomain,
      oidcIssuer: legacy.oidcIssuer,
      oidcAudience: "api-id",
      oidcSubjectClaim: "oid",
      oidcAdminScope: "hemlig.admin",
      oidcConsoleAccessScope: "api://api-id/hemlig.admin",
      oidcAdminRole: "Hemlig.Administrator",
      oidcClientId: "console-id",
    };
    const config = deploymentConfigFromContext({
      tryGetContext: (name: string) => values[name],
    });
    const fromContext = Template.fromStack(
      new HemligStack(new App(), "hml-test", config),
    );
    expect(JSON.stringify(fromContext.toJSON())).toBe(
      JSON.stringify(templateFor({}).toJSON()),
    );
  });

  it("legacy values keep today's literal env, authorizer audience and CSP", () => {
    const template = templateFor({
      oidcPkiCaAdminRole: "ca-admin",
      oidcPkiOperatorRole: "pki-op",
    });
    const env = lambdaEnv(template, "hml-test-admin");
    expect(env.ADMIN_JWT_AUDIENCE).toBe("api-id");
    expect(env.ADMIN_JWT_ROLE).toBe("Hemlig.Administrator");
    expect(env).not.toHaveProperty("ADMIN_ROLE_CLAIM");
    const pki = lambdaEnv(template, "hml-test-pki-admin");
    expect(pki.ADMIN_PKI_CA_ROLE).toBe("ca-admin");
    expect(pki.ADMIN_PKI_OPERATOR_ROLE).toBe("pki-op");
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      JwtConfiguration: Match.objectLike({ Audience: ["api-id"] }),
    });
    template.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: Match.objectLike({
            ContentSecurityPolicy: entraCsp,
          }),
        }),
      }),
    });
  });

  it("role lists, role claim and audience lists reach the gateway and every Lambda", () => {
    const template = templateFor({
      oidcAudience: ["api-a", "api-b"],
      oidcAdminRole: ["Hemlig Admins", "Hemlig.Administrator"],
      oidcPkiCaAdminRole: ["ca one", "ca-two"],
      oidcPkiOperatorRole: ["op one", "op-two"],
      oidcRoleClaim: "/realm_access/roles",
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      JwtConfiguration: Match.objectLike({ Audience: ["api-a", "api-b"] }),
    });
    const lambdas = Object.values(
      template.findResources("AWS::Lambda::Function"),
    );
    const withAdminEnv = lambdas.filter(
      (fn) => fn.Properties.Environment?.Variables?.ADMIN_JWT_ISSUER !== undefined,
    );
    expect(withAdminEnv.length).toBeGreaterThan(3);
    for (const fn of withAdminEnv) {
      const vars = fn.Properties.Environment.Variables as Record<string, string>;
      expect(vars.ADMIN_JWT_AUDIENCE).toBe("api-a,api-b");
      expect(vars.ADMIN_JWT_ROLE).toBe("Hemlig Admins,Hemlig.Administrator");
      expect(vars.ADMIN_ROLE_CLAIM).toBe("/realm_access/roles");
    }
    const pki = lambdaEnv(template, "hml-test-pki-admin");
    expect(pki.ADMIN_PKI_CA_ROLE).toBe("ca one,ca-two");
    expect(pki.ADMIN_PKI_OPERATOR_ROLE).toBe("op one,op-two");
    const outputs = template.toJSON().Outputs as Record<string, { Value: string }>;
    expect(outputs.AdminOidcAudience?.Value).toBe("api-a, api-b");
    expect(outputs.AdminOidcRole?.Value).toBe("Hemlig Admins, Hemlig.Administrator");
    expect(outputs.AdminOidcClientId?.Value).toBe("console-id");
  });

  it("oidcProviderOrigins extend connect-src and frame-src only", () => {
    const template = templateFor({
      oidcProviderOrigins: [
        "https://auth.example.org",
        "https://login.microsoftonline.com",
      ],
    });
    const csp = entraCsp
      .replace(
        "connect-src 'self' https://admin.test.example.com https://login.microsoftonline.com;",
        "connect-src 'self' https://admin.test.example.com https://login.microsoftonline.com https://auth.example.org;",
      )
      .replace(
        "frame-src 'self' https://login.microsoftonline.com;",
        "frame-src 'self' https://login.microsoftonline.com https://auth.example.org;",
      );
    template.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: Match.objectLike({ ContentSecurityPolicy: csp }),
        }),
      }),
    });
  });

  it("warns, without failing, when the console is on and no admin role is set", () => {
    const { oidcAdminRole: _role, ...noRole } = legacy;
    const warned = new HemligStack(new App(), "hml-test", noRole);
    expect(
      Annotations.fromStack(warned).findWarning(
        "*",
        Match.stringLikeRegexp("no oidcAdminRole"),
      ),
    ).toHaveLength(1);
    expect(
      Annotations.fromStack(stackFor({})).findWarning(
        "*",
        Match.stringLikeRegexp("no oidcAdminRole"),
      ),
    ).toHaveLength(0);
  });

  it("warns about a missing admin role on an API-only deployment too", () => {
    const { oidcAdminRole: _role, consoleFqdn: _fqdn, consoleCertificateArn: _arn, ...apiOnly } = legacy;
    const warned = new HemligStack(new App(), "hml-test", apiOnly);
    expect(
      Annotations.fromStack(warned).findWarning(
        "*",
        Match.stringLikeRegexp("anyone the issuer will mint a token for"),
      ),
    ).toHaveLength(1);
  });

  it("refuses a role claim without an admin role, and bad new values, on the props path", () => {
    const { oidcAdminRole: _role, ...noRole } = legacy;
    const make = (extra: Record<string, unknown>) => () =>
      new HemligStack(new App(), "hml-test", { ...noRole, ...extra } as Props);
    expect(make({ oidcRoleClaim: "roles" })).toThrow("oidcRoleClaim requires oidcAdminRole");
    expect(() => stackFor({ oidcRoleClaim: "/a/~2" })).toThrow("JSON Pointer");
    expect(() => stackFor({ oidcProviderOrigins: ["http://x.example.com"] })).toThrow(
      "bare HTTPS origin",
    );
    expect(() => stackFor({ oidcAuthorizeParams: { scope: "x" } })).toThrow(
      'must not set "scope"',
    );
  });
});
