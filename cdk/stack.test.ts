import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import { HemligStack } from "./stack";

const defaultCsp =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "font-src 'self'; connect-src 'self' https://admin.test.example.com https://login.example.com; " +
  "frame-src 'self' https://login.example.com; form-action 'none'; base-uri 'none'; " +
  "object-src 'none'; frame-ancestors 'none'";
const silentRenewCsp = defaultCsp.replace(
  "frame-ancestors 'none'",
  "frame-ancestors 'self'",
);

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
    template.resourceCountIs("AWS::S3::Bucket", 4);
    template.resourceCountIs("AWS::KMS::Key", 1);
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
        ],
        AllowMethods: ["GET", "POST", "PUT", "DELETE"],
        AllowCredentials: false,
        ExposeHeaders: ["etag"],
        MaxAge: 600,
      },
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "OPTIONS /{proxy+}",
      AuthorizationType: "NONE",
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
      RouteKey: "$default",
      AuthorizationScopes: ["hemlig.admin"],
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
      AccessLogSettings: Match.objectLike({
        DestinationArn: Match.anyValue(),
        Format: Match.anyValue(),
      }),
    });
    template.hasOutput("ApiUrl", {
      Value: "https://api.test.example.com",
    });
    template.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith([
              "apigateway:GET",
              "apigateway:PATCH",
              "apigateway:AddCertificateToDomain",
            ]),
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
      expect(csp).not.toContain("*");
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
    template.resourceCountIs("AWS::S3::Bucket", 3);
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
});
