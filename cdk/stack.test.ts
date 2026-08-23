import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { ClavisStack } from "./stack";

describe("ClavisStack", () => {
  it("creates clv-prefixed durable state and custom-domain APIs", () => {
    const app = new App();
    const stack = new ClavisStack(app, "clv-test", {
      environmentName: "test",
      adminFqdn: "admin.test.example.com",
      clusterFqdn: "clusters.test.example.com",
      zoneDomain: "test.example.com",
      oidcIssuer: "https://login.example.com/tenant/v2.0",
      oidcAudience: "clavis-api",
      oidcSubjectClaim: "sub",
    });
    const template = Template.fromStack(stack);
    template.hasResourceProperties("AWS::DynamoDB::Table", {
      TableName: "clv-test-control",
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
    template.resourceCountIs("AWS::S3::Bucket", 3);
    template.resourceCountIs("AWS::KMS::Key", 1);
    template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
      DisableExecuteApiEndpoint: true,
    });
    template.resourceCountIs("AWS::Cognito::UserPool", 0);
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      JwtConfiguration: {
        Audience: ["clavis-api"],
        Issuer: "https://login.example.com/tenant/v2.0",
      },
    });
    template.hasResourceProperties("AWS::Events::Rule", {
      Name: "clv-test-recovery",
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "clv-test-admin-access",
      RetentionInDays: 365,
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "clv-test-cluster-access",
      RetentionInDays: 365,
    });
    template.hasResourceProperties("AWS::ApiGatewayV2::Stage", {
      AccessLogSettings: Match.objectLike({
        DestinationArn: Match.anyValue(),
        Format: Match.anyValue(),
      }),
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
                "kms:EncryptionContext:service": "clavis",
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
                "kms:EncryptionContext:service": "clavis",
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
  });
});
