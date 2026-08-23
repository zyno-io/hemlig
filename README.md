# Clavis

Clavis is a standalone AWS Lambda implementation of a cluster secrets-delivery
API. It keeps encrypted payload revisions in S3, authorizes cluster reads from
DynamoDB, uses KMS envelope encryption, and writes application audit events to
a separate immutable S3 prefix.

The repository owns the reusable CDK construct and its reference CDK app; a
consumer owns the target account, stack instantiation, deployment pipeline, and
OIDC-provider configuration. The first consumer may be the internal IaC repo,
but any CDK app can import `clavis/cdk`. Given administrator and cluster API
FQDNs, an authoritative Route 53 zone, and an existing OIDC issuer/audience,
the construct provisions `clv-`-prefixed resources. It creates a public hosted
zone when `existingHostedZoneId` is omitted; the deployer must delegate that
new zone's name servers at its parent registrar/zone.

It is now a Yarn Berry workspace monorepo. The root package remains the AWS
service/CDK construct; [the workspace map](docs/monorepo.md) describes the
shared client, Kubernetes import/export controller, and Pulumi provider.

## Current implementation

The current implementation provides the payload/control-revision workflow,
KMS AES-256-GCM envelope codec, conditional immutable S3 writes, DynamoDB
leases/idempotency records, mTLS fingerprint authorization, OIDC actor
extraction, secret create/update/payload endpoints, organizational path/tag
catalog browsing, cluster reads/changes, immutable audit writes, and scheduled
recovery/retention.

It also supports CSR-based cluster enrollment: Clavis creates one online,
deployment-wide issuing root, KMS-wraps that root under the same application
CMK used for payload envelopes, signs each cluster's client-certificate CSR,
and publishes the one root as a version-pinned API Gateway truststore. It
supports overlapping API-leaf rotation and immediate leaf revocation.
Issuer-root rotation and audit querying remain deliberately out of scope. Do
not use this pre-1.0 project to deliver production credentials without an
isolated AWS acceptance test for your OIDC and mTLS configuration.

## Documentation

- [Architecture and security model](docs/architecture.md)
- [HTTP API reference](docs/api.md)
- [OpenAPI 3.1 contract](openapi/cluster-secrets.yaml)
- [CDK deployment guide](docs/cdk-integration.md)
- [Threat model](docs/threat-model.md)
- [Monorepo and consumer packages](docs/monorepo.md)

## Local development

```sh
corepack enable
yarn install
yarn build
yarn test
yarn ministack:up
```

## Deploy with CDK

Use the published construct from the CDK app that owns deployment. Build the
package before packing or publishing it; the construct packages the Lambda
sources included with Clavis. This example creates `dev.example.com`; use
`existingHostedZoneId` instead to add records to an existing authoritative
zone.

```ts
import { App } from "aws-cdk-lib";
import { ClavisStack, type DeploymentConfig } from "clavis/cdk";

const app = new App();
const config: DeploymentConfig = {
  environmentName: "dev",
  adminFqdn: "admin.dev.example.com",
  clusterFqdn: "clusters.dev.example.com",
  zoneDomain: "dev.example.com",
  oidcIssuer: "https://login.example.com/tenant/v2.0",
  oidcAudience: "api://clavis",
  oidcSubjectClaim: "sub",
};
new ClavisStack(app, "clv-dev", config);
```

The repository's CDK CLI is a reference app for direct provisioning. Bootstrap
the destination account and region once, then pass the same inputs as CDK
context:

```sh
yarn exec cdk bootstrap aws://ACCOUNT_ID/AWS_REGION
yarn cdk:deploy \
  -c environment=dev \
  -c adminFqdn=admin.dev.example.com \
  -c clusterFqdn=clusters.dev.example.com \
  -c zoneDomain=dev.example.com \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=api://clavis
```

For an existing zone:

```sh
yarn cdk:deploy \
  -c environment=dev \
  -c adminFqdn=admin.dev.example.com \
  -c clusterFqdn=clusters.dev.example.com \
  -c zoneDomain=dev.example.com \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=api://clavis \
  -c existingHostedZoneId=Z0123456789ABCDEF
```

The stack creates the revision and audit buckets with S3 Object Lock Compliance
defaults (90 days and seven years respectively), one application KMS key, DynamoDB
state and sparse GSIs, an externally configured OIDC JWT authorizer,
custom-domain HTTP APIs, Route 53 aliases, Lambda roles, and scheduled recovery
and retention invocations. Both execute-api endpoints are disabled. The APIs
are public DNS endpoints protected by OIDC or mTLS—not VPC-private APIs.
Clavis does not create or manage administrator identities.

MiniStack exercises AWS SDK integrations locally. It does not validate API
Gateway custom-domain mTLS, IAM policy enforcement, OIDC authorizers,
CloudTrail delivery, or the AWS administrative behavior of Object Lock. Those
controls require an isolated AWS acceptance environment.

## Lambda entry points

- `dist/handlers/admin.handler`
- `dist/handlers/cluster.handler`
- `dist/handlers/recovery.handler`
- `dist/handlers/retention.handler`

`audit-query` is intentionally not included in the normal Clavis deployment.
It must live in an audit boundary with a separate archive-read role.

## Security posture

Application audit events never include secret values, request bodies, tokens,
or private keys. The audit role is write-only to its assigned prefix. Secret
payloads are encrypted before S3 with a new KMS data key per payload revision.
The same CMK wraps the online issuing root with a separate encryption context;
only the admin function has context-restricted issuer decrypt permission.

See [SECURITY.md](SECURITY.md) for reporting and [PLAN.md](PLAN.md) for the
full intended architecture and deployment contract.
