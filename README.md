# Hemlig

Hemlig delivers secrets to workloads that run outside AWS without giving them an
AWS credential. It is a Lambda service you deploy into your own AWS account: KMS
envelope-encrypted payloads in immutable S3 Object Lock revisions, authorization
in DynamoDB, and an audit archive. Workloads authenticate with mTLS client
certificates issued by Hemlig itself.

**Who it is for:** platform and security teams running Kubernetes (or other
infrastructure) outside AWS that want AWS-grade key management, immutable history
and auditing, delivered through a Kubernetes controller, a CLI, a Pulumi provider,
or the HTTP API.

> Pre-1.0. Do not deliver production credentials without an isolated AWS
> acceptance test of your OIDC and mTLS configuration.

## Architecture

```text
 Administrator --(OIDC JWT)--> Admin API + Console   (adminFqdn)
                                      |
                                      v
 Kubernetes controller --+      +-------------+      +--> S3 Object Lock: encrypted revisions
 CLI / Pulumi (admin) ---+--->  |   Lambda    | -----+--> DynamoDB: control + authorization
 workload (mTLS leaf) ---+      |  functions  |      +--> KMS: envelope keys + issuing root
        |                       +-------------+      +--> S3 Object Lock: audit archive
        |  (mTLS)   Delivery API (apiFqdn)    ^
        |                                     | DynamoDB Stream
        +<---- MQTT change hints <-- AWS IoT <-+   (payload-free, per-consumer topic)
```

- **Admin API** (`adminFqdn`): OIDC bearer JWT; manages secrets, consumers, grants.
- **Delivery API** (`apiFqdn`): mTLS client certificate from one online issuing root.
- **Hints**: AWS IoT MQTT tells clients to resync sooner; they still verify over mTLS.

## Repository layout

| Path                             | What it is                                                         | License |
| -------------------------------- | ------------------------------------------------------------------ | ------- |
| `src/`                           | Lambda handlers, services, crypto, repositories (root `hemlig`)    | AGPL    |
| `cdk/`                           | `hemlig/cdk` construct and reference CDK app                       | MIT     |
| `openapi/`                       | OpenAPI 3.1 contract                                               | MIT     |
| `packages/client`                | `@zyno-io/hemlig-client` typed HTTPS client                        | MIT     |
| `packages/cli`                   | `@zyno-io/hemlig-cli` administrator CLI                            | MIT     |
| `packages/kubernetes-controller` | Controller, CRDs, Helm chart                                       | MIT     |
| `packages/pulumi-provider`       | `@zyno-io/hemlig-pulumi-provider`                                  | MIT     |
| `packages/console`               | Vue administrator console                                          | AGPL    |
| `docs/`                          | VitePress documentation site; `docs/design/` = historical records  | MIT     |

## Quickstart

Local development (Node.js 24, Docker):

```sh
corepack enable
yarn install
yarn build
yarn test
yarn ministack:up   # local DynamoDB/S3/KMS
yarn dev:api        # dev admin bridge on :5274
yarn dev:ui         # console on :5273
```

## Deploy with CDK

Use the published construct from the CDK app that owns deployment. Build the
package before packing or publishing it; the construct packages the Lambda
sources included with Hemlig. This example creates `dev.example.com`; use
`existingHostedZoneId` instead to add records to an existing authoritative
zone.

```ts
import { App } from "aws-cdk-lib";
import { HemligStack, type DeploymentConfig } from "hemlig/cdk";

const app = new App();
const config: DeploymentConfig = {
  environmentName: "dev",
  adminFqdn: "admin.dev.example.com",
  apiFqdn: "api.dev.example.com",
  zoneDomain: "dev.example.com",
  oidcIssuer: "https://login.example.com/tenant/v2.0",
  // The exact `aud` claim your issuer places in an API access token.
  // For Microsoft Entra v2 tokens, this is the API application's client ID.
  oidcAudience: "00000000-0000-0000-0000-000000000000",
  oidcSubjectClaim: "sub",
};
new HemligStack(app, "hml-dev", config);
```

The repository's CDK CLI is a reference app for direct provisioning. Bootstrap
the destination account and region once, then pass the same inputs as CDK
context:

```sh
yarn exec cdk bootstrap aws://ACCOUNT_ID/AWS_REGION
yarn cdk:deploy \
  -c environment=dev \
  -c adminFqdn=admin.dev.example.com \
  -c apiFqdn=api.dev.example.com \
  -c zoneDomain=dev.example.com \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=00000000-0000-0000-0000-000000000000
```

For an existing zone:

```sh
yarn cdk:deploy \
  -c environment=dev \
  -c adminFqdn=admin.dev.example.com \
  -c apiFqdn=api.dev.example.com \
  -c zoneDomain=dev.example.com \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=00000000-0000-0000-0000-000000000000 \
  -c existingHostedZoneId=Z0123456789ABCDEF
```

The stack creates the revision and audit buckets with S3 Object Lock Compliance
defaults (90 days and seven years), one application KMS key, DynamoDB state, an
OIDC-protected admin API, an mTLS delivery API, Route 53 aliases, and scheduled
recovery and retention. The APIs are public DNS endpoints protected by OIDC or
mTLS, not VPC-private. MiniStack does not validate mTLS, IAM, OIDC or Object
Lock; use the [AWS acceptance runbook](docs/operations/acceptance.md).

## Documentation

Docs site: **https://zyno-io.github.io/hemlig/**

| Topic                                  | Source                                                         |
| -------------------------------------- | -------------------------------------------------------------- |
| What is Hemlig, concepts               | [docs/guide/](docs/guide/what-is-hemlig.md)                    |
| Architecture and security model        | [docs/guide/architecture.md](docs/guide/architecture.md)       |
| Deploying with CDK                     | [docs/guide/deploying.md](docs/guide/deploying.md)             |
| Kubernetes controller                  | [docs/guide/kubernetes.md](docs/guide/kubernetes.md)           |
| HTTP API and OpenAPI                   | [docs/reference/api/](docs/reference/api/index.md), [openapi/](openapi/consumer-secrets.yaml) |
| Identity rotation, upgrades, releasing | [docs/operations/](docs/operations/identity-rotation.md)       |
| Threat model                           | [docs/security/threat-model.md](docs/security/threat-model.md) |
| Contributing                           | [CONTRIBUTING.md](CONTRIBUTING.md)                             |
| Historical design records              | [docs/design/](docs/design/plan.md)                            |

Preview the site locally with `yarn docs:dev`.

## License

The secrets service and administrator console are **AGPL-3.0-only**. The client,
CLI, Kubernetes controller, Pulumi provider, CDK integration and OpenAPI contract
are **MIT**. Commercial hosting is allowed; modified AGPL services must offer
their corresponding source to their network users. See [LICENSING.md](LICENSING.md).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md) and the
[threat model](docs/security/threat-model.md).
