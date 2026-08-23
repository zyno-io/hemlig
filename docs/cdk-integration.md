# Clavis CDK deployment

For the service model and caller boundaries, read the
[architecture guide](architecture.md) before provisioning an environment.

Clavis publishes a reusable `clavis/cdk` entry point containing `ClavisStack`,
`DeploymentConfig`, and `deploymentConfigFromContext`. A consumer's CDK app
owns the target account, stack name, synthesis, and deployment pipeline; this
repository owns the resources, policies, handlers, and defaults embodied by the
construct. The bundled `cdk/app.ts` is a reference app, not the required
deployment boundary.

`DeploymentConfig` requires `adminFqdn`, `clusterFqdn`, `zoneDomain`,
`oidcIssuer`, and `oidcAudience`; `environmentName` is set by the consumer.
The reference app accepts the `environment` context key and defaults it to
`dev`. `oidcSubjectClaim` defaults to `sub`, and `existingHostedZoneId` is
optional. The FQDNs must be distinct and be within `zoneDomain`. All physical
resource names use the `clv-<environment>-` prefix.

```ts
import { App } from "aws-cdk-lib";
import { ClavisStack, type DeploymentConfig } from "clavis/cdk";

const app = new App();
const config: DeploymentConfig = {
  environmentName: "prod",
  adminFqdn: "admin.example.com",
  clusterFqdn: "clusters.example.com",
  zoneDomain: "example.com",
  oidcIssuer: "https://issuer.example.com",
  oidcAudience: "clavis-admin",
  oidcSubjectClaim: "sub",
  existingHostedZoneId: "Z0123456789ABCDEF",
};
new ClavisStack(app, "clv-prod", config);
```

The OIDC issuer is an external organization-owned identity provider such as
Entra, Okta, Auth0, or Keycloak. It must expose an HTTPS OIDC issuer/JWKS and
issue RSA-signed JWTs for the configured audience. Clavis does not create a
user pool, app registration, user, or administrator group. Configure the
provider's application, scopes, and administrator assignment outside this
stack.

When `existingHostedZoneId` is omitted, Clavis creates a public Route 53 hosted
zone for `zoneDomain` and outputs its name servers. Delegating those name
servers from the parent zone is the only DNS action outside the stack. When
`existingHostedZoneId` is supplied, it creates ACM validation and API alias
records in that zone.

The stack retains all stateful resources and never attaches an S3 auto-delete
custom resource. The revision bucket uses a 90-day Object Lock Compliance
default, and the audit bucket uses seven years. It creates exactly one
customer-managed **application CMK** (`alias/clv-<environment>-application`).
Payload envelope generation, payload decryption, and the online issuer-root
envelope all use that same key. The cluster Lambda has `kms:Decrypt` only when
the context says `service=clavis, purpose=secret-payload`.
The admin Lambda can generate payload data keys and can decrypt only an issuer
envelope whose KMS context is exactly `service=clavis, purpose=issuer-ca`.
All application roles only have `PutObject` for the audit prefix.

The stack binds the supplied issuer and audience to the admin HTTP API JWT
authorizer. It creates custom domains and disables both default execute-api
endpoints. The cluster domain initially has no truststore, so it cannot admit a
useful caller. `POST /v1/admin/clusters` creates the Clavis issuing root on the
first enrollment, signs a submitted CSR, publishes the root's version-pinned
truststore, and only then activates the issued client leaf. The recovery Lambda
has the same narrowly scoped truststore/API Gateway update permissions so it can
resume an interrupted enrollment; neither the cluster Lambda nor the deployment
caller receives the issuer's unwrap permission.

Each HTTP API has a retained CloudWatch access-log group with one-year
retention. The log format includes only request ID, status, gateway error, and
authorizer error fields; it deliberately excludes URI, headers, query string,
and body. These records cover TLS/JWT rejections that cannot become Clavis
application audit events. The stack rejects a truststore containing more than
1,000 certificates or more than 1 MiB of PEM before publishing it. A normal
Clavis deployment contributes one root certificate regardless of cluster count.
