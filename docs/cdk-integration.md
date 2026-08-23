# Hemlig CDK deployment

For the service model and caller boundaries, read the
[architecture guide](architecture.md) before provisioning an environment.

Hemlig publishes a reusable `hemlig/cdk` entry point containing `HemligStack`,
`DeploymentConfig`, and `deploymentConfigFromContext`. An installer's CDK app
owns the target account, stack name, synthesis, and deployment pipeline; this
repository owns the resources, policies, handlers, and defaults embodied by the
construct. The bundled `cdk/app.ts` is a reference app, not the required
deployment boundary.

## Pre-1.0 rename migration

Hemlig is a new protocol and deployment namespace, not an in-place cosmetic
rename of a Clavis installation. It uses `hml-` resource names,
`service=hemlig` KMS encryption contexts, `spiffe://hemlig/...` certificate
identities, `HEMLIG_*` runtime configuration, and `hemlig.io` Kubernetes CRDs.
Deploy it as a new service, re-enroll workload identities, and migrate secret
control metadata and payloads through the administrator API. Do not point a
Hemlig Lambda at an existing Clavis table, bucket, or issuing root: its old
encrypted revisions and mTLS identity records are intentionally incompatible.

`DeploymentConfig` requires `adminFqdn`, `apiFqdn`, `zoneDomain`,
`oidcIssuer`, and `oidcAudience`; `environmentName` is set by the installer.
The reference app accepts the `environment` context key and defaults it to
`dev`. `oidcSubjectClaim` defaults to `sub`, and `existingHostedZoneId` is
optional. The FQDNs must be distinct and be within `zoneDomain`. All physical
resource names use the `hml-<environment>-` prefix.

```ts
import { App } from "aws-cdk-lib";
import { HemligStack, type DeploymentConfig } from "hemlig/cdk";

const app = new App();
const config: DeploymentConfig = {
  environmentName: "prod",
  adminFqdn: "admin.example.com",
  apiFqdn: "api.example.com",
  zoneDomain: "example.com",
  oidcIssuer: "https://issuer.example.com",
  oidcAudience: "hemlig-admin",
  oidcSubjectClaim: "sub",
  existingHostedZoneId: "Z0123456789ABCDEF",
};
new HemligStack(app, "hml-prod", config);
```

The OIDC issuer is an external organization-owned identity provider such as
Entra, Okta, Auth0, or Keycloak. It must expose an HTTPS OIDC issuer/JWKS and
issue RSA-signed JWTs for the configured audience. Hemlig does not create a
user pool, app registration, user, or administrator group. Configure the
provider's application, scopes, and administrator assignment outside this
stack.

`apiFqdn` deliberately names the public mTLS **delivery** API rather than a
Kubernetes-specific endpoint; use a name such as `api.example.com`. Changing
it in an existing Hemlig deployment replaces the API Gateway custom domain.
After the stack update, wait for the five-minute recovery schedule to reattach
the current version-pinned truststore to the new domain, then move each mTLS
client to `https://<apiFqdn>`. Existing leaf certificates remain valid: the
issuing root and fingerprint authorization do not depend on the hostname.

To allow a separately hosted browser console, add `consoleFqdn` and the exact
single-token `oidcAdminScope` (for example `hemlig.admin`). They must be used
together. The stack then permits only `https://<consoleFqdn>` through the admin
API CORS configuration, exposes `ETag`, creates an unauthenticated `OPTIONS
/{proxy+}` route ahead of the JWT-protected `$default` route, and requires the
scope at both API Gateway and Lambda. The preflight reaches Lambda only to
return `204` before authentication or application audit emission; API Gateway
adds the configured CORS headers.

```ts
const config: DeploymentConfig = {
  // ...required service fields...
  consoleFqdn: "dev.example.com",
  oidcAdminScope: "hemlig.admin",
  oidcClientId: "00000000-0000-0000-0000-000000000000",
  consoleCertificateArn:
    "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555",
  secretEnvironments: ["dev", "staging", "prod"],
};
```

Existing machine-to-machine admin deployments remain audience-only unless these
values are set.

## Console hosting

Setting `consoleFqdn` also provisions the static site: a private S3 bucket
reached only through CloudFront Origin Access Control, a distribution with the
console FQDN as an alias, and A/AAAA alias records. `consoleFqdn` may be the
zone apex, which is the intended layout — `N.domain.com` for the console,
`admin.N.domain.com` and `api.N.domain.com` for the two APIs.

**The certificate must be in us-east-1.** CloudFront accepts certificates from
that region only, and the stack's own API certificate is regional and covers
just the two API FQDNs, so it cannot be reused.

Supplying `consoleCertificateArn` is the simpler path and the one the reference
app expects. The alternative — letting the stack create a sibling us-east-1
stack for the certificate — carries two requirements, and synthesis fails with a
clear error if either is unmet:

- The stack needs a concrete `env`. Cross-region references require both stacks
  to have real account and region values, so a region-agnostic stack is
  rejected.
- You must also supply `existingHostedZoneId`. If the stack creates its own
  hosted zone, the certificate stack needs the zone and the main stack needs the
  certificate, which is a genuine CloudFormation dependency cycle rather than an
  ordering problem. Bring your own zone, or bring your own certificate.

The distribution serves two response-header policies. Everything gets a strict
Content-Security-Policy with `frame-ancestors 'none'`; `/silent.html` gets an
otherwise identical policy with `frame-ancestors 'self'`. That single exception
exists because OIDC silent renewal loads the provider in a hidden iframe and the
provider redirects back to the console's own origin, so the console must be able
to frame that one document. Without it every token renewal fails and each
session degrades to a full redirect.

`connect-src` is built from your configuration and names exactly the admin API
origin and the OIDC issuer origin. That assumes your provider serves its token
and JWKS endpoints from the issuer's origin — true for Entra, Okta, and Auth0,
but not universal (Google issues from `accounts.google.com` and serves tokens
from `oauth2.googleapis.com`). A provider that splits them needs both origins in
`connect-src`. The console is deliberately cross-origin to
the admin API — see [the console plan](console-plan.md) for why CloudFront is
kept out of the credential path.

Built console assets are uploaded when `packages/console/dist` is present in the
package, along with a generated `config.json` carrying the deployment name,
admin API URL, environment list, and OIDC client settings. `index.html`,
`config.json`, and `silent.html` are served uncached; content-hashed assets are
cached at the edge. If the build output is absent the stack still synthesises and
emits a `ConsoleAssetsPending` output, so an installer can own publication in its
own pipeline.

When `existingHostedZoneId` is omitted, Hemlig creates a public Route 53 hosted
zone for `zoneDomain` and outputs its name servers. Delegating those name
servers from the parent zone is the only DNS action outside the stack. When
`existingHostedZoneId` is supplied, it creates ACM validation and API alias
records in that zone.

The stack retains all stateful resources and never attaches an S3 auto-delete
custom resource. The revision bucket uses a 90-day Object Lock Compliance
default, and the audit bucket uses seven years. It creates exactly one
customer-managed **application CMK** (`alias/hml-<environment>-application`).
Payload envelope generation, payload decryption, and the online issuer-root
envelope all use that same key. The consumer Lambda has `kms:Decrypt` only when
the context says `service=hemlig, purpose=secret-payload`.
The admin Lambda can generate payload data keys and can decrypt only an issuer
envelope whose KMS context is exactly `service=hemlig, purpose=issuer-ca`.
All application roles only have `PutObject` for the audit prefix.

The stack binds the supplied issuer and audience to the admin HTTP API JWT
authorizer. It creates custom domains and disables both default execute-api
endpoints. The consumer domain initially has no truststore, so it cannot admit a
useful caller. `POST /v1/admin/consumers` creates the Hemlig issuing root on the
first enrollment, signs a submitted CSR, publishes the root's version-pinned
truststore, and only then activates the issued client leaf. The recovery Lambda
has the same narrowly scoped truststore/API Gateway update permissions so it can
resume an interrupted enrollment; neither the consumer Lambda nor the deployment
caller receives the issuer's unwrap permission.

Each HTTP API has a retained CloudWatch access-log group with one-year
retention. The log format includes only request ID, status, gateway error, and
authorizer error fields; it deliberately excludes URI, headers, query string,
and body. These records cover TLS/JWT rejections that cannot become Hemlig
application audit events. The stack rejects a truststore containing more than
1,000 certificates or more than 1 MiB of PEM before publishing it. A normal
Hemlig deployment contributes one root certificate regardless of consumer count.

This release adds three sparse DynamoDB indexes used only by administrative
management reads: consumer directory, consumer API identities, and time-ordered
control revisions. New records are indexed automatically. Before enabling the
new list/history routes against an existing table, run the explicit, idempotent
migration after deployment:

```sh
CONTROL_TABLE_NAME=hml-prod-control yarn build
CONTROL_TABLE_NAME=hml-prod-control node dist/scripts/backfill-console-indexes.js
CONTROL_TABLE_NAME=hml-prod-control node dist/scripts/backfill-console-indexes.js --apply
```

The first run is dry-run only. The migration only adds derived index attributes;
it never changes secret, identity, or certificate material.
