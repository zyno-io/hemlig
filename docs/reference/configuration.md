---
title: Configuration reference
description: CDK DeploymentConfig, reference-app context keys, controller Helm values, and every environment variable.
pageType: reference
---

# Configuration reference

Every setting you can change: the CDK `DeploymentConfig`, the controller's Helm values, and the environment variables used by the CLI, the Pulumi provider, the controller, the Lambdas and the maintenance scripts.

## CDK `DeploymentConfig`

Imported from `hemlig/cdk`. The reference app (`cdk/app.ts`) reads the same names as CDK context (`-c name=value`), with `environment` for `environmentName`. Procedure and examples: [Deploy Hemlig to AWS](../guide/deploying.md). Provider-specific values: [Connect your identity provider](../guide/identity-provider.md).

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `environmentName` | yes | `dev` (context only) | The [deployment name](glossary.md#deployment-name), `^[a-z][a-z0-9-]{1,31}$`. Prefixes resources as `hml-NAME-`. Context key `environment` |
| `adminFqdn` | yes | none | Administrator API host (OIDC). Also serves the bootstrap route |
| `apiFqdn` | yes | none | Public mTLS delivery API host |
| `zoneDomain` | yes | none | Route 53 zone name. Every FQDN must be the zone or inside it |
| `oidcIssuer` | yes | none | HTTPS OIDC issuer URL; RSA-signed JWTs |
| `oidcAudience` | no | `oidcClientId` | Exact access-token `aud`, each at most 512 characters. A list (1 to 8 values; comma-separated in CDK context) accepts any of them: the gateway gets the array and the Lambdas the comma-joined `ADMIN_JWT_AUDIENCE`. A value has no whitespace or comma and does not start with `[`. If a value equals `oidcClientId`, `oidcAdminScope` is required: an explicit audience equal to the client ID without a scope is refused, which also applies to an API-only deployment. Entra v2: the API's bare client ID. Set it when the token's audience is not the client ID (Okta and Auth0 use their API or authorization-server identifier) or for a split-app deployment or an API-only deployment with no console; with neither it nor `oidcClientId`, synthesis fails. Per-provider values are in the [provider recipes](../guide/identity-provider.md#provider-recipes). When omitted, `oidcAdminScope` is required, so the scope check rejects ID tokens issued to the same app |
| `oidcSubjectClaim` | yes | `sub` (context only) | Immutable actor claim name, `^[A-Za-z_][A-Za-z0-9_.-]{0,127}$` |
| `existingHostedZoneId` | no | creates a zone | Use an existing Route 53 zone |
| `existingApplicationKeyArn` | no | creates a key | Adopt an existing [application CMK](glossary.md#application-cmk). Must be a full KMS key ARN |
| `consoleFqdn` | no | console off | Enables [console](../guide/console.md) hosting and admin-API CORS for the console origin |
| `oidcAdminScope` | with `consoleFqdn` | none | One scope token enforced from the token's `scope` or `scp` |
| `oidcConsoleAccessScope` | no | derived | Resource-qualified scope the browser requests. Default, from `oidcAdminScope` and `oidcClientId`: `api://<audience>/<oidcAdminScope>` when the issuer host is `login.microsoftonline.com`, `login.microsoftonline.us` or `login.chinacloudapi.cn`; otherwise `oidcAdminScope` as-is. An explicit value always wins (custom identifier URIs) |
| `oidcClientId` | with `consoleFqdn` | none | The console single-page app's OAuth client ID. In a one-app deployment it is also the audience |
| `oidcAdminRole` | no | none | Role required after JWT validation, read from `oidcRoleClaim` (default `roles`, then `role`). A list (`string[]`; comma-separated in CDK context) means any-of. 1 to 16 values, each 1 to 256 printable characters, no comma, no leading or trailing space, not starting with `[`. Spaces inside a value are fine (`Hemlig Admins`). A single-string prop containing a comma is refused: pass a list. The comma-joined list is at most 1024 characters. With no admin role, synthesis emits a warning (not an error), with or without `consoleFqdn`: anyone the issuer will mint a token for, with the right audience, is an administrator |
| `oidcRoleClaim` | no | `roles`, then `role` | Where the bearer carries roles: a top-level claim name (no whitespace, at most 256 characters, not starting with `/`), or an RFC 6901 JSON Pointer of at most 8 non-empty segments, such as `/realm_access/roles`. Requires `oidcAdminRole`. Passed as `ADMIN_ROLE_CLAIM` |
| `oidcAuthorizeParams` | no | none | Extra query parameters the console adds to the authorize request, for example Auth0's `{ audience: "https://api.example.com" }`. In CDK context, a JSON object string. At most 8 keys matching `^[a-z_]{1,64}$`, values 1 to 512 characters. Protocol-owned keys are refused: `client_id`, `redirect_uri`, `response_type`, `response_mode`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`, `request`, `request_uri`, `prompt`. Written to `config.json` as `auth.extraQueryParams` only when set. Sign-in only: sign-out does not send them |
| `oidcProviderOrigins` | no | none | Extra bare HTTPS origins (at most 4; comma-separated in CDK context) added to the console CSP `connect-src` and `frame-src`, for a provider whose token endpoint or session frame is not on the issuer's origin. No path, wildcard or trailing slash |
| `oidcPkiCaAdminRole` | no | none | Role additionally required for PKI CA lifecycle and root CRL upload. A role or list (any-of), same rules as `oidcAdminRole`. Passed to the PKI admin Lambda as `ADMIN_PKI_CA_ROLE`. Checked, after the administrator JWT, on create, update, delete, activate, retire, destroy-key and root CRL upload. Unset means any administrator may. Reads need only the JWT |
| `oidcPkiOperatorRole` | no | none | Role additionally required for PKI grants, admin issuance, revocation and CRL force-publish. A role or list (any-of), same rules as `oidcAdminRole`. Passed as `ADMIN_PKI_OPERATOR_ROLE`. Checked, after the administrator JWT, on grant create, update and delete, administrator issuance, revoke, bulk revoke and CRL force-publish. Unset means any administrator may. Reads and `evaluate` need only the JWT |
| `pkiIssuanceRateLimit` | no | `20` | API Gateway stage throttle (requests per second) on `POST /v1/pki/{proxy+}`. Integer from 1 to 5000 |
| `pkiIssuanceBurstLimit` | no | `40` | Stage burst on the same route. Integer from 1 to 5000, at least `pkiIssuanceRateLimit` |
| `consoleCertificateArn` | no | sibling stack | ACM certificate in `us-east-1`. Needs `consoleFqdn`. Without it the stack creates a certificate stack, which needs a concrete `env` and `existingHostedZoneId` |
| `bootstrapQualifier` | no | none | CDK bootstrap qualifier, 1 to 10 lowercase letters or digits. Set it whenever you use a non-default synthesizer |
| `tracing` | no | `false` | `true` turns on AWS X-Ray active tracing for every Lambda function. Off by default: traces add cost and little beyond CloudWatch Logs and Lambda metrics |

The audience, role and role-claim values together may encode to at most 1536 bytes of Lambda environment (Lambda allows 4096 in total), and synthesis refuses more. Each `oidcProviderOrigins` entry must be a plain DNS host with an optional port: no `;`, `,`, quotes or `*`. A non-string list entry (a number or null) is an error, not ignored.

Synthesis fails with a message naming the rule if the `adminFqdn`, `apiFqdn` and `consoleFqdn` are not distinct, an FQDN is outside the zone, or `consoleFqdn` is set without `oidcAdminScope` and `oidcClientId`.

## Controller Helm values

Chart `hemlig-controller` (`packages/kubernetes-controller/chart/hemlig-controller`).
Unknown values are rejected by `values.schema.json`.

| Value                                      | Default                                  | Description                                                      |
| ------------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------- |
| `replicaCount`                             | `1`                                      | Must be `1` (schema-enforced; no leader election)                |
| `image.repository`                         | `ghcr.io/zyno-io/hemlig-controller`      | Image                                                            |
| `image.tag`                                | `""` (chart `appVersion`)                | Released charts pin the Git tag; source installs use `main`      |
| `image.pullPolicy`                         | `IfNotPresent`                           |                                                                  |
| `imagePullSecrets`                         | `[]`                                     |                                                                  |
| `nameOverride`, `fullnameOverride`         | `""`                                     |                                                                  |
| `serviceAccount.create`, `.name`, `.annotations`, `.automountServiceAccountToken` | `true`, `""`, `{}`, `true` |                                  |
| `rbac.create`                              | `true`                                   | Set `false` only if you supply an equivalent ClusterRole/Binding |
| `podAnnotations`, `podLabels`              | `{}`                                     |                                                                  |
| `podSecurityContext`                       | non-root, `RuntimeDefault` seccomp       |                                                                  |
| `securityContext`                          | no privilege escalation, read-only root FS, drop `ALL` |                                                    |
| `controller.reconcileIntervalMilliseconds` | `600000`                                 | Periodic resync; sets `HEMLIG_RECONCILE_INTERVAL_MS`             |
| `controller.sourceDebounceMilliseconds`    | `250`                                    | Source Secret debounce; sets `HEMLIG_SOURCE_DEBOUNCE_MS`         |
| `certManager.maxConcurrentRequests`        | `4`                                      | 1 to 64. Concurrent Hemlig PKI calls across all issuers, at most 2 per consumer; sets `HEMLIG_PKI_CONCURRENCY` |
| `trustBundles.refreshIntervalMilliseconds` | `300000` | 30000 to 3600000. How often each trust bundle re-reads its CAs and CRLs; sets `HEMLIG_PKI_BUNDLE_INTERVAL_MS` |
| `certManager.approval.grantDefaultApprover` | `true`                                  | Lets cert-manager's built-in approver approve every request that references a Hemlig issuer. Set `false` to gate with approver-policy |
| `certManager.approval.serviceAccount`, `.namespace` | `cert-manager`, `cert-manager`  | The ServiceAccount that receives `approve`. Must match your cert-manager install |
| `resources`, `nodeSelector`, `tolerations`, `affinity` | empty                        |                                                                  |

## Environment variables

### Name collision: `HEMLIG_ENVIRONMENT`

`HEMLIG_ENVIRONMENT` means two different things.

| Where | Meaning |
| --- | --- |
| [CLI](../guide/cli.md) | The runtime [environment](glossary.md#environment), such as `prod` (same as `--environment`) |
| Lambdas and `yarn dev:api` | The [deployment name](glossary.md#deployment-name), such as `prod` (the CDK `environmentName`) |

Do not copy one into the other's configuration without checking which you mean.

### CLI and Pulumi

| Variable | Used by | Description |
| --- | --- | --- |
| `HEMLIG_ADMIN_URL` | CLI | Administrator origin (`--admin-url`) |
| `HEMLIG_ENVIRONMENT` | CLI | Runtime environment (`--environment`) |
| `HEMLIG_ADMIN_TOKEN_FILE` | CLI | File containing the raw OIDC JWT (`--token-file`) |
| `HEMLIG_ADMIN_TOKEN` | CLI, Pulumi provider | Raw OIDC JWT |

### Maintenance script environment variables

Used by the [maintenance scripts](../operations/upgrades.md). The AWS SDK also reads the usual `AWS_*` variables; set `AWS_REGION`.

| Variable | Required by | Description |
| --- | --- | --- |
| `CONTROL_TABLE_NAME` | all seven scripts | DynamoDB control table, `hml-NAME-control` |
| `REVISION_BUCKET_NAME` | `migrate:secret-identity`, `reconcile:agent-grant-access` | Revision bucket name (`RevisionBucketName` output) |
| `HEMLIG_UPGRADE_QUIESCED` | `--apply` of `migrate:secret-identity` and `migrate:secret-uids`; every `reconcile:agent-grant-access` run | Must be `1`. Your acknowledgement that all writers and readers are stopped |
| `AWS_REGION` | `revoke:iot-for-revoked-identities`, `reconcile:agent-grant-access` | Defaults to `us-east-1` when unset. The others use the SDK's normal region resolution |

### Controller

| Variable                        | Default  | Range        | Description                         |
| ------------------------------- | -------- | ------------ | ----------------------------------- |
| `HEMLIG_RECONCILE_INTERVAL_MS`  | `600000` | 1 to 3600000 | Periodic full reconcile interval    |
| `HEMLIG_SOURCE_DEBOUNCE_MS`     | `250`    | 1 to 3600000 | Debounce for watched source changes |
| `HEMLIG_PKI_CONCURRENCY`        | `4`      | 1 to 64      | Concurrent Hemlig PKI calls for the cert-manager issuer |
| `HEMLIG_PKI_BUNDLE_INTERVAL_MS` | `300000` | 30000 to 3600000 | Trust bundle refresh interval, jittered by 10% either way |

The controller uses the in-cluster Kubernetes configuration (or your kubeconfig
when run locally). It needs no AWS credentials and no administrator token.

### Lambda environment variables

The stack sets these on the Lambdas; you do not configure them directly. The PKI variables are present only on the PKI Lambdas. They are listed for debugging.

| Variable | Source |
| --- | --- |
| `HEMLIG_ENVIRONMENT` | `environmentName` (the deployment name) |
| `CONTROL_TABLE_NAME`, `WORKFLOW_DUE_INDEX`, `RETENTION_DUE_INDEX`, `CATALOG_PATH_INDEX`, `CONSUMER_DIRECTORY_INDEX`, `CONSUMER_IDENTITY_INDEX`, `SECRET_REVISION_INDEX` | The control table and its six indexes (the seventh, `pki-directory`, goes only to the PKI Lambdas) |
| `REVISION_BUCKET_NAME`, `AUDIT_BUCKET_NAME`, `AUDIT_PREFIX`, `TRUSTSTORE_BUCKET_NAME`, `TRUSTSTORE_KEY_PREFIX` | The buckets and key prefixes |
| `PAYLOAD_KMS_KEY_ARN` | The application CMK |
| `DELIVERY_API_CUSTOM_DOMAIN_NAME`, `DELIVERY_API_HOSTNAME` | `apiFqdn` |
| `IOT_ENDPOINT`, `IOT_NOTIFICATION_POLICY_NAME`, `IOT_NOTIFICATION_TOPIC_PREFIX` | AWS IoT endpoint, policy name and topic prefix `hemlig/NAME/consumers` |
| `ADMIN_JWT_ISSUER`, `ADMIN_JWT_AUDIENCE`, `ADMIN_ACTOR_SUBJECT_CLAIM` | `oidcIssuer`, `oidcAudience` (comma-joined when a list), `oidcSubjectClaim` |
| `ADMIN_JWT_SCOPE`, `ADMIN_JWT_ROLE` | `oidcAdminScope`, `oidcAdminRole` (comma-joined when a list), when set |
| `ADMIN_ROLE_CLAIM` | `oidcRoleClaim`, when set. Every Lambda that carries the admin JWT variables |
| `PKI_DIRECTORY_INDEX`, `PKI_BUCKET_NAME` | The `pki-directory` index and the PKI bucket. Set on the three PKI Lambdas only |
| `ADMIN_PKI_CA_ROLE`, `ADMIN_PKI_OPERATOR_ROLE` | `oidcPkiCaAdminRole`, `oidcPkiOperatorRole` (comma-joined when a list), when set. The `pki-admin` Lambda only |
| `MAX_PAYLOAD_BYTES` | `768000`. The code accepts 1 to 768000; the stack sets the maximum |

