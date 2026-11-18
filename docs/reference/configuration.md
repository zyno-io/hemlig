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
| `oidcAudience` | yes | none | Exact access-token `aud`, at most 512 characters. Entra v2: the API's bare client ID |
| `oidcSubjectClaim` | yes | `sub` (context only) | Immutable actor claim name, `^[A-Za-z_][A-Za-z0-9_.-]{0,127}$` |
| `existingHostedZoneId` | no | creates a zone | Use an existing Route 53 zone |
| `existingApplicationKeyArn` | no | creates a key | Adopt an existing [application CMK](glossary.md#application-cmk). Must be a full KMS key ARN |
| `consoleFqdn` | no | console off | Enables [console](../guide/console.md) hosting and admin-API CORS for the console origin |
| `oidcAdminScope` | with `consoleFqdn` | none | One scope token enforced from the token's `scope` or `scp` |
| `oidcConsoleAccessScope` | with `consoleFqdn` | none | Resource-qualified scope the browser requests |
| `oidcClientId` | with `consoleFqdn` | none | The console single-page app's OAuth client ID |
| `oidcAdminRole` | no | none | Role required from `roles` or `role` after JWT validation. One role token |
| `consoleCertificateArn` | no | sibling stack | ACM certificate in `us-east-1`. Needs `consoleFqdn`. Without it the stack creates a certificate stack, which needs a concrete `env` and `existingHostedZoneId` |
| `bootstrapQualifier` | no | none | CDK bootstrap qualifier, 1 to 10 lowercase letters or digits. Set it whenever you use a non-default synthesizer |
| `tracing` | no | `false` | `true` turns on AWS X-Ray active tracing for every Lambda function. Off by default: traces add cost and little beyond CloudWatch Logs and Lambda metrics |

Synthesis fails with a message naming the rule if the `adminFqdn`, `apiFqdn` and `consoleFqdn` are not distinct, an FQDN is outside the zone, or `consoleFqdn` is set without `oidcAdminScope`, `oidcConsoleAccessScope` and `oidcClientId`.

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

The controller uses the in-cluster Kubernetes configuration (or your kubeconfig
when run locally). It needs no AWS credentials and no administrator token.

### Lambda environment variables

The stack sets these on every Lambda; you do not configure them directly. They are listed for debugging.

| Variable | Source |
| --- | --- |
| `HEMLIG_ENVIRONMENT` | `environmentName` (the deployment name) |
| `CONTROL_TABLE_NAME`, `WORKFLOW_DUE_INDEX`, `RETENTION_DUE_INDEX`, `CATALOG_PATH_INDEX`, `CONSUMER_DIRECTORY_INDEX`, `CONSUMER_IDENTITY_INDEX`, `SECRET_REVISION_INDEX` | The control table and its six indexes |
| `REVISION_BUCKET_NAME`, `AUDIT_BUCKET_NAME`, `AUDIT_PREFIX`, `TRUSTSTORE_BUCKET_NAME`, `TRUSTSTORE_KEY_PREFIX` | The buckets and key prefixes |
| `PAYLOAD_KMS_KEY_ARN` | The application CMK |
| `DELIVERY_API_CUSTOM_DOMAIN_NAME`, `DELIVERY_API_HOSTNAME` | `apiFqdn` |
| `IOT_ENDPOINT`, `IOT_NOTIFICATION_POLICY_NAME`, `IOT_NOTIFICATION_TOPIC_PREFIX` | AWS IoT endpoint, policy name and topic prefix `hemlig/NAME/consumers` |
| `ADMIN_JWT_ISSUER`, `ADMIN_JWT_AUDIENCE`, `ADMIN_ACTOR_SUBJECT_CLAIM` | `oidcIssuer`, `oidcAudience`, `oidcSubjectClaim` |
| `ADMIN_JWT_SCOPE`, `ADMIN_JWT_ROLE` | `oidcAdminScope`, `oidcAdminRole`, when set |
| `MAX_PAYLOAD_BYTES` | `768000`. The code accepts 1 to 768000; the stack sets the maximum |

