---
title: Configuration reference
description: CDK DeploymentConfig, reference-app context keys, and controller Helm values and environment variables.
---

# Configuration reference

## CDK `DeploymentConfig`

Imported from `hemlig/cdk`. The reference app (`cdk/app.ts`) reads the same names
as CDK context (`-c name=value`), with `environment` for `environmentName`. See
[Deploying with CDK](/guide/deploying) for examples.

| Field                        | Required     | Description                                                                                        |
| ---------------------------- | ------------ | -------------------------------------------------------------------------------------------------- |
| `environmentName`            | yes          | Deployment name, `^[a-z][a-z0-9-]{1,31}$`; prefixes resources `hml-<env>-`. Context key `environment`, default `dev` |
| `adminFqdn`                  | yes          | Administrator API host (OIDC); also serves the bootstrap route                                     |
| `apiFqdn`                    | yes          | Public mTLS delivery API host                                                                      |
| `zoneDomain`                 | yes          | Route 53 zone name; every FQDN must be within it                                                   |
| `oidcIssuer`                 | yes          | OIDC issuer URL (HTTPS, RSA-signed JWTs)                                                           |
| `oidcAudience`               | yes          | Exact access-token `aud` (Entra v2: the API app's bare client ID)                                  |
| `oidcSubjectClaim`           | no           | Immutable actor claim; default `sub`                                                               |
| `existingHostedZoneId`       | no           | Use an existing zone instead of creating one                                                       |
| `existingApplicationKeyArn`  | no           | Adopt an existing application CMK                                                                  |
| `consoleFqdn`                | no           | Enables console hosting and admin-API CORS; needs the three console fields below                   |
| `oidcAdminScope`             | with console | Short scope enforced from the token (`scope` or `scp`)                                             |
| `oidcConsoleAccessScope`     | with console | Resource-qualified scope the browser requests                                                      |
| `oidcClientId`               | with console | SPA's OAuth client ID                                                                              |
| `oidcAdminRole`              | no           | Role required from `roles`/`role` after JWT validation                                             |
| `consoleCertificateArn`      | no           | ACM certificate in `us-east-1` for CloudFront (otherwise a sibling stack creates one; needs a concrete `env` and `existingHostedZoneId`) |
| `bootstrapQualifier`         | no           | CDK bootstrap qualifier when using a non-default synthesizer                                       |

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

## Controller environment variables

| Variable                        | Default  | Range        | Description                         |
| ------------------------------- | -------- | ------------ | ----------------------------------- |
| `HEMLIG_RECONCILE_INTERVAL_MS`  | `600000` | 1 to 3600000 | Periodic full reconcile interval    |
| `HEMLIG_SOURCE_DEBOUNCE_MS`     | `250`    | 1 to 3600000 | Debounce for watched source changes |

The controller uses the in-cluster Kubernetes configuration (or your kubeconfig
when run locally). It needs no AWS credentials and no administrator token.

## CLI and Pulumi

| Variable                  | Used by              | Description                                       |
| ------------------------- | -------------------- | ------------------------------------------------- |
| `HEMLIG_ADMIN_URL`        | CLI                  | Administrator origin (`--admin-url`)              |
| `HEMLIG_ENVIRONMENT`      | CLI                  | Secret environment (`--environment`)              |
| `HEMLIG_ADMIN_TOKEN_FILE` | CLI                  | File containing the raw OIDC JWT (`--token-file`) |
| `HEMLIG_ADMIN_TOKEN`      | CLI, Pulumi provider | Raw OIDC JWT                                      |

Maintenance scripts take `CONTROL_TABLE_NAME` (and `REVISION_BUCKET_NAME` for
`reconcile:agent-grant-access`); see [Upgrade: secret UIDs](/operations/upgrade-secret-uids).
