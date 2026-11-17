---
title: Kubernetes controller
description: Install the Hemlig controller, bootstrap a namespace, import and export Secrets, and troubleshoot.
---

# Kubernetes controller

The controller (`hemlig.io/v1beta1`, image `ghcr.io/zyno-io/hemlig-controller`)
materializes Hemlig secrets into Kubernetes Secrets and exports application-owned
Secrets back to Hemlig. It **never holds an administrator OIDC token**. A platform
administrator creates an AgentGrant and a one-use bootstrap capability; the
controller generates and keeps its own private key in the namespace, redeems the
capability once, and uses the resulting mTLS leaf for all later API calls and its
AWS IoT notification connection.

## Resources

| Kind                 | Scope      | Short name     | Role                                                                                 |
| -------------------- | ---------- | -------------- | ------------------------------------------------------------------------------------ |
| `HemligProvider`     | Cluster    | `hmlprovider`  | Public endpoint URLs plus the namespace label selector allowed to use them          |
| `HemligConsumer`     | Namespaced | `hmlconsumer`  | Points at a same-namespace bootstrap Secret; owns the identity Secret               |
| `HemligSecretImport` | Namespaced | `hmlimport`    | Materializes a granted remote secret into an owned Kubernetes Secret                |
| `HemligSecretExport` | Namespaced | `hmlexport`    | Pushes a source Secret through the consumer's write scope (cannot set ACLs)         |

Field-by-field detail: [CRD reference](/reference/crds).

## Install

### Helm

```sh
helm repo add zyno https://zyno-io.github.io/charts
helm repo update
helm upgrade --install hemlig-controller zyno/hemlig-controller \
  --namespace hemlig-system --create-namespace
```

The chart installs the CRDs by default. Helm never upgrades CRDs from a chart's
`crds/` directory, so on chart upgrades apply CRD changes yourself (or let Flux do
it; see below). Values are listed in [Configuration](/reference/configuration).

::: warning Cluster-wide RBAC
The ClusterRole is deliberately broad: the controller lists and watches Hemlig
resources and source Secrets across namespaces. `HemligProvider` selectors and the
remote AgentGrant bound which *remote* secrets a namespace can use, but do not
narrow this Kubernetes RBAC grant. Review it before installing. A single replica
is enforced (no leader election yet), with a zero-surge rollout so two reconcilers
never overlap.
:::

### Flux

Using the same chart and image from Flux. `CreateReplace` keeps CRDs current on upgrades:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: zyno
  namespace: hemlig-system
spec:
  url: https://zyno-io.github.io/charts
  interval: 1h
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: hemlig-controller
  namespace: hemlig-system
spec:
  interval: 10m
  chart:
    spec:
      chart: hemlig-controller
      version: "<chart-version>"   # pin an exact chart version
      sourceRef: { kind: HelmRepository, name: zyno }
  install: { crds: CreateReplace }
  upgrade: { crds: CreateReplace }
```

See [Controller rollout via Flux](/operations/flux-rollout) for a staging-first
rollout procedure.

### Without Helm

Apply the [CRDs](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/config/crds.yaml) and the
[manager manifest](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/config/manager.yaml).
To build the image yourself from the repository root:

```sh
docker build -f packages/kubernetes-controller/Dockerfile -t hemlig-controller:dev .
```

## Server prerequisites

The server must support `GET /v1/agent/sync`. Existing environments must run the
dry-run-first `yarn backfill:agent-sync` once before upgrading controllers; new
environments initialize their index automatically. Older servers or incomplete
indexes fail visibly and back off. The controller does not fall back to
per-secret polling.

## Walkthrough

### 1. Administrator: create the grant and bootstrap capability

An administrator creates the secrets first, then one AgentGrant naming exactly the
secrets this namespace may read or write (`POST /v1/admin/agent-grants`, see the
[API](/reference/api/admin-consumers#agent-grants-and-bootstrap-capabilities), or
the [Pulumi provider](pulumi.md)), then issues the capability with
`POST /v1/admin/agent-grants/{grantId}/bootstrap-capabilities`. The `hmlb_...`
token is shown once and expires after 30 minutes.

### 2. Put the capability in the namespace

```sh
kubectl create namespace payments
kubectl label namespace payments hemlig.io/provider-production=true
kubectl -n payments create secret generic payments-bootstrap \
  --from-literal=token='hmlb_...'
```

### 3. Declare the resources

```yaml
apiVersion: hemlig.io/v1beta1
kind: HemligProvider
metadata:
  name: production
spec:
  bootstrapUrl: https://admin.hemlig.example.com   # adminFqdn
  apiUrl: https://api.hemlig.example.com           # apiFqdn
  allowedNamespaces:
    matchLabels:
      hemlig.io/provider-production: "true"
---
apiVersion: hemlig.io/v1beta1
kind: HemligConsumer
metadata:
  name: payments
  namespace: payments
spec:
  providerRef: production
  bootstrapTokenRef: { name: payments-bootstrap, key: token }
  identity: { secretName: hemlig-payments-client }
---
apiVersion: hemlig.io/v1beta1
kind: HemligSecretImport
metadata:
  name: payments-api
  namespace: payments
spec:
  consumerRef: payments
  secretId: payments/production/api-key
  target: { name: payments-api, type: Opaque }
---
apiVersion: hemlig.io/v1beta1
kind: HemligSecretExport
metadata:
  name: payments-api-source
  namespace: payments
spec:
  consumerRef: payments
  secretId: payments/production/api-key-source
  source: { name: payments-api-source }
  metadata: { description: Payments API }
```

The AgentGrant must explicitly select `payments/production/api-key` (read) and
`payments/production/api-key-source` (write). Kubernetes RBAC cannot widen that.
An export does **not** create the remote secret: an administrator must create it
and add it to the grant first (otherwise `RemoteSecretNotFound`).

### 4. Check status

```sh
kubectl -n payments get hmlconsumer,hmlimport,hmlexport
kubectl -n payments get hmlconsumer payments -o yaml
```

A healthy consumer has `Ready=True` with reason `IdentityReady`, and shows
`consumerId`, `environment`, `grantId`, and a `syncCursor` in `status`.

## Behavior

- **Identity Secret.** The controller creates `identity.secretName` (type `Opaque`)
  with `tls.key` and a CSR, redeems the bootstrap capability, then stores the
  issued `tls.crt`. The Secret carries owner markers; if one with that name already
  exists but is not owned by this `HemligConsumer`, the reason is
  `IdentityOwnershipConflict`. Keep the identity Secret: deleting it after the
  bootstrap capability is consumed means the consumer cannot re-enroll with the same
  grant. See [Identity rotation](/operations/identity-rotation) for renewal.
- **Imports** are written to an exact-owned Secret. An import refuses to overwrite
  a user-owned Secret (`TargetOwnershipConflict`). Removing the owned copy on
  revocation is covered in [Safety](/operations/safety).
- **Exports** reject an import-managed source (`SourceIsImportManaged`), update
  remote metadata when `spec.metadata` differs, and write the payload when the
  source checksum changes.
- **Sync.** Source changes debounce for 250 ms. MQTT QoS 1 hints trigger a prompt
  index sync; every ten minutes it also queries the version index after its saved
  checkpoint. Unchanged imports and exports make no per-secret remote read. The
  checkpoint is saved only after resources converge. An expired or scope-changed
  cursor triggers a fresh snapshot.
- **Retries** use capped exponential backoff with jitter (up to five minutes).
- **Cross-namespace use.** By default `consumerRef` resolves in the resource's own
  namespace (one consumer per namespace). A platform may share one consumer by
  setting `allowCrossNamespaceReferences: true` on it and naming
  `consumerRef` plus `consumerNamespace` on each workload resource. Every namespace
  allowed to refer to it shares its identity and the union of its grants. The
  bootstrap and identity Secrets stay in the consumer's namespace.

## Status and conditions

Each resource has a `Ready` condition. Common reasons:

| Resource | Reason                       | Meaning / action                                                          |
| -------- | ---------------------------- | ------------------------------------------------------------------------- |
| Consumer | `IdentityReady`              | Enrolled and syncing                                                      |
| Consumer | `ProviderNotFound`           | `providerRef` names no `HemligProvider`                                   |
| Consumer | `ProviderNotPermitted`       | Namespace labels do not match the provider's `allowedNamespaces`          |
| Consumer | `BootstrapTokenUnavailable`  | Bootstrap Secret or key missing (and no identity yet)                     |
| Consumer | `IdentityOwnershipConflict`  | Identity Secret exists but is not owned by this consumer                  |
| Consumer | `ReconcileFailed`            | Other error (for example Hemlig returned 403/409/503); see logs            |
| Import / Export | `ConsumerNotReady`    | Referenced consumer is not ready                                          |
| Import   | `TargetReady`                | Secret materialized                                                       |
| Import   | `AccessRevoked`              | Grant no longer includes this import; owned Secret removed                |
| Import   | `TargetOwnershipConflict`    | Target Secret is owned by something else                                  |
| Export   | `RemoteReady`                | Source written                                                            |
| Export   | `RemoteSecretNotFound`       | Administrator must create the secret and add it to the AgentGrant         |
| Export   | `SourceIsImportManaged`      | Source is an import target                                                |

## Troubleshooting

```sh
kubectl -n hemlig-system logs -l app.kubernetes.io/name=hemlig-controller --tail=100
kubectl -n payments describe hmlconsumer payments
```

- **Stuck on `BootstrapTokenUnavailable`**: the capability expired (30 minutes) or
  was never created. A new capability can only be issued for a grant that is still
  `PENDING`; see [Identity rotation](/operations/identity-rotation#if-the-certificate-already-expired).
- **`ReconcileFailed` with HTTP 503 / sync errors**: the server may not support the
  sync route or the environment's index backfill is incomplete.
- **Imports disappearing**: see [Safety: auth failures vs revoked grants](/operations/safety).
- **Nothing happens after changing a Secret**: the controller watches referenced
  Secrets and namespaces; check that the namespace still matches the provider selector.
