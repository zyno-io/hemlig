---
title: Kubernetes controller
description: Install the Hemlig controller and bootstrap a namespace so it can import and export secrets.
pageType: how-to
---

# Kubernetes controller

Install the Hemlig controller in a cluster, then connect a namespace to Hemlig with a bootstrap token.

The [controller](../reference/glossary.md#kubernetes-controller) copies Hemlig secrets into Kubernetes Secrets and pushes application Secrets back. It never holds an administrator token. It redeems a one-use [bootstrap token](../reference/glossary.md#bootstrap-token) and then authenticates with its own [client certificate](../reference/glossary.md#client-certificate).

**Role:** cluster administrator (install), platform team (bootstrap). **Before you start:** a deployed Hemlig stack and Kubernetes 1.28 or later.

## Resources

| Kind | Scope | Short name | Role |
| --- | --- | --- | --- |
| `HemligProvider` | Cluster | `hmlprovider` | Hemlig endpoint URLs, plus which namespaces may use them |
| `HemligConsumer` | Namespaced | `hmlconsumer` | Holds the bootstrap token and owns the identity Secret |
| `HemligSecretImport` | Namespaced | `hmlimport` | Copies a granted Hemlig secret into a Kubernetes Secret |
| `HemligSecretExport` | Namespaced | `hmlexport` | Pushes a Kubernetes Secret into Hemlig |
| `HemligIssuer` | Namespaced | `hmlissuer` | Lets cert-manager request certificates through a PKI issuance grant |
| `HemligClusterIssuer` | Cluster | `hmlclusterissuer` | The same, usable from any namespace the issuer selects |

Every field is in the [CRD reference](../reference/crds.md). The two issuer kinds are covered in [Issue certificates with cert-manager](cert-manager.md).

## Install the controller

::: warning Cluster-wide RBAC
The ClusterRole is broad: the controller lists and watches Hemlig resources and source Secrets in all namespaces. Provider selectors and the AgentGrant limit which Hemlig secrets a namespace can use, not this Kubernetes permission. Review the chart before installing.
:::

::: code-group

```sh [Helm]
helm repo add zyno https://zyno-io.github.io/charts
helm repo update
helm upgrade --install hemlig-controller zyno/hemlig-controller \
  --namespace hemlig-system --create-namespace
```

```yaml [Flux]
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
      version: "0.3.2"   # pin an exact chart version
      sourceRef: { kind: HelmRepository, name: zyno }
  install: { crds: CreateReplace }
  upgrade: { crds: CreateReplace }
```

```sh [Without Helm]
# Apply the CRDs and manager manifest from packages/kubernetes-controller/config/
kubectl apply -f packages/kubernetes-controller/config/crds.yaml
# Optional: lets cert-manager's built-in approver approve Hemlig requests (see the cert-manager guide)
kubectl apply -f packages/kubernetes-controller/config/cert-manager-approval.yaml
# manager.yaml has no Namespace resource
kubectl create namespace hemlig-system
# The manifest image is a placeholder. Replace it with a release version
sed 's#ghcr.io/hemlig/kubernetes-controller:REPLACE_WITH_VERSION#ghcr.io/zyno-io/hemlig-controller:<version>#' \
  packages/kubernetes-controller/config/manager.yaml | kubectl apply -f -
# To build the image yourself, from the repository root:
docker build -f packages/kubernetes-controller/Dockerfile -t hemlig-controller:dev .
```

:::

The chart installs the CRDs (`hemlig.zyno.io.yaml` and `hemlig.zyno.io-pki.yaml`). Helm never upgrades CRDs from a chart, so on chart upgrades apply both CRD files yourself, or use Flux with `CreateReplace` as above. Values are in [Configuration](../reference/configuration.md). The controller runs as one replica (there is no leader election) with a zero-surge rollout. For upgrades see [Controller rollout via Flux](../operations/flux-rollout.md).

Verify:

```sh
kubectl -n hemlig-system rollout status deploy/hemlig-controller
```

Expected output:

```text
deployment "hemlig-controller" successfully rolled out
```

### Server prerequisite

The server must serve `GET /v1/agent/sync`. A deployment created before that route existed needs the one-off `backfill:agent-sync` script before you upgrade controllers. Fresh deployments need nothing. Steps are in [Upgrades](../operations/upgrades.md#backfill-agent-sync).

## Bootstrap a namespace

An administrator first [creates the grant and issues a token](agent-grants.md). Then the platform team does the following.

1. Put the token in a Secret and label the namespace so the provider accepts it.

```sh
kubectl create namespace payments
kubectl label namespace payments hemlig.zyno.io/provider-production=true
kubectl -n payments create secret generic payments-bootstrap \
  --from-literal=token='hmlb_...'
```

2. Declare the provider and the consumer.

```yaml
apiVersion: hemlig.zyno.io/v1beta1
kind: HemligProvider
metadata:
  name: production
spec:
  bootstrapUrl: https://admin.example.com   # your adminFqdn
  apiUrl: https://api.example.com           # your apiFqdn
  allowedNamespaces:
    matchLabels:
      hemlig.zyno.io/provider-production: "true"
---
apiVersion: hemlig.zyno.io/v1beta1
kind: HemligConsumer
metadata:
  name: payments
  namespace: payments
spec:
  providerRef: production
  bootstrapTokenRef: { name: payments-bootstrap, key: token }
  identity: { secretName: hemlig-payments-client }
```

3. Verify.

```sh
kubectl -n payments get hmlconsumer payments
```

Expected output:

```text
NAME       READY   REASON          IDENTITY-EXPIRES   ROTATION   AGE
payments   True    IdentityReady   2031-01-01T...     NotDue     1m
```

If `READY` is not `True`, look the reason up in [Status reasons](../reference/crds.md#status-reasons) or in [Troubleshooting](../operations/troubleshooting.md#controller).

::: warning Keep the identity Secret
The controller stores its private key and certificate in `hemlig-payments-client`. If you delete it after the token was used, the consumer cannot enroll again with the same grant, because the token is spent. Recovery steps are in [Identity rotation](../operations/identity-rotation.md#if-the-certificate-already-expired). If a Secret with that name already exists and is not owned by the consumer, the reason is `IdentityOwnershipConflict`.
:::

## How the controller behaves

| Topic | Behavior |
| --- | --- |
| Sync | A change in a watched Secret is picked up after a 250 ms debounce. MQTT [change hints](../reference/glossary.md#change-hint) trigger a prompt sync. A resync also runs on the interval in [Limits and timings](../reference/limits.md#controller). See [Sync and notifications](sync-and-notifications.md) |
| Retries | Capped exponential backoff with jitter; see [Limits and timings](../reference/limits.md#controller) |
| Imports | Written to a Secret the import owns. It never overwrites a Secret owned by something else. See [Import a secret](import-secret.md) |
| Exports | Reject an import target as their source. See [Export a Secret](export-secret.md) |
| cert-manager requests | Processed as they change, with a 5-minute resync. See [Issue certificates with cert-manager](cert-manager.md) |
| Deletion | An import target is removed only when Hemlig confirms access was revoked. See [Safety](../operations/safety.md) |

### Share one consumer across namespaces

By default a consumer serves only its own namespace. Setting `allowCrossNamespaceReferences: true` on it lets other namespaces name it through `consumerRef` and `consumerNamespace`.

**Every namespace allowed to refer to it shares its identity and the union of all its grants.** Use one consumer per namespace unless you want that. The bootstrap and identity Secrets stay in the consumer's namespace.

## Next steps

- [Import a secret into your namespace](import-secret.md)
- [Export a Kubernetes Secret to Hemlig](export-secret.md)
- [Troubleshooting](../operations/troubleshooting.md#controller)
