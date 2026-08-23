# Hemlig Kubernetes controller

The Node 24 controller uses `hemlig.io/v1beta1` resources and never mounts an
administrator OIDC token. A platform administrator creates a remote Hemlig
AgentGrant and its one-use bootstrap capability, then places that capability in
the target namespace. The controller generates and retains its private key in
that namespace, redeems the capability once, and uses the resulting mTLS leaf
for every later import/export request and AWS IoT notification connection.

The resource topology is intentionally split:

- `HemligProvider` is cluster-scoped public endpoint configuration plus the
  namespace label selector allowed to use it.
- `HemligConsumer` is namespaced and points to a same-namespace bootstrap
  Secret. Its identity Secret is created only with exact owner markers.
- `HemligSecretImport` materializes a granted remote payload into an exact-owned
  Kubernetes Secret.
- `HemligSecretExport` pushes an application-owned source Secret through the
  consumer's remote write path scope. It cannot set ACLs.

The controller watches CRs, namespaces, and Secrets. Source changes debounce
for 250 ms; MQTT QoS 1 hints trigger prompt remote pulls. A ten-minute snapshot
remains the correctness path for missed watches or broker messages. Current raw
manifests install one replica; Lease leadership, manual enrollment, and leaf
rotation are tracked in the [controller plan](../../docs/kubernetes-controller-plan.md)
before multi-replica support is declared.

Install [CRDs](config/crds.yaml) then the broad cluster-operator
[manager manifest](config/manager.yaml). The forthcoming Helm chart will make
the namespace-restricted RBAC profile the default.

```yaml
apiVersion: hemlig.io/v1beta1
kind: HemligProvider
metadata:
  name: production
spec:
  bootstrapUrl: https://admin.hml.example.net
  apiUrl: https://api.hml.example.net
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
  secretId: payments-api
  target: { name: payments-api, type: Opaque }
---
apiVersion: hemlig.io/v1beta1
kind: HemligSecretExport
metadata:
  name: payments-api-source
  namespace: payments
spec:
  consumerRef: payments
  secretId: payments-api-source
  source: { name: payments-api-source }
  metadata: { path: payments/production, description: Payments API }
```

The administrator-side AgentGrant must give this consumer compatible
`payments/production` read/write prefixes. Remote Hemlig authorization is the
keyspace boundary: Kubernetes RBAC alone cannot expand it. An export rejects an
import-managed source, and an import refuses to overwrite a user-owned target.

Build from the monorepo root:

```sh
docker build -f packages/kubernetes-controller/Dockerfile -t hemlig-controller:dev .
```
