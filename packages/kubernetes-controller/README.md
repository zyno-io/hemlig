# Hemlig Kubernetes controller

Full documentation: the [Kubernetes controller guide](https://zyno-io.github.io/hemlig/guide/kubernetes), [CRD reference](https://zyno-io.github.io/hemlig/reference/crds), and [identity rotation](https://zyno-io.github.io/hemlig/operations/identity-rotation).

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
  Secret. Its identity Secret is created only with exact owner markers. It may
  explicitly opt in to serving imports and exports in other selected namespaces.
- `HemligSecretImport` materializes a granted remote payload into an exact-owned
  Kubernetes Secret.
- `HemligSecretExport` pushes an application-owned source Secret through the
  consumer's remote write exact-secret scope. It cannot set ACLs.

The controller watches CRs and referenced namespaces and Secrets. Source changes
debounce for 250 ms; MQTT QoS 1 hints trigger prompt index synchronization. Every
ten minutes it also queries the compact version index after its saved checkpoint
to repair missed watches or broker messages. Unchanged imports and exports make
no individual remote read. Missing or damaged targets and changed sources still
converge through the authoritative agent API. Current raw
manifests install one replica and use a zero-surge, one-unavailable Deployment
strategy, so an upgrade cannot briefly run two independent reconcilers. Lease
leadership and manual enrollment are tracked in the
[controller design record](../../docs/design/kubernetes-controller-plan.md) before multi-replica
support is declared.

The server must support `GET /v1/agent/sync`, and existing environments must
complete the dry-run-first `backfill:agent-sync` operator before upgrading the
controller. New environments initialize their index automatically. The cursor
and identity/API fingerprint are persisted in HemligConsumer status only after
resource reconciliation succeeds. Expired or scope-changed cursors trigger a
fresh index snapshot. Older servers or incomplete indexes fail visibly and
back off; the controller does not fall back to per-secret polling. See the
[sync design record](../../docs/design/agent-sync-plan.md).

## Identity rotation and recovery

The agent mTLS leaf is rotated by the controller itself; no administrator
credential is involved. When fewer than `spec.identity.rotateBefore` (default
`720h`, clamped to half the certificate lifetime; `0h` disables automatic
rotation) remain, the controller generates a new RSA key asynchronously,
persists it in the identity Secret (`hemlig.io.next-tls.key`,
`hemlig.io.next-csr`), asks Hemlig to sign the CSR over the current mTLS
identity (`POST /v1/agent/identities/rotate`, idempotent by CSR hash), stores
the issued leaf (`hemlig.io.next-tls.crt`), and **verifies it by authenticating
with it** before swapping. The old pair is kept as `hemlig.io.previous-tls.crt`
and `hemlig.io.previous-tls.key` (rollback: copy them back over `tls.crt` and
`tls.key`). Until verification succeeds the old identity keeps being used, and a
rotation failure never makes the consumer `Ready=False`; it is reported on the
separate `IdentityRotation` condition with a reason such as `RotationFailed`,
`RotationUnsupported` (older server), `RotationRejected`, `RotationForbidden`,
`IdentityLimitReached`, `IdentityAlreadyRotated`, `RotationConflict` (a concurrent
rotation of the same consumer; retried with the same staged key), `AuthenticationFailed`, or
`VerificationFailed`. Failed attempts retry with their own capped exponential
backoff (60 s doubling to 6 h; reset on restart), with the periodic sweep as a
safety net. Pending keys are discarded only when Hemlig rejects the request or
the issued certificate is unusable. If the current certificate can no longer
authenticate but an issued successor (`hemlig.io.next-tls.*`) is still valid and
verifies, the controller automatically recovers by swapping it in; the pending
keys are never discarded on that path. The swap only applies if `tls.crt` is
unchanged, so a concurrent operator rollback is not overwritten.

Inspect state with `kubectl get hemligconsumer` (Identity-Expires and Rotation
columns) or `status.identity` (`apiFingerprint`, `notBefore`, `notAfter`,
`rotateAfter`, `lastRotationTime`, `rotationRequest`, `lastRotationError`).

To rotate on demand, set a new token (any unique value) on the consumer:

```sh
kubectl annotate hemligconsumer payments hemlig.io/rotate-identity=$(date +%s) --overwrite
```

The consumed token is recorded on the identity Secret
(`hemlig.io/rotation-request`) in the same write as the new certificate, so a
token rotates exactly once even across restarts and failed passes.

### Imported Secrets are not deleted on our own failures

A materialized import is deleted only when Hemlig's authoritative grant no
longer includes read access: either the synchronized grant/index says so, or a
remote 403/404 is confirmed by a successful fresh agent configuration read that
no longer grants read. An expired or revoked client certificate
(`AuthenticationFailed`), an unconfirmable denial (`RevocationUnconfirmed`),
a denial while the grant still allows read (`RemoteAccessDenied`), and a secret
without a value yet (`AwaitingValue`) all retain the existing target.

### Recovering an expired or revoked identity

If the certificate expired before it could rotate, the consumer reports
`AuthenticationFailed` and imports report `ConsumerNotReady`; existing target
Secrets are left in place. Do not delete the identity Secret (that would require
a new bootstrap capability). Instead:

1. Generate a key and CSR locally:
   `openssl req -new -newkey rsa:3072 -nodes -keyout tls.key -subj "/CN=Hemlig Kubernetes agent" -out tls.csr`
2. An administrator issues a leaf for the consumer with
   `POST /v1/admin/consumers/{consumerId}/api-identities`
   (`apiCertificateSigningRequestPem` = the CSR) and returns the certificate.
3. Patch the identity Secret with base64 `tls.crt` and `tls.key`, and remove any
   stale `hemlig.io.next-*` keys:
   `kubectl -n payments patch secret hemlig-payments-client --type json -p '[{"op":"replace","path":"/data/tls.crt","value":"<b64>"},{"op":"replace","path":"/data/tls.key","value":"<b64>"}]'`
4. Run the on-demand rotation above so the controller moves onto a leaf issued
   through self-rotation, then have the administrator revoke the admin-issued
   leaf if desired. (Admin-issued leaves of an agent consumer are also
   registered with AWS IoT.)

If the identity limit is reached (`IdentityLimitReached`), an administrator must
revoke unused identities with `DELETE /v1/admin/consumers/{consumerId}/api-identities/{fingerprint}`.
After a successful rotation the predecessor may rotate again once its successor
has been revoked, which is how a rollback to `previous-tls.*` is followed by a
fresh rotation. The 3-identity cap is enforced under concurrent self-rotations
(a losing rotation is retried as `RotationConflict`); administrator-issued
identities are not capped.

For a release install, use the Zyno chart repository:

```sh
helm repo add zyno https://zyno-io.github.io/charts
helm repo update
helm upgrade --install hemlig-controller zyno/hemlig-controller \
  --namespace hemlig-system \
  --create-namespace
```

The chart installs the CRDs by default. Its current ClusterRole is deliberately
cluster-wide: the controller lists and watches Hemlig resources and source
Secrets across namespaces. `HemligProvider` namespace selectors and the remote
`AgentGrant` exact-secret scope still constrains which remote secrets a
namespace can use, but they do not narrow this Kubernetes RBAC grant. Review
that grant before installing it. Namespace-restricted Kubernetes RBAC depends
on a controller runtime that can limit discovery and watches to an explicit
namespace set; it is not represented as a false least-privilege option today.

For a non-Helm installation, apply [CRDs](config/crds.yaml) then the broad
cluster-operator [manager manifest](config/manager.yaml).

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

The administrator-side AgentGrant must explicitly select
`payments/production/api-key` and `payments/production/api-key-source` for the
appropriate read/write capabilities. Hemlig resolves those selections to
immutable UIDs, so Kubernetes RBAC alone cannot expand them. An export rejects
an import-managed source, and an import refuses to overwrite a user-owned
target.

By default, `consumerRef` resolves only inside the import or export namespace.
This is the normal one-consumer-per-namespace model. A platform may instead use
one deliberately shared cluster consumer by setting
`HemligConsumer.spec.allowCrossNamespaceReferences: true` and naming both the
consumer and its namespace on each workload resource:

```yaml
spec:
  consumerRef: cluster
  consumerNamespace: hemlig-system
```

This is an explicit trust-boundary decision: every namespace allowed to refer
to that consumer shares its mTLS identity and the union of its remote
AgentGrant exact-secret selections. The consumer's bootstrap Secret and identity Secret always
remain in the consumer's own namespace.

Build from the monorepo root:

```sh
docker build -f packages/kubernetes-controller/Dockerfile -t hemlig-controller:dev .
```

CI publishes `ghcr.io/zyno-io/hemlig-controller:main` from `main`; a Git tag
such as `v0.1.0` publishes the exact `:v0.1.0` image and a matching immutable
`hemlig-controller-0.1.0.tgz` asset in the
[Zyno charts repository](https://github.com/zyno-io/charts). The charts
repository then regenerates its public Helm index. Generated chart archives are
never committed to this source repository.
