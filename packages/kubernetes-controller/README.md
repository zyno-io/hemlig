# Clavis Kubernetes controller

The controller has two namespaced CRDs:

- `ClavisSecretImport` reads a granted Clavis secret over mTLS and materializes
  a Kubernetes Secret.
- `ClavisSecretExport` reads a Kubernetes Secret and reconciles its values,
  metadata, and ACL into Clavis through the administrator API.

Apply [CRDs](config/crds.yaml) and [manager RBAC/deployment](config/manager.yaml)
after replacing the image and endpoint placeholders. The mTLS Secret is read in
the same namespace as each import and must contain `tls.crt` and `tls.key`.
The admin token is a separate controller-pod Secret; it must be a short-lived
token refreshed by the workload identity/token delivery mechanism selected by
the installation.

Build the controller image from the monorepo root:

```sh
docker build -f packages/kubernetes-controller/Dockerfile -t clavis-controller:dev .
```

```yaml
apiVersion: clavis.io/v1alpha1
kind: ClavisSecretImport
metadata:
  name: payments-api
  namespace: payments
spec:
  secretId: payments-api
  target:
    name: payments-api
```

```yaml
apiVersion: clavis.io/v1alpha1
kind: ClavisSecretExport
metadata:
  name: payments-api-source
  namespace: payments
spec:
  secretId: payments-api
  environment: prod
  source: { name: payments-api-source }
  metadata: { name: payments-api, path: payments/production }
  acl:
    - clusterId: prod-east
      permissions: [read]
```

An export cannot source an imported Secret. An import will only update a target
that carries its exact `clavis.io/import-owner` marker; it refuses to overwrite
a user-owned Secret or another import's target. These constraints prevent
accidental import/export feedback loops and Secret clobbering. Clavis has no
delete API, so deleting either CR stops reconciliation but never deletes the
remote or local Secret.

Exports calculate a stable checksum of the source Secret. Once Clavis and the
CR status agree on that checksum and the Clavis revision, an unchanged polling
cycle makes no remote payload write, KMS encryption, or payload-write audit
event. The controller still reads control metadata to detect remote drift. A
source change or remote revision drift writes the payload again.

Imports use the cluster API's `If-None-Match` support after first confirming
that the materialized Secret still has the recorded Clavis revisions and data
checksum. An unchanged remote revision returns `304`, avoiding payload download
and KMS decryption; a missing or modified local target forces a full read and
repair. Conditional access requests remain represented in Clavis access audit
records as `not_modified` reads.
