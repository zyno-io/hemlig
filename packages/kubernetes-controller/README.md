# Hemlig Kubernetes controller

The `hemlig.io` CRDs replace the pre-1.0 `clavis.io` CRDs. Install them beside
the old CRDs, migrate resources to `HemligSecretImport` and
`HemligSecretExport`, then retire the old controller after the new resources
are ready; Kubernetes cannot rename a CRD group in place.

The controller has two namespaced CRDs:

- `HemligSecretImport` reads a granted Hemlig secret over mTLS and materializes
  a Kubernetes Secret.
- `HemligSecretExport` reads a Kubernetes Secret and reconciles its values,
  metadata, and ACL into Hemlig through the administrator API.

Apply [CRDs](config/crds.yaml) and [manager RBAC/deployment](config/manager.yaml)
after replacing the image and endpoint placeholders. The mTLS Secret is read in
the same namespace as each import and must contain `tls.crt` and `tls.key`.
The admin token is a separate controller-pod Secret; it must be a short-lived
token refreshed by the workload identity/token delivery mechanism selected by
the installation.

Build the controller image from the monorepo root:

```sh
docker build -f packages/kubernetes-controller/Dockerfile -t hemlig-controller:dev .
```

```yaml
apiVersion: hemlig.io/v1alpha1
kind: HemligSecretImport
metadata:
  name: payments-api
  namespace: payments
spec:
  secretId: payments-api
  target:
    name: payments-api
```

```yaml
apiVersion: hemlig.io/v1alpha1
kind: HemligSecretExport
metadata:
  name: payments-api-source
  namespace: payments
spec:
  secretId: payments-api
  environment: prod
  source: { name: payments-api-source }
  metadata: { name: payments-api, path: payments/production }
  acl:
    - consumerId: prod-east
      permissions: [read]
```

An export cannot source an imported Secret. An import will only update a target
that carries its exact `hemlig.io/import-owner` marker; it refuses to overwrite
a user-owned Secret or another import's target. These constraints prevent
accidental import/export feedback loops and Secret clobbering. Hemlig has no
delete API, so deleting either CR stops reconciliation but never deletes the
remote or local Secret.

Exports calculate a stable checksum of the source Secret. Once Hemlig and the
CR status agree on that checksum and the Hemlig revision, an unchanged polling
cycle makes no remote payload write, KMS encryption, or payload-write audit
event. The controller still reads control metadata to detect remote drift. A
source change or remote revision drift writes the payload again.

Imports use the consumer API's `If-None-Match` support after first confirming
that the materialized Secret still has the recorded Hemlig revisions and data
checksum. An unchanged remote revision returns `304`, avoiding payload download
and KMS decryption; a missing or modified local target forces a full read and
repair. Conditional access requests remain represented in Hemlig access audit
records as `not_modified` reads.
