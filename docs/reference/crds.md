---
title: Kubernetes CRD reference
description: Every field of the HemligProvider, HemligConsumer, HemligSecretImport and HemligSecretExport resources.
---

# Kubernetes CRD reference

Group `hemlig.io`, version `v1beta1` (the CRDs also serve `v1alpha1` for imports
and exports during migration; it is not extended). The schemas live in
[`chart/hemlig-controller/crds/hemlig.io.yaml`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.io.yaml).
For usage see the [controller guide](/guide/kubernetes).

## HemligProvider (cluster-scoped)

Short name `hmlprovider`. Public endpoints plus who may use them.

| Field                                | Type              | Required | Description                                                                 |
| ------------------------------------ | ----------------- | -------- | --------------------------------------------------------------------------- |
| `spec.bootstrapUrl`                  | string            | yes      | Administrator origin (`adminFqdn`), used only for `POST /v1/bootstrap/redeem`. `https://host` with no path, query or fragment |
| `spec.apiUrl`                        | string            | yes      | Delivery origin (`apiFqdn`) for mTLS calls. Same format                      |
| `spec.allowedNamespaces.matchLabels` | map[string]string | yes      | At least one label. A consumer's namespace must carry all of them            |

## HemligConsumer (namespaced)

Short name `hmlconsumer`. Has a `status` subresource.

| Field                                  | Type    | Required | Description                                                                                                  |
| -------------------------------------- | ------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `spec.providerRef`                     | string  | yes      | Name of a `HemligProvider`                                                                                   |
| `spec.bootstrapTokenRef.name`          | string  | yes      | Same-namespace Secret holding the `hmlb_...` capability                                                      |
| `spec.bootstrapTokenRef.key`           | string  | yes      | Key within that Secret                                                                                       |
| `spec.identity.secretName`             | string  | yes      | Name of the identity Secret the controller creates and owns (`tls.crt`, `tls.key`)                           |
| `spec.identity.rotateBefore`           | string  | no       | Duration `^[0-9]+[smhd]$`: how long before certificate expiry to rotate automatically. Default `720h`; `0s`/`0h` disables; the effective window is capped at half the certificate lifetime. Honored only by releases with [identity self-rotation](/operations/identity-rotation) (accepted but ignored before) |
| `spec.allowCrossNamespaceReferences`   | boolean | no       | Lets imports and exports in other namespaces use this consumer (they must set `consumerNamespace`)           |

### Status

| Field                                  | Description                                                                                          |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `observedGeneration`                   | Last reconciled generation                                                                           |
| `consumerId`, `environment`, `grantId` | From the active AgentGrant                                                                           |
| `syncCursor`, `syncIdentity`           | Saved sync checkpoint, and a hash of the provider URL and certificate it belongs to                  |
| `conditions`                           | `Ready` (reasons in the [guide](/guide/kubernetes#status-and-conditions))                            |
| `identity`, condition `IdentityRotation` | Certificate expiry and rotation state, in releases with rotation; see [Identity rotation](/operations/identity-rotation#observing-rotation) |

## HemligSecretImport (namespaced)

Short name `hmlimport`.

| Field                      | Type   | Required | Description                                                                                         |
| -------------------------- | ------ | -------- | --------------------------------------------------------------------------------------------------- |
| `spec.consumerRef`         | string | yes      | Consumer name                                                                                        |
| `spec.consumerNamespace`   | string | no       | Defaults to the import's namespace; another namespace requires the consumer's opt-in                 |
| `spec.secretId`            | string | yes      | Remote secret ID (max 256, `^[a-z][a-z0-9-]{2,63}(/[a-z][a-z0-9-]{2,63})*$`); must be in the grant's read scope |
| `spec.target.name`         | string | no       | Kubernetes Secret name; defaults to the import's name                                                |
| `spec.target.type`         | string | no       | Secret type; defaults to `Opaque`                                                                    |
| `spec.deletionPolicy`      | enum   | no       | `Retain` or `Delete`. Accepted by the schema but **not read by the current controller**              |

Status: `observedGeneration`, `secretUid`, `controlVersionId`, `payloadVersionId`, `conditions`.

## HemligSecretExport (namespaced)

Short name `hmlexport`.

| Field                        | Type                         | Required | Description                                                          |
| ---------------------------- | ---------------------------- | -------- | -------------------------------------------------------------------- |
| `spec.consumerRef`           | string                       | yes      | Consumer name                                                         |
| `spec.consumerNamespace`     | string                       | no       | As for imports                                                        |
| `spec.secretId`              | string                       | yes      | Remote secret ID; must already exist and be in the grant's write scope |
| `spec.source.name`           | string                       | yes      | Same-namespace source Secret (must not be import-managed)             |
| `spec.metadata`              | object                       | yes      | Remote metadata; may be `{}`                                          |
| `spec.metadata.description`  | string (max 1024)            | no       | Remote description                                                    |
| `spec.metadata.tags`         | map (max 20, values max 128) | no       | Remote tags                                                           |

Status adds `sourceChecksum`.

## Annotations and labels

| Key                              | On               | Meaning                                                              |
| -------------------------------- | ---------------- | -------------------------------------------------------------------- |
| `hemlig.io/managed-by`           | Secrets          | `consumer` for identity Secrets, `import` for import targets         |
| `hemlig.io/consumer-owner`       | identity Secret  | Owning `namespace/name` of the `HemligConsumer`                      |
| `hemlig.io/import-owner`         | import target    | Owning import                                                        |
| `hemlig.io/secret-id`, `secret-uid`, `control-version-id`, `payload-version-id`, `data-checksum` | import target | Provenance of the materialized data |
| `hemlig.io/provider`, `grant-id`, `api-fingerprint` | identity Secret | Provider name, grant, and fingerprint of the current leaf |
| `hemlig.io/rotate-identity`      | HemligConsumer   | Forces one rotation (see [Identity rotation](/operations/identity-rotation#force-a-rotation)) |
