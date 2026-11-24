---
title: Kubernetes CRD reference
description: Every field, status field, annotation and status reason of the HemligProvider, HemligConsumer, HemligSecretImport, HemligSecretExport, HemligIssuer, HemligClusterIssuer and HemligTrustBundle resources.
pageType: reference
---

# Kubernetes CRD reference

Field-by-field reference for the seven Hemlig custom resources, plus every status reason the controller reports.

Group `hemlig.zyno.io`, version `v1beta1` (the CRDs also serve `v1alpha1` for imports
and exports during migration; it is not extended).

`HemligIssuer`, `HemligClusterIssuer` and `HemligTrustBundle` are `v1alpha1` and may change before beta.

The schemas live in
[`chart/hemlig-controller/crds/hemlig.zyno.io.yaml`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io.yaml)
and [`hemlig.zyno.io-pki.yaml`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io-pki.yaml).

For usage see the [controller guide](../guide/kubernetes.md), [Issue certificates with cert-manager](../guide/cert-manager.md) and [Distribute trust bundles](../guide/trust-bundles.md).

## HemligProvider (cluster-scoped)

Short name `hmlprovider`. Public endpoints plus who may use them.

| Field                                | Type              | Required | Description                                                                 |
| ------------------------------------ | ----------------- | -------- | --------------------------------------------------------------------------- |
| `spec.bootstrapUrl`                  | string            | yes      | Administrator origin (`adminFqdn`), used only for `POST /v1/bootstrap/redeem`. an HTTPS origin with no path, query or fragment |
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
| `spec.identity.rotateBefore`           | string  | no       | Duration `^[0-9]+[smhd]$`: how long before certificate expiry to rotate automatically. Default `720h`; `0s`/`0h` disables; the effective window is capped at half the certificate lifetime. <Badge type="tip" text="v0.3.0+" /> Controllers before v0.3.0 accept the field but ignore it (see [Identity rotation](../operations/identity-rotation.md)) |
| `spec.allowCrossNamespaceReferences`   | boolean | no       | Lets imports, exports and `HemligIssuer`s in other namespaces use this consumer (they must set `consumerNamespace`) |
| `spec.allowClusterIssuers`             | boolean | no       | Lets a `HemligClusterIssuer` use this consumer from any namespace. Separate from `allowCrossNamespaceReferences`; default false |

### Status

| Field                                  | Description                                                                                          |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `observedGeneration`                   | Last reconciled generation                                                                           |
| `consumerId`, `environment`, `grantId` | From the active AgentGrant                                                                           |
| `syncCursor`, `syncIdentity`           | Saved sync checkpoint, and a hash of the provider URL and certificate it belongs to                  |
| `conditions`                           | `Ready`, and from v0.3.0 `IdentityRotation`. Reasons are in [Status reasons](#status-reasons)        |
| `identity.apiFingerprint`              | Fingerprint of the certificate in use                                                                |
| `identity.notBefore`, `identity.notAfter` | Validity of that certificate                                                                      |
| `identity.rotateAfter`                 | When automatic rotation becomes due                                                                  |
| `identity.lastRotationTime`            | When the last rotation completed                                                                     |
| `identity.rotationRequest`             | Last honored `hemlig.zyno.io/rotate-identity` token                                                       |
| `identity.lastRotationError`           | Most recent rotation failure, cleared on success                                                     |

The `identity` fields arrived in v0.3.0. How to read them is in [Identity rotation](../operations/identity-rotation.md#observe-rotation).

### Printer columns

`kubectl get hmlconsumer` shows `Ready`, `Reason`, `Identity-Expires`, `Rotation` and `Age`. `Rotation` is the reason of the `IdentityRotation` condition.

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

::: warning `deletionPolicy` does nothing
Deleting a `HemligSecretImport` leaves its target Secret behind, whatever `deletionPolicy` says. Delete the Secret yourself if you want it gone.
:::

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

## HemligIssuer (namespaced)

Short name `hmlissuer`, version `v1alpha1`. Has a `status` subresource. A cert-manager `Certificate` names it in `issuerRef`. See [Issue certificates with cert-manager](../guide/cert-manager.md).

| Field                    | Type   | Required | Description                                                                                   |
| ------------------------ | ------ | -------- | --------------------------------------------------------------------------------------------- |
| `spec.consumerRef`       | string | yes      | `HemligConsumer` name                                                                         |
| `spec.consumerNamespace` | string | no       | Defaults to the issuer's namespace; another namespace requires the consumer's `allowCrossNamespaceReferences` |
| `spec.issuanceGrant`     | string | yes      | Name of an issuance grant held by the consumer (`^[a-z][a-z0-9-]{2,63}$`)                     |

`spec` is immutable except `issuanceGrant`: create a new issuer to point at another consumer.

## HemligClusterIssuer (cluster-scoped)

Short name `hmlclusterissuer`, version `v1alpha1`. Has a `status` subresource.

| Field                                  | Type              | Required | Description                                                                                     |
| -------------------------------------- | ----------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `spec.consumerRef.name`                | string            | yes      | `HemligConsumer` name                                                                           |
| `spec.consumerRef.namespace`           | string            | yes      | The consumer's namespace. The consumer must set `allowClusterIssuers: true`                     |
| `spec.issuanceGrant`                   | string            | yes      | Name of an issuance grant held by the consumer                                                  |
| `spec.allowedNamespaces.matchLabels`   | map[string]string | no       | One to 16 labels. Only requests from namespaces carrying all of them are issued. Default: every namespace |

`spec` is immutable except `issuanceGrant`.

### Issuer status

| Field                  | Description                                                              |
| ---------------------- | ------------------------------------------------------------------------ |
| `observedGeneration`   | Last reconciled generation. A request waits until it equals `metadata.generation` |
| `consumerId`, `environment` | From the resolved consumer                                          |
| `caId`, `caFingerprint`, `caNotAfter` | The CA that the grant issues from                             |
| `issuanceGrantVersion`, `grantUid` | The grant's current version and identity                         |
| `conditions`           | `Ready`. Reasons are in [Status reasons](#hemligissuer-and-hemligclusterissuer-condition-ready)   |

### Printer columns

`kubectl get hmlissuer` and `kubectl get hmlclusterissuer` show `Ready`, `Reason`, `CA`, `Grant` and `Age`.

## HemligTrustBundle (namespaced)

Short name `hmltrustbundle`, version `v1alpha1`. Has a `status` subresource. It writes the anchors, intermediates and CRLs of the listed CAs to ConfigMaps in its own namespace. See [Distribute trust bundles](../guide/trust-bundles.md).

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `spec.consumerRef` | string | yes | `HemligConsumer` name |
| `spec.consumerNamespace` | string | no | Defaults to the bundle's namespace; another namespace requires the consumer's `allowCrossNamespaceReferences` |
| `spec.caIds` | []string | yes | 1 to 50 unique CA IDs, each `^ca-[a-z0-9-]{2,79}[a-z0-9]$`. Get them from `hemlig pki ca list` |
| `spec.includeCrl` | boolean | no | Default `true`. When `false`, no CRL ConfigMaps are written and existing ones are deleted |
| `spec.crlFormat` | string | no | `der` (default) or `pem` |
| `spec.target.name` | string | yes | Name of the target ConfigMap, 1 to 165 characters, `^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$` |

`consumerRef`, `consumerNamespace` and `target.name` are immutable (`consumerRef, consumerNamespace and target are immutable`); create a new bundle instead. `caIds`, `includeCrl` and `crlFormat` can change.

| Status field | Description |
| --- | --- |
| `observedGeneration` | Last reconciled generation |
| `consumerId`, `environment` | From the resolved consumer |
| `acceptedCaIds` | Sorted CA IDs whose material is in the target ConfigMap. Mirrors its `hemlig.zyno.io/ca-ids` annotation |
| `crls` | One entry per CRL ConfigMap, sorted by `id`: `id`, `source` (`GENERATED` or `UPLOADED`), `configMap`, `state`, `number`, `thisUpdate` and `nextUpdate` |
| `crls[].state` | `Current`, `Stale` (past `nextUpdate`), `Missing` (Hemlig has no CRL yet), `Rejected` (the ConfigMap could not be written) or `Conflict` (a ConfigMap the bundle does not own) |
| `conditions` | `Ready`. Reasons are in [Status reasons](#hemligtrustbundle-condition-ready) |

### Printer columns

`kubectl get hmltrustbundle` shows `Ready`, `Reason`, `Target` and `Age`.

### ConfigMaps

Both kinds carry the label `hemlig.zyno.io/managed-by: trust-bundle`, the annotation `hemlig.zyno.io/trust-bundle-owner: <namespace>/<name>` and an `ownerReferences` entry for the bundle, so Kubernetes deletes them with it. The controller never writes a ConfigMap that lacks this label and owner.

| ConfigMap | Name | Content | Extra annotations |
| --- | --- | --- | --- |
| Target | `spec.target.name` | `data["ca.crt"]`: the trusted anchors, deduplicated. `data["chain.crt"]`: every CA certificate and non-anchor intermediate, deduplicated | `hemlig.zyno.io/ca-ids`: the accepted CA IDs, sorted and comma-joined |
| CRL | `<target>-crl-<issuerId>` | `der`: `binaryData["crl.der"]`. `pem`: `data["crl.pem"]` | `hemlig.zyno.io/crl-issuer`, `crl-source`, `crl-sha256` (of the DER), `crl-number`, `crl-this-update`, `crl-next-update` |

## Annotations and labels

| Key                              | On               | Meaning                                                              |
| -------------------------------- | ---------------- | -------------------------------------------------------------------- |
| `hemlig.zyno.io/managed-by`           | Secrets          | `consumer` for identity Secrets, `import` for import targets         |
| `hemlig.zyno.io/consumer-owner`       | identity Secret  | Owning `namespace/name` of the `HemligConsumer`                      |
| `hemlig.zyno.io/import-owner`         | import target    | Owning import                                                        |
| `hemlig.zyno.io/secret-id`, `secret-uid`, `control-version-id`, `payload-version-id`, `data-checksum` | import target | Provenance of the materialized data |
| `hemlig.zyno.io/provider`, `grant-id`, `api-fingerprint` | identity Secret | Provider name, grant, and fingerprint of the current leaf |
| `hemlig.zyno.io/rotate-identity`      | HemligConsumer   | Forces one rotation (see [Identity rotation](../operations/identity-rotation.md#force-a-rotation)) |
| `hemlig.zyno.io/rotated-at`           | identity Secret  | When the current certificate was swapped in                           |
| `hemlig.zyno.io/managed-by`           | ConfigMaps       | `trust-bundle` on the target and CRL ConfigMaps of a `HemligTrustBundle` |
| `hemlig.zyno.io/trust-bundle-owner`   | trust bundle ConfigMaps | Owning `namespace/name` of the `HemligTrustBundle`              |
| `hemlig.zyno.io/ca-ids`               | target ConfigMap | Accepted CA IDs, sorted and comma-joined                              |
| `hemlig.zyno.io/crl-issuer`, `crl-source`, `crl-sha256`, `crl-number`, `crl-this-update`, `crl-next-update` | CRL ConfigMap | The CRL's issuer ID, source, DER SHA-256 and metadata |

## Status reasons

Every `reason` the controller writes on a `Ready` or `IdentityRotation` condition.
Use `kubectl describe` on the resource, or the `Reason` printer column, to see the current one.

The reasons below come from [`v1beta.ts`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/src/v1beta.ts). Any other error on a resource is reported as `ReconcileFailed`.

### HemligConsumer, condition `Ready`

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `IdentityReady` | True | Enrolled and syncing | None |
| `ProviderNotFound` | False | `providerRef` names no `HemligProvider` | Fix `providerRef` or create the provider |
| `ProviderNotPermitted` | False | The namespace labels do not match the provider's `allowedNamespaces` | Label the namespace, for example `kubectl label namespace payments hemlig.zyno.io/provider-production=true` |
| `BootstrapTokenUnavailable` | False | The bootstrap Secret or its key is missing and no identity exists yet | Create the Secret. If the token expired, ask an administrator for a new one ([Give a cluster access](../guide/agent-grants.md#replace-an-expired-token)) |
| `IdentityOwnershipConflict` | False | The identity Secret exists but this consumer does not own it, or the owned Secret is missing a key | Pick another `identity.secretName`, or delete the foreign Secret |
| `AuthenticationFailed` | False | Hemlig rejected the client certificate (expired, revoked or untrusted) <Badge type="tip" text="v0.3.0+" /> | The controller cannot repair this. See [expired certificate](../operations/identity-rotation.md#if-the-certificate-already-expired) |
| `ReconcileFailed` | False | Any other error, for example Hemlig answered 403, 409 or 503 | Read the controller logs. See [Troubleshooting](../operations/troubleshooting.md#controller) |

### HemligIssuer and HemligClusterIssuer, condition `Ready`

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `Ready` | True | The consumer is usable and the grant and its CA are active | None |
| `ConsumerNotFound` | False | `consumerRef` names no `HemligConsumer` | Fix `consumerRef` or create the consumer |
| `ConsumerNotReady` | False | The consumer is not ready, or Hemlig rejected its identity | Fix the consumer first |
| `ConsumerReferenceNotPermitted` | False | The consumer does not allow references from this namespace | Set `allowCrossNamespaceReferences: true` on the consumer, or use a consumer in the issuer's namespace |
| `ClusterIssuerNotPermitted` | False | The consumer does not set `allowClusterIssuers: true` | Set it on the consumer. `allowCrossNamespaceReferences` is not enough |
| `ProviderNotPermitted` | False | The namespace labels do not match the provider's `allowedNamespaces` (the issuer's namespace, or the consumer's for a cluster issuer) | Label the namespace |
| `IssuanceGrantNotFound` | False | The consumer holds no grant with this name | Create the grant, or fix `issuanceGrant` |
| `IssuanceGrantInactive` | False | The grant is `DISABLED` or has expired | Enable or replace the grant |
| `CaNotActive` | False | The grant's CA is not `ACTIVE` | Activate the CA, or move the grant to an active one |
| `RemoteError` | False | Hemlig could not be asked, or answered unexpectedly. A transient error keeps an already `Ready` issuer `Ready` | None for transient errors. Check the controller logs |

### HemligTrustBundle, condition `Ready`

The first matching row wins. The message names at most five CA IDs.

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `ConsumerNotFound` | False | `consumerRef` names no `HemligConsumer` | Fix `consumerRef` or create the consumer |
| `ConsumerReferenceNotPermitted` | False | The consumer does not allow references from this namespace | Set `allowCrossNamespaceReferences: true` on the consumer, or use a consumer in the bundle's namespace |
| `ConsumerNotReady` | False | The consumer is not ready, or Hemlig rejected its identity | Fix the consumer first |
| `ProviderNotPermitted` | False | The namespace labels do not match the provider's `allowedNamespaces` | Label the namespace |
| `ConfigMapConflict` | False | The target ConfigMap, or a CRL ConfigMap (`<target>-crl-<id>`), exists and the bundle does not own it. Nothing is written to it | Remove or rename the foreign ConfigMap, or create a new bundle with another `target.name` (`target.name` is immutable) |
| `ConfigMapRejected` | False | The target was not written: over 1,048,576 bytes, or the API server refused it. The previous content stays mounted | Remove CAs from `caIds`, or read the controller logs |
| `CaNotFound` | False | A listed CA does not exist, or is in another environment | Fix `caIds` |
| `CaNotActive` | False | A listed CA is `PENDING_CERTIFICATE` or `FAILED` | Activate the CA, or remove it from `caIds` |
| `CrlRejected` | False | A CRL is too large for a ConfigMap, or the API server refused it. The mounted copy is kept | Use `crlFormat: der`, or read the controller logs |
| `CrlMissing` | False | Hemlig has no CRL yet for a required issuer, for example a root CRL not uploaded | [Upload the root CRL](../guide/pki.md) |
| `CrlStale` | False | A required mounted CRL is past its `nextUpdate` | Check that Hemlig publishes it, or that the root CRL was uploaded |
| `RemoteError` | False | Hemlig could not be asked, or answered unexpectedly, and the bundle was not `Ready` before. A transient error keeps a `Ready` bundle `Ready` | None for transient errors. Check the controller logs |
| `CaDrained` | True | Every listed CA is usable, and at least one accepted CA is drained (not necessarily the one you plan to remove) | Check that `hemlig pki ca get <ca>` shows `drained: true` for the CA you want to remove, then remove it from `caIds` when no mount needs it |
| `Ready` | True | The target and every CRL are written and current | None |

A revoked CA stays in the target, so its anchor keeps verifying older chains. Its own CRL and a drained CA's CRL are not required, so they never raise `CrlStale` or `CrlMissing`.

### HemligSecretImport, condition `Ready`

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `TargetReady` | True | The Secret was materialized | None |
| `ConsumerNotReady` | False | The referenced consumer is not ready | Fix the consumer first |
| `AccessRevoked` | False | The grant no longer includes this import, so the owned Secret was removed | Ask for the secret to be added back to the grant |
| `TargetOwnershipConflict` | False | The target Secret belongs to something else | Choose another `target.name` |
| `AwaitingValue` | False | The remote secret exists but has no value yet <Badge type="tip" text="v0.3.0+" /> | Ask the owner to set the value. The import completes by itself |
| `AuthenticationFailed` | False | Hemlig denied the read and the controller's certificate is not valid <Badge type="tip" text="v0.3.0+" /> | Fix the identity. The target Secret is kept |
| `RevocationUnconfirmed` | False | Hemlig denied the read and the grant could not be re-checked <Badge type="tip" text="v0.3.0+" /> | Wait for the retry. The target Secret is kept |
| `RemoteAccessDenied` | False | Hemlig denied the read although the grant still allows it <Badge type="tip" text="v0.3.0+" /> | Ask an administrator to check the secret's state. The target Secret is kept |

How these protect your data is explained in [Safety](../operations/safety.md).

### HemligSecretExport, condition `Ready`

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `RemoteReady` | True | The source was written to Hemlig | None |
| `ConsumerNotReady` | False | The referenced consumer is not ready | Fix the consumer first |
| `RemoteSecretNotFound` | False | The control fetch returned `404`: the remote secret does not exist or is not visible to the grant | An administrator must create it and add it to the AgentGrant. A missing write grant shows `ReconcileFailed` (`Hemlig returned 403.`) instead |
| `SourceIsImportManaged` | False | The source Secret is an import target | Export a Secret your application owns |

### HemligConsumer, condition `IdentityRotation` <Badge type="tip" text="v0.3.0+" />

This condition never turns `Ready` false while the current certificate still works. Reasons that mention a staged key are explained in [Identity rotation](../operations/identity-rotation.md#failure-modes).

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `NotDue` | True | Healthy. Also set after a successful rotation | None |
| `AutomaticRotationDisabled` | True | `rotateBefore` is `0s` or `0h` | Annotate the consumer to rotate by hand |
| `RotationFailed` | False | Transient failure (429, 5xx, network, a Secret write conflict) | None. The same request is retried |
| `RotationRejected` | False | Hemlig refused the request, or the issued certificate did not match | None. A fresh key is generated on the next attempt |
| `RotationUnsupported` | False | The server has no rotation route | Deploy a Hemlig version that has it |
| `AuthenticationFailed` | False | The current certificate is expired or revoked | [Recover by hand](../operations/identity-rotation.md#if-the-certificate-already-expired) |
| `RotationForbidden` | False | The consumer has no `ACTIVE` AgentGrant | Check the grant with an administrator |
| `IdentityLimitReached` | False | Three active certificates already exist | [Revoke old certificates](../operations/identity-rotation.md#revoke-the-old-certificate) |
| `RotationConflict` | False | Another rotation of the same consumer committed at the same moment | None. Retried automatically |
| `IdentityAlreadyRotated` | False | This certificate already has an active successor | Revoke the unwanted successor, or install its key pair |
| `VerificationFailed` | False | The new certificate could not authenticate, or named another consumer | None. Retried; a fresh key is generated if the new one was unusable |
