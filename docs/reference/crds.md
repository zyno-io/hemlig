---
title: Kubernetes CRD reference
description: Every field, status field, annotation and status reason of the HemligProvider, HemligConsumer, HemligSecretImport and HemligSecretExport resources.
pageType: reference
---

# Kubernetes CRD reference

Field-by-field reference for the four Hemlig custom resources, plus every status reason the controller reports.

Group `hemlig.io`, version `v1beta1` (the CRDs also serve `v1alpha1` for imports
and exports during migration; it is not extended). The schemas live in
[`chart/hemlig-controller/crds/hemlig.io.yaml`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.io.yaml).
For usage see the [controller guide](../guide/kubernetes.md).

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
| `spec.allowCrossNamespaceReferences`   | boolean | no       | Lets imports and exports in other namespaces use this consumer (they must set `consumerNamespace`)           |

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
| `identity.rotationRequest`             | Last honored `hemlig.io/rotate-identity` token                                                       |
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

## Annotations and labels

| Key                              | On               | Meaning                                                              |
| -------------------------------- | ---------------- | -------------------------------------------------------------------- |
| `hemlig.io/managed-by`           | Secrets          | `consumer` for identity Secrets, `import` for import targets         |
| `hemlig.io/consumer-owner`       | identity Secret  | Owning `namespace/name` of the `HemligConsumer`                      |
| `hemlig.io/import-owner`         | import target    | Owning import                                                        |
| `hemlig.io/secret-id`, `secret-uid`, `control-version-id`, `payload-version-id`, `data-checksum` | import target | Provenance of the materialized data |
| `hemlig.io/provider`, `grant-id`, `api-fingerprint` | identity Secret | Provider name, grant, and fingerprint of the current leaf |
| `hemlig.io/rotate-identity`      | HemligConsumer   | Forces one rotation (see [Identity rotation](../operations/identity-rotation.md#force-a-rotation)) |
| `hemlig.io/rotated-at`           | identity Secret  | When the current certificate was swapped in                           |

## Status reasons

Every `reason` the controller writes on a `Ready` or `IdentityRotation` condition.
Use `kubectl describe` on the resource, or the `Reason` printer column, to see the current one.

The reasons below come from [`v1beta.ts`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/src/v1beta.ts). Any other error on a resource is reported as `ReconcileFailed`.

### HemligConsumer, condition `Ready`

| Reason | Status | Meaning | Action |
| --- | --- | --- | --- |
| `IdentityReady` | True | Enrolled and syncing | None |
| `ProviderNotFound` | False | `providerRef` names no `HemligProvider` | Fix `providerRef` or create the provider |
| `ProviderNotPermitted` | False | The namespace labels do not match the provider's `allowedNamespaces` | Label the namespace, for example `kubectl label namespace payments hemlig.io/provider-production=true` |
| `BootstrapTokenUnavailable` | False | The bootstrap Secret or its key is missing and no identity exists yet | Create the Secret. If the token expired, ask an administrator for a new one ([Give a cluster access](../guide/agent-grants.md#replace-an-expired-token)) |
| `IdentityOwnershipConflict` | False | The identity Secret exists but this consumer does not own it, or the owned Secret is missing a key | Pick another `identity.secretName`, or delete the foreign Secret |
| `AuthenticationFailed` | False | Hemlig rejected the client certificate (expired, revoked or untrusted) <Badge type="tip" text="v0.3.0+" /> | The controller cannot repair this. See [expired certificate](../operations/identity-rotation.md#if-the-certificate-already-expired) |
| `ReconcileFailed` | False | Any other error, for example Hemlig answered 403, 409 or 503 | Read the controller logs. See [Troubleshooting](../operations/troubleshooting.md#controller) |

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
| `RemoteSecretNotFound` | False | The remote secret does not exist or is not in the grant | An administrator must create it and add it to the AgentGrant |
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
