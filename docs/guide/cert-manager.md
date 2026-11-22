---
title: "Issue certificates with cert-manager"
description: "Let cert-manager request and renew certificates from a Hemlig CA through a HemligIssuer or HemligClusterIssuer, with approval, status reasons and retry behavior."
pageType: how-to
---

# Issue certificates with cert-manager

The Hemlig controller is an external issuer for [cert-manager](https://cert-manager.io/docs/). A `Certificate` that names a `HemligIssuer` or `HemligClusterIssuer` is signed by a Hemlig CA and renewed with no human involved.

The controller turns each approved `CertificateRequest` into a call to the [PKI consumer routes](../reference/api/pki.md) using the consumer's mTLS identity. The grant decides what may be issued; the issuer only chooses which grant to use.

**Role:** platform team. **Before you start:** the [controller](kubernetes.md) with a Ready `HemligConsumer`, cert-manager with its CRDs, an `ACTIVE` CA ([PKI](pki.md)), and a consumer whose AgentGrant is PKI-only.

## Grant the consumer

Create an issuance grant for the consumer. The names, lifetime and quotas live in the grant, not in Kubernetes. Hemlig takes names from the CSR, so list every DNS name your Certificates will use.

```sh
hemlig pki grant create payments-prod web --ca prod-issuing-1 --file grant.json
```

The grant file format is in [PKI](pki.md#grant-a-consumer). A Certificate whose names the grant does not permit ends `Failed`.

## Create a HemligIssuer

A `HemligIssuer` is namespaced and uses a consumer in its own namespace.

```yaml
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligIssuer
metadata:
  name: payments-web
  namespace: payments
spec:
  consumerRef: payments
  issuanceGrant: web
```

To use a consumer in another namespace, set `consumerNamespace` and let the consumer opt in:

```yaml
spec:
  consumerRef: shared-pki
  consumerNamespace: hemlig-system
  issuanceGrant: web
```

```yaml
# On the HemligConsumer in hemlig-system
spec:
  allowCrossNamespaceReferences: true
```

`spec` is immutable except `issuanceGrant`. Check the result with `kubectl -n payments get hmlissuer`. `READY` is `True` when the consumer is usable and the grant and its CA are active.

## Create a HemligClusterIssuer

A `HemligClusterIssuer` can be named from any namespace. Because that is wider than a namespace reference, the consumer needs its own opt-in, `allowClusterIssuers`. `allowCrossNamespaceReferences` does not imply it.

```yaml
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligClusterIssuer
metadata:
  name: mesh
spec:
  consumerRef: { name: cluster-pki, namespace: hemlig-system }
  issuanceGrant: mesh
  allowedNamespaces:
    matchLabels:
      pki.example.com/mesh: "true"
```

```yaml
# On the HemligConsumer cluster-pki
spec:
  allowClusterIssuers: true
```

`allowedNamespaces` is optional. When set, a request from a namespace without all those labels fails with `NamespaceNotPermitted`. When omitted, every namespace may use the issuer, so the grant is the only limit.

## Request a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web
  namespace: payments
spec:
  secretName: web-tls
  dnsNames: [api.payments.example.com]
  duration: 24h
  renewBeforePercentage: 33
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef:
    group: hemlig.zyno.io
    kind: HemligIssuer
    name: payments-web
```

Set `issuerRef.group` to `hemlig.zyno.io`. An empty group means cert-manager's own issuers, and the controller ignores those requests.

Prefer `renewBeforePercentage` to `renewBefore`. Hemlig clamps a lifetime to the grant and CA limits, and a fixed `renewBefore` larger than the clamped lifetime makes cert-manager renew continuously.

Hemlig issues only what the CSR and grant allow. It rejects `isCA: true` and any usage other than digital signature, key encipherment, server auth and client auth. It never uses cert-manager's `username` or `groups`.

## Approval

cert-manager's built-in approver approves only its own issuer types, so a request for a Hemlig issuer waits forever unless something approves it. The grant is the real boundary; approval is an extra layer. Pick one option.

| Option                   | Setup                                                                                                                                                                                                                           |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chart default            | `certManager.approval.grantDefaultApprover: true` (the default). A ClusterRole and binding let cert-manager's ServiceAccount (`certManager.approval.serviceAccount` and `.namespace`) approve every request for a Hemlig issuer |
| cert-manager Helm values | Add the two signer patterns to `approveSignerNames` in the cert-manager chart, and set `grantDefaultApprover: false`                                                                                                            |
| approver-policy          | Set `grantDefaultApprover: false`, disable cert-manager's default approver, and write a `CertificateRequestPolicy` for the Hemlig issuers                                                                                       |

For the raw manifests, apply [`config/cert-manager-approval.yaml`](https://github.com/zyno-io/hemlig/blob/main/packages/kubernetes-controller/config/cert-manager-approval.yaml) for the default option. Its subject is `cert-manager/cert-manager`; change it if cert-manager runs as another ServiceAccount.

```yaml
# cert-manager Helm values
approveSignerNames:
  - hemligissuers.hemlig.zyno.io/*
  - hemligclusterissuers.hemlig.zyno.io/*
```

```yaml
# approver-policy
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: hemlig
spec:
  selector:
    issuerRef:
      group: hemlig.zyno.io
      kind: HemligIssuer
      name: "*"
```

Grant approver-policy's ServiceAccount `approve` on both signers, and bind `use` of the policy to the requester, normally cert-manager's ServiceAccount.

The Hemlig controller's own ServiceAccount never has `approve`.

## What the controller writes

The `Ready` condition on a CertificateRequest uses only the reasons `Pending`, `Failed`, `Issued` and `Denied`, because cert-manager keys on them. The detail is a prefix in `message`. Look at it with `kubectl describe certificaterequest`.

| Reason    | Message prefix                                                                                       | Meaning                                                                                           | Action                                                                                                        |
| --------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `Issued`  | `Issued by <caId>, serial <serial>`                                                                  | The certificate was written to `status.certificate` and `status.ca`                               | None                                                                                                          |
| `Denied`  | `The CertificateRequest was denied.`                                                                 | An approver denied it                                                                             | None                                                                                                          |
| `Pending` | `Waiting for approval`                                                                               | Nothing approved it                                                                               | Approve it, or fix [approval](#approval)                                                                      |
| `Pending` | `IssuerNotFound`                                                                                     | The issuer does not exist                                                                         | Create it. The request waits                                                                                  |
| `Pending` | `IssuerNotReady`                                                                                     | The issuer is not `Ready`, or has not reconciled its latest generation                            | Read the issuer's reason in [CRDs](../reference/crds.md#hemligissuer-and-hemligclusterissuer-condition-ready) |
| `Pending` | `ConsumerNotFound`                                                                                   | The issuer's consumer is gone                                                                     | Fix `consumerRef`                                                                                             |
| `Pending` | `ConsumerNotReady`                                                                                   | The consumer is not Ready, or Hemlig rejected its identity (`identity_not_active`)                | Fix the consumer                                                                                              |
| `Pending` | `ConsumerReferenceNotPermitted`                                                                      | The consumer no longer allows this namespace                                                      | Restore `allowCrossNamespaceReferences`                                                                       |
| `Pending` | `ClusterIssuerNotPermitted`                                                                          | The consumer no longer sets `allowClusterIssuers`                                                 | Restore it                                                                                                    |
| `Pending` | `ProviderNotPermitted`                                                                               | The namespace no longer matches the provider's selector                                           | Restore the namespace labels                                                                                  |
| `Pending` | `InvalidResponse`                                                                                    | Hemlig returned an unexpected certificate response                                                | None. Retried; report it if it persists                                                                       |
| `Pending` | `HemligUnavailable`                                                                                  | A network error, a gateway `429`, or a `5xx`                                                      | None. Retried                                                                                                 |
| `Pending` | Hemlig code, for example `issuance_rate_limited (grant_hour)` or `ca_not_active`                     | A condition on the Hemlig side that can clear                                                     | Fix it in Hemlig, or wait                                                                                     |
| `Failed`  | `NamespaceNotPermitted`                                                                              | The cluster issuer's `allowedNamespaces` excludes the namespace                                   | Label the namespace, or use another issuer                                                                    |
| `Failed`  | `UnsupportedRequest`                                                                                 | `isCA`, an unsupported usage, an invalid duration, an invalid CSR, or an invalid `issuerRef.name` | Fix the Certificate                                                                                           |
| `Failed`  | Hemlig code, for example `issuance_denied (name_not_permitted)`, `issuance_revoked` or `invalid_csr` | Hemlig refused permanently                                                                        | Change the Certificate or the grant. cert-manager then creates a new request                                  |

A `Pending` request keeps its place and retries by itself. A `Failed` request is final; cert-manager creates a new one after its own backoff.

For a denial, the message adds the name type and the denied name when they are safe to print, for example `issuance_denied (name_not_permitted): dns api.not-granted.example.com`. Hemlig codes are listed in the [PKI consumer routes](../reference/api/pki.md#errors).

## Retries

| Cause                                                                                                                        | Delay                                                   |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Needs a person or a Hemlig change (grant missing or inactive, CA not active or full, identity not active, opt-ins withdrawn) | 30 s, doubling to 5 minutes, with jitter                |
| Network errors, `5xx`, a gateway `429`                                                                                       | 1 s, doubling to 5 minutes, with jitter                 |
| Hemlig `429 issuance_rate_limited`                                                                                           | The `Retry-After` the server sent, plus a little jitter |

The controller reuses the idempotency key `hml-cr-<metadata.uid>` for every attempt, so a lost response or a controller restart returns the same certificate and never issues twice. Constants are in [Limits and timings](../reference/limits.md#controller).

## Limits

- The controller runs as one replica. cert-manager requests are processed as they change, with a 5-minute resync.
- Default approval approves every request that names a Hemlig issuer. The grant limits what is issued.
- Mutually untrusted namespaces need separate consumers and grants. Hemlig cannot see namespaces, and a cluster issuer's grant is the union of everything its namespaces may ask for.
- Pointing an issuer at another consumer means a new issuer, so every Certificate on it issues one extra certificate.
- Trust bundles are not part of this release.

## Upgrading

Helm never upgrades CRDs. Before setting `allowClusterIssuers`, apply `crds/hemlig.zyno.io.yaml` and `crds/hemlig.zyno.io-pki.yaml` from the chart, or use Flux with `CreateReplace`. An old schema prunes `allowClusterIssuers`, which fails closed: cluster issuers stay `ClusterIssuerNotPermitted`.

## Next steps

- [CRD reference](../reference/crds.md)
- [PKI: certificate authorities and CRLs](pki.md)
- [Troubleshooting](../operations/troubleshooting.md#controller)
