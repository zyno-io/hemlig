---
title: "Troubleshooting"
description: "Symptom, cause and fix tables for the administrator API, enrollment, the controller and sync."
pageType: reference
---

# Troubleshooting

Find your symptom in the table for the part of Hemlig that is failing, then follow the fix.

For a Kubernetes status `reason`, go straight to [Status reasons](../reference/crds.md#status-reasons). For error codes see the [API reference](../reference/api/errors.md).

## Administrator API

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401` before any Hemlig error body | API Gateway rejected the token: missing, wrong audience, bad signature or expired | Get a fresh token and check it with [Verify your token](../guide/identity-provider.md#verify-your-token) |
| `403` | Insufficient scope (API Gateway, no Hemlig body), or the handler refused an accepted token (Hemlig error body: the gateway and the Lambda disagree about issuer, audience, scope or role) | Request the required scope, or fix the deployment configuration. A new token without the scope will not help. See [Identity provider](../guide/identity-provider.md) |
| `404` listing or writing in an environment | The environment does not exist. A new deployment has none | Create it with `POST /v1/admin/environments` |
| `409` creating an AgentGrant | The consumer ID is already enrolled | Use a new consumer ID |
| Creating an AgentGrant fails for a secret ID | Each secret in the grant must already exist | Create the secrets first, or add `dependsOn` in Pulumi |
| `409` issuing a bootstrap token | The grant is no longer `PENDING`. An `ACTIVE` grant cannot be re-bootstrapped | See [Give a cluster access](../guide/agent-grants.md#re-bootstrap-an-active-grant) |
| `409 conflict` on a secret write with a repeated `Idempotency-Key` | A key was reused with a different request | Use a fresh key. The rules per route are in [Idempotency](../reference/api/index.md#idempotency) |

## Enrollment

Enrollment is how a client gets its first [client certificate](../reference/glossary.md#client-certificate). Concepts are in [Identity and trust](../guide/identity-and-trust.md).

| Symptom | Cause | Fix |
| --- | --- | --- |
| `403` "bootstrap capability is invalid, expired, or already consumed" | The token is older than 30 minutes, was already used, or was mistyped | While the grant is `PENDING`, [issue a new token](../guide/agent-grants.md#replace-an-expired-token) |
| `400` on the CSR | The CSR is not a valid signed RSA request with a key of 2048 bits or more | Generate a new key and CSR. Limits are in [Limits and timings](../reference/limits.md#identity) |
| `409` "pending consumer enrollment does not match this certificate request" | A retry used a different CSR than the first attempt | Retry with the original CSR, or wait for the operation lease to end ([Limits and timings](../reference/limits.md#identity)) |
| `409` "issuing root is not available in the truststore" | An enrollment operation is stuck before the truststore update | Retry. The recovery worker may resume it after the operation lease ends ([Limits and timings](../reference/limits.md#identity)) |
| First enrollment takes longer than later ones | The issuing root is created on first use | Create it ahead of time with `POST /v1/admin/issuer` |
| `409 identity_limit_reached` | Self-rotation refused: 3 or more certificates are active | [Revoke old certificates](identity-rotation.md#revoke-the-old-certificate) |
| TLS handshake failure, no HTTP response | The client certificate is expired or not trusted by the gateway | [Identity rotation](identity-rotation.md#if-the-certificate-already-expired) |

## Controller

Start with the logs and the resource status:

```sh
kubectl -n hemlig-system logs -l app.kubernetes.io/name=hemlig-controller --tail=100
kubectl -n payments describe hmlconsumer payments
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| Consumer stuck on `BootstrapTokenUnavailable` | The token Secret is missing, or the token expired | Create the Secret, or [issue a new token](../guide/agent-grants.md#replace-an-expired-token) while the grant is `PENDING` |
| Consumer `ProviderNotPermitted` | The namespace lacks the provider's labels | Label the namespace as in [Bootstrap a namespace](../guide/kubernetes.md#bootstrap-a-namespace) |
| Consumer `AuthenticationFailed` | The client certificate expired or was revoked | [Recover the identity](identity-rotation.md#if-the-certificate-already-expired) |
| `ReconcileFailed` with HTTP `503` | The server's sync index is not ready | See [Sync](#sync) |
| Imported Secrets disappear | The grant no longer includes the secret | Confirm with an administrator. See [Safety](safety.md) |
| Imported Secrets stay but are stale, with `AuthenticationFailed` or `RevocationUnconfirmed` | The controller cannot confirm access, so it keeps the data | Fix the identity or the network. See [Safety](safety.md#when-it-never-deletes) |
| Nothing happens after changing a Secret | The namespace no longer matches the provider selector, or the consumer is not ready | Check the consumer reason first |
| `IdentityRotation` is `False` | A rotation attempt failed | See [Failure modes](identity-rotation.md#failure-modes). The old certificate keeps working |
| Pod restarts cause a gap in syncing | One replica with a zero-surge rollout | Expected. Imported Secrets stay in place |

## Sync

The controller keeps up with changes through a sync index. It is described in [Sync and notifications](../guide/sync-and-notifications.md).

| Symptom | Cause | Fix |
| --- | --- | --- |
| `503 sync_index_not_ready` | The environment's sync index was never backfilled | Run the [`backfill:agent-sync`](upgrades.md#backfill-agent-sync) script, dry run first |
| `503 sync_backfill_incomplete` | The backfill could not read a secret's current control revision | Re-run the backfill. If it keeps failing, report it |
| `410 sync_reset_required` | The sync checkpoint expired, or the grant's scope changed | The controller starts a fresh snapshot by itself. Other clients must drop the cursor and start over |
| Changes arrive only every ten minutes | MQTT hints are not reaching the controller, so only the periodic resync runs | Check that the client certificate is registered and not revoked in AWS IoT. See [Identity rotation](identity-rotation.md#certificates-revoked-before-the-upgrade) |

## Next steps

- [Status reasons](../reference/crds.md#status-reasons)
- [Upgrades](upgrades.md)
- [Reporting a problem](../security/reporting.md)
