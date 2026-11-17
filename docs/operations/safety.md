---
title: "Safety: auth failures vs revoked grants"
description: When the controller deletes imported Secrets and when it never does.
pageType: explanation
---

# Safety: auth failures vs revoked grants

The controller deletes an imported Secret only when Hemlig clearly says the consumer may no longer read it. Its own credential, network or service problems never count as a revocation.

## When the controller deletes an import target

It deletes only when a request that **itself authenticated successfully** shows the grant no longer includes read access for that secret. There are three cases.

1. The sync data fetched in the current pass shows the grant's `read` capability, or the secret's `read` permission, removed.
2. A remote `403` or `404` on the secret read is followed by a **fresh** `GET /v1/agent/config` that succeeds and no longer grants `read` for that secret ID.
3. A cross-namespace reference is no longer allowed by the consumer's `allowCrossNamespaceReferences` setting. This is local policy, not a Hemlig decision.

The import then shows `Ready=False` with reason `AccessRevoked`.

## When it never deletes

In every row the existing target Secret is left exactly as last written. Reason meanings are in [Status reasons](../reference/crds.md#status-reasons).

| Situation | Reason | Sync checkpoint |
| --- | --- | --- |
| Remote `403` or `404`, and the confirmation call fails on a certificate problem | `AuthenticationFailed` | Not advanced |
| Remote `403` or `404`, and the confirmation call fails for another reason (network, `5xx`) | `RevocationUnconfirmed` | Not advanced |
| Remote `403` or `404`, but the confirmed grant **still** includes read | `RemoteAccessDenied` | Advances |
| The secret exists but has no value yet | `AwaitingValue` (no remote read) | Advances |
| The consumer itself is not ready | `ConsumerNotReady` on the import; the consumer shows its own reason | n/a |
| The controller is down or being upgraded | Unchanged | n/a |
| The `HemligSecretImport` is deleted | The target Secret is kept; `deletionPolicy` is ignored | n/a |

The controller makes one confirmation call per consumer per pass, however many imports fail.

::: warning Controllers before v0.3.0 <Badge type="tip" text="v0.3.0+" />
Controllers older than v0.3.0 deleted the owned Secret on **any** `403` or `404`, including an API Gateway mTLS `403` caused by the controller's own expired certificate. If you run one, treat an expiring identity as a risk to your imported Secrets and upgrade, or [renew it early](identity-rotation.md#if-the-certificate-already-expired).
:::

## Reading the signals

| Signal | Means |
| --- | --- |
| `403` with code `identity_not_active` | My certificate is not valid. Fix the identity ([Identity rotation](identity-rotation.md#if-the-certificate-already-expired)) |
| `403` with code `forbidden` | A grant decision |
| An mTLS handshake failure with no Hemlig error body | A certificate problem, not a grant decision |

## Operator guidance

- Alert on `Ready=False` for `HemligConsumer`, and on certificate expiry approaching (see the [runbook](identity-rotation.md#runbook-renew-cluster-identities)).
- To revoke access on purpose, remove the secret from the AgentGrant. A secret's ACL does not control an agent's access. The controller deletes the owned Secret after confirming through an authenticated call.
- Revoking a client certificate stops that identity. It does **not** by itself delete imported Secrets.

## Next steps

- [Status reasons](../reference/crds.md#status-reasons)
- [Give a cluster access](../guide/agent-grants.md#change-the-grant-scope)
