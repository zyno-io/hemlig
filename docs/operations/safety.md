---
title: "Safety: auth failures vs revoked grants"
description: When the controller deletes imported Secrets and when it never does.
---

# Safety: auth failures vs revoked grants

The controller removes an imported Kubernetes Secret only when Hemlig
**authoritatively** says the consumer may no longer read it. A problem with the
controller's own credentials, the network, or the service must never look like a
revocation.

::: info Release note
The strict rule below ships with the first release that includes the
authentication-failure guard (the same change set as
[identity self-rotation](identity-rotation.md)). Releases before it deleted the
owned import Secret on **any** `403` or `404` from the secret read, including an
API Gateway mTLS `403` caused by the controller's own expired certificate. If you
run an older controller, treat an expiring identity as a risk to your imported
Secrets and renew it early.
:::

## When the controller deletes an import target

Only when a request that **itself authenticated successfully** shows the grant no
longer includes read access for that secret:

1. The sync configuration fetched in the current pass already shows the capability
   or the secret's `read` permission removed (the sync entry reports `secret.revoked`).
2. After a remote `403`/`404` on the secret read, a **fresh** `GET /v1/agent/config`
   *succeeds* and no longer grants `read` for that secret ID.
3. A cross-namespace reference is no longer permitted by the consumer's
   `allowCrossNamespaceReferences` opt-out (local policy, not remote).

The status condition is `Ready=False` with reason `AccessRevoked`.

## When it never deletes

| Situation | Import condition | Sync cursor | Retry |
| --- | --- | --- | --- |
| Remote `403`/`404`, and the confirmation call fails with a certificate problem (`identity_not_active`, code-less mTLS `403`) | `Ready=False`, `AuthenticationFailed` | not advanced | backoff |
| Remote `403`/`404`, and the confirmation call fails for another reason (network, `5xx`) | `Ready=False`, `RevocationUnconfirmed` | not advanced | backoff |
| Remote `403`/`404`, but the confirmed grant **still** includes read | `Ready=False`, `RemoteAccessDenied` | advances | next change or resync |
| The secret exists but has no value yet (sync state `PENDING_VALUE`) | `Ready=False`, `AwaitingValue` (no remote read) | advances | next change |
| The consumer itself is not ready (expired certificate, bad provider, missing bootstrap token) | `ConsumerNotReady`; consumer reports e.g. `AuthenticationFailed` | n/a | backoff |
| The controller is down or being upgraded | unchanged | n/a | n/a |
| The `HemligSecretImport` resource is deleted | the target is not deleted; `deletionPolicy` is in the schema but is not read by the current controller | n/a | n/a |

In every row the existing target Secret is left exactly as last written. One
confirmation call is made per consumer per pass, however many imports fail.

## Reading the signals

- `403` with code `identity_not_active` means "my certificate is not valid": fix the
  identity (see [Identity rotation](identity-rotation.md#if-the-certificate-already-expired)).
- `403` with code `forbidden` is a grant decision.
- An API Gateway mTLS handshake failure has no Hemlig error body at all; it is a
  certificate problem, not a grant decision.

## Operator guidance

- Alert on `Ready=False` for `HemligConsumer`, and on certificate `notAfter`
  approaching (see [inventory](identity-rotation.md#ops-runbook-renew-cluster-identities)).
- To intentionally revoke access, remove the secret from the AgentGrant (or the ACL
  read permission) in Hemlig. The controller will remove the owned Secret after
  confirming through an authenticated call.
- Revoking a leaf (admin `DELETE api-identities`) stops that identity; it does
  **not** by itself delete imported Secrets.
