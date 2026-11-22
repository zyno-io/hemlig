---
title: Administrator consumer and grant routes
description: Consumer enrollment, client certificates, the issuing root, AgentGrants and bootstrap tokens on the administrator API.
pageType: reference
---

# Administrator consumer and grant routes

These routes enroll workloads and manage their credentials on the administrator API. All need an OIDC bearer token, except [`POST /v1/bootstrap/redeem`](#post-v1-bootstrap-redeem).

For a walkthrough see [Connect a workload without Kubernetes](../../guide/direct-consumers.md). How certificates, the issuing root and the truststore work is owned by [Identity and trust](../../guide/identity-and-trust.md).

**Audit.** Every administrator route writes `attempted` and `authorized` events, then `succeeded` or `failed`. A CSR and a certificate are public and never appear in audit events. See [Audit](audit.md).

**Idempotency.** Which routes need an `Idempotency-Key`, and what a reuse does, is in the [overview](index.md#idempotency).

## Consumers

### `GET /v1/admin/consumers`

Lists consumer profiles in one environment, forward-only and eventually consistent.

| Query parameter | Required | Description |
| --- | --- | --- |
| `environment` | Yes | The environment; it must exist |
| `cursor` | No | `nextCursor` from the previous page |

Each profile has `consumerId`, `environment`, `status`, `subjectUri` and `createdAt`.

### `GET /v1/admin/consumers/{consumerId}`

Returns one consumer's authoritative profile: its creator, the current issuing-root fingerprint when one exists, and the exact count of active client certificates. The count comes from identity records, not a counter.

For an [agent](../glossary.md#agent) it also returns the attached AgentGrant with each secret's ID, UID and permissions.

### `GET /v1/admin/consumers/{consumerId}/grants`

Lists the secrets whose ACL names this consumer: the effective access view. Pages hold at most 100 entries and are strongly consistent.

Each entry has `secretId`, `secretUid`, the `read` permission, the current control revision and the secret state. Archived secrets and old tombstones are omitted.

### `DELETE /v1/admin/consumers/{consumerId}/grants/{secretId}`

Removes the consumer from that secret's ACL and writes a new control revision. The consumer's change snapshot receives a `secret.revoked` entry, so a workload that was offline still converges.

- Needs `Idempotency-Key`. It does not take `If-Match`: Hemlig reads the current revision and rejects a concurrent ACL change itself.
- An agent cannot be removed this way. It returns `409 conflict`; edit the AgentGrant instead.
- A consumer that is not on the ACL returns `404 not_found`.

### `POST /v1/admin/consumers`

Enrolls a [direct consumer](../glossary.md#direct-consumer) from a certificate signing request (CSR) and returns its first client certificate.

Required headers: `Authorization`, `Idempotency-Key`.

```json
{
  "consumerId": "payments-prod",
  "environment": "prod",
  "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
}
```

| Requirement | Value |
| --- | --- |
| CSR | One signed RSA request, at least 2048 bits, at most 32 KiB |
| `consumerId` | Unused, matching the [ID pattern](data-types.md#identifiers) |
| `environment` | Must exist |

Hemlig sets the `clientAuth` usage and the URI SAN `spiffe://hemlig/consumer/payments-prod`. Subject and extensions in the CSR do not control those fields.

Success is `201`:

```json
{
  "consumerId": "payments-prod",
  "environment": "prod",
  "rootFingerprint": "9f2c...",
  "apiFingerprint": "41ab...",
  "apiCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "status": "ACTIVE"
}
```

The consumer becomes `ACTIVE` only after the truststore is published. If API Gateway rejects the truststore with warnings, the same key returns `409 enrollment_failed`. Repair the issuer or truststore first, then enroll again with a new key. See [Errors](errors.md).

## Client certificates

### `GET /v1/admin/consumers/{consumerId}/api-identities`

Lists a consumer's client certificates, newest first. Each entry has `apiFingerprint`, `status`, `kind`, `notBefore`, `notAfter` and the public `apiCertificatePem`. Expiry is derived from `notAfter`; Hemlig does not rewrite a row when time passes. Private keys are never returned.

### `POST /v1/admin/consumers/{consumerId}/api-identities`

Signs an additional, overlapping client certificate from a new CSR under the same issuing root. Issue the new one before revoking the old.

Required headers: `Authorization`, `Idempotency-Key`. Body: `apiCertificateSigningRequestPem`.

- Success is `201` with `consumerId`, `environment`, `rootFingerprint`, `apiFingerprint`, `apiCertificatePem` and `status`.
- For an agent consumer (one with an `ACTIVE` AgentGrant) the new certificate is also registered with AWS IoT before the response, so it can receive change hints. A replay with the same key registers it again.
- The limit of 3 active certificates applies to agent self-rotation, not to this route ([limits](../limits.md#identity)).

### `DELETE /v1/admin/consumers/{consumerId}/api-identities/{apiFingerprint}`

Marks the certificate `REVOKED`. The delivery API checks the record on every request, so application access stops at once without a truststore change.

Required headers: `Authorization`, `Idempotency-Key`. Returns `200` with the identity.

- The certificate's AWS IoT certificate is revoked too, so it can no longer connect for change hints. A certificate that was never registered counts as revoked.
- If the IoT call fails, repeat the request. A `DELETE` on an identity that is already `REVOKED` re-applies the IoT revocation and returns `200`.

::: warning Distribute the replacement first
Revoke only after the new certificate is in place if the workload must keep running.
:::

## Issuing root

### `GET /v1/admin/issuer`

Returns the public issuing root and, after the first publication, the truststore object key, its exact S3 version and the anchor count. Before any enrollment it returns `404 not_found`. It never returns the wrapped private key.

### `POST /v1/admin/issuer`

Creates the issuing root now instead of at the first enrollment. It returns the same body as `GET /v1/admin/issuer`.

Required headers: `Authorization`, `Idempotency-Key`.

- `201` when this call created the root, `200` when it already existed. Repeating or racing the call is safe.
- Run it before the first enrollment to avoid delay at the first enrollment. It also lets you distribute the trust anchor early.

## Agent grants and bootstrap capabilities

An [AgentGrant](../glossary.md#agentgrant) is the policy an agent can ever use. It does not enroll anyone by itself. The flow is create grant, issue bootstrap token, then the agent redeems it. See [Agent grants](../../guide/agent-grants.md) for the task.

### `POST /v1/admin/agent-grants`

Creates a `PENDING` grant for a new consumer ID. No `Idempotency-Key` is used.

```json
{
  "consumerId": "payments-prod",
  "environment": "prod",
  "capabilities": ["read", "write"],
  "secretGrants": [
    { "secretId": "payments/stripe/api-key", "permissions": ["read", "write"] }
  ],
  "displayName": "Payments namespace"
}
```

| Field | Required | Description |
| --- | --- | --- |
| `consumerId` | Yes | Must be unused |
| `environment` | Yes | Must exist |
| `capabilities` | Yes | `read` and/or `write`, no duplicates. May be empty only together with an empty `secretGrants` |
| `secretGrants` | Yes | 0 to 1,000 unique exact secret IDs on create (0 only with empty `capabilities`; `PUT` also accepts an empty list), each with `permissions` that are a subset of `capabilities` |
| `displayName` | No | Label |

Every `secretId` must already exist as an active secret in the environment. Hemlig resolves each one to its immutable [secret UID](../glossary.md#secret-uid) and stores it beside the record. Create the secrets first.

Returns `201` with `grantId`, the fields above, `status: PENDING`, `createdAt` and `createdBy`. The grant becomes `ACTIVE` when the agent redeems its token.

### `PUT /v1/admin/agent-grants/{grantId}`

Replaces the grant's `capabilities` and `secretGrants` (same shape as creation) and optionally `displayName`. The grant ID, consumer ID and environment never change. On an `ACTIVE` grant the derived read access is reconciled as part of the call. Returns `200` with the grant. No `Idempotency-Key` is used.

### `POST /v1/admin/agent-grants/{grantId}/bootstrap-capabilities`

Issues the only plaintext [bootstrap token](../glossary.md#bootstrap-token) for a `PENDING` grant. A grant that is not pending returns `409 conflict`. No `Idempotency-Key` is used.

```json
{
  "grantId": "grant-example",
  "token": "hmlb_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
  "expiresAt": "2030-01-01T00:30:00.000Z"
}
```

The token is one use and valid for 30 minutes ([limits](../limits.md#identity)). Hemlig stores only its SHA-256 hash, so this response is the only chance to copy it. It cannot call any other route.

### `POST /v1/bootstrap/redeem`

Redeems a bootstrap token and a CSR for the agent's first client certificate. No bearer token is used.

```http
POST /v1/bootstrap/redeem HTTP/1.1
Authorization: Bootstrap hmlb_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG
Content-Type: application/json

{ "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----\n..." }
```

- The CSR field is at most 16,384 characters.
- The consumer ID, environment and scope come only from the AgentGrant, never from the request.
- Success is `201`: the enrollment result (`consumerId`, `environment`, `rootFingerprint`, `apiFingerprint`, `apiCertificatePem`, `status`) plus `grant` with its `grantId`, `capabilities` and `secretGrants`.
- The certificate is registered with AWS IoT, and the grant becomes `ACTIVE`.
- A retry with the same CSR after a lost response returns the same result. A different CSR returns `403 forbidden`, except for an `ACTIVE` grant, where it returns `409 conflict`.
- An invalid, expired or consumed token returns `403 forbidden`. A malformed `Authorization` header returns `400 bad_request`.
