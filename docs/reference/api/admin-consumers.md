---
title: Administrator consumer and grant routes
description: Consumer enrollment, API identities, issuer, agent grants and bootstrap capabilities.
---

# Administrator consumer and grant routes

All routes require the administrator bearer JWT.

## Consumer enrollment and certificates

All lifecycle routes require `Authorization` and `Idempotency-Key`. A CSR is a
public input and the issued certificate is public output; neither is included in
Hemlig audit events. Every successful result includes public SHA-256
fingerprints and the issued leaf PEM where a new leaf was created.

### `GET /v1/admin/consumers?environment=<env>&cursor=<opaque>`

Returns an eventually consistent, forward-only page of consumer profiles for the
required environment. Each profile has the consumer ID, environment, activation
state, SPIFFE subject URI, and creation time. The cursor is actor- and
environment-bound and expires after 15 minutes.

### `GET /v1/admin/consumers/{consumerId}`

Returns one authoritative consumer profile, its creator, the current issuing
root fingerprint when one exists, and the exact count of active API leaves.
The count is calculated from identity records rather than a mutable counter.
For an enrolled namespace agent, it also includes the attached AgentGrant and
its exact secret ID, UID, and permission records. Agent read delivery ACL rows
are derived automatically from this policy and are not a separate permission
layer in the consumer UI.

### `GET /v1/admin/consumers/{consumerId}/grants?cursor=<opaque>`

Returns every current secret ACL grant held by the consumer, in strongly
consistent pages of at most 100. Each entry contains its `secretId`, immutable
`secretUid`, `read` permission, current control revision, and secret state.
Historical revocation tombstones and archived secrets are omitted: this is the
effective access view used by the consumer management UI. The cursor is bound
to the administrator and consumer for 15 minutes.

### `DELETE /v1/admin/consumers/{consumerId}/grants/{secretId}`

Removes the consumer from that secret's source ACL and writes a new immutable
control revision. The normal delivery change feed receives a durable
revocation, so a materialized workload converges even if it was offline during
the action. This route requires `Authorization` and `Idempotency-Key`; it does
not accept an `If-Match` header because Hemlig reads the current revision and
uses a conditional update to reject a concurrent ACL change.

### `GET /v1/admin/consumers/{consumerId}/api-identities?cursor=<opaque>`

Returns a newest-first page of public API leaf records, including validity,
stored state, SHA-256 fingerprint, and public leaf PEM. Expiry is derived by a
caller from `notAfter`; Hemlig does not rewrite identity rows merely because
time passed. The endpoint intentionally excludes private-key material.

### `GET /v1/admin/issuer`

Returns the public deployment-wide issuer root and, after the first successful
publication, the current truststore object key, exact S3 version, and anchor
count. Before the first enrollment it returns `404`. It never returns the
KMS-wrapped issuer private key.

### `POST /v1/admin/issuer`

Deliberately provisions the deployment-wide issuing root instead of waiting
for the first enrollment to create it lazily. Use it to distribute the
truststore anchor before any consumer enrolls. It shares its creation logic
with that lazy path, so the two can never diverge, and creation is
race-safe: calling this repeatedly or concurrently is safe without an
additional lock. Returns the same body as `GET /v1/admin/issuer` and never
the KMS-wrapped issuer private key. `201 Created` only when this call created
the root; `200 OK` when one already existed.

Required headers: `Authorization`, `Idempotency-Key`

### `POST /v1/admin/consumers`

Creates a pending consumer profile and API identity in one DynamoDB transaction.
Hemlig creates its one issuing root on the first enrollment if needed, verifies
the signed RSA CSR (minimum 2048-bit public key), and signs a non-CA client
leaf. It then serializes truststore publication, writes a unique PEM bundle to
the versioned truststore bucket, updates the consumer custom domain to that exact
version, verifies the observed configuration, and atomically activates the
consumer/leaf records. A retry with the same idempotency key resumes a prepared
enrollment. Once it is active, the same key returns the recorded certificate
without another domain update. A bundle rejected with API Gateway warnings is
terminally failed and returns `409 enrollment_failed` on the same idempotency
key. Repair the issuer or truststore configuration before submitting a new
enrollment; a different CSR cannot repair a rejected root bundle.

```json
{
  "consumerId": "prod-east",
  "environment": "prod",
  "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----\\n..."
}
```

The CSR must be exactly one valid signed RSA certificate request no larger than
32 KiB and must contain a 2048-bit-or-larger public key. Hemlig sets the leaf's
`clientAuth` EKU and `spiffe://hemlig/consumer/prod-east` URI SAN; caller-supplied
CSR subjects/extensions do not control those identity fields. Success is `201`
with `status: ACTIVE`, `apiCertificatePem`, and both fingerprints. Save the
issued certificate with the local private key and send it for TLS mTLS.

### `POST /v1/admin/consumers/{consumerId}/api-identities`

Signs an overlapping active API leaf using a new CSR under the same deployment
root. Use it before retiring a leaf. The request contains only
`apiCertificateSigningRequestPem`; the response contains the new public
`apiCertificatePem`, its fingerprint, and the stable root fingerprint. Success
is `201`. For a consumer with an active agent grant, the new leaf is also
registered with AWS IoT before the response, so it can receive sync hints. A
replay with the same idempotency key registers it again.

### `DELETE /v1/admin/consumers/{consumerId}/api-identities/{apiFingerprint}`

Immediately changes the API identity to `REVOKED`. The consumer Lambda performs
a strongly consistent identity lookup on every request, so application-level
access stops without waiting for a truststore change. Revoke only after a new
active leaf has been distributed if continuity matters.

The leaf's AWS IoT certificate is revoked too, so it can no longer connect for
sync hints. A certificate that was never registered counts as revoked. If the
IoT call fails, repeat the request: a `DELETE` for an identity that is already
`REVOKED` re-applies the IoT revocation and returns `200`, with any
idempotency key.

## Agent grants and bootstrap capabilities

`POST /v1/admin/agent-grants` creates the one remote policy that a namespace
agent can ever use. It requires the ordinary administrator JWT, but does not
enroll a consumer yet. `consumerId` must be unused; `environment` must exist.

```json
{
  "consumerId": "prod-payments",
  "environment": "prod",
  "capabilities": ["read", "write"],
  "secretGrants": [
    {
      "secretId": "payments/production/stripe-api-key",
      "permissions": ["read", "write"]
    }
  ],
  "displayName": "Payments namespace"
}
```

`secretGrants` has one to twenty unique canonical IDs. Each record carries the
exact operations for that secret and may grant only an operation in
`capabilities`. It is an authorization boundary; Hemlig resolves and persists
the matching immutable secret UID beside each record. A grant is `PENDING`
until bootstrap completes, then becomes `ACTIVE`; it cannot silently fall back to a broad
consumer identity.

`POST /v1/admin/agent-grants/{grantId}/bootstrap-capabilities` returns the
only plaintext bootstrap token. It may be issued only for a pending grant and
is not stored by Hemlig in plaintext. Put that value in a Kubernetes Secret in
the target namespace; it is not a bearer token for administration or normal
secret delivery.

`PUT /v1/admin/agent-grants/{grantId}` replaces the grant's `capabilities` and
`secretGrants` (same shape as creation) and optionally `displayName`. The grant
ID, consumer ID and environment never change. On an `ACTIVE` grant, derived read
access is reconciled as part of the update.
