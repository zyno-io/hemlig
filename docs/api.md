# Hemlig API reference

This is the public reference for the **implemented v0.3 HTTP API**. Its
machine-readable contract is [openapi/consumer-secrets.yaml](../openapi/consumer-secrets.yaml).
It includes organizational browsing and the safe CSR enrollment/certificate
routes. Audit querying and issuer-root rotation are intentionally excluded.

## Base URLs

| API           | URL                     | Caller                              |
| ------------- | ----------------------- | ----------------------------------- |
| Administrator | `https://<adminFqdn>`   | Administrator with a valid JWT      |
| Delivery      | `https://<apiFqdn>`     | Enrolled workload identity over mTLS |

The CDK stack receives both FQDNs. `apiFqdn` names a generic delivery endpoint,
even though Kubernetes workloads are its first consumer. It disables each generated API Gateway
`execute-api` endpoint, so clients must use these custom domains.

## Authentication

### Administrator API

Use a bearer JWT from the external OIDC/OAuth provider configured in CDK.
API Gateway validates its issuer and audience; Hemlig verifies those claims
again and records the configured immutable subject claim (`sub` by default) as
the actor. The provider must issue a token with the configured `aud`, or with
the configured `client_id` only when `aud` is absent.

When the deployment configures a browser console origin, it also configures an
exact administrator OAuth scope. API Gateway and Hemlig both require that scope
in `scope` or `scp`; this is opt-in only to preserve existing non-browser
automation until its identity-provider configuration is ready.

```http
Authorization: Bearer <JWT>
```

Every administrator mutation also needs an `Idempotency-Key` of 8–128
characters. Use one durable random value per intended operation. Reusing a key
returns `409 conflict`; retain the initial response instead of treating a retry
as a new operation.

### Delivery API

The caller presents an API leaf certificate during TLS negotiation. After a
truststore has been published, API Gateway validates its chain; Hemlig then
hashes the DER bytes and checks for an `ACTIVE` enrolled identity record in
DynamoDB. The request never accepts a client-supplied consumer ID.

An administrator enrolls a consumer through `POST /v1/admin/consumers`. The
request supplies a signed RSA CSR. Hemlig has one deployment-wide issuing root:
it verifies the CSR, signs the submitted public key as a `clientAuth` leaf with
the URI SAN `spiffe://hemlig/consumer/<consumerId>`, writes the one-root
truststore at a unique S3 version, and waits for an `AVAILABLE` no-warning
domain configuration before marking the leaf `ACTIVE`. The consumer operator
retains its private key; Hemlig never accepts, stores, or returns private-key
material. If API Gateway rejects the bundle with warnings, Hemlig rolls back to
the last known bundle when one exists, marks the operation failed, and releases
the publication lease.

## Common behavior

### Headers

| Header            | Routes                    | Meaning                                |
| ----------------- | ------------------------- | -------------------------------------- |
| `Authorization`   | Admin routes              | Administrator JWT                      |
| `Idempotency-Key` | Admin mutations           | 8–128-character operation key          |
| `If-Match`        | `PUT` secret routes       | Required current control-revision ETag |
| `If-None-Match`   | Consumer secret read      | Optional current control-revision ETag |
| `ETag`            | Secret response and `304` | Current control revision ID            |

Responses include `Cache-Control: no-store`. Clients must not log a secret
payload or persist it in an HTTP cache.

### Error envelope

```json
{
  "error": {
    "code": "precondition_failed",
    "message": "If-Match does not name the current control revision.",
    "correlationId": "01J..."
  }
}
```

| Status | Code                  | Meaning                                                 |
| ------ | --------------------- | ------------------------------------------------------- |
| 400    | `bad_request`         | Invalid JSON, route, header, ID, ACL, or payload        |
| 403    | `forbidden`           | Invalid JWT, certificate, identity, or grant            |
| 404    | `not_found`           | Missing secret or active payload                        |
| 409    | `conflict`            | Used idempotency key or unavailable revision lease      |
| 409    | `enrollment_failed`   | Terminal truststore publication failure; do not retry   |
| 412    | `precondition_failed` | `If-Match` is no longer current                         |
| 500    | `internal_error`      | Unexpected failure; implementation details are withheld |
| 503    | `service_unavailable` | Storage or KMS consistency/availability failure         |

## Data types

### Identifiers

Secret IDs and consumer IDs must match:

```text
^[a-z][a-z0-9-]{2,63}$
```

`POST /v1/admin/secrets` generates an ID beginning with `sec-` when `secretId`
is omitted.

### Metadata and ACL

```json
{
  "metadata": {
    "name": "database-credentials",
    "description": "Optional human-readable description"
  },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

`metadata.name` is required (maximum 128 characters). `description` is optional
and at most 1,024 characters. `path` is an optional canonical, lowercase,
slash-delimited organizational location (up to 256 characters), for example
`payments/stripe/production`. `tags` is an optional map of up to 20 lowercase
keys to short exact-match values, for example `owner: payments` and
`system: billing`. Paths and tags are returned only to administrators; they
never select a delivery target, grant access, or appear in the consumer API.

An ACL has zero to ten unique consumers and only supports the `read` permission.
Every grant must identify an already-enrolled, active consumer in the same
environment as the secret. Removing a consumer keeps a `REVOKED` tombstone in
its snapshot so the operator removes the corresponding Kubernetes Secret.

### Payload

A payload is an object of Secret data entries. The serialized JSON body must
not exceed 768,000 bytes (750 KiB). Keys allow letters, digits, `.`, `_`, and
`-`; values are explicit UTF-8 or canonical base64.

```json
{
  "username": { "encoding": "utf8", "value": "service-account" },
  "password": {
    "encoding": "base64",
    "value": "Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ=="
  }
}
```

Base64 must use canonical RFC 4648 padding. Use `utf8` for ordinary text.

### Control revision

Admin routes return an immutable control revision. Its `controlVersionId` is
the optimistic-concurrency ETag for subsequent updates.

```json
{
  "schemaVersion": 1,
  "secretId": "database-credentials",
  "controlVersionId": "ctl-92b9be7b-4e03-4a8c-87be-6a2d0af66147",
  "payloadVersionId": "pay-8436f80a-00ee-48d2-8a18-3a1194279ddc",
  "payloadKeyCount": 2,
  "environment": "prod",
  "state": "ACTIVE",
  "createdAt": "2026-08-22T19:37:12.441Z",
  "createdBy": { "type": "human", "id": "external-oidc-subject" },
  "metadata": { "name": "database-credentials" },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

New secrets are `PENDING_VALUE` until a payload update succeeds, after which
they become `ACTIVE`. `payloadKeyCount` is written with a payload revision and
copied to later metadata/ACL-only revisions. It lets a caller warn about a
destructive replacement without retaining or exposing payload key names.

## Administrator routes

### `GET /v1/admin/secrets/{secretId}`

Returns the current immutable control revision—including metadata and ACL—but
never loads or returns the payload. The `controlVersionId` is returned as the
ETag and is the value required by a subsequent update. This route is intended
for declarative consumers such as the Kubernetes export controller and Pulumi
provider to converge against the current control-plane state.

### `GET /v1/admin/secrets`

Browses organizational metadata without returning payloads, ACLs, encryption
material, or certificate material. `environment` is required. `pathPrefix` is
an optional canonical path prefix; `tags` is an optional comma-separated list
of exact `key:value` terms, combined with AND. Results are sorted by path then
secret ID and paginated through an opaque cursor bound to the administrator.

```http
GET /v1/admin/secrets?environment=prod&pathPrefix=payments&tags=owner:payments,system:billing HTTP/1.1
Authorization: Bearer <JWT>
```

Tag filtering is an organizational catalog query. It can inspect a bounded
page of the environment catalog before finding matches; callers must continue
until `nextCursor` is absent when they need exhaustive results.
Each result may include `payloadKeyCount`; it never includes plaintext, key
names, ACLs, or encryption material.

### `GET /v1/admin/secrets/{secretId}/revisions`

Returns up to 500 newest-first control revisions. Each item contains revision
IDs, timestamp, actor, optional `payloadKeyCount`, whether it is current, and
whether the historic immutable S3 object remains available. `objectAvailable`
is true only after the object was committed and before retention deletes it. It
never returns a payload, payload key names, an object URL, or audit evidence.
`truncated: true` means older history exists beyond this bounded management
view.

### `POST /v1/admin/secrets`

Creates an empty secret, initial control revision, and ACL. It never accepts a
payload, so the response state is `PENDING_VALUE`.

Required headers: `Authorization`, `Idempotency-Key`

```http
POST /v1/admin/secrets HTTP/1.1
Content-Type: application/json
Idempotency-Key: 4b395a16-d19a-4ced-b5c8-d93bbd0f4dc9

{
  "secretId": "database-credentials",
  "environment": "prod",
  "metadata": { "name": "database-credentials" },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

Returns `201 Created`, a control revision, and `ETag: <controlVersionId>`.

### `PUT /v1/admin/secrets/{secretId}`

Creates a new control revision but preserves the current payload pointer. Use
it to update metadata, ACL, or both. It does not decrypt the payload.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`

```http
PUT /v1/admin/secrets/database-credentials HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: a2176a0f-3a95-4167-8d58-b2cd9ebfbca4
Content-Type: application/json

{
  "metadata": {
    "name": "database-credentials",
    "description": "rotated by platform team"
  },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

Either field may be omitted to retain its current value. Success is `200 OK`
with the replacement control revision and new ETag. A stale ETag is `412`.

### `PUT /v1/admin/secrets/{secretId}/payload`

Encrypts a new payload with a fresh KMS data key and creates a control revision
that points to the fresh payload revision. This activates an empty secret.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`

```http
PUT /v1/admin/secrets/database-credentials/payload HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: 3e24149a-6d92-4c12-8b3f-a10d05072255
Content-Type: application/json

{
  "payload": {
    "username": { "encoding": "utf8", "value": "service-account" },
    "password": { "encoding": "base64", "value": "c2VjcmV0" }
  }
}
```

Returns `200 OK`, a new `controlVersionId`, a new `payloadVersionId`,
`state: ACTIVE`, and the new ETag. Hemlig never echoes the plaintext payload.

### Consumer enrollment and certificates

All lifecycle routes require `Authorization` and `Idempotency-Key`. A CSR is a
public input and the issued certificate is public output; neither is included in
Hemlig audit events. Every successful result includes public SHA-256
fingerprints and the issued leaf PEM where a new leaf was created.

#### `GET /v1/admin/consumers?environment=<env>&cursor=<opaque>`

Returns an eventually consistent, forward-only page of consumer profiles for the
required environment. Each profile has the consumer ID, environment, activation
state, SPIFFE subject URI, and creation time. The cursor is actor- and
environment-bound and expires after 15 minutes.

#### `GET /v1/admin/consumers/{consumerId}`

Returns one authoritative consumer profile, its creator, the current issuing
root fingerprint when one exists, and the exact count of active API leaves.
The count is calculated from identity records rather than a mutable counter.

#### `GET /v1/admin/consumers/{consumerId}/api-identities?cursor=<opaque>`

Returns a newest-first page of public API leaf records, including validity,
stored state, SHA-256 fingerprint, and public leaf PEM. Expiry is derived by a
caller from `notAfter`; Hemlig does not rewrite identity rows merely because
time passed. The endpoint intentionally excludes private-key material.

#### `GET /v1/admin/issuer`

Returns the public deployment-wide issuer root and, after the first successful
publication, the current truststore object key, exact S3 version, and anchor
count. Before the first enrollment it returns `404`. It never returns the
KMS-wrapped issuer private key.

#### `POST /v1/admin/consumers`

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

#### `POST /v1/admin/consumers/{consumerId}/api-identities`

Signs an overlapping active API leaf using a new CSR under the same deployment
root. Use it before retiring a leaf. The request contains only
`apiCertificateSigningRequestPem`; the response contains the new public
`apiCertificatePem`, its fingerprint, and the stable root fingerprint. Success
is `201`.

#### `DELETE /v1/admin/consumers/{consumerId}/api-identities/{apiFingerprint}`

Immediately changes the API identity to `REVOKED`. The consumer Lambda performs
a strongly consistent identity lookup on every request, so application-level
access stops without waiting for a truststore change. Revoke only after a new
active leaf has been distributed if continuity matters.

## Consumer routes

### `GET /v1/secrets/{secretId}`

Reads one secret for the authenticated consumer. The consumer needs a current
`read` grant, its enrolled environment and grant environment must match the
secret, and the secret must be `ACTIVE`.

Optional header: `If-None-Match`

```http
GET /v1/secrets/database-credentials HTTP/1.1
If-None-Match: "ctl-01Jprevious"
```

`200 OK` includes only delivery material and immutable revision IDs:

```json
{
  "secretId": "database-credentials",
  "controlVersionId": "ctl-01J...",
  "payloadVersionId": "pay-01J...",
  "payload": {
    "username": { "encoding": "utf8", "value": "service-account" },
    "password": { "encoding": "base64", "value": "c2VjcmV0" }
  }
}
```

It includes `ETag: <controlVersionId>`. If `If-None-Match` equals the current
control version, Hemlig returns `304 Not Modified` with that ETag and does not
read/decrypt the payload. It never returns metadata, ACLs, encryption fields,
other consumer identities, or an S3 URL.

### `GET /v1/changes`

Returns a page of the caller's current access snapshot. Start a reconciliation
with no cursor and pass each opaque `nextCursor` unchanged until it is absent.
The cursor is bound to the caller's consumer identity and expires in 15 minutes.

```json
{
  "changes": [
    {
      "secretId": "database-credentials",
      "controlVersionId": "ctl-01J...",
      "payloadVersionId": "pay-01J...",
      "state": "ACTIVE",
      "changeKind": "secret.changed"
    },
    {
      "secretId": "retired-secret",
      "controlVersionId": "ctl-01K...",
      "state": "REVOKED",
      "changeKind": "secret.revoked"
    }
  ],
  "nextCursor": "<opaque-cursor-or-omitted>",
  "generatedAt": "2026-08-22T19:37:12.441Z"
}
```

For `secret.changed`, fetch the secret when the recorded version differs from
the operator's local annotation. For `secret.revoked`, delete the
operator-managed Kubernetes Secret. This endpoint is not a durable event log.

## Audit behavior

After a caller has been resolved to an application actor, Hemlig emits attempted,
authorized, and terminal-success or terminal-failed audit events. It writes
terminal success before responding with plaintext. TLS or JWT failures rejected
before an actor exists are outside the application event stream and must be
investigated through the stack's sanitized API Gateway access logs and
control-plane logs. Audit records never
include secret payloads, tokens, request bodies, or certificate material. See
[architecture](architecture.md#audit-evidence) for archive keys and retention
semantics.

## Deliberately excluded routes

There is no public issuer-root-rotation endpoint, audit-query endpoint, or
consumer-side write API. These need additional lifecycle/audit-boundary design;
clients must not infer them from the DynamoDB record shape.
