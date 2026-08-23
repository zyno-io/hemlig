# Clavis API reference

This is the public reference for the **implemented v0.2 HTTP API**. Its
machine-readable contract is [openapi/cluster-secrets.yaml](../openapi/cluster-secrets.yaml).
It includes organizational browsing and the safe CSR enrollment/certificate
routes. Audit querying and issuer-root rotation are intentionally excluded.

## Base URLs

| API           | URL                     | Caller                              |
| ------------- | ----------------------- | ----------------------------------- |
| Administrator | `https://<adminFqdn>`   | Administrator with a valid JWT      |
| Cluster       | `https://<clusterFqdn>` | Enrolled cluster operator over mTLS |

The CDK stack receives both FQDNs. It disables each generated API Gateway
`execute-api` endpoint, so clients must use these custom domains.

## Authentication

### Administrator API

Use a bearer JWT from the external OIDC/OAuth provider configured in CDK.
API Gateway validates its issuer and audience; Clavis verifies those claims
again and records the configured immutable subject claim (`sub` by default) as
the actor. The provider must issue a token with the configured `aud`, or with
the configured `client_id` only when `aud` is absent.

```http
Authorization: Bearer <JWT>
```

Every administrator mutation also needs an `Idempotency-Key` of 8–128
characters. Use one durable random value per intended operation. Reusing a key
returns `409 conflict`; retain the initial response instead of treating a retry
as a new operation.

### Cluster API

The caller presents an API leaf certificate during TLS negotiation. After a
truststore has been published, API Gateway validates its chain; Clavis then
hashes the DER bytes and checks for an `ACTIVE` identity record in DynamoDB.
The request never accepts a client-supplied cluster ID.

An administrator enrolls a cluster through `POST /v1/admin/clusters`. The
request supplies a signed RSA CSR. Clavis has one deployment-wide issuing root:
it verifies the CSR, signs the submitted public key as a `clientAuth` leaf with
the URI SAN `spiffe://clavis/cluster/<clusterId>`, writes the one-root
truststore at a unique S3 version, and waits for an `AVAILABLE` no-warning
domain configuration before marking the leaf `ACTIVE`. The cluster operator
retains its private key; Clavis never accepts, stores, or returns private-key
material. If API Gateway rejects the bundle with warnings, Clavis rolls back to
the last known bundle when one exists, marks the operation failed, and releases
the publication lease.

## Common behavior

### Headers

| Header            | Routes                    | Meaning                                |
| ----------------- | ------------------------- | -------------------------------------- |
| `Authorization`   | Admin routes              | Administrator JWT                      |
| `Idempotency-Key` | Admin mutations           | 8–128-character operation key          |
| `If-Match`        | `PUT` secret routes       | Required current control-revision ETag |
| `If-None-Match`   | Cluster secret read       | Optional current control-revision ETag |
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
| 412    | `precondition_failed` | `If-Match` is no longer current                         |
| 500    | `internal_error`      | Unexpected failure; implementation details are withheld |
| 503    | `service_unavailable` | Storage or KMS consistency/availability failure         |

## Data types

### Identifiers

Secret IDs and cluster IDs must match:

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
  "acl": [{ "clusterId": "prod-east", "permissions": ["read"] }]
}
```

`metadata.name` is required (maximum 128 characters). `description` is optional
and at most 1,024 characters. `path` is an optional canonical, lowercase,
slash-delimited organizational location (up to 256 characters), for example
`payments/stripe/production`. `tags` is an optional map of up to 20 lowercase
keys to short exact-match values, for example `owner: payments` and
`system: billing`. Paths and tags are returned only to administrators; they
never select a delivery target, grant access, or appear in the cluster API.

An ACL has zero to ten unique clusters and only supports the `read` permission.
Every grant must identify an already-enrolled, active cluster in the same
environment as the secret. Removing a cluster keeps a `REVOKED` tombstone in
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
  "controlVersionId": "ctl-01J...",
  "payloadVersionId": "pay-01J...",
  "environment": "prod",
  "state": "ACTIVE",
  "createdAt": "2026-08-22T19:37:12.441Z",
  "createdBy": { "type": "human", "id": "external-oidc-subject" },
  "metadata": { "name": "database-credentials" },
  "acl": [{ "clusterId": "prod-east", "permissions": ["read"] }]
}
```

New secrets are `PENDING_VALUE` until a payload update succeeds, after which
they become `ACTIVE`.

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
  "acl": [{ "clusterId": "prod-east", "permissions": ["read"] }]
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
  "acl": [{ "clusterId": "prod-east", "permissions": ["read"] }]
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
`state: ACTIVE`, and the new ETag. Clavis never echoes the plaintext payload.

### Cluster enrollment and certificates

All lifecycle routes require `Authorization` and `Idempotency-Key`. A CSR is a
public input and the issued certificate is public output; neither is included in
Clavis audit events. Every successful result includes public SHA-256
fingerprints and the issued leaf PEM where a new leaf was created.

#### `POST /v1/admin/clusters`

Creates a pending cluster profile and API identity in one DynamoDB transaction.
Clavis creates its one issuing root on the first enrollment if needed, verifies
the signed RSA CSR (minimum 2048-bit public key), and signs a non-CA client
leaf. It then serializes truststore publication, writes a unique PEM bundle to
the versioned truststore bucket, updates the cluster custom domain to that exact
version, verifies the observed configuration, and atomically activates the
cluster/leaf records. A retry with the same idempotency key resumes a prepared
enrollment. Once it is active, the same key returns the recorded certificate
without another domain update. A bundle rejected with API Gateway warnings is
terminally failed and must be resubmitted with a new CSR and idempotency key.

```json
{
  "clusterId": "prod-east",
  "environment": "prod",
  "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----\\n..."
}
```

The CSR must be exactly one valid signed RSA certificate request no larger than
32 KiB and must contain a 2048-bit-or-larger public key. Clavis sets the leaf's
`clientAuth` EKU and `spiffe://clavis/cluster/prod-east` URI SAN; caller-supplied
CSR subjects/extensions do not control those identity fields. Success is `201`
with `status: ACTIVE`, `apiCertificatePem`, and both fingerprints. Save the
issued certificate with the local private key and send it for TLS mTLS.

#### `POST /v1/admin/clusters/{clusterId}/api-identities`

Signs an overlapping active API leaf using a new CSR under the same deployment
root. Use it before retiring a leaf. The request contains only
`apiCertificateSigningRequestPem`; the response contains the new public
`apiCertificatePem`, its fingerprint, and the stable root fingerprint. Success
is `201`.

#### `DELETE /v1/admin/clusters/{clusterId}/api-identities/{apiFingerprint}`

Immediately changes the API identity to `REVOKED`. The cluster Lambda performs
a strongly consistent identity lookup on every request, so application-level
access stops without waiting for a truststore change. Revoke only after a new
active leaf has been distributed if continuity matters.

## Cluster routes

### `GET /v1/secrets/{secretId}`

Reads one secret for the authenticated cluster. The cluster needs a current
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
control version, Clavis returns `304 Not Modified` with that ETag and does not
read/decrypt the payload. It never returns metadata, ACLs, encryption fields,
other cluster identities, or an S3 URL.

### `GET /v1/changes`

Returns a page of the caller's current access snapshot. Start a reconciliation
with no cursor and pass each opaque `nextCursor` unchanged until it is absent.
The cursor is bound to the caller's cluster and expires in 15 minutes.

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

After a caller has been resolved to an application actor, Clavis emits attempted,
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
cluster-side write API. These need additional lifecycle/audit-boundary design;
clients must not infer them from the DynamoDB record shape.
