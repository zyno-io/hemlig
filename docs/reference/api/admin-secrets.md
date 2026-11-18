---
title: Administrator secret routes
description: Secret create, update, payload, archive, search, tree and revision routes.
---

# Administrator secret routes

All routes require the administrator bearer JWT. See the [overview](index.md) for headers, idempotency and errors.

## `GET /v1/admin/secrets/{secretId}`

All administrator routes that address one secret require the secret's
environment as the `environment` query parameter. Secret IDs are unique
within an environment, not across the deployment.

Returns the current immutable control revision—including metadata and ACL—but
never loads or returns the payload. The `controlVersionId` is returned as the
ETag and is the value required by a subsequent update. This route is intended
for declarative consumers such as the Kubernetes export controller and Pulumi
provider to converge against the current control-plane state.

Archived records are deliberately not addressable by this reusable name. Use
`GET /v1/admin/archived-secrets/{secretUid}?environment=...` to inspect an
archived control revision by its immutable UID.

## `GET /v1/admin/secrets/{secretId}/payload`

Decrypts and returns the current `ACTIVE` payload to an authenticated
administrator. It returns the same `secretId`, `controlVersionId`,
`payloadVersionId`, and payload shape as consumer delivery, with the current
control version as the `ETag`. It reads only the current immutable payload
version, performs the same envelope and revision-binding checks as consumer
delivery, and writes attempted, authorized, and terminal audit evidence without
including plaintext in that evidence.

The route does not support historical payload reads or `If-None-Match`. A
secret without an active payload returns `404`.

## `GET /v1/admin/secrets`

Browses organizational metadata without returning payloads, ACLs, encryption
material, or certificate material. `environment` is required. `pathPrefix` is
an optional secret-ID prefix; `tags` is an optional comma-separated list of
exact `key:value` terms, combined with AND. Results are sorted by folder then
secret ID and paginated through an opaque cursor bound to the administrator.
By default this endpoint reads only active catalog entries. Add
`archived=true` to query the separate archived catalog; `q`, `pathPrefix`, and
`tags` then apply only within that archived result set.

```http
GET /v1/admin/secrets?environment=prod&pathPrefix=payments&tags=owner:payments,system:billing HTTP/1.1
Authorization: Bearer <JWT>
```

Tag filtering is an organizational catalog query. It can inspect a bounded
page of the environment catalog before finding matches; callers must continue
until `nextCursor` is absent when they need exhaustive results.
Each result may include `payloadKeyCount`; it never includes plaintext, key
names, ACLs, or encryption material.

### Search with `q`

`q` is an optional case-insensitive substring match against `secretId` and
`metadata.description`, composed with `environment`, `pathPrefix`, and `tags`.
It must be 1–128 characters and not only whitespace.

```http
GET /v1/admin/secrets?environment=prod&pathPrefix=payments&q=stripe HTTP/1.1
Authorization: Bearer <JWT>
```

```http
GET /v1/admin/secrets?environment=prod&archived=true&q=stripe HTTP/1.1
Authorization: Bearer <JWT>
```

Adding `q` switches the response from cursor-paginated to bounded-complete:
the page never includes `nextCursor`, and includes `truncated` instead. This
is deliberate. The plain page above applies its filters after a bounded read,
so it can come back empty while `nextCursor` is still set — a caller has to
keep chasing cursors to learn whether there truly are no results. That is
tolerable for browsing but wrong for search, where "no matches" must be
trustworthy on the first response, and every admin request already writes
three audit objects into a seven-year Object Lock Compliance archive, so a
client-side, paginated substring walk is exactly the cost this route exists
to avoid. `q` instead paginates the same catalog index internally, up to the
same bounded scan the folder-tree route uses, and returns one
complete-or-truncated answer: `truncated: true` means the scan hit that bound
and some matches beyond it were not considered.

## `GET /v1/admin/secrets/tree`

Browses the organizational catalog as a folder tree instead of a flat page.
Every admin request writes three audit objects into a seven-year Object Lock
Compliance archive, so a console that browsed folder-by-folder would multiply
that archive write for every directory it opened; this route paginates the
underlying catalog-path index internally and returns one bounded page
instead. `environment` is required; `pathPrefix` is an optional canonical
path prefix, identical in format to `GET /v1/admin/secrets`.
Pass `archived=true` to build the same bounded tree from archived records only.

```http
GET /v1/admin/secrets/tree?environment=prod&pathPrefix=payments HTTP/1.1
Authorization: Bearer <JWT>
```

```json
{
  "environment": "prod",
  "pathPrefix": "payments",
  "folders": [
    {
      "segment": "stripe",
      "path": "payments/stripe",
      "secretCount": 12,
      "kind": "derived"
    }
  ],
  "secrets": [],
  "truncated": false,
  "generatedAt": "2026-08-22T19:37:12.441Z"
}
```

`folders` contains every immediate child segment below `pathPrefix` implied by
a slash-separated secret ID. `kind` is always `derived`, and `secretCount` is
computed recursively over each subtree. `secrets` lists only secrets whose ID
parent equals `pathPrefix` exactly; at the root (no `pathPrefix`), that means
IDs without a slash. This route uses the catalog-path index and scans an
internally bounded number of catalog records rather than exposing a cursor:
`truncated: true` means the page stopped early and the tree below it is
incomplete, not that more pages are available to fetch.

## `GET /v1/admin/secrets/{secretId}/revisions`

Returns up to 500 newest-first control revisions. Each item contains revision
IDs, timestamp, actor, optional `payloadKeyCount`, whether it is current, and
whether the historic immutable S3 object remains available. `objectAvailable`
is true only after the object was committed and before retention deletes it. It
never returns a payload, payload key names, an object URL, or audit evidence.
`truncated: true` means older history exists beyond this bounded management
view.

## `POST /v1/admin/secrets`

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
  "metadata": { "description": "Database credentials" },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

Returns `201 Created`, a control revision, and `ETag: <controlVersionId>`.

## `PUT /v1/admin/secrets/{secretId}`

Creates a new control revision but preserves the current payload pointer. Use
it to update metadata, ACL, or both. It does not decrypt the payload.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`

```http
PUT /v1/admin/secrets/database-credentials?environment=prod HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: a2176a0f-3a95-4167-8d58-b2cd9ebfbca4
Content-Type: application/json

{
  "metadata": {
    "description": "rotated by platform team"
  },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

Either field may be omitted to retain its current value. Success is `200 OK`
with the replacement control revision and new ETag. A stale ETag is `412`.

ACL rows for consumers that have an AgentGrant are server-managed. An ACL
replacement that omits such a row keeps it (it is appended after the submitted
rows, in its prior order); one that adds or changes it is rejected with `409`.
The 40-grant limit applies to the submitted `acl` only.

`GET /v1/admin/secrets/{secretId}` also returns a read-only
`agentManagedConsumerIds` array: the consumer IDs in `acl` that have an
AgentGrant. It is derived, never stored, and is not returned by create or `PUT`
responses.

## `POST /v1/admin/secrets/{secretId}/archive`

Archives the current secret identity without deleting immutable revision
objects. It requires `Authorization`, `Idempotency-Key`, and `If-Match`. The
archive control revision has `state: ARCHIVED` and an empty ACL; all prior
readers receive revocation tombstones. The transition atomically removes the
live name lookup and moves the head to the archived catalog, so active catalog
browsing and searches no longer return it and a new secret may immediately
reuse the same `secretId` in the environment. Archived details are addressed
by `secretUid`, never by the reusable name.

```http
POST /v1/admin/secrets/database-credentials/archive?environment=prod HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: 6f6253ba-b2ec-4aed-a216-8d2f4b4cbb8c
```

## `PUT /v1/admin/secrets/{secretId}/payload`

Encrypts a new payload with a fresh KMS data key and creates a control revision
that points to the fresh payload revision. This activates an empty secret.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`

```http
PUT /v1/admin/secrets/database-credentials/payload?environment=prod HTTP/1.1
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
