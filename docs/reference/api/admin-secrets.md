---
title: Administrator secret routes
description: Environments, secret catalog, create, update, payload, archive and revision routes on the administrator API.
pageType: reference
---

# Administrator secret routes

These routes manage environments and secrets on the administrator API. They are all `https://admin.example.com` routes that need an OIDC bearer token.

Shared headers, [idempotency](index.md#idempotency) and [pagination](index.md#pagination) are on the [overview](index.md). Shapes are in [Data types](data-types.md).

**Audit.** Every route here writes `attempted` and `authorized` events before it runs, then `succeeded` or `failed`. A payload read records `read` as its permission and never includes the value. See [Audit](audit.md).

**Secret addressing.** Routes that address one secret need the `environment` query parameter (at most 128 characters). A secret ID is unique within an environment, not across the deployment.

## Environments

### `GET /v1/admin/environments`

Lists every defined [environment](../glossary.md#environment). Returns `200` with `environments` (each `name`, `createdAt`, `createdBy`) and `generatedAt`.

### `POST /v1/admin/environments`

Defines a new environment. No `Idempotency-Key` is used.

```json
{ "name": "prod" }
```

Returns `201` with the environment. A name that already exists, or a full registry, returns `409 conflict`. The registry holds at most 100 ([limits](../limits.md#secrets-and-grants)).

## Browse and read

### `GET /v1/admin/secrets`

Browses the secret catalog. It never returns payloads, ACLs or encryption material.

| Query parameter | Required | Description |
| --- | --- | --- |
| `environment` | Yes | The environment to browse; it must exist |
| `pathPrefix` | No | Canonical secret-ID prefix |
| `tags` | No | Comma-separated exact `key:value` terms, combined with AND |
| `q` | No | Case-insensitive substring of `secretId` or `description`, 1 to 128 characters |
| `archived` | No | `true` browses archived secrets only; default `false` |
| `cursor` | No | `nextCursor` from the previous page |

Results sort by folder then secret ID. Each entry has `secretUid`, `secretId`, `environment`, `controlVersionId`, `payloadVersionId`, `payloadKeyCount`, `state`, `metadata` and `updatedAt`.

```http
GET /v1/admin/secrets?environment=prod&pathPrefix=payments&tags=owner:payments HTTP/1.1
Authorization: Bearer eyJ...
```

A plain page applies its filters after a bounded read, so it can be empty while `nextCursor` is present. Keep following cursors.

Adding `q` changes the response to bounded-complete. The page has no `nextCursor` and sets `truncated` instead. `truncated: true` means the scan hit its bound, so matches beyond it were not considered.

### `GET /v1/admin/secrets/tree`

Returns one bounded folder tree page instead of one request per folder.

| Query parameter | Required | Description |
| --- | --- | --- |
| `environment` | Yes | The environment to browse |
| `pathPrefix` | No | Canonical secret-ID prefix |
| `archived` | No | `true` builds the tree from archived records only |

```json
{
  "environment": "prod",
  "pathPrefix": "payments",
  "folders": [
    { "segment": "stripe", "path": "payments/stripe", "secretCount": 12, "kind": "derived" }
  ],
  "secrets": [],
  "truncated": false,
  "generatedAt": "2030-01-01T00:00:00.000Z"
}
```

`folders` lists each immediate child folder with a recursive `secretCount`. `secrets` lists only secrets whose parent equals `pathPrefix` exactly. `truncated: true` means the tree is incomplete; there is no cursor.

### `GET /v1/admin/secrets/{secretId}`

Returns the current [control revision](data-types.md#control-revision) with metadata and ACL, and never loads the payload. The `ETag` header is the value the next update needs.

Archived secrets are not addressable by their reusable name. Use [`GET /v1/admin/archived-secrets/{secretUid}`](#get-v1-admin-archived-secrets-secretuid).

### `GET /v1/admin/secrets/{secretId}/payload`

Decrypts and returns the current payload of an `ACTIVE` secret.

```json
{
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-01J...",
  "payloadVersionId": "pay-01J...",
  "payload": { "api-key": { "encoding": "utf8", "value": "sk_test_example" } }
}
```

- The `ETag` header is the control revision.
- Only the current payload is readable. `If-None-Match` is not supported.
- A secret with no active payload returns `404 not_found`.
- The read is audited without the value.

### `GET /v1/admin/secrets/{secretId}/revisions`

Lists up to 500 control revisions, newest first.

| Field | Meaning |
| --- | --- |
| `controlVersionId`, `payloadVersionId`, `payloadKeyCount` | Revision identifiers and entry count |
| `createdAt`, `createdBy` | When and by whom |
| `isCurrent` | This is the current revision |
| `objectAvailable` | The immutable object was committed and retention has not deleted it |

`truncated: true` means older history exists beyond the 500 returned. The route never returns a payload, entry names, an object URL or audit evidence.

### `GET /v1/admin/archived-secrets/{secretUid}`

Returns the archived control revision for a [secret UID](../glossary.md#secret-uid), for example one saved from an archive receipt. It needs `environment` and returns an `ETag`. There is no archived payload read.

## Create and change

### `POST /v1/admin/secrets`

Creates an empty secret with its initial ACL. It never accepts a payload, so the new state is `PENDING_VALUE`.

Required headers: `Authorization`, `Idempotency-Key`.

```http
POST /v1/admin/secrets HTTP/1.1
Authorization: Bearer eyJ...
Idempotency-Key: 4b395a16-d19a-4ced-b5c8-d93bbd0f4dc9
Content-Type: application/json

{
  "secretId": "payments/stripe/api-key",
  "environment": "prod",
  "metadata": { "description": "Stripe API key" },
  "acl": [{ "consumerId": "payments-prod", "permissions": ["read"] }]
}
```

Returns `201` with the control revision and its `ETag`.

### `PUT /v1/admin/secrets/{secretId}`

Replaces metadata, the ACL, or both without touching the payload. Omit a field to keep it.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`. Required query: `environment`.

```http
PUT /v1/admin/secrets/payments/stripe/api-key?environment=prod HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: a2176a0f-3a95-4167-8d58-b2cd9ebfbca4
Content-Type: application/json

{ "metadata": { "description": "rotated by platform team" } }
```

- A supplied `metadata` replaces all metadata, including tags. A supplied `acl` replaces the whole ACL.
- Success is `200` with the new revision and `ETag`. A stale `If-Match` is `412 precondition_failed`.
- Changing an agent's ACL row is `409 conflict`; see [ACL](data-types.md#acl).

### `PUT /v1/admin/secrets/{secretId}/payload`

Encrypts a new payload with a fresh data key and creates a control revision that points to it. This activates a `PENDING_VALUE` secret. It replaces the entire payload.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`. Required query: `environment`.

```http
PUT /v1/admin/secrets/payments/stripe/api-key/payload?environment=prod HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: 3e24149a-6d92-4c12-8b3f-a10d05072255
Content-Type: application/json

{ "payload": { "api-key": { "encoding": "utf8", "value": "sk_test_example" } } }
```

Returns `200` with a new `controlVersionId`, a new `payloadVersionId`, `state: ACTIVE` and the new `ETag`. The plaintext is never echoed.

### `POST /v1/admin/secrets/{secretId}/archive`

Archives the secret. It never deletes revision objects.

Required headers: `Authorization`, `Idempotency-Key`, `If-Match`. Required query: `environment`.

```http
POST /v1/admin/secrets/payments/stripe/api-key/archive?environment=prod HTTP/1.1
If-Match: "ctl-01Jprevious"
Idempotency-Key: 6f6253ba-b2ec-4aed-a216-8d2f4b4cbb8c
```

The archive revision has `state: ARCHIVED` and an empty ACL. Prior readers receive revocation [tombstones](../glossary.md#tombstone). The secret leaves the active catalog and its ID is free for reuse at once. Keep `secretUid` from the response to look the secret up later.
