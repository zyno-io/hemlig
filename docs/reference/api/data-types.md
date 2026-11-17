---
title: API data types
description: Identifiers, environments, metadata, ACLs, payloads and control revisions.
---

# Data types

## Identifiers

Consumer IDs must match:

```text
^[a-z][a-z0-9-]{2,63}$
```

Secret IDs use the same segment grammar, but may contain `/` between
segments (maximum 256 characters overall):

```text
^[a-z][a-z0-9-]{2,63}(/[a-z][a-z0-9-]{2,63})*$
```

This rejects leading and trailing slashes and empty segments (`//`).
`POST /v1/admin/secrets` requires a caller-supplied `secretId`.

## Environments

Administrators define logical secret/consumer environments at runtime with
`POST /v1/admin/environments`, then discover them with
`GET /v1/admin/environments`. A name must match
`^[a-z][a-z0-9-]{0,63}$`. New secret creation, consumer enrollment, and
environment-scoped catalog browsing require an existing definition; a fresh
deployment intentionally starts with none. The registry supports up to 100
environments.

## Folders

A folder is the parent prefix of a slash-separated secret ID. For example,
`payments/stripe/api-key` appears under `payments/stripe`. Folders are not
stored independently: an empty folder disappears until a secret exists below
it. The console's **New folder** flow only prefixes the ID of the next secret.

## Metadata and ACL

```json
{
  "metadata": {
    "description": "Optional human-readable description"
  },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

`description` is optional and at most 1,024 characters. `tags` is an optional
map of up to 20 lowercase keys to short exact-match values, for example
`owner: payments` and `system: billing`. Tags are returned only to
administrators; they never select a delivery target, grant access, or appear
in the consumer API. Folders and agent authorization are both derived from the
slash-separated secret ID; metadata never adds another path namespace.

An ACL has zero to forty unique consumers and only supports the `read` permission.
Every grant must identify an already-enrolled, active consumer in the same
environment as the secret. Removing a consumer keeps a `REVOKED` tombstone in
its snapshot so the operator removes the corresponding Kubernetes Secret.
The environment must first be defined by an administrator. Hemlig stores that
definition in the control table and rejects secret creation and consumer
enrollment for an unknown environment.

## Payload

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

## Control revision

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
  "metadata": { "description": "Database credentials" },
  "acl": [{ "consumerId": "prod-east", "permissions": ["read"] }]
}
```

New secrets are `PENDING_VALUE` until a payload update succeeds, after which
they become `ACTIVE`. `payloadKeyCount` is written with a payload revision and
copied to later metadata/ACL-only revisions. It lets a caller warn about a
destructive replacement without retaining or exposing payload key names.
