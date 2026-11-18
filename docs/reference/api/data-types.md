---
title: API data types
description: Identifier formats, environments, metadata, ACLs, payloads and control revisions used by the Hemlig API.
pageType: reference
---

# Data types

These are the shapes shared across the route pages. Numeric limits are owned by [Limits and timings](../limits.md).

## Identifiers

| Type | Pattern | Notes |
| --- | --- | --- |
| Consumer ID | `^[a-z][a-z0-9-]{2,63}$` | Unique across the deployment |
| Secret ID | `^[a-z][a-z0-9-]{2,63}(/[a-z][a-z0-9-]{2,63})*$` | At most 256 characters. No leading, trailing or empty segments. |
| Environment name | `^[a-z][a-z0-9-]{0,63}$` | Must be defined before use |
| Secret UID | `sec-...` | Immutable; assigned at creation. See [Secret UID](../glossary.md#secret-uid). |
| Control revision ID | `ctl-...` | The ETag |
| Payload revision ID | `pay-...` | |

`POST /v1/admin/secrets` requires a caller-supplied `secretId`. The ID is unique among live secrets in an environment and reusable after archive.

## Environments

An administrator defines each [environment](../glossary.md#environment) with [`POST /v1/admin/environments`](admin-secrets.md#post-v1-admin-environments). Secret creation, consumer enrollment and catalog browsing need an existing definition. A fresh deployment has none.

## Folders

A [folder](../glossary.md#folder) is the parent prefix of a secret ID. `payments/stripe/api-key` appears under `payments/stripe`.

- Folders are derived for browsing only. An empty folder does not exist.
- A folder never grants access, to a consumer or to an agent. Agent authorization is exact [secret UID](../glossary.md#secret-uid) membership in an [AgentGrant](../glossary.md#agentgrant).

## Metadata

| Field | Required | Limit | Notes |
| --- | --- | --- | --- |
| `description` | No | 1,024 characters | Free text |
| `tags` | No | 20 keys | Lowercase keys to short exact-match values |

Tags and descriptions are returned to administrators only. They never select a delivery target or grant access, and the consumer API never returns them. `metadata.path` is not supported.

## ACL

```json
{
  "metadata": { "description": "Stripe API key" },
  "acl": [{ "consumerId": "payments-prod", "permissions": ["read"] }]
}
```

| Rule | Value |
| --- | --- |
| Entries | At most 40, one per consumer |
| Permission | `read` only |
| Who can be listed | An active [direct consumer](../glossary.md#direct-consumer) in the secret's environment |

Removing a consumer leaves a `REVOKED` [tombstone](../glossary.md#tombstone) in its change snapshot so an offline workload learns it lost access.

::: warning Agent rows are server-managed
An [agent](../glossary.md#agent)'s access is managed by its AgentGrant. The server derives the matching read row from the grant and appends it to `acl`, so agent rows are visible there. A full ACL replacement must carry them through unchanged, or send `preserveAgentAcl: true` to keep omitted agent rows ([`PUT`](admin-secrets.md#put-v1-admin-secrets-secretid)). A request that adds, changes or removes an agent's ACL row returns `409 conflict`. Change the grant instead; see [Administrator consumer and grant routes](admin-consumers.md#put-v1-admin-agent-grants-grantid).
:::

## Payload

A payload is a map of entry names to values. The serialized JSON body is at most 768,000 bytes.

```json
{
  "username": { "encoding": "utf8", "value": "service-account" },
  "password": { "encoding": "base64", "value": "c2VjcmV0" }
}
```

| Part | Rule |
| --- | --- |
| Entry name | Letters, digits, `.`, `_` and `-` |
| `encoding` | `utf8` or `base64` |
| `value` | Text for `utf8`; canonical RFC 4648 base64 with padding for `base64` |

## Control revision

Admin routes return an immutable control revision. Its `controlVersionId` is the ETag for the next update.

::: details Example control revision
```json
{
  "schemaVersion": 1,
  "secretUid": "sec-0f5c2d1e-8a47-4c0e-9b1d-3a6e7f2c9d10",
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-92b9be7b-4e03-4a8c-87be-6a2d0af66147",
  "payloadVersionId": "pay-8436f80a-00ee-48d2-8a18-3a1194279ddc",
  "payloadKeyCount": 1,
  "environment": "prod",
  "state": "ACTIVE",
  "createdAt": "2030-01-01T00:00:00.000Z",
  "createdBy": { "type": "human", "id": "example-subject" },
  "metadata": { "description": "Stripe API key" },
  "acl": [{ "consumerId": "payments-prod", "permissions": ["read"] }]
}
```
:::

| Field | Meaning |
| --- | --- |
| `state` | `PENDING_VALUE` after create, `ACTIVE` once a payload exists, `ARCHIVED` (terminal). See [Secret state](../glossary.md#secret-state). |
| `payloadVersionId` | Absent until the first payload write |
| `payloadKeyCount` | Number of payload entries. Metadata-only revisions copy it. It never reveals entry names. |
