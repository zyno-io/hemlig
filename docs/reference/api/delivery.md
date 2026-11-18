---
title: Delivery and agent routes
description: Consumer secret reads, change snapshots, agent configuration, sync, agent writes and certificate self-rotation on the delivery API.
pageType: reference
---

# Delivery and agent routes

These routes are served on the delivery API (`https://api.example.com`). Every one needs an mTLS client certificate that is `ACTIVE` and unexpired.

Headers, [idempotency](index.md#idempotency) and [pagination](index.md#pagination) are on the [overview](index.md).

## Who can call what

| Caller | Routes it can use |
| --- | --- |
| [Direct consumer](../glossary.md#direct-consumer) | `GET /v1/secrets/{secretId}` and `GET /v1/changes` |
| [Agent](../glossary.md#agent) | The `/v1/agent/...` routes, plus `GET /v1/secrets/{secretId}` and `GET /v1/changes`, both limited to its [AgentGrant](../glossary.md#agentgrant) |

A direct consumer calling an `/v1/agent/...` route is rejected. An agent can never reach a secret outside its grant, even by guessing an ID on a generic route.

An agent's read access also needs a read row on the secret's ACL. The server derives that row from the grant, so administrators never edit it. See [ACL](data-types.md#acl).

**Audit.** After the caller is resolved, every route writes `attempted`, `authorized` and `succeeded`, or `failed` on error. Two exceptions are described under the secret reads and `GET /v1/agent/sync`. A rejected Hemlig-issued certificate is recorded as `failed` with `identity_not_active`. A missing or unparseable certificate, and TLS failures, are outside the audit stream. See [Audit](audit.md).

## Consumer routes

### `GET /v1/secrets/{secretId}`

Reads one secret.

- The caller needs a current `read` grant (an ACL entry for a direct consumer, an AgentGrant for an agent).
- Its environment must match the secret's, and the secret must be `ACTIVE`.
- Optional header: `If-None-Match`.

```http
GET /v1/secrets/payments/stripe/api-key HTTP/1.1
If-None-Match: "ctl-01Jprevious"
```

`200` returns the payload and revision IDs, plus `ETag`:

```json
{
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-01J...",
  "payloadVersionId": "pay-01J...",
  "payload": { "api-key": { "encoding": "utf8", "value": "sk_test_example" } }
}
```

If `If-None-Match` equals the current control revision, the route returns `304 Not Modified` with the `ETag` and does not decrypt anything.

**Audit.** A `304` writes no events. A read that fails before authorization writes only `failed`. Any other read writes `attempted` and `authorized` once it knows it will deliver, then `succeeded`.

The route never returns metadata, ACLs, encryption fields, other consumers or an S3 URL.

### `GET /v1/changes`

Returns a page of the caller's current access list. It is a snapshot, not an event log.

| Query parameter | Required | Description |
| --- | --- | --- |
| `cursor` | No | `nextCursor` from the previous page. Omit it to start. |

```json
{
  "changes": [
    {
      "secretId": "payments/stripe/api-key",
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
  "nextCursor": "opaque-cursor",
  "generatedAt": "2030-01-01T00:00:00.000Z"
}
```

| `changeKind` | Caller should |
| --- | --- |
| `secret.changed` | Fetch the secret if the recorded version differs from the local one |
| `secret.revoked` | Delete the local copy |

For an agent, a secret that left its scope appears as `secret.revoked`. The cursor lasts 15 minutes and is bound to the caller ([limits](../limits.md#pagination-and-sync)).

## Agent routes

### `GET /v1/agent/config`

Returns the active AgentGrant and the AWS IoT connection details for this identity.

```json
{
  "consumerId": "payments-prod",
  "environment": "prod",
  "grant": {
    "grantId": "grant-example",
    "capabilities": ["read"],
    "secretGrants": [
      { "secretId": "payments/stripe/api-key", "secretUid": "sec-example", "permissions": ["read"] }
    ]
  },
  "mqtt": {
    "endpoint": "iot.example.com",
    "clientId": "payments-prod",
    "topic": "hemlig/prod/consumers/payments-prod"
  }
}
```

`grant` also carries four legacy arrays (`readSecretIds`, `readSecretUids`, `writeSecretIds`, `writeSecretUids`) derived from `secretGrants`. New clients should use `secretGrants`.

The `topic` prefix is the [deployment name](../glossary.md#deployment-name), not the runtime environment.

### `GET /v1/agent/sync`

Returns current configuration and the scoped changes since a completed checkpoint. It works for write-only and empty grants too.

| Query parameter | Description |
| --- | --- |
| none | Start a current-state snapshot |
| `cursor` | Continue pages of the cycle that is in progress |
| `syncCursor` | Return changes since the checkpoint saved after the last completed cycle |

`cursor` and `syncCursor` are mutually exclusive; passing both is `400 bad_request`.

```json
{
  "config": { "consumerId": "payments-prod", "environment": "prod", "grant": { "...": "..." }, "mqtt": { "...": "..." } },
  "snapshot": false,
  "changes": [
    {
      "secretUid": "sec-example",
      "secretId": "payments/stripe/api-key",
      "controlVersionId": "ctl-example",
      "payloadVersionId": "pay-example",
      "permissions": ["read"],
      "state": "ACTIVE"
    }
  ],
  "syncCursor": "opaque-checkpoint"
}
```

- `config` has the same shape as the [`GET /v1/agent/config`](#get-v1-agent-config) response.
- Follow `nextCursor` until the final page supplies `syncCursor`. Save it only after applying the whole cycle, then pass it as `syncCursor` next time.
- Entries are current-state per secret, not history. A revoked entry never refers to a new secret that reuses the public ID.
- Metadata appears only on entries with write scope. Payloads and ACLs never appear.
- A checkpoint of an unchanged range returns an empty `changes` list and the same token.

| Status and code | Meaning |
| --- | --- |
| `410 sync_reset_required` | The token is no longer valid. Discard it and start a new snapshot. |
| `503 sync_index_not_ready` | The sync index for the environment has not finished its backfill. See [Upgrades](../../operations/upgrades.md). |

How sync, checkpoints and change hints fit together is owned by [Sync and notifications](../../guide/sync-and-notifications.md). Lifetimes are in [Pagination and sync](../limits.md#pagination-and-sync).

**Audit.** A successful sync writes no audit events: it returns no secret values and controllers poll it continuously. A sync that fails writes `failed` only.

### `GET /v1/agent/secrets/{secretId}`

Reads a payload within the grant's read scope. It behaves like [`GET /v1/secrets/{secretId}`](#get-v1-secrets-secretid): conditional with `If-None-Match`, `304` when unchanged, and a `304` writes no audit events.

### `GET /v1/agent/secrets/{secretId}/control`

Returns the agent-visible control data for one secret in the grant, including for a write-only exporter. It carries the ETag and no payload or ACL.

```json
{
  "secretId": "payments/stripe/api-key",
  "environment": "prod",
  "controlVersionId": "ctl-01J...",
  "payloadVersionId": "pay-01J...",
  "payloadKeyCount": 1,
  "state": "ACTIVE",
  "metadata": { "description": "Stripe API key" }
}
```

### `PUT /v1/agent/secrets/{secretId}`

Updates the secret's metadata. It needs `write` scope for that secret.

Required headers: `Idempotency-Key`, `If-Match`. Body: `{ "metadata": { ... } }`. It can never change an ACL. Returns `200` with the control revision and `ETag`.

### `PUT /v1/agent/secrets/{secretId}/payload`

Replaces the payload. It needs `write` scope for that secret.

Required headers: `Idempotency-Key`, `If-Match`. Body: `{ "payload": { ... } }` as in [Payload](data-types.md#payload). Returns `200` with the new control revision and `ETag`.

An administrator must create the secret and select it in the AgentGrant before an agent can write it. A stale `If-Match` is `412 precondition_failed`.

### `POST /v1/agent/identities/rotate` <Badge type="tip" text="v0.3.0+" />

Issues an overlapping replacement client certificate for the calling agent. Servers older than v0.3.0 answer `400 bad_request`. How the controller uses it is in [Identity rotation](../../operations/identity-rotation.md).

| Requirement | Value |
| --- | --- |
| Credential | The current client certificate: `ACTIVE`, unexpired, and the consumer has an `ACTIVE` AgentGrant (`403 identity_not_active` or `403 forbidden` otherwise) |
| Header | `Idempotency-Key`, 8 to 128 characters. The same key from the same certificate returns the same new certificate. |
| Body | JSON with `apiCertificateSigningRequestPem` |
| CSR | RSA, at least 2048 bits, a key different from the caller's, at most 16,384 characters |

```json
{ "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----\n..." }
```

`201` response:

```json
{
  "consumerId": "payments-prod",
  "environment": "prod",
  "rootFingerprint": "9f2c...",
  "apiFingerprint": "41ab...",
  "apiCertificatePem": "-----BEGIN CERTIFICATE-----\n...",
  "notBefore": "2030-01-01T00:00:00.000Z",
  "notAfter": "2031-01-01T00:00:00.000Z",
  "status": "ACTIVE"
}
```

- The new certificate is signed by the same issuing root, so no truststore change is needed. It is also registered with AWS IoT.
- The caller's certificate stays valid until it expires or an administrator revokes it.
- Self-rotation is refused while 3 or more certificates are active ([limits](../limits.md#identity)). Administrators are not capped.

| Error | Meaning |
| --- | --- |
| `400 invalid_csr` | The CSR is malformed, too weak, too large or reuses the caller's key |
| `409 identity_already_rotated` | This certificate already has an active successor |
| `409 identity_limit_reached` | 3 or more certificates are already active |
| `409 identity_rotation_conflict` | Another rotation for the consumer committed first. Retry with the same CSR and key. |
| `409 rotation_replay_inactive` | A replay names a certificate that is no longer active. Submit a new rotation. |

The route runs in a dedicated Lambda that can decrypt the issuer key. The ordinary delivery Lambda cannot.
