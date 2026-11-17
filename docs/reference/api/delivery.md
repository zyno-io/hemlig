---
title: Delivery and agent routes
description: mTLS consumer reads, change snapshots and agent sync.
---

# Delivery and agent routes

These routes are served on the delivery API (`https://<apiFqdn>`) and require an mTLS client certificate.

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

## Agent routes

### `GET /v1/agent/sync`

Synchronizes a compact UID-bound version index for an active AgentGrant,
including write-only or empty grants. It returns current safe agent
configuration and scoped version entries, never payloads or ACLs. Entry
permissions are effective: read scope also requires the current secret read
ACL. Organizational metadata is present only for write-authorized entries.
Archive and read revocation return a revoked entry without a payload version
unless separately authorized write access remains.

Start with no query parameters for a current-state snapshot. Continue every
`nextCursor` using `?cursor=<opaque>` until the final page supplies
`syncCursor`. After applying the entire cycle successfully, persist that
checkpoint and pass it as `?syncCursor=<opaque>` on the next synchronization.
The parameters are mutually exclusive. `@zyno-io/hemlig-client` exposes
`syncAgent({ syncCursor })` and `syncAgent({ cursor })`.

```json
{
  "config": {
    "consumerId": "cluster-prod",
    "environment": "prod",
    "grant": {
      "grantId": "grant-example",
      "capabilities": ["read"],
      "secretGrants": [
        {
          "secretId": "database-credentials",
          "secretUid": "sec-example",
          "permissions": ["read"]
        }
      ]
    },
    "mqtt": {
      "endpoint": "iot.example.test",
      "clientId": "cluster-prod",
      "topic": "hemlig/example/consumers/cluster-prod"
    }
  },
  "snapshot": false,
  "changes": [
    {
      "secretUid": "sec-example",
      "secretId": "database-credentials",
      "controlVersionId": "ctl-example",
      "payloadVersionId": "pay-example",
      "permissions": ["read"],
      "state": "ACTIVE"
    }
  ],
  "syncCursor": "<opaque-server-issued-checkpoint>"
}
```

Page cursors expire fifteen minutes after the cycle starts; checkpoints expire
seven days after its committed range is captured. Tokens are bound to the
caller, environment, current grant scope, and index epoch. `410
sync_reset_required` requires a new snapshot. An incomplete index returns
`503 sync_index_not_ready` until the operator backfill completes. An unchanged
checkpoint returns an empty delta and the same token.

Updates coalesce to each secret's latest state; this is not an event history.
Concurrent updates beyond a captured range appear on the next synchronization.
A missing snapshot entry can reflect such movement and must be checked
authoritatively before removing a mirror. A revoked old UID never refers to a
replacement secret that reuses its public ID.

The Kubernetes controller verifies local target checksums and resource status
before skipping a payload read. Local source changes retain authoritative
If-Match and Idempotency-Key protections on exports. It saves the checkpoint in
HemligConsumer status only after resource reconciliation succeeds. MQTT hints,
reconnects, and periodic passes all resume that checkpoint. See the
[design and rollout plan](/design/agent-sync-plan).

These are mTLS delivery routes for an active AgentGrant only. A normal consumer
may not use them, and an agent cannot use normal consumer routes to escape its
UID-bound exact-secret scope. All secret reads still require the agent's regular
per-secret read ACL in addition to that scope; agent writes can only affect
their selected secret UIDs and can never modify an ACL.

| Route                                      | Purpose                                                                                                                              |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /v1/agent/config`                     | Returns the active grant's safe scope and the exact AWS IoT endpoint/client/topic.                                                   |
| `GET /v1/agent/sync`                       | Returns current configuration and scoped version changes after a completed checkpoint, including write-only grants.                  |
| `GET /v1/agent/secrets/{secretId}`         | Conditional payload read within read scope.                                                                                          |
| `GET /v1/agent/secrets/{secretId}/control` | Returns only agent-visible metadata and ETag, including for a write-only exporter.                                                   |
| `PUT /v1/agent/secrets/{secretId}`         | Updates agent-allowed metadata with `If-Match`.                                                                                      |
| `PUT /v1/agent/secrets/{secretId}/payload` | Replaces payload with `If-Match`.                                                                                                    |
| `GET /v1/changes`                          | Returns the exact-secret current snapshot; an out-of-scope change is represented as `secret.revoked` so the local target is removed. |

An administrator must create the secret and select it in the AgentGrant before
an agent can update it. Agent payload/control writes require `Idempotency-Key`; updates also require
`If-Match`. The MQTT topic carries only `schemaVersion`, kind, secret ID, and
revision IDs with QoS 1. It has no payload, data key, path, ACL, token, or
certificate. Treat it solely as a trigger to fetch authoritative mTLS state;
duplicates and missed hints are expected, so reconnect and periodic snapshot
reconciliation remain required.

### `GET /v1/agent/config`

Returns the active AgentGrant (`consumerId`, `environment`, capabilities,
exact `secretGrants` with their immutable `secretUid`s) and the AWS IoT MQTT
connection details (endpoint, client ID, private topic) for this identity. The
Kubernetes controller reads this to learn what it may import or export and
where to listen for change hints.

### `POST /v1/agent/identities/rotate`

Issues an overlapping replacement for the **calling** agent's mTLS leaf. Available
from the first release that includes agent identity self-rotation; older servers
answer `400 bad_request`. See [Identity rotation](/operations/identity-rotation) for
how the controller uses it.

- **Auth:** the current client certificate, which must be `ACTIVE` and unexpired, and
  whose consumer must have an `ACTIVE` AgentGrant (`403 identity_not_active` /
  `403 forbidden` otherwise).
- **Headers:** `Idempotency-Key` (8 to 128 characters, required). Replaying the same
  key from the same certificate returns the same leaf.
- **Body:** `{ "apiCertificateSigningRequestPem": "<PEM CSR>" }`. RSA, at least 2048
  bits, and a key different from the caller's.

`201` response:

```json
{
  "consumerId": "payments-cluster",
  "environment": "prod",
  "rootFingerprint": "…",
  "apiFingerprint": "…",
  "apiCertificatePem": "-----BEGIN CERTIFICATE-----…",
  "notBefore": "2027-06-03T00:00:00.000Z",
  "notAfter": "2028-06-02T00:00:00.000Z",
  "status": "ACTIVE"
}
```

The new leaf is signed by the same issuing root (no truststore change) and is
registered with AWS IoT for MQTT hints. The caller's leaf stays valid until its own
expiry or until an administrator revokes it. Each identity may have only one active
successor, and a consumer may hold at most three active identities
(`409 identity_already_rotated` / `409 identity_limit_reached`). A CSR problem returns
`400 invalid_csr`.

The route is served by a dedicated Lambda that can decrypt the issuer key; the
ordinary delivery Lambda cannot.

### Agent secret routes

These apply the AgentGrant's exact-secret allowlist on top of the ordinary ACL
rules. An agent never changes ACLs through them.

| Route                                           | Needs         | Purpose                                                                                        |
| ----------------------------------------------- | ------------- | ---------------------------------------------------------------------------------------------- |
| `GET /v1/agent/secrets/{secretId}`              | read scope    | Read the payload. Supports `If-None-Match` and returns `304` when the control revision matches |
| `GET /v1/agent/secrets/{secretId}/control`      | grant scope   | Agent-visible control metadata and ETag, without payload or ACL                                |
| `PUT /v1/agent/secrets/{secretId}`              | write scope   | Update allowed metadata (`If-Match` and `Idempotency-Key` required; cannot alter ACLs)         |
| `PUT /v1/agent/secrets/{secretId}/payload`      | write scope   | Replace the payload (`If-Match` and `Idempotency-Key` required)                                |

Request and response shapes follow the same payload and control-revision types
described in [Data types](data-types.md); the machine-readable definitions are
in the [OpenAPI contract](/reference/openapi).
