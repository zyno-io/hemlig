---
title: Audit routes and behavior
description: The audit archive browsing route and exactly which requests write audit events.
pageType: reference
---

# Audit routes and behavior

This page documents the one audit route and lists which requests write [audit events](../glossary.md#audit-event). What the archive is, how it is stored and how to use it as evidence is owned by [Audit evidence](../../guide/audit-evidence.md).

## Browse the audit archive

### `GET /v1/admin/audit`

Returns one UTC day of immutable application events, newest first. Any authenticated administrator can call it. It is served by its own read-only Lambda on the administrator API.

| Query parameter | Required | Description |
| --- | --- | --- |
| `date` | No | `YYYY-MM-DD`, a real UTC date. Default: today (UTC). |
| `secretId` | No | Only events whose target secret ID matches exactly |
| `environment` | No | Only events whose target environment matches exactly |
| `cursor` | No | `nextCursor` from the previous page |

```json
{
  "date": "2030-01-01",
  "events": [
    {
      "eventId": "evt-example",
      "at": "2030-01-01T00:00:00.000Z",
      "correlationId": "01J...",
      "outcome": "succeeded",
      "actor": { "type": "human", "id": "example-subject", "email": "admin@example.com" },
      "operation": "adminget:/v1/admin/secrets/payments/stripe/api-key",
      "target": { "environment": "prod", "secretId": "payments/stripe/api-key" },
      "sourceIp": "192.0.2.10"
    }
  ],
  "nextCursor": "opaque-cursor",
  "generatedAt": "2030-01-01T00:00:00.000Z"
}
```

- A page reads at most 50 archive objects. Filters apply after that read, so a page can be short or empty while `nextCursor` is present. Keep following cursors.
- The cursor is bound to the administrator, date and filters, and expires after 15 minutes ([limits](../limits.md#pagination-and-sync)).
- Events hold only timestamp, correlation ID, actor, operation, outcome, safe target IDs, source IP and a reason code. They never hold payloads, request bodies, tokens or certificate material.
- The actor ID is the configured subject claim. An `email` claim, when present, is stored as a display-only label.
- **This route is not audited.** Reading the archive writes no events.

## Which requests write events

Current behavior as of v0.3.2. `operation` is `admin<method>:<path>` for administrator routes, `consumer<method>:<path>` or `agent<method>:<path>` for delivery routes, plus `bootstrap.redeem` and `agent.identity.rotate`.

| Request | Events written |
| --- | --- |
| Administrator route (not the audit route) | `attempted`, `authorized`, then `succeeded` or `failed` |
| CORS preflight (`OPTIONS`) | None |
| Consumer or agent route: config, control, writes | `attempted`, then `authorized` and `succeeded` after the operation. A failure writes `attempted` and `failed` |
| `GET /v1/changes` | `attempted`, `authorized` (before the capability check), then `succeeded` or `failed` |
| Secret read that delivers a value | `attempted`, `authorized`, `succeeded` |
| Conditional secret read answered `304` | None |
| Secret read that fails before authorization | `failed` only (secret reads are the only case) |
| `GET /v1/agent/sync` | `attempted` first; `authorized` and `succeeded` after the sync returns. A failed sync writes `attempted` and `failed`. |
| `POST /v1/agent/identities/rotate` | `attempted` first, then `authorized` once the caller passes the checks, then `succeeded`. A failure before that writes `attempted` and `failed` |
| `POST /v1/bootstrap/redeem` | `attempted`, `authorized`, `succeeded` once the token is redeemed; a rejected token writes none |
| `GET /v1/admin/audit` | None |
| JWT or TLS rejection before an actor exists | None. Use the stack's API Gateway access logs. |

A `failed` event carries `reasonCode: request_failed`. The server writes `succeeded` before it responds with a plaintext payload.

## Deliberately excluded routes

There is no public route to rotate the issuing root, and no write API for direct consumers. Do not infer other lifecycle routes from the storage layout.
