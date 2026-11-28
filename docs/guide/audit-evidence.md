---
title: Audit evidence
description: What Hemlig records, what it does not, where the evidence is kept and how long it lasts.
pageType: explanation
---

# Audit evidence

Hemlig writes an immutable audit event for nearly every authenticated request, keeps it for seven years, and never lets a secret value leave before its event is stored.

This page describes behavior in v0.3.2, plus the rows marked v0.3.6. Terms: [audit event](../reference/glossary.md#audit-event), [audit archive](../reference/glossary.md#audit-archive), [Object Lock](../reference/glossary.md#object-lock).

## What is audited

| Request | Audited | Events written |
| --- | --- | --- |
| Any administrator request, including reads and the plaintext payload read | Yes | `attempted`, `authorized`, `succeeded` |
| Consumer and agent requests (`/v1/changes`, `/v1/agent/config`, writes) | Yes | `attempted`, `authorized`, `succeeded` |
| Successful `GET /v1/agent/sync` | No | None |
| Failed `GET /v1/agent/sync` | Yes | `failed` only |
| Secret read that returns a value | Yes | `attempted`, `authorized`, `succeeded` |
| Conditional secret read that returns `304` | No | None |
| Secret read that fails before authorization | Partly | `failed` only |
| Failure after an audited request began | Yes, best effort | `failed` |
| Identity enrollment and rotation | Yes | Same three, plus `failed` on error |
| Bootstrap redemption | Only after the token is redeemed | `attempted`, `authorized`, `succeeded`. A rejected redemption writes none |
| Recovery and retention worker actions | Yes | Per action |
| Audit-archive reads (`GET /v1/admin/audit`) | No | None |
| `OPTIONS` preflight | No | None |
| Rejected Hemlig-issued client certificate (revoked, unknown, not yet valid or expired identity) | Yes | `failed` with `identity_not_active`, actor is the certificate fingerprint. At most one per fingerprint per 10 minutes. Starts in v0.3.6 |
| Missing or unparseable certificate, or a rejected token, before an actor exists | No (v0.3.2 and later) | None here; use API Gateway logs |

Two points are easy to miss:

- A successful `GET /v1/agent/sync` and a `304` are skipped on purpose. Neither returns a secret value, and controllers poll both, so auditing them would fill the archive with noise. Failures are still recorded.

Reading the audit archive is not audited. Querying it creates no events, and this is current behavior, not a promise to change. The query Lambda has no code path that writes one.

## Order of events

Events are written in order, and the last one comes before the response. The order of the first two depends on the route family.

| Route family | Sequence | A failure writes |
| --- | --- | --- |
| Administrator routes | `attempted`, `authorized`, operation, `succeeded` | `failed` after the events already written |
| Non-read consumer and agent routes, identity rotation | `attempted` first | `attempted`, `failed` |
| Agent config, control and write routes | `attempted`, operation, then `authorized`, `succeeded` | `attempted`, `failed` |
| `GET /v1/agent/sync` | Nothing on success | `failed` only |
| `GET /v1/changes` | `attempted`, `authorized` (before the capability check), operation, `succeeded` | `attempted`, `authorized`, `failed` |
| Secret reads | Nothing until the read is known to deliver a value, then `attempted`, `authorized`, `succeeded` | `failed` only |

For a secret read, the value is decrypted in memory and returned only after `succeeded` is stored. If the write fails, the caller gets an error and no plaintext.

Only a secret read fails with `failed` alone, with the reason code `request_failed`. If the `failed` write also fails, the original error is still what the caller sees.

## What an event contains

Each event holds a timestamp, a correlation ID, the actor, the operation, safe target IDs, the outcome, the source IP when known and a reason code on failure.

Events never contain secret values, request bodies, tokens, certificates, private keys or key material.

## Where evidence is stored

Events go to a dedicated S3 bucket with a unique key per event, newest first within a day:

```text
audit/yyyy/mm/dd/DESCENDING-TIMESTAMP-EVENT-ID.json
```

Keys are written once and never overwritten.

## Why seven years

The audit bucket uses Object Lock in Compliance mode with a seven-year default retention. In Compliance mode nobody can delete an event or shorten its retention, including the account's root user. That gives you tamper-resistant evidence for the retention windows common in security and financial audits.

The cost is permanence: locked events block stack teardown until they expire. The exact periods are in [Limits](../reference/limits.md#storage-and-retention).

Object Lock protects what was written. It does not prove the application never wrote a misleading event. Hemlig does not hash-chain events. See the [threat model](../security/threat-model.md).

## Reading the archive

Only the audit-query Lambda can read the bucket. Other Lambdas can only write to it. The administrator route returns one UTC day at a time, up to 50 objects per page, with an opaque cursor. Filters and parameters are in the [audit API](../reference/api/audit.md).

## Next steps

- [Audit API reference](../reference/api/audit.md)
- [Threat model](../security/threat-model.md)
- [AWS resources](../reference/aws-resources.md)
