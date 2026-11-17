---
title: Audit browsing and behavior
description: Administrator audit browsing route, audit semantics and excluded routes.
---

# Audit browsing and behavior

## `GET /v1/admin/audit?date=<YYYY-MM-DD>&secretId=<id>&cursor=<opaque>`

Every authenticated administrator may browse immutable application evidence for
one UTC day. `date` defaults to the current UTC day. An optional `secretId`
returns only records whose safe target ID exactly matches that secret. A page
contains at most 50 records in newest-first order; its opaque cursor is bound
to the requesting administrator, date, and filter, with server-side state that
expires after 15 minutes. The console exposes this as the **Audit** tab and
links each secret detail page to its filtered view.

Records contain only timestamp, correlation ID, actor, operation, outcome,
safe target IDs, source IP when available, and a safe reason code. They never
contain plaintext payloads, request bodies, tokens, or certificate material.
The immutable actor ID is the configured OIDC subject claim (`sub` by default).
When the access token contains an `email` claim, new records also carry it as a
display-only point-in-time label; it never takes part in authorization or
idempotency.
Reading the archive itself creates ordinary audit events, so audit-browser
activity is visible in later pages.

## Audit behavior

After a caller has been resolved to an application actor, Hemlig emits attempted,
authorized, and terminal-success or terminal-failed audit events. It writes
terminal success before responding with plaintext. TLS or JWT failures rejected
before an actor exists are outside the application event stream and must be
investigated through the stack's sanitized API Gateway access logs and
control-plane logs. Audit records never
include secret payloads, tokens, request bodies, or certificate material. See
[architecture](/guide/architecture#audit-evidence) for archive keys and retention
semantics.

## Deliberately excluded routes

There is no public issuer-root-rotation endpoint or consumer-side write API.
Clients must not infer future lifecycle routes from the DynamoDB record shape.
