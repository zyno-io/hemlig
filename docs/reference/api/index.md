---
title: HTTP API overview
description: Base URLs, authentication, headers, idempotency and pagination shared by every Hemlig HTTP route.
pageType: reference
---

# HTTP API overview

Hemlig serves two HTTPS APIs. This page covers what every route shares; the route pages list each endpoint once.

The machine-readable contract is the [OpenAPI document](../openapi.md). It also covers the bootstrap route.

## Base URLs

| API | URL | Caller | Credential |
| --- | --- | --- | --- |
| [Administrator API](../glossary.md#administrator-api) | `https://admin.example.com` | Administrator, or an agent redeeming a bootstrap token | OIDC access token, or bootstrap token |
| [Delivery API](../glossary.md#delivery-api) | `https://api.example.com` | Enrolled workload | Client certificate (mTLS) |

Both hosts come from the CDK stack inputs `adminFqdn` and `apiFqdn`. The stack disables the generated `execute-api` endpoints, so clients must use these custom domains.

## Authentication

### Administrator API

Send an OIDC access token for the API audience:

```http
Authorization: Bearer eyJ...
```

API Gateway validates the issuer and audience, and Hemlig checks them again. The audit [actor](../glossary.md#actor) is the configured subject claim (`sub` by default).

The required `aud`, scope and role claims are owned by [Identity provider](../../guide/identity-provider.md). The token must be an access token, not an ID token.

### Delivery API

The caller presents a [client certificate](../glossary.md#client-certificate) during the TLS handshake. API Gateway validates the chain against the published [truststore](../glossary.md#truststore). Hemlig then looks up the certificate's [fingerprint](../glossary.md#fingerprint) and requires an `ACTIVE`, unexpired identity.

The request never carries a consumer ID. It always comes from the identity record. How certificates are issued and trusted is owned by [Identity and trust](../../guide/identity-and-trust.md).

An [agent](../glossary.md#agent) uses the same delivery host. On the ordinary secret routes its [AgentGrant](../glossary.md#agentgrant) applies as well; see [Delivery and agent routes](delivery.md).

### Bootstrap route

`POST /v1/bootstrap/redeem` is on the administrator host but takes no JWT. It accepts only a [bootstrap token](../glossary.md#bootstrap-token):

```http
Authorization: Bootstrap hmlb_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG
```

See [Administrator consumer and grant routes](admin-consumers.md#post-v1-bootstrap-redeem).

## Headers

| Header | Used on | Meaning |
| --- | --- | --- |
| `Authorization` | Administrator routes | `Bearer` OIDC access token |
| `Authorization` | Bootstrap redemption | `Bootstrap` one-use token |
| `Idempotency-Key` | Selected mutations (see [Idempotency](#idempotency)) | 8 to 128 characters, one per intended operation |
| `If-Match` | Secret updates, payload writes, archive, agent writes | Current control-revision ETag |
| `If-None-Match` | Consumer and agent secret reads | Optional ETag; a match returns `304` |
| `ETag` | Control-revision and secret responses, `304` | Current control-revision ID |

Quotes around an ETag are accepted and stripped. Every response carries `Cache-Control: no-store`. Never log a payload or put it in an HTTP cache.

## Idempotency

An [idempotency key](../glossary.md#idempotency-key) is a random value (8 to 128 characters) that you generate once per intended operation. Keys are scoped to the caller. The table shows which routes need one and what a second use does.

| Route family | Key | Reusing the key |
| --- | --- | --- |
| Secret create, metadata or ACL update, payload write, archive | Required | `409 conflict`. The original response is not replayed. |
| Remove a consumer from a secret ACL (`DELETE .../grants/{secretId}`) | Required | `409 conflict`, as above |
| Agent secret writes (`PUT /v1/agent/secrets/...`) | Required | `409 conflict`, as above |
| Enroll a consumer (`POST /v1/admin/consumers`) | Required | Same request: resumes a prepared enrollment or returns the recorded certificate. Different request: `409 conflict`. A terminal truststore failure returns `409 enrollment_failed`. |
| Issue another client certificate (`POST .../api-identities`) | Required | Same CSR: returns the same certificate and re-registers it with AWS IoT for an agent. Different request: `409 conflict`. |
| Revoke a client certificate (`DELETE .../api-identities/{fingerprint}`) | Required | Returns `200` and re-applies the AWS IoT revocation |
| Agent self-rotation (`POST /v1/agent/identities/rotate`) | Required | Same key from the same certificate: returns the same new certificate |
| Provision the issuing root (`POST /v1/admin/issuer`) | Required (validated) | Safe to repeat: `201` when it creates the root, `200` afterwards |
| Create an environment, create or update an AgentGrant, issue a bootstrap token | Not used | Not applicable |
| Bootstrap redemption | Not used | A retry with the same CSR returns the same result; a different CSR is rejected |

Do not mint a new key to get past a `409`. After a lost response, read the current state and decide what to reconcile. See [Errors](errors.md).

## Pagination

List routes return a page and, when more remain, an opaque `nextCursor`. Pass it back unchanged as `cursor` until it is absent.

- A cursor is bound to the caller and to the filters of the request that created it. A different caller or filter is rejected.
- A page can be empty or short while `nextCursor` is still present, because filters apply after a bounded read. Keep following cursors.
- Search (`q`) and the folder tree return one bounded answer with `truncated` instead of a cursor. `truncated: true` means the scan hit its bound and results may be missing.
- Agent sync uses `cursor` for pages within one cycle and `syncCursor` for the checkpoint between cycles.

Cursor lifetimes, page sizes and scan bounds are in [Pagination and sync](../limits.md#pagination-and-sync).

## Errors

Every failure uses one envelope with a stable `code` and a `correlationId`. All codes, statuses and recommended actions are in [Errors](errors.md).

## Route pages

| Page | Routes |
| --- | --- |
| [Data types](data-types.md) | Shared shapes: IDs, environments, metadata, ACL, payload, control revision |
| [Administrator: secrets](admin-secrets.md) | Environments, secret catalog, tree, create, update, payload, archive, revisions, archived lookup |
| [Administrator: consumers, certificates and grants](admin-consumers.md) | Consumers, client certificates, issuing root, AgentGrants, bootstrap |
| [Delivery and agent routes](delivery.md) | Consumer reads, change snapshots, agent configuration, sync and writes, self-rotation |
| [Audit](audit.md) | Audit archive browsing and audit behavior |
