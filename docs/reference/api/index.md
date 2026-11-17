---
title: HTTP API overview
description: Base URLs, authentication and common behavior for the Hemlig HTTP API.
---

# Hemlig API reference

This is the public reference for the **implemented HTTP API**. Its
machine-readable contract is [openapi/consumer-secrets.yaml](../openapi.md).
It includes organizational browsing, bounded immutable-audit browsing, and the
safe CSR enrollment/certificate routes. Issuer-root rotation is intentionally
excluded.

## Base URLs

| API           | URL                   | Caller                               |
| ------------- | --------------------- | ------------------------------------ |
| Administrator | `https://<adminFqdn>` | Administrator with a valid JWT       |
| Delivery      | `https://<apiFqdn>`   | Enrolled workload identity over mTLS |

The CDK stack receives both FQDNs. `apiFqdn` names a generic delivery endpoint,
even though Kubernetes workloads are its first consumer. It disables each generated API Gateway
`execute-api` endpoint, so clients must use these custom domains.

## Authentication

### Administrator API

Use a bearer JWT from the external OIDC/OAuth provider configured in CDK.
API Gateway validates its issuer and audience; Hemlig verifies those claims
again and records the configured immutable subject claim (`sub` by default) as
the actor. The provider must issue a token with the configured `aud`, or with
the configured `client_id` only when `aud` is absent.

When the deployment configures a browser console origin, it also configures an
exact administrator OAuth scope. API Gateway and Hemlig both require that scope
in `scope` or `scp`. When `oidcAdminRole` is configured, Hemlig also requires
that exact value in the token's `roles` (or `role`) claim. This is opt-in only to preserve existing non-browser
automation until its identity-provider configuration is ready.

```http
Authorization: Bearer <JWT>
```

Secret and consumer mutations need an `Idempotency-Key` of 8–128 characters.
Use one durable random value per intended operation. Reusing a key returns
`409 conflict`; retain the initial response instead of treating a retry as a
new operation.

### Delivery API

The caller presents an API leaf certificate during TLS negotiation. After a
truststore has been published, API Gateway validates its chain; Hemlig then
hashes the DER bytes and checks for an `ACTIVE` enrolled identity record in
DynamoDB. The request never accepts a client-supplied consumer ID.

An administrator enrolls a consumer through `POST /v1/admin/consumers`. The
request supplies a signed RSA CSR. Hemlig has one deployment-wide issuing root:
it verifies the CSR, signs the submitted public key as a `clientAuth` leaf with
the URI SAN `spiffe://hemlig/consumer/<consumerId>`, writes the one-root
truststore at a unique S3 version, and waits for an `AVAILABLE` no-warning
domain configuration before marking the leaf `ACTIVE`. The consumer operator
retains its private key; Hemlig never accepts, stores, or returns private-key
material. If API Gateway rejects the bundle with warnings, Hemlig rolls back to
the last known bundle when one exists, marks the operation failed, and releases
the publication lease.

### Namespace-agent bootstrap

Kubernetes and other constrained automation must not hold an administrator
OIDC token. An administrator first creates an **AgentGrant** with a new
consumer ID, one environment, `read` and/or `write` capability, and explicit
per-secret permissions. It then issues a single-use, 30-minute bootstrap
capability. Hemlig stores only its SHA-256 digest.

```http
POST /v1/bootstrap/redeem
Authorization: Bootstrap hmlb_<256-bit-random-value>
Content-Type: application/json

{ "apiCertificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----…" }
```

The route receives no desired consumer ID, environment, ACL, metadata, or endpoint
from the caller. Those values come only from the pre-created AgentGrant. It
returns the public mTLS leaf and the fixed grant scope. A retry with the same
CSR returns the same enrollment result after a lost response; a different CSR
is rejected. After successful redemption, the leaf is also registered with AWS
IoT Core for its private notification topic. The bootstrap value can never be
used as a general API token.

An active agent identity cannot bypass its grant by calling ordinary delivery
endpoints: Hemlig applies its AgentGrant UID-bound allowlist there too. The
administrator selects exact IDs, and Hemlig records their current immutable
UIDs. Each selection authorizes that one secret only; a folder name never
implicitly authorizes its children, and archiving then reusing an ID does not
transfer the grant. This is independent of console folders, which are
always derived from the slash-separated secret ID.

## Common behavior

### Headers

| Header            | Routes                    | Meaning                                |
| ----------------- | ------------------------- | -------------------------------------- |
| `Authorization`   | Admin routes              | Administrator JWT                      |
| `Authorization`   | Bootstrap redemption      | One-use `Bootstrap hmlb_…` capability  |
| `Idempotency-Key` | Admin mutations           | 8–128-character operation key          |
| `If-Match`        | `PUT` secret routes       | Required current control-revision ETag |
| `If-None-Match`   | Consumer secret read      | Optional current control-revision ETag |
| `ETag`            | Secret response and `304` | Current control revision ID            |

Responses include `Cache-Control: no-store`. Clients must not log a secret
payload or persist it in an HTTP cache.

### Error envelope

```json
{
  "error": {
    "code": "precondition_failed",
    "message": "If-Match does not name the current control revision.",
    "correlationId": "01J..."
  }
}
```

| Status | Code                  | Meaning                                                 |
| ------ | --------------------- | ------------------------------------------------------- |
| 400    | `bad_request`         | Invalid JSON, route, header, ID, ACL, or payload        |
| 400    | `invalid_csr`         | Identity rotation CSR is malformed, too weak, or reuses the caller's key |
| 403    | `forbidden`           | Invalid JWT, or a grant/ACL decision                    |
| 403    | `identity_not_active` | The client certificate is missing, unknown, revoked, or outside its validity |
| 404    | `not_found`           | Missing secret or active payload                        |
| 409    | `conflict`            | Used idempotency key or unavailable revision lease      |
| 409    | `enrollment_failed`   | Terminal truststore publication failure; do not retry   |
| 409    | `identity_limit_reached` | Self-rotation would exceed 3 active identities per consumer |
| 409    | `identity_already_rotated` | The calling identity already has an active successor  |
| 409    | `rotation_replay_inactive` | An idempotent rotation replay names a leaf that is no longer active |
| 412    | `precondition_failed` | `If-Match` is no longer current                         |
| 500    | `internal_error`      | Unexpected failure; implementation details are withheld |
| 503    | `service_unavailable` | Storage or KMS consistency/availability failure         |

## Route pages

- [Data types](data-types.md)
- [Administrator: secrets](admin-secrets.md)
- [Administrator: consumers, certificates and agent grants](admin-consumers.md)
- [Delivery and agent routes](delivery.md)
- [Audit browsing, audit behavior and excluded routes](audit.md)
