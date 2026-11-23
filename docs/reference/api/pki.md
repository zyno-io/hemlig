---
title: "PKI consumer routes"
description: "List issuance grants, issue leaf certificates from a CSR, and read CA bundles and CRLs on the delivery API, with the replay rules, the requester metadata and the error tables."
pageType: reference
---

# PKI consumer routes

These routes are served on the delivery API (`https://api.example.com`). Each needs an mTLS client certificate that is `ACTIVE` and unexpired, like the [delivery routes](delivery.md). The caller is a direct consumer or an agent. An agent's AgentGrant must also be `ACTIVE`, in the same environment.

For the concepts see [PKI](../../guide/pki.md). Administrators manage grants and inventory on the [administrator PKI routes](admin-pki.md).

**Audit.** A successful read writes no event. A successful issuance writes one `succeeded` event before the response is returned, so a failed audit write fails the request and the retry replays. A failure writes one `failed` event with `reasonCode` set to the error reason. Identical failures from one identity, grant or issuer ID, and reason are recorded at most once per 10 minutes. Keys, CSRs and certificate PEMs never appear in events.

## Routes

| Method and path | Operation | Request | Success |
| --- | --- | --- | --- |
| `GET /v1/pki/issuance-grants` | `pki.grant.list` | none | `200`, `{grants, generatedAt}` |
| `GET /v1/pki/issuance-grants/{name}` | `pki.grant.get` | none | `200`, one grant |
| `POST /v1/pki/issuance-grants/{name}/certificates` | `pki.certificate.issue` | `Idempotency-Key`, issue body | `201`, the certificate |
| `GET /v1/pki/cas/{caId}/bundle` | `pki.bundle.get` | none | `200`, the CA bundle |
| `GET /v1/pki/crls/{id}` | `pki.crl.get` | optional `If-None-Match` | `200` DER, or `304` |

`name` is 3 to 64 lowercase letters, digits and hyphens, starting with a letter.

The bundle and CRL routes need no grant: any `ACTIVE` identity in the CA's environment may read them, because they carry only public material. The [trust bundle](../../guide/trust-bundles.md) controller uses them.

## The caller's grants

Both read routes return only live grants in the caller's environment. A deleted grant, a grant in another environment and a name that never existed are all `404 issuance_grant_not_found`.

```json
{
  "name": "web",
  "uid": "pkg-6f1c...",
  "status": "ACTIVE",
  "expired": false,
  "version": "pkv-2b9e...",
  "expiresAt": "2027-12-31T00:00:00.000Z",
  "policy": { "names": { "dns": { "allow": ["*.payments.example.com"] } } },
  "quotas": { "perHour": 100, "perDay": 1000 },
  "ca": {
    "caId": "ca-0a1b2c3d",
    "name": "prod-issuing-1",
    "fingerprint": "ab12...",
    "notAfter": "2031-01-01T00:00:00.000Z",
    "status": "ACTIVE"
  }
}
```

A disabled or expired grant is still returned, with `status` or `expired: true`. Issuing against it fails with `issuance_grant_inactive`. The list holds at most 20 grants, because a consumer cannot have more.

## Issue a certificate

`POST /v1/pki/issuance-grants/{name}/certificates` signs a certificate for the public key in a CSR. The request needs an `Idempotency-Key` of 8 to 128 characters.

```json
{
  "certificateSigningRequestPem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "durationSeconds": 7776000,
  "usages": ["digitalSignature", "keyEncipherment", "serverAuth"],
  "isCA": false,
  "requester": {
    "kubernetes": {
      "namespace": "payments",
      "name": "api-1",
      "uid": "6f1c2d3e-0000-0000-0000-000000000000",
      "certificateName": "api",
      "revision": "3"
    }
  }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `certificateSigningRequestPem` | Yes | One PEM CSR, at most 32 KiB. Its signature must verify, and its key algorithm must be in the grant and the CA policy |
| `durationSeconds` | No | A positive integer. Default: the grant's default lifetime. It is clamped to the grant, the CA and the CA certificate's remaining validity; `lifetimeClamped` says so. Below the grant's minimum is `lifetime_too_short` |
| `usages` | No | Up to 16 strings of at most 64 characters. When empty, usages come from the CSR |
| `isCA` | No | Anything but `false` is denied with `ca_not_permitted` |
| `requester.kubernetes` | No | Caller-asserted metadata, see below |

**Names come from the CSR alone.** A body with `sans` or `subject` is `400 names_from_csr_only`. Hemlig reads the CSR's SANs and subject and applies the grant to them. Unknown body fields are `400 unknown_field`.

A CSR that carries an email or other unsupported SAN, a subject attribute outside C, ST, L, O, OU and CN, a second CN, an unsupported key usage, or an extended key usage other than server or client authentication is denied (`name_not_permitted`, `subject_not_permitted`, `key_usage_not_permitted`, `extended_key_usage_not_permitted`).

On success the response is `201`:

```json
{
  "caId": "ca-0a1b2c3d",
  "serial": "4f1c...",
  "fingerprint": "9c0e...",
  "certificatePem": "-----BEGIN CERTIFICATE-----...",
  "chainPem": "-----BEGIN CERTIFICATE-----...",
  "caPem": "-----BEGIN CERTIFICATE-----...",
  "notBefore": "2030-01-01T00:00:00.000Z",
  "notAfter": "2030-04-01T00:00:00.000Z",
  "issuanceGrant": "web",
  "lifetimeClamped": false
}
```

| Field | Description |
| --- | --- |
| `certificatePem` | The leaf |
| `chainPem` | The issuing CA certificate and any intermediates, excluding the anchor |
| `caPem` | The anchor, your external root |

The leaf is `CA:FALSE`, carries the SKI and the CA's AKI, and its SAN is critical only when the subject is empty. A certificate larger than 16 KiB is denied with `certificate_too_large`. Hemlig re-parses the signed leaf and checks it against the plan before it commits.

### Replay

The idempotency record is keyed by the caller and the `Idempotency-Key`. It stores a digest of the issuance-affecting input:

```text
sha256(stableJson({op, consumerId, grantName, csrDerSha256, durationSeconds, sortedUsages, isCA}))
```

Requester metadata is not part of the digest, so a retry may change it.

| Retry | Result |
| --- | --- |
| Same key, same digest | `201` with the same certificate, with the chain from the current CA record. No quota is charged and no capacity is checked |
| Same key, different digest | `409 conflict`, reason `idempotency_key_reused` |
| The certificate is now revoked | `409 issuance_revoked`, reason `certificate_revoked`, or `ca_revoked` when the CA is revoked |
| The certificate expires within 60 seconds | `409 issuance_expired`, reason `result_expiring` |
| The certificate expired more than 90 days ago | `409 issuance_expired`, reason `inventory_expired` |

Use one key per intended certificate and reuse it for every retry of that request. The cert-manager issuer derives it from the CertificateRequest UID. A different CSR or duration needs a new key.

Concurrent requests with one key produce one certificate. A request that loses the race, or whose commit result is unknown, reads back and returns the winner. If the winner cannot be confirmed the response is `503`: retry with the same key.

### Requester metadata

`requester.kubernetes` is recorded on the certificate and in the audit event. It is never used for authorization.

| Field | Pattern |
| --- | --- |
| `namespace` | A DNS label: `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$` |
| `name`, `certificateName` | Up to 253 characters, `^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$` |
| `uid` | `^[0-9A-Fa-f-]{1,64}$` |
| `revision` | `^\d{1,10}$` |

A violation is `400 invalid_requester`.

### Quotas, capacity and `Retry-After`

Before it signs, Hemlig checks three hourly or daily counters and the CA's capacity.

| Check | Limit | Refusal |
| --- | --- | --- |
| Grant, per hour | `quotas.perHour`, default 100 | `429`, reason `grant_hour` |
| Grant, per day | `quotas.perDay`, default 1,000 | `429`, reason `grant_day` |
| CA, per hour | The CA's `issuancePerHour`, default 2,000, shared by every grant and administrator | `429`, reason `ca_hour` |
| CA capacity | The CA's `capacity`, default 8,000 certificates of any status | `409 ca_capacity_exceeded` |

Every `429` from Hemlig has the standard error body, a `Retry-After` header in seconds until the exhausted window ends (1 to 3600 for an hourly counter), and `error.details.retryAfterSeconds`. When both the grant day and hour counters are exhausted the reason is `grant_day`. Capacity wins over a quota.

API Gateway also throttles `POST /v1/pki/{proxy+}` (`pkiIssuanceRateLimit` and `pkiIssuanceBurstLimit`). That `429` has no error body. Retry with backoff.

## CA bundles

`GET /v1/pki/cas/{caId}/bundle` returns the public material a verifier needs for one CA. `caId` matches `ca-[a-z0-9-]{3,80}`. The response is `200 application/json` with `Cache-Control: no-store` and no `ETag`, and `If-None-Match` is ignored.

```json
{
  "caId": "ca-0a1b2c3d",
  "name": "prod-issuing-1",
  "status": "ACTIVE",
  "drained": false,
  "fingerprint": "ab12...",
  "notAfter": "2031-01-01T00:00:00.000Z",
  "anchorPem": "-----BEGIN CERTIFICATE-----...",
  "anchorTrusted": true,
  "chainPem": "-----BEGIN CERTIFICATE-----...",
  "crlIssuers": [
    { "id": "ca-0a1b2c3d", "source": "GENERATED" },
    { "id": "ext-0123456789abcdef0123456789abcdef01234567", "source": "UPLOADED" }
  ]
}
```

| Field | Description |
| --- | --- |
| `status` | `ACTIVE`, `RETIRED` or `REVOKED`. A revoked CA is still returned, with its anchor |
| `drained` | `true` for a `RETIRED` CA whose last certificate has expired and whose CRL covers it |
| `anchorPem` | The external root |
| `anchorTrusted` | Whether the anchor should be trusted. Always `true` in this release |
| `chainPem` | The CA certificate, then the non-anchor intermediates. Every block ends in a newline |
| `crlIssuers` | The CRLs a verifier needs, self first and then the parent root. `GENERATED` is a Hemlig CA, `UPLOADED` is a root CRL you upload |

A `PENDING_CERTIFICATE` or `FAILED` CA has no certificate and is `409 ca_not_active`.

## CRLs

`GET /v1/pki/crls/{id}` returns the current DER CRL for a CA (`ca-…`) or an external root (`ext-` and 40 hex digits). It reuses the [administrator route's](admin-pki.md#download-a-crl) bytes, integrity check and ETag.

| Header | Value |
| --- | --- |
| `Content-Type` | `application/pkix-crl` |
| `Cache-Control` | `no-store` |
| `ETag` | The SHA-256 of the DER as hex, without quotes |
| `Content-Disposition` | `attachment; filename="<id>-<number>.crl"` |
| `Hemlig-Crl-Number` | The CRL number: decimal for a `ca-` ID, 40 hex digits for an `ext-` ID |
| `Hemlig-Crl-This-Update` | ISO 8601 |
| `Hemlig-Crl-Next-Update` | ISO 8601 |

The body is base64 on the wire and decoded by API Gateway. Send `If-None-Match` with the SHA-256, quoted or not, a weak `W/` form, a list or `*`. A match returns `304` with no body and the same `ETag` and `Hemlig-Crl-*` headers.

**Scoping.** A `ca-` ID in another environment is `404 ca_not_found`, the same as an unknown ID, so existence does not leak. An `ext-` root is visible when it serves a CA in the caller's environment; otherwise `404 external_ca_not_found`. A CA or root with no CRL yet is `404 crl_missing`. The administrator route also returns the three `Hemlig-Crl-*` headers.

### Bundle and CRL routes

A failure writes one `failed` event with the caller, environment and `caId` or `extId`. The Trust bundle column says how the [controller](../../guide/trust-bundles.md) treats the failure.

| Route | Code | Status | `details.reason` | Trust bundle |
| --- | --- | --- | --- | --- |
| bundle | `not_found` | 404 | `ca_not_found` | `CaNotFound` |
| CRL | `not_found` | 404 | `ca_not_found` | CRL `Missing`, `CrlMissing` |
| bundle | `ca_not_active` | 409 | `pending_certificate`, `failed` | `CaNotActive` |
| bundle | `service_unavailable` | 503 | none. The CA record is incomplete | Retried |
| CRL | `not_found` | 404 | `external_ca_not_found` | CRL `Missing` |
| CRL | `not_found` | 404 | `crl_missing` | CRL `Missing`, `CrlMissing` |
| CRL | `service_unavailable` | 503 | none. S3 read failure or integrity mismatch | Retried; the mounted copy is kept |
| both | `identity_not_active` | 403 | none | `ConsumerNotReady` |
| both | `not_found` | 404 | none: the path does not match | Retried slowly |

## Errors

Every error carries `error.details.reason`. The code list is in [Errors](errors.md). The Controller column says how the [cert-manager issuer](../../guide/cert-manager.md) treats the failure: `Failed` is terminal for the CertificateRequest, `Pending` is retried.

| Code | Status | `details.reason` | Controller |
| --- | --- | --- | --- |
| `bad_request` | 400 | `names_from_csr_only`, `invalid_requester`, `unknown_field`, `body_too_large` | Failed |
| `invalid_csr` | 400 | The specific CSR problem, or `key_algorithm_not_permitted` for a key the CA policy refuses | Failed |
| `issuance_denied` | 403 | `name_not_permitted`, `wildcard_not_permitted`, `reserved_name`, `common_name_not_permitted`, `subject_not_permitted`, `key_algorithm_not_permitted`, `key_usage_not_permitted`, `extended_key_usage_not_permitted`, `ca_not_permitted`, `too_many_names`, `certificate_too_large`, `lifetime_too_short`, `name_constraint_violation`. Adds `deniedNameType` (`dns`, `ip`, `uri`, `commonName`, `subject`) and `deniedName` (up to 253 characters) when a name caused it | Failed |
| `issuance_grant_not_found` | 404 | `grant_not_found` | Pending |
| `issuance_grant_inactive` | 403 | `grant_disabled`, `grant_expired` | Pending |
| `identity_not_active` | 403 | `agent_grant_inactive`, or none when the certificate itself is not active | Pending |
| `ca_not_active` | 409 | `not_found`, `environment_mismatch`, `pending_certificate`, `retired`, `revoked`, `failed`, `revoked_by_parent`, `leaves_not_permitted`, `not_yet_valid`, `expired` | Pending |
| `ca_capacity_exceeded` | 409 | `ca_capacity_exceeded` | Pending |
| `ca_key_unavailable` | 409 | `ca_key_unavailable` | Pending, with an alarm |
| `issuance_revoked` | 409 | `certificate_revoked`, `ca_revoked` | Failed |
| `issuance_expired` | 409 | `result_expiring`, `inventory_expired`, `issuance_expired` | Failed |
| `conflict` | 409 | `idempotency_key_reused` | Failed |
| `issuance_rate_limited` | 429 | `grant_hour`, `grant_day`, `ca_hour`, with `retryAfterSeconds` | Pending, honors `Retry-After` |
| `service_unavailable` | 503 | `kms_access_denied` or none. Also a commit that stayed in conflict or could not be confirmed | Pending |

`issuance_denied` is a policy decision: retrying the same request fails the same way. Use the administrator [evaluate route](admin-pki.md#evaluate-a-grant) to see which rule applies.
