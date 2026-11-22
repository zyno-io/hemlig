---
title: Errors
description: Every Hemlig API error code with its HTTP status, meaning and what to do about it.
pageType: reference
---

# Errors

Every failure from a Hemlig handler uses one envelope with a stable `code`. Match on `code`, not on `message`.

```json
{
  "error": {
    "code": "precondition_failed",
    "message": "If-Match does not name the current control revision.",
    "correlationId": "01J..."
  }
}
```

An error may also carry an optional `error.details` object of safe, non-secret string, number or boolean fields (for example a stable `reason`). Treat unknown fields as additive; match on `code` first.

Quote the `correlationId` when you report a problem. It finds the request's [audit events](audit.md) and Lambda logs. For `500` responses the message is deliberately generic.

## Error codes

| Code | Status | Meaning | Action |
| --- | --- | --- | --- |
| `bad_request` | 400 | Invalid JSON, path, query, header, ID, ACL, payload, or a missing required header | Fix the request. Do not retry unchanged. |
| `invalid_csr` | 400 | A self-rotation CSR is malformed, too weak, too large or reuses the caller's key | Generate a new RSA key of at least 2048 bits and a new CSR |
| `forbidden` | 403 | The token or certificate is accepted but not permitted: no grant or ACL, wrong environment, or an invalid bootstrap token | Check the grant or ACL, or request a new bootstrap token |
| `identity_not_active` | 403 | The client certificate is unknown, revoked or outside its validity | Re-enroll, or use a certificate that is `ACTIVE` |
| `not_found` | 404 | The secret, consumer, grant, issuing root or active payload does not exist | Check the ID and `environment`. A secret with no payload also returns this on payload reads. |
| `conflict` | 409 | A used idempotency key, an unavailable revision lease, a duplicate or full registry, or an agent ACL change | Read the current state before acting. Do not mint a new key just to bypass it. |
| `enrollment_failed` | 409 | Terminal truststore publication failure for this enrollment | Do not retry. Repair the issuer or truststore, then enroll with a new key. |
| `identity_limit_reached` | 409 | Self-rotation would exceed 3 active certificates | Revoke an unused certificate, then rotate |
| `identity_already_rotated` | 409 | The calling certificate already has an active successor | Use the successor |
| `identity_rotation_conflict` | 409 | A concurrent rotation for the consumer committed first | Retry with the same CSR and `Idempotency-Key` |
| `rotation_replay_inactive` | 409 | A replay names a certificate that is no longer active | Submit a new rotation request |
| `chain_invalid` | 400 | A CA activation chain failed verification. `error.details.reason` names the check | Read the reason in [Admin: PKI](admin-pki.md#errors) and fix the certificate or chain |
| `crl_invalid` | 400 | An uploaded or supplied root CRL failed verification. `error.details.reason` names the check | Read the reason in [Admin: PKI](admin-pki.md#errors) |
| `crl_not_newer` | 409 | The uploaded root CRL is not newer than the stored one | Issue a newer CRL from the root |
| `ca_not_active` | 409 | The CA is not in a state the operation needs, or its parent revoked it. `details.reason` says which | Read the CA's `status` first |
| `ca_subject_in_use` | 409 | The CA subject DN is already claimed | Choose a new DN |
| `ca_key_unavailable` | 409 | The CA key cannot be used to sign | Check the CA's `key.state` and KMS access |
| `ca_issuance_budget_exceeded` | 409 | `capacity + 2 x issuancePerHour` is over 12,000 | Lower the capacity or the rate |
| `precondition_failed` | 412 | `If-Match` is not the current control revision | Read the current revision, reconcile, then retry with its ETag. Never retry blindly. |
| `sync_reset_required` | 410 | The sync token is no longer valid | Discard it and start a new snapshot |
| `internal_error` | 500 | Unexpected failure; details withheld | Retry later; report the `correlationId` if it persists |
| `service_unavailable` | 503 | Storage or KMS availability or consistency failure | Retry with backoff |
| `sync_index_not_ready` | 503 | The agent sync index has not finished its backfill | Wait for the operator backfill; see [Upgrades](../../operations/upgrades.md) |
| `sync_backfill_incomplete` | 503 | A secret's current control revision was unavailable while the sync index was being backfilled | Re-run the backfill; see [Upgrades](../../operations/upgrades.md) |

`internal_error` is the fallback for any error that is not one of the typed codes. The sync codes are raised by the sync service and backfill rather than the shared error helpers.

PKI administration also uses `bad_request`, `forbidden` (reason `pki_role_required`), `not_found`, `conflict` and `service_unavailable` with a `details.reason`. The full list of reasons is in [Admin: PKI](admin-pki.md#errors).

## Errors outside the envelope

API Gateway can reject a request before Hemlig runs, so the body is not this envelope.

| Status | Cause |
| --- | --- |
| 401 | Administrator API: the JWT is missing, invalid, expired, or has the wrong issuer or audience. Get a fresh token. |
| 403 | Administrator API: the token is valid but lacks a required scope (API Gateway). The Lambda also returns `403` for a failed role or configuration check |

An untrusted or expired client certificate fails the TLS handshake at API Gateway, so no HTTP response arrives. A revoked or unknown fingerprint gets `403 identity_not_active` with a Hemlig error body from the Lambda. A `403` that uses the envelope means Hemlig itself rejected an already-accepted request. See [Identity provider](../../guide/identity-provider.md) for token requirements.

For CLI exit codes see [CLI](../../guide/cli.md#exit-codes).
