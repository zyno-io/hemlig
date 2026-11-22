---
title: "Administrator PKI routes"
description: "CA lifecycle, CRL download and publication, and root CRL upload on the administrator API."
pageType: reference
---

# Administrator PKI routes

These routes create and manage PKI CAs, serve their CRLs and take root CRL uploads. All need an OIDC bearer token.

For the concepts see [PKI](../../guide/pki.md). Issuance routes are not available yet.

**Audit.** A mutation writes one `succeeded` event, or a `failed` event with its reason code. A read writes one `succeeded` event with `permission: read`. Keys, CSRs, certificates and CRLs never appear in audit events.

## Routes

Every mutation needs an `Idempotency-Key`. `PUT` and `DELETE` also need `If-Match` with the CA's `version`. A role of `ca-admin` or `operator` is enforced only when the matching [role setting](../configuration.md) is set.

| Method and path                               | Operation                    | Role     | Request                                                             | Success                                                   |
| --------------------------------------------- | ---------------------------- | -------- | ------------------------------------------------------------------- | --------------------------------------------------------- |
| `GET /v1/admin/pki/cas`                       | `pki.ca.list`                | read     | `environment` (required), `cursor`                                  | `200`, up to 100 CAs                                      |
| `POST /v1/admin/pki/cas`                      | `pki.ca.create`              | ca-admin | CA request body                                                     | `201`, CA detail with `csrPem`, `ETag`                    |
| `GET /v1/admin/pki/cas/{caId}`                | `pki.ca.get`                 | read     |                                                                     | `200`, CA detail, `ETag`                                  |
| `PUT /v1/admin/pki/cas/{caId}`                | `pki.ca.update`              | ca-admin | `displayName`, `policy`                                             | `200`, CA detail                                          |
| `DELETE /v1/admin/pki/cas/{caId}`             | `pki.ca.delete`              | ca-admin |                                                                     | `200`, the `FAILED` CA                                    |
| `POST /v1/admin/pki/cas/{caId}/certificate`   | `pki.ca.activate`            | ca-admin | `certificatePem`, `chainPem`, `rootCrl`, `acceptBroaderConstraints` | `200`, CA detail                                          |
| `POST /v1/admin/pki/cas/{caId}/retire`        | `pki.ca.retire`              | ca-admin | none                                                                | `200`, CA detail, `warnings` when grants reference the CA |
| `POST /v1/admin/pki/cas/{caId}/destroy-key`   | `pki.ca.destroy-key`         | ca-admin | none                                                                | `200`, CA detail                                          |
| `POST /v1/admin/pki/cas/{caId}/crl`           | `pki.crl.publish`            | operator | none                                                                | `200`, `{caId, crl}`                                      |
| `GET /v1/admin/pki/crls/{id}`                 | `pki.crl.get`                | read     | `If-None-Match`                                                     | `200` DER or `304`                                        |
| `GET /v1/admin/pki/external-cas`              | `pki.external-ca.list`       | read     | `cursor`                                                            | `200`, up to 100 external CAs                             |
| `GET /v1/admin/pki/external-cas/{extId}`      | `pki.external-ca.get`        | read     |                                                                     | `200`, external CA, `ETag`                                |
| `POST /v1/admin/pki/external-cas/{extId}/crl` | `pki.external-ca.upload-crl` | ca-admin | `crl`                                                               | `200`, `{extId, crl, changed, revokedCaIds}`              |

`caId` is `ca-` plus lowercase letters, digits and hyphens. `extId` is `ext-` plus 40 hex digits, taken from the root's public key. The `id` of a CRL route is either.

## Create a CA

The request body fields:

| Field                  | Required | Default        | Description                                                                                                                                |
| ---------------------- | -------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `environment`          | Yes      |                | An existing environment                                                                                                                    |
| `name`                 | Yes      |                | 3 to 64 lowercase letters, digits and hyphens, starting with a letter. Unique per environment                                              |
| `kind`                 | Yes      |                | Only `EXTERNAL_INTERMEDIATE`                                                                                                               |
| `keyAlgorithm`         | Yes      |                | `ECDSA_P256`, `ECDSA_P384`, `RSA_3072`, `RSA_4096` or `ED25519`                                                                            |
| `subject`              | Yes      |                | `commonName` (required), `organization`, `organizationalUnit`, `country`, `locality`, `state`. Printable ASCII only                        |
| `requestedConstraints` | No       | none           | `nameConstraints` (`permitted` and `excluded`, each with `dns`, `ip` and `uri` lists) and `extendedKeyUsages` (`serverAuth`, `clientAuth`) |
| `policy`               | No       | defaults below | See the policy table                                                                                                                       |
| `crl.validitySeconds`  | No       | `604800`       | Same as `policy.crlValiditySeconds`; if both are sent they must match                                                                      |
| `displayName`          | No       | none           | Up to 128 characters                                                                                                                       |

Unknown fields are refused with `unknown_field`. A DNS or URI base is a host with an optional leading dot. An IP base is a CIDR with zeroed host bits.

The policy fields (all optional; the update route keeps the stored value for omitted ones):

| Field                    | Default                                                | Range                    |
| ------------------------ | ------------------------------------------------------ | ------------------------ |
| `maxLeafLifetimeSeconds` | 7,776,000 (90 days)                                    | 300 to 34,300,800        |
| `leafKeyAlgorithms`      | ECDSA P-256, ECDSA P-384, Ed25519 and RSA 2048 to 4096 | A non-empty, unique list |
| `capacity`               | 8,000                                                  | 1 to 12,000              |
| `issuancePerHour`        | 2,000                                                  | 1 to 6,000               |
| `crlValiditySeconds`     | 604,800                                                | 3,600 to 2,592,000       |

`capacity + 2 x issuancePerHour` must not exceed 12,000 (`ca_issuance_budget_exceeded`). Ed25519 CA keys add an `ed25519_compatibility` warning to the response.

## CA detail

The response never includes the wrapped key. Beyond the summary fields it returns:

| Field                                                         | Description                                                                                                                        |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `key`                                                         | `custody`, `algorithm`, `spkiSha256`, `state` (`ACTIVE`, `DISABLED`, `DESTROYED`)                                                  |
| `subject`, `subjectDn`                                        | The subject, and its DN in encoded order                                                                                           |
| `requestedConstraints`, `effectiveConstraints`                | What you asked for, and what the signed certificate allows                                                                         |
| `csrPem`, `certificatePem`, `chainPem`, `serial`, `notBefore` | CSR and certificate material, all public                                                                                           |
| `parent`, `crlIssuers`                                        | The external root, and the CRL slots for this CA's leaves                                                                          |
| `policy`, `maxIssueLifetimeEverSeconds`                       | The policy, and the longest leaf lifetime it ever allowed                                                                          |
| `drained`, `drainAt`                                          | Retired CAs: the drain point and whether it has passed with a covering CRL                                                         |
| `crl`                                                         | `number`, `thisUpdate`, `nextUpdate`, `entryCount`, `sha256`, `revision`, `pendingRevocations` (an integer), `dirtySince`, `state` |
| `rootCrl`                                                     | `extId`, `state` (`MISSING`, `CURRENT`, `STALE`), `numberHex`, `thisUpdate`, `nextUpdate`                                          |

The `ETag` is the CA's `version`, without quotes. `If-Match` and `If-None-Match` accept quoted and weak forms.

## Replay and concurrency

A retry with the same `Idempotency-Key` and the same request returns the original status (`201` for create, otherwise `200`) and the current resource. The same key with a different request is `409 conflict`. A request whose `If-Match` is stale returns `412 precondition_failed`.

Lifecycle `POST` routes take no `If-Match`: they act on the version they loaded and re-read once when they lose a race. Request bodies over 1 MiB are `400 body_too_large`.

## Download a CRL

`GET /v1/admin/pki/crls/{id}` returns the DER CRL (`application/pkix-crl`) with the SHA-256 as `ETag` and `Cache-Control: no-store`. Send `If-None-Match` to get `304` when it is unchanged. A CA or root with no CRL yet is `404`.

## Upload a root CRL

The CRL is PEM or base64 DER, at most 512 KiB. A CRL identical to the stored one returns `changed: false`. A lower or equal number, or an earlier `thisUpdate`, is `409 crl_not_newer`. Dependent CAs the CRL lists are revoked first, and their IDs return in `revokedCaIds`.

## Errors

Every error carries `error.details.reason`. The codes are in [Errors](errors.md).

| Code                          | Status | `details.reason`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `chain_invalid`               | 400    | `certificate_malformed`, `chain_malformed`, `certificate_multiple_blocks`, `chain_multiple_blocks`, `root_not_self_signed`, `root_signature_invalid`, `root_not_valid`, `root_not_ca`, `root_key_usage`, `root_missing_ski`, `root_path_len`, `issuer_mismatch`, `signature_invalid`, `missing_aki`, `aki_mismatch`, `spki_mismatch`, `not_ca`, `key_usage`, `not_yet_valid`, `validity_too_short`, `subject_mismatch`, `constraints_broader`, `unsupported_name_constraint`, `policy_extension_present`, `unrecognized_critical_extension`, `identity_root_reserved`, `external_ca_mismatch` and the other chain checks |
| `crl_invalid`                 | 400    | `malformed`, `too_large`, `not_v2`, `missing_crl_number`, `crl_number_too_large`, `issuer_mismatch`, `bad_signature`, `issuer_cannot_sign_crl`, `missing_aki`, `aki_mismatch`, `this_update_in_future`, `missing_next_update`, `expired`, `invalid_validity`, `validity_too_long`, `issuing_distribution_point`, `delta_crl`, `remove_from_crl`, `indirect_crl`, `unrecognized_critical_extension`, `multiple_crls`, `upload_first`                                                                                                                                                                                      |
| `ca_not_active`               | 409    | `pending_certificate`, `retired`, `revoked`, `failed`, `revoked_by_parent`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `ca_subject_in_use`           | 409    | `subject_claimed`, `root_subject_claimed`, `identity_root_reserved`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `crl_not_newer`               | 409    | `crl_not_newer`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ca_issuance_budget_exceeded` | 409    | `ca_issuance_budget_exceeded`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ca_key_unavailable`          | 409    | `ca_key_unavailable`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `conflict`                    | 409    | `name_in_use`, `ca_not_pending`, `key_not_disabled`, `key_destroyed`, `ca_limit_reached`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `bad_request`                 | 400    | `kind_not_supported`, `invalid_name_constraint`, `reserved_name`, `invalid_policy`, `body_too_large`, `unknown_field`, and the restricted-subject reasons                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `not_found`                   | 404    | `ca_not_found`, `external_ca_not_found`, `crl_missing`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `forbidden`                   | 403    | `pki_role_required`, with `details.role`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `service_unavailable`         | 503    | `crl_publication_busy` (with `Retry-After: 30`), `kms_access_denied`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
