---
title: "Administrator PKI routes"
description: "CA lifecycle, CRLs, issuance grants, administrator issuance, certificate inventory and revocation on the administrator API."
pageType: reference
---

# Administrator PKI routes

These routes create and manage PKI CAs, serve their CRLs, take root CRL uploads, manage issuance grants, issue certificates, list the inventory and revoke. All need an OIDC bearer token.

For the concepts see [PKI](../../guide/pki.md). Consumers issue through the [consumer routes](pki.md).

**Audit.** A mutation writes one `succeeded` event, or a `failed` event with its reason code. A read writes one `succeeded` event with `permission: read`. Keys, CSRs, certificates and CRLs never appear in audit events.

## Routes

Every mutation needs an `Idempotency-Key`, except a grant `validateOnly` call. `PUT` and `DELETE` also need `If-Match` with the resource's `version`. A role of `ca-admin` or `operator` is enforced only when the matching [role setting](../configuration.md) is set. Every `GET` and `evaluate` is `read`; grant writes, administrator issuance, revoke and bulk revoke are `operator`.

| Method and path                               | Operation                    | Role     | Request                                                             | Success                                                   |
| --------------------------------------------- | ---------------------------- | -------- | ------------------------------------------------------------------- | --------------------------------------------------------- |
| `GET /v1/admin/pki/cas`                       | `pki.ca.list`                | read     | `environment` (required), `cursor`                                  | `200`, up to 100 CAs                                      |
| `POST /v1/admin/pki/cas`                      | `pki.ca.create`              | ca-admin | CA request body                                                     | `201`, CA detail with `csrPem` (external kind only), `ETag`, `warnings` |
| `GET /v1/admin/pki/cas/{caId}`                | `pki.ca.get`                 | read     |                                                                     | `200`, CA detail, `ETag`                                  |
| `PUT /v1/admin/pki/cas/{caId}`                | `pki.ca.update`              | ca-admin | `displayName`, `policy`                                             | `200`, CA detail                                          |
| `DELETE /v1/admin/pki/cas/{caId}`             | `pki.ca.delete`              | ca-admin |                                                                     | `200`, the `FAILED` CA                                    |
| `POST /v1/admin/pki/cas/{caId}/certificate`   | `pki.ca.activate`            | ca-admin | `certificatePem`, `chainPem`, `rootCrl`, `acceptBroaderConstraints` | `200`, CA detail                                          |
| `POST /v1/admin/pki/cas/{caId}/retire`        | `pki.ca.retire`              | ca-admin | none                                                                | `200`, CA detail, `warnings` when grants reference the CA |
| `POST /v1/admin/pki/cas/{caId}/destroy-key`   | `pki.ca.destroy-key`         | ca-admin | none                                                                | `200`, CA detail                                          |
| `POST /v1/admin/pki/cas/{caId}/revoke` | `pki.ca.revoke` | ca-admin | `reason`, `invalidityDate` | `200`, `{ca, changed, crlEntry, crlPublished, crlNumber, revokedCaIds, complete}`, `ETag` |
| `POST /v1/admin/pki/cas/{caId}/crl`           | `pki.crl.publish`            | operator | none                                                                | `200`, `{caId, crl}`                                      |
| `GET /v1/admin/pki/crls/{id}`                 | `pki.crl.get`                | read     | `If-None-Match`                                                     | `200` DER or `304`                                        |
| `GET /v1/admin/pki/external-cas`              | `pki.external-ca.list`       | read     | `cursor`                                                            | `200`, up to 100 external CAs                             |
| `GET /v1/admin/pki/external-cas/{extId}`      | `pki.external-ca.get`        | read     |                                                                     | `200`, external CA, `ETag`                                |
| `POST /v1/admin/pki/external-cas/{extId}/crl` | `pki.external-ca.upload-crl` | ca-admin | `crl`                                                               | `200`, `{extId, crl, changed, revokedCaIds}`              |
| `GET /v1/admin/pki/cas/{caId}/issuance-grants` | `pki.grant.list` | read | `cursor` | `200`, up to 100 live grants |
| `GET /v1/admin/pki/consumers/{consumerId}/issuance-grants` | `pki.grant.list` | read | `includeDeleted`, `cursor` | `200`, up to 100 grants |
| `POST /v1/admin/pki/consumers/{consumerId}/issuance-grants` | `pki.grant.create` | operator | Grant body; `Idempotency-Key`, not with `?validateOnly=true` | `201`, the grant, `ETag`; or `200`, validation result |
| `GET /v1/admin/pki/consumers/{consumerId}/issuance-grants/{name}` | `pki.grant.get` | read | | `200`, the grant (a tombstone too), `ETag` |
| `PUT /v1/admin/pki/consumers/{consumerId}/issuance-grants/{name}` | `pki.grant.update` | operator | Grant body; `If-Match` always; `Idempotency-Key` unless `validateOnly` | `200`, the grant, `ETag`; or `200`, validation result |
| `DELETE /v1/admin/pki/consumers/{consumerId}/issuance-grants/{name}` | `pki.grant.delete` | operator | `If-Match` | `200`, the `DELETED` grant |
| `POST /v1/admin/pki/consumers/{consumerId}/issuance-grants/{name}/evaluate` | `pki.grant.evaluate` | read | Evaluate body | `200`, decision, trace, plan |
| `GET /v1/admin/pki/cas/{caId}/certificates` | `pki.certificate.list` | read | `status`, `expiringBefore`, `cursor` | `200`, up to 100 certificates |
| `POST /v1/admin/pki/cas/{caId}/certificates` | `pki.certificate.issue` | operator | Issue body | `201`, the certificate |
| `GET /v1/admin/pki/cas/{caId}/certificates/{serial}` | `pki.certificate.get` | read | | `200`, certificate detail |
| `POST /v1/admin/pki/cas/{caId}/certificates/{serial}/revoke` | `pki.certificate.revoke` | operator | `reason`, `invalidityDate` | `200`, certificate and CRL outcome |
| `GET /v1/admin/pki/consumers/{consumerId}/certificates` | `pki.certificate.list` | read | `issuanceGrant`, `includeExpired`, `cursor` | `200`, up to 100 certificates, newest first |
| `POST /v1/admin/pki/consumers/{consumerId}/certificates/revoke` | `pki.certificate.revoke` | operator | `reason`, `invalidityDate`, `issuanceGrant`, `issuanceGrantUid` | `200`, progress or result |

`caId` is `ca-` plus lowercase letters, digits and hyphens. `extId` is `ext-` plus 40 hex digits, taken from the root's public key. The `id` of a CRL route is either. `consumerId` and grant `name` are 3 to 64 lowercase letters, digits and hyphens, starting with a letter. `serial` is 2 to 40 lowercase hex digits.

A grant or certificate route audits `consumerId`, or `caId` and `serial`, as its target, never the CA ID of the other kind.

## Create a CA

The request body fields:

| Field                  | Required | Default        | Description                                                                                                                                |
| ---------------------- | -------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `environment`          | Yes      |                | An existing environment                                                                                                                    |
| `name`                 | Yes      |                | 3 to 64 lowercase letters, digits and hyphens, starting with a letter. Unique per environment                                              |
| `kind`                 | Yes      |                | `EXTERNAL_INTERMEDIATE`, `ROOT` or `INTERMEDIATE`. A `ROOT` or `INTERMEDIATE` is `ACTIVE` at once and the response has no `csrPem`        |
| `parentCaId` | `INTERMEDIATE` | | `ca-` ID of an `ACTIVE` `ROOT` in the same environment. Refused for other kinds (`parent_not_allowed`), and required for an intermediate (`parent_required`) |
| `validitySeconds` | No | 315,360,000 (`ROOT`), 31,536,000 (`INTERMEDIATE`) | `ROOT` 7,776,000 to 630,720,000; `INTERMEDIATE` 2,592,000 to 630,720,000. Refused for the external kind (`validity_not_allowed`). An intermediate's is clamped to its root's remaining validity |
| `keyAlgorithm`         | Yes      |                | `ECDSA_P256`, `ECDSA_P384`, `RSA_3072`, `RSA_4096` or `ED25519`                                                                            |
| `subject`              | Yes      |                | `commonName` (required), `organization`, `organizationalUnit`, `country`, `locality`, `state`. Printable ASCII only                        |
| `requestedConstraints` | No       | none           | `nameConstraints` (`permitted` and `excluded`, each with `dns`, `ip` and `uri` lists) and `extendedKeyUsages` (`serverAuth`, `clientAuth`) |
| `policy`               | No       | defaults below | See the policy table                                                                                                                       |
| `crl.validitySeconds`  | No       | `604800`       | Same as `policy.crlValiditySeconds`; if both are sent they must match                                                                      |
| `displayName`          | No       | none           | Up to 128 characters                                                                                                                       |

Unknown fields are refused with `unknown_field`. On update, an omitted `displayName` keeps the stored one and `null` clears it. A DNS or URI base is a host with an optional leading dot. An IP base is a CIDR with zeroed host bits.

The policy fields (all optional; the update route keeps the stored value for omitted ones):

| Field                    | Default                                                | Range                    |
| ------------------------ | ------------------------------------------------------ | ------------------------ |
| `maxLeafLifetimeSeconds` | 7,776,000 (90 days)                                    | 300 to 34,300,800        |
| `leafKeyAlgorithms`      | ECDSA P-256, ECDSA P-384, Ed25519 and RSA 2048 to 4096 | A non-empty, unique list |
| `capacity`               | 8,000                                                  | 1 to 12,000              |
| `issuancePerHour`        | 2,000                                                  | 1 to 6,000               |
| `crlValiditySeconds`     | 604,800                                                | 3,600 to 2,592,000       |

`capacity + 2 x issuancePerHour` must not exceed 12,000 (`ca_issuance_budget_exceeded`). Ed25519 CA keys add an `ed25519_compatibility` warning to the response.

A `ROOT` issues no leaves: `policy.maxLeafLifetimeSeconds` and `policy.leafKeyAlgorithms` are refused with `400 invalid_policy`, on create and on update (when they differ from the stored values). Its `issueLeaves` is `false` and its `issueSubordinates` is `true`. Every `ROOT` create adds a warning with code `external_root_recommended` and this message, exactly:

> An external offline root is strongly recommended: this ROOT's key is WRAPPED and online, so a compromised PKI role can copy it, and local distrust only reaches relying parties that use Hemlig trust bundles.

## CA detail

The response never includes the wrapped key. Beyond the summary fields it returns:

| Field                                                         | Description                                                                                                                        |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `key`                                                         | `custody`, `algorithm`, `spkiSha256`, `state` (`ACTIVE`, `DISABLED`, `DESTROYED`)                                                  |
| `subject`, `subjectDn`                                        | The subject, and its DN in encoded order                                                                                           |
| `requestedConstraints`, `effectiveConstraints`                | What you asked for, and what the signed certificate allows                                                                         |
| `csrPem`, `certificatePem`, `chainPem`, `serial`, `notBefore` | CSR and certificate material, all public                                                                                           |
| `parent`, `crlIssuers`                                        | The external root, and the CRL slots for this CA's leaves                                                                          |
| `parentCaId` | An `INTERMEDIATE` only: the Hemlig root. Its `parent` is `{type: "ca", id}` and its `crlIssuers` list itself, then the root. A `ROOT` has no parent, its `crlIssuers` list only itself, and its `chainPem` equals its `certificatePem` |
| `policy`, `maxIssueLifetimeEverSeconds`                       | The policy, and the longest leaf lifetime it ever allowed                                                                          |
| `maxIssueLifetimeEverSeconds` (`ROOT`) | For a `ROOT`, the longest intermediate lifetime it ever signed. It starts at 0, only grows, and decides when a retired root drains |
| `drained`, `drainAt`                                          | Retired CAs: the drain point and whether it has passed with a covering CRL                                                         |
| `capacity`                                                    | `count` (every certificate with `notAfter` after `countFrom`, any status), `capacity`, `issuancePerHour`, `countFrom`, `countedAt`. `count` is absent until the first count |
| `crl`                                                         | `number`, `thisUpdate`, `nextUpdate`, `entryCount`, `sha256`, `revision`, `pendingRevocations` (an integer), `dirtySince`, `state` |
| `rootCrl`                                                     | `extId`, `state` (`MISSING`, `CURRENT`, `STALE`), `numberHex`, `thisUpdate`, `nextUpdate`                                          |

The `ETag` is the CA's `version`, without quotes. `If-Match` and `If-None-Match` accept quoted and weak forms.

## Issuance grants

An issuance grant is bound to one consumer and one CA. It says which names, subject attributes, key algorithms, usages and lifetimes that consumer may get. Everything is deny by default: an empty `allow` permits nothing. A grant has no CA section, so consumers can never obtain CA certificates.

```json
{
  "name": "web",
  "caId": "ca-0a1b2c3d",
  "displayName": "payments web certificates",
  "names": {
    "dns": {
      "allow": ["**.payments.svc.cluster.local", "*.payments.example.com"],
      "deny": ["internal.payments.example.com"],
      "allowWildcardNames": false
    },
    "ip": { "allow": ["10.20.0.0/16"] },
    "uri": { "allow": ["spiffe://prod.example.com/ns/payments/**"] },
    "commonName": { "mode": "san", "addToSans": true },
    "maxSans": 50
  },
  "subject": { "allow": { "organizationalUnit": ["payments-*"] } },
  "keyAlgorithms": ["ECDSA_P256", "ECDSA_P384", "RSA_2048", "RSA_3072"],
  "keyUsages": ["digitalSignature", "keyEncipherment"],
  "extendedKeyUsages": {
    "allow": ["serverAuth", "clientAuth"],
    "default": ["serverAuth", "clientAuth"]
  },
  "lifetime": { "defaultSeconds": 7776000, "maxSeconds": 7776000, "minSeconds": 3600 },
  "forced": {
    "subject": { "organization": "Example Corp", "country": "US" },
    "sans": { "uri": ["spiffe://prod.example.com/cluster/prod-a"] },
    "certificatePolicies": ["1.3.6.1.4.1.55555.1.1"]
  },
  "quotas": { "perHour": 100, "perDay": 1000 },
  "expiresAt": "2027-12-31T00:00:00Z"
}
```

| Field | Required | Description |
| --- | --- | --- |
| `name` | On create | Unique per consumer. On `PUT` it may be present but must equal the path |
| `caId` | Yes | The CA that signs. It must be `ACTIVE`, allow leaves and be in the consumer's environment. A `PUT` can move a grant to another CA |
| `displayName` | No | Up to 128 characters. Omitted on `PUT` clears it |
| `status` | No | `ACTIVE` (default) or `DISABLED`. `DELETED` is refused. An absent `status` on `PUT` keeps the current one |
| `expiresAt` | No | A future time. After it the grant is `expired` and issuance fails with `grant_expired` |
| `names`, `keyUsages`, `extendedKeyUsages`, `lifetime` | Yes | The policy |
| `subject`, `keyAlgorithms`, `forced`, `quotas` | No | See the table below |

Any other top-level key is `400 unknown_field`.

| Policy field | Notes |
| --- | --- |
| `names.dns`, `names.ip`, `names.uri` | `allow` and `deny` rule lists. DNS rules are exact names, `*.` (one label) or `**.` (any depth). `allowWildcardNames` permits wildcard SANs. IP rules are CIDRs. URI rules are `scheme://host[/path]`, where a trailing `/**` matches any path below |
| `names.commonName` | `mode` is `san` (a CN must equal an allowed SAN) or `forbid`. `addToSans` adds the CN to the SANs |
| `names.maxSans` | 1 to 100 |
| `subject.allow` | Glob patterns per attribute: `country`, `state`, `locality`, `organization`, `organizationalUnit` |
| `keyAlgorithms` | Default: ECDSA P-256 and P-384, RSA 2048 to 8192. Ed25519 and P-521 must be listed. Must be a subset of the CA's `leafKeyAlgorithms` |
| `keyUsages`, `extendedKeyUsages` | `digitalSignature`, `keyEncipherment`. `serverAuth`, `clientAuth`. `default` applies when a request names none. A CA EKU constraint also applies |
| `lifetime` | `300 <= minSeconds <= defaultSeconds <= maxSeconds <= the CA maximum` (at most 397 days). `minSeconds` defaults to 3,600 |
| `forced` | Subject attributes, SANs and certificate policy OIDs added to every certificate. An administrator sets them, so they bypass the name allowlists but not the CA's name constraints or the reserved names |
| `quotas` | `perHour` default 100, `perDay` default 1,000 |

The grant's `policy` view holds the normalized policy. `policyDigest` is `sha256` of its canonical JSON and is audited. `version` (`pkv-...`) is the `ETag`.

The view also has `uid` (`pkg-...`), `environment`, `status`, `expired`, `quotas` (resolved), `createdAt`, `createdBy`, `updatedAt` and `updatedBy`. A deleted grant is a tombstone: `status: DELETED`, `deletedAt`, `deletedBy`. It keeps its `uid` and policy. Creating the name again makes a new `uid`, so old certificates never point at a different policy.

### Validation

Create and update validate before they write, with a `400` and `reason: invalid_grant_policy` on the first error (`details.code`, `details.path`, `details.errorCount`). A canonical policy over 32 KiB is `400 policy_too_large`.

| Check | Result |
| --- | --- |
| Consumer has an AgentGrant (any status, so grants can be created before bootstrap), or is an `ACTIVE` direct consumer | `404 consumer_not_found`, `409 consumer_not_active` |
| CA exists, is `ACTIVE`, allows leaves | `404 ca_not_found`, `409 ca_not_active` with the status reason or `leaves_not_permitted` |
| CA environment equals the consumer's | `400 environment_mismatch` |
| Every rule parses and uses no reserved name | error |
| A rule entirely outside the CA's name constraints | error. A partial overlap is a warning |
| Forced SANs satisfy the CA constraints and the reserved names | error |
| Key algorithms, usages, EKUs and lifetimes fit the CA policy | error |
| Resolved `perHour` above the CA's `issuancePerHour` | warning `quota_exceeds_ca_rate` |
| 20 live grants already exist for the consumer | `409 grant_limit_reached` (best effort under concurrent creates) |

A create that finds the name taken is `409 grant_exists`. An update that only disables a grant still needs its CA `ACTIVE`. `DELETE` has no such condition.

### Validate only

`POST` and `PUT` with `?validateOnly=true` run the same validation and write nothing. They need no `Idempotency-Key`. `PUT` still needs `If-Match`. The response is `200`:

```json
{ "valid": false, "errors": [{ "code": "invalid_rule", "path": "policy.names.dns.allow[0]", "message": "..." }], "warnings": [], "policyDigest": "..." }
```

`policyDigest` is present when the policy parsed. The call writes one read audit event under the operation `pki.grant.validate`. The CLI's `pki grant migrate --dry-run` uses it.

### List, read, update and delete

- `GET .../consumers/{consumerId}/issuance-grants` lists grants in name order, up to 100 per page. `includeDeleted=true` adds tombstones.
- `GET .../cas/{caId}/issuance-grants` lists the live grants that name a CA, across consumers. Use it to check that a CA is unreferenced before you retire it.
- A `PUT` replaces the whole grant. A stale `If-Match` is `412 precondition_failed`. A grant that was deleted is `404 grant_not_found`.
- `DELETE` returns the tombstone. It cannot be undone, and the grant leaves the CA's list.

## Evaluate a grant

`POST .../issuance-grants/{name}/evaluate` dry-runs a request against a grant and writes only a read audit event (`decision`, `reasonCode`). Disabled and expired grants still evaluate, a deleted one is `404`. The CA must have a certificate.

Send either a CSR, or a key algorithm with names. Mixing them is `400 evaluate_input`.

```json
{
  "keyAlgorithm": "ECDSA_P256",
  "sans": { "dns": ["web.payments.example.com"] },
  "commonName": "web.payments.example.com",
  "durationSeconds": 3600,
  "usages": ["digitalSignature", "serverAuth"]
}
```

| Field | Description |
| --- | --- |
| `certificateSigningRequestPem` | A CSR. With it, `sans`, `commonName`, `subject` and `keyAlgorithm` are refused |
| `keyAlgorithm`, `sans`, `commonName`, `subject` | A synthetic request. `sans` has `dns`, `ip` and `uri` lists of at most 100 |
| `durationSeconds`, `usages`, `isCA` | As on issuance |

The response is `200`:

| Field | Description |
| --- | --- |
| `decision` | `allow` or `deny` |
| `denial` | On `deny`: `reason`, `detail`, and `deniedNameType` and `deniedName` when a name caused it |
| `trace` | The engine steps in order, ending with the CSR step. Each has `step`, `name` and `outcome` |
| `plan` | On `allow`: `keyAlgorithm`, `sans`, `subject` (as a DN), `keyUsages`, `extendedKeyUsages`, `certificatePolicies`, `notBefore`, `notAfter`, `lifetimeClamped`, `sanCritical` |
| `context` | `grant` (`status`, `expired`), `ca` (`status`, `keyState`), `capacity` (`count`, `capacity`, `countedAt`) and `quotas` (`grantHour`, `grantDay`, `caHour`, each `count` and `limit`) |

`context.capacity` is the stored count. Evaluate never recounts, and it consumes no quota.

## Administrator issuance

`POST .../cas/{caId}/certificates` signs a CSR without a grant, for bootstrapping infrastructure and one-off certificates. The CA's constraints, the Hemlig ceilings and the reserved names still apply. It needs the operator role and an `Idempotency-Key`.

| Field | Description |
| --- | --- |
| `certificateSigningRequestPem` | Required, at most 32 KiB |
| `useCsrNames` | `true` takes SANs and subject from the CSR. Without it, names come from `sans` and `subject` and the CSR's own are ignored |
| `sans` | `dns`, `ip`, `uri`, each at most 100 |
| `subject` | `commonName`, `organization`, `organizationalUnit`, `country`, `locality`, `state` |
| `durationSeconds`, `usages`, `isCA` | As on the consumer route. `isCA: true` is denied |

`useCsrNames: true` together with `sans` or `subject` is `400 names_conflict`. The response is `201` with the same body as the [consumer route](pki.md#issue-a-certificate), without `issuanceGrant`. Replay follows the same rules, keyed by the administrator and the key. The quota is 100 certificates per hour per CA for administrators, plus the CA's own hourly rate. Reasons: `admin_hour`, `ca_hour`.

## Certificate inventory

`GET .../cas/{caId}/certificates` lists a CA's certificates in `notAfter` order. `status` filters on the effective status:

| `status` | Selects |
| --- | --- |
| `ISSUED` | Unexpired and not revoked |
| `EXPIRED` | Stored as issued, past `notAfter` |
| `REVOKED` | Stored as revoked |
| (omitted) | All |

`expiringBefore` is an ISO time that limits the list to certificates expiring before it. The inventory reads a secondary index, so a certificate can appear a few seconds late.

`GET .../consumers/{consumerId}/certificates` lists the certificates issued to a consumer, newest first. `issuanceGrant` filters by grant name. Expired certificates are hidden unless `includeExpired=true`.

A summary has:

- `caId`, `serial`, `fingerprint`, `subject`, `sans`, `keyAlgorithm`, `notBefore`, `notAfter`, `issuedAt` and `requester`.
- `storedStatus` (`ISSUED` or `REVOKED`) and the effective `status`: `REVOKED` when stored as revoked, else `CA_REVOKED` when the CA is revoked, else `EXPIRED` after `notAfter`, else `ISSUED`.
- `revocation` (`at`, `reason`, `invalidityDate`, `upgradedAt`) when revoked.

The detail adds `certificatePem`, `spkiSha256`, `keyUsages`, `extendedKeyUsages`, `lifetimeClamped`, `requester.asserted` and `revocation.by`.

## Revoke a certificate

`POST .../certificates/{serial}/revoke` takes an optional body. It needs the operator role and an `Idempotency-Key`.

| Field | Description |
| --- | --- |
| `reason` | `unspecified` (default), `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`. `caCompromise` is `400 invalid_reason` |
| `invalidityDate` | Only with `keyCompromise` (`400 invalidity_date_requires_key_compromise`). Not in the future |

Revocation is one transaction: the certificate, its CRL entry and a CRL revision bump. Revocation is never refused for capacity.

| State | Effect | `crlEntry` |
| --- | --- | --- |
| Issued, unexpired, CA not revoked | Revoked, entry written, CRL published inline | `true` |
| Issued, past `notAfter` | Marked revoked in the inventory only. No entry, no CRL change | `false` |
| Issued, CA `REVOKED` | Marked revoked in the inventory only. The CA's key can no longer sign | `false` |
| Revoked, request is `keyCompromise` and the stored reason differs | Upgraded to `keyCompromise`, with the entry updated when it exists | Whether it exists |
| Revoked otherwise | No change, `changed: false` | Whether it exists |

The response is `200`:

| Field | Description |
| --- | --- |
| `certificate` | The certificate detail |
| `crlEntry` | Whether a CRL entry exists |
| `crlPublished`, `crlNumber` | Whether the CRL was published inline, and its number |
| `changed` | `false` when nothing was written |
| `crl` | `number` and `pendingRevocations` |

Inline publication is bounded to 5 seconds. When it is busy, late or fails, the revoke still succeeds with `crlPublished: false` and the next maintenance pass publishes (within 15 minutes). An unknown serial is `404 certificate_not_found`.

## Revoke a CA

`POST .../cas/{caId}/revoke` revokes a Hemlig `INTERMEDIATE`, or distrusts a Hemlig `ROOT` locally. It needs the CA administrator role and an `Idempotency-Key`. An `EXTERNAL_INTERMEDIATE` is revoked at its offline root instead, and the route answers `409 revoke_at_root`.

| Field | Description |
| --- | --- |
| `reason` | `unspecified` (default), `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`. `keyCompromise` is `400 invalid_reason` |
| `invalidityDate` | Only with `caCompromise` (`400 invalidity_date_requires_ca_compromise`). Not in the future (`400 invalid_invalidity_date`). Refused for a `ROOT` with `400 invalid_invalidity_date`: it applies to an `INTERMEDIATE`, which is listed on its root's CRL |

The response is `200` with the CA's version as `ETag`:

| Field | Description |
| --- | --- |
| `ca` | The CA detail, now `REVOKED` with its key `DISABLED` |
| `changed` | `false` when the CA was already `REVOKED` |
| `crlEntry`, `crlPublished`, `crlNumber` | Whether the root's CRL carries an entry, whether it was published inline, and its number. Always `false` for a `ROOT` |
| `revokedCaIds` | An `INTERMEDIATE`: its own ID when `changed`. A `ROOT`: every child that is `REVOKED` now, sorted |
| `complete` | `true` for an `INTERMEDIATE`. For a `ROOT`, `true` when every child the directory listed is `REVOKED`. The listing is eventually consistent, so a child created just before the revoke may be missing from it; issuance under it is refused regardless, and maintenance finishes it |

| State | Effect | `crlEntry` |
| --- | --- | --- |
| `INTERMEDIATE`, unexpired | `REVOKED`, key disabled, entry on the root's CRL, root CRL published inline | `true` |
| `INTERMEDIATE`, past `notAfter` | `REVOKED` and key disabled only. No entry and no CRL change | `false` |
| `INTERMEDIATE`, parent already `REVOKED` | `REVOKED` and key disabled only. The root's distrust is the evidence | `false` |
| Already `REVOKED` | No change, `changed: false`. There is no reason upgrade | `false` |
| `ROOT` | `REVOKED`, key disabled, then each child is flipped one by one. No CRL exists above a root | `false` |

The `revocationSource` of a revoked CA is `HEMLIG`. Its `revocationEvidence` is `local-distrust` for a root, `parent:<rootId>` for a CA revoke and `ancestor:<rootId>` when the distrust walk flipped it. A root revoke repeats safely: if `complete` is `false`, repeat it with the same `Idempotency-Key`.

`complete` covers the children the directory listed, which is eventually consistent. Issuance under any child is refused regardless, because every issuance and replay checks that no ancestor is `REVOKED`, and maintenance finishes any child the walk missed, including one created just before the revoke, within 15 minutes.

Issuance under a `REVOKED` CA, or under one whose root is `REVOKED`, is `409 ca_not_active`. A replayed issuance is `409 issuance_revoked`, with `ca_revoked` or `ancestor_revoked`. The audit event is `pki.ca.revoke`.

## Revoke a consumer's certificates

`POST .../consumers/{consumerId}/certificates/revoke` revokes every unexpired issued certificate of one consumer, for example after a compromise. It needs the operator role and an `Idempotency-Key`.

| Field | Description |
| --- | --- |
| `reason`, `invalidityDate` | As above |
| `issuanceGrant` | Limit to one grant name |
| `issuanceGrantUid` | Limit to one grant generation |

The run groups certificates by CA and commits them 30 at a time. It is per-certificate idempotent and stops after about 20 seconds. The response is `200`:

```json
{
  "consumerId": "payments-prod",
  "complete": false,
  "revoked": 120,
  "alreadyRevoked": 3,
  "caIds": ["ca-0a1b2c3d"],
  "crls": [{ "caId": "ca-0a1b2c3d", "crlPublished": false }]
}
```

`complete: false` means the time bound hit before the end. Repeat the request with the same `Idempotency-Key` until `complete` is `true`. Each repeat skips the certificates that are already revoked. Only a complete run stores the idempotency record, and one CRL is published per CA after the last batch. The operation is not atomic across batches, so a partial run leaves some certificates revoked. Each run writes its own audit event, with `complete` set.

Also revoke the consumer's client certificates ([Administrator consumers](admin-consumers.md)) if the consumer itself is compromised: this route only touches PKI leaves.

## Replay and concurrency

A retry with the same `Idempotency-Key` and the same request returns the original status (`201` for create, otherwise `200`) and the current resource. The same key with a different request is `409 conflict`. A request whose `If-Match` is stale returns `412 precondition_failed`.

Lifecycle `POST` routes take no `If-Match`: they act on the version they loaded and re-read once when they lose a race. Request bodies over 1 MiB are `400 body_too_large`.

## Download a CRL

`GET /v1/admin/pki/crls/{id}` returns the DER CRL (`application/pkix-crl`) with the SHA-256 as `ETag` and `Cache-Control: no-store`. Send `If-None-Match` to get `304` when it is unchanged. A CA or root with no CRL yet is `404`. The response also carries `Hemlig-Crl-Number`, `Hemlig-Crl-This-Update` and `Hemlig-Crl-Next-Update`, as on the [consumer CRL route](pki.md#crls).

## Upload a root CRL

The CRL is PEM or base64 DER, at most 512 KiB. A CRL identical to the stored one returns `changed: false`. A lower or equal number, or an earlier `thisUpdate`, is `409 crl_not_newer`. Dependent CAs the CRL lists are revoked first, and their IDs return in `revokedCaIds`.

## Errors

Every error carries `error.details.reason`. The codes are in [Errors](errors.md).

| Code                          | Status | `details.reason`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `chain_invalid`               | 400    | `certificate_malformed`, `chain_malformed`, `certificate_multiple_blocks`, `chain_multiple_blocks`, `root_not_self_signed`, `root_signature_invalid`, `root_not_valid`, `root_not_ca`, `root_key_usage`, `root_missing_ski`, `root_path_len`, `issuer_mismatch`, `signature_invalid`, `missing_aki`, `aki_mismatch`, `spki_mismatch`, `not_ca`, `key_usage`, `not_yet_valid`, `validity_too_short`, `subject_mismatch`, `constraints_broader`, `unsupported_name_constraint`, `policy_extension_present`, `unrecognized_critical_extension`, `identity_root_reserved`, `external_ca_mismatch` and the other chain checks |
| `crl_invalid`                 | 400    | `malformed`, `too_large`, `not_v2`, `missing_crl_number`, `crl_number_too_large`, `issuer_mismatch`, `bad_signature`, `issuer_cannot_sign_crl`, `missing_aki`, `aki_mismatch`, `this_update_in_future`, `missing_next_update`, `expired`, `invalid_validity`, `validity_too_long`, `issuing_distribution_point`, `delta_crl`, `remove_from_crl`, `indirect_crl`, `unrecognized_critical_extension`, `multiple_crls`, `upload_first`                                                                                                                                                                                      |
| `ca_not_active`               | 409    | `pending_certificate`, `retired`, `revoked`, `failed`, `revoked_by_parent`, `leaves_not_permitted`, `subordinates_not_permitted`, `expired`, `not_yet_valid`, `ancestor_revoked`. On create these describe the parent CA                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `ca_subject_in_use`           | 409    | `subject_claimed`, `root_subject_claimed`, `identity_root_reserved`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `crl_not_newer`               | 409    | `crl_not_newer`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ca_issuance_budget_exceeded` | 409    | `ca_issuance_budget_exceeded`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ca_key_unavailable`          | 409    | `ca_key_unavailable` (also the parent CA on an intermediate create)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `conflict`                    | 409    | `name_in_use`, `ca_not_pending`, `key_not_disabled`, `key_destroyed`, `ca_limit_reached`, `grant_exists`, `grant_limit_reached`, `consumer_not_active`, `use_ca_revoke`, `idempotency_key_reused`, `parent_environment_mismatch`, `parent_validity_insufficient`, `revoke_at_root`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `bad_request`                 | 400    | `kind_not_supported`, `invalid_name_constraint`, `reserved_name`, `invalid_policy`, `invalid_grant_policy`, `policy_too_large`, `body_too_large`, `unknown_field`, `names_from_csr_only`, `names_conflict`, `invalid_requester`, `invalid_expiry`, `environment_mismatch`, `evaluate_input`, `invalid_reason`, `invalidity_date_requires_key_compromise`, `parent_required`, `parent_not_allowed`, `validity_not_allowed`, `invalid_validity`, `name_constraints_broader_than_parent`, `extended_key_usage_broader_than_parent`, `invalidity_date_requires_ca_compromise`, `invalid_invalidity_date`. `invalid_policy` also covers leaf fields on a `ROOT`. `kind_not_supported` now means an unknown `kind`. Also the restricted-subject reasons                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `not_found`                   | 404    | `ca_not_found`, `external_ca_not_found`, `crl_missing`, `consumer_not_found`, `grant_not_found`, `certificate_not_found`, `parent_not_found`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `forbidden`                   | 403    | `pki_role_required`, with `details.role`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `service_unavailable`         | 503    | `crl_publication_busy` (with `Retry-After: 30`), `kms_access_denied`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `issuance_denied`             | 403    | The `issuance_denied` reasons in [PKI consumer routes](pki.md#errors), with `deniedNameType` and `deniedName` when a name caused it. Also returned by administrator issuance                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `issuance_grant_not_found`, `issuance_grant_inactive` | 404, 403 | `grant_not_found`; `grant_disabled`, `grant_expired`. Only on the consumer routes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ca_capacity_exceeded`        | 409    | `ca_capacity_exceeded` (also the parent root on an intermediate create). Administrator issuance counts against capacity too                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `issuance_revoked`, `issuance_expired` | 409 | `certificate_revoked`, `ca_revoked`, `ancestor_revoked`; `result_expiring`, `inventory_expired`, `issuance_expired`. On a replayed issuance                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `issuance_rate_limited`       | 429    | `admin_hour`, `ca_hour`, with `Retry-After` and `details.retryAfterSeconds` (also the parent root on an intermediate create)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
