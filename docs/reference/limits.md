---
title: Limits and timings
description: Every Hemlig limit, lifetime, retention period and interval in one place, each with the source line that enforces it.
pageType: reference
---

# Limits and timings

Every number Hemlig enforces, grouped by topic, with the source line it comes from. Other pages link here instead of repeating these values.

Source paths are relative to the [repository root](https://github.com/zyno-io/hemlig). Line numbers refer to release `v0.3.2`.

## Identity

| Item | Value | Source |
| --- | --- | --- |
| Consumer ID format | 3 to 64 characters: lowercase letters, digits and hyphens, starting with a letter | `src/domain/validation.ts:11` |
| Bootstrap token lifetime | 30 minutes from issue; one use | `src/services/agent-grants.ts:162`, `src/domain/types.ts:260` |
| Bootstrap token format | `hmlb_` followed by 43 URL-safe characters | `src/handlers/bootstrap.ts:27`, `src/services/agent-grants.ts:161` |
| Bootstrap token issue condition | Only for a grant in `PENDING` status | `src/services/agent-grants.ts:155-159` |
| Client certificate validity | 365 days | `src/services/issuer.ts:30,315` |
| Issuing root validity and size | 3,650 days; RSA 3072-bit key | `src/services/issuer.ts:29,151` |
| Minimum CSR key size | RSA 2048 bits | `src/services/issuer.ts:289` |
| Maximum CSR size (enrollment) | 32,768 bytes | `src/services/issuer.ts:28,278` |
| Maximum CSR field (bootstrap and rotation requests) | 16,384 characters | `src/handlers/bootstrap.ts:41`, `src/handlers/identity-rotation.ts:45` |
| Active client certificates per agent | Self-rotation is refused when 3 or more certificates are active (`identity_limit_reached`). Administrators can issue any number | `src/services/agent-identities.ts:17`, `src/services/consumers.ts:217` |
| Idempotency key length | 8 to 128 characters (the CLI also restricts them to printable non-space ASCII) | `src/handlers/admin.ts:1083`, `src/handlers/consumer.ts:444`, `src/handlers/identity-rotation.ts:95`, `packages/cli/src/index.ts:237` |
| Enrollment operation lease | 10 minutes; after it expires the recovery worker may resume the operation | `src/services/consumers.ts:403,577` |
| Truststore size | At most 1,000 certificates and 1 MiB (API Gateway's limit) | `src/services/consumers.ts:38-39,424,473` |

## Secrets and grants

| Item | Value | Source |
| --- | --- | --- |
| Secret ID | 3 to 64 lowercase characters per slash-separated segment, 256 characters in total | `src/domain/validation.ts:12,35` |
| Environment name | 1 to 64 lowercase characters, starting with a letter | `src/domain/validation.ts:13,42` |
| Environments per deployment | 100 | `src/repositories/dynamo.ts:165,343-347` |
| Payload size | 768,000 bytes of serialized JSON; the server can be configured lower, never higher | `src/domain/validation.ts:217-218`, `src/aws/config.ts:44-55`, `cdk/stack.ts:327` |
| Payload entry name | Letters, digits, `.`, `_` and `-` | `src/domain/validation.ts:10` |
| Payload entry encoding | `utf8` or canonical `base64` | `src/domain/validation.ts:201-211` |
| Metadata description | 1,024 characters | `src/domain/validation.ts:56` |
| Tags per secret | 20; key 1 to 32 characters, value 1 to 128 characters | `src/domain/validation.ts:14-15,237` |
| Catalog search text (`q`) | 1 to 128 characters | `src/domain/validation.ts:123` |
| Required query-string parameter length | 128 characters (such as `environment`) | `src/handlers/admin.ts:1076` |
| ACL entries per secret | 40 direct consumers, permission `read` only | `src/domain/validation.ts:19,161,182` |
| Capabilities per AgentGrant | `read` and/or `write`, no duplicates | `src/domain/validation.ts:101,111` |
| Secret grants per AgentGrant | 0 to 1,000 on create (0 only with empty `capabilities`). `PUT` accepts 0 to 1,000 | `src/services/agent-grants.ts:326,336` |
| Control revisions returned in history | 500, with `truncated` set when there are more | `src/repositories/dynamo.ts:163,1415,1431` |

## Pagination and sync

| Item | Value | Source |
| --- | --- | --- |
| Pagination cursor lifetime | 15 minutes; the cursor is bound to the filters and actor that created it | `src/handlers/admin.ts:172`, `src/handlers/consumer.ts:343`, `src/services/cursor.ts:58-62` |
| Rows read per DynamoDB page (lists and change snapshots) | Up to 100; a page can hold fewer after filtering | `src/repositories/dynamo.ts:946,986,1133,1289,1319` |
| Catalog search and folder tree scan | Bounded to 500 items; the response sets `truncated` instead of returning a cursor | `src/repositories/dynamo.ts:164,1177,1223` |
| Audit archive page | 50 objects per page, filtered after reading | `src/services/audit.ts:29,75` |
| Agent sync page | Up to 100 records per query page; the page cursor lasts 15 minutes | `src/repositories/agent-sync.ts:117`, `src/services/agent-sync.ts:70` |
| Sync checkpoint (`syncCursor`) lifetime | 7 days | `src/repositories/agent-sync.ts:18`, `src/services/agent-sync.ts:66-68` |
| Archived-secret sync records | Kept 8 days so that offline agents see the archive | `src/repositories/agent-sync.ts:19,192` |
| Delivered change-hint records | Expire 7 days after delivery | `src/repositories/dynamo.ts:677` |
| Change-hint dead-letter queue | Messages kept 14 days; the alarm checks every 5 minutes | `cdk/stack.ts:554,562` |

## Storage and retention

| Item | Value | Source |
| --- | --- | --- |
| Revision bucket Object Lock | Compliance mode, 90 days | `cdk/stack.ts:111-116` |
| Audit bucket Object Lock | Compliance mode, 7 years (`365 * 7` days) | `cdk/stack.ts:117-122` |
| Superseded revision retention | Extended to 91 days from the moment it is superseded | `src/services/secrets.ts:762` |
| Retention worker schedule | Once a day | `cdk/stack.ts:764-767` |
| Recovery worker schedule | Every 5 minutes | `cdk/stack.ts:759-762` |
| Lambda timeout and memory | 29 seconds, 512 MB. The PKI maintenance Lambda runs up to 5 minutes | `cdk/stack.ts:1169-1170` |
| API Gateway access log retention | 1 year | `cdk/stack.ts:1312` |
| Lambda function log retention | Not set, so CloudWatch keeps them indefinitely | `cdk/stack.ts` (no `logRetention` on any function) |
| Application CMK rotation | Automatic key rotation enabled | `cdk/stack.ts:211` |
| Console asset noncurrent versions | Expire after 30 days | `cdk/stack.ts:859` |
| MiniStack Object Lock (local only) | 1 day, so a developer machine never holds undeletable data | `src/scripts/dev-ministack.ts:89` |

::: warning Compliance-mode data cannot be deleted
Object Lock Compliance retention cannot be shortened by anyone. Revisions and audit events remain until their retention ends, and they block stack teardown.
:::

## PKI

| Item | Value | Source |
| --- | --- | --- |
| CAs per environment | 50 not counting `FAILED` ones; the count reads the directory index, so it can lag | `src/pki/ca-service.ts` |
| CA validity at activation | At least 30 days remaining | `src/pki/chain.ts` |
| Name constraint subtrees per CA | 50 in total | `src/pki/ca-model.ts` |
| CA request or certificate PEM | 32 KiB | `src/pki/ca-model.ts` |
| Admin request body | 1 MiB | `src/handlers/pki-http.ts` |
| Generated CRL validity | 1 hour to 30 days, default 7 days | `src/pki/ca-model.ts` |
| Generated CRL refresh | A third of the validity before `nextUpdate`, at least 45 minutes, at most half of the validity. 1 hour gives 30 minutes, 7 days gives 2.3 days | `src/pki/crl-service.ts` |
| `pki-generated-crl-stale` threshold | A third of the refresh margin, at most 2 days | `src/pki/crl-service.ts` |
| Uploaded root CRL | At most 512 KiB; `nextUpdate` at most 400 days after `thisUpdate` | `src/pki/crl-verify.ts` |
| Root CRL alarm | 30 days before `nextUpdate`; 24 hours with no CRL at all | `src/pki/maintenance.ts` |
| CA policy defaults | Leaf lifetime 90 days (300 seconds to 397 days), capacity 8,000 (1 to 12,000), 2,000 issuances per hour (1 to 6,000) | `src/pki/ca-model.ts` |
| Issuance budget | `capacity + 2 x issuancePerHour` at most 12,000 | `src/pki/ca-model.ts` |
| CRL lease | 60 seconds | `src/repositories/pki.ts` |
| Maintenance schedule | Every 15 minutes, with a 5-minute timeout; it stops starting CRL publications with less than 30 seconds left | `src/pki/maintenance.ts` |
| Expired revocation entries | Get a 1-day TTL once a CRL issued after their certificate's `notAfter` has carried them | `src/pki/crl-service.ts` |
| Issuance grants per consumer | 20 live grants; best effort under concurrent creates | `src/pki/grant-service.ts` |
| Grant policy | At most 32 KiB canonical JSON, 200 name rules, 10 forced SANs, 10 certificate policy OIDs | `src/pki/grant-policy.ts` |
| Grant quotas | 100 per hour and 1,000 per day by default, each 1 to 1,000,000 | `src/pki/grant-model.ts` |
| CA hourly issuance | The CA's `issuancePerHour` (default 2,000), shared by all grants and administrators | `src/repositories/pki.ts` |
| Administrator issuance | 100 certificates per hour per CA | `src/pki/issuance-service.ts` |
| SANs per certificate | 100, and the grant's `maxSans` | `src/pki/grant-policy.ts` |
| Issued certificate size | 16 KiB DER (the TBS is checked at 15 KiB) | `src/pki/issuance-model.ts` |
| CSR PEM | 32 KiB. Usages: 16 entries of up to 64 characters | `src/pki/issuance-model.ts` |
| Certificate lifetime | 300 seconds to 397 days; the grant minimum defaults to 1 hour; clamped to the CA certificate's validity | `src/pki/grant-policy.ts` |
| Replay window | A replay is refused within 60 seconds of `notAfter`, and 90 days after it. Replay records last until 400 days after `notAfter` | `src/pki/issuance-service.ts` |
| Capacity count age | A count older than 30 minutes is recounted by the next issuance; maintenance recounts every pass | `src/pki/capacity-service.ts` |
| Inline CRL publication after a revoke | 5-second deadline, then the next maintenance pass publishes | `src/pki/certificate-service.ts` |
| Bulk revoke | 30 certificates per transaction, a 20-second run; repeat with the same key while `complete` is `false` | `src/pki/certificate-service.ts` |
| Failure audit events | One per identity, grant and reason every 10 minutes | `src/handlers/pki-issuer-routes.ts` |
| List pages | 100 certificates or grants per page | `src/repositories/pki.ts` |

## Controller

| Item | Value | Source |
| --- | --- | --- |
| Resync interval | 600,000 ms (10 minutes); environment variable `HEMLIG_RECONCILE_INTERVAL_MS`, Helm value `controller.reconcileIntervalMilliseconds` | `packages/kubernetes-controller/src/v1beta.ts:2009-2012`, `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:46` |
| Source Secret debounce | 250 ms; `HEMLIG_SOURCE_DEBOUNCE_MS`, `controller.sourceDebounceMilliseconds` | `packages/kubernetes-controller/src/v1beta.ts:2013-2016`, `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:47` |
| Failed pass retry | Exponential from 1 s up to 5 minutes, with jitter; honours `Retry-After` | `packages/kubernetes-controller/src/v1beta.ts:1897-1903` |
| Failed identity rotation retry | Exponential from 60 s up to 6 hours | `packages/kubernetes-controller/src/v1beta.ts:738-739` |
| `rotateBefore` default | 720 hours (30 days) before expiry, capped at half the certificate lifetime; units `s`, `m`, `h`, `d`; `0s` disables | `packages/kubernetes-controller/src/v1beta.ts:51,2223-2262`, `packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io.yaml:82` |
| cert-manager issuer concurrency | 4 Hemlig PKI calls at once (`HEMLIG_PKI_CONCURRENCY`, `certManager.maxConcurrentRequests`, 1 to 64) and at most 2 per consumer | `packages/kubernetes-controller/src/pki/types.ts`, `packages/kubernetes-controller/src/pki/queue.ts` |
| cert-manager issuer retries | Slow backoff 30 s to 5 minutes for conditions that need a person or a Hemlig change; fast backoff 1 s to 5 minutes for network, 5xx and gateway 429, both with jitter. A Hemlig `429` waits `Retry-After` plus up to 10% (at most 30 s) of jitter | `packages/kubernetes-controller/src/pki/types.ts`, `packages/kubernetes-controller/src/pki/queue.ts` |
| cert-manager issuer resync | Every 5 minutes (jittered), over requests already known to be pending | `packages/kubernetes-controller/src/pki/module.ts` |
| cert-manager issuer remote timeout | 60 seconds per Hemlig call | `packages/kubernetes-controller/src/pki/types.ts` |
| cert-manager issuer relist page | 500 objects, at startup, after `410 Gone` and when a CRD appears | `packages/kubernetes-controller/src/pki/module.ts` |
| Trust bundle refresh | 300,000 ms (5 minutes), 30,000 to 3,600,000; `HEMLIG_PKI_BUNDLE_INTERVAL_MS`, `trustBundles.refreshIntervalMilliseconds`. Jittered by 10% either way | `packages/kubernetes-controller/src/pki/types.ts`, `packages/kubernetes-controller/src/pki/module.ts` |
| Trust bundle CAs | 50 per bundle | `packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io-pki.yaml` |
| Trust bundle ConfigMap | 1,048,576 bytes of payload (the decoded size of `binaryData`). A DER CRL is at most 1,000,000 bytes by the CA capacity bound; PEM adds about a third | `packages/kubernetes-controller/src/pki/types.ts` |
| Trust bundle target name | 165 characters, so `<target>-crl-<issuerId>` stays within 253 | `packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io-pki.yaml` |
| Default replicas | 1 | `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:6` |
