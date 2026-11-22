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
| Secret grants per AgentGrant | 1 to 1,000 exact secrets on create. `PUT` accepts 0 to 1,000 | `src/services/agent-grants.ts:326,336` |
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
| Lambda timeout and memory | 29 seconds, 512 MB | `cdk/stack.ts:1169-1170` |
| API Gateway access log retention | 1 year | `cdk/stack.ts:1312` |
| Lambda function log retention | Not set, so CloudWatch keeps them indefinitely | `cdk/stack.ts` (no `logRetention` on any function) |
| Application CMK rotation | Automatic key rotation enabled | `cdk/stack.ts:211` |
| Console asset noncurrent versions | Expire after 30 days | `cdk/stack.ts:859` |
| MiniStack Object Lock (local only) | 1 day, so a developer machine never holds undeletable data | `src/scripts/dev-ministack.ts:89` |

::: warning Compliance-mode data cannot be deleted
Object Lock Compliance retention cannot be shortened by anyone. Revisions and audit events remain until their retention ends, and they block stack teardown.
:::

## Controller

| Item | Value | Source |
| --- | --- | --- |
| Resync interval | 600,000 ms (10 minutes); environment variable `HEMLIG_RECONCILE_INTERVAL_MS`, Helm value `controller.reconcileIntervalMilliseconds` | `packages/kubernetes-controller/src/v1beta.ts:2009-2012`, `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:46` |
| Source Secret debounce | 250 ms; `HEMLIG_SOURCE_DEBOUNCE_MS`, `controller.sourceDebounceMilliseconds` | `packages/kubernetes-controller/src/v1beta.ts:2013-2016`, `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:47` |
| Failed pass retry | Exponential from 1 s up to 5 minutes, with jitter; honours `Retry-After` | `packages/kubernetes-controller/src/v1beta.ts:1897-1903` |
| Failed identity rotation retry | Exponential from 60 s up to 6 hours | `packages/kubernetes-controller/src/v1beta.ts:738-739` |
| `rotateBefore` default | 720 hours (30 days) before expiry, capped at half the certificate lifetime; units `s`, `m`, `h`, `d`; `0s` disables | `packages/kubernetes-controller/src/v1beta.ts:51,2223-2262`, `packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io.yaml:82` |
| Default replicas | 1 | `packages/kubernetes-controller/chart/hemlig-controller/values.yaml:6` |
