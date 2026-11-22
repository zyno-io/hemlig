---
title: Control-table data model
description: The DynamoDB keys and global secondary indexes of the Hemlig control table, verified against the repository code.
pageType: reference
---

# Control-table data model

The control table holds every Hemlig record except payload ciphertext, using one partition key (`pk`), one sort key (`sk`) and seven sparse indexes.

Source: [`src/repositories/dynamo.ts`](https://github.com/zyno-io/hemlig/blob/main/src/repositories/dynamo.ts) and [`src/repositories/agent-sync.ts`](https://github.com/zyno-io/hemlig/blob/main/src/repositories/agent-sync.ts). Index definitions: [`cdk/stack.ts`](https://github.com/zyno-io/hemlig/blob/main/cdk/stack.ts). Placeholders such as `UID` stand for a stored value.

## Secrets

| `pk` | `sk` | Purpose |
| --- | --- | --- |
| `SECRET#UID` | `HEAD` | Current revisions, state and write lease |
| `SECRET#UID` | `CONTROL#VERSION` | Control workflow and object metadata |
| `SECRET#UID` | `PAYLOAD#VERSION` | Payload workflow and object metadata |
| `SECRET_NAME#ENV#SECRET_ID` | `LOOKUP` | External name to immutable UID |
| `CONSUMER#ID` | `SECRET#ENV#UID` | Current grant, or a `REVOKED` tombstone |
| `SYSTEM#ENVIRONMENTS` | `ENVIRONMENT#NAME` | One record per environment |
| `IDEMPOTENCY#ACTOR_TYPE#ACTOR_ID` | `REQUEST#KEY` | Mutation state and terminal-audit marker |

## Identity and enrollment

| `pk` | `sk` | Purpose |
| --- | --- | --- |
| `CONSUMER#ID` | `PROFILE` | Consumer environment, URI identity and activation state |
| `IDENTITY#SHA256` | `PROFILE` | A client certificate: status, validity, successor |
| `SYSTEM#ISSUER` | `PROFILE` | The public root, its KMS-wrapped private key and validity |
| `TRUSTSTORE#ROOTS` | `ROOT#SHA256` | The public root used as the truststore anchor |
| `ENROLLMENT#OPERATION` | `STATE` | Recoverable enrollment state and publication due time |
| `SYSTEM#TRUSTSTORE` | `STATE` | Publication lease and the current or pending pinned bundle |

## Agents, sync and hints

| `pk` | `sk` | Purpose |
| --- | --- | --- |
| `AGENT_GRANT#ID` | `PROFILE` | AgentGrant: scope, capabilities, activation state |
| `CONSUMER#ID` | `AGENT_GRANT` | Marks an identity as an agent so it cannot fall back to direct-consumer routes |
| `BOOTSTRAP#SHA256` | `STATE` | Hash-only, expiring, one-use bootstrap token |
| `NOTIFICATION#ID` | `EVENT` | Pending or delivered change hint; TTL starts after delivery |
| `AGENT_SYNC#ENV` | `STATE` | Epoch, committed sequence and backfill readiness |
| `AGENT_SYNC#ENV` | `CHANGE#SEQUENCE#UID` | One current entry per secret; sequence is zero-padded to 16 digits |
| `CURSOR#TOKEN` | `STATE` | Opaque pagination continuation, bound to its caller; TTL |

Lifetimes for cursors, checkpoints and archived markers are in [Limits](limits.md#pagination-and-sync).

## PKI

Items whose `pk` starts with `PKI_` belong to the PKI and are written only by the PKI Lambdas; the other Lambdas are denied writes to them. The exception is the human idempotency record of an administrator issuance, `IDEMPOTENCY#human#ACTOR_ID`, which uses the same key shape as the secrets records. Pagination state for PKI lists uses `PKI_CURSOR#TOKEN`.

| `pk` | `sk` | Purpose |
| --- | --- | --- |
| `PKI_CA#CA_ID` | `PROFILE`, `CRL`, `REVOKED#SERIAL` | A CA, its CRL state and its revocation entries |
| `PKI_CA_NAME#ENV#NAME` | `LOOKUP` | CA name to `caId` |
| `PKI_SUBJECT#KEY` | `LOOKUP` | Subject registry |
| `PKI_EXTCA#EXT_ID` | `PROFILE` | An external CA |
| `PKI_CERT#CA_ID#SERIAL` | `PROFILE` | An issued certificate. TTL is its `notAfter` plus 90 days |
| `PKI_CONSUMER#ID` | `CERT#ISSUED_AT#CA_ID#SERIAL` | A consumer's certificate pointer. TTL as above |
| `PKI_GRANT#ID` | `NAME#NAME` | An issuance grant |
| `PKI_QUOTA#UID`, `PKI_QUOTA#admin#CA_ID`, `PKI_QUOTA#ca#CA_ID` | `HOUR#yyyymmddhh`, `DAY#yyyymmdd` | Quota counters. TTL 48 hours (hour) or 3 days (day) |
| `PKI_IDEMPOTENCY#ID` | `REQUEST#KEY` | Consumer replay record. TTL is `notAfter` plus 400 days |
| `PKI_CURSOR#TOKEN` | `STATE` | Opaque pagination continuation |

### PKI record details

| Record | Fields | Notes |
| --- | --- | --- |
| CA `PROFILE` | `status`, `version`, `key` (state, wrapped envelope), `subject`, `subjectKey`, `parent`, `crlIssuers`, `policy`, `maxIssueLifetimeEverSeconds`, `activatedAt`, `retiredAt`, `drainedAt`, `keyDestroyedAt` | `version` is the ETag. `subjectDer` is base64 DER and `subjectKeyIdentifier` is lowercase hex |
| CA `CRL` | `revision`, `lastNumber`, `dirtySince`, `lease` (owner, expiry), `published`, `sweptThrough` | `published` holds `number`, `objectKey`, `sha256`, `thisUpdate`, `nextUpdate`, `revision`, `entryCount` and `dropDueAt`. `sweptThrough` is the `thisUpdate` whose expired-entry sweep finished |
| `REVOKED#SERIAL` | `serial`, `revokedAt`, `reason`, `invalidityDate`, `notAfter`, `ttl` | Written when a leaf is revoked. `ttl` is set one day after a CRL issued after `notAfter` has carried the entry |
| External CA | `extId`, `certificatePem`, `fingerprint`, `spkiSha256`, `subjectDer`, `subjectAttributes`, `subjectKey`, `subjectKeyIdentifier`, `notAfter`, `createdAt`, `dependents`, `environments`, `version`, `crl` | `dependents` and `environments` are DynamoDB string sets. `crl` holds `numberHex` (40 hex digits), `thisUpdate`, `nextUpdate`, `sha256`, `objectKey`, `uploadedAt` and `uploadedBy` |
| `PKI_SUBJECT#KEY` | `ownerType` (`ca` or `external`), `caId` or `extId`, `spkiSha256`, `claimedAt` | Claims are never released |
| `PKI_CA_NAME#ENV#NAME` | `caId`, `environment`, `name`, `claimedAt` | Never released |

CRL objects live in the PKI bucket: `crl/CA_ID/NUMBER-SHA16.crl` for a generated CRL and `crl/EXT_ID/NUMBER_HEX-SHA16.crl` for an uploaded root CRL, where `SHA16` is the first 16 hex digits of the DER SHA-256. Objects are immutable; the pointer in the record names the current one.

## Global secondary indexes

| Index | Partition key | Sort key | Used for |
| --- | --- | --- | --- |
| `workflow-due` | `workflowDuePk` (`WORKFLOW#DUE`) | `workflowDueSk` (expiry time) | Finding expired prepared workflows |
| `retention-due` | `retentionDuePk` | `retentionDueSk` (due time) | Finding superseded revisions eligible for deletion |
| `catalog-path` | `catalogPk` (`CATALOG#ENV`, or `ARCHIVED_CATALOG#ENV`) | `catalogSk` (path, then secret ID) | Catalog browsing in path order |
| `consumer-directory` | `consumerDirectoryPk` (`CONSUMERS#ENV`) | `consumerDirectorySk` (consumer ID) | Listing consumers |
| `consumer-identity` | `identityConsumerPk` (`CONSUMER#ID`) | `identityConsumerSk` (expiry, then fingerprint) | Listing a consumer's certificates |
| `secret-revision` | `revisionPk` (`SECRET#UID`) | `revisionSk` (created time, then version) | Newest-first control revision history |
| `pki-directory` | `pkiDirectoryPk` (`PKI_CAS`, `PKI_EXTCAS`, `PKI_CA_GRANTS#CA_ID`, `PKI_CERTS#CA_ID`) | `pkiDirectorySk` (`ENV#NAME`, external CA ID, `CONSUMER#NAME`, or `NOT_AFTER#SERIAL`) | Listing CAs, external CAs, a CA's grants and its certificates |

Every index is sparse: an item appears in it only while it carries that index's attributes. The index names match the local environment in [`src/scripts/dev-ministack.ts`](https://github.com/zyno-io/hemlig/blob/main/src/scripts/dev-ministack.ts).

## Related

- [Secrets, revisions and encryption](../guide/secrets-and-encryption.md)
- [Sync and change hints](../guide/sync-and-notifications.md)
