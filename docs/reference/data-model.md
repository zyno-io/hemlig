---
title: Control-table data model
description: The DynamoDB keys and global secondary indexes of the Hemlig control table, verified against the repository code.
pageType: reference
---

# Control-table data model

The control table holds every Hemlig record except payload ciphertext, using one partition key (`pk`), one sort key (`sk`) and six sparse indexes.

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

## Global secondary indexes

| Index | Partition key | Sort key | Used for |
| --- | --- | --- | --- |
| `workflow-due` | `workflowDuePk` (`WORKFLOW#DUE`) | `workflowDueSk` (expiry time) | Finding expired prepared workflows |
| `retention-due` | `retentionDuePk` | `retentionDueSk` (due time) | Finding superseded revisions eligible for deletion |
| `catalog-path` | `catalogPk` (`CATALOG#ENV`, or `ARCHIVED_CATALOG#ENV`) | `catalogSk` (path, then secret ID) | Catalog browsing in path order |
| `consumer-directory` | `consumerDirectoryPk` (`CONSUMERS#ENV`) | `consumerDirectorySk` (consumer ID) | Listing consumers |
| `consumer-identity` | `identityConsumerPk` (`CONSUMER#ID`) | `identityConsumerSk` (expiry, then fingerprint) | Listing a consumer's certificates |
| `secret-revision` | `revisionPk` (`SECRET#UID`) | `revisionSk` (created time, then version) | Newest-first control revision history |

Every index is sparse: an item appears in it only while it carries that index's attributes. The index names match the local environment in [`src/scripts/dev-ministack.ts`](https://github.com/zyno-io/hemlig/blob/main/src/scripts/dev-ministack.ts).

## Related

- [Secrets, revisions and encryption](../guide/secrets-and-encryption.md)
- [Sync and change hints](../guide/sync-and-notifications.md)
