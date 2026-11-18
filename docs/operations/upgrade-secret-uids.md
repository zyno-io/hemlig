---
title: "Upgrade: immutable secret UIDs"
description: Migrate a deployment so every secret has an immutable secret UID and every AgentGrant lists exact secrets.
pageType: how-to
---

# Upgrade: immutable secret UIDs

Migrate an existing deployment so each secret is keyed by a generated [secret UID](../reference/glossary.md#secret-uid) and each [AgentGrant](../reference/glossary.md#agentgrant) lists exact secrets instead of path prefixes.

The public API keeps using the secret ID. The migration adds an environment-scoped name lookup so the external name stays unique and addressable. Each old prefix scope is snapshotted to the secrets it matches **at migration time**. It grants nothing for secrets created later, or for a later secret that reuses an archived ID.

This is one of the [maintenance scripts](upgrades.md#migrate-secret-uids). It needs downtime, because every writer and reader must be stopped.

**Before you start**

- Role: platform administrator with credentials for the deployment account.
- A checkout of the release tag and the [common setup](upgrades.md#common-setup) environment variables.
- A quiet window. Nothing may read or write while it runs.

## 1. Back up

Confirm DynamoDB point-in-time recovery is enabled (the stack enables it) and take any extra backup your change policy requires.

## 2. Quiesce and deploy

Stop every writer and reader: the administration, consumer, bootstrap, recovery, retention and notification workflows must not run during the migration. Deploy the UID-aware release while traffic stays quiesced.

## 3. Dry run

```sh
yarn migrate:secret-uids
```

Expected output:

```text
Secret UID migration: 12 secret row(s), 4 access row(s), 6 lookup(s), 2 AgentGrant update(s).
```

## 4. Resolve every reported issue

Each problem is printed to stderr as an `ISSUE:` line, and `--apply` refuses to run while any remain. Legacy `readPathPrefixes` or `writePathPrefixes` pre-date secret-ID folders and cannot be translated safely. Resolve each one, then repeat step 3 until no `ISSUE:` lines print.

## 5. Apply

```sh
HEMLIG_UPGRADE_QUIESCED=1 yarn migrate:secret-uids --apply
```

Expected output, ending with:

```text
Secret UID migration completed successfully.
```

The script changes DynamoDB only. Existing immutable S3 revisions are not copied or rewritten, and migrated heads keep their exact object keys. New revisions are written under `secrets/SECRET_UID/`.

It is safe to restart after an interruption while the service stays quiesced. It derives deterministic UIDs from the existing names and rebuilds the lookup records on every run.

## 6. Reconcile delivery access

Rebuild the read-delivery projection from the canonical AgentGrants. This removes ACL-only access held by agents and adds any missing delivery rows. Needs `REVISION_BUCKET_NAME` as well as `CONTROL_TABLE_NAME`.

```sh
HEMLIG_UPGRADE_QUIESCED=1 yarn reconcile:agent-grant-access
```

Expected output:

```text
Reconciled derived delivery access for 2 active AgentGrant(s).
```

It is safe to rerun while traffic stays quiesced.

## 7. Verify

Restore traffic, then check:

1. Read a secret by its existing secret ID. It returns the same value and now includes a `secretUid`.
2. Review every AgentGrant. A prefix that matched no current secret is now an empty exact list and grants no access.

::: warning Prefix scopes become snapshots
To let an agent reach a secret created after the migration, add its exact secret ID and permission through the AgentGrant API. The service records the secret's current UID at that moment.
:::

## Next steps

- [Run the remaining maintenance scripts](upgrades.md)
- [Change an AgentGrant's scope](../guide/agent-grants.md)
