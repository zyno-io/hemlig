# Upgrade to immutable secret UIDs

This migration changes the durable identity of a secret from its external
`environment` and `secretId` to a generated `secretUid`. The public API keeps
using `secretId`; the migration creates an environment-scoped name lookup so
the external name remains unique and addressable.

The migration also replaces AgentGrant prefix scopes with explicit secret-ID
selection lists and resolves those selections to immutable secret UIDs. Each
old prefix is snapshotted to the secrets it matches at migration time. It does
not grant access to secrets created later or to a later secret that reuses an
archived secret ID.

## Before applying

1. Confirm DynamoDB point-in-time recovery is enabled and take any additional
   backup required by your change policy.
2. Quiesce every writer and reader: the administration, consumer, bootstrap,
   recovery, retention, and notification workflows must not run during the
   migration.
3. Build the release and run a dry run using credentials for the deployment
   account:

   ```bash
   CONTROL_TABLE_NAME=your-control-table yarn migrate:secret-uids
   ```

4. Resolve every reported legacy `readPathPrefixes` or `writePathPrefixes`
   issue. Those pre-date secret-ID folders and cannot be translated safely.

## Apply

Run the same command with the explicit quiesce acknowledgement:

```bash
HEMLIG_UPGRADE_QUIESCED=1 \
  CONTROL_TABLE_NAME=your-control-table \
  yarn migrate:secret-uids --apply
```

The operation changes DynamoDB only. Existing immutable S3 revisions are not
copied or rewritten; migrated `HEAD` records retain their exact object keys.
New revisions are written under `secrets/<secretUid>/...`.

The script is safe to restart after an interruption while the service remains
quiesced. It uses deterministic UIDs for existing external names and rebuilds
the name lookup records on every run.

## After applying

Deploy the release containing the UID-aware service. Verify that a secret can
be read by its existing `secretId`, then inspect its returned `secretUid`.

Review AgentGrants after the migration. A prefix that previously matched no
current secret becomes an empty exact allowlist and grants no access. Add a
specific live secret ID through the AgentGrant API before an agent may access
it; the service records its current UID at that time.
