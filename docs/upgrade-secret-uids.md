# Upgrade to immutable secret UIDs

This migration changes the durable identity of a secret from its external
`environment` and `secretId` to a generated `secretUid`. The public API keeps
using `secretId`; the migration creates an environment-scoped name lookup so
the external name remains unique and addressable.

The migration also replaces AgentGrant prefix scopes and parallel ID/UID lists
with paired, exact `{ secretId, secretUid, permissions }` records. Each old
prefix is snapshotted to the secrets it matches at migration time. It does not
grant access to secrets created later or to a later secret that reuses an
archived secret ID.

## Before applying

1. Confirm DynamoDB point-in-time recovery is enabled and take any additional
   backup required by your change policy.
2. Quiesce every writer and reader: the administration, consumer, bootstrap,
   recovery, retention, and notification workflows must not run during the
   migration.
3. Deploy the UID-aware release while traffic remains quiesced, then run a dry
   run using credentials for the deployment
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

## Reconcile derived delivery access

Reconcile the read delivery projection from the canonical AgentGrants:

```bash
HEMLIG_UPGRADE_QUIESCED=1 \
CONTROL_TABLE_NAME=your-control-table \
REVISION_BUCKET_NAME=your-revision-bucket \
yarn reconcile:agent-grant-access
```

This removes any ACL-only access for agent consumers and adds any missing
read delivery rows. It is safe to rerun while traffic remains quiesced.

## After applying

Restore traffic and verify that a secret can be read by its existing `secretId`,
then inspect its returned `secretUid`.

Review AgentGrants after the migration. A prefix that previously matched no
current secret becomes an empty exact permission list and grants no access. Add
a specific live secret ID and permission through the AgentGrant API before an
agent may access it; the service records its current UID at that time.
