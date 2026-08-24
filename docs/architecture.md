# Hemlig architecture

Hemlig delivers Kubernetes Secret payloads to non-AWS workloads without giving
those consumers AWS credentials. Administrators define encrypted secrets and
consumer read ACLs; enrolled consumers receive only the payloads they may read.

This document describes the v0.4 implementation. It includes organizational
metadata/catalog browsing, the enrollment/truststore workflow, and bounded
audit-archive browsing. Issuer-root rotation remains intentionally excluded. See
[API reference](api.md) for the HTTP contract and
[deployment guide](cdk-integration.md) for installation inputs.

## Goals

- Keep plaintext values out of DynamoDB, audit records, logs, and S3 revisions.
- Give consumers no AWS principal or AWS credential.
- Make secret revisions immutable and mutations optimistic and idempotent.
- Keep application evidence in a distinct S3 Object Lock archive.
- Change metadata or ACLs without decrypting an existing payload.
- Provision an installation from CDK with `hml-<environment>-` resource names.

## System overview

```mermaid
flowchart LR
  administrator[Administrator] -->|OIDC JWT| adminApi[Admin HTTP API]
  bootstrap[Namespace bootstrap Secret] -->|one-use token + CSR| bootstrapApi[Bootstrap route]
  operator[Consumer operator] -->|mTLS leaf| consumerApi[Consumer HTTP API]
  adminApi --> adminLambda[Admin Lambda]
  adminApi --> auditQueryLambda[Audit query Lambda]
  bootstrapApi --> bootstrapLambda[Bootstrap Lambda]
  consumerApi --> consumerLambda[Consumer Lambda]
  adminLambda --> table[(DynamoDB control table)]
  consumerLambda --> table
  adminLambda --> kms[one Hemlig application CMK]
  consumerLambda --> kms
  adminLambda --> revisions[(S3 immutable revisions)]
  consumerLambda --> revisions
  adminLambda --> audit[(S3 Object Lock audit archive)]
  auditQueryLambda --> audit
  consumerLambda --> audit
  bootstrapLambda --> iot[AWS IoT Core]
  table -->|DynamoDB Stream| notificationLambda[Notification Lambda]
  notificationLambda -->|QoS 1 payload-free hint| iot
  recovery[Recovery Lambda] --> table
  adminLambda --> truststore[(S3 versioned truststore)]
  recovery --> truststore
  adminLambda --> domain[API Gateway consumer domain]
  recovery --> domain
  retention[Retention Lambda] --> revisions
```

The CDK stack binds an organization-owned OIDC issuer/audience, creates custom
domains, Route 53 aliases, a versioned truststore bucket, one-year sanitized
API Gateway access-log groups, and EventBridge schedules. Access logs record
only request ID, status, and gateway/authorizer error fields—never headers,
query strings, or request bodies. The consumer domain starts without a
truststore. Enrollment publishes a unique PEM bundle, pins its returned S3
version on that domain, verifies an observed `AVAILABLE` domain state without
truststore warnings, and only then activates the leaf identity. The consumer
handler also rejects a request without both a client certificate and active
identity row.

## Authentication and trust boundaries

| Caller            | Authentication                                                         | Rights                                                      |
| ----------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------- |
| Administrator     | External OIDC JWT, immutable configured actor claim (`sub` by default) | Secret mutation                                             |
| Consumer operator | Client certificate DER SHA-256 fingerprint in DynamoDB                 | Its allowed active secret reads and current access snapshot |
| Namespace agent   | One-use bootstrap capability, then the same mTLS leaf plus AgentGrant  | Only its configured read/write path prefixes and MQTT topic |
| Worker            | EventBridge/Lambda execution role                                      | Recovery or retention only                                  |

API Gateway verifies the administrator JWT, and the handler verifies its issuer
and audience again before using the configured subject claim for the audit
actor. The CDK stack receives the issuer/audience from the installer. The
handler accepts `client_id` only when `aud` is absent, matching API Gateway's
JWT-authorizer claim precedence.

For a consumer, API Gateway supplies the peer PEM in the HTTP API request
context. Hemlig parses it, SHA-256 hashes the raw DER bytes, and makes a
strongly consistent lookup of `IDENTITY#<fingerprint> / PROFILE`. It requires
an `ACTIVE` API identity within its validity window and carries its enrolled
environment into every authorization query. A caller never supplies a consumer
ID or environment: secret reads and change snapshots exclude rows outside that
identity's environment.

### AgentGrant and bootstrap boundary

An AgentGrant is created by the administrator API before the namespace gets a
credential. It names exactly one as-yet unused consumer ID, environment,
capabilities, and canonical read/write path prefixes. Its mapping is stored
beside the consumer identity, so any identity that has ever been an agent is
forced through AgentGrant checks even if it calls an ordinary consumer route.
This prevents a compromised controller from bypassing prefix enforcement by
guessing a known secret ID.

The bootstrap capability is a random 256-bit `hmlb_` value, stored only as a
SHA-256 digest with a thirty-minute expiry. It accepts one CSR and no caller
chosen identity/policy fields. The durable consumer-enrollment idempotency key
is derived from that digest, allowing the exact same CSR to recover its issued
leaf after a lost response while rejecting a different CSR. Before the grant is
marked active, the bootstrap Lambda registers the public leaf with AWS IoT,
attaches it to the consumer-named Thing and the CDK-created receive-only policy.
The cluster retains the private key; neither Hemlig nor IoT creates one.

Agent reads need both current ACL read access and an in-scope metadata path.
Agent writes must be in the write path scope and cannot change ACLs. An
unpathed secret is never agent-visible. A secret moved outside an existing
read prefix appears in the agent's access snapshot as `secret.revoked`, so an
already materialized Kubernetes Secret is removed without disclosing the new
path or payload.

### Enrollment trust boundary

Each Hemlig deployment has exactly one online, self-signed issuing root. The
first enrollment creates a 3072-bit RSA root; its private key is encrypted as
an AES-256-GCM envelope under the existing **single Hemlig application CMK**.
The envelope's KMS encryption context is
`{service: hemlig, purpose: issuer-ca}`. This is a logical separation from
payload envelopes, which bind their own secret/version context—not a second
KMS key. The admin Lambda has `kms:Decrypt` subject to that issuer context and,
separately, the payload context for authenticated administrator reads; consumer
Lambdas never receive issuer-envelope access.

`POST /v1/admin/consumers` accepts a signed RSA CSR, not a CA certificate or a
private key. Hemlig verifies the CSR signature and requires a 2048-bit-or-
larger RSA public key, then issues a non-CA TLS-client leaf containing:

```text
spiffe://hemlig/consumer/<consumer-id>
```

The consumer creates and retains the private key locally. Hemlig persists the
public leaf PEM and DER SHA-256 fingerprint so it can return the issued
certificate on an idempotent retry and validate the identity on every request.
The same root public certificate is the truststore anchor for every enrolled
consumer, so a normal deployment uses one truststore certificate rather than
one per consumer. Leaf rotation is additive; revocation is a strongly consistent
DynamoDB state change and takes effect at the application layer on the next
request. Issuer-root rotation is intentionally not exposed in v0.2: it would
need a separately reviewed overlap and migration protocol.

### Enrollment state machine

```text
verify CSR -> load/create one KMS-wrapped issuing root -> issue client leaf
  -> transaction: PENDING consumer/identity + PREPARED operation
  -> singleton truststore lease
  -> unique PEM object + exact S3 version
  -> UpdateDomainName + GetDomainName confirmation
  -> transaction: ACTIVE identity/consumer + READY operation
```

Only the operation holding the truststore lease can publish. It loads every
DynamoDB query page of active roots, sorts and deduplicates them by fingerprint,
and publishes the one deployment root. The request polls only briefly so a
candidate and its possible rollback fit the HTTP API Lambda window; longer
propagation is resumed by the five-minute worker with the same S3 object
version. A different enrollment receives `503` while the serialized publication
is in progress. No identity becomes active merely because an S3 object was
written. If API Gateway reports truststore warnings for the candidate version,
Hemlig rolls back to the prior known bundle when one exists, marks the pending
leaf workflow `FAILED`, and releases the lease; a warning-bearing bundle is
never promoted. A rejected enrollment returns terminal `409 enrollment_failed`.
Repair the issuer or truststore configuration before submitting a new
enrollment: a different CSR cannot alter the rejected root bundle.

The published bundle is preflighted against API Gateway's 1,000-certificate and
1 MiB limits before any S3 write or domain update. The one-root design avoids
the certificate-count concern in normal operation; the preflight remains as a
defense against invalid stored state and future root-overlap work.

## Secret lifecycle and revisions

```text
POST secret -> PENDING_VALUE
PUT payload -> ACTIVE
ACL removes a consumer -> that consumer receives a retained REVOKED tombstone
```

There is no public delete route. ACL removal is observable through
`GET /v1/changes` as `secret.revoked`.

Each mutation creates a fresh immutable control revision. A payload mutation
also creates a payload revision:

```text
secrets/<environment>/<secret-id>/control/<control-version-id>.json
secrets/<environment>/<secret-id>/payload/<payload-version-id>.json
```

A control revision contains metadata, ACL, state, actor, timestamp, and its
payload-version pointer. A payload revision has only an encrypted envelope.
The DynamoDB `HEAD` record points to current versions and its control version
is the HTTP ETag. Therefore an ACL or description edit reads only the control
object; it never decrypts or re-encrypts the payload.

### Mutation protocol

1. Validate caller, body, idempotency key, and (for an update) `If-Match`.
2. Serialize next revision(s); encrypt a new payload before it reaches S3.
3. Transactionally write `PREPARED` workflow records and acquire the head lease.
4. Conditionally write each unique S3 object with `If-None-Match: *` and a
   SHA-256 checksum.
5. Extend retention on exact old object versions before replacing the head.
6. Transactionally mark workflows ready and switch the head. When the ACL
   changed, replace its access projection/tombstone rows. Add one or two
   payload-free, grouped notification-outbox records that capture the affected
   consumer IDs.
7. Write terminal audit evidence before returning success.

An unchanged ACL is not rewritten when a payload changes: consumer delivery
checks the current secret head and the current grant transactionally, and the
background publisher fans the grouped outbox event out to recipients. An ACL
has at most 40 consumers. A complete ACL replacement can affect 80 grants
(40 additions plus 40 revocations); with the fixed mutation actions and at
most two grouped outbox records, that remains below DynamoDB's 100-action /
4 MiB transaction limit.

## Organization and catalog browsing

Secret metadata may contain a canonical `path` such as
`payments/stripe/production` and up to 20 `tags`, such as
`owner=payments`. Both are immutable control-revision fields: changing them
creates a new control revision but never decrypts or re-encrypts a payload.
They are explicitly non-operational—ACLs and resolved consumer identities alone
control delivery.

The current `HEAD` item carries a projection of the current metadata plus
`catalogPk=CATALOG#<environment>` and a path-ordered `catalogSk`. The sparse
`catalog-path` GSI supports paginated path-prefix browsing. Exact tag filters
are DynamoDB filter expressions on that bounded page. This intentionally favors
a simple, transaction-safe control-plane catalog over a second, eventually
consistent inverted-tag index. Catalog results never include ACLs or payloads.

## Encryption and integrity

Every payload revision uses a fresh KMS-generated AES-256 data key. Hemlig
encrypts canonical payload JSON with AES-256-GCM using a random 96-bit IV and
stores only the encrypted data key, IV, GCM tag, and ciphertext. It clears the
plaintext data-key buffer in process.

KMS encryption context and GCM additional authenticated data both bind the
ciphertext to `service=hemlig`, `purpose=secret-payload`, environment, secret
ID, and payload version ID.
Before decrypting, the consumer handler also requires the retrieved control and
payload documents to repeat the secret ID, environment, and exact versions from
the transactionally read authorization/head snapshot. A mismatched document,
missing immutable S3 version, or access/head version skew fails closed; the
consumer Lambda never uses a copied revision as a decrypt oracle.
On a consumer read, the service loads the exact S3 version named by `HEAD`,
verifies an available checksum, decrypts using the same KMS context, and checks
the GCM tag. A copied ciphertext, changed tag, or mismatched version fails
closed.

The same CMK also wraps the issuer's private-key envelope. A CMK is a key
management boundary, not an application-purpose boundary, so Hemlig uses both
encryption-context binding and context-conditioned IAM `Decrypt` **and
`GenerateDataKey`** grants for the issuer. The payload flow and issuer flow
never accept each other's context.
This deliberately keeps the application to one customer-managed KMS key while
keeping issuer and payload decrypt permissions independently conditioned. The
administrator route may use the payload allowance only after JWT authorization
and records its plaintext read in the immutable audit archive.

The revision and audit buckets are versioned and Object-Lock enabled at
creation. Their CDK defaults are 90-day and seven-year Compliance retention,
respectively. DynamoDB records exact S3 version IDs so retention code cannot
delete a different version.

## DynamoDB model

One on-demand DynamoDB table uses `pk`/`sk`, point-in-time recovery, and sparse
GSIs for scheduled work.

| Key                                             | Purpose                                                                     |
| ----------------------------------------------- | --------------------------------------------------------------------------- |
| `SECRET#<environment>#<id> / HEAD`              | Current revisions, state, write lease                                       |
| `SECRET#<environment>#<id> / CONTROL#<version>` | Control workflow/object metadata                                            |
| `SECRET#<environment>#<id> / PAYLOAD#<version>` | Payload workflow/object metadata                                            |
| `CONSUMER#<id> / SECRET#<environment>#<id>`     | Current grant or `REVOKED` tombstone                                        |
| `CONSUMER#<id> / PROFILE`                       | Immutable consumer environment/URI identity and activation state            |
| `IDENTITY#<sha256> / PROFILE`                   | Consumer API leaf identity and validity                                     |
| `SYSTEM#ISSUER / PROFILE`                       | One public root, KMS-wrapped private-key envelope, and root validity        |
| `TRUSTSTORE#ROOTS / ROOT#<sha256>`              | The public deployment-wide issuing-root truststore anchor                   |
| `ENROLLMENT#<operation> / STATE`                | Recoverable enrollment state and truststore publication due time            |
| `SYSTEM#TRUSTSTORE / STATE`                     | Singleton publication lease and current/pending version-pinned bundle       |
| `IDEMPOTENCY#<actor> / REQUEST#<key>`           | Mutation state and terminal-audit marker                                    |
| `AGENT_GRANT#<id> / PROFILE`                    | Administrator-owned path/capability boundary and activation state           |
| `CONSUMER#<id> / AGENT_GRANT`                   | Prevents an agent identity from falling back to unscoped delivery           |
| `BOOTSTRAP#<sha256> / STATE`                    | Hash-only, expiring, one-use CSR redemption capability                      |
| `NOTIFICATION#<id> / EVENT`                     | Pending/delivered MQTT hint; TTL begins only after terminal delivery        |
| `CURSOR#<token> / STATE`                        | Opaque, caller-bound pagination continuation; DynamoDB TTL after 15 minutes |
| `WORKFLOW#DUE` GSI                              | Expired prepared workflow discovery                                         |
| `RETENTION#DUE` GSI                             | Eligible non-head revision discovery                                        |
| `CATALOG#<environment>` GSI                     | Current `HEAD` records in path/secret order                                 |
| `CONSUMERS#<environment>` GSI                   | Administrative consumer profiles in consumer-ID order                       |
| `CONSUMER#<id>` identity GSI                    | Administrative API leaves in expiration order                               |
| `SECRET#<environment>#<id>` revision GSI        | Newest-first bounded control-revision management history                    |

`GET /v1/changes` is a paginated _current access snapshot_, not an event log.
The cursor is an opaque 256-bit token, bound to one consumer, and expires after
15 minutes. Its continuation state is server-side in the control table, so
Hemlig needs no pagination-signing secret.

## Immediate notification path

The CDK stack enables `NEW_IMAGE` streams on the control table and filters the
publisher Lambda to `NOTIFICATION#` records in `PENDING` state. One grouped
record captures the recipient consumer IDs for a secret change; the background
publisher fans it out as a QoS 1 message to each
`hemlig/<deployment>/consumers/<consumerId>` topic. The MQTT message contains
only secret ID, event kind, and revision IDs—never a payload, organizational
metadata, ACL, token, certificate, or presigned URL. A failed record is retried
by the stream mapping and then sent to an encrypted 14-day SQS DLQ with a
CloudWatch alarm.

The IoT policy allows an attached Thing to connect only as its exact consumer
ID and only subscribe/receive its exact topic. It permits no IoT publish,
wildcards, shadow, Jobs, or AWS credentials. MQTT is intentionally only a
prompt: controllers refetch mTLS state after every hint, reconstruct snapshots
on connect/reconnect, and resync every ten minutes. Duplicate, delayed, or
lost broker messages cannot change authorization or inject data.

## Audit evidence

After the handler resolves an application actor, implemented routes emit
`attempted` and `authorized` events, then write `succeeded` before a successful
response. A conditional `304` read is audited, as are scheduled recovery and
retention actions; post-authorization handler failures are best-effort audited
as `failed`. TLS or JWT requests rejected before an actor exists are not
application events and must be investigated through API Gateway logs. Each
object has a unique, reverse-time sortable key:

```text
audit/<yyyy>/<mm>/<dd>/<descending-timestamp>-<event-id>.json
```

Events contain a timestamp, correlation ID, stable actor, operation, safe
target IDs, outcome, source IP when available, and safe reason code. They do
not contain secret values, request bodies, tokens, certificates, private keys,
or plaintext KMS material.

Compliance retention prevents deletion or shortened retention; it does not
make a compromised writer unable to add misleading _new_ events. Hemlig claims
locked retention, not hash-chain tamper evidence. See the
[threat model](threat-model.md) for residual risks.

`GET /v1/admin/audit` is served by a dedicated query Lambda. It has the same
administrator JWT authorization as other management routes, but only this role
receives `s3:ListBucket` and `s3:GetObject` on the archive prefix. The normal
administrator Lambda remains write-only. Querying one UTC day reads at most 50
immutable records per page; a caller-bound opaque cursor continues the page.
The query Lambda writes its own audit events, preserving evidence of archive
access without granting its archive-read permission to ordinary handlers.

## Recovery and retention

Recovery runs every five minutes and paginates its due-index query. For a
secret preparation it marks expired workflows retryable and removes the
due-index attributes. If it was an initial create, it conditionally removes the
still-prepared head so the explicit secret ID can be used again; otherwise it
releases the matching head lease. It then audits the failure. It does not repair
partial revision writes or promote a prepared secret head. For an enrollment
preparation it reuses the retained operation ID to resume the version-pinned
truststore publication, writes a terminal success event after a successful
resume, and never marks a certificate active without observed API Gateway
confirmation. It does not silently make a partial S3 write current.

Retention runs daily. It queries only eligible non-head workflows, rereads the
head, checks the precise S3-version lock retention, then uses
`DeleteObjectVersion`. Serving roles cannot delete revision versions.

## CDK topology

The `cdk/` app takes `environment` (default `dev`), `adminFqdn`, `apiFqdn`,
`zoneDomain`, and optional `existingHostedZoneId`. `apiFqdn` is the generic
mTLS delivery endpoint, not a Kubernetes-only name. It rejects
FQDNs outside `zoneDomain` and creates a public zone when no ID is supplied.
The installer must delegate a created zone's output name servers at the parent
zone or registrar. With an existing zone ID, ACM validation and API aliases are
created directly in that zone.

Resources use `RemovalPolicy.DESTROY`; the non-locked truststore and console
buckets use automatic object deletion during stack teardown. Object Lock still
prevents removal of evidence before its compliance retention expires. Roles are
separated: admin can generate payload
data keys and decrypt issuer envelopes and current payloads only with their
respective required contexts; consumer can decrypt referenced payloads;
application roles receive only `PutObject` access to the audit prefix. The
dedicated audit-query Lambda additionally has prefix-scoped list/read access
and the same immutable-write ability needed to record archive views.

## Implementation status

| Capability                                                             | Status                |
| ---------------------------------------------------------------------- | --------------------- |
| Secret create, metadata/ACL update, payload update                     | Implemented           |
| Organizational paths, tags, and admin catalog browse                   | Implemented           |
| Consumer read, ETag, current access snapshot                           | Implemented           |
| Envelope encryption, immutable revisions, Object Lock provisioning     | Implemented           |
| Audit archive, query UI, recovery, and retention                       | Implemented           |
| FQDN-driven CDK deployment                                             | Implemented           |
| CSR enrollment, truststore publication, leaf rotation, leaf revocation | Implemented           |
| Issuer-root rotation and hash-chain seals                              | Deliberately excluded |

[PLAN.md](../PLAN.md) records longer-term issuer-root rotation and audit-boundary
acceptance criteria.
