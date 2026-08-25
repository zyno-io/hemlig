# Hemlig implementation plan

## Scope and ownership

This repository is a publishable open-source Yarn Berry monorepo for Hemlig, a
Consumer Secrets API. It owns:

- Lambda handlers and recovery worker;
- the OpenAPI contract, request/response validation, and AWS adapters;
- envelope encryption, DynamoDB state transitions, audit emission, and
  certificate identity validation;
- unit and MiniStack integration tests; and
- the reusable CDK construct, reference app, and AWS resource topology.

It also contains a Kubernetes import/export controller and a Pulumi dynamic
provider. Both consume the typed `@hemlig/client` package; neither imports
Lambda code or provisions a parallel AWS service topology.

Each Hemlig installation consumes the `hemlig/cdk` construct from its own CDK
app and deployment pipeline. The construct accepts administrator and consumer
API FQDNs, an environment name, a zone domain, and optionally an existing Route
53 hosted-zone ID. It creates the hosted zone when no ID is supplied; users
then delegate the resulting name servers. The consumer's stack provisions the
account-local IAM, S3, DynamoDB, KMS, API Gateway, DNS, ACM, Lambda, and
schedules using Hemlig's resource definitions. It receives an
organization-owned OIDC issuer, audience, and stable actor claim rather than
provisioning an identity provider. Every physical resource it names starts with
`hml-<environment>-`; it contains no organization-specific account IDs,
domains, or credentials.
The Kubernetes `HemligSecretImport`/`HemligSecretExport` CRDs and their
controller are a dedicated workspace. Import materializes an mTLS-authorized
Hemlig payload as a Kubernetes Secret; export reconciles a Kubernetes Secret
through the administrator API. The Pulumi workspace declaratively manages
Hemlig secret control-plane resources and retains a secret on destroy because
the service has no delete endpoint.

V1 is the Lambda/S3/DynamoDB/KMS service only. MQTT notification, a
consumer-side write/publication API, and hash-chained audit seals are excluded.

## Fixed design decisions

1. Use TypeScript on the current supported Node Lambda runtime. Build two
   deployable entry points from one domain library: `admin` and `consumer`.
   Add scheduled `recovery` and `retention` entry points. Ship `audit-query`
   only as an optional handler for deployment in a consumer's audit boundary;
   the normal secrets-service roles cannot read the audit archive.
2. Use API Gateway HTTP API payload format 2.0. The consumer handler obtains
   the peer leaf from `requestContext.authentication.clientCert.clientCertPem`,
   converts it to DER, and looks up its SHA-256 fingerprint with a strongly
   consistent DynamoDB read. It never accepts a consumer ID from the request.
3. Payloads are a JSON object of Kubernetes Secret entries. Each entry is
   either a UTF-8 string or explicitly encoded binary bytes; schema validation
   rejects duplicate/invalid keys and caps the serialized plaintext at 750 KiB.
   The consumer response contains only the payload and immutable ID/version
   metadata required by the operator.
4. Encrypt each revision with a fresh 256-bit KMS data key and AES-256-GCM.
   Bind both KMS encryption context and GCM additional authenticated data to
   `{service, purpose=secret-payload, environment, secretUid, payloadVersionId}`. Store the encrypted
   data key, 96-bit IV, authentication tag, ciphertext, and ciphertext-object
   SHA-256; discard plaintext data-key bytes immediately.
5. Split immutable secret state into control and payload revisions, each at a
   new S3 key. A control revision holds metadata, ACL, state, and the referenced
   payload revision; a payload revision holds only its encrypted envelope.
   This lets metadata/ACL changes remain immutable without KMS decryption or
   re-encryption. DynamoDB is the current authorization/query index.
6. Application audit is direct, one S3 object per event in the CDK-provisioned
   immutable archive. It uses a random UUID/ULID key under
   `audit/YYYY/MM/DD/`, `If-None-Match: *`, and S3 Object Lock **COMPLIANCE**
   default retention of seven years. The write-only role receives only
   `PutObject` on its prefix. It has no `Get*`, `Delete*`, retention, Object
   Lock, or bucket-policy permissions. Unique keys are essential: Object
   Lock retains an old version but does not stop a new version at the same key.
7. Do not add a hash chain in V1. S3 Compliance retention plus a separate
   archive/prefix and CloudTrail data events satisfies the stated immutable
   retention requirement with less state. A compromised service could still
   produce misleading new events; hash-chain seals are a separately approved
   tamper-evidence enhancement, not a claim made by V1.
8. The change endpoint returns a paginated _current access snapshot_, rather
   than an unbounded change journal. At this fleet size the operator scans
   all current rows every reconciliation, compares revision/state annotations,
   and converges. Revoked access remains as a tombstone so prior recipients
   are told to remove the locally managed Secret.

## Repository layout

```text
openapi/consumer-secrets.yaml      # endpoint and JSON-schema source of truth
src/
  handlers/{admin,consumer,recovery,retention,audit-query}.ts
  domain/                          # commands, policies, state-machine types
  auth/                            # OIDC actor and mTLS identity extraction
  crypto/envelope.ts               # KMS + AES-GCM, no logging of material
  repositories/{dynamo,s3,audit}.ts
  services/{secrets,consumers,truststore,changes}.ts
cdk/                                  # published construct, reference app, stack tests
  aws/config.ts                    # validated deployment-supplied configuration
test/{unit,integration,contract}/
docs/cdk-integration.md            # Hemlig CDK deployment guide
docs/threat-model.md               # assumptions, residual risks, WORM semantics
README.md                          # quick start and non-production safety notes
SECURITY.md                         # supported versions and disclosure process
LICENSE                             # chosen before the first public release
docker-compose.ministack.yml
scripts/{build,seed-ministack,verify-ministack}.ts
```

The domain layer depends on small interfaces for the clock, random-ID source,
KMS, S3, DynamoDB, API Gateway domain updater, and audit writer. Lambda
handlers only adapt HTTP events to validated commands. This keeps policy and
failure-path tests fast and makes MiniStack a transport/storage integration
test rather than a prerequisite for every test.

## State and storage model

Use one DynamoDB table with `PK`/`SK`, transactions, and point-in-time
recovery. A lease-expiry/index attribute identifies live expired preparations
for recovery; TTL is set only after an idempotency or workflow record has
reached a terminal state and its documented cleanup delay has elapsed. TTL
must never remove a `PREPARED` record that recovery still needs.

| Key                                          | Role                                                                                                                                |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `SECRET#<uid> / HEAD`                        | current control/payload versions, state, write lease, and current path/tag catalog projection; the control version is the HTTP ETag |
| `SECRET#<uid> / CONTROL#<id>`                | immutable metadata/ACL/state/payload-pointer revision, S3 version/checksum, and retention state                                     |
| `SECRET#<uid> / PAYLOAD#<id>`                | encrypted-envelope workflow metadata, S3 version/checksum, and retention state                                                      |
| `SECRET_NAME#<environment>#<id> / LOOKUP`    | external name to immutable UID lookup                                                                                               |
| `IDENTITY#<der-sha256> / PROFILE`            | consumer/environment, leaf type, validity, active/revoked state                                                                     |
| `CONSUMER#<id> / PROFILE`                    | immutable environment, SPIFFE identity, and enrollment state                                                                        |
| `CONSUMER#<id> / SECRET#<environment>#<uid>` | current permission/revision/state; a retained `REVOKED` tombstone is the change feed                                                |
| `SYSTEM#ISSUER / PROFILE`                    | one public issuing root, KMS-wrapped private-key envelope, fingerprint, and validity                                                |
| `TRUSTSTORE#ROOTS / ROOT#<fingerprint>`      | public deployment-wide issuing root used by every consumer                                                                          |
| `ENROLLMENT#<operation> / STATE`             | recoverable pending enrollment/leaf-issuance workflow                                                                               |
| `SYSTEM#TRUSTSTORE / STATE`                  | singleton publication lease plus current/pending root set and version-pinned bundle                                                 |
| `IDEMPOTENCY#<actor>#<key> / REQUEST`        | request digest, operation/response state, terminal audit event key/status, terminal cleanup TTL                                     |

Three sparse GSIs support scheduled/catalog work without a table scan:
`WORKFLOW#DUE` orders non-terminal secret and enrollment preparations by lease
expiry, `RETENTION#DUE` orders non-head revision candidates by the end of their
90-day lock period, and `CATALOG#<environment>` orders current `HEAD` records
by organizational path. Each worker re-reads the primary record and applies
its conditional state transition before acting.

The consumer/secret row replaces separate grant and access-projection rows. It
keeps an ACL replacement from ten old readers to ten new readers within
DynamoDB's 25-item transaction limit: 20 affected rows, one new control
record, the previous-control retention update, and the head. The old control
revision supplies the old ACL for the union calculation. A payload change
creates new payload/control records, updates prior control/payload retention,
updates the head, and touches no more than ten reader rows. This corrects the
separate-grant/projection shape, which can exceed the transaction limit even
with a ten-consumer ACL cap.

Secret revisions use:

```text
secrets/<secret-uid>/control/<control-version-id>.json
secrets/<secret-uid>/payload/<payload-version-id>.json
```

Every object is written conditionally with `If-None-Match: *` and an S3
checksum. A control object contains approved metadata, ACL snapshot, state,
and payload-version pointer; a payload object contains the encrypted envelope.
Neither returns an S3 access URL to a client.

The revision bucket is versioned and Object-Lock-enabled at creation. Each
control/payload object receives the bucket's initial 90-day Compliance
retention. Before a head can be superseded, the mutation/recovery workflow
extends each exact old S3 object version to at least `now + 91 days`. It then
switches the head in the same bounded attempt; recovery repeats the extension
with a fresh date before any delayed finalisation. The one-day safety margin
guarantees at least 90 days from the actual head transition, while a failed
finalisation merely leaves the still-current revision locked longer. After the
recorded retention date, a separate handler may delete only the recorded S3
version of an object no longer referenced by a `HEAD`; no request-serving role
can delete revisions. Thus superseded revisions are WORM for at least 90 days
after supersession, then eligible for controlled cleanup. They are not the
seven-year audit record.

Audit events use:

```text
audit/<yyyy>/<mm>/<dd>/<event-id>.json
```

An event records UTC time, correlation ID, `attempted`/`authorized`/
`succeeded`/`failed` outcome, stable actor, operation, target IDs/revision,
permission result, source IP, and safe reason code. It never contains secret
values, request bodies, authorization tokens, certificates/private keys, or
KMS context values. The audit writer retries bounded transient failures.

After an application actor has been resolved, mutations and secret-value reads
emit the applicable outcome sequence, including a `304` secret read,
enrollment, rotation, and revocation. A decrypted payload or a successful route
response is never returned until its terminal audit write has succeeded. Routine
metadata, configuration, change-feed, and audit-archive reads are not recorded.
TLS or JWT failures rejected before an actor exists are outside this application
event stream and belong in API Gateway access/control-plane logs. The idempotency
record records terminal-audit status after the write, but the two writes are not
one atomic cross-service transaction: an interruption between them can require
operator reconciliation. The implementation does not claim exactly-once
terminal audit events or automatic repair of that ambiguous case. It emits a
safe failed event when possible and alarms on audit-delivery failure; an audit
failure cannot itself always be audited.

## Command workflows

### Enrollment and truststore updates

1. Validate a signed, single RSA CSR (at least 2048-bit public key). Create the
   one self-signed issuing root on first use, and AES-GCM-envelope encrypt its
   private key with the existing Hemlig application CMK using
   `{service: hemlig, purpose: issuer-ca}`. Never accept a private key.
2. Sign the CSR with a non-CA client leaf whose identity extensions are set by
   Hemlig, then transactionally create `PENDING` consumer and API-leaf identity
   records using an actor-scoped idempotency key. The root is a permanent,
   active, deployment-wide truststore anchor rather than a per-consumer record.
3. Acquire the conditional singleton truststore-publication lease. Query every
   page of active roots, sort and deduplicate by fingerprint, and preflight the
   1,000-certificate/1 MiB API Gateway truststore limits. If those fingerprints
   match the current bundle, reuse its exact object reference; otherwise persist
   the new root set/object reference and upload a unique bundle object.
4. When the root set changed, update the custom domain to that exact S3 object
   version. In either case, read the domain configuration until its observed
   truststore version matches, there
   are no warnings, and every domain configuration is `AVAILABLE`. Only then
   transactionally activate this operation's leaf identity and release
   the generation lease. If API Gateway reports warnings, restore the previous
   known version when one exists, fail this operation, and release the lease.
5. The recovery handler resumes an expired generation from its persisted state
   and verifies domain state before activation. It never activates an identity
   merely because a bundle upload succeeded.

Leaf rotation accepts another CSR and creates an overlapping active identity
under the same deployment root. Revocation updates that identity to `REVOKED`
with strongly consistent read enforcement before any slower truststore change.

Issuer-root rotation remains deliberately unimplemented; it requires a
separately reviewed overlap, migration, and retirement protocol. It is not a
reason to create a root or KMS key per consumer.

### Secret creation and mutation

`POST /v1/admin/secrets` creates a `PENDING_VALUE` control revision with its
immutable environment and initial ACL. Metadata/ACL and payload commands
require the current control-version ETag in `If-Match`; the idempotency key is
required for all mutations. An ACL/metadata edit creates a new control revision
that retains the existing payload pointer. A payload update creates a fresh
payload revision and a new control revision pointing to it. The service never
decrypts an old payload just to update its ACL or description.

`POST /v1/admin/secrets/{secretId}/archive` creates an `ARCHIVED` control
revision with an empty ACL, moves its UID-backed head to the archive catalog,
and deletes the live name lookup in the same final DynamoDB transaction. The
secret ID is therefore immediately reusable by a different UID, while archived
details remain addressable only by the original UID.

For every secret mutation:

1. Validate the stable actor claims supplied by the API Gateway JWT authorizer
   and write `authorized` audit evidence. Record the configured immutable
   subject (and optional tenant) claims, never an email/display name.
2. Materialize the new canonical control object and, when replacing a payload,
   generate the data key and materialize its encrypted envelope. Compute final
   version IDs, object keys, and checksums _before_ acquiring any DynamoDB
   lease; a crash in this in-memory phase leaves no durable lock.
3. In one DynamoDB transaction, condition on the expected head and new
   idempotency key, acquire the head lease, and create indexed `PREPARED`
   control/payload records with their checksums, expiry, and finalisation
   intent. Recovery can therefore see every durable lease.
4. Conditionally write all new S3 objects, record the returned S3 version IDs,
   and immediately drop plaintext data-key/payload buffers as far as Node
   permits. Before switching the head, extend the exact prior control/payload
   S3 versions to `now + 91 days` in Compliance mode. If this fails, retain the
   old head and leave the preparation recoverable. In a final DynamoDB
   transaction, finalise the records/head, record the applied retention time
   for replaced versions, and atomically update each affected current
   consumer/secret row. ACL updates include revocation tombstones; payload
   updates advance the payload pointer for existing readers.
5. Write terminal audit success, persist its event ID in the idempotency state,
   and only then return the new control ETag and version references. These
   actions are deliberately ordered for evidence-before-response, but are not
   an atomic transaction across S3 and DynamoDB.

The scheduled recovery handler scans every page of expired `PREPARED` records.
For a secret preparation it marks the workflow `RETRYABLE`, removes it from the
due index, and emits a failure event. It conditionally deletes the still-
prepared head for an initial create; for an update it releases the matching head
lease. The consumed idempotency key remains unavailable, but an explicitly
named aborted secret can be created again with a new key. Recovery does not
inspect or repair partial S3 writes or promote a prepared head. Those stronger
reconciliation guarantees are future hardening work; operators must reconcile
an ambiguous failed request before submitting a new mutation. Enrollment
recovery instead resumes the persisted version-pinned truststore publication
and never activates an identity without confirmed API Gateway domain state.

### Consumer reads and reconciliation

For every consumer request, parse the client PEM into DER, hash it, strongly
consistently read `IDENTITY#...`, require `ACTIVE` and unexpired `api` identity,
then derive the consumer/environment from that record.

`GET /v1/secrets/{id}` strongly reads the matching consumer/secret row, requires
`read`, and checks its environment against both the resolved consumer and head.
Its HTTP `ETag` is the control version; a successful body includes both
`controlVersionId` and `payloadVersionId`, and the operator records both
annotations. This makes an ACL/metadata state change observable even when the
payload bytes are unchanged.
It writes attempted/authorized audit evidence first. If `If-None-Match` matches
the current version, it writes a terminal `succeeded` event with `notModified`
before returning 304, without S3/KMS work. Otherwise it loads the referenced
control/payload revisions, verifies their checksums and binding, calls KMS
`Decrypt` with the exact context, GCM-decrypts, writes terminal audit success,
and only then returns the payload over mTLS.

`GET /v1/changes` queries the consumer's `SECRET#` rows in secret-ID order and
returns `{secretId, controlVersionId, payloadVersionId, state, changeKind}`
with an opaque, short-lived pagination cursor bound to that consumer. Its
server-side continuation state is held in the control table, not in a separate
secret. A reconciliation cycle starts without a cursor and completes when
`nextCursor` is absent. An active row tells the operator what it should have;
a tombstone tells it to delete the operator-managed Kubernetes Secret. The
caller does not receive metadata, ACLs, or payloads from this endpoint and is
not audited as a secret-value read.

## CDK deployment contract

The published `hemlig/cdk` entry point bundles the four standard handler
sources with the construct. A release publishes those sources, the construct,
the reference CDK app, OpenAPI document, and deployment documentation together.
The consumer owns `App`, stack ID, account/region, and deployment pipeline; the
Hemlig deployment input is intentionally small:

```text
environment=dev
adminFqdn=admin.dev.example.com
apiFqdn=api.dev.example.com
zoneDomain=dev.example.com
oidcIssuer=https://login.example.com/tenant/v2.0
oidcAudience=api://hemlig
oidcSubjectClaim=sub                    # optional; default
existingHostedZoneId=Z0123456789ABCDEF  # optional
```

Omitting `existingHostedZoneId` creates a public hosted zone and outputs the
name servers to delegate. Providing it makes the stack add all ACM validation
and API alias records to that existing zone. The FQDNs must be distinct and
within `zoneDomain`; validation fails before synthesis otherwise.

The CDK app injects the following runtime configuration. `apiFqdn` is the
generic mTLS delivery endpoint (not a Kubernetes-only hostname). Pagination
cursors are opaque 256-bit tokens whose bounded server-side state is stored in
the existing control table and expires through its TTL attribute. This avoids a
separate secret or key-management path. The stack passes the installer-supplied
external OIDC issuer/audience and stable actor claim to the administrator JWT
authorizer:

```text
AWS_REGION
CONTROL_TABLE_NAME
WORKFLOW_DUE_INDEX
RETENTION_DUE_INDEX
CATALOG_PATH_INDEX
REVISION_BUCKET_NAME
TRUSTSTORE_BUCKET_NAME
TRUSTSTORE_KEY_PREFIX
PAYLOAD_KMS_KEY_ARN
HEMLIG_ENVIRONMENT
AUDIT_BUCKET_NAME
AUDIT_PREFIX
DELIVERY_API_CUSTOM_DOMAIN_NAME
DELIVERY_API_HOSTNAME
ADMIN_JWT_ISSUER
ADMIN_JWT_AUDIENCE
ADMIN_ACTOR_SUBJECT_CLAIM
MAX_PAYLOAD_BYTES=768000
```

The default administrator actor is the external provider's immutable `sub`
claim. Function-specific IAM is split as follows:

- **admin:** table mutation; revision-control `GetObject`; control/payload
  `PutObject`; exact-current-version `GetObjectRetention`/`PutObjectRetention`;
  KMS `GenerateDataKey` and context-limited `Decrypt` only for
  `purpose=issuer-ca`; CSR signing; truststore writes plus `UpdateDomainName`;
  audit `PutObject`;
- **consumer:** strongly consistent table reads; referenced control/payload
  `GetObject`; KMS `Decrypt`; audit `PutObject`; no truststore or table
  mutation;
- **recovery:** prepared-record/head mutation; revision `HeadObject` and
  exact-current-version
  `GetObjectRetention`/`PutObjectRetention`; truststore writes plus narrowly
  scoped `GetDomainName`/`UpdateDomainName`; audit `PutObject`; no normal read
  endpoint;
- **retention:** query only the eligible-revision index, strongly read heads,
  use `GetObjectRetention` and `DeleteObjectVersion` only on the recorded S3
  version after its Object Lock expiry; no KMS, API, truststore, or audit-
  archive permissions;
- **audit-query (optional):** deploy in the audit boundary/account with its
  own narrowly scoped archive-read role and a distinct write-only
  audit-query-events prefix. It is never part of the normal secrets-service
  stack or given to its roles.

CDK configures a versioned, Object-Lock-enabled revision bucket with a 90-day
Compliance default; a versioned truststore bucket; and an Object-Lock-enabled
audit bucket with a seven-year Compliance default. All buckets use SSE-S3,
Block Public Access, and HTTPS-only bucket policies. It creates one application
CMK shared by payload and issuer envelopes,
HTTP API v2 routes with an external-OIDC JWT authorizer, custom-domain DNS/ACM,
and scheduled recovery and retention invocations. Both HTTP APIs disable their
default execute-api endpoint. Resources use `RemovalPolicy.DESTROY`; the
non-locked truststore and console buckets are emptied automatically during
stack deletion. Object Lock still controls deletion of evidence objects.

The runtime role needs permission to update the consumer-domain truststore;
that is application lifecycle behavior, not a deployment pipeline privilege.
The deployment creates the consumer domain without a truststore. The enrollment
workflow publishes and pins the first versioned truststore before activating a
consumer identity; until then, no consumer request can pass the application
identity check. The deployment never receives application payload plaintext.

## Validation plan

### Unit and contract tests

- OpenAPI validation, error envelopes, ETags, input size/secret-entry rules,
  opaque cursor binding/expiry, and idempotency request-digest conflicts.
- CSR signature/key-size checks, issuer-envelope KMS context binding, issued
  CA/leaf/EKU/SAN validation, identity revocation, environment mismatch, and no
  caller-supplied consumer ID.
- AES-GCM happy/incorrect-AAD/tampered-tag paths; KMS/GCM binding to the
  payload—not control—version; and no log serializer accepts payload/key/
  certificate fields.
- Prepared-work crash points: before/during in-memory materialization, after
  the atomic lease/preparation transaction before object write, partial
  control/payload write, after all S3 writes before DynamoDB, after DynamoDB
  before terminal audit, and duplicate retries. Assert every durable lease has
  an indexed recovery record.
- Transaction-limit test for a complete 10-to-10 ACL replacement; old readers
  receive tombstones and new readers receive only current state.
- Concurrent enrollment/truststore generation, expired publication recovery,
  stable single-root truststore contents, and leaf-rotation transitions.
- Control/payload version and ETag semantics; 90-day retention measured from
  supersession; exact-S3-version retention extension before the head switch,
  deletion, and extension-failure no-switch behavior; and an admin role denied
  payload `kms:Decrypt` outside the issuer context.
- Route-by-route audit assertions for authorization failures, `304`, changes,
  enrollment/rotation/revocation, and the invariant that a plaintext response
  has a terminal immutable event first.

### MiniStack integration tests

Pin a known MiniStack image version in Compose. Configure every AWS SDK
client with the local endpoint and path-style S3, use isolated bucket/table/key
names per test, and seed an Object-Lock-enabled audit bucket, revision bucket,
table, and symmetric KMS key.

Exercise real SDK calls for `GenerateDataKey`/`Decrypt`, AES-encrypted S3
revision storage, DynamoDB conditional writes and transactions, idempotency,
recovery, audit object key uniqueness/retention/delete denial, `If-None-Match`
reads, conditional S3 revision writes, and Lambda HTTP-event adapters. Run
these tests in CI with a fresh emulator state.

MiniStack is deliberately not the final authority for IAM policy evaluation,
OIDC JWT authorizer behavior, custom-domain mTLS, API Gateway truststore
propagation, CloudTrail delivery, or S3 Compliance retention administration.
Add a small isolated AWS staging acceptance suite for those controls before
production, including a real mutual-TLS request with an active, revoked, and
unregistered leaf. It must assert that the default execute-api endpoint is
disabled, that the application role cannot read or delete the audit prefix,
and that the revision/audit bucket Object Lock defaults match the intended
90-day/seven-year Compliance policies.

## Delivery order and exit criteria

1. **Foundation:** repository/toolchain, OpenAPI, configuration validation,
   release manifest, interfaces, domain errors, test fixtures, MiniStack
   Compose, and the self-contained Hemlig CDK stack.
2. **Identity:** OIDC actor extraction, CSR enrollment and issuance, serialized
   truststore publication/recovery, leaf rotation, and revocation.
3. **Secrets:** envelope codec, prepared revision protocol, optimistic
   concurrency, ACL/tombstone projection, current-snapshot change endpoint,
   consumer read endpoint, and idempotency.
4. **Evidence/operations:** audit writer, recovery and retention workers,
   optional audit-boundary query handler, structured safe logs/metrics, alarms/
   runbook inputs, and failure-drill tests.
5. **Public release:** publish the README, threat model, CDK integration guide,
   `SECURITY.md`, compatibility matrix, chosen license, signed/tagged release
   bundle, and its checksum manifest. Make clear that MiniStack does not prove
   production IAM/mTLS/Object-Lock controls.
6. **Installation acceptance:** the installer CDK-synths/asserts the Hemlig
   stack topology and least-privilege policies, deploys an isolated staging
   environment, and executes the AWS-only security suite. It then performs a
   limited initial credential migration with its separate operator project. No
   production secret is migrated until audit retention, revocation, repair,
   and regional-outage drills pass.

## References

- [API Gateway HTTP API mutual TLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)
- [HTTP API Lambda payload format 2.0](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS CDK removal policies](https://docs.aws.amazon.com/cdk/v2/guide/resources.html)
- [MiniStack S3 service coverage and limitations](https://ministack.org/docs/services/s3)
