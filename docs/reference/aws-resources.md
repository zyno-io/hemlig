---
title: AWS resources and IAM
description: Every AWS resource the Hemlig stack creates, which permissions each Lambda holds, the KMS encryption contexts, the schedules and the stack outputs.
pageType: reference
---

# AWS resources and IAM

Every resource the `HemligStack` creates, the permissions each Lambda holds, and the stack outputs. This page is the single home for IAM: other pages link here instead of listing permissions.

In names below, `NAME` is the [deployment name](glossary.md#deployment-name), so a deployment `prod` creates `hml-prod-...` resources. The permissions come from [`cdk/stack.ts`](https://github.com/zyno-io/hemlig/blob/main/cdk/stack.ts) and were checked against the synthesized template.

## Resources

| Resource | Name or detail | Notes |
| --- | --- | --- |
| DynamoDB control table | `hml-NAME-control` | On-demand, AWS-managed encryption, point-in-time recovery, TTL attribute `ttl`, `NEW_IMAGE` stream. Seven global secondary indexes: `workflow-due`, `retention-due`, `catalog-path`, `consumer-directory`, `consumer-identity`, `secret-revision`, `pki-directory`. Keys: [Control-table data model](data-model.md) |
| Application CMK | alias `alias/hml-NAME-application` | One customer-managed key with automatic rotation, or your `existingApplicationKeyArn`. See [KMS contexts](#kms-encryption-contexts) |
| Revision bucket | `hml-NAME-revision...` | Versioned, [Object Lock](glossary.md#object-lock) Compliance, 90-day default retention |
| Audit bucket | `hml-NAME-audit...` | Versioned, Object Lock Compliance, 7-year default retention |
| Truststore bucket | `hml-NAME-truststore...` | Versioned, emptied on teardown. A bucket policy lets API Gateway read `truststores/*` |
| PKI bucket | `hml-NAME-pki...` | Versioned, private, S3-managed encryption, no resource policy beyond TLS-only, emptied on teardown. Holds CRL objects under `crl/`. Output `PkiBucketName` |
| Console bucket | `hml-NAME-console...` | Only with `consoleFqdn`. Private, reached through CloudFront Origin Access Control; noncurrent versions expire after 30 days |
| Console distribution | CloudFront | Only with `consoleFqdn`. See [Console](../guide/console.md) |
| Administrator HTTP API | `hml-NAME-admin` | Custom domain `adminFqdn`, TLS 1.2, default `execute-api` endpoint disabled |
| Delivery HTTP API | `hml-NAME-consumer` | Custom domain `apiFqdn`, TLS 1.2, default endpoint disabled. mTLS is enabled on the domain by the first enrollment |
| Eight Lambdas | `hml-NAME-admin`, `-audit-query`, `-consumer`, `-bootstrap`, `-identity-rotation`, `-notification-publisher`, `-recovery`, `-retention` | Node.js 24, 512 MB, 29-second timeout. X-Ray active tracing only when `tracing` is `true` |
| Three PKI Lambdas | `hml-NAME-pki-admin`, `-pki-issuer`, `-pki-maintenance` | Same runtime settings, except that `pki-maintenance` has a 5-minute timeout. `pki-admin` serves the CA lifecycle, CRL, root CRL upload, issuance grant, administrator issuance, inventory and revoke routes; any other PKI path returns `404` with the message `This PKI route is not available.` `pki-issuer` serves the consumer routes: it lists grants and issues certificates, and an unknown path returns the same `404`. `pki-maintenance` retires expired CAs, publishes due CRLs, disables drained keys, sweeps expired revocation entries, recounts CA capacity and emits the PKI metrics |
| AWS IoT policy | `hml-NAME-agent-notifications` | Connect, subscribe and receive for one private topic per attached thing. No publish, wildcard topic, Shadow, Jobs or AWS credentials |
| Notification dead-letter queue | `hml-NAME-notification-dlq` | Encrypted, messages kept 14 days |
| CloudWatch alarm | `hml-NAME-notification-dlq-not-empty` | Fires when the queue has at least one message (5-minute period) |
| PKI alarms | `hml-NAME-pki-...` (ten) | No actions. `pki-maintenance-errors`, `pki-maintenance-missed`, `pki-generated-crl-stale`, `pki-external-crl-stale`, `pki-external-crl-missing`, `pki-ca-expiring`, `pki-capacity-high`, `pki-crl-over-capacity`, `pki-ca-key-unavailable`, `pki-kms-access-denied`. All but the first two read custom metrics in namespace `Hemlig/PKI` (dimension `Deployment`). Maintenance recounts every active CA's certificates and emits every count each pass, zeros included. `CaCapacityHigh` counts active CAs above 80% of their capacity. The signing paths emit `CaKeyUnavailable` and `KmsAccessDenied`. `pki-maintenance-missed` shows `ALARM` from creation until the first scheduled pass, up to 15 minutes |
| Access logs | `hml-NAME-admin-access`, `hml-NAME-consumer-access` | One-year retention. Only request ID, status, gateway error and authorizer error, never URI, headers, query or body |
| Route 53 and ACM | zone (or yours), alias records, certificate | One regional certificate covers `adminFqdn` and `apiFqdn`. With `consoleFqdn`, a `us-east-1` certificate and `A` and `AAAA` records |

## Routes

| API | Route | Authorization | Lambda |
| --- | --- | --- | --- |
| Administrator | `$default` | OIDC JWT (audience, and scope when set) | admin |
| Administrator | `GET /v1/admin/audit` | OIDC JWT | audit-query |
| Administrator | `POST /v1/bootstrap/redeem` | None; the [bootstrap token](glossary.md#bootstrap-token) is the credential | bootstrap |
| Administrator | `OPTIONS /{proxy+}` | None. Only with `consoleFqdn`; answers CORS preflight | admin |
| Delivery | `$default` | [mTLS](glossary.md#mtls) client certificate | consumer |
| Delivery | `POST /v1/agent/identities/rotate` | mTLS client certificate | identity-rotation |
| Administrator | `GET`, `POST`, `PUT`, `DELETE /v1/admin/pki/{proxy+}` | OIDC JWT (audience, and scope when set) | pki-admin |
| Delivery | `GET`, `POST /v1/pki/{proxy+}` | mTLS client certificate | pki-issuer |

The administrator stage throttles to a burst of 100 and a rate of 50 requests per second, which also bounds the unauthenticated bootstrap route. The delivery stage throttles `POST /v1/pki/{proxy+}` to `pkiIssuanceRateLimit` and `pkiIssuanceBurstLimit` (default 20 and 40). The PKI routes use explicit methods, never `ANY`, so `OPTIONS /{proxy+}` stays the only `OPTIONS` match.

## Schedules and streams

| Trigger | Target | Detail |
| --- | --- | --- |
| EventBridge rule `hml-NAME-recovery` | recovery | Every 5 minutes. Resumes interrupted workflows and reattaches the truststore |
| EventBridge rule `hml-NAME-retention` | retention | Once a day. Deletes expired revision object versions |
| EventBridge rule `hml-NAME-pki-maintenance` | pki-maintenance | Every 15 minutes. Idles until the first CA exists |
| DynamoDB stream | notification publisher | Filtered to `INSERT` of pending `NOTIFICATION#` records. Batches of 10, batch bisecting on error, 5 retries, then the dead-letter queue |

## Permissions by Lambda

Every Lambda also has CloudWatch Logs write access, and `xray:PutTraceSegments` and `xray:PutTelemetryRecords` when `tracing` is on. All values below are the grants in the synthesized stack. The eight existing Lambdas also carry an explicit deny on writes to `PKI_*` items (see [PKI Lambdas](#pki-lambdas)).

| Lambda | DynamoDB | Revision bucket | Audit bucket | Truststore and API Gateway | KMS | IoT | Other |
| --- | --- | --- | --- | --- | --- | --- | --- |
| admin | RW | Mutate | Put | Publish | Generate and decrypt: `issuer-ca`, `secret-payload` | Provision | |
| audit-query | `GetItem`, `PutItem` on keys `CURSOR#*` only | none | `ListBucket` (prefix `audit/*`), `GetObject`, `PutObject` | none | none | none | |
| consumer | RW | Mutate, and bucket read and list | Put | none | Generate and decrypt: `secret-payload` | none | |
| bootstrap | RW | Mutate | Put | Publish | Generate and decrypt: `issuer-ca` | Provision | |
| identity-rotation | RW | none | Put | none | Decrypt only: `issuer-ca` | Provision | |
| notification publisher | RW | none | none | none | none | `iot:Publish` on `hemlig/NAME/consumers/*` | Stream read; `sqs:SendMessage` to the dead-letter queue |
| recovery | RW | Mutate | Put | Publish | none | none | |
| retention | RW | `DeleteObjectVersion`, `GetObjectRetention` only | Put | none | none | none | |

The abbreviations expand to these exact actions.

| Term | Actions | Resource |
| --- | --- | --- |
| RW | `BatchGetItem`, `Query`, `GetItem`, `Scan`, `ConditionCheckItem`, `BatchWriteItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `DescribeTable`, `GetRecords`, `GetShardIterator` | The table and all its indexes |
| Mutate | `s3:GetObject`, `GetObjectVersion`, `GetObjectRetention`, `PutObject`, `PutObjectRetention` | All objects in the revision bucket |
| Bucket read and list | `s3:GetObject*`, `GetBucket*`, `List*` | The revision bucket and its objects |
| Put | `s3:PutObject`, `PutObjectLegalHold`, `PutObjectRetention`, `PutObjectTagging`, `PutObjectVersionTagging`, `Abort*` | `audit/*` in the audit bucket. No read or list |
| Publish | `s3:GetObject`, `PutObject` on `truststores/*`; `apigateway:GET`, `PATCH`, `AddCertificateToDomain`, `RemoveCertificateFromDomain` | The truststore bucket prefix, and the delivery API's custom domain `apiFqdn` only |
| Provision | `iot:AttachPolicy`, `AttachThingPrincipal`, `CreateThing`, `DescribeCertificate`, `RegisterCertificateWithoutCA`, `UpdateCertificate` | `*`. Registers an agent's client certificate with AWS IoT |
| Generate and decrypt | `kms:GenerateDataKey` and `kms:Decrypt`, each conditioned on the listed encryption contexts | The [application CMK](glossary.md#application-cmk) |

Three points follow from the table:

- Only the audit-query role can list or read the [audit archive](glossary.md#audit-archive). It also holds `PutObject`, which its handler never uses: archive reads are not audited.
- Only the retention role can delete revision object versions.
- Only the admin, bootstrap and recovery roles can publish truststores and update the delivery domain. The consumer role cannot unwrap the issuing root.

### PKI Lambdas

The three PKI roles use hand-written statements, never `grantReadWriteData`. Every DynamoDB allow is conditioned with `ForAllValues:StringLike` on `dynamodb:LeadingKeys`, so a role can touch only the listed key prefixes.

`Scan`, `BatchGetItem`, `BatchWriteItem` (allow), `DeleteItem` (allow), PartiQL, `iot:*` and `apigateway:*` are never granted. `TransactWriteItems` has no IAM action of its own: DynamoDB authorizes each item as `PutItem`, `UpdateItem` or `ConditionCheckItem` against its own key, so one key outside the list cancels the whole transaction.

| Lambda | `GetItem` and `Query` (table and `pki-directory`) | `GetItem` only | `PutItem` and `UpdateItem` | `ConditionCheckItem` | KMS (`pki-ca`) | PKI bucket (`crl/*`) |
| --- | --- | --- | --- | --- | --- | --- |
| pki-admin | `PKI_*`, `IDEMPOTENCY#human#*` | `CONSUMER#*`, `AGENT_GRANT#*`, `SYSTEM#ISSUER`, `SYSTEM#ENVIRONMENTS` | `PKI_*`, `IDEMPOTENCY#human#*` | `PKI_*` | Generate and decrypt | Get, put |
| pki-issuer | `PKI_*` | `CONSUMER#*`, `IDENTITY#*`, `AGENT_GRANT#*` | `PKI_*`, `AUDIT_SUPPRESS#*` | `PKI_*`, `IDENTITY#*`, `AGENT_GRANT#*` | Decrypt | Get |
| pki-maintenance | `PKI_*` | none | `PKI_*` | `PKI_*` | Decrypt | Get, put |

All three also hold the audit-bucket `Put` grant. No PKI role has the revision or truststore bucket, or an `issuer-ca` or `secret-payload` context.

- **Identity plane.** An explicit deny blocks every PKI role from writing `IDENTITY#`, `CONSUMER#`, `AGENT_GRANT#`, `TRUSTSTORE#`, `SYSTEM#`, `ENROLLMENT#` and `BOOTSTRAP#` items. `pki-issuer` can only read them and use them in `ConditionCheckItem`.
- **Existing roles.** They can still read `PKI_*` items but cannot write them. A wrapped CA key they might read is useless without `pki-ca` decrypt.
- **Residual risk, administrator replays.** The shared `IDEMPOTENCY#human#*` write lets a compromised `pki-admin` overwrite non-PKI administrator replay records, because IAM cannot scope the sort key. The impact is limited to confused administrator replays.
- **Residual risk, audit suppression.** The `AUDIT_SUPPRESS#*` write of `pki-issuer` can suppress other fingerprints' rejection audits.

## KMS encryption contexts

One CMK protects both payloads and the issuing root. The two uses are separated by the `purpose` [encryption context](glossary.md#encryption-context), always with `service=hemlig`. No role has an unconditioned grant on the key.

| Context `purpose` | Protects | Generate | Decrypt |
| --- | --- | --- | --- |
| `secret-payload` | Secret [payload](glossary.md#payload) envelopes | admin, consumer | admin, consumer |
| `issuer-ca` | The [issuing root](glossary.md#issuing-root) private key | admin, bootstrap | admin, bootstrap, identity-rotation |
| `pki-ca` | A PKI CA private key (wrapped data key, with `caId` and `environment` also in the context) | pki-admin | pki-admin, pki-issuer, pki-maintenance |

The `pki-ca` grants additionally require `kms:EncryptionContextKeys` to be exactly `service`, `purpose`, `caId` and `environment`, and both `caId` and `environment` to be present. The existing roles' grants match `purpose` of `issuer-ca` or `secret-payload` only, so none of them can use `pki-ca`.

The identity-rotation Lambda has no generate permission on purpose: a missing issuing root must fail rather than mint a new one. Mechanics: [Secrets, revisions and encryption](../guide/secrets-and-encryption.md).

## Stack outputs

| Output | Present | Value |
| --- | --- | --- |
| `AdminUrl` | always | `adminFqdn` as an `https` URL |
| `ApiUrl` | always | `apiFqdn` as an `https` URL: the mTLS delivery API |
| `IotEndpoint` | always | AWS IoT data endpoint, resolved at deploy time |
| `AdminOidcIssuer` | always | `oidcIssuer` |
| `AdminOidcAudience` | always | `oidcAudience` |
| `AdminOidcScope` | with `oidcAdminScope` | `oidcAdminScope` |
| `AdminOidcRole` | with `oidcAdminRole` | `oidcAdminRole` |
| `RevisionBucketName` | always | Revision bucket |
| `AuditBucketName` | always | Audit bucket |
| `PkiBucketName` | always | PKI bucket |
| `CreatedHostedZoneNameServers` | when the stack created the zone | Comma-separated name servers to delegate |
| `ConsoleUrl` | with `consoleFqdn` | `consoleFqdn` as an `https` URL |
| `ConsoleBucketName` | with `consoleFqdn` | Console bucket |
| `ConsoleDistributionId` | with `consoleFqdn` | CloudFront distribution |
| `ConsoleAssetsPending` | with `consoleFqdn`, when the build output was missing at synth | A reminder to publish the console assets yourself |

## Teardown

All resources use `RemovalPolicy.DESTROY`. The truststore, PKI and console buckets empty automatically. The revision and audit buckets cannot be emptied until Object Lock retention ends (90 days, 7 years), which can block stack deletion. See [Limits](limits.md#storage-and-retention).
