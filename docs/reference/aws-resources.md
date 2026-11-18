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
| DynamoDB control table | `hml-NAME-control` | On-demand, AWS-managed encryption, point-in-time recovery, TTL attribute `ttl`, `NEW_IMAGE` stream. Six global secondary indexes: `workflow-due`, `retention-due`, `catalog-path`, `consumer-directory`, `consumer-identity`, `secret-revision`. Keys: [Control-table data model](data-model.md) |
| Application CMK | alias `alias/hml-NAME-application` | One customer-managed key with automatic rotation, or your `existingApplicationKeyArn`. See [KMS contexts](#kms-encryption-contexts) |
| Revision bucket | `hml-NAME-revision...` | Versioned, [Object Lock](glossary.md#object-lock) Compliance, 90-day default retention |
| Audit bucket | `hml-NAME-audit...` | Versioned, Object Lock Compliance, 7-year default retention |
| Truststore bucket | `hml-NAME-truststore...` | Versioned, emptied on teardown. A bucket policy lets API Gateway read `truststores/*` |
| Console bucket | `hml-NAME-console...` | Only with `consoleFqdn`. Private, reached through CloudFront Origin Access Control; noncurrent versions expire after 30 days |
| Console distribution | CloudFront | Only with `consoleFqdn`. See [Console](../guide/console.md) |
| Administrator HTTP API | `hml-NAME-admin` | Custom domain `adminFqdn`, TLS 1.2, default `execute-api` endpoint disabled |
| Delivery HTTP API | `hml-NAME-consumer` | Custom domain `apiFqdn`, TLS 1.2, default endpoint disabled. mTLS is enabled on the domain by the first enrollment |
| Eight Lambdas | `hml-NAME-admin`, `-audit-query`, `-consumer`, `-bootstrap`, `-identity-rotation`, `-notification-publisher`, `-recovery`, `-retention` | Node.js 24, 512 MB, 29-second timeout, X-Ray active tracing |
| AWS IoT policy | `hml-NAME-agent-notifications` | Connect, subscribe and receive for one private topic per attached thing. No publish, wildcard topic, Shadow, Jobs or AWS credentials |
| Notification dead-letter queue | `hml-NAME-notification-dlq` | Encrypted, messages kept 14 days |
| CloudWatch alarm | `hml-NAME-notification-dlq-not-empty` | Fires when the queue has at least one message (5-minute period) |
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

The administrator stage throttles to a burst of 100 and a rate of 50 requests per second, which also bounds the unauthenticated bootstrap route.

## Schedules and streams

| Trigger | Target | Detail |
| --- | --- | --- |
| EventBridge rule `hml-NAME-recovery` | recovery | Every 5 minutes. Resumes interrupted workflows and reattaches the truststore |
| EventBridge rule `hml-NAME-retention` | retention | Once a day. Deletes expired revision object versions |
| DynamoDB stream | notification publisher | Filtered to `INSERT` of pending `NOTIFICATION#` records. Batches of 10, batch bisecting on error, 5 retries, then the dead-letter queue |

## Permissions by Lambda

Every Lambda also has CloudWatch Logs write access and `xray:PutTraceSegments` and `xray:PutTelemetryRecords`. All values below are the grants in the synthesized stack.

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

## KMS encryption contexts

One CMK protects both payloads and the issuing root. The two uses are separated by the `purpose` [encryption context](glossary.md#encryption-context), always with `service=hemlig`. No role has an unconditioned grant on the key.

| Context `purpose` | Protects | Generate | Decrypt |
| --- | --- | --- | --- |
| `secret-payload` | Secret [payload](glossary.md#payload) envelopes | admin, consumer | admin, consumer |
| `issuer-ca` | The [issuing root](glossary.md#issuing-root) private key | admin, bootstrap | admin, bootstrap, identity-rotation |

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
| `CreatedHostedZoneNameServers` | when the stack created the zone | Comma-separated name servers to delegate |
| `ConsoleUrl` | with `consoleFqdn` | `consoleFqdn` as an `https` URL |
| `ConsoleBucketName` | with `consoleFqdn` | Console bucket |
| `ConsoleDistributionId` | with `consoleFqdn` | CloudFront distribution |
| `ConsoleAssetsPending` | with `consoleFqdn`, when the build output was missing at synth | A reminder to publish the console assets yourself |

## Teardown

All resources use `RemovalPolicy.DESTROY`. The truststore and console buckets empty automatically. The revision and audit buckets cannot be emptied until Object Lock retention ends (90 days, 7 years), which can block stack deletion. See [Limits](limits.md#storage-and-retention).
