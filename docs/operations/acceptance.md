---
title: AWS acceptance runbook
description: Ordered gates that validate a real AWS deployment of Hemlig for everything the local MiniStack emulator cannot prove.
pageType: how-to
---

# AWS acceptance runbook

Run these ordered gates in an isolated AWS account to prove what only a real deployment can: API Gateway, mTLS, CloudFront, IAM and Object Lock.

[MiniStack](../reference/glossary.md#ministack) exercises the AWS SDK integrations against a local emulator, but it is deliberately not evidence for anything AWS itself enforces. `yarn test` and `yarn ministack:verify` already cover KMS envelopes, conditional S3 writes, DynamoDB transactions, idempotency and recovery.

**Before you start**

- An isolated AWS account. The stack creates Object Lock Compliance buckets whose objects cannot be deleted for 90 days and 7 years.
- A Route 53 hosted zone you control, and the ability to delegate it if the stack creates one.
- An identity-provider registration that can issue an **access token** (not just an ID token) with your audience and `oidcAdminScope`. See [Connect your identity provider](../guide/identity-provider.md).
- An ACM certificate in `us-east-1` covering the console host. See [Console](../guide/console.md#the-certificate).
- About two hours, plus the retention wait at [teardown](#teardown).

Gates are ordered so failures stop you at the cheapest point. Gate 1 breaks every later gate, so do not skip ahead.

## Gate 0: the stack deploys

Set the example values once, synthesize without touching AWS, then deploy.

```sh
export CTX="-c environment=acc \
  -c adminFqdn=admin.acc.example.com \
  -c apiFqdn=api.acc.example.com \
  -c consoleFqdn=acc.example.com \
  -c zoneDomain=acc.example.com \
  -c existingHostedZoneId=Z0123456789ABCDEF \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=00000000-0000-0000-0000-000000000000 \
  -c oidcAdminScope=hemlig.admin \
  -c oidcConsoleAccessScope=api://00000000-0000-0000-0000-000000000000/hemlig.admin \
  -c oidcClientId=11111111-1111-1111-1111-111111111111 \
  -c consoleCertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"
yarn cdk:synth $CTX --quiet
yarn cdk:deploy $CTX
```

| Check | Pass | Fail means |
| --- | --- | --- |
| `cdk:synth` | Exits `0` without AWS credentials | A config rule failed, and the message names it. `consoleFqdn` requires `oidcAdminScope`, `oidcConsoleAccessScope` and `oidcClientId` |
| `cdk:deploy` | Completes and prints `AdminUrl`, `ApiUrl`, `ConsoleUrl` and `ConsoleDistributionId` | A CloudFormation error. Read the failing resource |
| No `ConsoleAssetsPending` output | Absent | The console build was missing at synth time and every request returns `403`. Run `yarn console:build` and redeploy |

## Gate 1: CORS preflight

**This is the highest-risk item.** Everything later depends on it, and MiniStack has no API Gateway.

The admin API uses a `$default` catch-all with a JWT authorizer, which also catches `OPTIONS`. The stack adds an unauthenticated `OPTIONS /{proxy+}` route to outrank it.

```sh
curl -i -X OPTIONS https://admin.acc.example.com/v1/admin/secrets \
  -H 'origin: https://acc.example.com' \
  -H 'access-control-request-method: POST' \
  -H 'access-control-request-headers: authorization,idempotency-key,if-match'
```

Also count audit objects before and after the request:

```sh
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Status | `204` | `401`: the explicit `OPTIONS` route is not outranking `$default`. Confirm it exists with `AuthorizationType: NONE` |
| Headers | `access-control-allow-origin: https://acc.example.com`, four methods, four allowed headers, `access-control-expose-headers: etag` | `204` without `allow-origin`: API Gateway ignores integration CORS headers when CORS is configured on the API. The fix is to drop the catch-all for explicit per-route definitions so API Gateway answers preflight itself, then review every route |
| Audit count | Unchanged | A preflight wrote audit evidence. It must not, because it is a browser capability check |
| PKI preflight | Repeat the request against `/v1/admin/pki/cas`: same `204` and headers, still no audit object | The PKI admin routes use `ANY`, which catches `OPTIONS`. They must list `GET`, `POST`, `PUT` and `DELETE` |

## Gate 2: the access token is the right shape

Follow [Verify your token](../guide/identity-provider.md#verify-your-token), then confirm the API accepts it.

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://admin.acc.example.com/v1/admin/environments" \
  -H "authorization: Bearer $TOKEN"
```

| Check | Pass | Fail means |
| --- | --- | --- |
| `aud` | Equals `oidcAudience` (on Entra, the bare client ID) | You requested an ID token or the wrong resource. Ask for a resource-scoped access token |
| `iss` | Equals `oidcIssuer` exactly | A trailing slash or `/v2.0` suffix differs. The handler compares issuers exactly |
| `scp` or `scope` | Contains `oidcAdminScope` | The scope was not requested or not granted |
| Status | `200` | `401`: the gateway rejected the token (missing, invalid, audience, signature, expiry). `403`: insufficient scope at the gateway, or gateway and Lambda disagree on issuer, audience, scope or role. Re-authenticating will not fix a configuration `403` |

## Gate 3: the console loads and reads

Open `https://acc.example.com`, sign in, and load the catalog. Then run:

```sh
curl -s https://acc.example.com/config.json
curl -sI https://acc.example.com/ | grep -i 'cache-control\|x-cache'
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Sign-in | Redirects to the provider and back, catalog loads | See [Console](../guide/console.md) and gate 2 |
| `config.json` | `auth.mode` is `oidc`, `adminApiUrl` is the admin FQDN | `adminApiUrl` is `http://127.0.0.1:5274`: the local development config reached the bucket. It boots cleanly and talks to nothing |
| Shell caching | `cache-control: no-store` | The default behavior is cached, so a console deploy will not reach browsers |

## Gate 4: silent renew survives the provider redirect

Renewal loads the provider in a hidden iframe that redirects back to `https://acc.example.com/silent.html`. Two CSP directives must both allow it.

```sh
curl -sI https://acc.example.com/silent.html | grep -i content-security-policy
curl -sI https://acc.example.com/ | grep -i content-security-policy
```

Then leave the console open past the access token's lifetime with the browser console visible.

| Check | Pass | Fail means |
| --- | --- | --- |
| `/` policy | `frame-src 'self'` plus the issuer origin, and `frame-ancestors 'none'` | The parent cannot navigate the iframe back |
| `/silent.html` policy | `frame-src 'self'` plus the issuer origin, and `frame-ancestors 'self'` | The callback document cannot be embedded |
| Session | Continues past token expiry with no CSP violation | A `frame-src` violation means renewal never completes, so requests go out with no bearer token and get `401`. If the provider refuses to be framed, the redirect fallback still works but interrupts the session |

## Gate 5: mutation semantics

In the console, create a secret, set a payload, then edit metadata.

| Check | Pass | Fail means |
| --- | --- | --- |
| Metadata-only edit | `payloadKeyCount` is unchanged | Inheritance in `SecretService.update` regressed and the destructive-edit warning goes blind |
| Stale `If-Match` | `412`, and the console keeps your draft in the concurrency panel | The console silently reloaded and lost the draft |
| Idempotency key reused on a secret route | `409`, no replay | The route replayed the original response. The console must reconcile by re-reading |
| Idempotency key reused on a consumer route | Replays the recorded result | The route returned an error instead. See [Idempotency](../reference/api/index.md#idempotency) |

## Gate 6: mutual TLS

Enroll a [direct consumer](../reference/glossary.md#direct-consumer) through the console with a CSR you generated locally, then call the delivery API with three certificates.

| Certificate | Pass | Fail means |
| --- | --- | --- |
| The issued, active client certificate | `200` with the payload | Truststore or enrollment is broken |
| The same certificate after revoking it | Rejected on the very next request | Revocation is a strongly consistent DynamoDB read, so there should be no propagation wait |
| A certificate from an unrelated CA | Rejected at TLS | The truststore admits foreign CAs |

Also confirm the default `execute-api` endpoints are disabled on both APIs: a request to either API's raw `execute-api` URL must fail.

## Gate 7: IAM boundaries

These are the controls MiniStack cannot evaluate. The full permission table is in [AWS resources and IAM](../reference/aws-resources.md#permissions-by-lambda). Check with the IAM policy simulator, for example against the consumer role:

```sh
aws iam simulate-principal-policy \
  --policy-source-arn CONSUMER_ROLE_ARN \
  --action-names s3:GetObject s3:DeleteObjectVersion \
  --resource-arns arn:aws:s3:::AUDIT_BUCKET/audit/example \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Audit writers | The admin, consumer, bootstrap, identity-rotation, recovery and retention roles can `PutObject` under `audit/` and cannot read or list it | A serving role can read audit evidence |
| Audit reader | Only the audit-query role can list and read `audit/` | Another role has read access |
| Payload decryption | The consumer role can decrypt only with `purpose=secret-payload` | It can open the issuer envelope |
| Admin decryption | The admin role can decrypt with `purpose=issuer-ca` and `purpose=secret-payload`, and nothing else | A context is missing or too broad |
| Retention | Only the retention role has `s3:DeleteObjectVersion` on the revision bucket | A serving role can delete revisions |

## Gate 8: Object Lock retention

```sh
aws s3api get-object-lock-configuration --bucket AUDIT_BUCKET
aws s3api get-object-lock-configuration --bucket REVISION_BUCKET
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Revision bucket | Default retention is 90 days, mode `COMPLIANCE` | Retention is not applied |
| Audit bucket | Default retention is 7 years, mode `COMPLIANCE` | Retention is not applied |
| Delete an audit object version | Fails | Object Lock is not enforcing |

## Gate PKI-0: PKI resources deploy and stay inert

Run after gate 8. You need the gate 2 `$TOKEN` and the gate 6 consumer certificate (`consumer.crt`, `consumer.key`).

```sh
export DEP=hml-acc
ADMIN_API=$(aws apigatewayv2 get-apis --query "Items[?Name=='$DEP-admin'].ApiId" --output text)
CONSUMER_API=$(aws apigatewayv2 get-apis --query "Items[?Name=='$DEP-consumer'].ApiId" --output text)
aws apigatewayv2 get-routes --api-id "$ADMIN_API" --query "Items[?contains(RouteKey,'pki')].[RouteKey,AuthorizationType]" --output text
aws apigatewayv2 get-routes --api-id "$CONSUMER_API" --query "Items[?contains(RouteKey,'pki')].[RouteKey,AuthorizationType]" --output text
aws apigatewayv2 get-stage --api-id "$CONSUMER_API" --stage-name '$default' --query RouteSettings
aws dynamodb describe-table --table-name "$DEP-control" \
  --query "Table.GlobalSecondaryIndexes[?IndexName=='pki-directory'].[IndexStatus,KeySchema[].AttributeName,Projection.ProjectionType]"
PKI_BUCKET=$(aws cloudformation describe-stacks --stack-name "$DEP" \
  --query "Stacks[0].Outputs[?OutputKey=='PkiBucketName'].OutputValue" --output text)
aws s3api get-public-access-block --bucket "$PKI_BUCKET"
aws s3api get-bucket-versioning --bucket "$PKI_BUCKET"
aws lambda invoke --function-name "$DEP-pki-maintenance" /tmp/pki-maintenance.json > /dev/null && cat /tmp/pki-maintenance.json
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
curl -s https://admin.acc.example.com/v1/admin/pki/cas -H "authorization: Bearer $TOKEN"
curl -s --cert consumer.crt --key consumer.key https://api.acc.example.com/v1/pki/issuance-grants
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
aws cloudwatch describe-alarms --alarm-name-prefix "$DEP-pki-" --query 'MetricAlarms[].[AlarmName,StateValue]' --output text
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Admin routes | Exactly `GET`, `POST`, `PUT`, `DELETE /v1/admin/pki/{proxy+}`, each `JWT` | An `ANY` route catches `OPTIONS` and breaks gate 1 |
| Consumer routes | `GET` and `POST /v1/pki/{proxy+}`, `NONE` | |
| Throttle | `POST /v1/pki/{proxy+}` with your `pkiIssuanceRateLimit` and `pkiIssuanceBurstLimit` (default 20 and 40) | Issuance is bounded only by the account limit |
| GSI | `ACTIVE`, `pkiDirectoryPk` and `pkiDirectorySk`, `ALL` | |
| PKI bucket | All four public-access blocks `true`, versioning `Enabled` | |
| Maintenance | `{"status":"idle"}` | `AccessDeniedException` on `Query`: the role's GSI allowlist is wrong. Read `/aws/lambda/hml-acc-pki-maintenance` |
| Admin probe | `404`, message `This PKI route is not available.` | Another message: the request reached the admin Lambda, not `pki-admin` |
| Consumer probe | `404` with the same message | `403 identity_not_active` with an active certificate: `pki-issuer` cannot read `IDENTITY#` |
| Audit count | Unchanged across both probes | A PKI 404 wrote evidence |
| Alarms | Ten `hml-acc-pki-*` alarms, all `OK` or `INSUFFICIENT_DATA`. `pki-maintenance-missed` is `ALARM` until the first scheduled pass and must be `OK` within 15 minutes of deploy | The schedule or its invoke permission is missing |

## Gate PKI-1: PKI IAM boundaries

```sh
TABLE=$(aws dynamodb describe-table --table-name "$DEP-control" --query Table.TableArn --output text)
KEY=$(aws kms describe-key --key-id "alias/$DEP-application" --query KeyMetadata.Arn --output text)
role() { aws lambda get-function-configuration --function-name "$DEP-$1" --query Role --output text; }
ddb() { aws iam simulate-principal-policy --policy-source-arn "$(role "$1")" --action-names "$2" --resource-arns "$TABLE" \
  --context-entries "ContextKeyName=dynamodb:LeadingKeys,ContextKeyValues=$3,ContextKeyType=stringList" \
  --query 'EvaluationResults[0].EvalDecision' --output text; }
kmsd() { aws iam simulate-principal-policy --policy-source-arn "$(role "$1")" --action-names "$2" --resource-arns "$KEY" \
  --context-entries "ContextKeyName=kms:EncryptionContext:service,ContextKeyValues=hemlig,ContextKeyType=string" \
    "ContextKeyName=kms:EncryptionContext:purpose,ContextKeyValues=$3,ContextKeyType=string" \
    "ContextKeyName=kms:EncryptionContext:caId,ContextKeyValues=ca-acceptance,ContextKeyType=string" \
    "ContextKeyName=kms:EncryptionContext:environment,ContextKeyValues=prod,ContextKeyType=string" \
    "ContextKeyName=kms:EncryptionContextKeys,ContextKeyValues=service,purpose,caId,environment${4:+,$4},ContextKeyType=stringList" \
  --query 'EvaluationResults[0].EvalDecision' --output text; }
```

DynamoDB authorizes each `TransactWriteItems` item as its own `PutItem`, `UpdateItem` or `ConditionCheckItem`, so one denied item denies the whole transaction.

| Command | Pass |
| --- | --- |
| `ddb pki-issuer dynamodb:PutItem 'IDENTITY#x'` | `explicitDeny` |
| `ddb pki-issuer dynamodb:PutItem 'PKI_CERT#ca-x#01'` | `allowed` |
| `ddb pki-issuer dynamodb:ConditionCheckItem 'IDENTITY#x'` | `allowed`. `pki-admin` and `pki-maintenance`: `implicitDeny` |
| For `pki-admin`, `pki-issuer`, `pki-maintenance` and each of `CONSUMER#y`, `IDENTITY#y`, `AGENT_GRANT#y`: `ddb ROLE dynamodb:PutItem KEY` | `explicitDeny` |
| `ddb ROLE dynamodb:BatchWriteItem 'PKI_CA#x,CONSUMER#y'` (each PKI role) | `explicitDeny`. With `'PKI_CA#x'` alone: `implicitDeny` |
| `aws iam simulate-principal-policy --policy-source-arn "$(role pki-admin)" --action-names dynamodb:Scan --resource-arns "$TABLE"` | `implicitDeny` |
| `ddb ROLE dynamodb:PutItem 'PKI_CA#x'` for `admin`, `audit-query`, `consumer`, `bootstrap`, `identity-rotation`, `notification-publisher`, `recovery`, `retention` | `explicitDeny` |
| `kmsd pki-admin kms:Decrypt pki-ca` and `kmsd pki-admin kms:GenerateDataKey pki-ca` | `allowed` |
| `kmsd pki-admin kms:Decrypt issuer-ca`, `… secret-payload`, `kmsd pki-admin kms:Decrypt pki-ca extra` | `implicitDeny` |
| `kmsd pki-issuer kms:GenerateDataKey pki-ca` | `implicitDeny` |
| `kmsd ROLE kms:Decrypt pki-ca` for `admin`, `consumer`, `bootstrap`, `identity-rotation` | `implicitDeny` |

The simulator evaluates identity policies only. With `existingApplicationKeyArn`, also confirm that the key policy grants these roles nothing directly. Gate PKI-4 proves the `ConditionCheckItem` grants with a real commit.

## Teardown

::: danger Compliance retention cannot be shortened by anyone
Not even the account root can shorten it. Every object written during this run persists for its full retention, and the two locked buckets cannot be emptied until it ends.
:::

Resources use `RemovalPolicy.DESTROY` and the unlocked truststore and console buckets empty automatically during `cdk destroy`. The locked buckets can still block teardown, so budget for the wait before you start.

## Next steps

- [Troubleshoot a failing gate](troubleshooting.md)
- [Review limits and timings](../reference/limits.md)
