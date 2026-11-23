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

Run after gate 8. You need the gate 2 `$TOKEN` and a consumer certificate that is still active (`consumer.crt`, `consumer.key`). Gate 6 revokes its certificate, so either run the consumer probe before that revocation or enroll a second consumer and use its certificate.

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
curl -s https://admin.acc.example.com/v1/admin/pki/_probe -H "authorization: Bearer $TOKEN"
curl -s --cert consumer.crt --key consumer.key https://api.acc.example.com/v1/pki/_probe
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
| Admin probe | `404`, message `This PKI route is not available.` `/v1/admin/pki/_probe` is never routed, unlike `/v1/admin/pki/cas`, which answers `400` or `200` | Another message: the request reached the admin Lambda, not `pki-admin` |
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
| `aws iam simulate-principal-policy --policy-source-arn "$(role ROLE)" --action-names dynamodb:PutItem --resource-arns "$TABLE" --context-entries "ContextKeyName=dynamodb:LeadingKeys,ContextKeyValues=PKI_CA#x,ContextKeyType=stringList" "ContextKeyName=dynamodb:Attributes,ContextKeyValues=pk,sk,workflowDuePk,ContextKeyType=stringList" --query 'EvaluationResults[0].EvalDecision' --output text` for each PKI role | `explicitDeny`. A PKI role must not write another index's key attributes |
| The same simulation for `admin`, `consumer`, `recovery` and the other existing roles, with `LeadingKeys=SECRET#x` and `dynamodb:Attributes=pk,sk,pkiDirectoryPk` | `explicitDeny`. An existing role must not write the PKI directory attributes |
| `kmsd ROLE kms:Decrypt pki-ca` for `admin`, `consumer`, `bootstrap`, `identity-rotation` | `implicitDeny` |

The simulator evaluates identity policies only. With `existingApplicationKeyArn`, also confirm that the key policy grants these roles nothing directly. Gate PKI-4 proves the `ConditionCheckItem` grants with a real commit.

## Gate PKI-2: an offline root activates a Hemlig intermediate

Run after PKI-1 on an offline-capable workstation with OpenSSL 3, the CLI logged in (`hemlig login`), and `HEMLIG_ENVIRONMENT=prod`. Use a throwaway root: this gate is not your production root ceremony.

```sh
# 1. Recipe root (docs/operations/pki-offline-root.md): root-ca.cnf, then
mkdir -p acc-root/certs acc-root/private && cd acc-root && chmod 700 private
touch index.txt && echo 01 > crlnumber && openssl rand -hex 16 > serial
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve -out private/root.key
openssl req -config root-ca.cnf -new -x509 -key private/root.key -days 3650 -out root.pem
# 2. Intermediate
hemlig pki ca create --name acc-issuing-1 --key-algorithm ECDSA_P256 \
  --subject 'CN=Hemlig Acceptance Issuing CA 1,O=Example Corp' --permit-dns acc.example.com --csr-out issuing.csr
openssl req -in issuing.csr -noout -text -verify
openssl ca -config root-ca.cnf -batch -in issuing.csr -out issuing.pem -notext
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki ca activate acc-issuing-1 --certificate issuing.pem --chain root.pem --root-crl root.crl.pem
CA_ID=$(hemlig pki ca get acc-issuing-1 | jq -r .data.caId)
EXT_ID=$(hemlig pki ca get acc-issuing-1 | jq -r .data.parent.id)
# 3. Envelope and CloudTrail (allow up to 15 minutes for delivery)
aws dynamodb get-item --table-name "$DEP-control" --key "{\"pk\":{\"S\":\"PKI_CA#$CA_ID\"},\"sk\":{\"S\":\"PROFILE\"}}" \
  --projection-expression '#k.#s, #k.wrapped.#a' --expression-attribute-names '{"#k":"key","#s":"state","#a":"algorithm"}'
for E in GenerateDataKey Decrypt; do aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$E \
  --max-results 50 --query 'Events[].CloudTrailEvent' --output text | tr '\t' '\n' \
  | jq -c "select(.requestParameters.encryptionContext.caId==\"$CA_ID\") | {e:.eventName, ctx:.requestParameters.encryptionContext, role:.userIdentity.sessionContext.sessionIssuer.userName}"; done
# 4. OpenSSL acceptance of the CA and its initial CRL
hemlig pki ca crl get acc-issuing-1 --out issuing.crl
openssl crl -inform DER -in issuing.crl -out issuing.crl.pem
cat issuing.pem root.pem > chain-and-root.pem
openssl verify -x509_strict -CAfile root.pem issuing.pem
openssl verify -crl_check -CAfile root.pem -CRLfile root.crl.pem issuing.pem
openssl crl -in issuing.crl.pem -CAfile chain-and-root.pem -noout -verify
# 5. Root CRL uploads
openssl ca -config root-ca.cnf -gencrl -out root2.crl.pem
hemlig pki external-ca upload-crl --for-ca acc-issuing-1 --crl root2.crl.pem
hemlig pki external-ca upload-crl --for-ca acc-issuing-1 --crl root2.crl.pem      # identical retry
hemlig pki external-ca upload-crl --for-ca acc-issuing-1 --crl root.crl.pem       # lower number
openssl crl -in root2.crl.pem -outform DER -out forged.der
printf '\x00' | dd of=forged.der bs=1 seek=$(( $(wc -c < forged.der) - 1 )) conv=notrunc
hemlig pki external-ca upload-crl "$EXT_ID" --crl forged.der
(mkdir -p ../other-root/certs ../other-root/private && cd ../other-root && touch index.txt && echo 10 > crlnumber && openssl rand -hex 16 > serial \
  && sed 's#^dir *=.*#dir = .#' ../acc-root/root-ca.cnf > root-ca.cnf \
  && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out private/root.key \
  && openssl req -config root-ca.cnf -new -x509 -key private/root.key -days 30 -out root.pem \
  && openssl ca -config root-ca.cnf -gencrl -out other.crl.pem)
hemlig pki external-ca upload-crl "$EXT_ID" --crl ../other-root/other.crl.pem
# 6. Maintenance
aws lambda invoke --function-name "$DEP-pki-maintenance" /tmp/pki-maintenance.json > /dev/null && cat /tmp/pki-maintenance.json
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Create | Receipt `status: PENDING_CERTIFICATE`; the CSR verifies and shows `CA:TRUE, pathlen:0`, critical `keyCertSign, cRLSign` and the permitted DNS subtree | Hemlig built the wrong CSR profile |
| Activate | Receipt `status: ACTIVE`, `parent.type: external`, `rootCrl.state: CURRENT`, `crl.number: 1` | `chain_invalid` or `crl_invalid`: read `error.apiDetails.reason` |
| Envelope | `key.state ACTIVE`, `wrapped.algorithm AES-256-GCM` | |
| CloudTrail | One `GenerateDataKey` (create) and at least one `Decrypt` (activation) with context exactly `{service: hemlig, purpose: pki-ca, caId: $CA_ID, environment: prod}`, both from the `pki-admin` role | Another role, or a context without `caId` or `environment` |
| OpenSSL | All three commands print `OK` or `verify OK` | |
| Upload | First `changed: true`, `revokedCaIds: []`. Identical retry `changed: false` (exit 0). Lower number: exit 5, `apiCode crl_not_newer`. Forged: exit 2, `crl_invalid`, reason `bad_signature`. Other key with the same DN: exit 2, `crl_invalid`, reason `bad_signature` | A forged or rolled-back CRL was accepted |
| Maintenance | `{"status":"ok",…,"failures":0}`. Within 15 minutes `hml-acc-pki-generated-crl-stale`, `-external-crl-stale` and `-external-crl-missing` show `OK` | `AccessDenied` on S3 or KMS: the role's grants are wrong |
| Audit | Succeeded events for `pki.ca.create`, `pki.ca.activate`, three `pki.external-ca.upload-crl`, and `pki.crl.get`. Failed events with reason codes `crl_not_newer` and `bad_signature`. No object contains `-----BEGIN` | |

Keep `acc-root` for PKI-4 to PKI-6.

## Gate PKI-3: a PKI certificate never authenticates to the delivery API

Run after gate 6 (the identity root is provisioned and published) and PKI-2 (`acc-issuing-1` is ACTIVE).

```sh
DOMAIN=api.acc.example.com
read TS_URI TS_VERSION < <(aws apigatewayv2 get-domain-name --domain-name "$DOMAIN" \
  --query 'MutualTlsAuthentication.[TruststoreUri,TruststoreVersion]' --output text)
TS_BUCKET=$(echo "$TS_URI" | cut -d/ -f3); TS_KEY=$(echo "$TS_URI" | cut -d/ -f4-)
aws s3api get-object --bucket "$TS_BUCKET" --key "$TS_KEY" --version-id "$TS_VERSION" ts-before.pem >/dev/null
grep -c 'BEGIN CERTIFICATE' ts-before.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout pki-client.key \
  -subj "/CN=client.acc.example.com" -addext "subjectAltName=DNS:client.acc.example.com" -out pki-client.csr
hemlig pki cert issue acc-issuing-1 --csr pki-client.csr --use-csr-names \
  --usage digitalSignature --usage clientAuth --duration 1h --out pki-client.pem --chain-out pki-client-chain.pem
cat pki-client.pem pki-client-chain.pem > pki-client-full.pem
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
for P in /v1/pki/issuance-grants /v1/agent/config; do
  curl -sS -o pki3.body -w "%{http_code}\n" --cert pki-client-full.pem --key pki-client.key "https://$DOMAIN$P"; echo "curl=$?"; cat pki3.body; echo; done
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
aws apigatewayv2 get-domain-name --domain-name "$DOMAIN" --query 'MutualTlsAuthentication.TruststoreVersion' --output text
aws s3api get-object --bucket "$TS_BUCKET" --key "$TS_KEY" ts-after.pem >/dev/null && grep -c 'BEGIN CERTIFICATE' ts-after.pem
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Issue | Receipt `status: ISSUED` with EKU `clientAuth` | Admin issuance or the operator role is broken |
| Both requests | Rejected by API Gateway: a TLS failure (`curl` exit 35 or 56) or `403` with body `{"message":"Forbidden"}`, **never** a Hemlig `error` envelope | A Hemlig envelope means the request reached a Lambda: the truststore admits the PKI chain |
| Audit count | Unchanged | Any new object (including `identity_not_active`) means the certificate reached a handler |
| Truststore | Same `TruststoreVersion`, same anchor count, and no PKI anchor (`openssl x509 -fingerprint` of each block differs from `acc-root/root.pem`) | PKI code wrote the truststore |

## Gate PKI-4: deployed issuance, revocation and quota

Run after PKI-3 with an active consumer certificate (`consumer.crt`, `consumer.key`, consumer `$CONSUMER_ID` in `prod`) and `acc-root` from PKI-2.

```sh
cat > grant.json <<'EOF'
{ "names": { "dns": { "allow": ["*.acc.example.com"] }, "maxSans": 10 },
  "keyUsages": ["digitalSignature", "keyEncipherment"],
  "extendedKeyUsages": { "allow": ["serverAuth", "clientAuth"], "default": ["serverAuth"] },
  "lifetime": { "defaultSeconds": 3600, "maxSeconds": 86400, "minSeconds": 600 },
  "quotas": { "perHour": 3, "perDay": 10 } }
EOF
hemlig pki grant create "$CONSUMER_ID" acc-web --ca acc-issuing-1 --file grant.json
issue() { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" \
    -subj "/CN=$1.acc.example.com" -addext "subjectAltName=DNS:$1.acc.example.com" -out "$1.csr" 2>/dev/null
  jq -n --rawfile csr "$1.csr" '{certificateSigningRequestPem:$csr, usages:["digital signature","key encipherment","server auth"]}' > "$1.json"
  curl -sS -D "$1.headers" --cert consumer.crt --key consumer.key -H 'content-type: application/json' \
    -H "idempotency-key: pki4-$2" --data @"$1.json" https://api.acc.example.com/v1/pki/issuance-grants/acc-web/certificates; }
issue web 0001 > issued.json
jq -r .certificatePem issued.json > leaf.pem; jq -r .chainPem issued.json > chain.pem; jq -r .caPem issued.json > ca.pem
cmp <(openssl x509 -in ca.pem -outform DER) <(openssl x509 -in acc-root/root.pem -outform DER) && echo anchor-ok
openssl verify -x509_strict -purpose sslserver -CAfile acc-root/root.pem -untrusted chain.pem leaf.pem
curl -sS --cert consumer.crt --key consumer.key -H 'content-type: application/json' -H 'idempotency-key: pki4-0001' \
  --data @web.json https://api.acc.example.com/v1/pki/issuance-grants/acc-web/certificates | jq -r .serial   # replay
SERIAL=$(jq -r .serial issued.json); T0=$(date +%s)
hemlig pki cert revoke acc-issuing-1 "$SERIAL" --reason keyCompromise
until hemlig pki ca crl get acc-issuing-1 --out issuing.crl >/dev/null && \
  openssl crl -inform DER -in issuing.crl -noout -text | grep -qi "Serial Number: $SERIAL"; do
  [ $(( $(date +%s) - T0 )) -ge 60 ] && break; sleep 5; done; echo "elapsed=$(( $(date +%s) - T0 ))"
openssl crl -inform DER -in issuing.crl -out issuing.crl.pem
openssl verify -crl_check_all -CAfile acc-root/root.pem -untrusted chain.pem \
  -CRLfile issuing.crl.pem -CRLfile acc-root/root2.crl.pem leaf.pem
curl -sS --cert consumer.crt --key consumer.key -H 'content-type: application/json' -H 'idempotency-key: pki4-0001' \
  --data @web.json https://api.acc.example.com/v1/pki/issuance-grants/acc-web/certificates            # revoked replay
issue api2 0002 >/dev/null; issue api3 0003 >/dev/null; issue api4 0004; grep -i retry-after api4.headers
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Issue | `201` through the deployed `pki-issuer` role. This proves its `ConditionCheckItem` on `IDENTITY#*` and `AGENT_GRANT#*`, and its `PKI_*` writes | `503` with `AccessDeniedException` in `/aws/lambda/hml-acc-pki-issuer`: the IAM allowlist is wrong |
| Chain | `anchor-ok`, and `leaf.pem: OK` under `-x509_strict -purpose sslserver` | Wrong chain or profile |
| Replay | The same serial | Replay records are broken |
| Revocation | `elapsed` ≤ 60, and `verify` reports `certificate revoked` | Inline publication failed: read the `pki_inline_crl_failed` log |
| Revoked replay | `409 issuance_revoked` | A revoked certificate was re-delivered |
| Quota | `api2` and `api3` give `201`; `api4` gives `429 issuance_rate_limited`, `details.reason: grant_hour`, and a `Retry-After` of 1 to 3600 | Quota is not enforced |
| CloudTrail | `Decrypt` with `purpose=pki-ca` and this `caId` from the `pki-issuer` role (issuance) and the `pki-admin` role (inline CRL) | |
| Audit | Succeeded: `pki.grant.create`, four `pki.certificate.issue` (one `replayed: "true"`), `pki.certificate.revoke` (`crlEntry: "true"`). Failed: `pki.certificate.issue` with `certificate_revoked` and with `grant_hour`. No event for `GET /v1/pki/issuance-grants`. No object contains `-----BEGIN` | |

## Gate PKI-5: cert-manager renews unattended

Run after PKI-4, on Kind or EKS, with `acc-root` from PKI-2. This gate is manual: no Kind job exists in CI. Install cert-manager with Helm and its CRDs, then the controller chart from this release with default approval (`certManager.approval.grantDefaultApprover=true`). Use a consumer with a PKI-only AgentGrant, in namespace `pki5`.

Delete the `HemligTrustBundle` CRD before this gate (`kubectl delete crd hemligtrustbundles.hemlig.zyno.io`): the issuer must run without it. PKI-6 applies it again.

```sh
cat > grant5.json <<'EOF2'
{ "names": { "dns": { "allow": ["*.pki5.acc.example.com"] }, "maxSans": 10 },
  "keyUsages": ["digitalSignature"],
  "extendedKeyUsages": { "allow": ["serverAuth", "clientAuth"], "default": ["serverAuth"] },
  "lifetime": { "defaultSeconds": 3600, "maxSeconds": 3600, "minSeconds": 600 },
  "quotas": { "perHour": 10, "perDay": 100 } }
EOF2
hemlig pki grant create "$CONSUMER_ID" acc-k8s --ca acc-issuing-1 --file grant5.json
kubectl apply -f - <<'EOF2'
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligIssuer
metadata: { name: acc, namespace: pki5 }
spec: { consumerRef: acc-consumer, issuanceGrant: acc-k8s }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: web, namespace: pki5 }
spec:
  secretName: web-tls
  commonName: web.pki5.acc.example.com
  dnsNames: [web.pki5.acc.example.com]
  duration: 1h
  renewBefore: 40m
  # The default of 1 would delete the old requests that carry the serials.
  revisionHistoryLimit: 3
  # Explicit, because the default adds key encipherment, which the grant denies.
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc }
EOF2
kubectl -n pki5 wait certificate/web --for=condition=Ready --timeout=120s
# Wait at least 45 minutes, then compare the revisions
kubectl -n pki5 get certificaterequest -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.certificate}{"\n"}{end}'
kubectl -n pki5 get secret web-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > tls.crt
kubectl -n pki5 get secret web-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
openssl verify -CAfile acc-root/root.pem -untrusted tls.crt tls.crt
openssl x509 -in ca.crt -noout -fingerprint -sha256
kubectl apply -f - <<'EOF2'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: denied, namespace: pki5 }
spec:
  secretName: denied-tls
  dnsNames: [api.not-granted.example.com]
  # Same key settings and usages as `web`, so the name check is what denies it.
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc }
EOF2
kubectl -n pki5 get certificaterequest -o json | jq '.items[] | select(.metadata.annotations["cert-manager.io/certificate-name"] == "denied") | .status.conditions'
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Renewal | At least 3 distinct serials across the CertificateRequests, and each `tls.crt` chain passes `openssl verify -CAfile acc-root/root.pem -untrusted tls.crt tls.crt` | The unattended renewal loop is broken |
| Anchor | The SHA-256 fingerprint of `ca.crt` equals the recorded `acc-root/root.pem` fingerprint | `status.ca` is not the anchor |
| Encoding | `tls.crt` equals the decoded `status.certificate` of the latest-revision CertificateRequest, and `ca.crt` equals the decoded `status.ca` | The base64 encoding is wrong |
| Server copy | The leaf block equals `hemlig pki cert get acc-issuing-1 $SERIAL --out`, and the intermediate block equals the CA certificate | The returned chain differs from what Hemlig stored |
| Denied name | A Certificate for `api.not-granted.example.com` ends `Ready=False` with reason `Failed` and `name_not_permitted` in the message | A denial was retried or hidden |
| Restart | After `kubectl rollout restart` of the controller during a pending issuance, the request still becomes `Ready`, and `hemlig pki cert list --consumer` shows one certificate for it | The idempotency key was not reused |
| Approval off (optional) | With `grantDefaultApprover=false`, a request stays `Waiting for approval` until approved | The controller approved by itself |
| CRDs | The API server accepts both new CRDs, including their CEL immutability rules, and rejects a change of `spec.consumerRef` | A CEL rule failed validation. This is the only gate that proves them |

## Gate PKI-6: mounted full-chain revocation

Run after PKI-5 in the same cluster and namespace `pki5`, with `acc-root`, `$CA_ID` and `$EXT_ID` from PKI-2 and the PKI-4 shell (`consumer.crt`, the `issue` function, `api2.json`). It revokes `acc-issuing-1` at the root, so only PKI-7 follows it. Before applying the CRD, run `helm upgrade --reuse-values --set trustBundles.refreshIntervalMilliseconds=60000`. The verifying pod needs OpenSSL 3; the example installs it in `alpine:3.20`, which needs package egress.

```sh
kubectl apply -f packages/kubernetes-controller/chart/hemlig-controller/crds/hemlig.zyno.io-pki.yaml
kubectl logs deploy/hemlig-controller -n hemlig-system --since=10m | grep 'trust bundles enabled'   # within 6 minutes
kubectl apply -f - <<EOF3
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligTrustBundle
metadata: { name: acc-trust, namespace: pki5 }
spec: { consumerRef: acc-consumer, caIds: [$CA_ID], target: { name: acc-trust } }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: pki6a, namespace: pki5 }
spec:
  secretName: pki6a-tls
  dnsNames: [pki6a.pki5.acc.example.com]
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: pki6b, namespace: pki5 }
spec:
  secretName: pki6b-tls
  dnsNames: [pki6b.pki5.acc.example.com]
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc }
---
apiVersion: v1
kind: Pod
metadata: { name: pki6-verify, namespace: pki5 }
spec:
  containers:
    - name: verify
      image: alpine:3.20
      command: [sh, -c, "apk add --no-cache openssl >/dev/null && sleep 7200"]
      volumeMounts: [{ name: trust, mountPath: /trust, readOnly: true }]
  volumes:
    - name: trust
      projected:
        sources:
          - configMap: { name: acc-trust }
          - configMap: { name: acc-trust-crl-$CA_ID, items: [{ key: crl.der, path: crls/issuing.der }] }
          - configMap: { name: acc-trust-crl-$EXT_ID, items: [{ key: crl.der, path: crls/root.der }] }
EOF3
kubectl -n pki5 wait hemligtrustbundle/acc-trust --for=condition=Ready --timeout=300s
kubectl -n pki5 wait certificate/pki6a certificate/pki6b --for=condition=Ready --timeout=120s
kubectl -n pki5 wait pod/pki6-verify --for=condition=Ready --timeout=300s
for C in pki6a pki6b; do kubectl -n pki5 get secret $C-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > $C.pem
  kubectl -n pki5 exec -i pki6-verify -- sh -c "cat > /tmp/$C.pem" < $C.pem; done
check() { kubectl -n pki5 exec pki6-verify -- sh -c "openssl crl -inform DER -in /trust/crls/issuing.der -out /tmp/i.pem && \
  openssl crl -inform DER -in /trust/crls/root.der -out /tmp/r.pem && openssl verify -CAfile /trust/ca.crt \
  -untrusted /trust/chain.crt -crl_check_all -CRLfile /tmp/i.pem -CRLfile /tmp/r.pem /tmp/$1.pem"; }
check pki6a; check pki6b
kubectl -n pki5 get hemligtrustbundle acc-trust -o jsonpath='{.status}' | jq .
kubectl -n pki5 exec pki6-verify -- sh -c 'grep -c "BEGIN CERTIFICATE" /trust/ca.crt /trust/chain.crt; openssl x509 -in /trust/ca.crt -noout -fingerprint -sha256'
# Leaf revocation
SERIAL_A=$(openssl x509 -in pki6a.pem -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
hemlig pki cert revoke acc-issuing-1 "$SERIAL_A" --reason keyCompromise; T0=$(date +%s)
until check pki6a 2>&1 | grep -q 'certificate revoked'; do [ $(( $(date +%s) - T0 )) -ge 600 ] && break; sleep 15; done; echo "elapsed=$(( $(date +%s) - T0 ))"
check pki6a; check pki6b
# Intermediate revocation at the root
(cd acc-root && openssl ca -config root-ca.cnf -revoke issuing.pem -crl_reason keyCompromise && openssl ca -config root-ca.cnf -gencrl -out root3.crl.pem)
hemlig pki external-ca upload-crl --for-ca acc-issuing-1 --crl acc-root/root3.crl.pem; T1=$(date +%s)
until check pki6b 2>&1 | grep -q 'at 1 depth'; do [ $(( $(date +%s) - T1 )) -ge 600 ] && break; sleep 15; done; echo "elapsed=$(( $(date +%s) - T1 ))"
check pki6b
hemlig pki ca get acc-issuing-1 | jq -r .data.status
issue api6 0006
curl -sS --cert consumer.crt --key consumer.key -H 'content-type: application/json' -H 'idempotency-key: pki4-0002' \
  --data @api2.json https://api.acc.example.com/v1/pki/issuance-grants/acc-web/certificates
kubectl -n pki5 get hemligtrustbundle acc-trust -o jsonpath='{.status.acceptedCaIds}'
# CEL and ownership
kubectl -n pki5 patch hemligtrustbundle acc-trust --type merge -p '{"spec":{"target":{"name":"other"}}}'
kubectl -n pki5 create configmap foreign-trust --from-literal=ca.crt=keep
kubectl apply -f - <<EOF3
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligTrustBundle
metadata: { name: foreign, namespace: pki5 }
spec: { consumerRef: acc-consumer, caIds: [$CA_ID], target: { name: foreign-trust } }
EOF3
sleep 30; kubectl -n pki5 get hmltrustbundle foreign; kubectl -n pki5 get configmap foreign-trust -o jsonpath='{.data.ca\.crt}'
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Feature | The controller logs `trust bundles enabled` within 6 minutes of applying the CRD, with no restart | The CRD probe or re-probe is broken |
| Bundle | `Ready=True`, `acceptedCaIds: [$CA_ID]`, two `crls` entries (`$CA_ID` `GENERATED`, `$EXT_ID` `UPLOADED`), both `Current` | Bundle or CRL routes, or ConfigMap writes |
| Content | `ca.crt` holds 1 certificate whose fingerprint equals the recorded `acc-root` fingerprint; `chain.crt` holds 1 | Anchors and intermediates are mixed |
| Healthy | Both `check` runs print `OK` | Wrong chain or CRLs |
| Leaf revocation | `elapsed` is at most the refresh interval plus 120 s; `check pki6a` reports `error 23 at 0 depth lookup: certificate revoked`; `pki6b` stays `OK` | Refresh or kubelet propagation is broken |
| Intermediate revocation | The upload returns `revokedCaIds` containing `$CA_ID`; `check pki6b` reports `error 23 at 1 depth lookup: certificate revoked`; the CA status is `REVOKED` | The root CRL was not delivered |
| Anchor kept | `acceptedCaIds` still lists `$CA_ID`, and the `ca.crt` fingerprint is unchanged | A revoked CA dropped its anchor |
| Issuance | `api6` gives `409 ca_not_active`, reason `revoked`; the replay gives `409 issuance_revoked`, reason `ca_revoked` | |
| CRDs | The API server accepted the CRD and rejects the patch with `consumerRef, consumerNamespace and target are immutable` | A CEL rule failed. Only a real API server proves it |
| Ownership | `foreign` is `Ready=False` `ConfigMapConflict`, and `foreign-trust` still holds `keep` | A foreign ConfigMap was overwritten |
| Audit | No `succeeded` events for `pki.bundle.get` or `pki.crl.get` from the consumer actor since the gate started (the admin route shares `pki.crl.get`, and PKI-2 created such events); `pki.certificate.revoke` and `pki.external-ca.upload-crl` (with `revokedCaIds`) succeeded; no object contains `-----BEGIN` | |

## Gate PKI-7: a Hemlig root and its intermediates

Run after PKI-6 in the same cluster and namespace `pki5`, with the PKI-4 shell (`consumer.crt`, `consumer.key`, `$CONSUMER_ID`), `grant5.json` from PKI-5 and the chart still at `trustBundles.refreshIntervalMilliseconds=60000`. Every key is `WRAPPED` in real KMS. This root is a throwaway: in production an external offline root is strongly recommended.

```sh
# 1. A root, two intermediates, and one refused as broader than the root
hemlig pki ca create --kind ROOT --name acc-hroot-1 --key-algorithm ECDSA_P384 \
  --subject 'CN=Hemlig Acceptance Root CA 1,O=Example Corp' --permit-dns acc.example.com 2> hroot.err
for N in 1 2; do hemlig pki ca create --kind INTERMEDIATE --parent acc-hroot-1 --name acc-hint-$N --key-algorithm ECDSA_P256 \
  --subject "CN=Hemlig Acceptance Intermediate CA $N,O=Example Corp" --validity 90d; done
hemlig pki ca create --kind INTERMEDIATE --parent acc-hroot-1 --name acc-hint-x --key-algorithm ECDSA_P256 \
  --subject 'CN=Hemlig Acceptance Intermediate CA X,O=Example Corp' --permit-dns example.org
ROOT_ID=$(hemlig pki ca get acc-hroot-1 | jq -r .data.caId)
H1_ID=$(hemlig pki ca get acc-hint-1 | jq -r .data.caId); H2_ID=$(hemlig pki ca get acc-hint-2 | jq -r .data.caId)
hemlig pki ca get acc-hroot-1 | jq -r .data.certificatePem > hroot.pem
hemlig pki ca get acc-hint-2 | jq -r .data.certificatePem > hint2.pem
hemlig pki ca get acc-hint-1 | jq '.data | {status, parentCaId, crlIssuers, effectiveConstraints}'
hemlig pki cert list acc-hroot-1 | jq -c '.data.certificates[] | {childCaId, status}'
openssl x509 -in hroot.pem -noout -text | grep -A1 'Basic Constraints'
openssl verify -x509_strict -CAfile hroot.pem hint2.pem
# 2. Grants, issuers, certificates, a bundle and a verifying pod
hemlig pki grant create "$CONSUMER_ID" acc-h1 --ca acc-hint-1 --file grant5.json
hemlig pki grant create "$CONSUMER_ID" acc-h2 --ca acc-hint-2 --file grant5.json
kubectl apply -f - <<EOF4
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligIssuer
metadata: { name: acc-h1, namespace: pki5 }
spec: { consumerRef: acc-consumer, issuanceGrant: acc-h1 }
---
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligIssuer
metadata: { name: acc-h2, namespace: pki5 }
spec: { consumerRef: acc-consumer, issuanceGrant: acc-h2 }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: pki7a, namespace: pki5 }
spec:
  secretName: pki7a-tls
  dnsNames: [pki7a.pki5.acc.example.com]
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc-h1 }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: pki7b, namespace: pki5 }
spec:
  secretName: pki7b-tls
  dnsNames: [pki7b.pki5.acc.example.com]
  usages: [digital signature, server auth]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  issuerRef: { group: hemlig.zyno.io, kind: HemligIssuer, name: acc-h2 }
---
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligTrustBundle
metadata: { name: acc-htrust, namespace: pki5 }
spec: { consumerRef: acc-consumer, caIds: [$H1_ID, $H2_ID], target: { name: acc-htrust } }
---
apiVersion: v1
kind: Pod
metadata: { name: pki7-verify, namespace: pki5 }
spec:
  containers:
    - name: verify
      image: alpine:3.20
      command: [sh, -c, "apk add --no-cache openssl >/dev/null && sleep 7200"]
      volumeMounts: [{ name: trust, mountPath: /trust, readOnly: true }]
  volumes:
    - name: trust
      projected:
        sources:
          - configMap: { name: acc-htrust }
          - configMap: { name: acc-htrust-crl-$H1_ID, items: [{ key: crl.der, path: crls/h1.der }] }
          - configMap: { name: acc-htrust-crl-$H2_ID, items: [{ key: crl.der, path: crls/h2.der }] }
          - configMap: { name: acc-htrust-crl-$ROOT_ID, items: [{ key: crl.der, path: crls/root.der }] }
EOF4
kubectl -n pki5 wait hemligtrustbundle/acc-htrust --for=condition=Ready --timeout=300s
kubectl -n pki5 wait certificate/pki7a certificate/pki7b --for=condition=Ready --timeout=120s
kubectl -n pki5 wait pod/pki7-verify --for=condition=Ready --timeout=300s
for C in pki7a pki7b; do kubectl -n pki5 get secret $C-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > $C.pem
  kubectl -n pki5 exec -i pki7-verify -- sh -c "cat > /tmp/$C.pem" < $C.pem; done
check7() { kubectl -n pki5 exec pki7-verify -- sh -c "for F in h1 h2 root; do openssl crl -inform DER -in /trust/crls/\$F.der -out /tmp/\$F.pem || exit 1; done; \
  openssl verify -CAfile ${2:-/trust/ca.crt} -untrusted /trust/chain.crt -crl_check_all -CRLfile /tmp/h1.pem -CRLfile /tmp/h2.pem -CRLfile /tmp/root.pem /tmp/$1.pem"; }
check7 pki7a; check7 pki7b
kubectl -n pki5 get hemligtrustbundle acc-htrust -o jsonpath='{.status}' | jq '{acceptedCaIds, crls: [.crls[] | {id, source, state}]}'
kubectl -n pki5 exec pki7-verify -- sh -c 'grep -c "BEGIN CERTIFICATE" /trust/ca.crt /trust/chain.crt; openssl x509 -in /trust/ca.crt -noout -fingerprint -sha256'
openssl x509 -in hroot.pem -noout -fingerprint -sha256
# 3. CA revoke of acc-hint-1: the generated root CRL rejects its leaves
hemlig pki ca revoke acc-hint-1 --reason caCompromise | jq '.data | {changed, crlEntry, crlPublished, revokedCaIds}'; T0=$(date +%s)
until check7 pki7a 2>&1 | grep -q 'at 1 depth'; do [ $(( $(date +%s) - T0 )) -ge 600 ] && break; sleep 15; done; echo "elapsed=$(( $(date +%s) - T0 ))"
check7 pki7a; check7 pki7b
hemlig pki cert revoke acc-hroot-1 "$(hemlig pki ca get acc-hint-1 | jq -r .data.serial)"
issue7() { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$2.key" \
    -subj "/CN=$2.pki5.acc.example.com" -addext "subjectAltName=DNS:$2.pki5.acc.example.com" -out "$2.csr" 2>/dev/null
  jq -n --rawfile csr "$2.csr" '{certificateSigningRequestPem:$csr, usages:["digital signature","server auth"]}' > "$2.json"
  curl -sS --cert consumer.crt --key consumer.key -H 'content-type: application/json' -H "idempotency-key: pki7-$3" \
    --data @"$2.json" "https://api.acc.example.com/v1/pki/issuance-grants/$1/certificates"; }
issue7 acc-h1 h7a 0701
# 4. Local distrust of the root
issue7 acc-h2 h7b 0702 | jq -r .serial
kubectl -n pki5 exec pki7-verify -- cp /trust/ca.crt /tmp/saved-ca.crt
hemlig pki ca revoke acc-hroot-1 --reason caCompromise | jq '.data | {changed, revokedCaIds, complete}'; T1=$(date +%s)
curl -sS --cert consumer.crt --key consumer.key -H 'content-type: application/json' -H 'idempotency-key: pki7-0702' \
  --data @h7b.json https://api.acc.example.com/v1/pki/issuance-grants/acc-h2/certificates
until kubectl -n pki5 exec pki7-verify -- sh -c '! grep -q "BEGIN CERTIFICATE" /trust/ca.crt'; do [ $(( $(date +%s) - T1 )) -ge 600 ] && break; sleep 15; done; echo "elapsed=$(( $(date +%s) - T1 ))"
check7 pki7b; echo "exit=$?"
check7 pki7b /tmp/saved-ca.crt
issue7 acc-h2 h7c 0703
hemlig pki ca get acc-hint-2 | jq -r '.data | [.status, .key.state, .revocationEvidence] | @tsv'
kubectl -n pki5 get hemligtrustbundle acc-htrust -o jsonpath='{.status}' | jq '{acceptedCaIds, reason: .conditions[0].reason}'
```

| Check | Pass | Fail means |
| --- | --- | --- |
| Create | `acc-hroot-1` is `ACTIVE`, `kind: ROOT`, `crl.number: 1`, and `hroot.err` holds the `warning:` line recommending an external offline root. Each intermediate is `ACTIVE` with `parentCaId: $ROOT_ID`, `crlIssuers` `[$Hn_ID, $ROOT_ID]` and the inherited `acc.example.com` constraint | |
| Parent check | `acc-hint-x` exits 2 with `apiCode bad_request`, reason `name_constraints_broader_than_parent`, and `hemlig pki ca get acc-hint-x` exits 4 | A child broader than its root was signed |
| Inventory | The root lists two certificates, each with a `childCaId` | Creation skipped the root's inventory row |
| Profile | The root shows `CA:TRUE, pathlen:1`, and `hint2.pem: OK` under `-x509_strict` | |
| Bundle | `Ready=True`; three `crls` entries (`$H1_ID`, `$H2_ID`, `$ROOT_ID`), all `GENERATED` and `Current`; `ca.crt` holds 1 certificate with the fingerprint of `hroot.pem`; `chain.crt` holds 2 | |
| Healthy | Both `check7` runs print `OK` | |
| CA revoke | `changed`, `crlEntry` and `crlPublished` are `true`, `revokedCaIds: [$H1_ID]`; `elapsed` is at most the refresh interval plus 120 s; `check7 pki7a` reports `error 23 at 1 depth lookup: certificate revoked`; `pki7b` stays `OK` | The generated root CRL was not published or not delivered |
| Leaf route | `cert revoke` on the child's serial exits 5, `apiCode conflict`, reason `use_ca_revoke` | |
| Issuance | `h7a` gives `409 ca_not_active`, reason `revoked` | |
| Distrust | `changed: true`, `revokedCaIds` lists `$H1_ID` and `$H2_ID`, `complete: true`; `acc-hint-2` shows `REVOKED`, `DISABLED`, `ancestor:$ROOT_ID` | |
| Replay | The `pki7-0702` replay gives `409 issuance_revoked`, reason `ca_revoked` (or `ancestor_revoked` if it raced the child walk) | A leaf under a distrusted root was delivered again |
| Anchor removed | `elapsed` is at most the refresh interval plus 120 s; `check7 pki7b` fails with a non-zero `exit=`; `check7 pki7b /tmp/saved-ca.crt` prints `OK`, so only the anchor's removal rejects it; `acceptedCaIds` still lists both CAs | The distrusted root stayed in `ca.crt` |
| New issuance | `h7c` gives `409 ca_not_active`, reason `revoked` or `ancestor_revoked` | |
| CloudTrail | One `GenerateDataKey` per new CA with its own `caId`; `Decrypt` with `caId=$ROOT_ID` only from `pki-admin` (signing the intermediates and the revoke's CRL) or `pki-maintenance`, never from `pki-issuer` | The root key signed a leaf |
| Audit | Succeeded: three `pki.ca.create` (`kind` `ROOT` and `INTERMEDIATE`) and two `pki.ca.revoke`. Failed: `pki.ca.create` with `name_constraints_broader_than_parent`, `pki.certificate.revoke` with `use_ca_revoke`, and `pki.certificate.issue` with `revoked` and with `ca_revoked` or `ancestor_revoked`. No object contains `-----BEGIN` | |

## Gate PKI-8: console and Pulumi drive the PKI

Run after gate PKI-7. You need the gate 2 `$TOKEN`, the PKI-2 recipe root, the console from gate 3, a Pulumi project with the provider and a stack for this deployment, and the `hemlig` CLI. Steps 1 to 6 are in the console. Step 7 is in Pulumi. Steps 8 and 9 read the results.

```sh
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS https://admin.acc.example.com/v1/admin/pki/consumers/acc-h2/issuance-grants/web \
  -H 'origin: https://console.acc.example.com' -H 'access-control-request-method: PUT' \
  -H 'access-control-request-headers: authorization,if-match,idempotency-key,content-type'
aws s3 ls s3://AUDIT_BUCKET/audit/ --recursive | wc -l
openssl crl -inform DER -in downloaded.crl -noout -text | head -5
hemlig pki ca get acc-console-1 | jq -r '.data | [.status, .key.state] | @tsv'
pulumi stack export | jq 'del(.. | .__provider?)' | grep -c -e "$HEMLIG_ADMIN_TOKEN" -e 'PRIVATE KEY'
```

| Step | Do | Pass | Fail means |
| --- | --- | --- | --- |
| 1. Preflight | The `OPTIONS` request above, between the two audit counts | `204`, and the two audit counts are equal | The PKI routes lack the CORS headers, or a preflight wrote evidence |
| 2. Create and activate | In the console, create an external CA `acc-console-1` with `maxLeafLifetimeSeconds` 300 in its policy, so step 6's key drains quickly. Sign the CSR with the PKI-2 recipe root and activate it. Download its CRL in the browser. Generate a newer root CRL (`cd acc-root && openssl ca -config root-ca.cnf -gencrl -out root4.crl.pem`), because the root already has a stored CRL from earlier gates and an identical upload reports no change. Upload `root4.crl.pem` from the offline roots card | The CA is `ACTIVE`. `openssl crl -inform DER` parses the download, which proves binary responses over CORS. The upload reports a change | A binary body was decoded as text, or `Access-Control-Expose-Headers` is wrong |
| 3. Rollover pre-fill | Choose "Roll over" on the CA | The name and common name are incremented. Setting the common name back to the old one disables Create and shows the reuse message | The console allows a DN the server will refuse |
| 4. Grant editor | Create a grant with a DNS allow rule. Validate it, then evaluate an allowed name and a denied one. Save from two tabs | Validate lists no errors. Evaluate returns `allow` with a plan, then `deny` with `name_not_permitted`. The second save shows the stale panel with the draft intact | The editor retried a `412`, or lost the draft |
| 5. Revoke | Issue a certificate under the CA with `hemlig pki cert issue acc-console-1 --csr pki-client.csr --use-csr-names --usage digitalSignature --usage clientAuth --duration 5m` (the PKI-3 CSR; the CA policy caps leaves at 300 s). Revoke it from its detail page in the console, then open it again | The CRL number rises within 60 seconds, and the second view offers only the key compromise upgrade | A second revoke is offered, or the CRL was not published |
| 6. Destroy the key | Retire the CA. The key becomes `DISABLED` once the drain point (`retiredAt` plus the longest lifetime ever issued, here the 5 minute certificate from step 5) has passed and maintenance has published a CRL after it, so expect about 5 minutes plus up to 15 minutes. Then destroy the key and type the CA name | The button needs the exact name. The key becomes `DESTROYED` and the CA record remains | Destroy ran without confirmation, or deleted the record |
| 7. Pulumi | Apply the [two-phase CA](../guide/pulumi-pki.md), then create a grant. Edit the grant in the console, change it in Pulumi and apply. Run `pulumi destroy` with `protect`, then unprotect and destroy | The first apply gives `PENDING_CERTIFICATE` and `csrPem`. After the config is set, `ACTIVE`. The grant update succeeds. A protected destroy is refused. After unprotecting, the grant is a tombstone, the CA is `RETIRED` with its key still `ACTIVE`, and nothing is revoked | The provider replaced or revoked something, or destroyed the key |
| 8. State | The `pulumi stack export` count | `0` | The token or a private key reached state |
| 9. Audit volume | Load one CA detail page, then count audit objects and search them for `-----BEGIN` | A bounded number of read events and no `-----BEGIN` | The console refetches PKI reads, or evidence carries PEM |

## Teardown

::: danger Compliance retention cannot be shortened by anyone
Not even the account root can shorten it. Every object written during this run persists for its full retention, and the two locked buckets cannot be emptied until it ends.
:::

Resources use `RemovalPolicy.DESTROY` and the unlocked truststore and console buckets empty automatically during `cdk destroy`. The locked buckets can still block teardown, so budget for the wait before you start.

## Next steps

- [Troubleshoot a failing gate](troubleshooting.md)
- [Review limits and timings](../reference/limits.md)
