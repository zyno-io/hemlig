---
title: Threat model
description: The threats Hemlig defends against, the control for each, where the code enforces it and what risk remains.
pageType: reference
---

# Threat model

Each row names a threat, the control that stops it, the file that enforces the control and the risk that remains. Paths are relative to the [repository root](https://github.com/zyno-io/hemlig).

For the components and boundaries, see [Architecture](../guide/architecture.md). For per-role IAM, see [AWS resources](../reference/aws-resources.md).

## Access and identity

| Threat | Control | Where enforced (file) | Residual risk |
| --- | --- | --- | --- |
| Stolen or forged administrator token | API Gateway checks the issuer and audience. The handler re-checks audience and, when `oidcAdminScope` or `oidcAdminRole` is set, the scope and app role. | `cdk/stack.ts`, `src/auth/actors.ts` | An administrator whose token is valid and in scope has full administrator rights. Protect the identity provider. |
| `hemlig login` hand-off intercepted or redirected | The console posts the token only to `http://127.0.0.1:<port>` (CSP `form-action http://127.0.0.1:*`), never in a URL. The CLI requires a 256-bit `state`, accepts the first valid POST only, and reads the admin API from the console's HTTPS `/config.json`, not the POST. The page shows a code to match against the terminal and arms Authorize only after 1.5 s of focus. | `packages/cli/src/login.ts`, `packages/console/src/views/CliLogin.vue`, `cdk/stack.ts` | A local user who learns the port and `state` can submit their own token, but cannot redirect later commands. The cached token is full admin until it expires; it is a `0600` file. |
| Token for another application accepted as an administrator token | Exact audience match, with the `client_id` fallback only when `aud` is absent. | `src/auth/actors.ts` | Depends on a correct audience in the deployment config. |
| Consumer impersonates another consumer or environment | The consumer ID and environment come from the stored identity record. The caller supplies neither. | `src/auth/actors.ts`, `src/handlers/consumer.ts` | None known. |
| Stolen client certificate and key | Revocation is a strongly consistent DynamoDB status change, effective on the next request. The IoT certificate is revoked too. | `src/repositories/dynamo.ts`, `src/handlers/admin.ts`, `src/services/agent-notifications.ts` | The thief can read until an administrator revokes. Certificates last 365 days. |
| Compromised agent reads secrets outside its grant | Agents are forced through exact-UID AgentGrant checks, even on generic routes. | `src/handlers/consumer.ts`, `src/services/agent-grants.ts` | The agent can read everything in its own grant. |
| Replay of a bootstrap token | Stored only as a hash, valid 30 minutes, one use. The same CSR may retry. | `src/services/agent-grants.ts`, `src/handlers/bootstrap.ts` | A leaked token can be used within its window. |
| Rogue certificate issuance | Only a signed CSR is accepted, never a CA certificate. The root key is encrypted and decryptable only by the administrator, bootstrap and identity-rotation roles. | `src/services/issuer.ts`, `cdk/stack.ts` | A compromise of the administrator, bootstrap or identity-rotation Lambda role could mint certificates. The bootstrap route is unauthenticated except for a one-use token. Rotation is reachable by any active mTLS client. The root is online. |
| Truststore change locks out or admits wrong certificates | A leaf is activated only after API Gateway confirms the pinned bundle. A rejected bundle is rolled back. | `src/services/consumers.ts` | Issuing-root rotation is not supported. |

## Secrets and keys

| Threat | Control | Where enforced (file) | Residual risk |
| --- | --- | --- | --- |
| Plaintext in storage or logs | Payloads are AES-256-GCM encrypted before S3. Access logs exclude headers, queries and bodies. | `src/crypto/envelope.ts`, `cdk/stack.ts` | Plaintext exists in Lambda memory during a read. |
| Ciphertext copied to another secret or version | KMS context and GCM data bind the environment, secret UID and version. The handler also checks the loaded documents against the head. | `src/crypto/envelope.ts`, `src/services/secrets.ts` | None known. |
| Consumer Lambda decrypts the issuing root | Separate KMS context for the root, conditioned in IAM. | `src/services/issuer.ts`, `cdk/stack.ts` | One CMK serves both uses. Separation relies on context conditions. |
| Overwritten or half-applied revision | Immutable objects written once, with an optimistic head lease and recovery. | `src/services/secrets.ts`, `src/handlers/recovery.ts` | None known. |
| Deleting revision history | Object Lock Compliance on revisions. Serving roles cannot delete versions. | `cdk/stack.ts`, `src/handlers/retention.ts` | Compliance locks also prevent intentional early deletion. |

## Audit and operations

| Threat | Control | Where enforced (file) | Residual risk |
| --- | --- | --- | --- |
| Tampering with audit history | Write-once keys in a seven-year Object Lock Compliance bucket. Application roles are write-only. | `src/services/audit.ts`, `cdk/stack.ts` | A compromised writer can add misleading new events. Events are not hash-chained. |
| Secret read with no record | The `succeeded` event is stored before plaintext is returned. | `src/handlers/consumer.ts`, `src/handlers/admin.ts` | Conditional `304` reads and reads of the audit archive are not audited. See [Audit evidence](../guide/audit-evidence.md). |
| Requests rejected before an actor exists | Not recorded as application events, except a rejected Hemlig-issued client certificate, which is recorded as `failed` with `identity_not_active`. A missing or unparseable certificate is not recorded. Rejected-certificate events are limited to one per fingerprint per 10 minutes (a conditional write on the control table, failing open), so a revoked certificate cannot flood the permanent archive. | `src/handlers/shared.ts` | Use API Gateway access logs to investigate. |
| Forged or replayed change hint | Hints carry no payload and grant nothing. Controllers re-sync over mutual TLS. The IoT policy is receive-only and per-topic. | `src/handlers/notifications.ts`, `cdk/stack.ts` | A dropped hint delays updates until the next resync. |
| Browser console reaches the API | Preflight `OPTIONS` is answered without a token and is never audited. The default route needs the token and scope. | `src/handlers/admin.ts`, `cdk/stack.ts` | None known. |

## PKI

These rows cover the CA, grants, issuance and revocation. The PKI invariant is that a PKI-issued certificate never authenticates to the delivery API, AWS IoT or any Hemlig route. For the IAM boundaries see [AWS resources](../reference/aws-resources.md#pki-lambdas).

| Threat | Control | Where enforced (file) | Residual risk |
| --- | --- | --- | --- |
| A PKI certificate authenticates to Hemlig | Seven layers: the truststore holds only enrollment roots, the identity lookup needs an `IDENTITY#` item, PKI decrypts only `purpose=pki-ca`, PKI roles have a write allowlist and no truststore or IoT access, PKI code cannot import the identity services, reserved identities are refused | `cdk/stack.ts`, `src/auth/actors.ts`, `src/pki/chain.ts`, `src/pki/import-boundary.test.ts` | None known. The acceptance gate PKI-3 checks it on a deployment |
| A compromised cluster mints names outside its grant | Deny by default. The CSR is never a template: names come from it and are checked against the grant, and the final name check runs after forced attributes | `src/pki/policy.ts`, `src/pki/issuance-model.ts` | Anything inside its own grant |
| A compromised cluster mints a CA | `isCA` is denied on every v1 path, and Hemlig builds `CA:FALSE` | `src/pki/policy.ts`, `src/pki/issuance-model.ts` | None |
| Issuance flood or cost exhaustion | Grant hour and day quotas and the per-CA hourly counter, all in the commit. The route throttle. The CA capacity cap | `src/repositories/pki.ts`, `src/pki/issuance-service.ts`, `src/pki/capacity-service.ts`, `cdk/stack.ts` | Up to the quota until the grant is disabled |
| Grant narrowed, CA retired or revoked, or identity revoked during issuance | Commit-time conditions on grant `uid`, version, status and expiry, the CA's version, status and key, and the identity and AgentGrant. A conflict reruns the pipeline once | `src/repositories/pki.ts`, `src/pki/issuance-service.ts` | A certificate committed before the change stands until revoked |
| Two certificates for one request, or one serial for two | The serial and the replay record are written with `attribute_not_exists`. The loser of a race returns the winner | `src/repositories/pki.ts`, `src/pki/issuance-service.ts` | One extra certificate per distinct consumer after an issuer repoint (accepted) |
| A revoked or expired certificate delivered by replay | Replay re-reads the certificate and the CA, and refuses a revoked one or one with `notAfter` within 60 seconds | `src/pki/issuance-service.ts` | None known |
| A malformed or substituted certificate is returned | Hemlig re-parses the signed leaf and checks the signature, serial, names, keys, usages, extensions and size against the plan before it commits | `src/pki/issuance-model.ts` | None known |
| Unrecorded issuance or key copy by a compromised PKI role | Nothing is released before the commit. The success audit event is written before the response. The key is decrypted only with `purpose=pki-ca`, and CloudTrail records each `Decrypt` | `src/handlers/pki-issuer-routes.ts`, `cdk/stack.ts` | A wrapped key can be copied and used offline until the root revokes the intermediate or it expires. Relying parties outside the cluster need the root CRL from the operator |
| Forged, stale or regressed Hemlig CRL | CA-signed. Numbers strictly increase. A lease and a monotone pointer commit. A staleness alarm. Revocation publishes inline, or within 15 minutes by maintenance | `src/pki/crl-service.ts`, `src/repositories/pki.ts` | Relying parties that ignore CRLs |
| Forged or rolled-back root CRL | Verified against the stored root key and exact issuer. Numbers must increase. Only an identical retry is accepted | `src/pki/crl-verify.ts`, `src/pki/external-ca-service.ts` | A compromised CA administrator can withhold uploads (alarmed) but cannot forge them |
| Compromised offline root | Outside Hemlig. The recipe keeps the key offline and encrypted | [Offline root recipe](../operations/pki-offline-root.md) | Rotate the root. Hemlig cannot detect it |
| A CRL too large to deliver | The capacity count and cap, and the per-CA hourly issuance counter. Revocation is never refused | `src/pki/capacity-service.ts`, `src/pki/ca-model.ts` | The count's age and index lag, absorbed by the `2 x rate` spare |
| Two issuers publish CRLs under one name | A deployment-wide subject registry, external names included | `src/pki/subject.ts` | Across separate Hemlig deployments |
| Name confusion (IDN, case, trailing dot, wildcard reach) | A-label round trip, canonicalization and wildcard coverage rules | `src/pki/names.ts` | Clients that compare U-labels |
| Spoofed requester metadata | Recorded as caller-asserted, charset-checked, never used for authorization and not part of the replay digest | `src/pki/issuance-model.ts` | Misleading inventory annotations |
| Private key or CSR in logs or audit | Field allowlists. Tests scan logs and audit targets for `-----BEGIN` | `src/pki/issuance-service.ts`, `src/handlers/pki-issuer-routes.ts` | None known |
| Failure events flood the permanent audit archive | One failure event per identity, grant and reason every 10 minutes, claimed with a conditional write that fails open | `src/handlers/pki-issuer-routes.ts`, `src/repositories/dynamo.ts` | A compromised `pki-issuer` can claim other fingerprints' suppression slots and hide their rejection events |
| A compromised administrator | Optional PKI roles. Every mutation is audited with the grant's policy digest | `src/handlers/pki-admin.ts`, `src/pki/grant-service.ts` | A CA administrator can create CAs and grants, and an operator can issue anything within the CA's constraints |

### Accepted limitations

- **Shared idempotency records.** `pki-admin` writes `IDEMPOTENCY#human#*` items, which IAM cannot scope by sort key, so a compromised `pki-admin` can overwrite other administrators' replay records. The effect is confused replays only.
- **Audit suppression.** `pki-issuer` writes `AUDIT_SUPPRESS#*` items for the failure throttle, so a compromised `pki-issuer` can suppress the rejection events of other fingerprints.
- **No AgentGrant kill switch.** An AgentGrant has no revoked state. Revoking the agent's client certificate is how you stop its PKI access, and it takes effect on the next request and at the commit of any in-flight issuance.
- **Bulk revoke is not atomic.** A consumer-wide revoke commits in batches. A partial run leaves some certificates revoked. Repeat it with the same key until `complete` is `true`.
- **Per-CA serialization.** Issuance under one CA serializes on its hourly counter, and a request that keeps conflicting returns `503`. Retry with the same key.

## Not covered

- Compromise of the AWS account or of an IAM principal with broad access.
- A malicious or compromised identity provider.
- Local emulation (MiniStack) is not evidence that IAM, mTLS or Object Lock behave correctly in AWS. Use the [acceptance runbook](../operations/acceptance.md).

Found a gap? See [Reporting vulnerabilities](reporting.md).
