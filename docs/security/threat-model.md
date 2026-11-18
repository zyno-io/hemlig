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
| Requests rejected before an actor exists | Not recorded as application events, except a rejected Hemlig-issued client certificate, which is recorded as `failed` with `identity_not_active`. A missing or unparseable certificate is not recorded. | `src/handlers/shared.ts` | Use API Gateway access logs to investigate. |
| Forged or replayed change hint | Hints carry no payload and grant nothing. Controllers re-sync over mutual TLS. The IoT policy is receive-only and per-topic. | `src/handlers/notifications.ts`, `cdk/stack.ts` | A dropped hint delays updates until the next resync. |
| Browser console reaches the API | Preflight `OPTIONS` is answered without a token and is never audited. The default route needs the token and scope. | `src/handlers/admin.ts`, `cdk/stack.ts` | None known. |

## Not covered

- Compromise of the AWS account or of an IAM principal with broad access.
- A malicious or compromised identity provider.
- Local emulation (MiniStack) is not evidence that IAM, mTLS or Object Lock behave correctly in AWS. Use the [acceptance runbook](../operations/acceptance.md).

Found a gap? See [Reporting vulnerabilities](reporting.md).
