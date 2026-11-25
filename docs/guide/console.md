---
title: Console
description: Host the static Vue management console, sign in, and see what it can and cannot do.
pageType: how-to
---

# Console

The console is a static browser app for the administrator API. Enable it with one CDK field, sign in with your identity provider, and manage secrets and consumers without curl.

It is an ordinary HTTP client of the [administrator API](../reference/glossary.md#administrator-api): no server, no AWS credentials, and no access to DynamoDB, S3 or KMS. The package is `@zyno-io/hemlig-console` (`packages/console`), licensed AGPL-3.0-only with the server.

**Before you start:** a [deployed stack](deploying.md), an [identity provider](identity-provider.md) with a single-page-app registration, and an ACM certificate in `us-east-1` covering the console host.

## Enable hosting

Setting `consoleFqdn` makes the stack host the console on a private S3 bucket behind CloudFront. It also allows that one origin through the admin API's CORS configuration.

### 1. Add the console fields

They must be set together.

| Field | Required | Description |
| --- | --- | --- |
| `consoleFqdn` | yes | Console host, for example `console.example.com`. May be the zone apex |
| `oidcAdminScope` | yes | Short scope carried in the access token, for example `hemlig.admin` |
| `oidcConsoleAccessScope` | yes | Resource-qualified scope the browser requests |
| `oidcClientId` | yes | The single-page app's OAuth client ID |
| `consoleCertificateArn` | no | ACM certificate in `us-east-1`. The simplest path |
| `oidcAdminRole` | no | Role the Lambda requires after the gateway validates the token |

The full field list is in [Configuration](../reference/configuration.md#cdk-deploymentconfig).

### 2. Deploy the stack again

```sh
yarn cdk:deploy \
  -c environment=prod \
  -c adminFqdn=admin.example.com \
  -c apiFqdn=api.example.com \
  -c consoleFqdn=console.example.com \
  -c zoneDomain=example.com \
  -c existingHostedZoneId=Z0123456789ABCDEF \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=00000000-0000-0000-0000-000000000000 \
  -c oidcAdminScope=hemlig.admin \
  -c oidcConsoleAccessScope=api://00000000-0000-0000-0000-000000000000/hemlig.admin \
  -c oidcClientId=11111111-1111-1111-1111-111111111111 \
  -c consoleCertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555
```

### 3. Check the outputs

Expected outputs: `ConsoleUrl`, `ConsoleBucketName` and `ConsoleDistributionId`.

If `ConsoleAssetsPending` appears instead, the build output was missing at synth time. Run `yarn console:build` and deploy again, or publish `packages/console/dist` to `ConsoleBucketName` in your own pipeline.

### The certificate

CloudFront accepts certificates from `us-east-1` only, and the stack's own API certificate is regional, so it cannot be reused. Supplying `consoleCertificateArn` is the simple path.

Without it the stack creates a sibling `us-east-1` certificate stack. That needs a concrete `env` on your stack **and** `existingHostedZoneId`; synthesis fails with a clear error otherwise.

If you use a non-default CDK bootstrap qualifier, also set `bootstrapQualifier` and a matching synthesizer.

### What CloudFront serves

| Path | Caching | `frame-ancestors` |
| --- | --- | --- |
| `index.html`, `config.json` | none | `'none'` |
| `silent.html` | none | `'self'` |
| `assets/*` (content-hashed) | long-lived, immutable | `'none'` |

Every response carries a strict Content-Security-Policy. `silent.html` is the only framable document, because OIDC silent renewal loads your provider in a hidden iframe that redirects back to it. Without that exception every token renewal fails and each session falls back to a full redirect.

`connect-src` names exactly the admin API origin and the issuer origin. A provider that serves tokens or keys from a different origin than its issuer (Google, for example) needs both origins allowed, which the stack does not do today.

The generated `config.json` carries the deployment name, the admin API URL and the OIDC client settings. The console is deliberately cross-origin to the admin API; the [console plan](../design/console-plan.md) explains why CloudFront stays out of the credential path.

## Sign in

Open the console URL. It redirects to your provider and returns with an access token (not an ID token) that it sends to the admin API. The API then applies the same checks as for curl, described in [Connect your identity provider](identity-provider.md#what-the-api-checks).

A `401` comes from API Gateway: sign in again. A `403` means the Lambda refused a token the gateway accepted, which is a deployment configuration mismatch. See [Troubleshooting](../operations/troubleshooting.md#administrator-api).

A fresh deployment has no environments. The console prompts you to create the first one.

## What it can and cannot do

| Area | Can | Cannot |
| --- | --- | --- |
| Secrets | Browse and search the catalog, create, edit metadata and ACLs, write payloads, inspect revisions, archive | Show values in lists. A value loads only when you ask, and every such read is audited |
| Environments | List and create | Delete |
| Consumers | Enroll with an optional in-browser CSR generator, rotate or revoke client certificates, see truststore status | |
| Agent grants | Revoke a secret from an existing grant | Create a grant or issue a bootstrap token. Use the API, the [Pulumi provider](pulumi.md) or curl |
| PKI | List CAs and offline roots. Create a CA (an intermediate signed by your offline root in two phases, an intermediate signed by a Hemlig root, or a root held by Hemlig), activate it, download certificates and CRLs, upload a root CRL, retire, abandon or destroy the key. Edit grants with validate and evaluate. Revoke a certificate, or a consumer's certificates in bulk | Edit a CA's policy, revoke or distrust a CA, issue as an administrator, or migrate grants in bulk. Use the [CLI](cli.md) or [Pulumi](pulumi-pki.md) |
| Audit | Browse the audit archive | |

## PKI

The PKI tab lists the environment's certificate authorities and the offline roots they chain to. Create a CA there, or roll one over: "Roll over" pre-fills the old CA's settings with an incremented name and common name, and blocks Create while the subject DN equals the old one, because a DN is never reused. See [Roll over a CA](../operations/pki-ca-rollover.md).

The kind picker offers three choices. "Intermediate signed by your offline root (recommended)" is `EXTERNAL_INTERMEDIATE`: Hemlig creates the key and a CSR, you sign the CSR with your root, and you paste back the certificate.

"Intermediate signed by a Hemlig root" is `INTERMEDIATE`.

"Root held by Hemlig (not recommended)" is `ROOT`; selecting it shows the server's recommendation to use an offline root, and asks you to acknowledge it before Create. An intermediate signed by your offline root shows its CSR after creation.

The activation panel has two tabs, EZ (the default) and Manual. EZ shows copy-ready [`hemlig pki ez`](cli.md#offline-root-pki-ez) commands with the CA's ID and environment filled in: one for the machine that holds the root, and an air-gapped variant that pins the CSR with its SPKI SHA-256, followed by the `activate` command for an online machine.

Manual is the paste-the-certificate form: sign the CSR yourself, then paste the certificate and the root chain.

The root-CRL upload dialog has the same two tabs: EZ shows the `renew-crl` and `upload-crl` commands. The console remembers your last tab in this browser. A root CRL is optional at activation. Without one, the root CRL state is `MISSING` until you upload it.

Retiring a CA asks for the CA name when grants still reference it. Abandoning a pending CA and destroying a disabled key always ask you to type the CA name. A grant's editor validates against the server and tests the saved grant with a dry-run evaluation. An unsaved draft is not tested.

A consumer's "Certificate grants" tab lists its grants and the certificates they issued, and creates new grants. Deleting a grant does not revoke its certificates. Revoke them from the same tab, which asks you to type the consumer ID and can limit the revocation to one grant, or to one generation of a deleted grant.

::: warning PKI reads are audited
Every PKI read and evaluation writes an audit event, unlike routine secret metadata. The console therefore never refetches PKI data on focus or reconnect, loads details only when you open them, and runs validate and evaluate only when you ask. Reload deliberately.
:::

## CLI authorization

The `/cli-login` page lets a signed-in administrator hand a token to `hemlig login` on this computer, or, with `mode=code` for SSH sessions, copy a login code to paste into the terminal; see [CLI sign in](cli.md#sign-in-with-hemlig-login).

## Local development

See the [quickstart](quickstart.md). From `packages/console`:

```sh
yarn dev      # vite dev server on 127.0.0.1:5273
yarn build    # type-check and bundle to dist/
yarn lint     # vue-tsc --noEmit
yarn test     # vitest
```

Contributor invariants, such as never fetching payloads to render lists and never retrying a `412`, live in the [package README](https://github.com/zyno-io/hemlig/blob/main/packages/console/README.md).

## Next steps

- [Validate it with the acceptance gates](../operations/acceptance.md)
- [Manage secrets](managing-secrets.md)
