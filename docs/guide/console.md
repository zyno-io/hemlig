---
title: Console
description: The static Vue management console for the administrator API.
---

# Console

`@zyno-io/hemlig-console` (`packages/console`) is a static Vue single-page app for
the administrator API. It is an ordinary HTTP client of the public API: no server,
no AWS credentials, no access to DynamoDB, S3 or KMS. It is licensed AGPL-3.0-only
with the server.

## What it does

Browse and search the secret catalog (folders, tags, archived view), create
secrets, edit metadata and ACLs, write payloads (values load only when you ask,
and every read is audited), inspect revisions and archive secrets, manage
environments, enroll consumers and rotate or revoke their certificates (with an
optional in-browser CSR generator), see truststore status, and browse the audit
archive, and revoke a secret from an existing agent grant. Creating agent grants
and issuing bootstrap capabilities are not in the console yet; use the API, the
[Pulumi provider](pulumi.md) or `curl`.

## Hosting

The CDK stack hosts it when you set `consoleFqdn`: a private S3 bucket behind
CloudFront with a strict Content-Security-Policy, plus a generated `config.json`
carrying the deployment name, admin API URL and OIDC client settings. See
[Deploying with CDK](deploying.md#console-hosting) for the required inputs
(`consoleFqdn`, `oidcAdminScope`, `oidcConsoleAccessScope`, `oidcClientId`, and an
ACM certificate in `us-east-1`).

## Authentication

The browser signs in with your OIDC provider (access token, not ID token) and
sends it to the admin API, which is deliberately cross-origin. A `401` comes from
API Gateway (re-authenticate); a `403` means the handler rejected an
already-accepted token, which indicates a deployment configuration mismatch.

## Local development

See [Quickstart](quickstart.md). Commands from `packages/console`:

```sh
yarn dev      # vite dev server on 127.0.0.1:5273
yarn build    # type-check and bundle to dist/
yarn lint     # vue-tsc --noEmit
yarn test     # vitest
```

Contributor-facing invariants (never fetch payloads to render lists, never retry a
`412`, empty pages are not "no results") are documented in the
[package README](https://github.com/zyno-io/hemlig/blob/main/packages/console/README.md).
The original [console plan](../design/console-plan.md) is a historical record.
