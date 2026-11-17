---
title: "Quickstart: run Hemlig locally"
description: In about ten minutes you run the administrator API and console on your machine, then create, write and read back a secret.
pageType: tutorial
---

# Quickstart: run Hemlig locally

In about ten minutes you run the [administrator API](../reference/glossary.md#administrator-api) and [console](../reference/glossary.md#console) on your machine, then create, write and read back a secret.

## Before you start

- Node.js 24 with Corepack, Docker, `curl` and `jq`.
- Ports 4566, 5273 and 5274 free on your machine.
- About ten minutes. No AWS account is needed.

## Steps

You need three terminals: one for MiniStack (a local AWS emulator, see [MiniStack](../reference/glossary.md#ministack)), one for the API and one for the console. Use a fourth for the `curl` commands, or reuse the first.

### 1. Clone and install

```sh
git clone https://github.com/zyno-io/hemlig
cd hemlig
corepack enable
yarn install
```

Expected output ends with:

```text
➤ YN0000: · Done with warnings in 1s 622ms
```

### 2. Start MiniStack

```sh
yarn ministack:up
```

Expected output: Docker reports the `ministack` container as started. It runs image `ministackorg/ministack:1.4.21` on port 4566.

```text
 Container <project>-ministack-1 Started
```

Check that the port answers: `curl -s localhost:4566/_localstack/health` returns JSON listing services such as `"s3"` and `"dynamodb"`.

### 3. Start the API

In a second terminal, from the same directory:

```sh
yarn dev:api
```

::: warning Local mode is not a deployment
The local bridge **bypasses authentication** and serves only the administrator API. There is no delivery API. It binds to loopback and refuses a non-local `AWS_ENDPOINT_URL`.
:::

Expected output, after the build finishes:

```text
created bucket hml-local-truststore
created bucket hml-local-audit (object lock)
created bucket hml-local-revision (object lock)
created table hml-local-control
created key alias/hml-local-application
Hemlig dev admin bridge on http://127.0.0.1:5274 (console origin http://127.0.0.1:5273)
Authentication is bypassed. Local MiniStack use only.
```

Leave it running.

### 4. Create an environment

An [environment](../reference/glossary.md#environment) groups secrets. A fresh deployment has none. Use the first terminal again.

```sh
export HEMLIG_ADMIN_URL=http://127.0.0.1:5274
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/environments" \
  -H 'content-type: application/json' \
  -d '{"name":"dev"}' | jq
```

No `Authorization` header is needed locally. Expected output (HTTP 201):

```json
{
  "name": "dev",
  "createdAt": "2030-01-01T00:00:00.000Z",
  "createdBy": { "type": "human", "id": "local-administrator" }
}
```

### 5. Create a secret

Every change needs an [idempotency key](../reference/glossary.md#idempotency-key). The request also needs `metadata` and `acl`, even when both are empty.

```sh
CONTROL=$(curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/secrets" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H 'content-type: application/json' \
  -d '{"secretId":"payments/stripe/api-key","environment":"dev","metadata":{"description":"Stripe API key"},"acl":[]}' \
  | tee /dev/stderr | jq -r .controlVersionId)
```

Expected output (HTTP 201), trimmed:

```json
{
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-754df98b-e142-4a31-bf22-81cf3a83a78c",
  "environment": "dev",
  "state": "PENDING_VALUE",
  "metadata": { "description": "Stripe API key" },
  "acl": []
}
```

The secret exists but has no value yet (`PENDING_VALUE`). The shell variable `CONTROL` now holds its [ETag](../reference/glossary.md#etag).

### 6. Write the value

The write needs the ETag in `If-Match`, so it fails if someone else changed the secret first.

```sh
curl -sS -X PUT "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key/payload?environment=dev" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "If-Match: $CONTROL" \
  -H 'content-type: application/json' \
  -d '{"payload":{"api-key":{"encoding":"utf8","value":"sk_test_example_123"}}}' | jq
```

Expected output (HTTP 200), trimmed. The state is now `ACTIVE`, with a new ETag and a `payloadVersionId`:

```json
{
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-86757576-3558-4717-878d-f181810eea70",
  "payloadVersionId": "pay-290191a8-be05-42ed-b016-d2803bb846f2",
  "payloadKeyCount": 1,
  "state": "ACTIVE"
}
```

### 7. Read it back

```sh
curl -sS "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key/payload?environment=dev" | jq
```

Expected output:

```json
{
  "secretId": "payments/stripe/api-key",
  "controlVersionId": "ctl-86757576-3558-4717-878d-f181810eea70",
  "payloadVersionId": "pay-290191a8-be05-42ed-b016-d2803bb846f2",
  "payload": {
    "api-key": { "encoding": "utf8", "value": "sk_test_example_123" }
  }
}
```

### 8. See it in the console and audit log

In a third terminal run `yarn dev:ui`, then open `http://127.0.0.1:5273`. Open the `dev` environment to see the secret in the catalog, then open **Audit** to see the events from steps 4 to 7.

To see the same events without the console:

```sh
curl -sS "$HEMLIG_ADMIN_URL/v1/admin/audit?environment=dev" | jq '.events[] | {operation, outcome}'
```

Expected output, one object per event, newest first (the `actor`, `target` and other fields are trimmed):

```json
{ "operation": "adminget:/v1/admin/secrets/payments/stripe/api-key/payload", "outcome": "succeeded" }
{ "operation": "adminput:/v1/admin/secrets/payments/stripe/api-key/payload", "outcome": "succeeded" }
{ "operation": "adminpost:/v1/admin/secrets", "outcome": "succeeded" }
{ "operation": "adminpost:/v1/admin/environments", "outcome": "succeeded" }
```

### 9. Clean up

Stop `yarn dev:api` and `yarn dev:ui` with Ctrl+C, then remove MiniStack and its state:

```sh
yarn ministack:down
```

## What you just did

- Created an environment, `dev`.
- Created a secret with a [secret ID](../reference/glossary.md#secret-id) and a first [control revision](../reference/glossary.md#control-revision), whose version ID is the ETag.
- Wrote a [payload](../reference/glossary.md#payload) as a second revision, guarded by `If-Match` and an idempotency key.
- Read the audit trail of those requests as [audit events](../reference/glossary.md#audit-event).

## What local mode cannot show

| Capability | Why | Where to see it |
| --- | --- | --- |
| Delivery with mTLS | No API Gateway locally, so no delivery API | [Tutorial: your first secret in Kubernetes](first-secret.md) |
| Token checks | The bridge fabricates the token claims | [Connect your identity provider](identity-provider.md) |
| Object Lock retention | Local buckets keep data for one day, not 90 days or 7 years | [Acceptance runbook](../operations/acceptance.md) |
| Consumer enrollment | Publishing the truststore needs the API Gateway domain | [Tutorial: your first secret in Kubernetes](first-secret.md) |
| Change hints | No AWS IoT locally | [Sync and change hints](sync-and-notifications.md) |

## Next steps

- [Deploy Hemlig to AWS](deploying.md)
- [Tutorial: your first secret in Kubernetes](first-secret.md)
- [Concepts](concepts.md)
