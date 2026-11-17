---
title: Manage secrets
description: Create, update, read and archive a Hemlig secret with the console, the CLI, curl or Pulumi.
pageType: how-to
---

# Manage secrets

Create a secret, give it a value, share it with a consumer, read it back and archive it, using whichever tool you prefer.

**Before you start**

- Role: administrator, with an OIDC access token for the API audience ([how to get one](cli.md#get-an-administrator-token)).
- An [environment](../reference/glossary.md#environment) named `prod` already exists.
- For the access step, a [direct consumer](../reference/glossary.md#direct-consumer) is enrolled. See [Connect a workload without Kubernetes](direct-consumers.md).
- Time: a few minutes of hands-on work and no waiting steps.

Set these once. The CLI reads the first three. curl needs the token value.

```sh
export HEMLIG_ADMIN_URL=https://admin.example.com
export HEMLIG_ENVIRONMENT=prod
export HEMLIG_ADMIN_TOKEN_FILE=$HOME/.hemlig-token
export HEMLIG_ADMIN_TOKEN=$(cat "$HEMLIG_ADMIN_TOKEN_FILE")
```

The API rules behind each step (ETags, idempotency, audit) are on [Administrator secret routes](../reference/api/admin-secrets.md) and the [API overview](../reference/api/index.md).

## 1. Create the secret

A new secret has metadata and an ACL but no value. Its state is `PENDING_VALUE`.

::: code-group

```text [Console]
1. Open Secrets and choose the prod environment.
2. Choose New secret.
3. Enter the secret ID payments/stripe/api-key and a description.
4. Save.
```

```sh [CLI]
printf '%s\n' '{"metadata":{"description":"Stripe API key"},"acl":[]}' |
  hemlig secret create --secret-id payments/stripe/api-key --input - > created.json
```

```sh [curl]
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/secrets" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"secretId":"payments/stripe/api-key","environment":"prod","metadata":{"description":"Stripe API key"},"acl":[]}' \
  > created.json
```

```ts [Pulumi]
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@zyno-io/hemlig-pulumi-provider";

const hemlig = new Provider("hemlig", { adminUrl: "https://admin.example.com" });

// The provider creates the secret and writes the payload in one resource.
export const apiKey = hemlig.secret("stripe-api-key", {
  secretId: "payments/stripe/api-key",
  environment: "prod",
  metadata: { description: "Stripe API key" },
  acl: [],
  payload: pulumi.secret({ "api-key": { encoding: "utf8", value: "sk_test_example" } }),
});
```

:::

Expected output (CLI and curl), trimmed:

```json
{ "secretId": "payments/stripe/api-key", "state": "PENDING_VALUE", "controlVersionId": "ctl-..." }
```

The CLI wraps this in a receipt, so the same data sits under `data` and the ETag is `etag`. Pulumi users can skip to step 4: the payload is part of the resource.

## 2. Write the value

Each write replaces the whole payload and activates the secret. You need the current ETag.

::: code-group

```text [Console]
1. Open the secret and choose Replace payload.
2. Add the entry api-key with the value (Form, JSON and .env tabs are available).
3. Choose Replace payload, then confirm.
```

```sh [CLI]
etag=$(jq -r .etag created.json)
printf '%s\n' '{"api-key":{"encoding":"utf8","value":"sk_test_example"}}' |
  hemlig secret write-payload --secret-id payments/stripe/api-key --if-match "$etag" --input - > written.json
```

```sh [curl]
etag=$(jq -r .controlVersionId created.json)
curl -sS -X PUT "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key/payload?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "If-Match: \"$etag\"" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"payload":{"api-key":{"encoding":"utf8","value":"sk_test_example"}}}' \
  > written.json
```

```ts [Pulumi]
// Change the `payload` input of the resource above and run `pulumi up`.
// A payload revision is written only when the declared payload changes.
```

:::

Expected output: `"state": "ACTIVE"` and new `controlVersionId` and `payloadVersionId` values. The response never echoes the value.

## 3. Read the secret

Metadata reads never decrypt anything. Reading the value is a deliberate, audited action.

::: code-group

```text [Console]
Open the secret to see metadata and access.
Choose Reveal in the Payload section to read the value.
```

```sh [CLI]
hemlig secret read --secret-id payments/stripe/api-key > current.json
hemlig secret read-payload --secret-id payments/stripe/api-key > payload-receipt.json
```

```sh [curl]
curl -sS "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" > current.json
curl -sS "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key/payload?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" > payload.json
```

```text [Pulumi]
The provider has no read operation. Use the console, CLI or curl.
```

:::

::: warning Treat payload output as secret
`payload-receipt.json` and `payload.json` hold the plaintext. Delete them when you are done, and never commit them.
:::

## 4. Share the secret with a consumer

Replace the ACL to let a [direct consumer](../reference/glossary.md#direct-consumer) read the secret. A supplied `acl` replaces the whole list. An [agent](../reference/glossary.md#agent) cannot be added here; use an [AgentGrant](agent-grants.md).

::: code-group

```text [Console]
Open the secret and choose Edit metadata & ACL.
Add the consumer payments-prod with read, then Save.
```

```sh [CLI]
etag=$(jq -r .etag current.json)
printf '%s\n' '{"acl":[{"consumerId":"payments-prod","permissions":["read"]}]}' |
  hemlig secret update --secret-id payments/stripe/api-key --if-match "$etag" --input - > updated.json
```

```sh [curl]
etag=$(jq -r .controlVersionId current.json)
curl -sS -X PUT "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "If-Match: \"$etag\"" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"acl":[{"consumerId":"payments-prod","permissions":["read"]}]}' > updated.json
```

```ts [Pulumi]
// Set the `acl` input of the resource above, then run `pulumi up`.
acl: [{ consumerId: "payments-prod", permissions: ["read"] }],
```

:::

Expected output: the same secret with the new `acl` and a new `controlVersionId`. A `412 precondition_failed` means someone changed the secret since you read it. Read it again and decide whether your change still applies.

## 5. Archive the secret

Archiving is final. There is no delete.

::: code-group

```text [Console]
Open the secret and choose Archive secret.
```

```sh [CLI]
etag=$(jq -r .etag updated.json)
hemlig secret archive --secret-id payments/stripe/api-key --if-match "$etag" > archived.json
```

```sh [curl]
etag=$(jq -r .controlVersionId updated.json)
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/secrets/payments/stripe/api-key/archive?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "If-Match: \"$etag\"" \
  -H "Idempotency-Key: $(uuidgen)" > archived.json
```

```text [Pulumi]
Destroying the resource only removes it from Pulumi state. The secret stays.
Archive with the console, CLI or curl.
```

:::

::: danger Archive revokes access and frees the ID
Archiving empties the ACL, so every reader receives a revocation and deletes its copy. The ID can be reused at once, but the old secret keeps its own [UID](../reference/glossary.md#secret-uid) and history.
:::

Expected output: `"state": "ARCHIVED"` and a `secretUid`. Keep the UID. It is how you look the record up later:

```sh
uid=$(jq -r .data.secretUid archived.json)
hemlig secret read --secret-uid "$uid"
```

## Verify

List the active catalog. The secret must be gone from it.

```sh
curl -sS "$HEMLIG_ADMIN_URL/v1/admin/secrets?environment=prod&pathPrefix=payments" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN"
```

Expected output: a page whose `secrets` list does not contain `payments/stripe/api-key`.

## Next steps

- [Connect a workload without Kubernetes](direct-consumers.md)
- [Agent grants](agent-grants.md)
- [Audit evidence](audit-evidence.md)
