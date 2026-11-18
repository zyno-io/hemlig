---
title: "Give a cluster access"
description: "Create an AgentGrant, issue a bootstrap token, and change or narrow a cluster's scope."
pageType: how-to
---

# Give a cluster access

Create an [AgentGrant](../reference/glossary.md#agentgrant) that lists the secrets a namespace may read or write, then hand its [bootstrap token](../reference/glossary.md#bootstrap-token) to the team.

**Role:** administrator. **Before you start:**

- An environment and the secrets to grant already exist. Grant creation fails with `404` for a secret that does not exist.
- You have an administrator access token (see [Identity provider](identity-provider.md#verify-your-token)).
- You chose a [consumer ID](../reference/limits.md#identity) that has never been enrolled.

```sh
export HEMLIG_ADMIN_URL=https://admin.example.com
export HEMLIG_ADMIN_TOKEN=eyJ...   # a short-lived OIDC access token
```

## Create the grant

The grant is an exact allow-list. A folder never authorizes anything, so list every secret ID. The limit is in [Limits and timings](../reference/limits.md#secrets-and-grants).

::: code-group

```sh [curl]
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/agent-grants" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "consumerId": "payments-prod",
    "environment": "prod",
    "capabilities": ["read"],
    "secretGrants": [
      { "secretId": "payments/stripe/api-key", "permissions": ["read"] }
    ],
    "displayName": "payments namespace in prod"
  }'
```

```ts [Pulumi]
const stripeKey = hemlig.secret("stripe-key", {
  secretId: "payments/stripe/api-key",
  environment: "prod",
  metadata: { description: "Stripe API key" },
  acl: [],
  payload: pulumi.secret({ "api-key": { encoding: "utf8", value: "changeme" } }),
});

const grant = hemlig.agentGrant(
  "payments-prod",
  {
    consumerId: "payments-prod",
    environment: "prod",
    capabilities: ["read"],
    secretGrants: [{ secretId: "payments/stripe/api-key", permissions: ["read"] }],
    displayName: "payments namespace in prod",
    bootstrapGeneration: "1",
  },
  { dependsOn: [stripeKey], protect: true },
);
```

:::

Expected output (curl):

```json
{
  "grantId": "grant-0a1b2c3d",
  "consumerId": "payments-prod",
  "environment": "prod",
  "capabilities": ["read"],
  "secretGrants": [
    { "secretId": "payments/stripe/api-key", "secretUid": "...", "permissions": ["read"] }
  ],
  "status": "PENDING"
}
```

Rules the server enforces:

- Every permission in `secretGrants` must also be in `capabilities`.
- Each capability (`read`, `write`) needs at least one secret that uses it.
- Secret IDs must be unique within the grant.

The Pulumi tab uses `dependsOn` because the grant resolves each secret when it is created. Without it the grant fails unless the secret already exists.

## Issue a bootstrap token

The grant starts as `PENDING`. Issue the token that the controller redeems once.

```sh
export GRANT_ID=grant-0a1b2c3d
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/agent-grants/$GRANT_ID/bootstrap-capabilities" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN"
```

Expected output:

```json
{ "grantId": "grant-0a1b2c3d", "token": "hmlb_...", "expiresAt": "2030-01-01T00:30:00.000Z" }
```

The token is shown once and is valid for 30 minutes (see [Limits and timings](../reference/limits.md#identity)). Hemlig does not store it. The Pulumi `agentGrant` resource exposes it as `bootstrapToken`.

Give it to the platform team, who put it in a Secret as described in [Install the controller](kubernetes.md#bootstrap-a-namespace).

## Verify

Once the controller has redeemed the token, the grant becomes `ACTIVE`. Check that the consumer is `Ready` in the namespace:

```sh
kubectl -n payments get hmlconsumer
```

Expected output:

```text
NAME       READY   REASON          IDENTITY-EXPIRES   ROTATION   AGE
payments   True    IdentityReady   2031-01-01T...     NotDue     1m
```

## Change the grant scope

`PUT` replaces `capabilities` and `secretGrants` in full, and optionally `displayName`. The grant ID, consumer ID and environment never change. Send the complete new list, not a delta.

```sh
curl -sS -X PUT "$HEMLIG_ADMIN_URL/v1/admin/agent-grants/$GRANT_ID" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "capabilities": ["read", "write"],
    "secretGrants": [
      { "secretId": "payments/stripe/api-key", "permissions": ["read"] },
      { "secretId": "payments/stripe/webhook-source", "permissions": ["write"] }
    ]
  }'
```

On an `ACTIVE` grant the change applies at once, and the controller picks it up on its next sync. In Pulumi, edit `secretGrants` and run `pulumi up`; permissions update in place.

::: warning Removing a secret removes the namespace's copy
When you take a secret out of a grant, the controller deletes the Kubernetes Secret it imported from it (status `AccessRevoked`). Warn the team first. See [Safety](../operations/safety.md).
:::

## Replace an expired token

A bootstrap token that expired before the controller used it is replaced by issuing another one. This works only while the grant is `PENDING`.

::: code-group

```sh [curl]
curl -sS -X POST "$HEMLIG_ADMIN_URL/v1/admin/agent-grants/$GRANT_ID/bootstrap-capabilities" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN"
```

```ts [Pulumi]
// Bump the string, then run `pulumi up`. Each bump issues a new 30-minute token.
bootstrapGeneration: "2",
```

:::

Then update the bootstrap Secret in the namespace with the new token.

## Re-bootstrap an ACTIVE grant

You cannot. Once the first redemption succeeds the grant is `ACTIVE`, and issuing another token returns `409`. A consumer ID maps to exactly one grant.

If a cluster lost its certificate, recover it with [Identity rotation](../operations/identity-rotation.md#if-the-certificate-already-expired). If you want a clean start, create a new grant with a new consumer ID and re-grant the secrets to it.

## Next steps

- [Import a secret into your namespace](import-secret.md)
- [Export a Kubernetes Secret to Hemlig](export-secret.md)
- [Status reasons](../reference/crds.md#status-reasons)
