---
title: Pulumi provider
description: Declare Hemlig secrets and AgentGrants in Pulumi and hand the bootstrap token to a Kubernetes namespace.
pageType: how-to
---

# Pulumi provider

Declare a secret, an [AgentGrant](../reference/glossary.md#agentgrant) for it and the Kubernetes Secret that carries its bootstrap token, all in one Pulumi program.

`@zyno-io/hemlig-pulumi-provider` is a dynamic Pulumi provider for the [administrator API](../reference/glossary.md#administrator-api). It does not create AWS infrastructure; the [CDK construct](deploying.md) owns that. It is MIT licensed and needs Node.js 24.

**Before you start**

- Role: administrator, with an OIDC access token for the API audience ([get one](cli.md#get-an-administrator-token)).
- The `prod` [environment](../reference/glossary.md#environment) exists.
- A Pulumi project with `@pulumi/pulumi` and `@pulumi/kubernetes`.

## 1. Install the provider

```sh
npm install @zyno-io/hemlig-pulumi-provider
```

## 2. Set the token and the secret value

The provider reads the token from `HEMLIG_ADMIN_TOKEN` while it calls the API. It is not a Pulumi input or output, so it never lands in state.

```sh
export HEMLIG_ADMIN_TOKEN=$(cat "$HOME/.hemlig-token")
pulumi config set --secret stripeApiKey sk_test_example
```

## 3. Declare the resources

The grant resolves each secret ID to an existing secret, so the secret must be created first. The `dependsOn` option guarantees that order.

```ts
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@zyno-io/hemlig-pulumi-provider";

const config = new pulumi.Config();
const stripeKey = config.requireSecret("stripeApiKey");

const hemlig = new Provider("hemlig", { adminUrl: "https://admin.example.com" });

// The secret. Agent rows in `acl` are added by the server from the grant.
const apiKey = hemlig.secret("stripe-api-key", {
  secretId: "payments/stripe/api-key",
  environment: "prod",
  metadata: { description: "Stripe API key" },
  acl: [],
  payload: stripeKey.apply((value) => ({
    "api-key": { encoding: "utf8" as const, value },
  })),
});

// The grant for the namespace agent. It must wait for the secret.
const agent = hemlig.agentGrant(
  "payments-agent",
  {
    consumerId: "payments-prod",
    environment: "prod",
    capabilities: ["read"],
    secretGrants: [{ secretId: "payments/stripe/api-key", permissions: ["read"] }],
    displayName: "Payments namespace in prod",
    bootstrapGeneration: "1",
  },
  { protect: true, dependsOn: [apiKey] },
);

// One-use, 30-minute bootstrap token for the controller to redeem.
new k8s.core.v1.Secret("payments-bootstrap", {
  metadata: { name: "payments-bootstrap", namespace: "payments" },
  stringData: { token: agent.bootstrapToken },
});
```

::: tip Agent rows in `acl` are server-managed
The server adds a read row for each enrolled agent. Do not declare it. The provider ignores agent rows when comparing and sets `preserveAgentAcl` on updates, so the server keeps them.

This needs a server that returns `agentManagedConsumerIds` (v0.3.3 or later). On an older server, a Pulumi update to an agent-granted secret fails with `409 conflict` unless `acl` lists the agent rows exactly as stored, in the same order.
:::

## 4. Preview and apply

```sh
pulumi preview
pulumi up
```

Expected output: a preview that creates the secret, the grant and the Kubernetes Secret, in that order.

## Verify

Read the secret metadata. It must be `ACTIVE`.

```sh
curl -sS "https://admin.example.com/v1/admin/secrets/payments/stripe/api-key?environment=prod" \
  -H "Authorization: Bearer $HEMLIG_ADMIN_TOKEN"
```

Expected output: JSON with `"state": "ACTIVE"`. The grant stays `PENDING` until the controller redeems the token. See [Agent grants](agent-grants.md).

## Behavior

| Topic | Behavior |
| --- | --- |
| Token | Read from `HEMLIG_ADMIN_TOKEN` per call; never stored in state |
| Destroy | Hemlig has no secret deletion. Destroying a `secret` or `agentGrant` resource removes it from Pulumi state and leaves it in Hemlig. |
| Payload | A payload revision is written only when the declared payload changes. Metadata or ACL changes create a control revision and keep the payload. |
| Immutable grant fields | Changing `consumerId` or `environment` replaces the resource |
| Grant policy | `capabilities`, `secretGrants` and `displayName` update in place |
| `bootstrapGeneration` | Bump it only while the grant is still `PENDING`, to replace an expired token. Each bump issues a new 30-minute token. |
| `protect: true` | Used in the example so Pulumi refuses to replace or remove the grant until you unprotect it |

Payload values are stored in Pulumi state, encrypted when marked secret. Treat your state backend accordingly.

## Next steps

- [Manage secrets](managing-secrets.md)
- [Agent grants](agent-grants.md)
- [Install the controller](kubernetes.md)
