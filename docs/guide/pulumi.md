---
title: Pulumi provider
description: Declare Hemlig secrets and agent grants from Pulumi.
---

# Pulumi provider

`@zyno-io/hemlig-pulumi-provider` is a dynamic Pulumi provider for Hemlig
control-plane resources. It talks to the **administrator API**; AWS infrastructure
for Hemlig itself is owned by the [CDK construct](deploying.md). MIT licensed,
Node.js 24.

```sh
npm install @zyno-io/hemlig-pulumi-provider
```

```ts
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@zyno-io/hemlig-pulumi-provider";

const hemlig = new Provider("hemlig", { adminUrl: "https://admin.example.com" });

hemlig.secret("payments", {
  secretId: "payments-api",
  environment: "prod",
  metadata: { description: "Payments API" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
  payload: pulumi.secret({ API_TOKEN: { encoding: "utf8", value: "value" } }),
});

const agent = hemlig.agentGrant(
  "payments-agent",
  {
    consumerId: "prod-payments",
    environment: "prod",
    capabilities: ["read", "write"],
    secretGrants: [{ secretId: "payments/production/api-key", permissions: ["read", "write"] }],
    displayName: "payments namespace in prod",
    bootstrapGeneration: "1",
  },
  { protect: true },
);

// One-use, 30-minute capability for the controller to redeem.
new k8s.core.v1.Secret("payments-bootstrap", {
  metadata: { name: "payments-bootstrap", namespace: "payments" },
  stringData: { token: agent.bootstrapToken },
});
```

## Behavior to know

- Set a short-lived OIDC token in `HEMLIG_ADMIN_TOKEN` per invocation. It is read
  only while calling the API and is not a Pulumi input or output.
- Hemlig has no public secret deletion. Destroying a `secret` resource removes it
  from Pulumi state and leaves the remote secret intact.
- A payload revision is written only when the declared payload changes; metadata
  or ACL-only changes create a control revision and keep the payload.
- ACL rows for agent-enrolled consumers are server-managed. The provider
  preserves them automatically, so you do not declare them in `acl`; this needs
  a server that reports `agentManagedConsumerIds`. Against an older server, do
  not manage `acl` for an agent-granted secret.
- An AgentGrant's `consumerId` and `environment` are immutable (changing either
  replaces the resource). Per-secret permissions update in place.
- `bootstrapGeneration` may be bumped only while the grant is still `PENDING`, to
  replace an expired unredeemed capability (each bump creates a new 30-minute one).
