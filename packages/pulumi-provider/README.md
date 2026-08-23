# Clavis Pulumi provider

`@clavis/pulumi-provider` is a dynamic Pulumi provider for Clavis control-plane
secrets. It uses the administrator API; AWS infrastructure remains owned by the
`clavis/cdk` construct.

```ts
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@clavis/pulumi-provider";

const clavis = new Provider("clavis", {
  adminUrl: "https://admin.example.com",
  adminToken: pulumi.secret(process.env.CLAVIS_ADMIN_TOKEN!),
});

clavis.secret("payments", {
  secretId: "payments-api",
  environment: "prod",
  metadata: { name: "payments-api", path: "payments/production" },
  acl: [{ clusterId: "prod-east", permissions: ["read"] }],
  payload: pulumi.secret({ API_TOKEN: { encoding: "utf8", value: "value" } }),
});
```

The service has no public secret deletion endpoint. Destroying this resource
removes it from Pulumi state but intentionally leaves the remote secret intact.
