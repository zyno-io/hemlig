# Hemlig Pulumi provider

`@hemlig/pulumi-provider` is a dynamic Pulumi provider for Hemlig control-plane
secrets. It uses the administrator API; AWS infrastructure remains owned by the
`hemlig/cdk` construct.

```ts
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@hemlig/pulumi-provider";

const hemlig = new Provider("hemlig", {
  adminUrl: "https://admin.example.com",
  adminToken: pulumi.secret(process.env.HEMLIG_ADMIN_TOKEN!),
});

hemlig.secret("payments", {
  secretId: "payments-api",
  environment: "prod",
  metadata: { name: "payments-api", path: "payments/production" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
  payload: pulumi.secret({ API_TOKEN: { encoding: "utf8", value: "value" } }),
});
```

The service has no public secret deletion endpoint. Destroying this resource
removes it from Pulumi state but intentionally leaves the remote secret intact.
