# Hemlig Pulumi provider

`@hemlig/pulumi-provider` is a dynamic Pulumi provider for Hemlig control-plane
secrets. It uses the administrator API; AWS infrastructure remains owned by the
`hemlig/cdk` construct.

```ts
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@hemlig/pulumi-provider";

const hemlig = new Provider("hemlig", {
  adminUrl: "https://admin.example.com",
});

hemlig.secret("payments", {
  secretId: "payments-api",
  environment: "prod",
  metadata: { description: "Payments API", path: "payments/production" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
  payload: pulumi.secret({ API_TOKEN: { encoding: "utf8", value: "value" } }),
});
```

The service has no public secret deletion endpoint. Destroying this resource
removes it from Pulumi state but intentionally leaves the remote secret intact.

Set a short-lived OIDC token in `HEMLIG_ADMIN_TOKEN` for each invocation. The
provider reads it only while performing a Hemlig API mutation; it is not a
Pulumi resource input or output. A payload revision is written only when the
declared payload changes. Metadata or ACL-only changes create a new control
revision while retaining the current payload revision.
