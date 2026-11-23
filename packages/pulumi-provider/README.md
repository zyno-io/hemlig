# Hemlig Pulumi provider

`@zyno-io/hemlig-pulumi-provider` is a dynamic Pulumi provider for Hemlig control-plane
secrets. It uses the administrator API; AWS infrastructure remains owned by the
`hemlig/cdk` construct.

```ts
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@zyno-io/hemlig-pulumi-provider";

const hemlig = new Provider("hemlig", {
  adminUrl: "https://admin.example.com",
});

hemlig.secret("payments", {
  secretId: "payments-api",
  environment: "prod",
  metadata: { description: "Payments API" },
  acl: [{ consumerId: "prod-east", permissions: ["read"] }],
  payload: pulumi.secret({ API_TOKEN: { encoding: "utf8", value: "value" } }),
});

const paymentsAgent = hemlig.agentGrant(
  "payments-agent",
  {
    consumerId: "prod-payments",
    environment: "prod",
    capabilities: ["read", "write"],
    secretGrants: [
      {
        secretId: "payments/production/api-key",
        permissions: ["read", "write"],
      },
    ],
    displayName: "payments namespace in prod",
    bootstrapGeneration: "1",
  },
  { protect: true },
);

// Store only this one-use value in the intended namespace. It expires after
// 30 minutes and is consumed by the controller when it creates its mTLS leaf.
new k8s.core.v1.Secret("payments-bootstrap", {
  metadata: { name: "payments-bootstrap", namespace: "payments" },
  stringData: { token: paymentsAgent.bootstrapToken },
});
```

The service has no public secret deletion endpoint. Destroying this resource
removes it from Pulumi state but intentionally leaves the remote secret intact.

Set a short-lived OIDC token in `HEMLIG_ADMIN_TOKEN` for each invocation. The
provider reads it only while performing a Hemlig API mutation; it is not a
Pulumi resource input or output. A payload revision is written only when the
declared payload changes. Metadata or ACL-only changes create a new control
revision while retaining the current payload revision.

An AgentGrant's consumer ID and environment are immutable; changing either
replaces the resource. Exact per-secret permissions are updated in place and
automatically reconcile read delivery access. `bootstrapGeneration` may be
bumped only while its grant is still pending, to replace an expired unredeemed
capability; each bump creates one fresh 30-minute capability.

## PKI

`hemlig.certificateAuthority` and `hemlig.issuanceGrant` declare PKI
certificate authorities and issuance grants. An external CA is created in two
applies: the first outputs `csrPem` while the CA is `PENDING_CERTIFICATE`; after
the offline root signs it, set `signedCertificatePem` and `chainPem` and apply
again to activate it. Pulumi never sends or uploads a root CRL.

```ts
const issuing = hemlig.certificateAuthority(
  "prod-issuing-1",
  {
    environment: "prod",
    name: "prod-issuing-1",
    kind: "EXTERNAL_INTERMEDIATE",
    keyAlgorithm: "ECDSA_P256",
    subject: { commonName: "Example Prod Issuing CA 1" },
    signedCertificatePem: config.get("issuing1Certificate"),
    chainPem: config.get("issuing1Chain"),
  },
  { protect: true },
);
export const csrPem = issuing.csrPem;
```

A CA is never replaced. Its name, kind, key algorithm, subject, parent and
constraints are immutable, and changing one fails at preview with the rollover
procedure. Policy and display name update in place.

**Delete means retire.** Destroying a CA resource retires an `ACTIVE` CA, but
only after every grant that references it has been deleted or migrated. For any
other status it makes no remote call. The provider can never destroy a key,
abandon or revoke a CA, or revoke certificates, and destroying a grant leaves a
tombstone. Use `protect: true`. See
[Manage PKI with Pulumi](https://zyno-io.github.io/hemlig/guide/pulumi-pki.html).
