# Hemlig monorepo

This repository is a Yarn Berry workspace monorepo. The root `hemlig` package
remains the publishable AWS service and CDK construct; it owns Lambda handlers,
the public OpenAPI contract, and `hemlig/cdk`.

| Workspace | Ownership | Purpose |
| --- | --- | --- |
| root `hemlig` | AWS service | Lambda APIs, shared root CA, CDK construct, storage, audit |
| `@hemlig/client` | shared client contract | Typed HTTPS client and import/export payload/control models |
| `@hemlig/kubernetes-controller` | Kubernetes integration | Namespaced import/export CRDs and reconciler |
| `@hemlig/pulumi-provider` | IaC integration | Pulumi dynamic provider for declarative control-plane secrets |
| `@hemlig/console` | browser administration | Static Vue management interface for the administrator API |

Use `yarn build:all`, `yarn lint:all`, and `yarn test:all` for workspace-wide
commands. The controller and Pulumi package intentionally depend on the shared
client rather than importing Lambda source or duplicating HTTP request shapes.

The controller owns Kubernetes Secret materialization and export. The Pulumi
provider owns administrative declaration of Hemlig secrets. The AWS/CDK package
still owns provisioning the Hemlig service itself; a provider resource never
creates a second deployment topology or manages the Hemlig CMK.
