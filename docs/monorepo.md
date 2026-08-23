# Clavis monorepo

This repository is a Yarn Berry workspace monorepo. The root `clavis` package
remains the publishable AWS service and CDK construct; it owns Lambda handlers,
the public OpenAPI contract, and `clavis/cdk`.

| Workspace | Ownership | Purpose |
| --- | --- | --- |
| root `clavis` | AWS service | Lambda APIs, shared root CA, CDK construct, storage, audit |
| `@clavis/client` | shared consumer contract | Typed HTTPS client and import/export payload/control models |
| `@clavis/kubernetes-controller` | Kubernetes consumer | Namespaced import/export CRDs and reconciler |
| `@clavis/pulumi-provider` | IaC consumer | Pulumi dynamic provider for declarative control-plane secrets |

Use `yarn build:all`, `yarn lint:all`, and `yarn test:all` for workspace-wide
commands. The controller and Pulumi package intentionally depend on the shared
client rather than importing Lambda source or duplicating HTTP request shapes.

The controller owns Kubernetes Secret materialization and export. The Pulumi
provider owns administrative declaration of Clavis secrets. The AWS/CDK package
still owns provisioning the Clavis service itself; a provider resource never
creates a second deployment topology or manages the Clavis CMK.
