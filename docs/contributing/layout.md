---
title: Repository layout
description: Map of the Hemlig monorepo, workspace ownership and licensing boundaries.
pageType: reference
---

# Repository layout

Hemlig is a Yarn 4 workspace monorepo: the root `hemlig` package is the AWS service and the reusable CDK construct, and integrations live in `packages/`.

| Path                             | Package / owner                         | What it is                                                                                   | License |
| -------------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------- | ------- |
| `src/`                           | root `hemlig`                           | Lambda handlers, services, repositories, crypto, dev scripts and migration scripts           | AGPL-3.0-only |
| `cdk/`                           | root `hemlig` (`hemlig/cdk`)            | `HemligStack` construct, `DeploymentConfig`, reference CDK app                                | MIT     |
| `openapi/`                       | root                                    | OpenAPI 3.1 contract                                                                         | MIT     |
| `packages/client`                | `@zyno-io/hemlig-client`                | Typed HTTPS client and shared payload/control models                                         | MIT     |
| `packages/cli`                   | `@zyno-io/hemlig-cli`                   | JSON-only administrator CLI (`hemlig`)                                                       | MIT     |
| `packages/kubernetes-controller` | `@zyno-io/hemlig-kubernetes-controller` | CRDs, reconciler, Dockerfile, Helm chart (`chart/hemlig-controller`), raw manifests (`config/`) | MIT |
| `packages/pulumi-provider`       | `@zyno-io/hemlig-pulumi-provider`       | Pulumi dynamic provider for secrets and agent grants                                         | MIT     |
| `packages/console`               | `@zyno-io/hemlig-console`               | Vue single-page administrator console                                                         | AGPL-3.0-only |
| `docs/`                          | `@zyno-io/hemlig-docs` (private)        | This VitePress site; `docs/design/` holds historical design records                          | AGPL-3.0-only |
| `scripts/`                       | root                                    | `release.mjs` (tag validation, packing, publication) and its tests                           | AGPL-3.0-only |
| `.github/workflows/`             |                                         | `ci.yml` (verify, MiniStack, image, chart, release) and `docs.yml` (docs build and Pages)    | n/a     |

See [LICENSING.md](https://github.com/zyno-io/hemlig/blob/main/LICENSING.md) for the exact subtree boundaries and the
commercial-hosting source obligations.

## Ownership rules

- The controller and Pulumi provider depend on the shared **client**; they never
  import Lambda source or duplicate HTTP request shapes.
- The CLI uses the client for secret lifecycle; it does not manage Kubernetes
  resources or enroll consumers.
- The **controller** owns Kubernetes Secret materialization and export. The
  **Pulumi provider** owns declarative secrets and agent grants. The **CDK
  construct** alone provisions the Hemlig service; a provider resource never creates
  a second deployment topology or manages the CMK.
- Only `client`, `cli` and `pulumi-provider` are published to npm. The root package
  (`hemlig`, imported by CDK apps as `hemlig/cdk`), the console and the controller
  workspace are not. See [Releasing](releasing.md).

## Workspace-wide commands

```sh
yarn build:all   # topological build of every workspace
yarn lint:all    # build then lint every workspace
yarn test:all    # build then test every workspace
```

The docs workspace deliberately only defines `docs:*` scripts, so these
`foreach` commands skip it. Build docs with `yarn docs:build`.

::: details Possible future layout

This is a note about a direction, not a commitment.

The root package mixes the service (`src/`), the construct (`cdk/`) and the
workspace tooling. A cleaner shape would move `src/` and `cdk/` into a
`packages/server` workspace.

This has **not** been done on purpose: downstream CDK apps import `hemlig/cdk`
from the root package, so moving it is a breaking change to every installer's
import path and the published package contents. It would need
a coordinated migration (for example a root package that re-exports
`@zyno-io/hemlig-server/cdk`, a deprecation period, and updated release tooling).
Until then the layout above is canonical.

:::
