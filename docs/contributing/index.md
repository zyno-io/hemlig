---
title: Contributing
description: Prerequisites, dev loop, tests per package, conventions and the PR checklist for Hemlig.
pageType: how-to
---

# Contributing

Set up the repository, run the tests and open a pull request. The root
[`CONTRIBUTING.md`](https://github.com/zyno-io/hemlig/blob/main/CONTRIBUTING.md) links here.

Where code lives: [Repository layout](layout.md). How to write docs: [Docs site and style guide](docs-site.md).

## Prerequisites

- Node.js 24 and Corepack (`corepack enable`)
- Docker, for MiniStack (local DynamoDB/S3/KMS)
- Optional: Helm 3 (chart lint), an AWS sandbox account (acceptance runbook)

```sh
corepack enable
yarn install
```

## Dev loop

```sh
yarn build            # root service (tsc to dist/)
yarn test             # root service + CDK construct (Jest)
yarn ministack:up     # local AWS emulator on :4566
yarn dev:api          # dev admin bridge on :5274 (builds first)
yarn dev:ui           # console dev server on :5273
yarn ministack:verify # DynamoDB/S3/KMS integration checks against MiniStack
```

To try the local stack as a user, follow the [quickstart](../guide/quickstart.md).

## Tests per package

| Where                              | Command                                          | Framework        |
| ---------------------------------- | ------------------------------------------------ | ---------------- |
| Root service + `cdk/`              | `yarn test` (`yarn test:watch`)                  | Jest + ts-jest   |
| Root type checks                   | `yarn lint` (service and CDK `tsc --noEmit`)     | tsc              |
| `client`, `cli`, `kubernetes-controller`, `pulumi-provider` | `yarn workspace @zyno-io/hemlig-client build && yarn workspace <name> build && yarn workspace <name> test` | `node --test` on built output |
| `console`                          | `yarn workspace @zyno-io/hemlig-console test`    | Vitest           |
| Everything                         | `yarn lint:all`, `yarn test:all`                 |                  |
| Release script                     | `node --test scripts/release.test.mjs`           | `node --test`    |
| Helm chart                         | `helm lint packages/kubernetes-controller/chart/hemlig-controller` | Helm |

CI (`.github/workflows/ci.yml`) runs release tests, `lint:all`, `test`, `test:all`,
`build:cdk`, MiniStack verification, Helm lint/template and release packaging dry runs.

## Conventions

- TypeScript strict mode; format with `yarn format` (Prettier).
- Keep the layering: handlers call services, services call repositories and AWS
  adapters. Do not import `src/` from `packages/*`; use the client.
- Never log or audit secret values, tokens, CSR private keys or request bodies.
- Mutations are idempotent and ETag-guarded; preserve that contract and update the
  OpenAPI file and docs together with any route change.
- Public documentation must not contain internal infrastructure names, hostnames
  or dates of real certificates. Use `example.com` style placeholders.
- Changes to deploys, secrets, auth or deletion behavior need a careful review.

## Documentation

Docs live in `docs/` and ship as a VitePress site. See
[Docs site and style guide](docs-site.md) for the workflow, the style rules and the
page checklist.

## Pull requests

1. Branch from `main`; keep commits focused.
2. Run `yarn lint`, `yarn test` and the package tests you touched; run
   `yarn docs:build` (and `yarn docs:lint`) when editing docs.
3. Describe behavior changes and any rollout ordering (for example
   server-before-controller).
4. Do not tag releases; see [Releasing](releasing.md).
