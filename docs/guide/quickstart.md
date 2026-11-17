---
title: Quickstart and local development
description: Run Hemlig locally with MiniStack, the dev API bridge and the console.
---

# Quickstart and local development

## Prerequisites

- Node.js 24 and Corepack (`corepack enable`; Yarn 4 is pinned in `package.json`)
- Docker (for MiniStack, a local AWS emulator)

## Install and test

```sh
corepack enable
yarn install
yarn build
yarn test          # root service + CDK construct (Jest)
```

`yarn test:all` builds every workspace and runs each package's tests.

## Run the API and console locally

```sh
yarn ministack:up   # MiniStack on :4566 (DynamoDB, S3, KMS)
yarn dev:api        # provisions hml-local resources, serves a dev admin bridge on :5274
yarn dev:ui         # serves the console on :5273
```

Open the console at `http://127.0.0.1:5273`. The first screen asks you to create
an environment. Stop MiniStack with `yarn ministack:down` (this deletes its state).

`yarn dev:api` invokes the admin handlers in process and fabricates the JWT claims
API Gateway would normally validate. It binds to loopback only, requires a local
`AWS_ENDPOINT_URL`, and is never bundled into a Lambda.

To verify DynamoDB, S3 and KMS integration against MiniStack:

```sh
yarn ministack:up
yarn ministack:verify
```

## What local dev cannot prove

MiniStack does not validate API Gateway custom-domain mTLS, IAM policies, OIDC
authorizers, CORS preflight against the real routes, CloudTrail, or Object Lock
administrative behavior. Those need an isolated AWS account; see the
[acceptance runbook](../operations/acceptance.md).

## Next

- Deploy to AWS: [Deploying with CDK](deploying.md).
- Package-level commands and conventions: [Contributing](../contributing/index.md).
