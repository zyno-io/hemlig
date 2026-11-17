# Contributing to Hemlig

Thanks for helping. The full contributor guide lives in the docs:

- Site: https://zyno-io.github.io/hemlig/contributing/
- Source: [docs/contributing/index.md](docs/contributing/index.md)
- Repository layout: [docs/contributing/layout.md](docs/contributing/layout.md)
- Docs workflow and Pages deploy: [docs/contributing/docs-site.md](docs/contributing/docs-site.md)

## Quick start

```sh
corepack enable      # Node.js 24, Yarn 4
yarn install
yarn build && yarn test
yarn lint            # type-check service and CDK
yarn test:all        # every workspace
yarn docs:dev        # preview the docs site
```

## Before you open a pull request

- Run `yarn lint`, `yarn test` and the tests of the packages you changed.
- Update the docs (and `openapi/consumer-secrets.yaml` for route changes) with your
  change; `yarn docs:build` must pass (it fails on dead links).
- Never include secrets, tokens, private keys or internal infrastructure names in
  code, tests, docs or issues.
- Report security issues privately; see [SECURITY.md](SECURITY.md).

Licensing boundaries per component are described in [LICENSING.md](LICENSING.md).
