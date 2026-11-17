---
title: Docs site
description: How to write, preview and publish the Hemlig documentation site.
---

# Docs site

The site is [VitePress](https://vitepress.dev) 1.x in `docs/`, a private Yarn
workspace (`@zyno-io/hemlig-docs`). It is published at
`https://zyno-io.github.io/hemlig/` (base path `/hemlig/`).

## Workflow

```sh
yarn install
yarn docs:dev       # live preview
yarn docs:build     # production build; fails on dead links
yarn docs:preview   # serve the build output
```

- Pages are Markdown under `docs/`, grouped as `guide/`, `reference/`,
  `operations/`, `security/`, `contributing/` and `design/`. Add new pages to the
  sidebar in `docs/.vitepress/config.ts`.
- Link to other pages with site-absolute paths (`/guide/concepts`) or relative `.md`
  links. Dead-link checking is on, so links to files outside `docs/` (source files,
  `LICENSING.md`) must be full GitHub URLs.
- Put angle-bracket placeholders (`<consumerId>`) in code spans, not bare prose, or
  Vue will try to parse them as tags.
- Local search is enabled. `docs/design/` is excluded from search but still
  reachable; each design page carries a "historical design record" banner.
- Every page has an "Edit this page on GitHub" link.
- Use placeholders (`example.com`); never add internal hostnames or cluster names.

## How deploys work

`.github/workflows/docs.yml`:

- **Pull requests** touching `docs/**` (or `openapi/**`, `package.json`, `yarn.lock`)
  build the site only. Nothing is deployed.
- **Pushes to `main`** and manual runs (`workflow_dispatch`) build the site, upload
  it with `actions/upload-pages-artifact` and deploy with `actions/deploy-pages`
  (permissions `pages: write`, `id-token: write`; concurrency group `pages`).

::: warning One-time maintainer setup
GitHub Pages is not enabled by default. A repository maintainer must open
**Settings, Pages** and set **Source** to **GitHub Actions** before the first
deployment can succeed. If the repository has a `github-pages` environment
protection rule, ensure `main` is allowed to deploy to it.
:::

## Publishing

The `docs` workspace is `private` and is not part of any npm release. Because it
is a workspace, Yarn never packs `docs/` into the root `hemlig` package; the
published documentation is this site.
Build output (`docs/.vitepress/dist`) and cache are git-ignored.
