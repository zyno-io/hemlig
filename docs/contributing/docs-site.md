---
title: Docs site and style guide
description: How to write, preview and publish the Hemlig documentation site, with the style rules every page follows.
pageType: how-to
---

# Docs site and style guide

The docs are a [VitePress](https://vitepress.dev) 1.x site in `docs/`, published at `https://zyno-io.github.io/hemlig/`. This page covers the workflow, how to add a page, the style rules and the review checklist.

## Preview and build

The site is a private Yarn workspace (`@zyno-io/hemlig-docs`) with base path `/hemlig/`.

```sh
yarn install
yarn docs:dev       # live preview
yarn docs:build     # production build; fails on dead links
yarn docs:lint      # style checks (see "Automated checks")
yarn docs:preview   # serve the build output
```

## Add a page

1. Create the Markdown file under `docs/guide/`, `docs/reference/`, `docs/operations/`, `docs/security/` or `docs/contributing/`.
2. Add frontmatter with `title`, `description` and `pageType` (rules 1 and 2 below).
3. Add the page to the sidebar in `docs/.vitepress/config.ts`.
4. Link to the topic's owner page instead of re-explaining it (rule 10).
5. Link the new page from at least one existing page.
6. Run `yarn docs:build` and `yarn docs:lint`.

Pages that are not ready use `search: false` in frontmatter so they stay out of local search.

## Style guide

### Structure

1. **One page type.** Frontmatter declares `pageType: tutorial | how-to | reference | explanation`. A how-to explains internals in at most one sentence and then links. Reference pages contain no rationale.
2. **Summary first.** The H1 is followed by one sentence of 30 words or fewer saying what the reader gets. Frontmatter `description` repeats it. Tutorials and how-tos follow it with a "Before you start" list covering role, prerequisites and time.
3. **Short paragraphs.** A paragraph is at most 4 rendered lines (about 60 words or 3 sentences). Each sentence carries one idea. Never chain parentheticals.
4. **Procedures are numbered.** Each step is one action and one fenced `sh` block that can be pasted (no `$` prompt), then an "Expected output" block. The last step is "Verify". Output shapes must match the handler; cite the handler file in the PR description.
5. **Endings and headings.** Every tutorial and how-to ends with "Next steps" (at most 3 links). Task headings are imperative ("Create the grant"). Reference headings are nouns.

### Words and examples

6. **Placeholders are variables.** Set them once at the top (`export HEMLIG_ADMIN_URL=https://admin.example.com`). Never use `<angle>` placeholders inside commands. Prose placeholders go in code spans, because Vue parses bare `<x>`.
7. **One running example site-wide.** Use these values everywhere:

   | Thing | Value |
   | --- | --- |
   | Deployment name and runtime environment | `prod` |
   | Secret | `payments/stripe/api-key`, entry `api-key` |
   | Namespace | `payments` |
   | Consumer ID | `payments-prod` |
   | HemligProvider | `production` |
   | Hosts | `admin.example.com`, `api.example.com`, `console.example.com` |
   | DNS zone | `example.com` |

8. **Define, then link.** The first use of a glossary term on a page links to its [glossary](../reference/glossary.md) anchor. Use glossary spelling exactly:
   - "client certificate", not leaf or API identity, except where an API field name requires it;
   - "bootstrap token" (API: bootstrap capability);
   - "deployment name" versus "environment";
   - "AgentGrant", "direct consumer" and "agent".
9. **Tables for options.** Fields, flags, environment variables, values, error codes and status reasons always go in tables with columns Name | Required | Default | Description (or Code | Status | Meaning | Action). Never list options in prose.
10. **One home per topic.** Explain a topic only on its owner page (table below). Elsewhere write two sentences and link.
11. **Numbers come from one place.** Limits, TTLs and intervals live in [Limits and timings](../reference/limits.md). Repeat a number elsewhere only where the reader acts on it, and link it.

### Diagrams, callouts and code

12. **Diagrams for flows.** Any flow with 3 or more actors or 4 or more steps gets a mermaid `sequenceDiagram`, `flowchart` or `stateDiagram-v2`. Keep diagrams to about 12 nodes. Label edges with the credential (OIDC token, client certificate, bootstrap token). Diagram text is not searched, so key terms must also appear in prose.
13. **Callouts are rare and sit at the step they guard.** Use at most 2 per page. `warning` and `danger` are only for data loss, security exposure or irreversible actions. `tip` is for optional shortcuts. Do not use `info` for core content.
14. **Mark version gates with a badge.** Add `<Badge type="tip" text="v0.3.0+" />` on the heading plus one line on what older versions do. Avoid relative-time phrases ("recently", "the first release that...").
15. **Code-fence hygiene.**
    - Every fence has a language.
    - Show several tools with `::: code-group` (Console | CLI | curl | Pulumi).
    - Put responses over 15 lines in `::: details Example response`.
    - JSON timestamps use `2030-01-01T00:00:00.000Z`.
16. **Links and hygiene.**
    - Use relative `.md` links between pages; they work on GitHub and VitePress checks them.
    - Link source files with full `https://github.com/zyno-io/hemlig/blob/main/...` URLs.
    - No internal names, hosts, clusters, people or real dates.

### Topic owners

| Topic | Owner page |
| --- | --- |
| Term definitions | [Glossary](../reference/glossary.md) |
| Any number (limit, TTL, retention, interval) | [Limits and timings](../reference/limits.md) |
| Access model (ACL versus AgentGrant, direct versus agent) | [Concepts](../guide/concepts.md) |
| Token requirements (`aud`, `iss`, scope, role) | [Connect your identity provider](../guide/identity-provider.md) |
| Console hosting | [Console](../guide/console.md) |
| Enrollment, truststore, root, revocation mechanics | [Identity and trust](../guide/identity-and-trust.md) |
| Revisions, UIDs, encryption, KMS contexts | [Secrets, revisions and encryption](../guide/secrets-and-encryption.md) |
| IAM per Lambda, stack outputs | [AWS resources and IAM](../reference/aws-resources.md) |
| Sync, checkpoints, MQTT | [Sync and change hints](../guide/sync-and-notifications.md) |
| Audit semantics | [Audit evidence](../guide/audit-evidence.md) |
| Route contracts | [HTTP API](../reference/api/index.md) |
| Error codes | [Errors](../reference/api/errors.md) |
| CRD fields, status reasons | [Kubernetes CRDs](../reference/crds.md) |
| DeploymentConfig, Helm, environment variables | [Configuration](../reference/configuration.md) |
| Deletion safety | [Revocation and deletion safety](../operations/safety.md) |
| Maintenance scripts | [Upgrades and migrations](../operations/upgrades.md) |

## Page checklist

Copy this into the pull request description.

- [ ] Frontmatter has `title`, `description` and `pageType`; the page has one type.
- [ ] A summary sentence of 30 words or fewer follows the H1.
- [ ] Paragraphs are short; options are in tables; procedures are numbered with expected output.
- [ ] Placeholders are variables; examples use the running example.
- [ ] First use of each glossary term links to the glossary.
- [ ] Numbers link to Limits and timings; no topic is explained twice.
- [ ] Flows of 3 or more actors have a diagram; at most 2 callouts.
- [ ] Every fence has a language; no internal names, hosts or real dates.
- [ ] Every fact was checked against the code, and the PR lists the source file for each changed fact.
- [ ] `yarn docs:build` and `yarn docs:lint` pass; commands you could not run are listed in the PR.

## Search and design archive

- Local search is on. `docs/design/` is excluded from search but stays reachable; each design page carries a "historical design record" banner. Do not edit it.
- Pages with `search: false` frontmatter are excluded from search.
- Every page has an "Edit this page on GitHub" link.

## Redirect a moved page

Keep the old URL as a stub whose meta refresh points at the new one. The target includes the `/hemlig/` base:

```md
---
title: Moved
search: false
sidebar: false
aside: false
head:
  - - meta
    - http-equiv: refresh
      content: 0; url=/hemlig/contributing/releasing
---

# Moved

This page is now [Releasing](../contributing/releasing.md).
```

## Automated checks

`yarn docs:lint` runs `docs/scripts/lint-docs.mjs` over every page except `docs/design/`. It checks:

- `description` and `pageType` frontmatter;
- a text paragraph directly after the H1;
- a language on every code fence;
- no `::: info` callouts;
- banned phrases and hostnames outside an allowlist;
- that every `](page.md#anchor)` link resolves to a heading in the target page.

Placeholder pages (`search: false`, "Being written.") are skipped until they are written.

## How deploys work

`.github/workflows/docs.yml`:

- **Pull requests** touching `docs/**` (or `openapi/**`, `package.json`, `yarn.lock`) build the site only. Nothing is deployed.
- **Pushes to `main`** and manual runs (`workflow_dispatch`) build the site, upload it with `actions/upload-pages-artifact` and deploy with `actions/deploy-pages`.

::: warning One-time maintainer setup
GitHub Pages is not enabled by default. A repository maintainer must open **Settings, Pages** and set **Source** to **GitHub Actions** before the first deployment can succeed. If the repository has a `github-pages` environment protection rule, ensure `main` is allowed to deploy to it.
:::

The `docs` workspace is `private` and is never packed into a npm release. Build output (`docs/.vitepress/dist`) and cache are git-ignored.
