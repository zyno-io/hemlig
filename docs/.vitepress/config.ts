import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

const repo = "https://github.com/zyno-io/hemlig";
const siteUrl = "https://zyno-io.github.io/hemlig/";
const ogImage = `${siteUrl}og-image.png`;

// "guide/cli.md" -> "guide/cli"; "reference/api/index.md" -> "reference/api/".
const pageUrl = (relativePath: string): string =>
  siteUrl + relativePath.replace(/(^|\/)index\.md$/, "$1").replace(/\.md$/, "");

export default withMermaid(
  defineConfig({
    title: "Hemlig",
    description:
      "A serverless secrets manager you deploy in your own AWS account. No per-secret fees, access granted on the secret instead of an IAM role per workload, and changes pushed to Kubernetes.",
    base: "/hemlig/",
    lang: "en-US",
    cleanUrls: true,
    lastUpdated: true,
    // Dead-link checking stays ON: a broken internal link fails the build.
    ignoreDeadLinks: false,
    srcExclude: ["README.md"],
    head: [["meta", { name: "theme-color", content: "#2f6f5e" }]],
    sitemap: { hostname: siteUrl },
    // Open Graph and Twitter card tags for link previews. Each page's title and
    // `description` frontmatter feed them; the site description is the fallback.
    transformHead: ({ pageData, title, description }) => {
      const url = pageUrl(pageData.relativePath);
      return [
        ["link", { rel: "canonical", href: url }],
        ["meta", { property: "og:type", content: "website" }],
        ["meta", { property: "og:site_name", content: "Hemlig" }],
        ["meta", { property: "og:title", content: title }],
        ["meta", { property: "og:description", content: description }],
        ["meta", { property: "og:url", content: url }],
        ["meta", { property: "og:image", content: ogImage }],
        ["meta", { property: "og:image:width", content: "1200" }],
        ["meta", { property: "og:image:height", content: "630" }],
        [
          "meta",
          {
            property: "og:image:alt",
            content: "Hemlig: serverless secrets, without the IAM sprawl",
          },
        ],
        ["meta", { name: "twitter:card", content: "summary_large_image" }],
        ["meta", { name: "twitter:title", content: title }],
        ["meta", { name: "twitter:description", content: description }],
        ["meta", { name: "twitter:image", content: ogImage }],
      ];
    },
    themeConfig: {
      nav: [
        {
          text: "Get started",
          link: "/guide/what-is-hemlig",
          activeMatch:
            "^/guide/(what-is-hemlig|quickstart|first-secret|concepts)",
        },
        {
          text: "Guides",
          link: "/guide/deploying",
          activeMatch:
            "^/guide/(?!what-is-hemlig|quickstart|first-secret|concepts)",
        },
        {
          text: "Operations",
          link: "/operations/troubleshooting",
          activeMatch: "^/operations/",
        },
        {
          text: "Reference",
          link: "/reference/api/",
          activeMatch: "^/reference/",
        },
        {
          text: "More",
          activeMatch: "^/(security|contributing|design)/",
          items: [
            { text: "Security", link: "/security/threat-model" },
            { text: "Contributing", link: "/contributing/" },
            { text: "Design archive", link: "/design/" },
          ],
        },
      ],
      sidebar: {
        "/": [
          {
            text: "Start here",
            items: [
              { text: "What is Hemlig", link: "/guide/what-is-hemlig" },
              { text: "Quickstart: run it locally", link: "/guide/quickstart" },
              {
                text: "Tutorial: your first secret in Kubernetes",
                link: "/guide/first-secret",
              },
              { text: "Concepts", link: "/guide/concepts" },
            ],
          },
          {
            text: "Deploy and configure",
            items: [
              { text: "Deploy Hemlig to AWS", link: "/guide/deploying" },
              {
                text: "Connect your identity provider",
                link: "/guide/identity-provider",
              },
              {
                text: "Validate in a real AWS account",
                link: "/operations/acceptance",
              },
              {
                text: "Install the Kubernetes controller",
                link: "/guide/kubernetes",
              },
            ],
          },
          {
            text: "Use Hemlig",
            items: [
              { text: "Manage secrets", link: "/guide/managing-secrets" },
              { text: "Give a cluster access", link: "/guide/agent-grants" },
              {
                text: "Import a secret into your namespace",
                link: "/guide/import-secret",
              },
              {
                text: "Export a Kubernetes Secret to Hemlig",
                link: "/guide/export-secret",
              },
              {
                text: "Connect a workload without Kubernetes",
                link: "/guide/direct-consumers",
              },
              {
                text: "PKI: certificate authorities and CRLs",
                link: "/guide/pki",
              },
            ],
          },
          {
            text: "Tools",
            items: [
              { text: "Console", link: "/guide/console" },
              { text: "CLI", link: "/guide/cli" },
              { text: "Pulumi provider", link: "/guide/pulumi" },
            ],
          },
          {
            text: "Operate",
            items: [
              { text: "Troubleshooting", link: "/operations/troubleshooting" },
              {
                text: "Rotate identities",
                link: "/operations/identity-rotation",
              },
              {
                text: "Revocation and deletion safety",
                link: "/operations/safety",
              },
              {
                text: "Upgrades and migrations",
                link: "/operations/upgrades",
                items: [
                  {
                    text: "Upgrade: immutable secret UIDs",
                    link: "/operations/upgrade-secret-uids",
                  },
                  {
                    text: "Upgrade: API group hemlig.zyno.io",
                    link: "/operations/crd-group-migration",
                  },
                ],
              },
              {
                text: "Roll out controller upgrades with Flux",
                link: "/operations/flux-rollout",
              },
              {
                text: "PKI: offline root recipe",
                link: "/operations/pki-offline-root",
              },
              {
                text: "PKI: roll over a CA",
                link: "/operations/pki-ca-rollover",
              },
            ],
          },
          {
            text: "How it works",
            items: [
              { text: "Architecture overview", link: "/guide/architecture" },
              { text: "Identity and trust", link: "/guide/identity-and-trust" },
              {
                text: "Secrets, revisions and encryption",
                link: "/guide/secrets-and-encryption",
              },
              {
                text: "Sync and change hints",
                link: "/guide/sync-and-notifications",
              },
              { text: "Audit evidence", link: "/guide/audit-evidence" },
            ],
          },
          {
            text: "Security",
            items: [
              { text: "Threat model", link: "/security/threat-model" },
              {
                text: "Reporting vulnerabilities",
                link: "/security/reporting",
              },
            ],
          },
          {
            text: "Reference",
            items: [
              { text: "Glossary", link: "/reference/glossary" },
              { text: "Limits and timings", link: "/reference/limits" },
              {
                text: "HTTP API",
                collapsed: true,
                items: [
                  { text: "Overview", link: "/reference/api/" },
                  { text: "Errors", link: "/reference/api/errors" },
                  { text: "Data types", link: "/reference/api/data-types" },
                  {
                    text: "Admin: environments and secrets",
                    link: "/reference/api/admin-secrets",
                  },
                  {
                    text: "Admin: consumers, issuer and agent grants",
                    link: "/reference/api/admin-consumers",
                  },
                  {
                    text: "Admin: PKI",
                    link: "/reference/api/admin-pki",
                  },
                  {
                    text: "Delivery and agent routes",
                    link: "/reference/api/delivery",
                  },
                  { text: "Audit route", link: "/reference/api/audit" },
                  { text: "OpenAPI contract", link: "/reference/openapi" },
                ],
              },
              {
                text: "Kubernetes CRDs and status reasons",
                link: "/reference/crds",
              },
              { text: "Configuration", link: "/reference/configuration" },
              {
                text: "AWS resources and IAM",
                link: "/reference/aws-resources",
              },
              {
                text: "Control-table data model",
                link: "/reference/data-model",
              },
            ],
          },
        ],
        "/contributing/": [
          {
            text: "Contributing",
            items: [
              { text: "Getting started", link: "/contributing/" },
              { text: "Repository layout", link: "/contributing/layout" },
              {
                text: "Docs site and style guide",
                link: "/contributing/docs-site",
              },
              { text: "Releasing", link: "/contributing/releasing" },
            ],
          },
        ],
        "/design/": [
          {
            text: "Design archive",
            items: [
              { text: "About the archive", link: "/design/" },
              { text: "Implementation plan", link: "/design/plan" },
              { text: "Console plan", link: "/design/console-plan" },
              {
                text: "Kubernetes controller plan",
                link: "/design/kubernetes-controller-plan",
              },
              { text: "Agent sync plan", link: "/design/agent-sync-plan" },
            ],
          },
        ],
      },
      socialLinks: [{ icon: "github", link: repo }],
      editLink: {
        pattern: `${repo}/edit/main/docs/:path`,
        text: "Edit this page on GitHub",
      },
      search: {
        provider: "local",
        options: {
          // Historical design records are noisy and may contradict current
          // behavior; keep them reachable but out of search results.
          // Pages with `search: false` frontmatter (stubs, placeholders, redirects)
          // are skipped too. The custom `_render` replaces VitePress's own check,
          // so frontmatter is only known after rendering.
          _render(src, env, md) {
            if (
              env.relativePath.startsWith("design/") &&
              env.relativePath !== "design/index.md"
            ) {
              return "";
            }
            const html = md.render(src, env);
            if (env.frontmatter?.search === false) {
              return "";
            }
            return html;
          },
        },
      },
      footer: {
        message:
          "Server AGPL-3.0-only; client, CLI, controller, Pulumi provider and CDK MIT.",
      },
      outline: { level: [2, 3], label: "On this page" },
    },
    // "neutral" keeps diagrams grey-on-white in light mode instead of mermaid's
    // default purple; the plugin switches to its dark theme automatically.
    mermaid: { theme: "neutral" },
  }),
);
