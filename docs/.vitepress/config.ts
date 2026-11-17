import { defineConfig } from "vitepress";

const repo = "https://github.com/zyno-io/hemlig";

export default defineConfig({
  title: "Hemlig",
  description:
    "mTLS secrets delivery for non-AWS workloads, backed by AWS Lambda, S3, DynamoDB and KMS.",
  base: "/hemlig/",
  lang: "en-US",
  cleanUrls: true,
  lastUpdated: true,
  // Dead-link checking stays ON: a broken internal link fails the build.
  ignoreDeadLinks: false,
  srcExclude: ["README.md"],
  head: [["meta", { name: "theme-color", content: "#2f6f5e" }]],
  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/what-is-hemlig", activeMatch: "/guide/" },
      { text: "Reference", link: "/reference/api/", activeMatch: "/reference/" },
      {
        text: "Operations",
        link: "/operations/identity-rotation",
        activeMatch: "/operations/",
      },
      { text: "Security", link: "/security/threat-model", activeMatch: "/security/" },
      { text: "Contributing", link: "/contributing/", activeMatch: "/contributing/" },
      { text: "Design archive", link: "/design/", activeMatch: "/design/" },
    ],
    sidebar: {
      "/guide/": [
        {
          text: "Introduction",
          items: [
            { text: "What is Hemlig", link: "/guide/what-is-hemlig" },
            { text: "Concepts", link: "/guide/concepts" },
            { text: "Architecture", link: "/guide/architecture" },
          ],
        },
        {
          text: "Get started",
          items: [
            { text: "Quickstart and local dev", link: "/guide/quickstart" },
            { text: "Deploying with CDK", link: "/guide/deploying" },
          ],
        },
        {
          text: "Clients",
          items: [
            { text: "Kubernetes controller", link: "/guide/kubernetes" },
            { text: "CLI", link: "/guide/cli" },
            { text: "Console", link: "/guide/console" },
            { text: "Pulumi provider", link: "/guide/pulumi" },
          ],
        },
      ],
      "/reference/": [
        {
          text: "HTTP API",
          items: [
            { text: "Overview", link: "/reference/api/" },
            { text: "Data types", link: "/reference/api/data-types" },
            { text: "Admin: secrets", link: "/reference/api/admin-secrets" },
            { text: "Admin: consumers and grants", link: "/reference/api/admin-consumers" },
            { text: "Delivery and agent routes", link: "/reference/api/delivery" },
            { text: "Audit and excluded routes", link: "/reference/api/audit" },
            { text: "OpenAPI contract", link: "/reference/openapi" },
          ],
        },
        {
          text: "Configuration",
          items: [
            { text: "Kubernetes CRDs", link: "/reference/crds" },
            { text: "Deployment and controller config", link: "/reference/configuration" },
          ],
        },
      ],
      "/operations/": [
        {
          text: "Operations",
          items: [
            { text: "Identity rotation", link: "/operations/identity-rotation" },
            { text: "Safety: auth failures vs revocation", link: "/operations/safety" },
            { text: "Controller rollout via Flux", link: "/operations/flux-rollout" },
            { text: "Upgrade: secret UIDs", link: "/operations/upgrade-secret-uids" },
            { text: "AWS acceptance runbook", link: "/operations/acceptance" },
            { text: "Releasing", link: "/operations/releasing" },
          ],
        },
      ],
      "/security/": [
        {
          text: "Security",
          items: [
            { text: "Threat model", link: "/security/threat-model" },
            { text: "Reporting vulnerabilities", link: "/security/reporting" },
          ],
        },
      ],
      "/contributing/": [
        {
          text: "Contributing",
          items: [
            { text: "Getting started", link: "/contributing/" },
            { text: "Repository layout", link: "/contributing/layout" },
            { text: "Docs site", link: "/contributing/docs-site" },
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
            { text: "Kubernetes controller plan", link: "/design/kubernetes-controller-plan" },
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
        _render(src, env, md) {
          if (env.relativePath.startsWith("design/") && env.relativePath !== "design/index.md") {
            return "";
          }
          return md.render(src, env);
        },
      },
    },
    footer: {
      message: "Server AGPL-3.0-only; client, CLI, controller, Pulumi provider and CDK MIT.",
    },
    outline: [2, 3],
  },
});
