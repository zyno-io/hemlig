#!/usr/bin/env node
// Enforces the mechanically checkable rules of the docs style guide
// (docs/contributing/docs-site.md). Skips docs/design/ and unwritten placeholders.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const docsRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const skipDirs = new Set(["design", "node_modules", ".vitepress", "scripts"]);
const bannedPhrases = ["first release that includes", "v0.2", "api://hemlig"];
const allowedHosts = [
  "example.com",
  "example.test",
  "github.com",
  "zyno-io.github.io",
  "ghcr.io",
  "docs.npmjs.com",
  "vitepress.dev",
  "cert-manager.io",
  "aws.amazon.com",
  "localhost",
  "127.0.0.1",
];

const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      return skipDirs.has(entry.name) ? [] : walk(join(dir, entry.name));
    }
    return entry.name.endsWith(".md") ? [join(dir, entry.name)] : [];
  });

const parse = (text) => {
  const match = /^---\n([\s\S]*?)\n---\n?/.exec(text);
  const frontmatter = {};
  if (match) {
    for (const line of match[1].split("\n")) {
      const kv = /^([A-Za-z]+):\s*(.*)$/.exec(line);
      if (kv) frontmatter[kv[1]] = kv[2].trim();
    }
  }
  return { frontmatter, body: match ? text.slice(match[0].length) : text };
};

// GitHub-style slug as produced by VitePress (markdown-it-anchor + its slugify).
const slugify = (heading) =>
  heading
    .replace(/<[^>]*>/g, "")
    .replace(/`([^`]*)`/g, "$1")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[\s~`!@#$%^&*()\-_+=[\]{}|\;:"'“”‘’<>,.?/]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/^(\d)/, "_$1")
    .toLowerCase();

const headingSlugs = (body) => {
  const slugs = new Set();
  let fenced = false;
  for (const line of body.split("\n")) {
    if (/^(```|~~~)/.test(line)) fenced = !fenced;
    const m = !fenced && /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (m) slugs.add(slugify(m[1]));
  }
  return slugs;
};

const files = walk(docsRoot);
const pages = new Map(files.map((f) => [f, parse(readFileSync(f, "utf8"))]));
const errors = [];

for (const [file, { frontmatter, body }] of pages) {
  const rel = relative(docsRoot, file);
  const fail = (message) => errors.push(`${rel}: ${message}`);
  if (frontmatter.layout === "home" || frontmatter.sidebar === "false")
    continue;
  if (frontmatter.search === "false" && /Being written\./.test(body)) continue;

  if (!frontmatter.description) fail("missing frontmatter `description`");
  if (
    !/^(tutorial|how-to|reference|explanation)$/.test(
      frontmatter.pageType ?? "",
    )
  ) {
    fail(
      "frontmatter `pageType` must be tutorial, how-to, reference or explanation",
    );
  }

  const lines = body.split("\n");
  let fenced = false;
  let paragraphChars = 0;
  let afterH1 = false;
  let h1Seen = false;
  lines.forEach((line, index) => {
    const at = `${rel}:${index + 1}`;
    if (/^(```|~~~)/.test(line)) {
      if (!fenced && /^(```|~~~)\s*$/.test(line))
        errors.push(`${at}: code fence without a language`);
      fenced = !fenced;
      return;
    }
    if (fenced) return;
    if (/^:::\s*info\b/.test(line))
      errors.push(`${at}: \`::: info\` is not allowed`);
    for (const phrase of bannedPhrases) {
      if (line.includes(phrase))
        errors.push(`${at}: banned phrase "${phrase}"`);
    }
    for (const m of line.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)) {
      const host = m[1].toLowerCase();
      if (
        !allowedHosts.some(
          (allowed) => host === allowed || host.endsWith(`.${allowed}`),
        )
      ) {
        errors.push(`${at}: hostname ${host} is not in the allowlist`);
      }
    }
    if (/^#\s/.test(line) && !h1Seen) {
      h1Seen = true;
      afterH1 = true;
      return;
    }
    if (afterH1 && line.trim() !== "") {
      afterH1 = false;
      if (/^(#|:::|```|\||[-*]\s|\d+\.\s|<)/.test(line)) {
        errors.push(`${at}: the H1 must be followed by a text paragraph`);
      }
    }
    // A paragraph may take at most 6 lines at 80 columns (480 characters).
    if (
      line.trim() === "" ||
      /^\s*(#|\||:::|[-*]\s|\d+\.\s|```|<)/.test(line)
    ) {
      paragraphChars = 0;
    } else {
      const before = paragraphChars;
      paragraphChars += line.trim().length + 1;
      if (before <= 480 && paragraphChars > 480) {
        errors.push(`${at}: paragraph longer than 6 lines at 80 columns`);
      }
    }
  });

  const linkText = body
    .replace(/```[\s\S]*?```/g, "")
    .replace(/`[^`\n]*`/g, "");
  for (const m of linkText.matchAll(
    /\]\(([^)\s]+\.md)?#([^)\s]+)\)|\]\(([^)\s#]+\.md)\)/g,
  )) {
    const target = m[1] ?? m[3];
    const anchor = m[2];
    if (target === undefined && anchor === undefined) continue;
    if (target?.startsWith("http")) continue;
    const targetFile =
      target === undefined ? file : resolve(dirname(file), target);
    const targetPage = pages.get(targetFile);
    if (targetPage === undefined) {
      if (
        !existsSync(targetFile) &&
        !relative(docsRoot, targetFile).startsWith("design")
      ) {
        fail(`link target ${target} does not exist`);
      }
      continue;
    }
    if (anchor !== undefined && !headingSlugs(targetPage.body).has(anchor)) {
      fail(`anchor #${anchor} not found in ${relative(docsRoot, targetFile)}`);
    }
  }
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  console.error(`\n${errors.length} docs lint error(s).`);
  process.exit(1);
}
console.log(`docs lint passed (${files.length} pages checked).`);
