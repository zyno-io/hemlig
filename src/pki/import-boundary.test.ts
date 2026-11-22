import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// Layer 5: src/pki must not import the identity-root, consumer or notification services.
const forbidden = [
  "services/issuer",
  "services/consumers",
  "services/agent-notifications",
];

const sourceFiles = (directory: string): string[] =>
  readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory()
      ? sourceFiles(path)
      : path.endsWith(".ts")
        ? [path]
        : [];
  });

describe("src/pki import boundary", () => {
  const files = sourceFiles(__dirname).filter(
    (file) => !file.endsWith("import-boundary.test.ts"),
  );

  it("scans the PKI sources", () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it.each(forbidden)("never imports %s", (target) => {
    const offenders = files.filter((file) => {
      const text = readFileSync(file, "utf8");
      const specifiers = [
        ...text.matchAll(/(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]/g),
        ...text.matchAll(/(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]/g),
      ].map((match) => match[1] ?? "");
      return specifiers.some((specifier) => specifier.includes(target));
    });
    expect(offenders).toEqual([]);
  });
});
