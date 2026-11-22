import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

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

const specifiersOf = (text: string): string[] =>
  [
    ...text.matchAll(/(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]/g),
    ...text.matchAll(/(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]/g),
  ].map((match) => match[1] ?? "");

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
      return specifiersOf(text).some((specifier) => specifier.includes(target));
    });
    expect(offenders).toEqual([]);
  });
});

// The PKI Lambdas must not transitively pull in the identity plane, the IoT or API Gateway SDKs, or the
// application factory that builds every service.
const sourceRoot = resolve(__dirname, "..");
const stripTypeOnly = (text: string): string =>
  text
    .replace(/^\s*import\s+type\s[^;]*;/gm, "")
    .replace(/^\s*export\s+type\s[^;]*?from\s*['"][^'"]+['"]\s*;/gm, "");
const resolveRelative = (
  from: string,
  specifier: string,
): string | undefined => {
  const base = resolve(dirname(from), specifier);
  for (const candidate of [`${base}.ts`, join(base, "index.ts")]) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
};
const walk = (
  entries: string[],
): { files: Set<string>; packages: Set<string> } => {
  const files = new Set<string>();
  const packages = new Set<string>();
  const pending = [...entries];
  while (pending.length > 0) {
    const file = pending.pop() as string;
    if (files.has(file)) {
      continue;
    }
    files.add(file);
    for (const specifier of specifiersOf(
      stripTypeOnly(readFileSync(file, "utf8")),
    )) {
      if (specifier.startsWith(".")) {
        const resolved = resolveRelative(file, specifier);
        if (resolved !== undefined) {
          pending.push(resolved);
        }
      } else {
        packages.add(specifier);
      }
    }
  }
  return { files, packages };
};

describe("PKI transitive import boundary", () => {
  const entries = [
    join(sourceRoot, "pki", "app.ts"),
    join(sourceRoot, "repositories", "pki.ts"),
    ...readdirSync(join(sourceRoot, "handlers"))
      .filter((name) => /^pki-.*\.ts$/.test(name) && !name.endsWith(".test.ts"))
      .map((name) => join(sourceRoot, "handlers", name)),
  ];
  const { files, packages } = walk(entries);
  const relative = [...files].map((file) =>
    file.slice(sourceRoot.length + 1).replaceAll("\\", "/"),
  );

  it("walks a meaningful part of the graph", () => {
    expect(entries.length).toBeGreaterThanOrEqual(5);
    expect(relative).toContain("handlers/request.ts");
    expect(relative).toContain("repositories/dynamo.ts");
  });

  it.each([
    "services/issuer.ts",
    "services/consumers.ts",
    "services/agent-notifications.ts",
    "services/secrets.ts",
    "app.ts",
    "handlers/shared.ts",
  ])("never reaches %s", (target) => {
    expect(relative).not.toContain(target);
  });

  it.each([
    "@aws-sdk/client-iot",
    "@aws-sdk/client-iot-data-plane",
    "@aws-sdk/client-apigatewayv2",
  ])("never reaches %s", (target) => {
    expect([...packages]).not.toContain(target);
  });
});
