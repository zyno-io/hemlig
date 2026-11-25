import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";

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

// Licensing: the MIT CLI (packages/cli) must never import the AGPL server in `src/` or the root `hemlig` package. The
// server's tests may import the CLI library (MIT into AGPL), not the other way round.
describe("the MIT CLI never imports the AGPL server", () => {
  const cliPackage = resolve(__dirname, "..", "..", "packages", "cli");
  const cliRoot = join(cliPackage, "src");
  const cliFiles = sourceFiles(cliRoot);
  // Only real import/export-from/require/dynamic-import specifiers, not string literals such as Buffer.from("...").
  const importPattern =
    /(?:^|[;\s])(?:import|export)\s[^'"()]*?\bfrom\s*['"]([^'"]+)['"]|(?:^|[^.\w])(?:require|import)\s*\(\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm;
  const specifiers = cliFiles.flatMap((file) =>
    [...readFileSync(file, "utf8").matchAll(importPattern)].map((m) => ({ file, specifier: m[1] ?? m[2] ?? m[3] ?? "" })),
  );
  // The command layer (`ez.ts`, `ez-online.ts`) and the API test double (`ez-fake.ts`) talk to the client package on purpose.
  const isLibrary = (file: string): boolean =>
    /[\\/](ez-[a-z0-9-]+|tty)\.ts$/.test(file) && !file.endsWith(".test.ts") && !/[\\/]ez-(online|fake)\.ts$/.test(file);

  it("scans the CLI sources, recursively", () => {
    expect(cliFiles.map((f) => f.slice(cliRoot.length + 1))).toEqual(
      expect.arrayContaining(["pki.ts", "ez-x509.ts", "ez-state.ts", "tty.ts"]),
    );
    expect(specifiers.length).toBeGreaterThan(50);
  });

  it("has no relative specifier that leaves packages/cli/src", () => {
    const offenders = specifiers.filter(
      ({ file, specifier }) =>
        specifier.startsWith(".") && !`${resolve(dirname(file), specifier)}${sep}`.startsWith(`${cliRoot}${sep}`),
    );
    expect(offenders).toEqual([]);
  });

  it("imports only node built-ins, itself, the client package and @peculiar/asn1-*", () => {
    const offenders = specifiers.filter(
      ({ specifier }) =>
        !(
          specifier.startsWith("node:") ||
          specifier.startsWith(".") ||
          specifier === "@zyno-io/hemlig-client" ||
          /^@peculiar\/asn1-(schema|x509|csr)$/.test(specifier)
        ),
    );
    expect(offenders).toEqual([]);
  });

  it("never names the console package, the root `hemlig` package or the server sources", () => {
    const offenders = specifiers.filter(
      ({ specifier }) =>
        specifier === "hemlig" ||
        specifier.startsWith("hemlig/") ||
        specifier.startsWith("@zyno-io/hemlig-console") ||
        /(^|\/)src\/(pki|services|handlers|domain)\b/.test(specifier),
    );
    expect(offenders).toEqual([]);
  });

  it("keeps the EZ library free of the client package and of anything but node, @peculiar and itself", () => {
    const library = specifiers.filter(({ file }) => isLibrary(file));
    expect(library.length).toBeGreaterThan(20);
    const offenders = library.filter(
      ({ specifier }) =>
        !(specifier.startsWith("node:") || (specifier.startsWith("./ez-") && !/^\.\/ez-(online|fake)(\.[jt]s)?$/.test(specifier)) || specifier === "./tty" || /^@peculiar\/asn1-(schema|x509|csr)$/.test(specifier)),
    );
    expect(offenders).toEqual([]);
  });

  it("declares only the allowed runtime dependencies", () => {
    const manifest = JSON.parse(readFileSync(join(cliPackage, "package.json"), "utf8")) as { dependencies: Record<string, string> };
    expect(Object.keys(manifest.dependencies).sort()).toEqual([
      "@peculiar/asn1-csr", "@peculiar/asn1-schema", "@peculiar/asn1-x509", "@zyno-io/hemlig-client",
    ]);
  });
});
