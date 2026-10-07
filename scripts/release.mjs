import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const releasePackages = [
  {
    name: "@hemlig/client",
    directory: "packages/client",
    archive: "hemlig-client.tgz",
  },
  { name: "@hemlig/cli", directory: "packages/cli", archive: "hemlig-cli.tgz" },
  {
    name: "@hemlig/pulumi-provider",
    directory: "packages/pulumi-provider",
    archive: "hemlig-pulumi-provider.tgz",
  },
];

export function releaseVersion(tag) {
  const match =
    /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?:-([0-9A-Za-z.-]+))?$/.exec(
      tag,
    );
  if (
    !match ||
    match[0] !== tag ||
    (match[2] &&
      !match[2]
        .split(".")
        .every((part) =>
          /^(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)$/.test(part),
        ))
  ) {
    throw new Error(
      "Release tags must be v-prefixed SemVer without build metadata, such as v0.2.0 or v0.2.0-rc.1.",
    );
  }
  return {
    version: tag.slice(1),
    npmTag: match[2] ? "next" : "latest",
    prerelease: Boolean(match[2]),
  };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} failed with exit code ${result.status}.`);
  return result.stdout;
}

export function preparePackages(root, version) {
  const manifests = releasePackages.map((pkg) => {
    const filename = path.join(root, pkg.directory, "package.json");
    const manifest = JSON.parse(readFileSync(filename, "utf8"));
    if (
      manifest.name !== pkg.name ||
      manifest.license !== "MIT" ||
      manifest.private
    ) {
      throw new Error(`Unexpected publish metadata for ${pkg.name}.`);
    }
    if (
      pkg.name !== "@hemlig/client" &&
      manifest.dependencies?.["@hemlig/client"] !== "workspace:*"
    ) {
      throw new Error(
        `${pkg.name} must use the client workspace before packing.`,
      );
    }
    return { filename, manifest: { ...manifest, version } };
  });
  for (const { filename, manifest } of manifests) {
    writeFileSync(filename, `${JSON.stringify(manifest, null, 2)}\n`);
  }
}

export function validatePackedManifest(manifest, pkg, version) {
  if (
    manifest.name !== pkg.name ||
    manifest.version !== version ||
    manifest.license !== "MIT" ||
    manifest.private
  ) {
    throw new Error(`Archive metadata does not match ${pkg.name}@${version}.`);
  }
  if (
    pkg.name !== "@hemlig/client" &&
    manifest.dependencies?.["@hemlig/client"] !== version
  ) {
    throw new Error(
      `${pkg.name} archive must depend on @hemlig/client@${version}.`,
    );
  }
  if (pkg.name === "@hemlig/cli" && manifest.bin?.hemlig !== "dist/main.js") {
    throw new Error("CLI archive must expose the hemlig executable.");
  }
}

function readArchive(directory, pkg, version) {
  const filename = path.resolve(directory, pkg.archive);
  const contents = readFileSync(filename);
  const json = run("tar", ["-xOf", filename, "package/package.json"], {
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  const manifest = JSON.parse(json);
  validatePackedManifest(manifest, pkg, version);
  return {
    ...pkg,
    filename,
    integrity: `sha512-${createHash("sha512").update(contents).digest("base64")}`,
  };
}

export async function publicationNeeded(pkg, version, fetchRegistry = fetch) {
  const response = await fetchRegistry(
    `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/${encodeURIComponent(version)}`,
  );
  if (response.status === 404) return true;
  if (!response.ok)
    throw new Error(
      `Registry lookup for ${pkg.name}@${version} failed: HTTP ${response.status}.`,
    );
  const manifest = await response.json();
  if (manifest.dist?.integrity !== pkg.integrity) {
    throw new Error(
      `${pkg.name}@${version} already exists with different contents; use a new release tag.`,
    );
  }
  return false;
}

async function main() {
  const [command, tag, directory = "release-artifacts"] = process.argv.slice(2);
  const metadata = releaseVersion(tag ?? "");
  const root = process.cwd();
  if (command === "prepare") {
    preparePackages(root, metadata.version);
    if (process.env.GITHUB_OUTPUT) {
      appendFileSync(
        process.env.GITHUB_OUTPUT,
        `version=${metadata.version}\nnpm_tag=${metadata.npmTag}\nprerelease=${metadata.prerelease}\n`,
      );
    }
  } else if (command === "pack") {
    mkdirSync(directory, { recursive: true });
    for (const pkg of releasePackages) {
      run("yarn", [
        "workspace",
        pkg.name,
        "pack",
        "--out",
        path.resolve(directory, pkg.archive),
      ]);
      readArchive(directory, pkg, metadata.version);
    }
  } else if (command === "publish") {
    const archives = releasePackages.map((pkg) =>
      readArchive(directory, pkg, metadata.version),
    );
    // Check every version before publishing anything; allow a partial-run retry
    // only when an already-published archive is byte-identical.
    const pending = [];
    for (const pkg of archives) {
      const needed = await publicationNeeded(pkg, metadata.version);
      if (needed) pending.push(pkg);
      else
        console.log(
          `${pkg.name}@${metadata.version} already published with identical contents.`,
        );
    }
    for (const pkg of pending) {
      run("npm", [
        "publish",
        pkg.filename,
        "--access",
        "public",
        "--provenance",
        "--tag",
        metadata.npmTag,
      ]);
    }
  } else {
    throw new Error(
      "Usage: node scripts/release.mjs <prepare|pack|publish> <vVERSION> [artifact-directory]",
    );
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
