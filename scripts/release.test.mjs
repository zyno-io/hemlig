import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  preparePackages,
  publicationNeeded,
  releasePackages,
  releaseVersion,
  validatePackedManifest,
} from "./release.mjs";

test("stable and prerelease tags select distinct npm distribution tags", () => {
  assert.deepEqual(releaseVersion("v1.2.3"), {
    version: "1.2.3",
    npmTag: "latest",
    prerelease: false,
  });
  assert.deepEqual(releaseVersion("v0.2.0-rc.1"), {
    version: "0.2.0-rc.1",
    npmTag: "next",
    prerelease: true,
  });
});

test("invalid or ambiguous release versions fail before any publication", () => {
  for (const tag of [
    "1.2.3",
    "v01.2.3",
    "v1.02.3",
    "v1.2.03",
    "v1.2",
    "v1.2.3+build",
    "v1.2.3-01",
    "v1.2.3-rc..1",
    "v1.2.3-",
    "v1.2.3-rc/1",
    "v1.2.3\n",
  ]) {
    assert.throws(() => releaseVersion(tag));
  }
});

test("release preparation preserves metadata and aligns the three workspace versions", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "hemlig-release-test-"));
  try {
    for (const pkg of releasePackages) {
      const dir = path.join(root, pkg.directory);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({
          name: pkg.name,
          version: "0.1.0",
          license: "MIT",
          author: "Zyno Consulting <oss@zyno.io>",
          ...(pkg.name !== "@hemlig/client"
            ? { dependencies: { "@hemlig/client": "workspace:*" } }
            : {}),
        }),
      );
    }
    preparePackages(root, "0.2.0-rc.1");
    for (const pkg of releasePackages) {
      const manifest = JSON.parse(
        readFileSync(path.join(root, pkg.directory, "package.json"), "utf8"),
      );
      assert.equal(manifest.version, "0.2.0-rc.1");
      assert.equal(manifest.author, "Zyno Consulting <oss@zyno.io>");
      if (pkg.name !== "@hemlig/client")
        assert.equal(manifest.dependencies["@hemlig/client"], "workspace:*");
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("packed consumers must refer to the released client version and expose the CLI", () => {
  const pkg = releasePackages[1];
  const manifest = {
    name: pkg.name,
    version: "0.2.0",
    license: "MIT",
    bin: { hemlig: "dist/main.js" },
    dependencies: { "@hemlig/client": "0.2.0" },
  };
  validatePackedManifest(manifest, pkg, "0.2.0");
  for (const dependency of ["workspace:*", "0.1.0", "^0.2.0"]) {
    assert.throws(() =>
      validatePackedManifest(
        { ...manifest, dependencies: { "@hemlig/client": dependency } },
        pkg,
        "0.2.0",
      ),
    );
  }
  assert.throws(() =>
    validatePackedManifest({ ...manifest, bin: {} }, pkg, "0.2.0"),
  );
});

test("publication permits new versions and byte-identical retries", async () => {
  const pkg = { name: "@hemlig/client", integrity: "sha512-same" };
  const absent = await publicationNeeded(pkg, "0.2.0", async (url) => {
    assert.equal(url, "https://registry.npmjs.org/%40hemlig%2Fclient/0.2.0");
    return new Response(null, { status: 404 });
  });
  assert.equal(absent, true);
  const identical = await publicationNeeded(pkg, "0.2.0", async () =>
    Response.json({ dist: { integrity: "sha512-same" } }),
  );
  assert.equal(identical, false);
});

test("publication rejects conflicting versions, registry failures and interrupted lookups", async () => {
  const pkg = { name: "@hemlig/client", integrity: "sha512-same" };
  await assert.rejects(
    publicationNeeded(pkg, "0.2.0", async () =>
      Response.json({ dist: { integrity: "sha512-different" } }),
    ),
    /different contents/,
  );
  await assert.rejects(
    publicationNeeded(
      pkg,
      "0.2.0",
      async () => new Response(null, { status: 503 }),
    ),
    /HTTP 503/,
  );
  await assert.rejects(
    publicationNeeded(pkg, "0.2.0", async () => {
      throw new Error("connection interrupted");
    }),
    /connection interrupted/,
  );
});
