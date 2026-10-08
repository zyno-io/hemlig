# Hemlig releases

Pushing a tag such as `v0.2.0` runs `.github/workflows/ci.yml`. All service,
workspace, MiniStack, Helm and package checks must pass before publishing.
The workflow does not deploy the AWS service or update a Kubernetes installation.

The workflow creates a GitHub release for the existing tag, with generated notes,
three npm package archives and their `SHA256SUMS`. It then publishes these public
MIT packages in dependency order:

1. `@hemlig/client`
2. `@hemlig/cli`
3. `@hemlig/pulumi-provider`

The existing workflow also publishes the tagged controller image and the Helm
chart to the `zyno-io/charts` release repository. The root AWS/CDK package,
administrator console and controller workspace are not published to npm by
these release jobs.

## Versions and tags

Use a tag in the form `vMAJOR.MINOR.PATCH`, optionally with a SemVer prerelease
suffix such as `v0.2.0-rc.1`. Leading zeroes in numeric identifiers and build
metadata are rejected. Prereleases become GitHub prereleases and use npm's
`next` distribution tag; stable releases use `latest`.

The release build sets all three package versions to the tag version in its
temporary checkout. Source manifests retain their development versions. Yarn
packing replaces `workspace:*` with the exact released client version in the
CLI and Pulumi archives. The archive manifests are verified before publication.
On pull requests and branch builds, this packaging path runs with `0.0.0-ci`
and performs npm dry runs without publishing.

The packages are public and require Node.js 24. For example, after `v0.2.0`
has been published:

```bash
npm install --global @hemlig/cli@0.2.0
npm install @hemlig/pulumi-provider@0.2.0
hemlig --help
```

The CLI retains its OIDC administrator authentication and JSON output contract.
See the [CLI guide](cli.md) for token handling and command examples.

## npm trusted publishing

Publication uses GitHub Actions OIDC through npm trusted publishing. Configure an
[npm trusted publisher](https://docs.npmjs.com/trusted-publishers/) for each:

| Setting             | Value                                                   |
| ------------------- | ------------------------------------------------------- |
| GitHub organization | `zyno-io`                                               |
| Repository          | `hemlig`                                                |
| Workflow filename   | `ci.yml`                                                |
| Environment         | Leave empty; this job does not use a GitHub environment |
| Allowed action      | Direct publishing with `npm publish`                    |

The job runs on a GitHub-hosted runner, uses npm 11 with trusted-publishing
support, and has `id-token: write`. npm exchanges the job's GitHub OIDC identity
for a short-lived publish credential and generates provenance attestations.
There is no stored npm publishing credential or token fallback in the workflow.
The npm account configuring the publishers must have write access to the
`@hemlig` packages. Confirm all three publisher registrations before pushing a
release tag. npm-side package setup is separate from this repository change;
the workflow does not create or configure trusted publisher registrations.

## Failed publications and retries

Publishing to several registries is not atomic. A GitHub release may exist even
if a later npm publication fails. Fix the publisher configuration or transient
failure and rerun the failed job; it downloads the same verified archives from
that run.
An npm version is skipped only when the registry's SHA-512 integrity exactly
matches the archive. A version containing different bytes fails before any
package in that job is published; choose a new tag rather than replacing it.

Rerunning GitHub release creation accepts an existing release only when its
assets match. It does not overwrite release assets. The separate Helm publishing
job retains its existing immutable-release policy: a chart release that already
exists is not replaced. Rerun only failed jobs when recovering an npm failure.
Tag builds do not cancel an in-progress release when another run starts.

Creating or pushing a release tag is a publication action. Merge the workflow
and configure the npm trusted publishers before tagging a version you intend
to release.
