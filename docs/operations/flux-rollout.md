---
title: Rolling out controller upgrades via Flux
description: A staging-first, pinned, verifiable procedure for upgrading the Hemlig controller with Flux.
pageType: how-to
---

# Rolling out controller upgrades via Flux

Upgrade the controller one cluster class at a time, with everything pinned, and verify before moving on.

The controller runs with cluster-wide RBAC and holds each namespace's identity, so
upgrade it deliberately: pin exact versions, roll **staging clusters first**, verify,
then production. This procedure is generic; adapt the repository layout to yours.

## Principles

- **Pin everything.** A mutable tag (`main`) or a floating chart range makes the
  fleet drift apart. Pin the chart version, and pin the image by digest.
- **One cluster class at a time.** Staging, observe, then production.
- **Server before controller** when a controller release needs a newer Hemlig
  service (for example [identity rotation](identity-rotation.md#version-requirements)).
  Controllers against an older server degrade visibly but keep working.
- **A single replica.** Upgrades use a zero-surge strategy; expect a short gap in
  reconciliation while the pod restarts. Imported Secrets stay in place.

## 1. Choose the release

Release tags publish the image `ghcr.io/zyno-io/hemlig-controller:<tag>` and the
chart `hemlig-controller-<version>` (see [Releasing](../contributing/releasing.md)). Resolve the
image digest:

```sh
docker buildx imagetools inspect ghcr.io/zyno-io/hemlig-controller:vX.Y.Z \
  --format '{{ .Manifest.Digest }}'
```

## 2. Pin source and image

Pin the Git commit that holds your manifests, the chart version, and the image
digest. For example a `GitRepository` pinned to a commit:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: { name: platform, namespace: flux-system }
spec:
  url: https://git.example.com/platform/clusters
  interval: 5m
  ref:
    commit: 0123456789abcdef0123456789abcdef01234567
```

and the release values, with the digest (the chart builds `repository:tag`, so a
digest goes in the tag field as `<tag>@sha256:...`):

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: { name: hemlig-controller, namespace: hemlig-system }
spec:
  interval: 10m
  chart:
    spec:
      chart: hemlig-controller
      version: "<chart-version>"
      sourceRef: { kind: HelmRepository, name: zyno }
  install: { crds: CreateReplace }
  upgrade: { crds: CreateReplace }
  values:
    image:
      tag: "vX.Y.Z@sha256:<digest>"
```

## 3. Staging first

1. Update the pin in the staging cluster configuration only; merge.
2. Reconcile and watch:
   ```sh
   flux reconcile source git platform
   flux reconcile helmrelease hemlig-controller -n hemlig-system
   kubectl -n hemlig-system rollout status deploy/hemlig-controller
   ```
3. Verify on every staging cluster:
   ```sh
   kubectl get hemligconsumer,hemligsecretimport,hemligsecretexport -A
   kubectl -n hemlig-system logs deploy/hemlig-controller --since=15m
   ```
   - Every `HemligConsumer` is `Ready=True`.
   - Imports and exports are `Ready=True`; no new `AccessRevoked`, `AuthenticationFailed`,
     or `ReconcileFailed` (see [Status reasons](../reference/crds.md#status-reasons)).
   - Logs show no repeating "reconciliation failed; retrying".
   - If the release includes identity rotation, force one rotation on a staging
     consumer and confirm `IdentityRotation=True`.
4. Soak for a period matching your risk appetite (at least one 10-minute
   resync, ideally longer).

## 4. Production

Only after staging is clean, update the same pin in production configuration.
Roll one cluster (or a small group) at a time and repeat the verification. If any
cluster shows a regression, **stop** and revert that pin; do not continue to the
next cluster.

## Rollback

Revert the pinned commit, chart version and digest to the previous values and
reconcile. CRDs are updated with `CreateReplace`; check the release notes before
rolling back across a CRD schema change.

## Next steps

- [Identity rotation](identity-rotation.md)
- [Status reasons](../reference/crds.md#status-reasons)
