# Release procedure

This document describes how authentik-operator is versioned and released (docs/spec.md §6).

## Versioning

Releases are tagged `v<authentik major>.<authentik minor>.<operator patch>`.
For example, `v2026.8.3` is the fourth release of the operator for authentik 2026.8.x (patches start at 0).

- Each release supports only the authentik minor version that matches the client-go module `goauthentik.io/api/v3`. The client-go tag `v3.2026080.x` corresponds to authentik 2026.8.x.
- The patch number advances with operator-side changes and is unrelated to the authentik patch version.
- The container image and the Helm chart use the version without the `v` prefix (`2026.8.3`) as the image tag, the chart `version`, and the chart `appVersion`.

## What a tag publishes

Pushing a tag runs [.github/workflows/release.yml](../.github/workflows/release.yml):

1. `hack/release/check-version.sh` rejects a tag that does not follow the scheme or that names a different authentik minor version than client-go in `go.mod`.
2. The container image is built for `linux/amd64` and `linux/arm64` and pushed to `ghcr.io/slashnephy/authentik-operator:<version>`.
3. The chart version and appVersion are set to `<version>`, and chart-releaser packages `charts/chart`, attaches it to a GitHub release named `authentik-operator-<version>`, and updates the Helm repository index on the `gh-pages` branch.

The Helm repository is served from GitHub Pages at `https://slashnephy.github.io/authentik-operator`.

## One-time setup

- Create an empty `gh-pages` branch and enable GitHub Pages for it. chart-releaser writes `index.yaml` there.
- After the first image is pushed, make the `authentik-operator` package on GHCR public.

## Releasing a patch

1. Make sure CI and the e2e tests are green on `main`.
2. Tag the commit with the next patch number of the current authentik minor version and push the tag.

   ```bash
   git tag -s v2026.8.1 -m v2026.8.1
   git push origin v2026.8.1
   ```

3. Check that the Release workflow succeeded, then write the release notes on the GitHub release of the tag.

## Releasing for a new authentik minor version

1. Renovate opens a pull request that bumps `goauthentik.io/api/v3` to the new minor version (for example `v3.2026100.0` for authentik 2026.10). Renovate also bumps the authentik chart in `hack/authentik/up.sh`, which the e2e tests install; keep both on the same minor version.
2. Fix compilation errors and behavior changes in that pull request. The e2e tests run against the new authentik version.
3. Update the "Target version" of [docs/spec.md](spec.md) and the compatibility table in the [README](../README.md).
4. Merge the pull request and tag the merge commit with the new minor version and patch 0, such as `v2026.10.0`.
   `hack/release/check-version.sh` refuses a tag that still names the previous minor version.
5. Users upgrade the operator together with authentik. An operator that talks to another minor version logs a warning and sets the `authentik_operator_authentik_version_mismatch` metric.
