# Release procedure

This document describes how authentik-operator is versioned and released (docs/spec.md §6).

## Versioning

Releases are tagged `v<authentik major>.<authentik minor>.<operator patch>`.
For example, `v2026.8.3` is the fourth release of the operator for authentik 2026.8.x (patches start at 0).

- Each release supports only the authentik minor version that matches the client-go module `goauthentik.io/api/v3`. The client-go tag `v3.2026080.x` corresponds to authentik 2026.8.x.
- The patch number advances with operator-side changes and is unrelated to the authentik patch version.
- The container image and the Helm chart use the version without the `v` prefix (`2026.8.3`) as the image tag, the chart `version`, and the chart `appVersion`.

## What a release publishes

Publishing a GitHub release of a `v*` tag runs [.github/workflows/release.yml](../.github/workflows/release.yml).
Pushing a tag alone publishes nothing, and a draft release starts the workflow only when it is published.

1. `hack/release/check-version.sh` rejects a tag that does not follow the scheme or that names a different authentik minor version than client-go in `go.mod`.
2. The container image is built for `linux/amd64` and `linux/arm64` and pushed to `ghcr.io/slashnephy/authentik-operator`, tagged `<version>`, `latest`, and the commit SHA. `docker/metadata-action` also writes the OCI labels.
3. The chart version and appVersion are set to `<version>`, and the packaged chart is attached to the release.
4. The Helm repository index on the `gh-pages` branch gets an entry that points to the attached chart.

The Helm repository is served from GitHub Pages at `https://slashnephy.github.io/authentik-operator`.
No other tag or release is created.

## The Pages site

The same GitHub Pages site serves a landing page, so that a browser that opens the Helm repository URL is not answered with a 404.
Its source is [docs/pages](pages), and [.github/workflows/pages.yml](../.github/workflows/pages.yml) copies `index.md` and `_config.yml` to the `gh-pages` branch on a push to `main` that touches them. It can also be started by hand with `gh workflow run pages.yml`.

GitHub Pages builds the branch with Jekyll, which turns `index.md` into `index.html` and copies `index.yaml` verbatim.
Keep `_config.yml` minimal: a Jekyll build failure would also stop serving `index.yaml`.

A release created with `GITHUB_TOKEN` in another workflow does not start the Release workflow, so releases are created by a person.

## One-time setup

- Create an empty `gh-pages` branch and enable GitHub Pages for it. The Release workflow writes `index.yaml` there.
- After the first image is pushed, make the `authentik-operator` package on GHCR public.

## Releasing a patch

1. Make sure CI and the e2e tests are green on `main`.
2. Tag the commit with the next patch number of the current authentik minor version and push the signed tag.

   ```bash
   git tag -s v2026.8.1 -m v2026.8.1
   git push origin v2026.8.1
   ```

3. Create and publish a release of the tag with the release notes.

   ```bash
   gh release create v2026.8.1 --verify-tag --generate-notes
   ```

4. Check that the Release workflow succeeded.

## Releasing for a new authentik minor version

1. Renovate opens a pull request that bumps `goauthentik.io/api/v3` to the new minor version (for example `v3.2026100.0` for authentik 2026.10). Renovate also bumps the authentik chart in `hack/authentik/up.sh`, which the e2e tests install; keep both on the same minor version.
2. Fix compilation errors and behavior changes in that pull request. The e2e tests run against the new authentik version.
3. Update the "Target version" of [docs/spec.md](spec.md) and the compatibility table in the [README](../README.md).
4. Merge the pull request, then tag the merge commit with the new minor version and patch 0, such as `v2026.10.0`, and publish a release of it as in "Releasing a patch".
   `hack/release/check-version.sh` refuses a tag that still names the previous minor version.
5. Users upgrade the operator together with authentik. An operator that talks to another minor version logs a warning and sets the `authentik_operator_authentik_version_mismatch` metric.
