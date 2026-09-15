#!/usr/bin/env bash
# Set the version and the appVersion of the Helm chart to the operator version, such as 2026.8.0.
set -euo pipefail

cd "$(dirname "$0")/../.."

version="${1:?usage: set-chart-version.sh <version without the v prefix>}"
chart="charts/chart/Chart.yaml"

sed -i -E \
  -e "s/^version: .*/version: ${version}/" \
  -e "s/^appVersion: .*/appVersion: \"${version}\"/" \
  "${chart}"
grep -E '^(version|appVersion):' "${chart}"
