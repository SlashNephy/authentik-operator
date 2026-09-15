#!/usr/bin/env bash
# Check that a release tag follows v<authentik major>.<authentik minor>.<operator patch> and names the authentik
# minor version that the client-go module in go.mod supports (docs/spec.md §6).
# client-go tags encode the authentik version as v3.<year><two-digit minor><digit>.<patch>, such as v3.2026080.2
# for authentik 2026.8.
set -euo pipefail

cd "$(dirname "$0")/../.."

tag="${1:?usage: check-version.sh <tag>}"
if [[ ! "${tag}" =~ ^v([0-9]{4})\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "tag ${tag} does not follow v<authentik major>.<authentik minor>.<operator patch>" >&2
  exit 1
fi
tag_minor="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"

client_version="$(go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' goauthentik.io/api/v3)"
if [[ ! "${client_version}" =~ ^v3\.([0-9]{4})([0-9]{2})[0-9]\. ]]; then
  echo "unexpected client-go version ${client_version}" >&2
  exit 1
fi
client_minor="${BASH_REMATCH[1]}.$((10#${BASH_REMATCH[2]}))"

if [[ "${tag_minor}" != "${client_minor}" ]]; then
  echo "tag ${tag} names authentik ${tag_minor}, but client-go ${client_version} supports authentik ${client_minor}" >&2
  exit 1
fi
echo "tag ${tag} matches client-go ${client_version} (authentik ${client_minor})"
