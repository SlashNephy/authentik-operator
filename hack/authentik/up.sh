#!/usr/bin/env bash
# Create a kind cluster and install authentik with the official chart.
# Credentials are generated on the first run and stored in the authentik-bootstrap Secret,
# which later runs reuse.
set -euo pipefail

cd "$(dirname "$0")"

CLUSTER_NAME="${CLUSTER_NAME:-authentik-operator}"
NAMESPACE="${AUTHENTIK_NAMESPACE:-authentik}"
RELEASE="${AUTHENTIK_RELEASE:-authentik}"
# renovate: datasource=helm depName=authentik registryUrl=https://charts.goauthentik.io
AUTHENTIK_CHART_VERSION="${AUTHENTIK_CHART_VERSION:-2026.8.3}"

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  kind create cluster --name "${CLUSTER_NAME}" --wait 120s
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

if ! kubectl -n "${NAMESPACE}" get secret authentik-bootstrap >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE}" create secret generic authentik-bootstrap \
    --from-literal=AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)" \
    --from-literal=AUTHENTIK_POSTGRESQL__PASSWORD="$(openssl rand -hex 16)" \
    --from-literal=AUTHENTIK_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)" \
    --from-literal=AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -hex 16)" \
    --from-literal=AUTHENTIK_BOOTSTRAP_EMAIL="akadmin@example.com"
fi

helm upgrade --install "${RELEASE}" authentik \
  --repo https://charts.goauthentik.io \
  --version "${AUTHENTIK_CHART_VERSION}" \
  --namespace "${NAMESPACE}" \
  --values values.yaml \
  --wait --timeout 15m

# The bootstrap token is not usable until the worker has applied the bootstrap blueprint.
kubectl -n "${NAMESPACE}" rollout status "deployment/${RELEASE}-worker" --timeout 10m
