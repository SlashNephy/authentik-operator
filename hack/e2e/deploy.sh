#!/usr/bin/env bash
# Build the manager image, load it into the kind cluster started by hack/authentik/up.sh, and install the operator
# chart configured with the bootstrap token of authentik.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER_NAME="${CLUSTER_NAME:-authentik-operator}"
AUTHENTIK_NAMESPACE="${AUTHENTIK_NAMESPACE:-authentik}"
AUTHENTIK_RELEASE="${AUTHENTIK_RELEASE:-authentik}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-authentik-operator}"
IMG="${IMG:-ghcr.io/slashnephy/authentik-operator:e2e}"

docker build -t "${IMG}" .
kind load docker-image "${IMG}" --name "${CLUSTER_NAME}"

kubectl create namespace "${OPERATOR_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
token="$(kubectl -n "${AUTHENTIK_NAMESPACE}" get secret authentik-bootstrap -o jsonpath='{.data.AUTHENTIK_BOOTSTRAP_TOKEN}' | base64 -d)"
kubectl -n "${OPERATOR_NAMESPACE}" create secret generic authentik-operator-token \
  --from-file=token=<(printf '%s' "${token}") --dry-run=client -o yaml | kubectl apply -f -

# A short resync interval keeps the drift repair scenarios fast.
helm upgrade --install authentik-operator charts/chart \
  --namespace "${OPERATOR_NAMESPACE}" \
  --set clusterName=e2e \
  --set authentik.url="http://${AUTHENTIK_RELEASE}-server.${AUTHENTIK_NAMESPACE}.svc" \
  --set authentik.token.secretName=authentik-operator-token \
  --set manager.image.repository="${IMG%:*}" \
  --set manager.image.tag="${IMG##*:}" \
  --set manager.image.pullPolicy=Never \
  --set resyncInterval=15s \
  --wait --timeout 5m

# The image tag does not change between runs, so restart to pick up a rebuilt image.
kubectl -n "${OPERATOR_NAMESPACE}" rollout restart deployment/authentik-operator-controller-manager
kubectl -n "${OPERATOR_NAMESPACE}" rollout status deployment/authentik-operator-controller-manager --timeout 5m
