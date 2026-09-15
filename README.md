# authentik-operator

A Kubernetes operator that manages [authentik](https://goauthentik.io) Applications, Providers (Proxy and OAuth2/OpenID), and access rights (PolicyBindings) declaratively through the `AuthentikApplication` custom resource.

The design is described in [docs/spec.md](docs/spec.md).

## Compatibility

Each operator release supports exactly one authentik minor version, and the release number starts with it: `v<authentik major>.<authentik minor>.<operator patch>`.
Upgrade the operator together with authentik.

| Operator | authentik |
|---|---|
| `v2026.8.x` | 2026.8.x |

## Installation

Create an API token for a service account with the permissions listed in the [chart README](charts/chart/README.md), and store it in a Secret:

```bash
kubectl create namespace authentik-operator
kubectl -n authentik-operator create secret generic authentik-operator-token --from-literal=token=<token>
```

Install the chart from the Helm repository:

```bash
helm repo add authentik-operator https://slashnephy.github.io/authentik-operator
helm install authentik-operator authentik-operator/authentik-operator \
  --namespace authentik-operator \
  --set clusterName=production \
  --set authentik.url=https://auth.example.com \
  --set authentik.token.secretName=authentik-operator-token
```

Then create an `AuthentikApplication`:

```yaml
apiVersion: authentik.starry.blue/v1alpha1
kind: AuthentikApplication
metadata:
  name: wiki
spec:
  slug: wiki
  name: Wiki
  launchURL: https://wiki.example.com
  provider:
    flows:
      authorization:
        slug: default-provider-authorization-implicit-consent
      invalidation:
        slug: default-provider-invalidation-flow
    proxy:
      forwardAuthSingle:
        externalHost: https://wiki.example.com
  access:
    rules:
      - group:
          name: admins
```

## Development

The toolchain (Go, kubebuilder, controller-gen, golangci-lint, kind, Helm, and others) is pinned in [mise.toml](mise.toml).

```bash
mise install
```

| Command | Description |
|---|---|
| `make build` | Build the manager binary |
| `make lint` | Run golangci-lint |
| `make test` | Run the unit tests (including envtest) |
| `make helm-lint` | Lint and render the Helm chart |
| `make authentik-up` | Start authentik on a local kind cluster |
| `make test-e2e` | Run the e2e tests against authentik and the operator chart on kind |
| `make poc` | Verify the authentik behavior assumed by the spec against the local authentik |
| `make help` | List every target |

Releases are described in [docs/release.md](docs/release.md).

## License

[Apache License 2.0](LICENSE)
