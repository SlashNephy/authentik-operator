# authentik-operator

A Kubernetes operator that manages [authentik](https://goauthentik.io) Applications, Providers (Proxy and OAuth2/OpenID), and access rights (PolicyBindings) declaratively through the `AuthentikApplication` custom resource.

> [!WARNING]
> This project is under early development and is not usable yet.

The design is described in [docs/spec.md](docs/spec.md).

## Development

The toolchain (Go, kubebuilder, controller-gen, golangci-lint, kind, and others) is pinned in [mise.toml](mise.toml).

```bash
mise install
```

| Command | Description |
|---|---|
| `make build` | Build the manager binary |
| `make lint` | Run golangci-lint |
| `make test` | Run the unit tests (including envtest) |
| `make authentik-up` | Start authentik on a local kind cluster |
| `make poc` | Verify the authentik behavior assumed by the spec against the local authentik |
| `make help` | List every target |

## License

[Apache License 2.0](LICENSE)
