---
layout: default
title: authentik-operator
---

# authentik-operator

A Kubernetes operator that manages [authentik](https://goauthentik.io) Applications, Providers (Proxy and OAuth2/OpenID), and access rights (PolicyBindings) declaratively through the `AuthentikApplication` custom resource.

This site is also the Helm repository of the chart: `https://slashnephy.github.io/authentik-operator`.

- [Source code](https://github.com/SlashNephy/authentik-operator)
- [Design document](https://github.com/SlashNephy/authentik-operator/blob/main/docs/spec.md)
- [Chart reference](https://github.com/SlashNephy/authentik-operator/blob/main/charts/chart/README.md)
- [Releases](https://github.com/SlashNephy/authentik-operator/releases)

## What it does

One `AuthentikApplication` describes an application and everything authentik needs around it, and the operator reconciles authentik to match:

- the Application itself, with its slug, name, and launch URL;
- a Proxy Provider (forward auth or a standalone proxy) or an OAuth2/OpenID Provider, including its flows;
- for a Proxy Provider, membership of the Outpost that serves it;
- for an OAuth2 Provider, the client credentials, written to a Secret that stays the source of truth;
- who may use the application, as PolicyBindings against groups, users, and policies.

Every object the operator creates is marked with an ownership role, so it never edits or deletes objects that a person made by hand. Objects that already exist can be adopted explicitly. Drift is corrected on a resync interval, and `deletionPolicy` decides whether deleting the custom resource also deletes the authentik objects.

## Compatibility

Each release supports exactly one authentik minor version, and the release number starts with it: `v<authentik major>.<authentik minor>.<operator patch>`.
Upgrade the operator together with authentik.

| Operator | authentik |
|---|---|
| `v2026.8.x` | 2026.8.x |

## Install

### 1. Create an API token

Create a service account in authentik and a non-expiring API token for it.
The account does not need to be a superuser; assign a role that holds the permissions listed in the [chart reference](https://github.com/SlashNephy/authentik-operator/blob/main/charts/chart/README.md#api-token).

Store the token in a Secret in the namespace the operator runs in:

```bash
kubectl create namespace authentik-operator
kubectl -n authentik-operator create secret generic authentik-operator-token --from-literal=token=<token>
```

### 2. Install the chart

```bash
helm repo add authentik-operator https://slashnephy.github.io/authentik-operator
helm repo update
helm install authentik-operator authentik-operator/authentik-operator \
  --namespace authentik-operator \
  --set clusterName=production \
  --set authentik.url=https://auth.example.com \
  --set authentik.token.secretName=authentik-operator-token
```

`clusterName` names the ownership role (`authentik-operator-<clusterName>`) that marks the objects of this cluster.
Give each cluster that talks to the same authentik its own value.

The chart installs the CRD by default and keeps it on `helm uninstall`, so that managed resources are not lost.
The full list of values is in the [chart reference](https://github.com/SlashNephy/authentik-operator/blob/main/charts/chart/README.md#values).

### 3. Declare an application

```yaml
apiVersion: authentik.starry.blue/v1alpha1
kind: AuthentikApplication
metadata:
  name: wiki
  namespace: authentik-operator
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

```bash
kubectl apply -f wiki.yaml
kubectl -n authentik-operator get authentikapplication wiki
```

The status reports the created Application and Provider, and the `Ready` condition tells you whether authentik matches the spec.

## Upgrade

```bash
helm repo update
helm upgrade authentik-operator authentik-operator/authentik-operator --namespace authentik-operator --reuse-values
```

Pick the chart version that matches your authentik minor version, and upgrade both together.

## License

[Apache License 2.0](https://github.com/SlashNephy/authentik-operator/blob/main/LICENSE)
