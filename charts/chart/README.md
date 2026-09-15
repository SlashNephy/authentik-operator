# authentik-operator Helm chart

Installs authentik-operator, which manages authentik Applications, Providers, and access rights through `AuthentikApplication` resources.
See [docs/spec.md](../../docs/spec.md) for the behavior.

## Prerequisites

### API token

Create a service account in authentik and an API token for it with `intent=api` and `expiring=false`.
The account does not need to be a superuser. Assign a role with the following global permissions to it (docs/spec.md §4).

| Purpose | Permissions |
|---|---|
| Ownership role | `authentik_rbac.view_role`, `authentik_rbac.add_role`, `authentik_rbac.change_role`, `authentik_rbac.assign_role_permissions`, `authentik_rbac.unassign_role_permissions`, `guardian.view_roleobjectpermission` |
| Application | `authentik_core.view_application`, `add_application`, `change_application`, `delete_application` |
| Proxy Provider | `authentik_providers_proxy.view_proxyprovider`, `add_proxyprovider`, `change_proxyprovider`, `delete_proxyprovider` |
| OAuth2 Provider | `authentik_providers_oauth2.view_oauth2provider`, `add_oauth2provider`, `change_oauth2provider`, `delete_oauth2provider` |
| PolicyBinding | `authentik_policies.view_policybinding`, `add_policybinding`, `change_policybinding`, `delete_policybinding` |
| Outpost membership | `authentik_outposts.view_outpost`, `authentik_outposts.change_outpost` |
| Reference resolution | `authentik_core.view_group`, `authentik_core.view_user`, `authentik_policies.view_policy`, `authentik_flows.view_flow`, `authentik_crypto.view_certificatekeypair`, `authentik_providers_oauth2.view_scopemapping` |

`guardian.view_roleobjectpermission` is not offered by the permission picker of the web UI.
Assign it through the API with a token that may change roles:

```bash
curl -X POST "https://auth.example.com/api/v3/rbac/permissions/assigned_by_roles/<role uuid>/assign/" \
  -H "Authorization: Bearer <admin token>" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["guardian.view_roleobjectpermission"]}'
```

Store the token in a Secret in the release namespace:

```bash
kubectl -n authentik-operator create secret generic authentik-operator-token --from-literal=token=<token>
```

## Install

```bash
helm install authentik-operator ./charts/chart \
  --namespace authentik-operator \
  --set clusterName=production \
  --set authentik.url=https://auth.example.com \
  --set authentik.token.secretName=authentik-operator-token
```

## Values

| Key | Default | Description |
|---|---|---|
| `clusterName` | `""` | Cluster identifier in the ownership role name `authentik-operator-<clusterName>`. Required unless `ownerRole` is set |
| `ownerRole` | `""` | Full name of the ownership role. Takes precedence over `clusterName` |
| `authentik.url` | `""` | Root URL of authentik. Required |
| `authentik.token.secretName` | `""` | Secret that holds the API token. Required |
| `authentik.token.key` | `token` | Key of the API token in the Secret |
| `authentik.ca.secretName` | `""` | Secret that holds additional CA certificates to trust |
| `authentik.ca.key` | `ca.crt` | Key of the CA certificates in the Secret |
| `authentik.insecure` | `false` | Disable TLS certificate verification |
| `resyncInterval` | `10m` | Period of drift detection and the upper bound of the retry interval |
| `markerGC` | `true` | Remove markers of objects deleted outside the operator. Disable it on authentik versions that clean up orphaned object permissions themselves |
| `crd.enable` | `true` | Install the CRD with the chart |
| `crd.keep` | `true` | Keep the CRD on `helm uninstall` (`helm.sh/resource-policy: keep`) so that resources are not lost |
| `manager.replicas` | `1` | Replicas of the manager. Leader election is always enabled |
| `manager.image.repository` | `ghcr.io/slashnephy/authentik-operator` | Image repository |
| `manager.image.tag` | Chart `appVersion` | Image tag |
| `metrics.enabled` | `true` | Serve metrics through the metrics Service |
| `metrics.secure` | `true` | Serve metrics over HTTPS with authentication and authorization |
| `prometheus.enabled` | `false` | Create a ServiceMonitor |

See [values.yaml](values.yaml) for the remaining settings of the Deployment.
