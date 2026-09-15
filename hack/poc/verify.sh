#!/usr/bin/env bash
# Verify the assumptions listed in docs/spec.md §8 against the authentik started by hack/authentik/up.sh.
# Every check prints PASS or FAIL, and the script exits non-zero when any check fails.
# Objects are created with a per-run suffix, so the script can be run repeatedly against the same instance.
set -euo pipefail

NAMESPACE="${AUTHENTIK_NAMESPACE:-authentik}"
RELEASE="${AUTHENTIK_RELEASE:-authentik}"
LOCAL_PORT="${AUTHENTIK_LOCAL_PORT:-9000}"
URL="http://localhost:${LOCAL_PORT}"
RUN="$(date +%s)"

WORK="$(mktemp -d)"
trap 'kill "${PF_PID:-}" 2>/dev/null || true; rm -rf "${WORK}"' EXIT

kubectl -n "${NAMESPACE}" port-forward "svc/${RELEASE}-server" "${LOCAL_PORT}:80" >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 60); do
  curl -sf -o /dev/null "${URL}/-/health/ready/" && break
  sleep 1
done

ADMIN_TOKEN="$(kubectl -n "${NAMESPACE}" get secret authentik-bootstrap -o jsonpath='{.data.AUTHENTIK_BOOTSTRAP_TOKEN}' | base64 -d)"

FAILED=0
STATUS=""
BODY=""

# call <token> <method> <path> [json]: store the response in STATUS and BODY.
call() {
  local token=$1 method=$2 path=$3 body=${4:-}
  local args=(-sS -o "${WORK}/body" -w '%{http_code}' -X "${method}"
    -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json')
  [[ -n "${body}" ]] && args+=(--data "${body}")
  STATUS="$(curl "${args[@]}" "${URL}/api/v3${path}")"
  BODY="$(cat "${WORK}/body")"
}

# must <token> <method> <path> [json]: abort unless the response is 2xx (for setup steps).
must() {
  call "$@"
  if [[ "${STATUS}" != 2* ]]; then
    echo "setup failed: $2 $3 -> ${STATUS}: ${BODY:0:500}" >&2
    exit 1
  fi
}

section() { printf '\n== %s\n' "$1"; }

pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1"
  echo "      last response: ${STATUS} ${BODY:0:300}"
  FAILED=1
}

# jqb <filter>: extract a value from BODY.
jqb() { jq -r "$1" <<<"${BODY}"; }

# expect_status <status> <description>
expect_status() {
  if [[ "${STATUS}" == "$1" ]]; then pass "$2 (${STATUS})"; else fail "$2"; fi
}

# expect_body <jq filter> <expected> <description>: the response is 2xx and the filter yields the expected value.
expect_body() {
  if [[ "${STATUS}" == 2* && "$(jqb "$1")" == "$2" ]]; then pass "$3"; else fail "$3"; fi
}

# assign_marker <token> <role> <model> <object_pk>
assign_marker() {
  local token=$1 role=$2 model=$3 object_pk=$4
  call "${token}" POST "/rbac/permissions/assigned_by_roles/${role}/assign/" \
    "$(jq -n --arg m "${model}" --arg o "${object_pk}" --arg p "${model%%.*}.view_${model#*.}" \
      '{permissions: [$p], model: $m, object_pk: $o}')"
}

# unassign_marker <token> <role> <model> <object_pk>
unassign_marker() {
  local token=$1 role=$2 model=$3 object_pk=$4
  call "${token}" PATCH "/rbac/permissions/assigned_by_roles/${role}/unassign/" \
    "$(jq -n --arg m "${model}" --arg o "${object_pk}" --arg p "${model%%.*}.view_${model#*.}" \
      '{permissions: [$p], model: $m, object_pk: $o}')"
}

# is_marked <token> <role> <model> <object_pk>: whether the reverse lookup returns an object permission of the role for the object.
is_marked() {
  local token=$1 role=$2 model=$3 object_pk=$4
  call "${token}" GET "/rbac/permissions/assigned_by_roles/?model=${model}&object_pk=${object_pk}"
  [[ "${STATUS}" == 200 ]] && jq -e --arg r "${role}" --arg o "${object_pk}" \
    '.results[] | select(.role_pk == $r) | .object_permissions[] | select(.object_pk == $o)' <<<"${BODY}" >/dev/null
}

# ---------------------------------------------------------------------------
section "setup"

must "${ADMIN_TOKEN}" GET /admin/version/
echo "authentik version: $(jqb .version_current)"

must "${ADMIN_TOKEN}" GET "/flows/instances/?slug=default-provider-authorization-implicit-consent"
AUTHZ_FLOW="$(jqb '.results[0].pk')"
must "${ADMIN_TOKEN}" GET "/flows/instances/?slug=default-provider-invalidation-flow"
INVALIDATION_FLOW="$(jqb '.results[0].pk')"

must "${ADMIN_TOKEN}" POST /core/users/ "$(jq -n --arg u "poc-user-${RUN}" '{username: $u, name: $u, type: "internal", is_active: true}')"
USER_PK="$(jqb .pk)"
must "${ADMIN_TOKEN}" POST /core/groups/ "$(jq -n --arg n "poc-group-${RUN}" '{name: $n}')"
GROUP_PK="$(jqb .pk)"

# The ownership role and the objects that receive markers.
must "${ADMIN_TOKEN}" POST /rbac/roles/ "$(jq -n --arg n "authentik-operator-poc-${RUN}" '{name: $n}')"
OWNER_ROLE="$(jqb .pk)"
OWNER_ROLE_NAME="$(jqb .name)"

must "${ADMIN_TOKEN}" POST /providers/proxy/ "$(jq -n --arg n "poc-marker-${RUN}" --arg a "${AUTHZ_FLOW}" --arg i "${INVALIDATION_FLOW}" \
  '{name: $n, authorization_flow: $a, invalidation_flow: $i, mode: "forward_single", external_host: "https://marker.example.com"}')"
PROVIDER_PK="$(jqb .pk)"
MARKER_SLUG="poc-marker-${RUN}"
must "${ADMIN_TOKEN}" POST /core/applications/ "$(jq -n --arg s "${MARKER_SLUG}" --argjson p "${PROVIDER_PK}" '{name: $s, slug: $s, provider: $p}')"
APP_PK="$(jqb .pk)"
must "${ADMIN_TOKEN}" POST /policies/bindings/ "$(jq -n --arg t "${APP_PK}" --arg g "${GROUP_PK}" '{target: $t, group: $g, order: 10}')"
BINDING_PK="$(jqb .pk)"

MARKED_OBJECTS=(
  "authentik_core.application ${APP_PK}"
  "authentik_providers_proxy.proxyprovider ${PROVIDER_PK}"
  "authentik_policies.policybinding ${BINDING_PK}"
)

# ---------------------------------------------------------------------------
section "§8-1 object permissions on a role and reverse lookup (API token)"

for entry in "${MARKED_OBJECTS[@]}"; do
  read -r model object_pk <<<"${entry}"
  assign_marker "${ADMIN_TOKEN}" "${OWNER_ROLE}" "${model}" "${object_pk}"
  expect_status 200 "assign view permission on ${model} ${object_pk}"
done

for entry in "${MARKED_OBJECTS[@]}"; do
  read -r model object_pk <<<"${entry}"
  description="reverse lookup finds the owner role for ${model} ${object_pk}"
  if is_marked "${ADMIN_TOKEN}" "${OWNER_ROLE}" "${model}" "${object_pk}"; then pass "${description}"; else fail "${description}"; fi
done

call "${ADMIN_TOKEN}" GET "/rbac/permissions/assigned_by_roles/?model=authentik_core.application&object_pk=${APP_PK}"
echo "info: roles returned by the reverse lookup: $(jqb '[.results[].name] | join(", ")')"
# object_permissions is not narrowed by object_pk: it holds every object permission of the role.
expect_body "[.results[] | select(.role_pk == \"${OWNER_ROLE}\") | .object_permissions[]] | length" 3 \
  "reverse lookup returns all object permissions of the role, not only those of the requested object"
# Roles holding a global permission on the model (such as \"authentik Read-only\") are also returned.
expect_body "[.results[] | select(.model_permissions | length > 0)] | length > 0" true \
  "reverse lookup also returns roles that hold only model-level permissions"

call "${ADMIN_TOKEN}" GET "/rbac/permissions/roles/?uuid=${OWNER_ROLE}"
expect_body .pagination.count 3 "listing the role's object permissions returns all 3 markers"
echo "info: /rbac/permissions/roles/ entries: $(jqb '[.results[] | "\(.app_label).\(.model)/\(.object_pk)"] | join(", ")')"

# ---------------------------------------------------------------------------
section "§8-2 an application with zero bindings is accessible to every user"

PUBLIC_SLUG="poc-public-${RUN}"
must "${ADMIN_TOKEN}" POST /core/applications/ "$(jq -n --arg s "${PUBLIC_SLUG}" '{name: $s, slug: $s}')"

call "${ADMIN_TOKEN}" GET "/core/applications/${PUBLIC_SLUG}/check_access/?for_user=${USER_PK}"
expect_body .passing true "check_access passes for a plain user on an application without bindings"
call "${ADMIN_TOKEN}" GET "/core/applications/${MARKER_SLUG}/check_access/?for_user=${USER_PK}"
expect_body .passing false "control: check_access fails for the same user when a group binding exists"

must "${ADMIN_TOKEN}" POST /core/tokens/ "$(jq -n --arg i "poc-user-token-${RUN}" --argjson u "${USER_PK}" '{identifier: $i, intent: "api", user: $u, expiring: false}')"
must "${ADMIN_TOKEN}" GET "/core/tokens/poc-user-token-${RUN}/view_key/"
USER_TOKEN="$(jqb .key)"

call "${USER_TOKEN}" GET "/core/applications/?page_size=1000"
expect_body "[.results[].slug] | index(\"${PUBLIC_SLUG}\") != null" true \
  "the plain user's library lists the application without bindings"
expect_body "[.results[].slug] | index(\"${MARKER_SLUG}\") != null" false \
  "control: the plain user's library does not list the application with a group binding"

# ---------------------------------------------------------------------------
section "§8-3 minimum permissions for the operator's token (non-superuser)"

OPERATOR_PERMISSIONS=(
  authentik_rbac.view_role
  authentik_rbac.add_role
  authentik_rbac.change_role
  authentik_rbac.assign_role_permissions
  authentik_rbac.unassign_role_permissions
  guardian.view_roleobjectpermission
  authentik_core.view_application
  authentik_core.add_application
  authentik_core.change_application
  authentik_core.delete_application
  authentik_core.view_group
  authentik_core.view_user
  authentik_providers_proxy.view_proxyprovider
  authentik_providers_proxy.add_proxyprovider
  authentik_providers_proxy.change_proxyprovider
  authentik_providers_proxy.delete_proxyprovider
  authentik_providers_oauth2.view_oauth2provider
  authentik_providers_oauth2.add_oauth2provider
  authentik_providers_oauth2.change_oauth2provider
  authentik_providers_oauth2.delete_oauth2provider
  authentik_providers_oauth2.view_scopemapping
  authentik_policies.view_policybinding
  authentik_policies.add_policybinding
  authentik_policies.change_policybinding
  authentik_policies.delete_policybinding
  authentik_policies.view_policy
  authentik_flows.view_flow
  authentik_crypto.view_certificatekeypair
  authentik_outposts.view_outpost
  authentik_outposts.change_outpost
)

must "${ADMIN_TOKEN}" POST /rbac/roles/ "$(jq -n --arg n "poc-operator-permissions-${RUN}" '{name: $n}')"
PERMISSIONS_ROLE="$(jqb .pk)"
must "${ADMIN_TOKEN}" POST "/rbac/permissions/assigned_by_roles/${PERMISSIONS_ROLE}/assign/" \
  "$(printf '%s\n' "${OPERATOR_PERMISSIONS[@]}" | jq -R . | jq -s '{permissions: .}')"
must "${ADMIN_TOKEN}" POST /core/users/ "$(jq -n --arg u "poc-operator-${RUN}" --arg r "${PERMISSIONS_ROLE}" '{username: $u, name: $u, type: "service_account", roles: [$r]}')"
OPERATOR_USER_PK="$(jqb .pk)"
must "${ADMIN_TOKEN}" POST /core/tokens/ "$(jq -n --arg i "poc-operator-token-${RUN}" --argjson u "${OPERATOR_USER_PK}" '{identifier: $i, intent: "api", user: $u, expiring: false}')"
must "${ADMIN_TOKEN}" GET "/core/tokens/poc-operator-token-${RUN}/view_key/"
OP="$(jqb .key)"

call "${OP}" GET /core/users/me/
expect_body .user.is_superuser false "the operator token's user is not a superuser"

# op <description> <method> <path> [json]: call with the operator token and expect 2xx.
op() {
  local description=$1
  shift
  call "${OP}" "$@"
  if [[ "${STATUS}" == 2* ]]; then pass "${description} ($1 $2 -> ${STATUS})"; else fail "${description} ($1 $2 -> ${STATUS})"; fi
}

# without_permission <permission>: temporarily remove a permission from the operator's role (restore with with_permission).
without_permission() {
  must "${ADMIN_TOKEN}" PATCH "/rbac/permissions/assigned_by_roles/${PERMISSIONS_ROLE}/unassign/" "$(jq -n --arg p "$1" '{permissions: [$p]}')"
}
with_permission() {
  must "${ADMIN_TOKEN}" POST "/rbac/permissions/assigned_by_roles/${PERMISSIONS_ROLE}/assign/" "$(jq -n --arg p "$1" '{permissions: [$p]}')"
}

op "read the server version" GET /admin/version/
op "look up the owner role by name" GET "/rbac/roles/?name=${OWNER_ROLE_NAME}"
op "create an owner role" POST /rbac/roles/ "$(jq -n --arg n "authentik-operator-poc-min-${RUN}" '{name: $n}')"
OP_ROLE="$(jqb .pk)"

op "resolve a flow by slug" GET "/flows/instances/?slug=default-provider-authorization-implicit-consent"
op "resolve a group by name" GET "/core/groups/?name=poc-group-${RUN}"
op "resolve a user by username" GET "/core/users/?username=poc-user-${RUN}"
op "resolve a policy by name" GET "/policies/all/?name=default-authentication-flow-password-stage"
op "resolve a scope mapping by scope_name" GET "/propertymappings/provider/scope/?scope_name=openid"
SCOPE_PKS="$(jqb '[.results[].pk]')"
op "resolve a certificate by name" GET "/crypto/certificatekeypairs/?name=authentik%20Self-signed%20Certificate&has_key=true"
CERT_PK="$(jqb '.results[0].pk')"
op "resolve the embedded outpost by name" GET "/outposts/instances/?name__iexact=authentik%20Embedded%20Outpost"
OUTPOST_PK="$(jqb '.results[0].pk')"
OUTPOST_PROVIDERS="$(jqb '.results[0].providers')"

op "create a proxy provider" POST /providers/proxy/ "$(jq -n --arg n "poc-op-proxy-${RUN}" --arg a "${AUTHZ_FLOW}" --arg i "${INVALIDATION_FLOW}" \
  '{name: $n, authorization_flow: $a, invalidation_flow: $i, mode: "forward_single", external_host: "https://op.example.com"}')"
OP_PROXY_PK="$(jqb .pk)"
assign_marker "${OP}" "${OP_ROLE}" authentik_providers_proxy.proxyprovider "${OP_PROXY_PK}"
expect_status 200 "mark the proxy provider"

OP_SLUG="poc-op-${RUN}"
op "create an application" POST /core/applications/ "$(jq -n --arg s "${OP_SLUG}" --argjson p "${OP_PROXY_PK}" '{name: $s, slug: $s, provider: $p}')"
OP_APP_PK="$(jqb .pk)"
assign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${OP_APP_PK}"
expect_status 200 "mark the application"

op "create a policy binding" POST /policies/bindings/ "$(jq -n --arg t "${OP_APP_PK}" --arg g "${GROUP_PK}" '{target: $t, group: $g, order: 10}')"
OP_BINDING_PK="$(jqb .pk)"
assign_marker "${OP}" "${OP_ROLE}" authentik_policies.policybinding "${OP_BINDING_PK}"
expect_status 200 "mark the policy binding"

description="reverse lookup through the operator token finds the owner role"
if is_marked "${OP}" "${OP_ROLE}" authentik_core.application "${OP_APP_PK}"; then pass "${description}"; else fail "${description}"; fi
op "list objects marked by the owner role" GET "/rbac/permissions/roles/?uuid=${OP_ROLE}"
expect_body .pagination.count 3 "the marked object list through the operator token contains 3 markers"

op "fetch the application by slug" GET "/core/applications/${OP_SLUG}/"
op "list bindings of the application" GET "/policies/bindings/?target=${OP_APP_PK}"
op "update the application with a partial PATCH" PATCH "/core/applications/${OP_SLUG}/" '{"meta_publisher": "authentik-operator PoC", "open_in_new_tab": false}'

# The proxy provider serializer treats a missing mode as "proxy" and then requires internal_host.
call "${OP}" PATCH "/providers/proxy/${OP_PROXY_PK}/" '{"intercept_header_auth": false}'
expect_status 400 "a proxy provider PATCH without mode is rejected"
op "update the proxy provider with mode included" PATCH "/providers/proxy/${OP_PROXY_PK}/" '{"mode": "forward_single", "intercept_header_auth": false}'

# The binding serializer reads target and the group/user/policy fields from the request body only.
call "${OP}" PATCH "/policies/bindings/${OP_BINDING_PK}/" '{"negate": true}'
expect_status 500 "a policy binding PATCH without target fails"
call "${OP}" PATCH "/policies/bindings/${OP_BINDING_PK}/" "$(jq -n --arg t "${OP_APP_PK}" '{target: $t, negate: true}')"
expect_status 400 "a policy binding PATCH with target but without group is rejected"
op "update the policy binding with target and group included" PATCH "/policies/bindings/${OP_BINDING_PK}/" \
  "$(jq -n --arg t "${OP_APP_PK}" --arg g "${GROUP_PK}" '{target: $t, group: $g, negate: true}')"

op "add the provider to the embedded outpost" PATCH "/outposts/instances/${OUTPOST_PK}/" \
  "$(jq -n --argjson p "${OUTPOST_PROVIDERS}" --argjson n "${OP_PROXY_PK}" '{providers: ($p + [$n])}')"
expect_body ".providers | index(${OP_PROXY_PK}) != null" true "the embedded outpost now includes the provider"

op "create an oauth2 provider" POST /providers/oauth2/ "$(jq -n --arg n "poc-op-oauth2-${RUN}" --arg a "${AUTHZ_FLOW}" --arg i "${INVALIDATION_FLOW}" --argjson s "${SCOPE_PKS}" --arg c "${CERT_PK}" \
  '{name: $n, authorization_flow: $a, invalidation_flow: $i, client_type: "confidential", redirect_uris: [{matching_mode: "strict", url: "https://op.example.com/callback", type: "authorization"}], property_mappings: $s, signing_key: $c}')"
OP_OAUTH2_PK="$(jqb .pk)"
op "read the oauth2 provider" GET "/providers/oauth2/${OP_OAUTH2_PK}/"
expect_body '.client_secret | length > 0' true "client_secret is readable through the operator token"
op "set the oauth2 client id and secret" PATCH "/providers/oauth2/${OP_OAUTH2_PK}/" "$(jq -n --arg i "poc-client-${RUN}" '{client_id: $i, client_secret: "poc-secret"}')"

op "remove the provider from the embedded outpost" PATCH "/outposts/instances/${OUTPOST_PK}/" "$(jq -n --argjson p "${OUTPOST_PROVIDERS}" '{providers: $p}')"
unassign_marker "${OP}" "${OP_ROLE}" authentik_policies.policybinding "${OP_BINDING_PK}"
expect_status 204 "unmark the policy binding"
op "delete the policy binding" DELETE "/policies/bindings/${OP_BINDING_PK}/"
op "delete the application" DELETE "/core/applications/${OP_SLUG}/"
op "delete the proxy provider" DELETE "/providers/proxy/${OP_PROXY_PK}/"
op "delete the oauth2 provider" DELETE "/providers/oauth2/${OP_OAUTH2_PK}/"

# Controls: each permission below that is not an obvious per-model CRUD permission is actually required.
without_permission authentik_rbac.assign_role_permissions
assign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${APP_PK}"
expect_status 403 "control: assign is denied without authentik_rbac.assign_role_permissions"
with_permission authentik_rbac.assign_role_permissions

without_permission authentik_rbac.add_role
assign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${APP_PK}"
expect_status 403 "control: assign is denied without authentik_rbac.add_role"
with_permission authentik_rbac.add_role

assign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${APP_PK}"
expect_status 200 "assign succeeds again once the permissions are restored"

without_permission authentik_rbac.unassign_role_permissions
unassign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${APP_PK}"
expect_status 403 "control: unassign is denied without authentik_rbac.unassign_role_permissions"
with_permission authentik_rbac.unassign_role_permissions

without_permission authentik_rbac.change_role
unassign_marker "${OP}" "${OP_ROLE}" authentik_core.application "${APP_PK}"
expect_status 403 "control: unassign is denied without authentik_rbac.change_role"
with_permission authentik_rbac.change_role

without_permission guardian.view_roleobjectpermission
call "${OP}" GET "/rbac/permissions/roles/?uuid=${OP_ROLE}"
expect_status 403 "control: listing marked objects is denied without guardian.view_roleobjectpermission"
with_permission guardian.view_roleobjectpermission

# guardian.view_roleobjectpermission is outside the authentik apps, so the permission list used by the web UI does not offer it.
call "${ADMIN_TOKEN}" GET "/rbac/permissions/?codename=view_roleobjectpermission"
expect_body .pagination.count 0 "guardian.view_roleobjectpermission is not listed by /rbac/permissions/"

# ---------------------------------------------------------------------------
section "§8-5 recovery after the owner role is deleted and recreated"

must "${ADMIN_TOKEN}" DELETE "/rbac/roles/${OWNER_ROLE}/"
call "${ADMIN_TOKEN}" GET "/rbac/permissions/roles/?uuid=${OWNER_ROLE}"
expect_body .pagination.count 0 "deleting the role removes its object permissions"
for entry in "${MARKED_OBJECTS[@]}"; do
  read -r model object_pk <<<"${entry}"
  description="reverse lookup no longer finds a marker for ${model} ${object_pk}"
  if is_marked "${ADMIN_TOKEN}" "${OWNER_ROLE}" "${model}" "${object_pk}"; then fail "${description}"; else pass "${description}"; fi
done

must "${ADMIN_TOKEN}" POST /rbac/roles/ "$(jq -n --arg n "${OWNER_ROLE_NAME}" '{name: $n}')"
NEW_OWNER_ROLE="$(jqb .pk)"
description="the recreated role with the same name has a different UUID"
if [[ "${NEW_OWNER_ROLE}" != "${OWNER_ROLE}" ]]; then pass "${description}"; else fail "${description}"; fi

for entry in "${MARKED_OBJECTS[@]}"; do
  read -r model object_pk <<<"${entry}"
  assign_marker "${ADMIN_TOKEN}" "${NEW_OWNER_ROLE}" "${model}" "${object_pk}"
  expect_status 200 "re-mark ${model} ${object_pk} from the recorded pk"
  description="reverse lookup finds the recreated role for ${model} ${object_pk}"
  if is_marked "${ADMIN_TOKEN}" "${NEW_OWNER_ROLE}" "${model}" "${object_pk}"; then pass "${description}"; else fail "${description}"; fi
done
call "${ADMIN_TOKEN}" GET "/rbac/permissions/roles/?uuid=${NEW_OWNER_ROLE}"
expect_body .pagination.count 3 "the recreated role lists all 3 markers again"

# ---------------------------------------------------------------------------
section "§8-4 icons (applications for the browser check)"

for icon in "https://goauthentik.io/img/icon.png" "fa://fa-book"; do
  slug="poc-icon-${icon%%:*}-${RUN}"
  # The library view hides applications without a launch URL.
  call "${ADMIN_TOKEN}" POST /core/applications/ "$(jq -n --arg s "${slug}" --arg i "${icon}" \
    '{name: $s, slug: $s, meta_icon: $i, meta_launch_url: "https://example.com/"}')"
  expect_status 201 "create an application with meta_icon ${icon}"
  call "${ADMIN_TOKEN}" GET "/core/applications/${slug}/"
  expect_body .meta_icon_url "${icon}" "meta_icon_url of ${slug} is passed through unchanged"
done

# Issue a recovery link so that the library view can be opened in a browser without entering a password.
must "${ADMIN_TOKEN}" GET "/stages/user_login/?name=default-authentication-login"
LOGIN_STAGE="$(jqb '.results[0].pk')"
must "${ADMIN_TOKEN}" POST /flows/instances/ "$(jq -n --arg s "poc-recovery-${RUN}" '{name: $s, slug: $s, title: $s, designation: "recovery", authentication: "none"}')"
RECOVERY_FLOW="$(jqb .pk)"
must "${ADMIN_TOKEN}" POST /flows/bindings/ "$(jq -n --arg t "${RECOVERY_FLOW}" --arg s "${LOGIN_STAGE}" '{target: $t, stage: $s, order: 0}')"
must "${ADMIN_TOKEN}" GET "/core/brands/?default=true"
must "${ADMIN_TOKEN}" PATCH "/core/brands/$(jqb '.results[0].brand_uuid')/" "$(jq -n --arg f "${RECOVERY_FLOW}" '{flow_recovery: $f}')"
must "${ADMIN_TOKEN}" POST "/core/users/${USER_PK}/recovery/" '{"token_duration": "minutes=30"}'
RECOVERY_LINK_FILE="${RECOVERY_LINK_FILE:-${WORK}/recovery-link}"
jqb .link >"${RECOVERY_LINK_FILE}"
echo "info: recovery link for poc-user-${RUN} written to ${RECOVERY_LINK_FILE}; follow it, then open ${URL}/if/user/"

echo
if [[ "${FAILED}" == 0 ]]; then
  echo "RESULT: all checks passed"
else
  echo "RESULT: some checks failed"
fi
exit "${FAILED}"
