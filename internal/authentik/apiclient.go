/*
Copyright 2026 SlashNephy.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authentik

import (
	"context"
	"net/http"
	"time"

	api "goauthentik.io/api/v3"
)

// listPageSize is the page size requested from list APIs.
const listPageSize = 100

// client implements Client with client-go.
type client struct {
	api *api.APIClient
}

var _ Client = new(client)

// call runs a client-go request that returns a body, records metrics, and converts errors.
func call[T any](operation string, execute func() (T, *http.Response, error)) (T, error) {
	start := time.Now()
	result, resp, err := execute()
	observeRequest(operation, start, resp)
	if err := wrapError(operation, resp, err); err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

// callNoContent runs a client-go request that returns no body, records metrics, and converts errors.
func callNoContent(operation string, execute func() (*http.Response, error)) error {
	start := time.Now()
	resp, err := execute()
	observeRequest(operation, start, resp)
	return wrapError(operation, resp, err)
}

// page is one page of a list API.
type page[T any] struct {
	results []T
	next    float32
}

// listAll follows every page of a list API and returns the items for which keep returns true.
func listAll[T any](operation string, fetch func(page int32) (page[T], *http.Response, error), keep func(*T) bool) ([]T, error) {
	items := []T{}
	for current := int32(1); ; {
		p, err := call(operation, func() (page[T], *http.Response, error) { return fetch(current) })
		if err != nil {
			return nil, err
		}
		for i := range p.results {
			if keep(&p.results[i]) {
				items = append(items, p.results[i])
			}
		}
		if p.next <= 0 {
			return items, nil
		}
		current = int32(p.next)
	}
}

// toPage converts the pagination fields of a client-go list response.
func toPage[T any](results []T, pagination *api.Pagination) page[T] {
	if pagination == nil {
		return page[T]{results: results}
	}
	return page[T]{results: results, next: pagination.Next}
}

func (c *client) GetVersion(ctx context.Context) (*api.Version, error) {
	return call("GetVersion", c.api.AdminAPI.AdminVersionRetrieve(ctx).Execute)
}

func (c *client) GetApplication(ctx context.Context, slug string) (*api.Application, error) {
	return call("GetApplication", c.api.CoreAPI.CoreApplicationsRetrieve(ctx, slug).Execute)
}

func (c *client) CreateApplication(ctx context.Context, request *api.ApplicationRequest) (*api.Application, error) {
	return call("CreateApplication", c.api.CoreAPI.CoreApplicationsCreate(ctx).ApplicationRequest(*request).Execute)
}

func (c *client) PatchApplication(ctx context.Context, slug string, request *api.PatchedApplicationRequest) (*api.Application, error) {
	return call("PatchApplication", c.api.CoreAPI.CoreApplicationsPartialUpdate(ctx, slug).PatchedApplicationRequest(*request).Execute)
}

func (c *client) DeleteApplication(ctx context.Context, slug string) error {
	return callNoContent("DeleteApplication", c.api.CoreAPI.CoreApplicationsDestroy(ctx, slug).Execute)
}

func (c *client) GetProxyProvider(ctx context.Context, pk int32) (*api.ProxyProvider, error) {
	return call("GetProxyProvider", c.api.ProvidersAPI.ProvidersProxyRetrieve(ctx, pk).Execute)
}

func (c *client) FindProxyProvidersByName(ctx context.Context, name string) ([]api.ProxyProvider, error) {
	return listAll("FindProxyProvidersByName", func(p int32) (page[api.ProxyProvider], *http.Response, error) {
		// name__iexact is case-insensitive, so the results are narrowed to exact matches below.
		list, resp, err := c.api.ProvidersAPI.ProvidersProxyList(ctx).NameIexact(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.ProxyProvider]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(provider *api.ProxyProvider) bool { return provider.Name == name })
}

func (c *client) CreateProxyProvider(ctx context.Context, request *api.ProxyProviderRequest) (*api.ProxyProvider, error) {
	return call("CreateProxyProvider", c.api.ProvidersAPI.ProvidersProxyCreate(ctx).ProxyProviderRequest(*request).Execute)
}

func (c *client) PatchProxyProvider(ctx context.Context, pk int32, request *api.PatchedProxyProviderRequest) (*api.ProxyProvider, error) {
	return call("PatchProxyProvider", c.api.ProvidersAPI.ProvidersProxyPartialUpdate(ctx, pk).PatchedProxyProviderRequest(*request).Execute)
}

func (c *client) DeleteProxyProvider(ctx context.Context, pk int32) error {
	return callNoContent("DeleteProxyProvider", c.api.ProvidersAPI.ProvidersProxyDestroy(ctx, pk).Execute)
}

func (c *client) GetOAuth2Provider(ctx context.Context, pk int32) (*api.OAuth2Provider, error) {
	return call("GetOAuth2Provider", c.api.ProvidersAPI.ProvidersOauth2Retrieve(ctx, pk).Execute)
}

func (c *client) FindOAuth2ProvidersByName(ctx context.Context, name string) ([]api.OAuth2Provider, error) {
	return listAll("FindOAuth2ProvidersByName", func(p int32) (page[api.OAuth2Provider], *http.Response, error) {
		list, resp, err := c.api.ProvidersAPI.ProvidersOauth2List(ctx).Name(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.OAuth2Provider]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(provider *api.OAuth2Provider) bool { return provider.Name == name })
}

func (c *client) CreateOAuth2Provider(ctx context.Context, request *api.OAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	return call("CreateOAuth2Provider", c.api.ProvidersAPI.ProvidersOauth2Create(ctx).OAuth2ProviderRequest(*request).Execute)
}

func (c *client) PatchOAuth2Provider(ctx context.Context, pk int32, request *api.PatchedOAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	return call("PatchOAuth2Provider", c.api.ProvidersAPI.ProvidersOauth2PartialUpdate(ctx, pk).PatchedOAuth2ProviderRequest(*request).Execute)
}

func (c *client) DeleteOAuth2Provider(ctx context.Context, pk int32) error {
	return callNoContent("DeleteOAuth2Provider", c.api.ProvidersAPI.ProvidersOauth2Destroy(ctx, pk).Execute)
}

func (c *client) GetPolicyBinding(ctx context.Context, uuid string) (*api.PolicyBinding, error) {
	return call("GetPolicyBinding", c.api.PoliciesAPI.PoliciesBindingsRetrieve(ctx, uuid).Execute)
}

func (c *client) ListPolicyBindings(ctx context.Context, target string) ([]api.PolicyBinding, error) {
	return listAll("ListPolicyBindings", func(p int32) (page[api.PolicyBinding], *http.Response, error) {
		list, resp, err := c.api.PoliciesAPI.PoliciesBindingsList(ctx).Target(target).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.PolicyBinding]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(binding *api.PolicyBinding) bool { return binding.Target == target })
}

func (c *client) CreatePolicyBinding(ctx context.Context, request *api.PolicyBindingRequest) (*api.PolicyBinding, error) {
	return call("CreatePolicyBinding", c.api.PoliciesAPI.PoliciesBindingsCreate(ctx).PolicyBindingRequest(*request).Execute)
}

func (c *client) PatchPolicyBinding(ctx context.Context, uuid string, request *api.PatchedPolicyBindingRequest) (*api.PolicyBinding, error) {
	return call("PatchPolicyBinding", c.api.PoliciesAPI.PoliciesBindingsPartialUpdate(ctx, uuid).PatchedPolicyBindingRequest(*request).Execute)
}

func (c *client) DeletePolicyBinding(ctx context.Context, uuid string) error {
	return callNoContent("DeletePolicyBinding", c.api.PoliciesAPI.PoliciesBindingsDestroy(ctx, uuid).Execute)
}

func (c *client) GetOutpost(ctx context.Context, uuid string) (*api.Outpost, error) {
	return call("GetOutpost", c.api.OutpostsAPI.OutpostsInstancesRetrieve(ctx, uuid).Execute)
}

func (c *client) FindOutpostsByName(ctx context.Context, name string) ([]api.Outpost, error) {
	return listAll("FindOutpostsByName", func(p int32) (page[api.Outpost], *http.Response, error) {
		// name__iexact is case-insensitive, so the results are narrowed to exact matches below.
		list, resp, err := c.api.OutpostsAPI.OutpostsInstancesList(ctx).NameIexact(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Outpost]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(outpost *api.Outpost) bool { return outpost.Name == name })
}

func (c *client) SetOutpostProviders(ctx context.Context, uuid string, providers []int32) (*api.Outpost, error) {
	if providers == nil {
		// A nil slice is omitted from the request body, which would leave the list unchanged.
		providers = []int32{}
	}
	request := api.PatchedOutpostRequest{Providers: providers}
	return call("SetOutpostProviders", c.api.OutpostsAPI.OutpostsInstancesPartialUpdate(ctx, uuid).PatchedOutpostRequest(request).Execute)
}

func (c *client) GetRole(ctx context.Context, uuid string) (*api.Role, error) {
	return call("GetRole", c.api.RbacAPI.RbacRolesRetrieve(ctx, uuid).Execute)
}

func (c *client) FindRolesByName(ctx context.Context, name string) ([]api.Role, error) {
	return listAll("FindRolesByName", func(p int32) (page[api.Role], *http.Response, error) {
		list, resp, err := c.api.RbacAPI.RbacRolesList(ctx).Name(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Role]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(role *api.Role) bool { return role.Name == name })
}

func (c *client) CreateRole(ctx context.Context, name string) (*api.Role, error) {
	return call("CreateRole", c.api.RbacAPI.RbacRolesCreate(ctx).RoleRequest(api.RoleRequest{Name: name}).Execute)
}

func (c *client) AssignObjectPermission(ctx context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error {
	request := api.PermissionAssignRequest{Permissions: []string{permission}, Model: &model, ObjectPk: &objectPK}
	_, err := call("AssignObjectPermission", c.api.RbacAPI.RbacPermissionsAssignedByRolesAssign(ctx, roleUUID).PermissionAssignRequest(request).Execute)
	return err
}

func (c *client) UnassignObjectPermission(ctx context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error {
	request := api.PatchedPermissionAssignRequest{Permissions: []string{permission}, Model: &model, ObjectPk: &objectPK}
	return callNoContent("UnassignObjectPermission", c.api.RbacAPI.RbacPermissionsAssignedByRolesUnassignPartialUpdate(ctx, roleUUID).PatchedPermissionAssignRequest(request).Execute)
}

func (c *client) ListRoleObjectPermissions(ctx context.Context, roleUUID string) ([]api.ExtraRoleObjectPermission, error) {
	return listAll("ListRoleObjectPermissions", func(p int32) (page[api.ExtraRoleObjectPermission], *http.Response, error) {
		list, resp, err := c.api.RbacAPI.RbacPermissionsRolesList(ctx).Uuid(roleUUID).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.ExtraRoleObjectPermission]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(*api.ExtraRoleObjectPermission) bool { return true })
}

func (c *client) ListObjectPermissionRoles(ctx context.Context, model api.ModelEnum, objectPK string) ([]api.RoleAssignedObjectPermission, error) {
	return listAll("ListObjectPermissionRoles", func(p int32) (page[api.RoleAssignedObjectPermission], *http.Response, error) {
		list, resp, err := c.api.RbacAPI.RbacPermissionsAssignedByRolesList(ctx).Model(string(model)).ObjectPk(objectPK).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.RoleAssignedObjectPermission]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(*api.RoleAssignedObjectPermission) bool { return true })
}

func (c *client) GetGroup(ctx context.Context, uuid string) (*api.Group, error) {
	return call("GetGroup", c.api.CoreAPI.CoreGroupsRetrieve(ctx, uuid).IncludeUsers(false).Execute)
}

func (c *client) FindGroupsByName(ctx context.Context, name string) ([]api.Group, error) {
	return listAll("FindGroupsByName", func(p int32) (page[api.Group], *http.Response, error) {
		list, resp, err := c.api.CoreAPI.CoreGroupsList(ctx).Name(name).IncludeUsers(false).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Group]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(group *api.Group) bool { return group.Name == name })
}

func (c *client) GetUser(ctx context.Context, pk int32) (*api.User, error) {
	return call("GetUser", c.api.CoreAPI.CoreUsersRetrieve(ctx, pk).Execute)
}

func (c *client) FindUsersByUsername(ctx context.Context, username string) ([]api.User, error) {
	return listAll("FindUsersByUsername", func(p int32) (page[api.User], *http.Response, error) {
		list, resp, err := c.api.CoreAPI.CoreUsersList(ctx).Username(username).IncludeGroups(false).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.User]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(user *api.User) bool { return user.Username == username })
}

func (c *client) GetPolicy(ctx context.Context, uuid string) (*api.Policy, error) {
	return call("GetPolicy", c.api.PoliciesAPI.PoliciesAllRetrieve(ctx, uuid).Execute)
}

func (c *client) FindPoliciesByName(ctx context.Context, name string) ([]api.Policy, error) {
	return listAll("FindPoliciesByName", func(p int32) (page[api.Policy], *http.Response, error) {
		// The policy list API has no name filter. search matches the name partially and case-insensitively,
		// so the results are narrowed to exact matches below.
		list, resp, err := c.api.PoliciesAPI.PoliciesAllList(ctx).Search(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Policy]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(policy *api.Policy) bool { return policy.Name == name })
}

func (c *client) GetFlow(ctx context.Context, uuid string) (*api.Flow, error) {
	// The retrieve API of flows is keyed by slug, so the UUID is looked up through the list API.
	flows, err := listAll("GetFlow", func(p int32) (page[api.Flow], *http.Response, error) {
		list, resp, err := c.api.FlowsAPI.FlowsInstancesList(ctx).FlowUuid(uuid).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Flow]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(flow *api.Flow) bool { return flow.Pk == uuid })
	if err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return nil, &APIError{Operation: "GetFlow", StatusCode: http.StatusNotFound, Body: "no flow with uuid " + uuid}
	}
	return &flows[0], nil
}

func (c *client) FindFlowsBySlug(ctx context.Context, slug string) ([]api.Flow, error) {
	return listAll("FindFlowsBySlug", func(p int32) (page[api.Flow], *http.Response, error) {
		list, resp, err := c.api.FlowsAPI.FlowsInstancesList(ctx).Slug(slug).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.Flow]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(flow *api.Flow) bool { return flow.Slug == slug })
}

func (c *client) GetCertificateKeyPair(ctx context.Context, uuid string) (*api.CertificateKeyPair, error) {
	return call("GetCertificateKeyPair", c.api.CryptoAPI.CryptoCertificatekeypairsRetrieve(ctx, uuid).Execute)
}

func (c *client) FindCertificateKeyPairsByName(ctx context.Context, name string) ([]api.CertificateKeyPair, error) {
	return listAll("FindCertificateKeyPairsByName", func(p int32) (page[api.CertificateKeyPair], *http.Response, error) {
		list, resp, err := c.api.CryptoAPI.CryptoCertificatekeypairsList(ctx).Name(name).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.CertificateKeyPair]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(keyPair *api.CertificateKeyPair) bool { return keyPair.Name == name })
}

func (c *client) GetScopeMapping(ctx context.Context, uuid string) (*api.ScopeMapping, error) {
	return call("GetScopeMapping", c.api.PropertymappingsAPI.PropertymappingsProviderScopeRetrieve(ctx, uuid).Execute)
}

func (c *client) FindScopeMappingsByScopeName(ctx context.Context, scopeName string) ([]api.ScopeMapping, error) {
	return listAll("FindScopeMappingsByScopeName", func(p int32) (page[api.ScopeMapping], *http.Response, error) {
		list, resp, err := c.api.PropertymappingsAPI.PropertymappingsProviderScopeList(ctx).ScopeName(scopeName).Page(p).PageSize(listPageSize).Execute()
		if list == nil {
			return page[api.ScopeMapping]{}, resp, err
		}
		return toPage(list.Results, &list.Pagination), resp, err
	}, func(mapping *api.ScopeMapping) bool { return mapping.ScopeName == scopeName })
}
