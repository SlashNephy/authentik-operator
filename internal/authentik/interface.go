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

	api "goauthentik.io/api/v3"
)

// Client is the subset of the authentik API that the operator uses.
// Methods take and return client-go models. Get methods return an error matching ErrNotFound when the object
// does not exist. Find methods return every object whose name-like key matches exactly (possibly none or several),
// following all pages of the list API.
type Client interface {
	VersionClient
	ApplicationClient
	ProxyProviderClient
	OAuth2ProviderClient
	PolicyBindingClient
	OutpostClient
	RBACClient
	LookupClient
}

// VersionClient reads the authentik server version.
type VersionClient interface {
	GetVersion(ctx context.Context) (*api.Version, error)
}

// ApplicationClient manages Applications.
// Applications are not listed: for a non-superuser the list API returns only the Applications that the
// requesting user may open, so they are always fetched by slug.
type ApplicationClient interface {
	GetApplication(ctx context.Context, slug string) (*api.Application, error)
	CreateApplication(ctx context.Context, request *api.ApplicationRequest) (*api.Application, error)
	PatchApplication(ctx context.Context, slug string, request *api.PatchedApplicationRequest) (*api.Application, error)
	DeleteApplication(ctx context.Context, slug string) error
}

// ProxyProviderClient manages Proxy Providers.
type ProxyProviderClient interface {
	GetProxyProvider(ctx context.Context, pk int32) (*api.ProxyProvider, error)
	FindProxyProvidersByName(ctx context.Context, name string) ([]api.ProxyProvider, error)
	CreateProxyProvider(ctx context.Context, request *api.ProxyProviderRequest) (*api.ProxyProvider, error)
	PatchProxyProvider(ctx context.Context, pk int32, request *api.PatchedProxyProviderRequest) (*api.ProxyProvider, error)
	DeleteProxyProvider(ctx context.Context, pk int32) error
}

// OAuth2ProviderClient manages OAuth2/OpenID Providers.
type OAuth2ProviderClient interface {
	GetOAuth2Provider(ctx context.Context, pk int32) (*api.OAuth2Provider, error)
	FindOAuth2ProvidersByName(ctx context.Context, name string) ([]api.OAuth2Provider, error)
	CreateOAuth2Provider(ctx context.Context, request *api.OAuth2ProviderRequest) (*api.OAuth2Provider, error)
	PatchOAuth2Provider(ctx context.Context, pk int32, request *api.PatchedOAuth2ProviderRequest) (*api.OAuth2Provider, error)
	DeleteOAuth2Provider(ctx context.Context, pk int32) error
}

// PolicyBindingClient manages PolicyBindings.
type PolicyBindingClient interface {
	GetPolicyBinding(ctx context.Context, uuid string) (*api.PolicyBinding, error)
	// ListPolicyBindings returns every Binding whose target is the given pbm_uuid.
	ListPolicyBindings(ctx context.Context, target string) ([]api.PolicyBinding, error)
	CreatePolicyBinding(ctx context.Context, request *api.PolicyBindingRequest) (*api.PolicyBinding, error)
	PatchPolicyBinding(ctx context.Context, uuid string, request *api.PatchedPolicyBindingRequest) (*api.PolicyBinding, error)
	DeletePolicyBinding(ctx context.Context, uuid string) error
}

// OutpostClient reads Outposts and updates their Provider list.
type OutpostClient interface {
	GetOutpost(ctx context.Context, uuid string) (*api.Outpost, error)
	FindOutpostsByName(ctx context.Context, name string) ([]api.Outpost, error)
	// SetOutpostProviders replaces the whole providers list of the Outpost.
	SetOutpostProviders(ctx context.Context, uuid string, providers []int32) (*api.Outpost, error)
}

// RBACClient manages the ownership role and its object permissions (docs/spec.md §3.1).
type RBACClient interface {
	GetRole(ctx context.Context, uuid string) (*api.Role, error)
	FindRolesByName(ctx context.Context, name string) ([]api.Role, error)
	CreateRole(ctx context.Context, name string) (*api.Role, error)
	// AssignObjectPermission assigns the permission (app_label.codename) on the object to the role.
	AssignObjectPermission(ctx context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error
	// UnassignObjectPermission removes the permission (app_label.codename) on the object from the role.
	UnassignObjectPermission(ctx context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error
	// ListRoleObjectPermissions returns every object permission assigned to the role.
	ListRoleObjectPermissions(ctx context.Context, roleUUID string) ([]api.ExtraRoleObjectPermission, error)
	// ListObjectPermissionRoles returns the roles that hold a permission on the object or on its model.
	// The object permissions of each returned role are not narrowed to the object (docs/spec.md §3.1).
	ListObjectPermissionRoles(ctx context.Context, model api.ModelEnum, objectPK string) ([]api.RoleAssignedObjectPermission, error)
}

// LookupClient resolves the objects that an AuthentikApplication references (docs/spec.md §3.6).
type LookupClient interface {
	GetGroup(ctx context.Context, uuid string) (*api.Group, error)
	FindGroupsByName(ctx context.Context, name string) ([]api.Group, error)
	GetUser(ctx context.Context, pk int32) (*api.User, error)
	FindUsersByUsername(ctx context.Context, username string) ([]api.User, error)
	GetPolicy(ctx context.Context, uuid string) (*api.Policy, error)
	FindPoliciesByName(ctx context.Context, name string) ([]api.Policy, error)
	GetFlow(ctx context.Context, uuid string) (*api.Flow, error)
	FindFlowsBySlug(ctx context.Context, slug string) ([]api.Flow, error)
	GetCertificateKeyPair(ctx context.Context, uuid string) (*api.CertificateKeyPair, error)
	FindCertificateKeyPairsByName(ctx context.Context, name string) ([]api.CertificateKeyPair, error)
	GetScopeMapping(ctx context.Context, uuid string) (*api.ScopeMapping, error)
	FindScopeMappingsByScopeName(ctx context.Context, scopeName string) ([]api.ScopeMapping, error)
}
