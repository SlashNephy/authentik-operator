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

package fake_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/authentik/fake"
)

const (
	authorizationFlow = "authorization-flow-uuid"
	invalidationFlow  = "invalidation-flow-uuid"
	providerName      = "wiki"
	appName           = "Wiki"
	bindingTarget     = "target"
)

// assertStatus asserts that err is an *authentik.APIError with the status code.
func assertStatus(t *testing.T, err error, status int) {
	t.Helper()

	var apiErr *authentik.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, status, apiErr.StatusCode)
}

func proxyRequest() *api.ProxyProviderRequest {
	return &api.ProxyProviderRequest{
		Name:              providerName,
		AuthorizationFlow: authorizationFlow,
		InvalidationFlow:  invalidationFlow,
		ExternalHost:      "https://" + providerName + ".example.com",
		Mode:              new(api.PROXYMODE_FORWARD_SINGLE),
	}
}

func oauth2Request(name string) *api.OAuth2ProviderRequest {
	return &api.OAuth2ProviderRequest{
		Name:              name,
		AuthorizationFlow: authorizationFlow,
		InvalidationFlow:  invalidationFlow,
		RedirectUris:      []api.RedirectURIRequest{},
	}
}

func TestProviderNamesAreUniqueAcrossTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		create func(c *fake.Client) error
	}{
		{
			name: "proxy provider with the name of a proxy provider",
			create: func(c *fake.Client) error {
				_, err := c.CreateProxyProvider(t.Context(), proxyRequest())
				return err
			},
		},
		{
			name: "oauth2 provider with the name of a proxy provider",
			create: func(c *fake.Client) error {
				_, err := c.CreateOAuth2Provider(t.Context(), oauth2Request(providerName))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			_, err := c.CreateProxyProvider(t.Context(), proxyRequest())
			require.NoError(t, err)

			assertStatus(t, tt.create(c), http.StatusBadRequest)
		})
	}
}

func TestOAuth2ClientIDIsUnique(t *testing.T) {
	t.Parallel()

	c := fake.New()
	first := oauth2Request("first")
	first.ClientId = new("shared-client")
	_, err := c.CreateOAuth2Provider(t.Context(), first)
	require.NoError(t, err)

	second := oauth2Request("second")
	second.ClientId = new("shared-client")
	_, err = c.CreateOAuth2Provider(t.Context(), second)
	assertStatus(t, err, http.StatusBadRequest)

	second.ClientId = nil
	created, err := c.CreateOAuth2Provider(t.Context(), second)
	require.NoError(t, err)
	assert.Len(t, *created.ClientId, 40, "authentik generates a 40-character client ID")
	assert.Len(t, *created.ClientSecret, 128, "authentik generates a 128-character client secret")

	_, err = c.PatchOAuth2Provider(t.Context(), created.Pk, &api.PatchedOAuth2ProviderRequest{ClientId: new("shared-client")})
	assertStatus(t, err, http.StatusBadRequest)
}

func TestApplicationProviderIsOneToOne(t *testing.T) {
	t.Parallel()

	c := fake.New()
	provider, err := c.CreateProxyProvider(t.Context(), proxyRequest())
	require.NoError(t, err)

	_, err = c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: appName, Slug: providerName, Provider: *api.NewNullableInt32(new(provider.Pk))})
	require.NoError(t, err)

	got, err := c.GetProxyProvider(t.Context(), provider.Pk)
	require.NoError(t, err)
	assert.Equal(t, providerName, *got.AssignedApplicationSlug.Get())

	_, err = c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: "Other", Slug: "other", Provider: *api.NewNullableInt32(new(provider.Pk))})
	assertStatus(t, err, http.StatusBadRequest)
}

func TestPatchProxyProviderRequiresMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    *api.PatchedProxyProviderRequest
		wantStatus int
	}{
		{
			name:       "without mode",
			request:    &api.PatchedProxyProviderRequest{InterceptHeaderAuth: new(false)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "proxy mode without internal host",
			request:    &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_PROXY)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:    "forward auth mode",
			request: &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_FORWARD_SINGLE), InterceptHeaderAuth: new(false)},
		},
		{
			name:    "proxy mode with internal host",
			request: &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_PROXY), InternalHost: new("http://wiki.default.svc")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			provider, err := c.CreateProxyProvider(t.Context(), proxyRequest())
			require.NoError(t, err)

			_, err = c.PatchProxyProvider(t.Context(), provider.Pk, tt.request)
			if tt.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			assertStatus(t, err, tt.wantStatus)
		})
	}
}

func TestPolicyBindingSubjectAndTarget(t *testing.T) {
	t.Parallel()

	group := *api.NewNullableString(new("group-uuid"))
	user := *api.NewNullableInt32(new(int32(42)))
	null := *api.NewNullableString(nil)

	tests := []struct {
		name       string
		patch      func(target string) *api.PatchedPolicyBindingRequest
		wantStatus int
		wantGroup  api.NullableString
		wantUser   api.NullableInt32
	}{
		{
			name: "patch without target",
			patch: func(string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Negate: new(true)}
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "patch with target but without the subject",
			patch: func(target string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Target: new(target), Negate: new(true)}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "patch with two subjects",
			patch: func(target string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Target: new(target), Group: group, User: user}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "patch with target and subject",
			patch: func(target string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Target: new(target), Group: group, Negate: new(true)}
			},
			wantGroup: group,
		},
		{
			// Confirmed against authentik 2026.8.2: the omitted group is kept next to the new user.
			name: "patch with another subject keeps the omitted one",
			patch: func(target string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Target: new(target), User: user, Negate: new(true)}
			},
			wantGroup: group,
			wantUser:  user,
		},
		{
			name: "patch with another subject and explicit nulls replaces the subject",
			patch: func(target string) *api.PatchedPolicyBindingRequest {
				return &api.PatchedPolicyBindingRequest{Target: new(target), Group: null, User: user, Negate: new(true)}
			},
			wantGroup: null,
			wantUser:  user,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			binding, err := c.CreatePolicyBinding(t.Context(), &api.PolicyBindingRequest{Target: "app-pbm-uuid", Group: group, Order: 10})
			require.NoError(t, err)

			patched, err := c.PatchPolicyBinding(t.Context(), binding.Pk, tt.patch(binding.Target))
			if tt.wantStatus != 0 {
				assertStatus(t, err, tt.wantStatus)
				return
			}
			require.NoError(t, err)
			assert.True(t, *patched.Negate)
			assert.Equal(t, tt.wantGroup.Get(), patched.Group.Get())
			assert.Equal(t, tt.wantUser.Get(), patched.User.Get())
		})
	}
}

func TestCreatePolicyBindingValidation(t *testing.T) {
	t.Parallel()

	policy := *api.NewNullableString(new("policy-uuid"))
	group := *api.NewNullableString(new("group-uuid"))

	tests := []struct {
		name       string
		existing   *api.PolicyBindingRequest
		request    *api.PolicyBindingRequest
		wantStatus int
	}{
		{
			name:       "no subject",
			request:    &api.PolicyBindingRequest{Target: bindingTarget, Order: 10},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "policy reusing the order on the same target",
			existing:   &api.PolicyBindingRequest{Target: bindingTarget, Policy: policy, Order: 10},
			request:    &api.PolicyBindingRequest{Target: bindingTarget, Policy: policy, Order: 10},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "group reusing the order on the same target",
			existing: &api.PolicyBindingRequest{Target: bindingTarget, Group: group, Order: 10},
			request:  &api.PolicyBindingRequest{Target: bindingTarget, Group: group, Order: 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			if tt.existing != nil {
				_, err := c.CreatePolicyBinding(t.Context(), tt.existing)
				require.NoError(t, err)
			}

			_, err := c.CreatePolicyBinding(t.Context(), tt.request)
			if tt.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			assertStatus(t, err, tt.wantStatus)
		})
	}
}

func TestObjectPermissions(t *testing.T) {
	t.Parallel()

	c := fake.New()
	role, err := c.CreateRole(t.Context(), "authentik-operator-test")
	require.NoError(t, err)
	provider, err := c.CreateProxyProvider(t.Context(), proxyRequest())
	require.NoError(t, err)
	app, err := c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: appName, Slug: providerName})
	require.NoError(t, err)
	unmarked, err := c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: "Unmarked", Slug: "unmarked"})
	require.NoError(t, err)

	require.NoError(t, c.AssignObjectPermission(t.Context(), role.Pk, api.MODELENUM_AUTHENTIK_CORE_APPLICATION, app.Pk, "authentik_core.view_application"))
	require.NoError(t, c.AssignObjectPermission(t.Context(), role.Pk, api.MODELENUM_AUTHENTIK_PROVIDERS_PROXY_PROXYPROVIDER, fmt.Sprint(provider.Pk), "authentik_providers_proxy.view_proxyprovider"))

	t.Run("owner lookup returns every object permission of the role", func(t *testing.T) {
		owners, err := c.ListObjectPermissionRoles(t.Context(), api.MODELENUM_AUTHENTIK_CORE_APPLICATION, app.Pk)
		require.NoError(t, err)
		require.Len(t, owners, 1)
		assert.Equal(t, role.Pk, owners[0].RolePk)
		assert.Len(t, owners[0].ObjectPermissions, 2)
	})

	t.Run("owner lookup of an unmarked object is empty", func(t *testing.T) {
		owners, err := c.ListObjectPermissionRoles(t.Context(), api.MODELENUM_AUTHENTIK_CORE_APPLICATION, unmarked.Pk)
		require.NoError(t, err)
		assert.Empty(t, owners)
	})

	t.Run("assigning a permission on a missing object is rejected", func(t *testing.T) {
		err := c.AssignObjectPermission(t.Context(), role.Pk, api.MODELENUM_AUTHENTIK_POLICIES_POLICYBINDING, "missing-binding", "authentik_policies.view_policybinding")
		assertStatus(t, err, http.StatusBadRequest)
	})
}

func TestObjectPermissionsOutliveTheObject(t *testing.T) {
	t.Parallel()

	c := fake.New()
	role, err := c.CreateRole(t.Context(), "authentik-operator-test")
	require.NoError(t, err)
	app, err := c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: appName, Slug: providerName})
	require.NoError(t, err)
	require.NoError(t, c.AssignObjectPermission(t.Context(), role.Pk, api.MODELENUM_AUTHENTIK_CORE_APPLICATION, app.Pk, "authentik_core.view_application"))

	require.NoError(t, c.DeleteApplication(t.Context(), providerName))

	permissions, err := c.ListRoleObjectPermissions(t.Context(), role.Pk)
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	assert.Equal(t, app.Pk, permissions[0].ObjectPk)

	c.DeleteRole(role.Pk)
	permissions, err = c.ListRoleObjectPermissions(t.Context(), role.Pk)
	require.NoError(t, err)
	assert.Empty(t, permissions)
}

func TestDeletingProviderDetachesIt(t *testing.T) {
	t.Parallel()

	c := fake.New()
	provider, err := c.CreateProxyProvider(t.Context(), proxyRequest())
	require.NoError(t, err)
	_, err = c.CreateApplication(t.Context(), &api.ApplicationRequest{Name: appName, Slug: providerName, Provider: *api.NewNullableInt32(new(provider.Pk))})
	require.NoError(t, err)
	outpost := c.AddOutpost("authentik Embedded Outpost")
	_, err = c.SetOutpostProviders(t.Context(), outpost.Pk, []int32{provider.Pk})
	require.NoError(t, err)

	require.NoError(t, c.DeleteProxyProvider(t.Context(), provider.Pk))

	app, err := c.GetApplication(t.Context(), providerName)
	require.NoError(t, err)
	assert.Nil(t, app.Provider.Get())
	gotOutpost, err := c.GetOutpost(t.Context(), outpost.Pk)
	require.NoError(t, err)
	assert.Empty(t, gotOutpost.Providers)
}

func TestMissingObjectsAreNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		get  func(c *fake.Client) error
	}{
		{name: "application", get: func(c *fake.Client) error { _, err := c.GetApplication(t.Context(), "missing"); return err }},
		{name: "proxy provider", get: func(c *fake.Client) error { _, err := c.GetProxyProvider(t.Context(), 1); return err }},
		{name: "oauth2 provider", get: func(c *fake.Client) error { _, err := c.GetOAuth2Provider(t.Context(), 1); return err }},
		{name: "policy binding", get: func(c *fake.Client) error { _, err := c.GetPolicyBinding(t.Context(), "missing"); return err }},
		{name: "role", get: func(c *fake.Client) error { _, err := c.GetRole(t.Context(), "missing"); return err }},
		{name: "delete application", get: func(c *fake.Client) error { return c.DeleteApplication(t.Context(), "missing") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.get(fake.New())
			assert.True(t, errors.Is(err, authentik.ErrNotFound), "expected ErrNotFound, got %v", err)
		})
	}
}
