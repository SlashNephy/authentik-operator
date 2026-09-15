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

package ownership_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/authentik/fake"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
)

const (
	roleName   = "authentik-operator-test"
	customRole = "custom"
)

func TestRoleName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		clusterName string
		ownerRole   string
		want        string
		wantErr     bool
	}{
		{name: "derived from the cluster name", clusterName: "prod", want: "authentik-operator-prod"},
		{name: "owner role takes precedence", clusterName: "prod", ownerRole: customRole, want: customRole},
		{name: "owner role without a cluster name", ownerRole: customRole, want: customRole},
		{name: "neither is given", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ownership.RoleName(tt.clusterName, tt.ownerRole)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// racingClient simulates another replica that creates the role between the lookup and the creation.
type racingClient struct {
	*fake.Client
}

func (c racingClient) CreateRole(ctx context.Context, name string) (*api.Role, error) {
	if _, err := c.Client.CreateRole(ctx, name); err != nil {
		return nil, err
	}
	return c.Client.CreateRole(ctx, name)
}

// failingCreateClient cannot create roles.
type failingCreateClient struct {
	*fake.Client
}

func (failingCreateClient) CreateRole(context.Context, string) (*api.Role, error) {
	return nil, &authentik.APIError{Operation: "CreateRole", StatusCode: 403}
}

func TestEnsureRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(c *fake.Client) (client authentik.RBACClient, existing string)
		wantErr bool
	}{
		{
			name: "creates the role when it does not exist",
			setup: func(c *fake.Client) (authentik.RBACClient, string) {
				return c, ""
			},
		},
		{
			name: "reuses the existing role",
			setup: func(c *fake.Client) (authentik.RBACClient, string) {
				role, err := c.CreateRole(t.Context(), roleName)
				require.NoError(t, err)
				return c, role.Pk
			},
		},
		{
			name: "uses the role created concurrently by another replica",
			setup: func(c *fake.Client) (authentik.RBACClient, string) {
				return racingClient{c}, ""
			},
		},
		{
			name: "fails when the role cannot be created",
			setup: func(c *fake.Client) (authentik.RBACClient, string) {
				return failingCreateClient{c}, ""
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			client, existing := tt.setup(c)
			marker := ownership.NewMarker(client, roleName)

			current, previous, err := marker.EnsureRole(t.Context())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, previous)

			roles, err := c.FindRolesByName(t.Context(), roleName)
			require.NoError(t, err)
			require.Len(t, roles, 1)
			assert.Equal(t, roles[0].Pk, current)
			if existing != "" {
				assert.Equal(t, existing, current)
			}
		})
	}
}

func TestEnsureRoleDetectsRecreation(t *testing.T) {
	t.Parallel()

	c := fake.New()
	marker := ownership.NewMarker(c, roleName)

	first, _, err := marker.EnsureRole(t.Context())
	require.NoError(t, err)

	current, previous, err := marker.EnsureRole(t.Context())
	require.NoError(t, err)
	assert.Equal(t, first, current, "an unchanged role keeps its UUID")
	assert.Equal(t, first, previous)

	c.DeleteRole(first)
	current, previous, err = marker.EnsureRole(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, first, current, "a recreated role has a new UUID")
	assert.Equal(t, first, previous)
}

func TestEnsureRoleFailsOnDuplicateRoles(t *testing.T) {
	t.Parallel()

	marker := ownership.NewMarker(duplicateRolesClient{fake.New()}, roleName)
	_, _, err := marker.EnsureRole(t.Context())
	require.Error(t, err)
}

// duplicateRolesClient returns two roles for every name lookup.
type duplicateRolesClient struct {
	*fake.Client
}

func (duplicateRolesClient) FindRolesByName(_ context.Context, name string) ([]api.Role, error) {
	return []api.Role{{Pk: "a", Name: name}, {Pk: "b", Name: name}}, nil
}

// authentikObjects creates one object of every marked model and returns them.
func authentikObjects(t *testing.T, c *fake.Client) []ownership.Object {
	t.Helper()
	ctx := t.Context()

	proxy, err := c.CreateProxyProvider(ctx, &api.ProxyProviderRequest{
		Name: "wiki", AuthorizationFlow: "authorization", InvalidationFlow: "invalidation",
		ExternalHost: "https://wiki.example.com", Mode: new(api.PROXYMODE_FORWARD_SINGLE),
	})
	require.NoError(t, err)
	oauth2, err := c.CreateOAuth2Provider(ctx, &api.OAuth2ProviderRequest{
		Name: "chat", AuthorizationFlow: "authorization", InvalidationFlow: "invalidation", RedirectUris: []api.RedirectURIRequest{},
	})
	require.NoError(t, err)
	app, err := c.CreateApplication(ctx, &api.ApplicationRequest{Name: "Wiki", Slug: "wiki", Provider: *api.NewNullableInt32(&proxy.Pk)})
	require.NoError(t, err)
	group := c.AddGroup("admins")
	binding, err := c.CreatePolicyBinding(ctx, &api.PolicyBindingRequest{
		Target: app.Pk, Group: *api.NewNullableString(&group.Pk), Order: 0,
	})
	require.NoError(t, err)

	return []ownership.Object{
		{Model: ownership.ModelApplication, PK: app.Pk},
		{Model: ownership.ModelProxyProvider, PK: strconv.Itoa(int(proxy.Pk))},
		{Model: ownership.ModelOAuth2Provider, PK: strconv.Itoa(int(oauth2.Pk))},
		{Model: ownership.ModelPolicyBinding, PK: binding.Pk},
	}
}

func TestMarkAssignsTheViewPermission(t *testing.T) {
	t.Parallel()

	c := fake.New()
	objects := authentikObjects(t, c)
	marker := ownership.NewMarker(c, roleName)
	for _, object := range objects {
		require.NoError(t, marker.Mark(t.Context(), object))
	}

	role, _, err := marker.EnsureRole(t.Context())
	require.NoError(t, err)
	permissions, err := c.ListRoleObjectPermissions(t.Context(), role)
	require.NoError(t, err)

	got := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		got = append(got, permission.AppLabel+"."+permission.Codename+"/"+permission.ObjectPk)
	}
	assert.ElementsMatch(t, []string{
		"authentik_core.view_application/" + objects[0].PK,
		"authentik_providers_proxy.view_proxyprovider/" + objects[1].PK,
		"authentik_providers_oauth2.view_oauth2provider/" + objects[2].PK,
		"authentik_policies.view_policybinding/" + objects[3].PK,
	}, got)
}

func TestIsManaged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup marks objects and returns the object to look up.
		setup func(t *testing.T, c *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object
		want  bool
	}{
		{
			name: "marked object",
			setup: func(t *testing.T, _ *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object {
				require.NoError(t, marker.Mark(t.Context(), objects[0]))
				return objects[0]
			},
			want: true,
		},
		{
			name: "object that was never marked",
			setup: func(_ *testing.T, _ *fake.Client, _ *ownership.Marker, objects []ownership.Object) ownership.Object {
				return objects[0]
			},
		},
		{
			name: "unmarked object while the role marks other objects",
			setup: func(t *testing.T, _ *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object {
				for _, object := range objects[1:] {
					require.NoError(t, marker.Mark(t.Context(), object))
				}
				return objects[0]
			},
		},
		{
			name: "object marked only by another role",
			setup: func(t *testing.T, c *fake.Client, _ *ownership.Marker, objects []ownership.Object) ownership.Object {
				other := ownership.NewMarker(c, "authentik-operator-other")
				require.NoError(t, other.Mark(t.Context(), objects[0]))
				return objects[0]
			},
		},
		{
			name: "marked object that another role also holds a permission on",
			setup: func(t *testing.T, c *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object {
				other := ownership.NewMarker(c, "authentik-operator-other")
				require.NoError(t, other.Mark(t.Context(), objects[1]))
				require.NoError(t, marker.Mark(t.Context(), objects[1]))
				return objects[1]
			},
			want: true,
		},
		{
			name: "same pk under a different model",
			setup: func(t *testing.T, _ *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object {
				require.NoError(t, marker.Mark(t.Context(), objects[1]))
				return ownership.Object{Model: ownership.ModelOAuth2Provider, PK: objects[1].PK}
			},
		},
		{
			name: "unmarked after Unmark",
			setup: func(t *testing.T, _ *fake.Client, marker *ownership.Marker, objects []ownership.Object) ownership.Object {
				require.NoError(t, marker.Mark(t.Context(), objects[3]))
				require.NoError(t, marker.Unmark(t.Context(), objects[3]))
				return objects[3]
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.New()
			objects := authentikObjects(t, c)
			marker := ownership.NewMarker(c, roleName)
			object := tt.setup(t, c, marker, objects)

			got, err := marker.IsManaged(t.Context(), object)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestListManaged(t *testing.T) {
	t.Parallel()

	c := fake.New()
	objects := authentikObjects(t, c)
	marker := ownership.NewMarker(c, roleName)
	other := ownership.NewMarker(c, "authentik-operator-other")

	for _, object := range objects[:3] {
		require.NoError(t, marker.Mark(t.Context(), object))
		require.NoError(t, marker.Mark(t.Context(), object), "marking twice keeps one marker")
	}
	require.NoError(t, other.Mark(t.Context(), objects[3]))
	require.NoError(t, marker.Unmark(t.Context(), objects[2]))

	set, err := marker.ListManaged(t.Context())
	require.NoError(t, err)
	assert.ElementsMatch(t, objects[:2], set.Objects())
	assert.Equal(t, 2, set.Len())
	assert.True(t, set.Contains(objects[0]))
	assert.False(t, set.Contains(objects[2]))
	assert.False(t, set.Contains(objects[3]))
}

func TestMarkerPropagatesAPIErrors(t *testing.T) {
	t.Parallel()

	marker := ownership.NewMarker(failingCreateClient{fake.New()}, roleName)
	object := ownership.Object{Model: ownership.ModelApplication, PK: "pk"}

	tests := []struct {
		name string
		call func() error
	}{
		{name: "Mark", call: func() error { return marker.Mark(t.Context(), object) }},
		{name: "Unmark", call: func() error { return marker.Unmark(t.Context(), object) }},
		{name: "IsManaged", call: func() error { _, err := marker.IsManaged(t.Context(), object); return err }},
		{name: "ListManaged", call: func() error { _, err := marker.ListManaged(t.Context()); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var apiErr *authentik.APIError
			require.True(t, errors.As(tt.call(), &apiErr))
			assert.Equal(t, 403, apiErr.StatusCode)
		})
	}
}
