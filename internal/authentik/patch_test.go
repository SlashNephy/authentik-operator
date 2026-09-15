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

package authentik_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

const mappingA = "mapping-a"

func nullableString(v *string) api.NullableString { return *api.NewNullableString(v) }

func nullableInt32(v *int32) api.NullableInt32 { return *api.NewNullableInt32(v) }

func TestDiffApplication(t *testing.T) {
	t.Parallel()

	observed := &api.Application{
		Name:          "Wiki",
		Slug:          "wiki",
		Provider:      nullableInt32(new(int32(3))),
		OpenInNewTab:  new(true),
		MetaIcon:      new("fa://fa-book"),
		MetaPublisher: new("Team A"),
	}

	tests := []struct {
		name    string
		desired *api.PatchedApplicationRequest
		want    *api.PatchedApplicationRequest
	}{
		{
			name:    "no managed field differs",
			desired: &api.PatchedApplicationRequest{Name: new("Wiki"), Provider: nullableInt32(new(int32(3))), OpenInNewTab: new(true)},
		},
		{
			name:    "unmanaged fields are not compared",
			desired: &api.PatchedApplicationRequest{Name: new("Wiki")},
		},
		{
			name:    "only the differing fields are sent",
			desired: &api.PatchedApplicationRequest{Name: new("Wiki"), MetaPublisher: new("Team B")},
			want:    &api.PatchedApplicationRequest{MetaPublisher: new("Team B")},
		},
		{
			name:    "false is sent when the observed value is true",
			desired: &api.PatchedApplicationRequest{OpenInNewTab: new(false)},
			want:    &api.PatchedApplicationRequest{OpenInNewTab: new(false)},
		},
		{
			name:    "a value missing on the server differs",
			desired: &api.PatchedApplicationRequest{MetaDescription: new("")},
			want:    &api.PatchedApplicationRequest{MetaDescription: new("")},
		},
		{
			name:    "a managed null provider detaches the provider",
			desired: &api.PatchedApplicationRequest{Provider: nullableInt32(nil)},
			want:    &api.PatchedApplicationRequest{Provider: nullableInt32(nil)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := authentik.DiffApplication(tt.desired, observed)
			assert.Equal(t, tt.want != nil, changed)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDiffProxyProvider(t *testing.T) {
	t.Parallel()

	observed := &api.ProxyProvider{
		Name:                "wiki",
		ExternalHost:        "https://wiki.example.com",
		Mode:                new(api.PROXYMODE_FORWARD_SINGLE),
		InterceptHeaderAuth: new(true),
		PropertyMappings:    []string{mappingA, "mapping-b"},
	}

	tests := []struct {
		name    string
		desired *api.PatchedProxyProviderRequest
		want    *api.PatchedProxyProviderRequest
	}{
		{
			name:    "no managed field differs, including mode",
			desired: &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_FORWARD_SINGLE), ExternalHost: new("https://wiki.example.com")},
		},
		{
			name:    "mode from the observed object is added to a change of another field",
			desired: &api.PatchedProxyProviderRequest{InterceptHeaderAuth: new(false)},
			want:    &api.PatchedProxyProviderRequest{InterceptHeaderAuth: new(false), Mode: new(api.PROXYMODE_FORWARD_SINGLE)},
		},
		{
			name:    "desired mode is sent when it changes",
			desired: &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_PROXY), InternalHost: new("http://wiki.default.svc")},
			want:    &api.PatchedProxyProviderRequest{Mode: new(api.PROXYMODE_PROXY), InternalHost: new("http://wiki.default.svc")},
		},
		{
			name:    "property mappings in another order are the same set",
			desired: &api.PatchedProxyProviderRequest{PropertyMappings: []string{"mapping-b", mappingA, mappingA}},
		},
		{
			name:    "a different set of property mappings is sent in full",
			desired: &api.PatchedProxyProviderRequest{PropertyMappings: []string{mappingA}},
			want:    &api.PatchedProxyProviderRequest{PropertyMappings: []string{mappingA}, Mode: new(api.PROXYMODE_FORWARD_SINGLE)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := authentik.DiffProxyProvider(tt.desired, observed)
			assert.Equal(t, tt.want != nil, changed)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDiffOAuth2Provider(t *testing.T) {
	t.Parallel()

	callback := "https://app.example.com/oauth/callback"
	logout := "https://app.example.com/logout"
	observed := &api.OAuth2Provider{
		Name:         "app",
		ClientSecret: new("secret-a"),
		SigningKey:   nullableString(new("key-uuid")),
		GrantTypes:   []api.GrantTypeEnum{api.GRANTTYPEENUM_AUTHORIZATION_CODE, api.GRANTTYPEENUM_REFRESH_TOKEN},
		RedirectUris: []api.RedirectURI{
			{Url: logout, MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_LOGOUT)},
			{Url: callback, MatchingMode: api.MATCHINGMODEENUM_STRICT},
		},
	}

	tests := []struct {
		name    string
		desired *api.PatchedOAuth2ProviderRequest
		want    *api.PatchedOAuth2ProviderRequest
	}{
		{
			name: "redirect URIs in another order with the default type spelled out are the same set",
			desired: &api.PatchedOAuth2ProviderRequest{RedirectUris: []api.RedirectURIRequest{
				{Url: callback, MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_AUTHORIZATION)},
				{Url: logout, MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_LOGOUT)},
			}},
		},
		{
			name: "a redirect URI with a different matching mode is sent in full",
			desired: &api.PatchedOAuth2ProviderRequest{RedirectUris: []api.RedirectURIRequest{
				{Url: callback, MatchingMode: api.MATCHINGMODEENUM_REGEX},
				{Url: logout, MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_LOGOUT)},
			}},
			want: &api.PatchedOAuth2ProviderRequest{RedirectUris: []api.RedirectURIRequest{
				{Url: callback, MatchingMode: api.MATCHINGMODEENUM_REGEX},
				{Url: logout, MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_LOGOUT)},
			}},
		},
		{
			name:    "grant types in another order are the same set",
			desired: &api.PatchedOAuth2ProviderRequest{GrantTypes: []api.GrantTypeEnum{api.GRANTTYPEENUM_REFRESH_TOKEN, api.GRANTTYPEENUM_AUTHORIZATION_CODE}},
		},
		{
			name:    "an empty managed list clears the grant types",
			desired: &api.PatchedOAuth2ProviderRequest{GrantTypes: []api.GrantTypeEnum{}},
			want:    &api.PatchedOAuth2ProviderRequest{GrantTypes: []api.GrantTypeEnum{}},
		},
		{
			name:    "a managed null signing key is sent",
			desired: &api.PatchedOAuth2ProviderRequest{SigningKey: nullableString(nil)},
			want:    &api.PatchedOAuth2ProviderRequest{SigningKey: nullableString(nil)},
		},
		{
			name:    "the same signing key is not sent",
			desired: &api.PatchedOAuth2ProviderRequest{SigningKey: nullableString(new("key-uuid"))},
		},
		{
			name:    "a rotated client secret is sent",
			desired: &api.PatchedOAuth2ProviderRequest{ClientSecret: new("secret-b")},
			want:    &api.PatchedOAuth2ProviderRequest{ClientSecret: new("secret-b")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := authentik.DiffOAuth2Provider(tt.desired, observed)
			assert.Equal(t, tt.want != nil, changed)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDiffPolicyBinding(t *testing.T) {
	t.Parallel()

	observed := &api.PolicyBinding{
		Target: "app-pbm-uuid",
		Group:  nullableString(new("group-uuid")),
		Policy: nullableString(nil),
		User:   nullableInt32(nil),
		Negate: new(false),
		Order:  10,
	}

	tests := []struct {
		name    string
		desired *api.PatchedPolicyBindingRequest
		want    *api.PatchedPolicyBindingRequest
	}{
		{
			name: "no managed field differs",
			desired: &api.PatchedPolicyBindingRequest{
				Target: new("app-pbm-uuid"), Group: nullableString(new("group-uuid")), Negate: new(false),
			},
		},
		{
			name:    "target and the subject from the observed object are added to a change",
			desired: &api.PatchedPolicyBindingRequest{Negate: new(true)},
			want: &api.PatchedPolicyBindingRequest{
				Target: new("app-pbm-uuid"),
				Group:  nullableString(new("group-uuid")),
				Policy: nullableString(nil),
				User:   nullableInt32(nil),
				Negate: new(true),
			},
		},
		{
			name:    "a new subject replaces the observed one",
			desired: &api.PatchedPolicyBindingRequest{User: nullableInt32(new(int32(42)))},
			want: &api.PatchedPolicyBindingRequest{
				Target: new("app-pbm-uuid"),
				Policy: nullableString(nil),
				Group:  nullableString(nil),
				User:   nullableInt32(new(int32(42))),
			},
		},
		{
			name:    "an order change is sent",
			desired: &api.PatchedPolicyBindingRequest{Order: new(int32(20))},
			want: &api.PatchedPolicyBindingRequest{
				Target: new("app-pbm-uuid"),
				Group:  nullableString(new("group-uuid")),
				Policy: nullableString(nil),
				User:   nullableInt32(nil),
				Order:  new(int32(20)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := authentik.DiffPolicyBinding(tt.desired, observed)
			assert.Equal(t, tt.want != nil, changed)
			assert.Equal(t, tt.want, got)
		})
	}
}
