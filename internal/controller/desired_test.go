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

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

func testFlows() *reference.Flows {
	return &reference.Flows{Authorization: "authorization-uuid", Invalidation: "invalidation-uuid"}
}

func TestDesiredApplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		spec       v1alpha1.AuthentikApplicationSpec
		providerPK *int32
		want       *api.PatchedApplicationRequest
	}{
		{
			name: "only required fields",
			spec: v1alpha1.AuthentikApplicationSpec{Slug: "wiki", Name: testName},
			want: &api.PatchedApplicationRequest{Name: new(testName)},
		},
		{
			name: "every field including false and empty values",
			spec: v1alpha1.AuthentikApplicationSpec{
				Slug: "wiki", Name: testName,
				LaunchURL: new("https://wiki.example.com"), Icon: new("fa://fa-book"), Description: new(""),
				Publisher: new("Example"), Group: new("Docs"), OpenInNewTab: new(false), HideFromApplicationDashboard: new(true),
				Access: v1alpha1.AccessSpec{Mode: new(v1alpha1.AccessModeAll)},
			},
			providerPK: new(int32(7)),
			want: &api.PatchedApplicationRequest{
				Name: new(testName), Provider: *api.NewNullableInt32(new(int32(7))),
				MetaLaunchUrl: new("https://wiki.example.com"), MetaIcon: new("fa://fa-book"), MetaDescription: new(""),
				MetaPublisher: new("Example"), Group: new("Docs"), OpenInNewTab: new(false), MetaHide: new(true),
				PolicyEngineMode: new(api.POLICYENGINEMODE_ALL),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, desiredApplication(&tt.spec, tt.providerPK))
		})
	}
}

func TestDesiredProxyProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy v1alpha1.ProxyProviderSpec
		refs  reference.ProxyReferences
		want  *api.PatchedProxyProviderRequest
	}{
		{
			name: "proxy mode",
			proxy: v1alpha1.ProxyProviderSpec{
				Proxy: &v1alpha1.ProxyModeSpec{ExternalHost: "https://wiki.example.com", InternalHost: "http://wiki", InternalHostSSLValidation: new(false)},
			},
			want: &api.PatchedProxyProviderRequest{
				AuthorizationFlow: new("authorization-uuid"), InvalidationFlow: new("invalidation-uuid"),
				Mode: new(api.PROXYMODE_PROXY), ExternalHost: new("https://wiki.example.com"), InternalHost: new("http://wiki"),
				InternalHostSslValidation: new(false),
			},
		},
		{
			name: "forward auth for a single application with every optional field",
			proxy: v1alpha1.ProxyProviderSpec{
				ForwardAuthSingle:    &v1alpha1.ForwardAuthSingleSpec{ExternalHost: "https://wiki.example.com"},
				UnauthenticatedPaths: []string{"^/api/health$", "^/static/"},
				BasicAuth:            &v1alpha1.BasicAuthSpec{UserAttribute: "user", PasswordAttribute: "password"},
				InterceptHeaderAuth:  new(true),
				AccessTokenValidity:  new("hours=24"),
				RefreshTokenValidity: new("days=30"),
			},
			refs: reference.ProxyReferences{Certificate: new("certificate-uuid"), Outpost: "outpost-uuid"},
			want: &api.PatchedProxyProviderRequest{
				AuthorizationFlow: new("authorization-uuid"), InvalidationFlow: new("invalidation-uuid"),
				Mode: new(api.PROXYMODE_FORWARD_SINGLE), ExternalHost: new("https://wiki.example.com"),
				SkipPathRegex:    new("^/api/health$\n^/static/"),
				BasicAuthEnabled: new(true), BasicAuthUserAttribute: new("user"), BasicAuthPasswordAttribute: new("password"),
				InterceptHeaderAuth: new(true), AccessTokenValidity: new("hours=24"), RefreshTokenValidity: new("days=30"),
				Certificate: *api.NewNullableString(new("certificate-uuid")),
			},
		},
		{
			name: "forward auth for a domain",
			proxy: v1alpha1.ProxyProviderSpec{
				ForwardAuthDomain: &v1alpha1.ForwardAuthDomainSpec{AuthenticationURL: "https://auth.example.com", CookieDomain: "example.com"},
			},
			want: &api.PatchedProxyProviderRequest{
				AuthorizationFlow: new("authorization-uuid"), InvalidationFlow: new("invalidation-uuid"),
				Mode: new(api.PROXYMODE_FORWARD_DOMAIN), ExternalHost: new("https://auth.example.com"), CookieDomain: new("example.com"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider := &v1alpha1.ProviderSpec{Proxy: &tt.proxy}
			assert.Equal(t, tt.want, desiredProxyProvider(provider, testFlows(), &tt.refs))
		})
	}
}

func TestDesiredOAuth2Provider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider v1alpha1.ProviderSpec
		flows    reference.Flows
		refs     reference.OAuth2References
		want     *api.PatchedOAuth2ProviderRequest
	}{
		{
			name:     "only required fields",
			provider: v1alpha1.ProviderSpec{OAuth2: &v1alpha1.OAuth2ProviderSpec{}},
			flows:    *testFlows(),
			want: &api.PatchedOAuth2ProviderRequest{
				AuthorizationFlow: new("authorization-uuid"), InvalidationFlow: new("invalidation-uuid"),
			},
		},
		{
			name: "every field",
			provider: v1alpha1.ProviderSpec{
				Name: new(oauth2Slug),
				OAuth2: &v1alpha1.OAuth2ProviderSpec{
					ClientType: new(v1alpha1.ClientTypePublic),
					RedirectURIs: []v1alpha1.RedirectURI{
						{URL: "https://chat.example.com/callback"},
						{URL: "https://chat.example.com/.*", MatchingMode: new(v1alpha1.MatchingModeRegex), Type: new(v1alpha1.RedirectURITypePostLogout)},
					},
					GrantTypes:             []v1alpha1.GrantType{v1alpha1.GrantTypeAuthorizationCode, v1alpha1.GrantTypeDeviceCode},
					SubjectMode:            new(v1alpha1.SubjectModeUserEmail),
					IssuerMode:             new(v1alpha1.IssuerModeGlobal),
					IncludeClaimsInIDToken: new(false),
					AccessCodeValidity:     new("minutes=1"),
					AccessTokenValidity:    new("minutes=5"),
					RefreshTokenValidity:   new("days=30"),
					RefreshTokenThreshold:  new("seconds=0"),
					LogoutURI:              new("https://chat.example.com/logout"),
					LogoutMethod:           new(v1alpha1.LogoutMethodFrontChannel),
				},
			},
			flows: reference.Flows{Authorization: "authorization-uuid", Invalidation: "invalidation-uuid", Authentication: new("authentication-uuid")},
			refs: reference.OAuth2References{
				Scopes: []string{"openid-uuid"}, SigningKey: new("signing-uuid"), EncryptionKey: new("encryption-uuid"),
			},
			want: &api.PatchedOAuth2ProviderRequest{
				Name:               new(oauth2Slug),
				AuthorizationFlow:  new("authorization-uuid"),
				InvalidationFlow:   new("invalidation-uuid"),
				AuthenticationFlow: *api.NewNullableString(new("authentication-uuid")),
				PropertyMappings:   []string{"openid-uuid"},
				ClientType:         new(api.CLIENTTYPEENUM_PUBLIC),
				RedirectUris: []api.RedirectURIRequest{
					{Url: "https://chat.example.com/callback", MatchingMode: api.MATCHINGMODEENUM_STRICT, RedirectUriType: new(api.REDIRECTURITYPEENUM_AUTHORIZATION)},
					{Url: "https://chat.example.com/.*", MatchingMode: api.MATCHINGMODEENUM_REGEX, RedirectUriType: new(api.REDIRECTURITYPEENUM_LOGOUT)},
				},
				GrantTypes:             []api.GrantTypeEnum{api.GRANTTYPEENUM_AUTHORIZATION_CODE, api.GRANTTYPEENUM_URN_IETF_PARAMS_OAUTH_GRANT_TYPE_DEVICE_CODE},
				SubMode:                new(api.SUBMODEENUM_USER_EMAIL),
				IssuerMode:             new(api.ISSUERMODEENUM_GLOBAL),
				IncludeClaimsInIdToken: new(false),
				AccessCodeValidity:     new("minutes=1"),
				AccessTokenValidity:    new("minutes=5"),
				RefreshTokenValidity:   new("days=30"),
				RefreshTokenThreshold:  new("seconds=0"),
				SigningKey:             *api.NewNullableString(new("signing-uuid")),
				EncryptionKey:          *api.NewNullableString(new("encryption-uuid")),
				LogoutUri:              new("https://chat.example.com/logout"),
				LogoutMethod:           new(api.OAUTH2PROVIDERLOGOUTMETHODENUM_FRONTCHANNEL),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, desiredOAuth2Provider(&tt.provider, &tt.flows, &tt.refs))
		})
	}
}

func TestCreateOAuth2ProviderRequest(t *testing.T) {
	t.Parallel()

	defaults := &reference.CreationDefaults{Scopes: defaultScopes, SigningKey: new("self-signed")}
	tests := []struct {
		name    string
		desired *api.PatchedOAuth2ProviderRequest
		want    *api.OAuth2ProviderRequest
	}{
		{
			name:    "omitted fields receive the creation defaults",
			desired: &api.PatchedOAuth2ProviderRequest{AuthorizationFlow: new("a"), InvalidationFlow: new("i")},
			want: &api.OAuth2ProviderRequest{
				Name: oauth2Slug, AuthorizationFlow: "a", InvalidationFlow: "i",
				PropertyMappings: defaultScopes,
				SigningKey:       *api.NewNullableString(new("self-signed")),
				RedirectUris:     []api.RedirectURIRequest{},
			},
		},
		{
			name: "specified fields take precedence over the defaults",
			desired: &api.PatchedOAuth2ProviderRequest{
				AuthorizationFlow: new("a"), InvalidationFlow: new("i"),
				PropertyMappings: []string{}, SigningKey: *api.NewNullableString(new("custom")),
				RedirectUris: []api.RedirectURIRequest{{Url: "https://chat.example.com", MatchingMode: api.MATCHINGMODEENUM_STRICT}},
			},
			want: &api.OAuth2ProviderRequest{
				Name: oauth2Slug, AuthorizationFlow: "a", InvalidationFlow: "i",
				PropertyMappings: []string{},
				SigningKey:       *api.NewNullableString(new("custom")),
				RedirectUris:     []api.RedirectURIRequest{{Url: "https://chat.example.com", MatchingMode: api.MATCHINGMODEENUM_STRICT}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, createOAuth2ProviderRequest(oauth2Slug, tt.desired, defaults))
		})
	}
}
