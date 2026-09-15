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

package v1alpha1_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	authentikv1alpha1 "github.com/SlashNephy/authentik-operator/api/v1alpha1"
)

const (
	testNamespace    = "default"
	wikiExternalHost = "https://wiki.example.com"
)

// newProxyApplication returns a valid AuthentikApplication with a forward auth proxy provider and one group rule.
func newProxyApplication(name string) *authentikv1alpha1.AuthentikApplication {
	return &authentikv1alpha1.AuthentikApplication{
		Name:      name,
		Namespace: testNamespace,
		Spec: authentikv1alpha1.AuthentikApplicationSpec{
			Slug: name,
			Name: "Wiki",
			Provider: &authentikv1alpha1.ProviderSpec{
				Flows: authentikv1alpha1.ProviderFlows{
					Authorization: authentikv1alpha1.FlowReference{Slug: new("default-provider-authorization-implicit-consent")},
					Invalidation:  authentikv1alpha1.FlowReference{Slug: new("default-provider-invalidation-flow")},
				},
				Proxy: &authentikv1alpha1.ProxyProviderSpec{
					ForwardAuthSingle: &authentikv1alpha1.ForwardAuthSingleSpec{ExternalHost: wikiExternalHost},
				},
			},
			Access: authentikv1alpha1.AccessSpec{
				Rules: []authentikv1alpha1.AccessRule{
					{Group: &authentikv1alpha1.NamedReference{Name: new("admins")}},
				},
			},
		},
	}
}

// newOAuth2Provider returns a valid OAuth2 provider spec.
func newOAuth2Provider() *authentikv1alpha1.ProviderSpec {
	return &authentikv1alpha1.ProviderSpec{
		Flows: authentikv1alpha1.ProviderFlows{
			Authorization: authentikv1alpha1.FlowReference{Slug: new("default-provider-authorization-implicit-consent")},
			Invalidation:  authentikv1alpha1.FlowReference{Slug: new("default-provider-invalidation-flow")},
		},
		OAuth2: &authentikv1alpha1.OAuth2ProviderSpec{
			ClientType: new(authentikv1alpha1.ClientTypeConfidential),
			RedirectURIs: []authentikv1alpha1.RedirectURI{
				{URL: "https://app.example.com/oauth/callback"},
			},
			Scopes: []authentikv1alpha1.ScopeMappingReference{
				{ScopeName: new("openid")},
			},
			GrantTypes:   []authentikv1alpha1.GrantType{authentikv1alpha1.GrantTypeAuthorizationCode},
			SubjectMode:  new(authentikv1alpha1.SubjectModeHashedUserID),
			IssuerMode:   new(authentikv1alpha1.IssuerModePerProvider),
			LogoutMethod: new(authentikv1alpha1.LogoutMethodBackChannel),
			Credentials: &authentikv1alpha1.OAuth2CredentialsSpec{
				SecretRef: authentikv1alpha1.OAuth2CredentialsSecretReference{Name: "app-oidc"},
			},
		},
	}
}

// objectName turns a test case index into a unique, valid object name.
func objectName(prefix string, index int) string {
	return fmt.Sprintf("%s-%d", strings.ToLower(prefix), index)
}

func TestAuthentikApplicationCreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(app *authentikv1alpha1.AuthentikApplication)
		// wantErr is a substring of the expected validation error; empty means the object is accepted.
		wantErr string
	}{
		{
			name:   "forward auth single proxy provider with a group rule",
			mutate: func(*authentikv1alpha1.AuthentikApplication) {},
		},
		{
			name: "proxy mode",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy = &authentikv1alpha1.ProxyProviderSpec{
					Proxy: &authentikv1alpha1.ProxyModeSpec{
						ExternalHost:              wikiExternalHost,
						InternalHost:              "http://wiki.default.svc",
						InternalHostSSLValidation: new(false),
					},
					Outpost: &authentikv1alpha1.NamedReference{Name: new("authentik Embedded Outpost")},
				}
			},
		},
		{
			name: "forward auth domain mode",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy = &authentikv1alpha1.ProxyProviderSpec{
					ForwardAuthDomain: &authentikv1alpha1.ForwardAuthDomainSpec{
						AuthenticationURL: "https://auth.example.com",
						CookieDomain:      "example.com",
					},
				}
			},
		},
		{
			name: "link-only application that is public",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = nil
				app.Spec.Access = authentikv1alpha1.AccessSpec{Public: new(true)}
			},
		},
		{
			name: "oauth2 provider with clientID and a secretRef without clientIDKey",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
				app.Spec.Provider.OAuth2.Credentials.ClientID = new("my-app")
			},
		},
		{
			name: "oauth2 provider with clientIDKey and no clientID",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
				app.Spec.Provider.OAuth2.Credentials.SecretRef.ClientIDKey = new("client-id")
			},
		},
		{
			name: "rules referencing a user by pk and a policy by uuid",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access = authentikv1alpha1.AccessSpec{
					Mode: new(authentikv1alpha1.AccessModeAll),
					Rules: []authentikv1alpha1.AccessRule{
						{User: &authentikv1alpha1.UserReference{PK: new(int64(42))}, Negate: new(true)},
						{Policy: &authentikv1alpha1.NamedReference{UUID: new("3f2c6b8e-1d2a-4c5b-9e7f-0a1b2c3d4e5f")}},
					},
				}
			},
		},
		{
			name: "slug with a character outside the slug pattern",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Slug = "wiki.example"
			},
			wantErr: "spec.slug",
		},
		{
			name: "provider with both proxy and oauth2",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.OAuth2 = newOAuth2Provider().OAuth2
			},
			wantErr: "exactly one of proxy or oauth2 must be specified",
		},
		{
			name: "provider with neither proxy nor oauth2",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy = nil
			},
			wantErr: "exactly one of proxy or oauth2 must be specified",
		},
		{
			name: "proxy provider without a mode",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy = &authentikv1alpha1.ProxyProviderSpec{}
			},
			wantErr: "exactly one of proxy, forwardAuthSingle, or forwardAuthDomain must be specified",
		},
		{
			name: "proxy provider with two modes",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy.ForwardAuthDomain = &authentikv1alpha1.ForwardAuthDomainSpec{
					AuthenticationURL: "https://auth.example.com",
					CookieDomain:      "example.com",
				}
			},
			wantErr: "exactly one of proxy, forwardAuthSingle, or forwardAuthDomain must be specified",
		},
		{
			name: "flow reference with both slug and uuid",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Flows.Authorization.UUID = new("3f2c6b8e-1d2a-4c5b-9e7f-0a1b2c3d4e5f")
			},
			wantErr: "exactly one of slug or uuid must be specified",
		},
		{
			name: "flow reference with neither slug nor uuid",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Flows.Invalidation = authentikv1alpha1.FlowReference{}
			},
			wantErr: "exactly one of slug or uuid must be specified",
		},
		{
			name: "named reference with both name and uuid",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Rules[0].Group.UUID = new("3f2c6b8e-1d2a-4c5b-9e7f-0a1b2c3d4e5f")
			},
			wantErr: "exactly one of name or uuid must be specified",
		},
		{
			name: "named reference with an identifier that is not a UUID",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Rules[0].Group = &authentikv1alpha1.NamedReference{UUID: new("admins")}
			},
			wantErr: "spec.access.rules[0].group.uuid",
		},
		{
			name: "user reference with both username and pk",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Rules = []authentikv1alpha1.AccessRule{
					{User: &authentikv1alpha1.UserReference{Username: new("bob"), PK: new(int64(42))}},
				}
			},
			wantErr: "exactly one of username or pk must be specified",
		},
		{
			name: "scope mapping reference with neither scopeName nor uuid",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
				app.Spec.Provider.OAuth2.Scopes = []authentikv1alpha1.ScopeMappingReference{{}}
			},
			wantErr: "exactly one of scopeName or uuid must be specified",
		},
		{
			name: "rule with both group and user",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Rules[0].User = &authentikv1alpha1.UserReference{Username: new("bob")}
			},
			wantErr: "exactly one of group, user, or policy must be specified",
		},
		{
			name: "rule without a subject",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Rules = []authentikv1alpha1.AccessRule{{Negate: new(true)}}
			},
			wantErr: "exactly one of group, user, or policy must be specified",
		},
		{
			name: "no rules and public is false",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access = authentikv1alpha1.AccessSpec{}
			},
			wantErr: "at least one rule is required unless public is true",
		},
		{
			name: "rules and public is true",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Access.Public = new(true)
			},
			wantErr: "public must be false when rules are specified",
		},
		{
			name: "clientID together with secretRef.clientIDKey",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
				app.Spec.Provider.OAuth2.Credentials.ClientID = new("my-app")
				app.Spec.Provider.OAuth2.Credentials.SecretRef.ClientIDKey = new("client-id")
			},
			wantErr: "clientID and secretRef.clientIDKey are mutually exclusive",
		},
		{
			name: "enum value in the API spelling instead of UpperCamelCase",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
				app.Spec.Provider.OAuth2.ClientType = new(authentikv1alpha1.ClientType("confidential"))
			},
			wantErr: "spec.provider.oauth2.clientType",
		},
		{
			name: "unknown deletion policy",
			mutate: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.DeletionPolicy = new(authentikv1alpha1.DeletionPolicy("Orphan"))
			},
			wantErr: "spec.deletionPolicy",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := newProxyApplication(objectName("create", i))
			tt.mutate(app)

			err := k8sClient.Create(t.Context(), app)
			if err == nil {
				t.Cleanup(func() {
					_ = k8sClient.Delete(t.Context(), app)
				})
			}

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, apierrors.IsInvalid(err), "expected an Invalid error, got %v", err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAuthentikApplicationDefaults(t *testing.T) {
	t.Parallel()

	app := newProxyApplication("defaults")
	require.NoError(t, k8sClient.Create(t.Context(), app))
	t.Cleanup(func() {
		_ = k8sClient.Delete(t.Context(), app)
	})

	assert.Equal(t, new(authentikv1alpha1.DeletionPolicyRetain), app.Spec.DeletionPolicy)
	assert.Equal(t, new(authentikv1alpha1.AdoptionPolicyNever), app.Spec.Adopt)
	assert.Equal(t, new(authentikv1alpha1.AccessModeAny), app.Spec.Access.Mode)
	assert.Equal(t, new(false), app.Spec.Access.Public)
	assert.Equal(t, new(false), app.Spec.Access.Prune)
}

func TestAuthentikApplicationUpdateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		initial func(app *authentikv1alpha1.AuthentikApplication)
		update  func(app *authentikv1alpha1.AuthentikApplication)
		// wantErr is a substring of the expected validation error; empty means the update is accepted.
		wantErr string
	}{
		{
			name:    "change the display name",
			initial: func(*authentikv1alpha1.AuthentikApplication) {},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Name = "Team Wiki"
			},
		},
		{
			name:    "switch the proxy mode",
			initial: func(*authentikv1alpha1.AuthentikApplication) {},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider.Proxy.ForwardAuthSingle = nil
				app.Spec.Provider.Proxy.Proxy = &authentikv1alpha1.ProxyModeSpec{
					ExternalHost: wikiExternalHost,
					InternalHost: "http://wiki.default.svc",
				}
			},
		},
		{
			name: "add a provider to a link-only application",
			initial: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = nil
			},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
			},
		},
		{
			name:    "change the slug",
			initial: func(*authentikv1alpha1.AuthentikApplication) {},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Slug = "wiki-renamed"
			},
			wantErr: "slug is immutable",
		},
		{
			name:    "change the provider type",
			initial: func(*authentikv1alpha1.AuthentikApplication) {},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = newOAuth2Provider()
			},
			wantErr: "the provider type cannot be changed",
		},
		{
			name:    "remove the provider",
			initial: func(*authentikv1alpha1.AuthentikApplication) {},
			update: func(app *authentikv1alpha1.AuthentikApplication) {
				app.Spec.Provider = nil
			},
			wantErr: "provider cannot be removed once set",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := newProxyApplication(objectName("update", i))
			tt.initial(app)
			require.NoError(t, k8sClient.Create(t.Context(), app))
			t.Cleanup(func() {
				_ = k8sClient.Delete(t.Context(), app)
			})

			tt.update(app)
			err := k8sClient.Update(t.Context(), app)

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, apierrors.IsInvalid(err), "expected an Invalid error, got %v", err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
