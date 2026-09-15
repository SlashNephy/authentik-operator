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

package reference_test

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kubefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/authentik/fake"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

const (
	namespace         = "apps"
	secretName        = "wiki-oidc"
	authorizationSlug = "default-provider-authorization-implicit-consent"
	invalidationSlug  = "default-provider-invalidation-flow"
	slug              = "wiki"
	externalHost      = "https://wiki.example.com"
	clientSecret      = "s3cr3t"
	scopesPath        = "provider.oauth2.scopes"
)

// objects are the authentik objects stored in the fake by newAuthentik.
type objects struct {
	authorization *api.Flow
	invalidation  *api.Flow
	embedded      *api.Outpost
	certificate   *api.CertificateKeyPair
	openid        *api.ScopeMapping
	profile       *api.ScopeMapping
	customProfile *api.ScopeMapping
	email         *api.ScopeMapping
	admins        *api.Group
	bob           *api.User
	office        *api.Policy
}

func newAuthentik() (*fake.Client, *objects) {
	c := fake.New()
	return c, &objects{
		authorization: c.AddFlow(authorizationSlug),
		invalidation:  c.AddFlow(invalidationSlug),
		embedded:      c.AddOutpost(reference.EmbeddedOutpostName),
		certificate:   c.AddCertificateKeyPair(reference.DefaultSigningKeyName),
		openid:        c.AddManagedScopeMapping("OpenID 'openid'", "openid", "goauthentik.io/providers/oauth2/scope-openid"),
		email:         c.AddManagedScopeMapping("OpenID 'email'", "email", "goauthentik.io/providers/oauth2/scope-email"),
		profile:       c.AddManagedScopeMapping("OpenID 'profile'", "profile", "goauthentik.io/providers/oauth2/scope-profile"),
		customProfile: c.AddScopeMapping("custom profile", "profile"),
		admins:        c.AddGroup("admins"),
		bob:           c.AddUser("bob"),
		office:        c.AddPolicy("allow-from-office"),
	}
}

func flows() v1alpha1.ProviderFlows {
	return v1alpha1.ProviderFlows{
		Authorization: v1alpha1.FlowReference{Slug: new(authorizationSlug)},
		Invalidation:  v1alpha1.FlowReference{Slug: new(invalidationSlug)},
	}
}

func application(provider *v1alpha1.ProviderSpec, rules ...v1alpha1.AccessRule) *v1alpha1.AuthentikApplication {
	return &v1alpha1.AuthentikApplication{
		Namespace: namespace, Name: slug,
		Spec: v1alpha1.AuthentikApplicationSpec{
			Slug:     slug,
			Name:     "Wiki",
			Provider: provider,
			Access:   v1alpha1.AccessSpec{Rules: rules},
		},
	}
}

func oauth2Provider(oauth2 *v1alpha1.OAuth2ProviderSpec) *v1alpha1.ProviderSpec {
	return &v1alpha1.ProviderSpec{Flows: flows(), OAuth2: oauth2}
}

func proxyProvider(proxy *v1alpha1.ProxyProviderSpec) *v1alpha1.ProviderSpec {
	return &v1alpha1.ProviderSpec{Flows: flows(), Proxy: proxy}
}

func credentialsSpec() *v1alpha1.OAuth2CredentialsSpec {
	return &v1alpha1.OAuth2CredentialsSpec{SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: secretName}}
}

func secret(data map[string]string) *corev1.Secret {
	s := &corev1.Secret{Namespace: namespace, Name: secretName, Data: map[string][]byte{}}
	for key, value := range data {
		s.Data[key] = []byte(value)
	}
	return s
}

func newKube(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return kubefake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestResolve(t *testing.T) {
	t.Parallel()

	ak, o := newAuthentik()

	tests := []struct {
		name    string
		app     *v1alpha1.AuthentikApplication
		secrets []client.Object
		want    *reference.Resolved
	}{
		{
			name: "link-only application without rules",
			app:  application(nil),
			want: &reference.Resolved{Rules: []reference.Rule{}},
		},
		{
			name: "proxy provider joins the embedded outpost when outpost is omitted",
			app: application(
				proxyProvider(&v1alpha1.ProxyProviderSpec{ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: externalHost}}),
				v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("admins")}},
			),
			want: &reference.Resolved{
				Flows: &reference.Flows{Authorization: o.authorization.Pk, Invalidation: o.invalidation.Pk},
				Proxy: &reference.ProxyReferences{Outpost: o.embedded.Pk},
				Rules: []reference.Rule{{Group: &o.admins.Pk}},
			},
		},
		{
			name: "references by identifier",
			app: application(
				&v1alpha1.ProviderSpec{
					Flows: v1alpha1.ProviderFlows{
						Authorization:  v1alpha1.FlowReference{UUID: &o.authorization.Pk},
						Invalidation:   v1alpha1.FlowReference{UUID: &o.invalidation.Pk},
						Authentication: &v1alpha1.FlowReference{UUID: &o.authorization.Pk},
					},
					Proxy: &v1alpha1.ProxyProviderSpec{
						ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: externalHost},
						Certificate:       &v1alpha1.NamedReference{UUID: &o.certificate.Pk},
						Outpost:           &v1alpha1.NamedReference{UUID: &o.embedded.Pk},
					},
				},
				v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{UUID: &o.admins.Pk}},
				v1alpha1.AccessRule{User: &v1alpha1.UserReference{PK: new(int64(o.bob.Pk))}, Negate: new(true)},
				v1alpha1.AccessRule{Policy: &v1alpha1.NamedReference{UUID: &o.office.Pk}},
			),
			want: &reference.Resolved{
				Flows: &reference.Flows{Authorization: o.authorization.Pk, Invalidation: o.invalidation.Pk, Authentication: &o.authorization.Pk},
				Proxy: &reference.ProxyReferences{Certificate: &o.certificate.Pk, Outpost: o.embedded.Pk},
				Rules: []reference.Rule{{Group: &o.admins.Pk}, {User: &o.bob.Pk, Negate: true}, {Policy: &o.office.Pk}},
			},
		},
		{
			name: "oauth2 references by name-like keys and an absent credentials Secret",
			app: application(
				oauth2Provider(&v1alpha1.OAuth2ProviderSpec{
					Scopes:        []v1alpha1.ScopeMappingReference{{ScopeName: new("openid")}, {UUID: &o.customProfile.Pk}},
					SigningKey:    &v1alpha1.NamedReference{Name: new(reference.DefaultSigningKeyName)},
					EncryptionKey: &v1alpha1.NamedReference{Name: new(reference.DefaultSigningKeyName)},
					Credentials:   &v1alpha1.OAuth2CredentialsSpec{ClientID: new(slug), SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: secretName}},
				}),
				v1alpha1.AccessRule{User: &v1alpha1.UserReference{Username: new("bob")}},
				v1alpha1.AccessRule{Policy: &v1alpha1.NamedReference{Name: new("allow-from-office")}},
			),
			want: &reference.Resolved{
				Flows: &reference.Flows{Authorization: o.authorization.Pk, Invalidation: o.invalidation.Pk},
				OAuth2: &reference.OAuth2References{
					Scopes:        []string{o.openid.Pk, o.customProfile.Pk},
					SigningKey:    &o.certificate.Pk,
					EncryptionKey: &o.certificate.Pk,
					Credentials:   &reference.Credentials{ClientID: slug},
				},
				Rules: []reference.Rule{{User: &o.bob.Pk}, {Policy: &o.office.Pk}},
			},
		},
		{
			name:    "credentials are read from the default keys of an existing Secret",
			app:     application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{Credentials: credentialsSpec()})),
			secrets: []client.Object{secret(map[string]string{"client-id": "id-from-secret", "client-secret": clientSecret})},
			want: &reference.Resolved{
				Flows:  &reference.Flows{Authorization: o.authorization.Pk, Invalidation: o.invalidation.Pk},
				OAuth2: &reference.OAuth2References{Credentials: &reference.Credentials{SecretExists: true, ClientID: "id-from-secret", ClientSecret: clientSecret}},
				Rules:  []reference.Rule{},
			},
		},
		{
			name: "clientID in the spec takes precedence and custom keys are used",
			app: application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{Credentials: &v1alpha1.OAuth2CredentialsSpec{
				ClientID:  new("wiki"),
				SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: secretName, ClientSecretKey: new("oidc.clientSecret")},
			}})),
			secrets: []client.Object{secret(map[string]string{"oidc.clientSecret": clientSecret})},
			want: &reference.Resolved{
				Flows:  &reference.Flows{Authorization: o.authorization.Pk, Invalidation: o.invalidation.Pk},
				OAuth2: &reference.OAuth2References{Credentials: &reference.Credentials{SecretExists: true, ClientID: slug, ClientSecret: clientSecret}},
				Rules:  []reference.Rule{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := reference.NewResolver(ak, newKube(t, tt.secrets...))
			got, err := resolver.Resolve(context.Background(), tt.app)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveFailures(t *testing.T) {
	t.Parallel()

	ak, _ := newAuthentik()
	missingUUID := "00000000-0000-4000-8000-999999999999"
	withoutEmbedded := fake.New()
	withoutEmbedded.AddFlow(authorizationSlug)
	withoutEmbedded.AddFlow(invalidationSlug)

	tests := []struct {
		name       string
		authentik  reference.AuthentikReader
		app        *v1alpha1.AuthentikApplication
		secrets    []client.Object
		wantReason string
		want       []reference.Failure
	}{
		{
			name:      "every unresolved reference is listed",
			authentik: ak,
			app: application(
				&v1alpha1.ProviderSpec{
					Flows: v1alpha1.ProviderFlows{
						Authorization: v1alpha1.FlowReference{Slug: new("missing-flow")},
						Invalidation:  v1alpha1.FlowReference{UUID: &missingUUID},
					},
					Proxy: &v1alpha1.ProxyProviderSpec{
						ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: externalHost},
						Certificate:       &v1alpha1.NamedReference{Name: new("missing-certificate")},
						Outpost:           &v1alpha1.NamedReference{Name: new("missing-outpost")},
					},
				},
				v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("admins")}},
				v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{UUID: &missingUUID}},
				v1alpha1.AccessRule{User: &v1alpha1.UserReference{Username: new("alice")}},
				v1alpha1.AccessRule{User: &v1alpha1.UserReference{PK: new(int64(math.MaxInt32) + 1)}},
				v1alpha1.AccessRule{Policy: &v1alpha1.NamedReference{Name: new("missing-policy")}},
			),
			wantReason: v1alpha1.ReasonReferenceNotFound,
			want: []reference.Failure{
				{Path: "provider.flows.authorization", Target: `Flow slug "missing-flow"`},
				{Path: "provider.flows.invalidation", Target: `Flow uuid "` + missingUUID + `"`},
				{Path: "provider.proxy.certificate", Target: `CertificateKeyPair name "missing-certificate"`},
				{Path: "provider.proxy.outpost", Target: `Outpost name "missing-outpost"`},
				{Path: "access.rules[1].group", Target: `Group uuid "` + missingUUID + `"`},
				{Path: "access.rules[2].user", Target: `User username "alice"`},
				{Path: "access.rules[3].user", Target: "User pk 2147483648"},
				{Path: "access.rules[4].policy", Target: `Policy name "missing-policy"`},
			},
		},
		{
			name:      "a scope name shared by several ScopeMappings is ambiguous",
			authentik: ak,
			app: application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{
				Scopes: []v1alpha1.ScopeMappingReference{{ScopeName: new("openid")}, {ScopeName: new("profile")}},
			})),
			wantReason: v1alpha1.ReasonAmbiguousReference,
			want:       []reference.Failure{{Path: "provider.oauth2.scopes[1]", Target: `ScopeMapping scopeName "profile"`, Matches: 2}},
		},
		{
			name:      "a missing reference takes precedence over an ambiguous one",
			authentik: ak,
			app: application(
				oauth2Provider(&v1alpha1.OAuth2ProviderSpec{Scopes: []v1alpha1.ScopeMappingReference{{ScopeName: new("profile")}}}),
				v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("missing-group")}},
			),
			wantReason: v1alpha1.ReasonReferenceNotFound,
			want: []reference.Failure{
				{Path: "provider.oauth2.scopes[0]", Target: `ScopeMapping scopeName "profile"`, Matches: 2},
				{Path: "access.rules[0].group", Target: `Group name "missing-group"`},
			},
		},
		{
			name:       "the embedded outpost is required when outpost is omitted",
			authentik:  withoutEmbedded,
			app:        application(proxyProvider(&v1alpha1.ProxyProviderSpec{ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: externalHost}})),
			wantReason: v1alpha1.ReasonReferenceNotFound,
			want:       []reference.Failure{{Path: "provider.proxy.outpost", Target: `Outpost name "authentik Embedded Outpost"`}},
		},
		{
			name:       "keys missing from an existing Secret",
			authentik:  ak,
			app:        application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{Credentials: credentialsSpec()})),
			secrets:    []client.Object{secret(map[string]string{"client-secret-typo": clientSecret})},
			wantReason: v1alpha1.ReasonReferenceNotFound,
			want: []reference.Failure{
				{Path: "provider.oauth2.credentials.secretRef.clientIDKey", Target: `key "client-id" in Secret "wiki-oidc"`},
				{Path: "provider.oauth2.credentials.secretRef.clientSecretKey", Target: `key "client-secret" in Secret "wiki-oidc"`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := reference.NewResolver(tt.authentik, newKube(t, tt.secrets...))
			got, err := resolver.Resolve(context.Background(), tt.app)
			assert.Nil(t, got)
			var refErr *reference.Error
			require.ErrorAs(t, err, &refErr)
			assert.Equal(t, tt.wantReason, refErr.Reason())
			assert.Equal(t, tt.want, refErr.Failures)
			assert.NotContains(t, err.Error(), clientSecret)
		})
	}
}

// errAuthentik is a server error returned by failingAuthentik.
var errAuthentik = &authentik.APIError{Operation: "FindGroupsByName", StatusCode: http.StatusInternalServerError}

// failingAuthentik answers every Group search with errAuthentik.
type failingAuthentik struct {
	*fake.Client
}

func (failingAuthentik) FindGroupsByName(context.Context, string) ([]api.Group, error) {
	return nil, errAuthentik
}

func TestResolveReturnsOtherErrors(t *testing.T) {
	t.Parallel()

	ak, _ := newAuthentik()
	errKube := errors.New("apiserver unavailable")
	failingKube := interceptor.NewClient(newKube(t), interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errKube
		},
	})

	tests := []struct {
		name      string
		authentik reference.AuthentikReader
		kube      client.Reader
		app       *v1alpha1.AuthentikApplication
		wantErr   error
	}{
		{
			name:      "an authentik error other than 404",
			authentik: failingAuthentik{Client: ak},
			kube:      newKube(t),
			app:       application(nil, v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("admins")}}),
			wantErr:   errAuthentik,
		},
		{
			name:      "a Kubernetes error other than NotFound",
			authentik: ak,
			kube:      failingKube,
			app:       application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{Credentials: credentialsSpec()})),
			wantErr:   errKube,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := reference.NewResolver(tt.authentik, tt.kube).Resolve(context.Background(), tt.app)
			require.ErrorIs(t, err, tt.wantErr)
			var refErr *reference.Error
			assert.NotErrorAs(t, err, &refErr)
		})
	}
}

func TestResolveCreationDefaults(t *testing.T) {
	t.Parallel()

	ak, o := newAuthentik()
	withoutDefaults := fake.New()
	withoutDefaults.AddScopeMapping("custom openid", "openid")

	tests := []struct {
		name       string
		authentik  reference.AuthentikReader
		app        *v1alpha1.AuthentikApplication
		want       *reference.CreationDefaults
		wantFailed []reference.Failure
	}{
		{
			name:      "no defaults for a proxy provider",
			authentik: ak,
			app:       application(proxyProvider(&v1alpha1.ProxyProviderSpec{})),
			want:      &reference.CreationDefaults{},
		},
		{
			name:      "the shipped ScopeMappings are chosen over custom ones that share a scope name",
			authentik: ak,
			app:       application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{})),
			want: &reference.CreationDefaults{
				Scopes:     []string{o.openid.Pk, o.email.Pk, o.profile.Pk},
				SigningKey: &o.certificate.Pk,
			},
		},
		{
			name:      "fields set in the spec have no defaults",
			authentik: ak,
			app: application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{
				Scopes:     []v1alpha1.ScopeMappingReference{{ScopeName: new("openid")}},
				SigningKey: &v1alpha1.NamedReference{Name: new("other")},
			})),
			want: &reference.CreationDefaults{},
		},
		{
			name:      "explicitly empty scopes have no defaults",
			authentik: ak,
			app: application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{
				Scopes:     []v1alpha1.ScopeMappingReference{},
				SigningKey: &v1alpha1.NamedReference{Name: new("other")},
			})),
			want: &reference.CreationDefaults{},
		},
		{
			name:      "missing defaults are reported",
			authentik: withoutDefaults,
			app:       application(oauth2Provider(&v1alpha1.OAuth2ProviderSpec{})),
			wantFailed: []reference.Failure{
				{Path: scopesPath, Target: `ScopeMapping managed "goauthentik.io/providers/oauth2/scope-openid"`},
				{Path: scopesPath, Target: `ScopeMapping managed "goauthentik.io/providers/oauth2/scope-email"`},
				{Path: scopesPath, Target: `ScopeMapping managed "goauthentik.io/providers/oauth2/scope-profile"`},
				{Path: "provider.oauth2.signingKey", Target: `CertificateKeyPair name "authentik Self-signed Certificate"`},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := reference.NewResolver(tt.authentik, newKube(t)).ResolveCreationDefaults(context.Background(), tt.app)
			if tt.wantFailed != nil {
				var refErr *reference.Error
				require.ErrorAs(t, err, &refErr)
				assert.Equal(t, tt.wantFailed, refErr.Failures)
				assert.Equal(t, v1alpha1.ReasonReferenceNotFound, refErr.Reason())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
