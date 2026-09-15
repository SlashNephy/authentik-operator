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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

const (
	credentialsSecret = "oidc"
	myClientID        = "my-client"
)

func (f *fixture) oauth2Spec(credentials *v1alpha1.OAuth2CredentialsSpec) v1alpha1.AuthentikApplicationSpec {
	return v1alpha1.AuthentikApplicationSpec{
		Slug: f.slug, Name: testName,
		Provider: &v1alpha1.ProviderSpec{
			Flows:  testProviderFlows(),
			OAuth2: &v1alpha1.OAuth2ProviderSpec{Credentials: credentials},
		},
		Access: v1alpha1.AccessSpec{Public: new(true)},
	}
}

func secretCredentials() *v1alpha1.OAuth2CredentialsSpec {
	return &v1alpha1.OAuth2CredentialsSpec{SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: credentialsSecret}}
}

func (f *fixture) createSecret(t *testing.T, data map[string]string) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{Namespace: f.namespace, Name: credentialsSecret, StringData: data}
	require.NoError(t, k8sClient.Create(t.Context(), secret))
	return secret
}

func (f *fixture) getSecret(t *testing.T) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Namespace: f.namespace, Name: credentialsSecret}, secret))
	return secret
}

func (f *fixture) oauth2Provider(t *testing.T, app *v1alpha1.AuthentikApplication) *api.OAuth2Provider {
	t.Helper()
	provider, err := f.authentik.GetOAuth2Provider(t.Context(), int32(*app.Status.ProviderPK))
	require.NoError(t, err)
	return provider
}

func TestReconcileExportsCredentialsWhenSecretIsMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		credentials *v1alpha1.OAuth2CredentialsSpec
		wantKeys    []string
		wantID      string
	}{
		{
			name:        "default keys",
			credentials: secretCredentials(),
			wantKeys:    []string{reference.DefaultClientIDKey, reference.DefaultClientSecretKey},
		},
		{
			name: "inline client ID and a custom secret key",
			credentials: &v1alpha1.OAuth2CredentialsSpec{
				ClientID:  new("inline-id"),
				SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: credentialsSecret, ClientSecretKey: new("oidc.clientSecret")},
			},
			wantKeys: []string{"oidc.clientSecret"},
			wantID:   "inline-id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)

			_, got, err := f.reconcile(t, f.create(t, f.oauth2Spec(tt.credentials)))
			require.NoError(t, err)
			assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
			provider := f.oauth2Provider(t, got)
			if tt.wantID != "" {
				assert.Equal(t, new(tt.wantID), provider.ClientId)
			}

			secret := f.getSecret(t)
			keys := make([]string, 0, len(secret.Data))
			for key := range secret.Data {
				keys = append(keys, key)
			}
			assert.ElementsMatch(t, tt.wantKeys, keys)
			if value, ok := secret.Data[reference.DefaultClientIDKey]; ok {
				assert.Equal(t, *provider.ClientId, string(value))
			}
			secretKey := tt.wantKeys[len(tt.wantKeys)-1]
			assert.Equal(t, *provider.ClientSecret, string(secret.Data[secretKey]))
			require.Len(t, secret.OwnerReferences, 1)
			assert.Equal(t, got.UID, secret.OwnerReferences[0].UID)
			assert.Equal(t, new(true), secret.OwnerReferences[0].Controller)

			// The exported Secret is the source of truth from now on: a change in authentik is reverted.
			_, err = f.authentik.PatchOAuth2Provider(t.Context(), provider.Pk, &api.PatchedOAuth2ProviderRequest{ClientSecret: new("changed")})
			require.NoError(t, err)
			_, got, err = f.reconcile(t, got)
			require.NoError(t, err)
			assert.Equal(t, string(secret.Data[secretKey]), *f.oauth2Provider(t, got).ClientSecret)
		})
	}
}

func TestReconcileUsesExistingSecretAsSourceOfTruth(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	secret := f.createSecret(t, map[string]string{reference.DefaultClientIDKey: myClientID, reference.DefaultClientSecretKey: "s3cr3t"})

	_, got, err := f.reconcile(t, f.create(t, f.oauth2Spec(secretCredentials())))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	provider := f.oauth2Provider(t, got)
	assert.Equal(t, new(myClientID), provider.ClientId)
	assert.Equal(t, new("s3cr3t"), provider.ClientSecret)
	assert.Empty(t, f.getSecret(t).OwnerReferences, "a Secret managed by someone else is not taken over")

	// Rotation by rewriting the Secret.
	secret.StringData = map[string]string{reference.DefaultClientSecretKey: "rotated"}
	require.NoError(t, k8sClient.Update(t.Context(), secret))
	_, got, err = f.reconcile(t, got)
	require.NoError(t, err)
	assert.Equal(t, new("rotated"), f.oauth2Provider(t, got).ClientSecret)
	assert.Equal(t, []reconcile.Request{{Namespace: f.namespace, Name: got.Name}}, requestsEventually(t, f, secret))
}

// requestsEventually waits until the cached index maps the Secret to a resource and returns the requests.
func requestsEventually(t *testing.T, f *fixture, secret *corev1.Secret) []reconcile.Request {
	t.Helper()
	var requests []reconcile.Request
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		requests = f.reconciler.credentialsSecretRequests(t.Context(), secret)
		assert.NotEmpty(c, requests)
	}, 10*time.Second, 50*time.Millisecond)
	return requests
}

func TestReconcileCredentialsFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup prepares the Secret and authentik, and returns the data of the Secret.
		setup  func(t *testing.T, f *fixture) map[string]string
		reason string
	}{
		{
			name: "key missing in an existing Secret",
			setup: func(t *testing.T, f *fixture) map[string]string {
				data := map[string]string{reference.DefaultClientIDKey: myClientID}
				f.createSecret(t, data)
				return data
			},
			reason: v1alpha1.ReasonReferenceNotFound,
		},
		{
			name: "client ID used by another Provider",
			setup: func(t *testing.T, f *fixture) map[string]string {
				data := map[string]string{reference.DefaultClientIDKey: "taken", reference.DefaultClientSecretKey: "s3cr3t"}
				f.createSecret(t, data)
				_, err := f.authentik.CreateOAuth2Provider(t.Context(), &api.OAuth2ProviderRequest{
					Name: "other-" + f.slug, AuthorizationFlow: "a", InvalidationFlow: "i",
					RedirectUris: []api.RedirectURIRequest{}, ClientId: new("taken"),
				})
				require.NoError(t, err)
				return data
			},
			reason: v1alpha1.ReasonAPIError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			data := tt.setup(t, f)

			_, got, err := f.reconcile(t, f.create(t, f.oauth2Spec(secretCredentials())))
			require.Error(t, err)
			assertReady(t, got, metav1.ConditionFalse, tt.reason)
			if tt.reason == v1alpha1.ReasonAPIError {
				assert.Contains(t, got.Status.Conditions[0].Message, "Client ID already exists")
			}
			assert.Empty(t, got.Status.ApplicationPK)
			secretData := map[string]string{}
			for key, value := range f.getSecret(t).Data {
				secretData[key] = string(value)
			}
			assert.Equal(t, data, secretData, "a Secret managed by someone else is never modified")
		})
	}
}

func TestReconcileAdoptionExportsCredentials(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	authorization, err := f.authentik.FindFlowsBySlug(ctx, authorizationSlug)
	require.NoError(t, err)
	invalidation, err := f.authentik.FindFlowsBySlug(ctx, invalidationSlug)
	require.NoError(t, err)
	provider, err := f.authentik.CreateOAuth2Provider(ctx, &api.OAuth2ProviderRequest{
		Name: "manual-" + f.slug, AuthorizationFlow: authorization[0].Pk, InvalidationFlow: invalidation[0].Pk,
		RedirectUris: []api.RedirectURIRequest{}, ClientId: new("manual-id"), ClientSecret: new("manual-secret"),
	})
	require.NoError(t, err)
	_, err = f.authentik.CreateApplication(ctx, &api.ApplicationRequest{Name: testName, Slug: f.slug, Provider: *api.NewNullableInt32(&provider.Pk)})
	require.NoError(t, err)

	spec := f.oauth2Spec(secretCredentials())
	spec.Adopt = new(v1alpha1.AdoptionPolicyIfMatch)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Equal(t, int64(provider.Pk), *got.Status.ProviderPK)
	secret := f.getSecret(t)
	assert.Equal(t, "manual-id", string(secret.Data[reference.DefaultClientIDKey]))
	assert.Equal(t, "manual-secret", string(secret.Data[reference.DefaultClientSecretKey]))
}

func TestIfMatchComparesSecretRedacted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	authorization, err := f.authentik.FindFlowsBySlug(ctx, authorizationSlug)
	require.NoError(t, err)
	invalidation, err := f.authentik.FindFlowsBySlug(ctx, invalidationSlug)
	require.NoError(t, err)
	provider, err := f.authentik.CreateOAuth2Provider(ctx, &api.OAuth2ProviderRequest{
		Name: "manual-" + f.slug, AuthorizationFlow: authorization[0].Pk, InvalidationFlow: invalidation[0].Pk,
		RedirectUris: []api.RedirectURIRequest{}, ClientId: new(myClientID), ClientSecret: new("old"),
	})
	require.NoError(t, err)
	_, err = f.authentik.CreateApplication(ctx, &api.ApplicationRequest{Name: testName, Slug: f.slug, Provider: *api.NewNullableInt32(&provider.Pk)})
	require.NoError(t, err)
	f.createSecret(t, map[string]string{reference.DefaultClientIDKey: myClientID, reference.DefaultClientSecretKey: "new"})

	spec := f.oauth2Spec(secretCredentials())
	spec.Adopt = new(v1alpha1.AdoptionPolicyIfMatch)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonAdoptionDiff)
	assert.Equal(t, []v1alpha1.FieldDiff{
		{Field: "provider.oauth2.credentials.secretRef.clientSecretKey", Desired: redacted, Actual: redacted},
	}, got.Status.AdoptionDiff)
}
