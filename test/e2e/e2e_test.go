//go:build e2e

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

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

const (
	// waitTimeout covers several resyncs of the operator installed by hack/e2e/deploy.sh (15s).
	waitTimeout       = 3 * time.Minute
	pollInterval      = 2 * time.Second
	authorizationFlow = "default-provider-authorization-implicit-consent"
	invalidationFlow  = "default-provider-invalidation-flow"
	embeddedOutpost   = "authentik Embedded Outpost"
	credentialsSecret = "oidc"
)

// newNamespace creates a namespace for one test. Its name also serves as the unique slug of the test.
func newNamespace(t *testing.T) string {
	t.Helper()
	namespace := &corev1.Namespace{GenerateName: "e2e-"}
	require.NoError(t, k8s.Create(t.Context(), namespace))
	t.Cleanup(func() {
		_ = k8s.Delete(context.Background(), namespace)
	})
	return namespace.Name
}

// callAPI sends a request to the authentik API for the operations that the client does not cover.
func callAPI(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	var reader bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&reader).Encode(body))
	}
	request, err := http.NewRequestWithContext(t.Context(), method, authentikURL+"/api/v3"+path, &reader)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+authentikToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Less(t, response.StatusCode, 300, "%s %s returned %d", method, path, response.StatusCode)
	result := map[string]any{}
	if response.StatusCode != http.StatusNoContent {
		require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
	}
	return result
}

// createGroup creates a Group that is deleted after the test.
func createGroup(t *testing.T, name string) string {
	t.Helper()
	pk := callAPI(t, http.MethodPost, "/core/groups/", map[string]any{"name": name})["pk"].(string)
	t.Cleanup(func() {
		request, _ := http.NewRequest(http.MethodDelete, authentikURL+"/api/v3/core/groups/"+pk+"/", nil)
		request.Header.Set("Authorization", "Bearer "+authentikToken)
		if response, err := http.DefaultClient.Do(request); err == nil {
			_ = response.Body.Close()
		}
	})
	return pk
}

func flowPK(t *testing.T, slug string) string {
	t.Helper()
	flows, err := ak.FindFlowsBySlug(t.Context(), slug)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	return flows[0].Pk
}

func providerFlows() v1alpha1.ProviderFlows {
	return v1alpha1.ProviderFlows{
		Authorization: v1alpha1.FlowReference{Slug: new(authorizationFlow)},
		Invalidation:  v1alpha1.FlowReference{Slug: new(invalidationFlow)},
	}
}

// proxyApplication returns a forward auth Application for the group that deletes its objects with the resource.
func proxyApplication(namespace, group string) *v1alpha1.AuthentikApplication {
	return &v1alpha1.AuthentikApplication{
		Namespace: namespace, Name: "app",
		Spec: v1alpha1.AuthentikApplicationSpec{
			Slug:           namespace,
			Name:           "E2E " + namespace,
			LaunchURL:      new("https://" + namespace + ".example.com"),
			DeletionPolicy: new(v1alpha1.DeletionPolicyDelete),
			Provider: &v1alpha1.ProviderSpec{
				Flows: providerFlows(),
				Proxy: &v1alpha1.ProxyProviderSpec{
					ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: "https://" + namespace + ".example.com"},
				},
			},
			Access: v1alpha1.AccessSpec{Rules: []v1alpha1.AccessRule{{Group: &v1alpha1.NamedReference{Name: new(group)}}}},
		},
	}
}

// create creates the resource and deletes it after the test, waiting for its finalizer.
func create(t *testing.T, app *v1alpha1.AuthentikApplication) {
	t.Helper()
	require.NoError(t, k8s.Create(t.Context(), app))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()
		_ = k8s.Delete(ctx, app)
		for ctx.Err() == nil {
			if apierrors.IsNotFound(k8s.Get(ctx, client.ObjectKeyFromObject(app), &v1alpha1.AuthentikApplication{})) {
				return
			}
			time.Sleep(pollInterval)
		}
	})
}

// waitForReady waits until the Ready condition has the reason and returns the resource.
func waitForReady(t *testing.T, app *v1alpha1.AuthentikApplication, reason string) *v1alpha1.AuthentikApplication {
	t.Helper()
	got := &v1alpha1.AuthentikApplication{}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NoError(c, k8s.Get(t.Context(), client.ObjectKeyFromObject(app), got))
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeReady)
		require.NotNil(c, condition)
		assert.Equal(c, reason, condition.Reason, condition.Message)
		assert.Equal(c, got.Generation, got.Status.ObservedGeneration)
	}, waitTimeout, pollInterval)
	return got
}

// update applies mutate to the latest resource.
func update(t *testing.T, app *v1alpha1.AuthentikApplication, mutate func(*v1alpha1.AuthentikApplication)) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		latest := &v1alpha1.AuthentikApplication{}
		require.NoError(c, k8s.Get(t.Context(), client.ObjectKeyFromObject(app), latest))
		mutate(latest)
		require.NoError(c, k8s.Update(t.Context(), latest))
	}, waitTimeout, pollInterval)
}

func embeddedOutpostProviders(t *testing.T) []int32 {
	t.Helper()
	outposts, err := ak.FindOutpostsByName(t.Context(), embeddedOutpost)
	require.NoError(t, err)
	require.Len(t, outposts, 1)
	return outposts[0].Providers
}

func TestProxyApplicationLifecycle(t *testing.T) {
	t.Parallel()
	namespace := newNamespace(t)
	groupPK := createGroup(t, namespace)
	app := proxyApplication(namespace, namespace)
	create(t, app)

	got := waitForReady(t, app, v1alpha1.ReasonReconciled)
	ctx := t.Context()
	application, err := ak.GetApplication(ctx, namespace)
	require.NoError(t, err)
	assert.Equal(t, got.Status.ApplicationPK, application.Pk)
	providerPK := int32(*got.Status.ProviderPK)
	assert.Equal(t, new(providerPK), application.Provider.Get())

	provider, err := ak.GetProxyProvider(ctx, providerPK)
	require.NoError(t, err)
	assert.Equal(t, namespace, provider.Name)
	assert.Equal(t, new(api.PROXYMODE_FORWARD_SINGLE), provider.Mode)
	assert.Contains(t, embeddedOutpostProviders(t), providerPK, "the Provider joins the embedded outpost")

	bindings, err := ak.ListPolicyBindings(ctx, application.PbmUuid)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	assert.Equal(t, new(groupPK), bindings[0].Group.Get())

	t.Run("drift is repaired", func(t *testing.T) {
		_, err := ak.PatchApplication(ctx, namespace, &api.PatchedApplicationRequest{Name: new("changed in the UI")})
		require.NoError(t, err)
		_, err = ak.PatchProxyProvider(ctx, providerPK, &api.PatchedProxyProviderRequest{
			Mode: new(api.PROXYMODE_FORWARD_SINGLE), ExternalHost: new("https://changed.example.com"),
		})
		require.NoError(t, err)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			application, err := ak.GetApplication(ctx, namespace)
			require.NoError(c, err)
			assert.Equal(c, app.Spec.Name, application.Name)
			provider, err := ak.GetProxyProvider(ctx, providerPK)
			require.NoError(c, err)
			assert.Equal(c, "https://"+namespace+".example.com", provider.ExternalHost)
		}, waitTimeout, pollInterval)
	})

	t.Run("Delete removes the objects", func(t *testing.T) {
		require.NoError(t, k8s.Delete(ctx, got))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, apierrors.IsNotFound(k8s.Get(ctx, client.ObjectKeyFromObject(app), &v1alpha1.AuthentikApplication{})))
		}, waitTimeout, pollInterval)
		_, err := ak.GetApplication(ctx, namespace)
		require.ErrorIs(t, err, authentik.ErrNotFound)
		_, err = ak.GetProxyProvider(ctx, providerPK)
		require.ErrorIs(t, err, authentik.ErrNotFound)
		assert.NotContains(t, embeddedOutpostProviders(t), providerPK)
	})
}

func TestOAuth2CredentialsAndRetain(t *testing.T) {
	t.Parallel()
	namespace := newNamespace(t)
	ctx := t.Context()
	app := &v1alpha1.AuthentikApplication{
		Namespace: namespace, Name: "app",
		Spec: v1alpha1.AuthentikApplicationSpec{
			Slug: namespace, Name: "E2E " + namespace,
			Provider: &v1alpha1.ProviderSpec{
				Flows: providerFlows(),
				OAuth2: &v1alpha1.OAuth2ProviderSpec{
					RedirectURIs: []v1alpha1.RedirectURI{{URL: "https://" + namespace + ".example.com/callback"}},
					Credentials: &v1alpha1.OAuth2CredentialsSpec{
						SecretRef: v1alpha1.OAuth2CredentialsSecretReference{Name: credentialsSecret},
					},
				},
			},
			Access: v1alpha1.AccessSpec{Public: new(true)},
		},
	}
	create(t, app)

	got := waitForReady(t, app, v1alpha1.ReasonReconciled)
	providerPK := int32(*got.Status.ProviderPK)
	t.Cleanup(func() {
		_ = ak.DeleteApplication(context.Background(), namespace)
		_ = ak.DeleteOAuth2Provider(context.Background(), providerPK)
	})

	secret := &corev1.Secret{}
	require.NoError(t, k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: credentialsSecret}, secret))
	provider, err := ak.GetOAuth2Provider(ctx, providerPK)
	require.NoError(t, err)
	assert.Equal(t, *provider.ClientId, string(secret.Data["client-id"]), "authentik's values are exported")
	assert.Equal(t, *provider.ClientSecret, string(secret.Data["client-secret"]))
	require.Len(t, secret.OwnerReferences, 1)
	assert.Equal(t, got.UID, secret.OwnerReferences[0].UID)
	assert.Len(t, provider.PropertyMappings, 3, "openid, email, and profile are the default scopes")
	assert.NotNil(t, provider.SigningKey.Get(), "the self-signed certificate is the default signing key")

	t.Run("a Secret change is applied", func(t *testing.T) {
		secret.StringData = map[string]string{"client-secret": "rotated-" + namespace}
		require.NoError(t, k8s.Update(ctx, secret))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			provider, err := ak.GetOAuth2Provider(ctx, providerPK)
			require.NoError(c, err)
			assert.Equal(c, new("rotated-"+namespace), provider.ClientSecret)
		}, waitTimeout, pollInterval)
	})

	t.Run("Retain keeps the objects", func(t *testing.T) {
		require.NoError(t, k8s.Delete(ctx, got))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, apierrors.IsNotFound(k8s.Get(ctx, client.ObjectKeyFromObject(app), &v1alpha1.AuthentikApplication{})))
		}, waitTimeout, pollInterval)
		_, err := ak.GetApplication(ctx, namespace)
		require.NoError(t, err)
		_, err = ak.GetOAuth2Provider(ctx, providerPK)
		require.NoError(t, err)
	})
}

func TestAdoptionModes(t *testing.T) {
	t.Parallel()
	namespace := newNamespace(t)
	ctx := t.Context()
	createGroup(t, namespace)

	provider, err := ak.CreateProxyProvider(ctx, &api.ProxyProviderRequest{
		Name:              "manual-" + namespace,
		AuthorizationFlow: flowPK(t, authorizationFlow),
		InvalidationFlow:  flowPK(t, invalidationFlow),
		ExternalHost:      "https://manual.example.com",
		Mode:              new(api.PROXYMODE_FORWARD_SINGLE),
	})
	require.NoError(t, err)
	_, err = ak.CreateApplication(ctx, &api.ApplicationRequest{
		Name: "Manual", Slug: namespace, Provider: *api.NewNullableInt32(&provider.Pk),
	})
	require.NoError(t, err)

	app := proxyApplication(namespace, namespace)
	app.Spec.LaunchURL = nil
	create(t, app)
	waitForReady(t, app, v1alpha1.ReasonUnmanaged)
	unchanged, err := ak.GetApplication(ctx, namespace)
	require.NoError(t, err)
	assert.Equal(t, "Manual", unchanged.Name, "Never writes nothing")

	update(t, app, func(latest *v1alpha1.AuthentikApplication) { latest.Spec.Adopt = new(v1alpha1.AdoptionPolicyIfMatch) })
	diff := waitForReady(t, app, v1alpha1.ReasonAdoptionDiff)
	fields := make([]string, 0, len(diff.Status.AdoptionDiff))
	for _, field := range diff.Status.AdoptionDiff {
		fields = append(fields, field.Field)
	}
	assert.ElementsMatch(t, []string{"name", "provider.proxy.forwardAuthSingle.externalHost"}, fields)

	update(t, app, func(latest *v1alpha1.AuthentikApplication) { latest.Spec.Adopt = new(v1alpha1.AdoptionPolicyForce) })
	adopted := waitForReady(t, app, v1alpha1.ReasonReconciled)
	assert.Equal(t, int64(provider.Pk), *adopted.Status.ProviderPK, "the attached Provider is adopted")
	application, err := ak.GetApplication(ctx, namespace)
	require.NoError(t, err)
	assert.Equal(t, app.Spec.Name, application.Name)
}

func TestUnmanagedBindingsAndPrune(t *testing.T) {
	t.Parallel()
	namespace := newNamespace(t)
	ctx := t.Context()
	createGroup(t, namespace)
	legacyPK := createGroup(t, namespace+"-legacy")

	app := proxyApplication(namespace, namespace)
	create(t, app)
	waitForReady(t, app, v1alpha1.ReasonReconciled)

	application, err := ak.GetApplication(ctx, namespace)
	require.NoError(t, err)
	legacy, err := ak.CreatePolicyBinding(ctx, &api.PolicyBindingRequest{
		Target: application.PbmUuid, Group: *api.NewNullableString(&legacyPK), Order: 500,
	})
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got := &v1alpha1.AuthentikApplication{}
		require.NoError(c, k8s.Get(ctx, client.ObjectKeyFromObject(app), got))
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeUnmanagedBindings)
		require.NotNil(c, condition)
		assert.Equal(c, metav1.ConditionTrue, condition.Status)
		want := []v1alpha1.UnmanagedBinding{{UUID: legacy.Pk, Target: "group/" + namespace + "-legacy"}}
		assert.Equal(c, want, got.Status.UnmanagedBindings)
	}, waitTimeout, pollInterval)

	update(t, app, func(latest *v1alpha1.AuthentikApplication) { latest.Spec.Access.Prune = new(true) })
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		bindings, err := ak.ListPolicyBindings(ctx, application.PbmUuid)
		require.NoError(c, err)
		assert.False(c, slices.ContainsFunc(bindings, func(b api.PolicyBinding) bool { return b.Pk == legacy.Pk }))
		assert.Len(c, bindings, 1, "the managed Binding stays")
	}, waitTimeout, pollInterval)
}

func TestOutpostMembershipIsRepaired(t *testing.T) {
	t.Parallel()
	namespace := newNamespace(t)
	ctx := t.Context()
	createGroup(t, namespace)
	app := proxyApplication(namespace, namespace)
	create(t, app)
	got := waitForReady(t, app, v1alpha1.ReasonReconciled)
	providerPK := int32(*got.Status.ProviderPK)

	outposts, err := ak.FindOutpostsByName(ctx, embeddedOutpost)
	require.NoError(t, err)
	remaining := slices.DeleteFunc(slices.Clone(outposts[0].Providers), func(pk int32) bool { return pk == providerPK })
	_, err = ak.SetOutpostProviders(ctx, outposts[0].Pk, remaining)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		outposts, err := ak.FindOutpostsByName(ctx, embeddedOutpost)
		require.NoError(c, err)
		assert.Contains(c, outposts[0].Providers, providerPK, "the Provider rejoins the outpost")
	}, waitTimeout, pollInterval)
}
