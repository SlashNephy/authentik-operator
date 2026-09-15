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
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

// deleteAndReconcile deletes the resource and runs the reconcile that finalizes it.
func (f *fixture) deleteAndReconcile(t *testing.T, app *v1alpha1.AuthentikApplication) error {
	t.Helper()
	require.NoError(t, k8sClient.Delete(t.Context(), app))
	_, err := f.reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	return err
}

func assertGone(t *testing.T, app *v1alpha1.AuthentikApplication) {
	t.Helper()
	err := k8sClient.Get(t.Context(), client.ObjectKeyFromObject(app), &v1alpha1.AuthentikApplication{})
	assert.True(t, apierrors.IsNotFound(err), "the finalizer is removed and the resource is gone: %v", err)
}

func TestReconcileAddsFinalizer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, got, err := f.reconcile(t, f.create(t, f.proxySpec()))
	require.NoError(t, err)
	assert.Contains(t, got.Finalizers, finalizer)
}

func TestDeletionPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy v1alpha1.DeletionPolicy
		oauth2 bool
	}{
		{name: "Retain keeps the objects", policy: v1alpha1.DeletionPolicyRetain},
		{name: "Delete deletes a proxy application", policy: v1alpha1.DeletionPolicyDelete},
		{name: "Delete deletes an OAuth2 application", policy: v1alpha1.DeletionPolicyDelete, oauth2: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			ctx := t.Context()
			spec := f.proxySpec()
			if tt.oauth2 {
				spec = f.oauth2Spec(nil)
			}
			spec.DeletionPolicy = new(tt.policy)
			_, got, err := f.reconcile(t, f.create(t, spec))
			require.NoError(t, err)
			require.NotEmpty(t, f.managed(t))
			providerPK := int32(*got.Status.ProviderPK)

			require.NoError(t, f.deleteAndReconcile(t, got))
			assertGone(t, got)
			assert.Empty(t, f.managed(t), "every marker is removed")

			_, appErr := f.authentik.GetApplication(ctx, f.slug)
			var providerErr error
			if tt.oauth2 {
				_, providerErr = f.authentik.GetOAuth2Provider(ctx, providerPK)
			} else {
				_, providerErr = f.authentik.GetProxyProvider(ctx, providerPK)
			}
			_, bindingErr := f.authentik.GetPolicyBinding(ctx, firstOr(got.Status.BindingUUIDs, "none"))
			outposts, err := f.authentik.FindOutpostsByName(ctx, reference.EmbeddedOutpostName)
			require.NoError(t, err)

			if tt.policy == v1alpha1.DeletionPolicyRetain {
				require.NoError(t, appErr)
				require.NoError(t, providerErr)
				require.NoError(t, bindingErr)
				assert.Equal(t, []int32{providerPK}, outposts[0].Providers)
				return
			}
			require.ErrorIs(t, appErr, authentik.ErrNotFound)
			require.ErrorIs(t, providerErr, authentik.ErrNotFound)
			if !tt.oauth2 {
				require.ErrorIs(t, bindingErr, authentik.ErrNotFound)
			}
			assert.Empty(t, outposts[0].Providers)
		})
	}
}

func firstOr(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

func TestDeletionTreatsMissingObjectsAsDeleted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	spec := f.proxySpec()
	spec.DeletionPolicy = new(v1alpha1.DeletionPolicyDelete)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, f.authentik.DeleteApplication(ctx, f.slug))
	require.NoError(t, f.authentik.DeleteProxyProvider(ctx, int32(*got.Status.ProviderPK)))

	require.NoError(t, f.deleteAndReconcile(t, got))
	assertGone(t, got)
}

func TestDeletionKeepsApplicationWithAnotherPK(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	spec := f.proxySpec()
	spec.DeletionPolicy = new(v1alpha1.DeletionPolicyDelete)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, f.authentik.DeleteApplication(ctx, f.slug))
	manual, err := f.authentik.CreateApplication(ctx, &api.ApplicationRequest{Name: manualName, Slug: f.slug})
	require.NoError(t, err)

	require.NoError(t, f.deleteAndReconcile(t, got))
	assertGone(t, got)
	application, err := f.authentik.GetApplication(ctx, f.slug)
	require.NoError(t, err)
	assert.Equal(t, manual.Pk, application.Pk, "an Application that took over the slug is not deleted")
}

// unreachableClient fails every deletion of Applications, as an unreachable authentik does.
type unreachableClient struct {
	*recordingClient
}

func (unreachableClient) DeleteApplication(context.Context, string) error {
	return &authentik.APIError{Operation: "DeleteApplication", StatusCode: http.StatusServiceUnavailable}
}

func TestDeletionKeepsFinalizerWhileAuthentikFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	spec := f.proxySpec()
	spec.DeletionPolicy = new(v1alpha1.DeletionPolicyDelete)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)

	f.reconciler.Authentik = unreachableClient{f.authentik}
	require.Error(t, f.deleteAndReconcile(t, got))

	kept := &v1alpha1.AuthentikApplication{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(got), kept))
	assert.Contains(t, kept.Finalizers, finalizer)
	assertReady(t, kept, metav1.ConditionFalse, v1alpha1.ReasonAPIError)

	f.reconciler.Authentik = f.authentik
	_, err = f.reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(got)})
	require.NoError(t, err)
	assertGone(t, got)
}

func TestDeletionOfResourceThatNeverManagedAnything(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	spec := f.proxySpec()
	spec.DeletionPolicy = new(v1alpha1.DeletionPolicyDelete)
	_, err := f.authentik.CreateApplication(t.Context(), &api.ApplicationRequest{Name: manualName, Slug: f.slug})
	require.NoError(t, err)
	_, got, err := f.reconcile(t, f.create(t, spec))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonUnmanaged)
	f.authentik.takeWrites()

	require.NoError(t, f.deleteAndReconcile(t, got))
	assertGone(t, got)
	assert.Empty(t, f.authentik.takeWrites())
	_, err = f.authentik.GetApplication(t.Context(), f.slug)
	require.NoError(t, err, "an unmanaged Application is never deleted")
}
